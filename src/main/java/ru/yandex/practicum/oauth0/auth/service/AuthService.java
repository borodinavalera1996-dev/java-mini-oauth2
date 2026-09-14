package ru.yandex.practicum.oauth0.auth.service;

import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import ru.yandex.practicum.oauth0.auth.api.dto.*;
import ru.yandex.practicum.oauth0.auth.api.exception.AccessDeniedException;
import ru.yandex.practicum.oauth0.auth.api.exception.BadCredentialsException;
import ru.yandex.practicum.oauth0.auth.api.exception.NotFoundException;
import ru.yandex.practicum.oauth0.auth.api.exception.TokenReuseException;
import ru.yandex.practicum.oauth0.auth.db.entity.*;
import ru.yandex.practicum.oauth0.auth.db.repository.*;
import ru.yandex.practicum.oauth0.auth.service.token.JwtPayload;
import ru.yandex.practicum.oauth0.auth.service.token.RefreshTokenPayload;
import ru.yandex.practicum.oauth0.auth.service.token.TokenProvider;

import java.time.Instant;
import java.time.OffsetDateTime;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.stream.Collectors;

@Slf4j
@Service
@RequiredArgsConstructor
public class AuthService {

    @Value("${minioauth.auth_secret}")
    private String secret;
    @Value("${minioauth.issuer}")
    private String issuer;
    @Value("${minioauth.accessttl}")
    private Integer accessttl;
    @Value("${minioauth.refreshttl}")
    private Integer refreshttl;

    private final UserRepository userRepository;
    private final ClientRepository clientRepository;
    private final MetricRepository metricRepository;
    private final RefreshIndexRepository refreshIndexRepository;
    private final RevocationRepository revocationRepository;
    private final TokenProvider tokenProvider;
    private final BCryptPasswordEncoder passwordEncoder;

    @Transactional
    public TokenResponse loginWithUserCredentials(PasswordTokenRequest request, HttpServletRequest httpServletRequest) throws Exception {
        User user = getUser(request.getUsername(), httpServletRequest.getRemoteAddr());
        checkPassword(request.getPassword(), user.getPasswordHash(), user, "password", request.getUsername(), httpServletRequest.getRemoteAddr());

        Client client = getClient(request.getClientId(), httpServletRequest.getRemoteAddr());
        validatePassword(request.getClientSecret(), httpServletRequest, client, "password");

        List<String> finalScopes = calculateIntersectedScopes(user, client, request.getScopes());

        String jti = UUID.randomUUID().toString();
        String accessToken = createAccessToken(user, client, finalScopes, accessttl, jti);

        UUID refreshId = UUID.randomUUID();
        OffsetDateTime refreshExp = OffsetDateTime.now().plusDays(refreshttl);
        String refreshToken = createRefreshToken(refreshId, user, client, refreshExp);

        metricRepository.save(Metric.builder().eventType(Metric.EventType.token_issued).client(client).user(user).ipAddress(httpServletRequest.getRemoteAddr()).details(Map.of("grant_type", "password", "jti", jti, "refresh_id", refreshId.toString(), "issued_scopes", finalScopes)).build());

        TokenResponse tokenResponse = TokenResponse.builder().tokenType("Bearer").accessToken(accessToken).refreshToken(refreshToken).build();
        return tokenResponse;
    }

    @Transactional
    public TokenResponse loginWithClientCredentials(PasswordTokenRequest request, HttpServletRequest httpServletRequest) throws Exception {
        Client client = getClient(request.getClientId(), httpServletRequest.getRemoteAddr());
        validatePassword(request.getClientSecret(), httpServletRequest, client, "client_credentials");

        List<String> finalScopes = calculateIntersectedScopes(null, client, request.getScopes());

        String jti = UUID.randomUUID().toString();
        String accessToken = createAccessToken(null, client, finalScopes, accessttl, jti);

        metricRepository.save(Metric.builder().eventType(Metric.EventType.token_issued).client(client).user(null).ipAddress(httpServletRequest.getRemoteAddr()).details(Map.of("grant_type", "client_credentials", "jti", jti, "issued_scopes", finalScopes)).build());

        return TokenResponse.builder().tokenType("Bearer").accessToken(accessToken).refreshToken(null).build();
    }

    @Transactional
    public TokenResponse refreshSession(RefreshTokenRequest request, HttpServletRequest httpServletRequest) throws Exception {
        Client client = getClient(request.getClientId(), httpServletRequest.getRemoteAddr());
        validatePassword(request.getClientSecret(), httpServletRequest, client, request.getGrantType());

        RefreshTokenPayload tokenPayload = tokenProvider.parseAndValidateRefreshToken(request.getRefreshToken());
        RefreshIndex tokenIndex = getRefreshIndex(tokenPayload.getRefreshid(), httpServletRequest, client);
        User user = getUser(tokenIndex.getUser().getUsername(), httpServletRequest.getRemoteAddr());
        validateRefreshToken(httpServletRequest.getRemoteAddr(), tokenIndex, client, user);

        List<String> finalScopes = calculateIntersectedScopes(user, client, request.getScopes());

        tokenIndex.setRotated(true);
        refreshIndexRepository.save(tokenIndex);

        String newJti = UUID.randomUUID().toString();
        String newAccessToken = createAccessToken(user, client, finalScopes, accessttl, newJti);

        UUID newRefreshId = UUID.randomUUID();
        OffsetDateTime newRefreshExp = OffsetDateTime.now().plusDays(refreshttl);
        String newRefreshToken = createRefreshToken(newRefreshId, user, client, newRefreshExp);

        refreshIndexRepository.save(RefreshIndex.builder().refreshId(newRefreshId).client(client).user(user).exp(newRefreshExp).rotated(false).build());
        metricRepository.save(Metric.builder().eventType(Metric.EventType.token_refreshed).client(client).user(user).ipAddress(httpServletRequest.getRemoteAddr()).details(Map.of("grant_type", "refresh_token", "jti", newJti, "old_refresh_id", tokenIndex.getRefreshId(), "new_refresh_id", newRefreshId.toString(), "issued_scopes", finalScopes)).build());

        return TokenResponse.builder().tokenType("Bearer").accessToken(newAccessToken).refreshToken(newRefreshToken).build();
    }

    @Transactional(readOnly = true)
    public AuthMetadataResponse getTokenMetadata(Map<String, String> tokenRequest, HttpServletRequest httpServletRequest) throws Exception {
        String token = tokenRequest.get("token");
        String ipAddress = httpServletRequest.getRemoteAddr();

        if (token == null || token.isBlank()) {
            log.warn("Token metadata request failed: 'token' parameter is missing. IP: '{}'", ipAddress);
            throw new IllegalArgumentException("Token parameter is required");
        }
        log.debug("Received token metadata request from IP: '{}'", ipAddress);
        try {
            JwtPayload tokenPayload = tokenProvider.parseAndValidateToken(token);
            if (revocationRepository.existsByTargetId(tokenPayload.getJti())) {
                log.warn("Token metadata request denied: Token is revoked. JTI: '{}', IP: '{}'", tokenPayload.getJti(), ipAddress);
                throw new SecurityException("Token has been revoked");
            }
            log.info("Token metadata successfully retrieved for JTI: '{}', Client: '{}', IP: '{}'", tokenPayload.getJti(), tokenPayload.getClient_id(), ipAddress);
            return AuthMetadataResponse.builder().issuer(issuer).aud(tokenPayload.getAud()).accessTtlSec(accessttl).refreshTtlDays(refreshttl).tokenAlg("HS256").build();
        } catch (SecurityException e) {
            log.warn("Token metadata request failed: Invalid token signature or expired. Message: '{}', IP: '{}'", e.getMessage(), ipAddress);
            throw e;
        } catch (Exception e) {
            log.error("Unexpected error while fetching token metadata. IP: '{}'", ipAddress, e);
            throw e;
        }
    }

    @Transactional
    public void revokeToken(TokenHintRequest request, HttpServletRequest httpServletRequest) throws Exception {
        String hint = request.getTokenTypeHint();

        boolean isRevoked = false;
        String userIdForMetric = null;
        String targetIdForMetric;

        if ("refresh_token".equalsIgnoreCase(hint)) {
            RefreshTokenPayload tokenPayload = tokenProvider.parseAndValidateRefreshToken(request.getToken());
            RefreshIndex tokenIndex = getRefreshIndex(tokenPayload.getRefreshid(), httpServletRequest, null);
            targetIdForMetric = tokenPayload.getRefreshid();
            if (tokenIndex.isRotated()) {
                log.warn("SECURITY ALERT: Refresh token reuse detected! Token was already rotated. " +
                                "RefreshId: '{}', IP: '{}'", tokenIndex.getRefreshId(), httpServletRequest.getRemoteAddr());
                metricRepository.save(Metric.builder()
                    .eventType(Metric.EventType.auth_error)
                    .client(tokenIndex.getClient())
                    .user(tokenIndex.getUser())
                    .ipAddress(httpServletRequest.getRemoteAddr())
                    .errorCode("refresh_token_reuse_detected")
                    .details(Map.of("grant_type", "refresh_token", "token_id", tokenIndex.getRefreshId().toString()))
                    .build());
                revocationRepository.save(Revocation.builder().tokenType(Revocation.TokenType.refresh).targetId(targetIdForMetric).exp(tokenIndex.getExp()).reason("User explicit revocation request").build());
                throw new TokenReuseException("Refresh token already used. Potential breach detected.");
            }
        } else if ("access_token".equalsIgnoreCase(hint)) {
            JwtPayload tokenPayload = tokenProvider.parseAndValidateToken(request.getToken());
            targetIdForMetric = tokenPayload.getJti();
            if (!revocationRepository.existsByTargetId(tokenPayload.getJti())) {
                OffsetDateTime expiresAt = OffsetDateTime.now().plusSeconds(accessttl);

                revocationRepository.save(Revocation.builder().tokenType(Revocation.TokenType.access).targetId(targetIdForMetric).exp(expiresAt).reason("User explicit revocation request").build());
                isRevoked = true;
            }
        } else {
            log.warn("Invalid hint configuration. Hint: '{}'", hint);
            throw new NotFoundException(String.format("Suitable configuration not found for the provided hint: '%s'", hint));
        }

        if (isRevoked) {
            metricRepository.save(Metric.builder().eventType(Metric.EventType.token_revoked).client(null).user(userIdForMetric != null ? getUser(userIdForMetric, httpServletRequest.getRemoteAddr()) : null).ipAddress(httpServletRequest.getRemoteAddr()).details(Map.of("action", "token_revocation_success", "token_type_hint", hint != null ? hint : "auto_detected", "target_id", targetIdForMetric)).build());
        } else {
            metricRepository.save(Metric.builder().eventType(Metric.EventType.auth_error).client(null).user(null).ipAddress(httpServletRequest.getRemoteAddr()).errorCode("revocation_target_not_found").details(Map.of("token_type_hint", hint != null ? hint : "auto_detected")).build());
        }
    }

    @Transactional(readOnly = true)
    public IntrospectResponse introspectToken(TokenHintRequest request, HttpServletRequest httpServletRequest) {
        String hint = request.getTokenTypeHint();
        log.debug("Access token introspection request received. Hint: '{}', IP: '{}'", hint, httpServletRequest.getRemoteAddr());
        if (hint != null && !hint.equalsIgnoreCase("access_token")) {
            log.warn("Invalid hint configuration for user session. Hint '{}' is not supported. Requested IP: '{}'", hint, httpServletRequest.getRemoteAddr());
            throw new NotFoundException(String.format("Suitable configuration not found for the provided hint: '%s'", hint));
        }

        try {
            JwtPayload tokenPayload = tokenProvider.parseAndValidateToken(request.getToken());
            if (revocationRepository.existsByTargetId(tokenPayload.getJti())) {
                log.warn("Introspection failed: Access token is revoked. JTI: '{}', Client: '{}', IP: '{}'", tokenPayload.getJti(), tokenPayload.getClient_id(), httpServletRequest.getRemoteAddr());
                metricRepository.save(Metric.builder().eventType(Metric.EventType.auth_error).errorCode("introspection_token_revoked").ipAddress(httpServletRequest.getRemoteAddr()).details(Map.of("token_type_hint", hint != null ? hint : "unknown")).build());

                return IntrospectResponse.builder().active(false).build();
            }
            log.info("Introspection SUCCESS: Token is active. JTI: '{}', Client: '{}', Subject: '{}'", tokenPayload.getJti(), tokenPayload.getClient_id(), tokenPayload.getSub());

            return IntrospectResponse.builder().active(true).clientId(tokenPayload.getClient_id()).username(tokenPayload.getSub()).scope(tokenPayload.getScopes()).tokenType("Bearer").exp(tokenPayload.getExp()).build();
        } catch (SecurityException e) {
            log.warn("Introspection failed: Invalid JWT signature or token expired. Message: '{}', IP: '{}'", e.getMessage(), httpServletRequest.getRemoteAddr());
            metricRepository.save(Metric.builder().eventType(Metric.EventType.auth_error).errorCode("introspection_invalid_jwt").ipAddress(httpServletRequest.getRemoteAddr()).build());
        } catch (Exception e) {
            log.error("Unexpected error during token introspection. IP: '{}'", httpServletRequest.getRemoteAddr(), e);
            metricRepository.save(Metric.builder().eventType(Metric.EventType.auth_error).errorCode("introspection_system_error").ipAddress(httpServletRequest.getRemoteAddr()).build());
        }
        return IntrospectResponse.builder().active(false).build();
    }

    private void validateRefreshToken(String ipAddress, RefreshIndex tokenIndex, Client client, User user) {
        String userId = (user != null) ? user.getUserId() : "ANONYMOUS";
        if (tokenIndex.isRotated()) {
            log.warn("SECURITY ALERT: Refresh token reuse detected! Token has already been rotated. " + "RefreshId: '{}', Client: '{}', User: '{}', IP: '{}'", tokenIndex.getRefreshId(), client.getClientId(), userId, ipAddress);

            log.debug("Saving 'refresh_token_reuse_detected' metric to repository.");
            metricRepository.save(Metric.builder().eventType(Metric.EventType.auth_error).client(client).user(user).ipAddress(ipAddress).errorCode("refresh_token_reuse_detected").details(Map.of("grant_type", "refresh_token", "token_id", tokenIndex.getRefreshId().toString())).build());
            throw new IllegalStateException("Refresh token already used");
        }

        if (tokenIndex.getExp().isBefore(OffsetDateTime.now())) {
            log.warn("Refresh token expired. RefreshId: '{}', Expired at: '{}', Client: '{}', User: '{}', IP: '{}'", tokenIndex.getRefreshId(), tokenIndex.getExp(), client.getClientId(), userId, ipAddress);

            log.debug("Saving 'refresh_token_expired' metric to repository.");
            metricRepository.save(Metric.builder().eventType(Metric.EventType.auth_error).client(client).user(user).ipAddress(ipAddress).errorCode("refresh_token_expired").details(Map.of("grant_type", "refresh_token")).build());
            throw new IllegalArgumentException("Refresh token expired");
        }
        log.debug("Refresh token validation successful. RefreshId: '{}' is active and valid.", tokenIndex.getRefreshId());
    }

    private RefreshIndex getRefreshIndex(String refreshTokenStr, HttpServletRequest httpServletRequest, Client client) {
        log.debug("Attempting to find refresh token session for Client: '{}'", (client != null) ? client.getClientId() : "UNKNOWN");

        RefreshIndex tokenIndex = refreshIndexRepository.findById(UUID.fromString(refreshTokenStr)).orElseThrow(() -> {
            log.warn("Refresh token validation failed: Token not found in repository. Client: '{}', IP: '{}'", (client != null) ? client.getClientId() : "UNKNOWN", httpServletRequest.getRemoteAddr());

            log.debug("Saving 'refresh_token_not_found' metric to repository.");
            metricRepository.save(Metric.builder().eventType(Metric.EventType.auth_error).client(client).user(null).ipAddress(httpServletRequest.getRemoteAddr()).errorCode("refresh_token_not_found").details(Map.of("grant_type", "refresh_token")).build());

            return new BadCredentialsException("Refresh token not found");
        });

        log.debug("Refresh token session successfully found. TokenId: '{}', User: '{}', Client: '{}'", tokenIndex.getRefreshId(), (tokenIndex.getUser() != null) ? tokenIndex.getUser().getUserId() : "ANONYMOUS", (tokenIndex.getClient() != null) ? tokenIndex.getClient().getClientId() : "UNKNOWN");
        return tokenIndex;
    }

    private Client getClient(String clientId, String addr) {
        log.info("Client authentication attempt for clientId: '{}' from IP: '{}'", clientId, addr);
        log.debug("Fetching client details for clientId: '{}'", clientId);
        return clientRepository.findById(clientId).orElseThrow(() -> {
            log.warn("Client authentication failed: clientId '{}' not found. IP: '{}'", clientId, addr);
            return new IllegalArgumentException("Client not found");
        });
    }

    private User getUser(String userName, String addr) {
        log.info("Attempting login for user: '{}' from IP: '{}'", userName, addr);
        log.debug("Fetching user details for username: '{}'", userName);
        return userRepository.findByUsername(userName).orElseThrow(() -> {
            log.warn("Login failed: User '{}' not found. IP: '{}'", userName, addr);
            return new NotFoundException("Пользователь " + userName + " не найден");
        });
    }

    private void checkPassword(String plainPassword, String hashedPassword, User user, String grandType, String userName, String addr) {
        log.debug("Validating password for user: '{}'", userName);
        if (!passwordEncoder.matches(plainPassword, hashedPassword)) {
            metricRepository.save(Metric.builder().eventType(Metric.EventType.auth_error).client(null).user(user).ipAddress(addr).errorCode("invalid_user_password").details(Map.of("grant_type", grandType, "username", userName)).build());
            log.warn("Login failed: Invalid credentials for user '{}' from IP: '{}'", userName, addr);
            throw new BadCredentialsException("Invalid username or password");
        }
        log.info("User '{}' successfully authenticated from IP: '{}'", userName, addr);
    }

    private List<String> calculateIntersectedScopes(User user, Client client, List<String> requestedScopes) {
        String userId = (user != null) ? user.getUserId() : "ANONYMOUS";
        String clientId = (client != null) ? client.getClientId() : "UNKNOWN";
        log.debug("Calculating intersected scopes. User: '{}', Client: '{}', Requested scopes: {}", userId, clientId, requestedScopes);
        List<String> clientAllowedScopes = client != null && client.getInfo() != null && client.getInfo().containsKey("allowed_scopes")
                ? (List<String>) client.getInfo().get("allowed_scopes")
                : List.of();
        log.trace("Client '{}' allowed scopes: {}", clientId, clientAllowedScopes);
        List<String> maxCapabilities;
        if (user == null) {
            log.debug("No user context provided. Using client allowed scopes as base for client '{}'", clientId);
            maxCapabilities = new ArrayList<>(clientAllowedScopes);
        } else {
            List<String> userAllowedScopes = user.getInfo() != null && user.getInfo().containsKey("roles")
                    ? (List<String>) user.getInfo().get("roles")
                    : List.of();
            log.trace("User '{}' allowed scopes (roles): {}", userId, userAllowedScopes);
            maxCapabilities = userAllowedScopes.stream().filter(clientAllowedScopes::contains).collect(Collectors.toList());
            log.debug("Intersection of User '{}' and Client '{}' scopes: {}", userId, clientId, maxCapabilities);
        }
        if (user != null && maxCapabilities.isEmpty()) {
            log.warn("403 Forbidden: User '{}' and Client '{}' have no overlapping scopes.", userId, clientId);
            throw new AccessDeniedException("User roles and client allowed scopes do not match.");
        }
        if (requestedScopes != null && !requestedScopes.isEmpty()) {
            if (!maxCapabilities.containsAll(requestedScopes)) {
                log.warn("403 Forbidden: Requested scopes {} exceed maximum allowed capabilities {} for User '{}'/Client '{}'",
                        requestedScopes, maxCapabilities, userId, clientId);
                throw new AccessDeniedException("Requested scopes exceed allowed capabilities.");
            }
            maxCapabilities.retainAll(requestedScopes);
            log.debug("Filtered by requested scopes. Final intersected scopes for User '{}'/Client '{}': {}", userId, clientId, maxCapabilities);
        } else {
            log.debug("No specific scopes requested. Returning max capabilities for User '{}'/Client '{}': {}", userId, clientId, maxCapabilities);
        }
        if (maxCapabilities.isEmpty()) {
            log.warn("403 Forbidden: Final calculated scopes list is empty for User '{}'/Client '{}'", userId, clientId);
            throw new AccessDeniedException("No valid scopes assigned to the token.");
        }
        return maxCapabilities;
    }


    private String createRefreshToken(UUID refreshId, User user, Client client, OffsetDateTime refreshExp) throws Exception {
        String userId = (user != null) ? user.getUserId() : "ANONYMOUS";
        String clientId = (client != null) ? client.getClientId() : "UNKNOWN";
        log.debug("Initiating refresh token creation. RefreshId: '{}', User: '{}', Client: '{}', Expires at: {}", refreshId, userId, clientId, refreshExp);
        try {
            RefreshIndex refreshSession = RefreshIndex.builder().refreshId(refreshId).user(user).client(client).exp(refreshExp).rotated(false).build();

            log.trace("Saving refresh session context to repository for RefreshId: '{}'", refreshId);
            refreshIndexRepository.save(refreshSession);
            String refreshToken = tokenProvider.createRefreshToken(refreshId, refreshExp);
            log.info("Successfully created and persisted refresh token. RefreshId: '{}', User: '{}', Client: '{}'", refreshId, userId, clientId);
            return refreshToken;
        } catch (Exception e) {
            log.error("Failed to create refresh token session for RefreshId: '{}', User: '{}', Client: '{}'. Error: {}", refreshId, userId, clientId, e.getMessage(), e);
            throw e;
        }
    }

    private String createAccessToken(User user, Client client, List<String> intersectedScopes, long ttlSec, String jti) throws Exception {
        String userId = (user != null) ? user.getUserId() : "ANONYMOUS";
        String clientId = (client != null) ? client.getClientId() : "UNKNOWN";

        log.debug("Initiating access token creation. JTI: '{}', User: '{}', Client: '{}', TTL: {}s", jti, userId, clientId, ttlSec);
        Instant now = Instant.now();

        List<String> userRoles = user != null ? (List<String>) user.getInfo().getOrDefault("roles", List.of()) : List.of();

        String audience = (client != null && client.getInfo() != null) ? (String) client.getInfo().getOrDefault("aud", "unknown-api") : "unknown-api";

        log.trace("Token payload details - Audience: '{}', Scopes: {}, Roles: {}", audience, intersectedScopes, userRoles);

        try {
            JwtPayload jwt = JwtPayload.builder().jti(jti).iss(issuer).aud(audience).sub(user == null ? null : user.getUserId()).iat(now.getEpochSecond()).exp(now.plusSeconds(ttlSec).getEpochSecond()).client_id(clientId).scopes(intersectedScopes).roles(userRoles).build();

            String token = tokenProvider.createAccessToken(jwt);
            log.info("Successfully created access token. JTI: '{}', Subject (User): '{}', Client: '{}', Expires at: {}", jti, userId, clientId, now.plusSeconds(ttlSec));
            return token;

        } catch (Exception e) {
            log.error("Failed to create access token for JTI: '{}', User: '{}', Client: '{}'. Error: {}", jti, userId, clientId, e.getMessage(), e);
            throw e;
        }
    }

    private void validatePassword(String clientSecret, HttpServletRequest httpServletRequest, Client client, String grantType) {
        log.debug("Validating secret for clientId: '{}'", client.getClientId());
        if (!passwordEncoder.matches(clientSecret, client.getClientSecretHash())) {
            metricRepository.save(Metric.builder().eventType(Metric.EventType.auth_error).client(client).user(null).ipAddress(httpServletRequest.getRemoteAddr()).errorCode("invalid_client_secret").details(Map.of("grant_type", grantType)).build());
            log.warn("Client authentication failed: Invalid secret for clientId '{}' from IP: '{}'", client.getClientId(), httpServletRequest.getRemoteAddr());
            throw new BadCredentialsException("Invalid client secret");
        }
        log.info("Client '{}' successfully authenticated from IP: '{}'", client.getClientId(), httpServletRequest.getRemoteAddr());
    }

}

package ru.yandex.practicum.oauth0.auth.api;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import ru.yandex.practicum.oauth0.auth.api.dto.*;
import ru.yandex.practicum.oauth0.auth.api.exception.TokenReuseException;
import ru.yandex.practicum.oauth0.auth.service.AuthService;

import java.util.Map;

@Slf4j
@RestController
@RequestMapping("/")
@RequiredArgsConstructor
public class AuthController {

    private final AuthService authService;

    @PostMapping(value = "/token", consumes = "application/json", produces = "application/json")
    public TokenResponse issueToken(@Valid @RequestBody PasswordTokenRequest request,
                                    HttpServletRequest httpServletRequest) throws Exception {
        String ipAddress = httpServletRequest.getRemoteAddr();
        String grantType = request.getGrantType();
        String clientId = request.getClientId() != null ? request.getClientId() : "NOT_SPECIFIED";
        String username = request.getUsername() != null ? request.getUsername() : "NOT_SPECIFIED";

        log.info("Token generation request received. GrantType: '{}', ClientId: '{}', Username: '{}', IP: '{}'",
                grantType, clientId, username, ipAddress);
        TokenResponse tokenResponse;
        try {
            if ("password".equalsIgnoreCase(grantType)) {
                log.debug("Processing 'password' grant type flow for user: '{}'", username);
                tokenResponse = authService.loginWithUserCredentials(request, httpServletRequest);
            } else if ("client_credentials".equalsIgnoreCase(grantType)) {
                log.debug("Processing 'client_credentials' grant type flow for client: '{}'", clientId);
                tokenResponse = authService.loginWithClientCredentials(request, httpServletRequest);
            } else {
                log.warn("Authentication failed: Unsupported grant type '{}' from IP: '{}'", grantType, ipAddress);
                throw new IllegalArgumentException("Unsupported grant type: " + grantType);
            }
            log.info("Successfully issued tokens. GrantType: '{}', ClientId: '{}', User: '{}', IP: '{}'",
                    grantType, clientId, username, ipAddress);
            return tokenResponse;

        } catch (IllegalArgumentException e) {
            log.warn("Token issue rejected: Invalid arguments. Message: '{}', IP: '{}'", e.getMessage(), ipAddress);
            throw e;
        } catch (Exception e) {
            log.error("Error occurred during token issuance for GrantType: '{}', ClientId: '{}', IP: '{}'. Error: {}",
                    grantType, clientId, ipAddress, e.getMessage());
            throw e;
        }
    }


    @PostMapping(value = "/token/refresh", consumes = "application/json", produces = "application/json")
    public TokenResponse refreshToken(@RequestBody @Valid RefreshTokenRequest refreshToken,
                                      HttpServletRequest request) throws Exception {
        String ipAddress = request.getRemoteAddr();
        log.info("Token refresh request received from IP: '{}'", ipAddress);
        try {
            TokenResponse tokenResponse = authService.refreshSession(refreshToken, request);
            log.info("Session successfully refreshed for IP: '{}'. New tokens issued.", ipAddress);
            return tokenResponse;
        } catch (TokenReuseException e) {
            log.warn("SECURITY WARNING: Token refresh blocked due to potential reuse or invalid state from IP: '{}'. Message: {}",
                    ipAddress, e.getMessage());
            throw e;
        } catch (Exception e) {
            log.error("Failed to refresh token from IP: '{}'. Error: {}", ipAddress, e.getMessage());
            throw e;
        }
    }


    @PostMapping(value = "/token/password", consumes = "application/json", produces = "application/json")
    public AuthMetadataResponse getTokenMetadata(
            @RequestBody Map<String, String> requestBody,
            HttpServletRequest request) throws Exception {
        log.debug("Received HTTP POST request for token metadata from IP: '{}'", request.getRemoteAddr());
        AuthMetadataResponse response;
        try {
            response = authService.getTokenMetadata(
                    requestBody,
                    request
            );
            log.debug("Successfully returning token metadata response for IP: '{}'", request.getRemoteAddr());
        } catch (Exception e) {
            log.error("Failed to getTokenMetadata token from IP: '{}'. Error: {}", request.getRemoteAddr(), e.getMessage());
            throw e;
        }
        return response;
    }

    @PostMapping(value = "/revoke", consumes = "application/json")
    public void revokeToken(@RequestBody @Valid TokenHintRequest token,
                            HttpServletRequest request) throws Exception {
        String ipAddress = request.getRemoteAddr();
        String hint = token.getTokenTypeHint();
        log.info("Token revocation request received. Hint: '{}', IP: '{}'", hint != null ? hint : "NOT_SPECIFIED", ipAddress);
        try {
            authService.revokeToken(token, request);
            log.debug("Token revocation processed successfully for IP: '{}'", ipAddress);
        } catch (Exception e) {
            log.error("Failed to revoke token from IP: '{}'. Error: {}", ipAddress, e.getMessage());
            throw e;
        }
    }

    @PostMapping(value = "/introspect", consumes = "application/json")
    public IntrospectResponse introspectToken(@RequestBody @Valid TokenHintRequest token,
                                              HttpServletRequest request) throws Exception {
        String ipAddress = request.getRemoteAddr();
        String hint = token.getTokenTypeHint();

        log.debug("HTTP POST /introspect requested. Hint: '{}', IP: '{}'",
                hint != null ? hint : "NOT_SPECIFIED", ipAddress);
        try {
            IntrospectResponse introspectResponse = authService.introspectToken(token, request);
            if (introspectResponse != null && introspectResponse.isActive()) {
                log.debug("Token introspection successful: Token is ACTIVE. Client: '{}', IP: '{}'",
                        introspectResponse.getClientId(), ipAddress);
            } else {
                log.debug("Token introspection completed: Token is INACTIVE. IP: '{}'", ipAddress);
            }
            return introspectResponse;
        } catch (Exception e) {
            log.error("Error occurred during HTTP token introspection from IP: '{}'. Error: {}",
                    ipAddress, e.getMessage());
            throw e;
        }
    }
}

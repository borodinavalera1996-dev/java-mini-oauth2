package ru.yandex.practicum.oauth0.auth.service.token;

import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.time.OffsetDateTime;
import java.util.Base64;
import java.util.UUID;

@Slf4j
@Component
public class TokenProvider {

    private static final long CLOCK_SKEW_SECONDS = 60;

    private final ObjectMapper objectMapper;
    private final String secretKey;

    public TokenProvider(ObjectMapper objectMapper, @Value("${minioauth.auth_secret}") String secretKey) {
        this.objectMapper = objectMapper;
        this.secretKey = secretKey;
    }

    public String createAccessToken(JwtPayload payload) throws Exception {
        String jti = (payload != null) ? payload.getJti() : "UNKNOWN";
        String clientId = (payload != null) ? payload.getClient_id() : "UNKNOWN";
        log.debug("Serializing JWT components for Access Token. JTI: '{}', Client: '{}'", jti, clientId);
        try {
            String headerJson = objectMapper.writeValueAsString(new JwtHeader());
            String payloadJson = objectMapper.writeValueAsString(payload);
            log.trace("Signing JWT payload for JTI: '{}'. Payload size: {} chars", jti, payloadJson.length());
            String token = signeToken(headerJson, payloadJson);
            log.debug("Access Token string generated successfully. JTI: '{}', Client: '{}'", jti, clientId);
            return token;
        } catch (Exception e) {
            log.error("Failed to serialize or sign Access Token for JTI: '{}', Client: '{}'. Error: {}",
                    jti, clientId, e.getMessage(), e);
            throw e;
        }
    }

    public JwtPayload parseAndValidateToken(String token) throws Exception {
        if (token == null || token.isBlank()) {
            log.warn("Access token validation failed: token is null or blank");
            throw new SecurityException("Invalid token");
        }

        String[] parts = token.split("\\.");
        if (parts.length != 3) {
            log.warn("Access token validation failed: Invalid format. Parts count: {}", parts.length);
            throw new SecurityException("Invalid token format");
        }

        String base64Header = parts[0];
        String base64Payload = parts[1];
        String providedSignature = parts[2];

        String dataToSign = base64Header + "." + base64Payload;
        String expectedSignature = calculateHmacSha256(dataToSign, secretKey);
        if (!java.security.MessageDigest.isEqual(expectedSignature.getBytes(java.nio.charset.StandardCharsets.UTF_8),
                providedSignature.getBytes(java.nio.charset.StandardCharsets.UTF_8))) {
            log.error("SECURITY ALERT: Access token signature verification failed! Potential tampering attempt.");
            throw new SecurityException("Signature verification failed! Token has been tampered with.");
        }

        JwtPayload payload;
        try {
            byte[] decodedPayloadBytes = Base64.getUrlDecoder().decode(base64Payload);
            payload = objectMapper.readValue(decodedPayloadBytes, JwtPayload.class);
        } catch (Exception e) {
            log.error("Failed to parse access token payload. Error: {}", e.getMessage());
            throw new SecurityException("Invalid token structure");
        }

        long currentUnixTime = System.currentTimeMillis() / 1000;
        if (currentUnixTime > (payload.getExp() + CLOCK_SKEW_SECONDS)) {
            log.warn("Access token expired. JTI: '{}', Client: '{}', Exp: {}, Current: {}",
                    payload.getJti(), payload.getClient_id(), payload.getExp(), currentUnixTime);
            throw new SecurityException("Token has expired");
        }

        if (payload.getIat() > (currentUnixTime + CLOCK_SKEW_SECONDS)) {
            log.warn("Access token issued in the future (Clock skew issue). JTI: '{}', Iat: {}, Current: {}",
                    payload.getJti(), payload.getIat(), currentUnixTime);
            throw new SecurityException("Token issued in the future");
        }

        if (payload.getJti() == null || payload.getJti().isBlank()) {
            log.warn("Access token is missing unique identifier (jti)");
            throw new SecurityException("Invalid token identifier");
        }

        log.debug("Access token successfully validated. JTI: '{}', Client: '{}', Subject: '{}'",
                payload.getJti(), payload.getClient_id(), payload.getSub());

        return payload;
    }

    public String createRefreshToken(UUID refreshId, OffsetDateTime refreshExp) throws Exception {
        String refreshIdStr = (refreshId != null) ? refreshId.toString() : "UNKNOWN";
        long expTime = refreshExp.toEpochSecond();

        log.debug("Serializing Refresh Token components. RefreshId: '{}', Expires at (Epoch): {}", refreshIdStr, expTime);
        try {
            RefreshTokenPayload payload = RefreshTokenPayload.builder()
                    .refreshid(refreshIdStr)
                    .exp(expTime)
                    .build();
            String headerJson = objectMapper.writeValueAsString(new JwtHeader("RT", "HS256"));
            String payloadJson = objectMapper.writeValueAsString(payload);
            log.trace("Signing Refresh Token payload for RefreshId: '{}'", refreshIdStr);
            String token = signeToken(headerJson, payloadJson);
            log.debug("Refresh Token string successfully generated and signed for RefreshId: '{}'", refreshIdStr);
            return token;
        } catch (Exception e) {
            log.error("Failed to create or sign Refresh Token for RefreshId: '{}'. Error: {}",
                    refreshIdStr, e.getMessage(), e);
            throw e;
        }
    }

    public RefreshTokenPayload parseAndValidateRefreshToken(String token) throws Exception {
        if (token == null || token.isBlank()) {
            log.warn("Refresh token validation failed: token is null or blank");
            throw new SecurityException("Invalid refresh token");
        }

        String[] parts = token.split("\\.");
        if (parts.length != 3) {
            log.warn("Refresh token validation failed: Invalid format. Parts count: {}", parts.length);
            throw new SecurityException("Invalid refresh token format");
        }

        String dataToSign = parts[0] + "." + parts[1];
        String expectedSignature = calculateHmacSha256(dataToSign, secretKey);
        if (!expectedSignature.equals(parts[2])) {
            log.error("SECURITY ALERT: Refresh token signature verification failed!");
            throw new SecurityException("Refresh token signature verification failed!");
        }

        RefreshTokenPayload payload;
        try {
            byte[] decodedPayloadBytes = Base64.getUrlDecoder().decode(parts[1]);
            payload = objectMapper.readValue(decodedPayloadBytes, RefreshTokenPayload.class);
        } catch (Exception e) {
            log.error("Failed to parse refresh token payload. Error: {}", e.getMessage());
            throw new SecurityException("Invalid refresh token structure");
        }

        long currentUnixTime = System.currentTimeMillis() / 1000;

        if (currentUnixTime > (payload.getExp() + CLOCK_SKEW_SECONDS)) {
            log.warn("Refresh token expired. RefreshId: '{}', Exp: {}, Current: {}",
                    payload.getRefreshid(), payload.getExp(), currentUnixTime);
            throw new SecurityException("Refresh token has expired");
        }
        log.debug("Refresh token signature and expiration validated successfully for RefreshId: '{}'", payload.getRefreshid());
        return payload;
    }

    private String signeToken(String headerJson, String payloadJson) throws NoSuchAlgorithmException, InvalidKeyException {
        String base64Header = Base64.getUrlEncoder().withoutPadding().encodeToString(headerJson.getBytes(StandardCharsets.UTF_8));
        String base64Payload = Base64.getUrlEncoder().withoutPadding().encodeToString(payloadJson.getBytes(StandardCharsets.UTF_8));

        String dataToSign = base64Header + "." + base64Payload;
        String signature = calculateHmacSha256(dataToSign, secretKey);

        return dataToSign + "." + signature;
    }

    private String calculateHmacSha256(String data, String secret) throws NoSuchAlgorithmException, InvalidKeyException {
        Mac sha256Hmac = Mac.getInstance("HmacSHA256");
        SecretKeySpec secretKeySpec = new SecretKeySpec(secret.getBytes(StandardCharsets.UTF_8), "HmacSHA256");
        sha256Hmac.init(secretKeySpec);

        byte[] signedBytes = sha256Hmac.doFinal(data.getBytes(StandardCharsets.UTF_8));
        return Base64.getUrlEncoder().withoutPadding().encodeToString(signedBytes);
    }
}


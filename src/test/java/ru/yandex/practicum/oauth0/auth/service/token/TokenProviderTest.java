package ru.yandex.practicum.oauth0.auth.service.token;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.time.OffsetDateTime;
import java.util.List;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.*;

class TokenProviderTest {

    private TokenProvider tokenProvider;
    private ObjectMapper objectMapper;
    private final String testSecretKey = "my-super-secret-key-for-oauth2-2026-validation";

    @BeforeEach
    void setUp() {
        objectMapper = new ObjectMapper();
        tokenProvider = new TokenProvider(objectMapper, testSecretKey);
    }

    @Test
    void createAndValidateAccessToken_Success() throws Exception {
        long nowSeconds = System.currentTimeMillis() / 1000;
        JwtPayload payload = JwtPayload.builder()
                .jti(UUID.randomUUID().toString())
                .client_id("cli-001")
                .sub("user-123")
                .aud("payments-api")
                .iat(nowSeconds)
                .exp(nowSeconds + 300)
                .scopes(List.of("read"))
                .roles(List.of("USER"))
                .build();

        String tokenStr = tokenProvider.createAccessToken(payload);
        assertNotNull(tokenStr);
        assertEquals(3, tokenStr.split("\\.").length);
        JwtPayload validatedPayload = tokenProvider.parseAndValidateToken(tokenStr);
        assertEquals(payload.getJti(), validatedPayload.getJti());
        assertEquals(payload.getClient_id(), validatedPayload.getClient_id());
        assertEquals(payload.getSub(), validatedPayload.getSub());
    }

    @Test
    void validateAccessToken_InvalidSignature_ThrowsException() throws Exception {
        long nowSeconds = System.currentTimeMillis() / 1000;
        JwtPayload payload = JwtPayload.builder()
                .jti(UUID.randomUUID().toString())
                .exp(nowSeconds + 300)
                .build();

        String originalToken = tokenProvider.createAccessToken(payload);
        String[] parts = originalToken.split("\\.");
        String tamperedToken = parts[0] + "." + parts[1] + "." + "fakeSignature1234567890";
        assertThrows(SecurityException.class, () -> tokenProvider.parseAndValidateToken(tamperedToken));
    }

    @Test
    @DisplayName("Успешная валидация просроченного Access токена, если отклонение укладывается в рамки Clock Skew")
    void validateAccessToken_ExpiredWithinClockSkew_Success() throws Exception {
        long nowSeconds = System.currentTimeMillis() / 1000;
        JwtPayload payload = JwtPayload.builder()
                .jti(UUID.randomUUID().toString())
                .iat(nowSeconds - 120)
                .exp(nowSeconds - 30)
                .build();
        String tokenStr = tokenProvider.createAccessToken(payload);
        assertDoesNotThrow(() -> tokenProvider.parseAndValidateToken(tokenStr));
    }

    @Test
    void validateAccessToken_ExpiredOutsideClockSkew_ThrowsException() throws Exception {
        long nowSeconds = System.currentTimeMillis() / 1000;
        JwtPayload payload = JwtPayload.builder()
                .jti(UUID.randomUUID().toString())
                .exp(nowSeconds - 65)
                .build();

        String tokenStr = tokenProvider.createAccessToken(payload);
        assertThrows(SecurityException.class, () -> tokenProvider.parseAndValidateToken(tokenStr));
    }

    @Test
    void validateAccessToken_InvalidFormat_ThrowsException() {
        assertThrows(SecurityException.class, () -> tokenProvider.parseAndValidateToken(null));
        assertThrows(SecurityException.class, () -> tokenProvider.parseAndValidateToken("   "));
        assertThrows(SecurityException.class, () -> tokenProvider.parseAndValidateToken("part1.part2"));
    }

    @Test
    void createAndValidateRefreshToken_Success() throws Exception {
        UUID refreshId = UUID.randomUUID();
        OffsetDateTime expirationTime = OffsetDateTime.now().plusDays(14);
        String tokenStr = tokenProvider.createRefreshToken(refreshId, expirationTime);
        assertNotNull(tokenStr);
        RefreshTokenPayload payload = tokenProvider.parseAndValidateRefreshToken(tokenStr);
        assertEquals(refreshId.toString(), payload.getRefreshid());
        assertEquals(expirationTime.toEpochSecond(), payload.getExp());
    }

    @Test
    void validateRefreshToken_Expired_ThrowsException() throws Exception {
        UUID refreshId = UUID.randomUUID();
        OffsetDateTime expiredTime = OffsetDateTime.now().minusHours(2);
        String tokenStr = tokenProvider.createRefreshToken(refreshId, expiredTime);
        assertThrows(SecurityException.class, () -> tokenProvider.parseAndValidateRefreshToken(tokenStr));
    }
}

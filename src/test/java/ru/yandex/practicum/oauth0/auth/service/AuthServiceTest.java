package ru.yandex.practicum.oauth0.auth.service;

import jakarta.servlet.http.HttpServletRequest;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.test.util.ReflectionTestUtils;
import ru.yandex.practicum.oauth0.auth.api.dto.*;
import ru.yandex.practicum.oauth0.auth.api.exception.BadCredentialsException;
import ru.yandex.practicum.oauth0.auth.api.exception.NotFoundException;
import ru.yandex.practicum.oauth0.auth.api.exception.TokenReuseException;
import ru.yandex.practicum.oauth0.auth.db.entity.*;
import ru.yandex.practicum.oauth0.auth.db.repository.*;
import ru.yandex.practicum.oauth0.auth.service.token.JwtPayload;
import ru.yandex.practicum.oauth0.auth.service.token.RefreshTokenPayload;
import ru.yandex.practicum.oauth0.auth.service.token.TokenProvider;

import java.time.OffsetDateTime;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class AuthServiceTest {

    @Mock
    private UserRepository userRepository;
    @Mock
    private ClientRepository clientRepository;
    @Mock
    private MetricRepository metricRepository;
    @Mock
    private RefreshIndexRepository refreshIndexRepository;
    @Mock
    private RevocationRepository revocationRepository;
    @Mock
    private TokenProvider tokenProvider;
    @Mock
    private BCryptPasswordEncoder passwordEncoder;
    @Mock
    private HttpServletRequest httpServletRequest;

    @InjectMocks
    private AuthService authService;

    @BeforeEach
    void setUp() {
        ReflectionTestUtils.setField(authService, "secret", "test-secret-key");
        ReflectionTestUtils.setField(authService, "issuer", "mini-auth");
        ReflectionTestUtils.setField(authService, "accessttl", 900);
        ReflectionTestUtils.setField(authService, "refreshttl", 14);
    }

    @Test
    void loginWithUserCredentials_Success() throws Exception {
        PasswordTokenRequest request = PasswordTokenRequest.builder()
                .grantType("password")
                .username("valery")
                .password("password123")
                .clientId("cli-001")
                .clientSecret("super-secret-2026")
                .scopes(List.of("read"))
                .build();

        User mockUser = User.builder()
                .userId("user-123")
                .username("valery")
                .passwordHash("encoded-password-hash")
                .info(Map.of("roles", List.of("read", "write")))
                .build();

        Client mockClient = Client.builder()
                .clientId("cli-001")
                .clientSecretHash("encoded-client-secret-hash")
                .info(Map.of("allowed_scopes", List.of("read"), "aud", "payments-api"))
                .build();

        when(httpServletRequest.getRemoteAddr()).thenReturn("127.0.0.1");
        when(userRepository.findByUsername("valery")).thenReturn(Optional.of(mockUser));
        when(clientRepository.findById("cli-001")).thenReturn(Optional.of(mockClient));

        when(tokenProvider.createAccessToken(any(JwtPayload.class))).thenReturn("mocked-access-token");
        when(tokenProvider.createRefreshToken(any(), any(OffsetDateTime.class))).thenReturn("mocked-refresh-token");

        when(passwordEncoder.matches(eq("password123"), eq("encoded-password-hash"))).thenReturn(true);
        when(passwordEncoder.matches(eq("super-secret-2026"), eq("encoded-client-secret-hash"))).thenReturn(true);

        TokenResponse response = authService.loginWithUserCredentials(request, httpServletRequest);

        assertNotNull(response);
        assertEquals("Bearer", response.getTokenType());
        assertEquals("mocked-access-token", response.getAccessToken());
        assertEquals("mocked-refresh-token", response.getRefreshToken());

        verify(metricRepository, times(1)).save(any(Metric.class));
        verify(refreshIndexRepository, times(1)).save(any());
    }

    @Test
    void loginWithUserCredentials_UserNotFound_ThrowsNotFoundException() {
        PasswordTokenRequest request = PasswordTokenRequest.builder()
                .grantType("password")
                .username("unknown_user")
                .build();

        lenient().when(httpServletRequest.getRemoteAddr()).thenReturn("127.0.0.1");
        when(userRepository.findByUsername("unknown_user")).thenReturn(Optional.empty());

        assertThrows(NotFoundException.class, () ->
                authService.loginWithUserCredentials(request, httpServletRequest));
    }

    @Test
    void loginWithUserCredentials_InvalidClientSecret_ThrowsBadCredentialsException() {
        PasswordTokenRequest request = PasswordTokenRequest.builder()
                .grantType("password")
                .username("valery")
                .password("password123")
                .clientId("cli-001")
                .clientSecret("wrong-secret")
                .build();
        User mockUser = User.builder().username("valery").passwordHash("hash").build();

        when(httpServletRequest.getRemoteAddr()).thenReturn("127.0.0.1");
        when(userRepository.findByUsername("valery")).thenReturn(Optional.of(mockUser));

        assertThrows(BadCredentialsException.class, () ->
                authService.loginWithUserCredentials(request, httpServletRequest));
    }

    @Test
    void loginWithClientCredentials_Success() throws Exception {
        PasswordTokenRequest request = PasswordTokenRequest.builder()
                .grantType("client_credentials")
                .clientId("cli-001")
                .clientSecret("super-secret-2026")
                .scopes(List.of("read"))
                .build();

        String validClientSecretHash = "$2a$10$KqX3tS7bO8qGgM5WvRhUe.3iYvF3mGscA3f7p4t3YlD6.5rS0WvG";

        Client mockClient = Client.builder()
                .clientId("cli-001")
                .clientSecretHash(validClientSecretHash)
                .info(Map.of("allowed_scopes", List.of("read", "write"), "aud", "payments-api"))
                .build();

        when(httpServletRequest.getRemoteAddr()).thenReturn("192.168.1.1");

        lenient().when(clientRepository.findById("cli-001")).thenReturn(Optional.of(mockClient));
        lenient().when(clientRepository.findById("cli-001")).thenReturn(Optional.of(mockClient));

        when(tokenProvider.createAccessToken(any(JwtPayload.class))).thenReturn("mocked-client-access-token");
        lenient().when(passwordEncoder.matches(anyString(), anyString())).thenReturn(true);
        TokenResponse response = authService.loginWithClientCredentials(request, httpServletRequest);

        assertNotNull(response);
        assertEquals("Bearer", response.getTokenType());
        assertEquals("mocked-client-access-token", response.getAccessToken());
        assertNull(response.getRefreshToken());

        verify(metricRepository, times(1)).save(any(Metric.class));
    }

    @Test
    void loginWithClientCredentials_InvalidSecret_ThrowsBadCredentialsException() {
        PasswordTokenRequest request = PasswordTokenRequest.builder()
                .grantType("client_credentials")
                .clientId("cli-001")
                .clientSecret("wrong-application-secret")
                .build();

        String validClientSecretHash = "$2a$10$KqX3tS7bO8qGgM5WvRhUe.3iYvF3mGscA3f7p4t3YlD6.5rS0WvG";

        Client mockClient = Client.builder()
                .clientId("cli-001")
                .clientSecretHash(validClientSecretHash)
                .build();

        when(httpServletRequest.getRemoteAddr()).thenReturn("192.168.1.1");

        lenient().when(clientRepository.findById("cli-001")).thenReturn(Optional.of(mockClient));
        lenient().when(clientRepository.findById("cli-001")).thenReturn(Optional.of(mockClient));

        assertThrows(BadCredentialsException.class, () ->
                authService.loginWithClientCredentials(request, httpServletRequest));
    }

    @Test
    void refreshSession_Success() throws Exception {
        RefreshTokenRequest request = RefreshTokenRequest.builder()
                .grantType("refresh_token")
                .refreshToken("valid.refresh.token")
                .clientId("cli-001")
                .clientSecret("super-secret-2026")
                .scopes(List.of("read"))
                .build();

        String validClientSecretHash = "$2a$10$KqX3tS7bO8qGgM5WvRhUe.3iYvF3mGscA3f7p4t3YlD6.5rS0WvG";
        UUID oldRefreshId = UUID.randomUUID();
        Client mockClient = Client.builder()
                .clientId("cli-001")
                .clientSecretHash(validClientSecretHash)
                .info(Map.of("allowed_scopes", List.of("read"), "aud", "payments-api"))
                .build();
        User mockUser = User.builder()
                .userId("user-123")
                .username("valery")
                .info(Map.of("roles", List.of("read")))
                .build();

        RefreshIndex mockOldSession = RefreshIndex.builder()
                .refreshId(oldRefreshId)
                .client(mockClient)
                .user(mockUser)
                .exp(OffsetDateTime.now().plusDays(5))
                .rotated(false)
                .build();
        RefreshTokenPayload mockPayload = RefreshTokenPayload.builder()
                .refreshid(oldRefreshId.toString())
                .exp(OffsetDateTime.now().plusDays(5).toEpochSecond())
                .build();
        when(httpServletRequest.getRemoteAddr()).thenReturn("127.0.0.1");
        lenient().when(clientRepository.findById("cli-001")).thenReturn(Optional.of(mockClient));
        lenient().when(clientRepository.findById("cli-001")).thenReturn(Optional.of(mockClient));
        lenient().when(userRepository.findByUsername("valery")).thenReturn(Optional.of(mockUser));
        when(tokenProvider.parseAndValidateRefreshToken("valid.refresh.token")).thenReturn(mockPayload);
        lenient().when(refreshIndexRepository.findById(oldRefreshId)).thenReturn(Optional.of(mockOldSession));
        when(tokenProvider.createAccessToken(any(JwtPayload.class))).thenReturn("new-mocked-access-token");
        when(tokenProvider.createRefreshToken(any(UUID.class), any(OffsetDateTime.class))).thenReturn("new-mocked-refresh-token");
        lenient().when(passwordEncoder.matches(anyString(), anyString())).thenReturn(true);
        TokenResponse response = authService.refreshSession(request, httpServletRequest);
        assertNotNull(response);
        assertEquals("Bearer", response.getTokenType());
        assertEquals("new-mocked-access-token", response.getAccessToken());
        assertEquals("new-mocked-refresh-token", response.getRefreshToken());

        verify(refreshIndexRepository, times(3)).save(any(RefreshIndex.class));
        verify(metricRepository, times(1)).save(any(Metric.class));
    }

    @Test
    void refreshSession_TokenAlreadyRotated_ThrowsTokenReuseException() throws Exception {
        RefreshTokenRequest request = RefreshTokenRequest.builder()
                .grantType("refresh_token")
                .refreshToken("stale.refresh.token")
                .clientId("cli-001")
                .clientSecret("super-secret-2026")
                .build();
        String validClientSecretHash = "$2a$10$KqX3tS7bO8qGgM5WvRhUe.3iYvF3mGscA3f7p4t3YlD6.5rS0WvG";
        UUID compromisedRefreshId = UUID.randomUUID();

        Client mockClient = Client.builder()
                .clientId("cli-001")
                .clientSecretHash(validClientSecretHash)
                .build();
        User mockUser = User.builder()
                .userId("user-123")
                .username("valery")
                .build();
        RefreshIndex mockStaleSession = RefreshIndex.builder()
                .refreshId(compromisedRefreshId)
                .client(mockClient)
                .user(mockUser)
                .exp(OffsetDateTime.now().plusDays(5))
                .rotated(true)
                .build();
        RefreshTokenPayload mockPayload = RefreshTokenPayload.builder()
                .refreshid(compromisedRefreshId.toString())
                .build();
        when(httpServletRequest.getRemoteAddr()).thenReturn("127.0.0.1");
        lenient().when(clientRepository.findById("cli-001")).thenReturn(Optional.of(mockClient));
        lenient().when(clientRepository.findById("cli-001")).thenReturn(Optional.of(mockClient));
        lenient().when(userRepository.findByUsername("valery")).thenReturn(Optional.of(mockUser));

        when(tokenProvider.parseAndValidateRefreshToken("stale.refresh.token")).thenReturn(mockPayload);
        lenient().when(refreshIndexRepository.findById(compromisedRefreshId)).thenReturn(Optional.of(mockStaleSession));
        lenient().when(passwordEncoder.matches(anyString(), anyString())).thenReturn(true);
        assertThrows(IllegalStateException.class, () ->
                authService.refreshSession(request, httpServletRequest));
    }

    @Test
    void getTokenMetadata_Success() throws Exception {
        Map<String, String> tokenRequest = Map.of("token", "valid-access-token");

        JwtPayload mockPayload = JwtPayload.builder()
                .jti("jti-abc-123")
                .client_id("cli-001")
                .aud("payments-api")
                .build();
        when(httpServletRequest.getRemoteAddr()).thenReturn("192.168.1.50");
        when(tokenProvider.parseAndValidateToken("valid-access-token")).thenReturn(mockPayload);
        when(revocationRepository.existsByTargetId("jti-abc-123")).thenReturn(false);

        AuthMetadataResponse response = authService.getTokenMetadata(tokenRequest, httpServletRequest);
        assertNotNull(response);
        assertEquals("mini-auth", response.getIssuer());
        assertEquals("payments-api", response.getAud());
        assertEquals(900, response.getAccessTtlSec());
        assertEquals(14, response.getRefreshTtlDays());
        assertEquals("HS256", response.getTokenAlg());
    }

    @Test
    void getTokenMetadata_MissingToken_ThrowsIllegalArgumentException() {
        Map<String, String> tokenRequest = Map.of();
        when(httpServletRequest.getRemoteAddr()).thenReturn("192.168.1.50");
        assertThrows(IllegalArgumentException.class, () ->
                authService.getTokenMetadata(tokenRequest, httpServletRequest));
    }

    @Test
    void getTokenMetadata_TokenRevoked_ThrowsSecurityException() throws Exception {
        Map<String, String> tokenRequest = Map.of("token", "revoked-access-token");
        JwtPayload mockPayload = JwtPayload.builder()
                .jti("revoked-jti-999")
                .client_id("cli-001")
                .build();
        when(httpServletRequest.getRemoteAddr()).thenReturn("192.168.1.50");
        when(tokenProvider.parseAndValidateToken("revoked-access-token")).thenReturn(mockPayload);
        when(revocationRepository.existsByTargetId("revoked-jti-999")).thenReturn(true);
        assertThrows(SecurityException.class, () ->
                authService.getTokenMetadata(tokenRequest, httpServletRequest));
    }

    @Test
    void revokeToken_AccessToken_Success() throws Exception {
        TokenHintRequest request = TokenHintRequest.builder()
                .token("valid-access-jwt")
                .tokenTypeHint("access_token")
                .build();
        JwtPayload mockPayload = JwtPayload.builder()
                .jti("jti-access-111")
                .client_id("cli-001")
                .sub("user-valery")
                .build();
        when(httpServletRequest.getRemoteAddr()).thenReturn("127.0.0.1");
        when(tokenProvider.parseAndValidateToken("valid-access-jwt")).thenReturn(mockPayload);
        when(revocationRepository.existsByTargetId("jti-access-111")).thenReturn(false);
        assertDoesNotThrow(() -> authService.revokeToken(request, httpServletRequest));
        verify(revocationRepository, times(1)).save(any(Revocation.class));
        verify(metricRepository, times(1)).save(argThat(metric ->
                metric.getEventType() == Metric.EventType.token_revoked
        ));
    }

    @Test
    void revokeToken_RefreshToken_AlreadyRotated_ThrowsTokenReuseException() throws Exception {
        TokenHintRequest request = TokenHintRequest.builder()
                .token("stale-refresh-jwt")
                .tokenTypeHint("refresh_token")
                .build();
        UUID compromisedRefreshId = UUID.randomUUID();
        RefreshTokenPayload mockPayload = RefreshTokenPayload.builder()
                .refreshid(compromisedRefreshId.toString())
                .build();
        RefreshIndex mockStaleSession = RefreshIndex.builder()
                .refreshId(compromisedRefreshId)
                .exp(OffsetDateTime.now().plusDays(5))
                .rotated(true)
                .build();
        when(httpServletRequest.getRemoteAddr()).thenReturn("127.0.0.1");
        when(tokenProvider.parseAndValidateRefreshToken("stale-refresh-jwt")).thenReturn(mockPayload);

        lenient().when(refreshIndexRepository.findById(compromisedRefreshId)).thenReturn(Optional.of(mockStaleSession));
        assertThrows(TokenReuseException.class, () ->
                authService.revokeToken(request, httpServletRequest));
        verify(metricRepository, times(1)).save(argThat(metric ->
                metric.getEventType() == Metric.EventType.auth_error && "refresh_token_reuse_detected".equals(metric.getErrorCode())
        ));
        verify(revocationRepository, times(1)).save(any(Revocation.class));
    }

    @Test
    void revokeToken_InvalidHint_ThrowsNotFoundException() {
        TokenHintRequest request = TokenHintRequest.builder()
                .token("some-token")
                .tokenTypeHint("invalid_hint_type")
                .build();
        assertThrows(NotFoundException.class, () ->
                authService.revokeToken(request, httpServletRequest));
        verifyNoInteractions(revocationRepository);
    }

    @Test
    void introspectToken_Active_Success() throws Exception {
        TokenHintRequest request = TokenHintRequest.builder()
                .token("valid-jwt-token")
                .tokenTypeHint("access_token")
                .build();
        JwtPayload mockPayload = JwtPayload.builder()
                .jti("jti-active-001")
                .client_id("cli-001")
                .sub("valery")
                .scopes(List.of("read", "write"))
                .exp(1789262537L)
                .build();
        when(httpServletRequest.getRemoteAddr()).thenReturn("127.0.0.1");
        when(tokenProvider.parseAndValidateToken("valid-jwt-token")).thenReturn(mockPayload);
        when(revocationRepository.existsByTargetId("jti-active-001")).thenReturn(false);
        IntrospectResponse response = authService.introspectToken(request, httpServletRequest);
        assertNotNull(response);
        assertTrue(response.isActive());
        assertEquals("cli-001", response.getClientId());
        assertEquals("valery", response.getUsername());
        assertEquals("Bearer", response.getTokenType());
        assertEquals(List.of("read", "write"), response.getScope());
        assertEquals(1789262537L, response.getExp());
    }

    @Test
    void introspectToken_Revoked_ReturnsActiveFalse() throws Exception {
        TokenHintRequest request = TokenHintRequest.builder()
                .token("revoked-jwt-token")
                .tokenTypeHint("access_token")
                .build();
        JwtPayload mockPayload = JwtPayload.builder()
                .jti("jti-revoked-999")
                .client_id("cli-001")
                .build();
        when(httpServletRequest.getRemoteAddr()).thenReturn("127.0.0.1");
        when(tokenProvider.parseAndValidateToken("revoked-jwt-token")).thenReturn(mockPayload);
        when(revocationRepository.existsByTargetId("jti-revoked-999")).thenReturn(true);
        IntrospectResponse response = authService.introspectToken(request, httpServletRequest);
        assertNotNull(response);
        assertFalse(response.isActive());
        verify(metricRepository, times(1)).save(argThat(metric ->
                "introspection_token_revoked".equals(metric.getErrorCode())
        ));
    }

    @Test
    void introspectToken_InvalidJwt_ReturnsActiveFalse() throws Exception {
        TokenHintRequest request = TokenHintRequest.builder()
                .token("invalid-or-expired-token")
                .build();
        when(httpServletRequest.getRemoteAddr()).thenReturn("127.0.0.1");
        when(tokenProvider.parseAndValidateToken("invalid-or-expired-token"))
                .thenThrow(new SecurityException("Token has expired"));
        IntrospectResponse response = authService.introspectToken(request, httpServletRequest);
        assertNotNull(response);
        assertFalse(response.isActive());
        verify(metricRepository, times(1)).save(argThat(metric ->
                "introspection_invalid_jwt".equals(metric.getErrorCode())
        ));
    }

    @Test
    void introspectToken_UnsupportedHint_ThrowsNotFoundException() {
        TokenHintRequest request = TokenHintRequest.builder()
                .token("any-token")
                .tokenTypeHint("refresh_token")
                .build();

        when(httpServletRequest.getRemoteAddr()).thenReturn("127.0.0.1");
        assertThrows(NotFoundException.class, () ->
                authService.introspectToken(request, httpServletRequest));
        verifyNoInteractions(tokenProvider);
        verifyNoInteractions(metricRepository);
    }
}

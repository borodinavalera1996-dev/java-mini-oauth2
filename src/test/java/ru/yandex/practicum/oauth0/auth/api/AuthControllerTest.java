package ru.yandex.practicum.oauth0.auth.api;

import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.http.HttpServletRequest;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.http.MediaType;
import org.springframework.security.test.context.support.WithMockUser;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.servlet.MockMvc;
import ru.yandex.practicum.oauth0.auth.api.dto.*;
import ru.yandex.practicum.oauth0.auth.api.exception.NotFoundException;
import ru.yandex.practicum.oauth0.auth.api.exception.TokenReuseException;
import ru.yandex.practicum.oauth0.auth.service.AuthService;

import java.util.List;
import java.util.Map;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.when;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.csrf;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@WebMvcTest(AuthController.class)
class AuthControllerTest {

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private ObjectMapper objectMapper;

    @MockitoBean
    private AuthService authService;

    @Test
    @WithMockUser(username = "test-client", roles = "CLIENT")
    void issueToken_PasswordGrant_Success() throws Exception {
        PasswordTokenRequest request = PasswordTokenRequest.builder()
                .grantType("password")
                .username("valery")
                .password("password123")
                .clientId("cli-001")
                .clientSecret("super-secret-2026")
                .scopes(List.of("read", "write"))
                .build();

        TokenResponse expectedResponse = TokenResponse.builder()
                .tokenType("Bearer")
                .accessToken("mock-access-token")
                .refreshToken("mock-refresh-token")
                .build();

        when(authService.loginWithUserCredentials(any(PasswordTokenRequest.class), any(HttpServletRequest.class)))
                .thenReturn(expectedResponse);

        mockMvc.perform(post("/token")
                        .with(csrf())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.token_type").value("Bearer"))
                .andExpect(jsonPath("$.access_token").value("mock-access-token"))
                .andExpect(jsonPath("$.refresh_token").value("mock-refresh-token"));
    }

    @Test
    @WithMockUser(username = "test-client", roles = "CLIENT")
    void issueToken_ClientCredentialsGrant_Success() throws Exception {
        PasswordTokenRequest request = PasswordTokenRequest.builder()
                .grantType("client_credentials")
                .clientId("cli-001")
                .clientSecret("super-secret-2026")
                .scopes(List.of("read"))
                .build();

        TokenResponse expectedResponse = TokenResponse.builder()
                .tokenType("Bearer")
                .accessToken("mock-client-access-token")
                .build();

        when(authService.loginWithClientCredentials(any(PasswordTokenRequest.class), any(HttpServletRequest.class)))
                .thenReturn(expectedResponse);

        mockMvc.perform(post("/token")
                        .with(csrf())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.token_type").value("Bearer"))
                .andExpect(jsonPath("$.access_token").value("mock-client-access-token"))
                .andExpect(jsonPath("$.refresh_token").doesNotExist());
    }

    @Test
    @WithMockUser(username = "test-client", roles = "CLIENT")
    void issueToken_UnsupportedGrantType_Returns400() throws Exception {
        PasswordTokenRequest request = PasswordTokenRequest.builder()
                .grantType("invalid_flow")
                .build();

        mockMvc.perform(post("/token")
                        .with(csrf())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isBadRequest());
    }


    @Test
    @WithMockUser(username = "test-user")
    void refreshToken_Success() throws Exception {
        RefreshTokenRequest request = RefreshTokenRequest.builder()
                .grantType("refresh_token")
                .refreshToken("valid-refresh-token")
                .clientId("cli-001")
                .clientSecret("super-secret-2026")
                .build();

        TokenResponse expectedResponse = TokenResponse.builder()
                .accessToken("new-access-token")
                .refreshToken("new-refresh-token")
                .build();

        when(authService.refreshSession(any(RefreshTokenRequest.class), any(HttpServletRequest.class)))
                .thenReturn(expectedResponse);

        mockMvc.perform(post("/token/refresh")
                        .with(csrf())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.access_token").value("new-access-token"))
                .andExpect(jsonPath("$.refresh_token").value("new-refresh-token"));
    }

    @Test
    @WithMockUser(username = "test-user")
    void refreshToken_Reuse_Returns409() throws Exception {
        RefreshTokenRequest request = RefreshTokenRequest.builder()
                .grantType("refresh_token")
                .refreshToken("already-used-token")
                .clientId("cli-001")
                .clientSecret("super-secret-2026")
                .build();

        when(authService.refreshSession(any(RefreshTokenRequest.class), any(HttpServletRequest.class)))
                .thenThrow(new TokenReuseException("Refresh token already used"));

        mockMvc.perform(post("/token/refresh")
                        .with(csrf())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isConflict());
    }


    @Test
    @WithMockUser(username = "test-server")
    void getTokenMetadata_Success() throws Exception {
        Map<String, String> requestBody = Map.of("token", "valid-access-token");
        AuthMetadataResponse expectedResponse = AuthMetadataResponse.builder()
                .issuer("mini-auth")
                .aud("payments-api")
                .accessTtlSec(900)
                .refreshTtlDays(14)
                .tokenAlg("HS256")
                .build();

        when(authService.getTokenMetadata(any(Map.class), any(HttpServletRequest.class)))
                .thenReturn(expectedResponse);

        mockMvc.perform(post("/token/password")
                        .with(csrf())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(requestBody)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.issuer").value("mini-auth"))
                .andExpect(jsonPath("$.access_ttl_sec").value(900))
                .andExpect(jsonPath("$.token_alg").value("HS256"));
    }


    @Test
    @WithMockUser(username = "test-user")
    void revokeToken_Success() throws Exception {
        TokenHintRequest request = TokenHintRequest.builder()
                .token("token-to-revoke")
                .tokenTypeHint("access_token")
                .build();

        mockMvc.perform(post("/revoke")
                        .with(csrf())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isOk());
    }


    @Test
    @WithMockUser(username = "resource-server")
    void introspectToken_Active_Success() throws Exception {
        TokenHintRequest request = TokenHintRequest.builder()
                .token("active-jwt-token")
                .tokenTypeHint("access_token")
                .build();

        IntrospectResponse expectedResponse = IntrospectResponse.builder()
                .active(true)
                .clientId("cli-001")
                .username("valery")
                .scope(List.of("read"))
                .build();

        when(authService.introspectToken(any(TokenHintRequest.class), any(HttpServletRequest.class)))
                .thenReturn(expectedResponse);

        mockMvc.perform(post("/introspect")
                        .with(csrf())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.active").value(true))
                .andExpect(jsonPath("$.client_id").value("cli-001")).andExpect(jsonPath("$.username").value("valery"));
    }

    @Test
    @WithMockUser(username = "resource-server")
    void introspectToken_InvalidHint_Returns404() throws Exception {
        TokenHintRequest request = TokenHintRequest.builder().token("jwt-token").tokenTypeHint("unsupported_hint").build();
        when(authService.introspectToken(any(TokenHintRequest.class), any(HttpServletRequest.class))).thenThrow(new NotFoundException("Suitable configuration not found for the provided hint"));
        mockMvc.perform(post("/introspect").with(csrf()).contentType(MediaType.APPLICATION_JSON).content(objectMapper.writeValueAsString(request))).andExpect(status().isNotFound());
    }
}
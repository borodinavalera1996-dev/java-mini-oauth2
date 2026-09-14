package ru.yandex.practicum.oauth0.rs;

import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import ru.yandex.practicum.oauth0.auth.api.exception.AccessDeniedException;
import ru.yandex.practicum.oauth0.auth.db.repository.RevocationRepository;
import ru.yandex.practicum.oauth0.auth.service.token.JwtPayload;
import ru.yandex.practicum.oauth0.auth.service.token.TokenProvider;

import java.util.List;

@Slf4j
@Service
@RequiredArgsConstructor
public class ResourceAccessValidator {

    private final TokenProvider tokenProvider;
    private final RevocationRepository revocationRepository;

    @Value("${minioauth.resource_audience:payments-api}")
    private String expectedAudience;

    public JwtPayload validateRequestAndGetPayload(HttpServletRequest request) throws Exception {
        String authHeader = request.getHeader("Authorization");

        if (authHeader == null || !authHeader.startsWith("Bearer ")) {
            log.warn("Access denied: Missing or invalid Authorization header from IP: '{}'", request.getRemoteAddr());
            throw new SecurityException("Missing or invalid Bearer token");
        }

        String token = authHeader.substring(7);

        JwtPayload payload = tokenProvider.parseAndValidateToken(token);
        if (payload.getAud() == null || !expectedAudience.equalsIgnoreCase(payload.getAud())) {
            log.warn("Access denied: Audience mismatch. Expected: '{}', Found: '{}', JTI: '{}'",
                    expectedAudience, payload.getAud(), payload.getJti());
            throw new SecurityException("Token audience mismatch");
        }
        if (revocationRepository.existsByTargetId(payload.getJti())) {
            log.warn("Access denied: Token is revoked. JTI: '{}', IP: '{}'", payload.getJti(), request.getRemoteAddr());
            throw new SecurityException("Token has been revoked");
        }
        return payload;
    }

    public void checkRequiredScope(JwtPayload payload, String requiredScope) {
        List<String> scopes = payload.getScopes();
        if (scopes == null || !scopes.contains(requiredScope)) {
            log.warn("Access forbidden: Missing required scope '{}' for Client: '{}', User: '{}'",
                    requiredScope, payload.getClient_id(), payload.getSub());
            throw new AccessDeniedException("Insufficient scopes. Required: " + requiredScope);
        }
    }
}

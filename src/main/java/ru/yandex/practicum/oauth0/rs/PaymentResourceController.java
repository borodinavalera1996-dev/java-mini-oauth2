package ru.yandex.practicum.oauth0.rs;

import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import ru.yandex.practicum.oauth0.auth.service.token.JwtPayload;

import java.util.Map;

@Slf4j
@RestController
@RequestMapping("/api/payments")
@RequiredArgsConstructor
public class PaymentResourceController {

    private final ResourceAccessValidator accessValidator;

    @GetMapping
    public ResponseEntity<Map<String, Object>> getPayments(HttpServletRequest request) throws Exception {
        log.debug("GET /api/payments requested from IP: '{}'", request.getRemoteAddr());
        JwtPayload payload = accessValidator.validateRequestAndGetPayload(request);
        accessValidator.checkRequiredScope(payload, "payments:read");
        log.info("Successfully granted GET access to payments for Client: '{}', User: '{}'",
                payload.getClient_id(), payload.getSub());
        return ResponseEntity.ok(Map.of(
                "status", "success",
                "data", "Payments list data stream secure view",
                "client_id", payload.getClient_id()
        ));
    }

    @PostMapping
    public ResponseEntity<Map<String, Object>> createPayment(@RequestBody Map<String, Object> body,
                                                             HttpServletRequest request) throws Exception {
        log.debug("POST /api/payments requested from IP: '{}'", request.getRemoteAddr());
        JwtPayload payload = accessValidator.validateRequestAndGetPayload(request);
        accessValidator.checkRequiredScope(payload, "payments:write");
        log.info("Successfully granted POST access to payments for Client: '{}', User: '{}'",
                payload.getClient_id(), payload.getSub());
        return ResponseEntity.ok(Map.of(
                "status", "created",
                "transaction_id", "tx_99882211",
                "message", "Payment processed successfully"
        ));
    }
}

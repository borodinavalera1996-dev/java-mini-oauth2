package ru.yandex.practicum.oauth0.rs;

import lombok.Builder;
import lombok.Data;

import java.math.BigDecimal;

@Data
@Builder
public class PaymentDto {
    private Long id;
    private BigDecimal amount;
    private String currency;
    private String status;
    private String description;
}

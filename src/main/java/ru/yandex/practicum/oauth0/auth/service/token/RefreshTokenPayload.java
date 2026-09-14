package ru.yandex.practicum.oauth0.auth.service.token;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class RefreshTokenPayload {
    @Builder.Default
    private String typ = "RT";
    private String refreshid;
    private long exp;
}
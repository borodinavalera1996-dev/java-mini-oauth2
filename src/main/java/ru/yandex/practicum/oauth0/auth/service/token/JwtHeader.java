package ru.yandex.practicum.oauth0.auth.service.token;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@AllArgsConstructor
@NoArgsConstructor
public class JwtHeader {
    private String typ = "AT";
    private String alg = "HS256";
}

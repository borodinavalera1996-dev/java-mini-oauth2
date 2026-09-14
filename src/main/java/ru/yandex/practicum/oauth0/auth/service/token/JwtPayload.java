package ru.yandex.practicum.oauth0.auth.service.token;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.List;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class JwtPayload {
    private String iss;
    private String aud;
    private String sub;
    private String client_id;
    private List<String> scopes;
    private List<String> roles;
    private long iat;
    private long exp;
    private String jti;
}

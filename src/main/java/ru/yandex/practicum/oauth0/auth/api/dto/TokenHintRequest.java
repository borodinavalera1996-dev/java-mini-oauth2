package ru.yandex.practicum.oauth0.auth.api.dto;

import com.fasterxml.jackson.annotation.JsonProperty;
import jakarta.validation.constraints.NotBlank;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class TokenHintRequest {

    @NotBlank(message = "Token must not be blank")
    @JsonProperty("token")
    private String token;

    @JsonProperty("token_type_hint")
    private String tokenTypeHint;
}

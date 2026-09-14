package ru.yandex.practicum.oauth0.auth.api.dto;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
@JsonInclude(JsonInclude.Include.NON_NULL)
public class AuthMetadataResponse {

    private String issuer;

    private String aud;

    @JsonProperty("access_ttl_sec")
    private long accessTtlSec;

    @JsonProperty("refresh_ttl_days")
    private long refreshTtlDays;

    @JsonProperty("token_alg")
    private String tokenAlg;
}
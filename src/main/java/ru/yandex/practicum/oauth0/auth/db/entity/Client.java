package ru.yandex.practicum.oauth0.auth.db.entity;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import lombok.*;
import org.hibernate.annotations.JdbcTypeCode;
import org.hibernate.type.SqlTypes;

import java.time.OffsetDateTime;
import java.util.Map;

@Entity
@Table(name = "clients")
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class Client {

    @Id
    @Column(name = "clientid", length = 100)
    private String clientId;

    @Column(name = "clientsecrethash", nullable = false, length = 255)
    private String clientSecretHash;

    @JdbcTypeCode(SqlTypes.JSON)
    @Column(name = "info")
    private Map<String, Object> info;

    @Column(name = "created_at", insertable = false, updatable = false)
    private OffsetDateTime createdAt;
}


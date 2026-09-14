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
@Table(name = "users")
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class User {

    @Id
    @Column(name = "userid", length = 100)
    private String userId;

    @Column(name = "username", nullable = false, unique = true, length = 150)
    private String username;

    @Column(name = "passwordhash", nullable = false, length = 255)
    private String passwordHash;

    @JdbcTypeCode(SqlTypes.JSON)
    @Column(name = "info")
    private Map<String, Object> info;

    @Column(name = "created_at", insertable = false, updatable = false)
    private OffsetDateTime createdAt;

    @Column(name = "updated_at", insertable = false, updatable = false)
    private OffsetDateTime updatedAt;
}

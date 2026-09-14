package ru.yandex.practicum.oauth0.auth.db.entity;

import jakarta.persistence.*;
import lombok.*;

import java.time.OffsetDateTime;

@Entity
@Table(name = "revocation")
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class Revocation {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Column(name = "revocation_id")
    private Long revocationId;

    @Enumerated(EnumType.STRING)
    @Column(name = "token_type", nullable = false)
    private TokenType tokenType;

    @Column(name = "target_id", nullable = false, length = 255)
    private String targetId;

    @Column(name = "exp", nullable = false)
    private OffsetDateTime exp;

    @Column(name = "revoked_at", insertable = false, updatable = false)
    private OffsetDateTime revokedAt;

    @Column(name = "reason", length = 255)
    private String reason;

    public enum TokenType {
        access, refresh
    }
}

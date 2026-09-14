package ru.yandex.practicum.oauth0.auth.db.repository;

import org.springframework.data.jpa.repository.JpaRepository;
import ru.yandex.practicum.oauth0.auth.db.entity.Revocation;

public interface RevocationRepository extends JpaRepository<Revocation, Long> {
    boolean existsByTargetId(String tokenId);
}

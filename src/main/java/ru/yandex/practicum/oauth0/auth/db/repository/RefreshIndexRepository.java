package ru.yandex.practicum.oauth0.auth.db.repository;

import org.springframework.data.jpa.repository.JpaRepository;
import ru.yandex.practicum.oauth0.auth.db.entity.RefreshIndex;

import java.util.UUID;

public interface RefreshIndexRepository extends JpaRepository<RefreshIndex, UUID> {
}

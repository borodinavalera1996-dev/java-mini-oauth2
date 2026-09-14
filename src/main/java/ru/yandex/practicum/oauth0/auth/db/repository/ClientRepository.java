package ru.yandex.practicum.oauth0.auth.db.repository;

import org.springframework.data.jpa.repository.JpaRepository;
import ru.yandex.practicum.oauth0.auth.db.entity.Client;

public interface ClientRepository extends JpaRepository<Client, String> {
}

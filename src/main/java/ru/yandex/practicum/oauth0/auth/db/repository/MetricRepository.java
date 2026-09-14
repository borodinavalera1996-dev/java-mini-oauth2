package ru.yandex.practicum.oauth0.auth.db.repository;

import org.springframework.data.jpa.repository.JpaRepository;
import ru.yandex.practicum.oauth0.auth.db.entity.Metric;

public interface MetricRepository extends JpaRepository<Metric, Long> {
}

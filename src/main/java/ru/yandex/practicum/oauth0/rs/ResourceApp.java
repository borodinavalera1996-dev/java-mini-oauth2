package ru.yandex.practicum.oauth0.rs;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.autoconfigure.domain.EntityScan;
import org.springframework.data.jpa.repository.config.EnableJpaRepositories;

@SpringBootApplication(scanBasePackages = {
        "ru.yandex.practicum.oauth0.auth.service.token",
        "ru.yandex.practicum.oauth0.rs"
})
@EnableJpaRepositories(basePackages = "ru.yandex.practicum.oauth0.auth.db.repository")
@EntityScan(basePackages = "ru.yandex.practicum.oauth0.auth.db.entity")
public class ResourceApp {

    public static void main(String[] args) {
        SpringApplication.run(ResourceApp.class, args);
    }
}

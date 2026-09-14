package ru.yandex.practicum.oauth0.auth.api.exception;

public class RateLimitException extends RuntimeException {
    public RateLimitException(String message) {
        super(message);
    }
}

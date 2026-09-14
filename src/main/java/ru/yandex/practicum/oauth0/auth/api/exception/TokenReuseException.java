package ru.yandex.practicum.oauth0.auth.api.exception;

public class TokenReuseException extends RuntimeException {
    public TokenReuseException(String message) {
        super(message);
    }
}


package ru.yandex.practicum.oauth0.auth.api.exception;

import com.fasterxml.jackson.core.JsonProcessingException;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestControllerAdvice;

@Slf4j
@RestControllerAdvice
public class ErrorHandler {

    @ExceptionHandler({
            MethodArgumentNotValidException.class,
            IllegalArgumentException.class,
            JsonProcessingException.class
    })
    @ResponseStatus(HttpStatus.BAD_REQUEST)
    public ErrorResponse handleBadRequest(Exception ex) {
        log.warn("400 Bad Request: {}", ex.getMessage());
        return new ErrorResponse("invalid_request: " + ex.getMessage());
    }

    @ExceptionHandler({
            BadCredentialsException.class,
            SecurityException.class
    })
    @ResponseStatus(HttpStatus.UNAUTHORIZED)
    public ErrorResponse handleUnauthorized(Exception ex) {
        log.warn("401 Unauthorized: {}", ex.getMessage());
        return new ErrorResponse("invalid_grant: " + ex.getMessage());
    }

    @ExceptionHandler(AccessDeniedException.class)
    @ResponseStatus(HttpStatus.FORBIDDEN)
    public ErrorResponse handleForbidden(AccessDeniedException ex) {
        log.warn("403 Forbidden: {}", ex.getMessage());
        return new ErrorResponse("access_denied: " + ex.getMessage());
    }

    @ExceptionHandler(NotFoundException.class)
    @ResponseStatus(HttpStatus.NOT_FOUND)
    public ErrorResponse handleNotFoundException(final NotFoundException e) {
        log.warn("404 Not Found: {}", e.getMessage());
        return new ErrorResponse("not_found: " + e.getMessage());
    }

    @ExceptionHandler(TokenReuseException.class)
    @ResponseStatus(HttpStatus.CONFLICT)
    public ErrorResponse handleConflictException(final TokenReuseException e) {
        log.warn("409 Conflict (Token Reuse Detected): {}", e.getMessage());
        return new ErrorResponse("token_reuse_detected: " + e.getMessage());
    }

    @ExceptionHandler(RateLimitException.class)
    @ResponseStatus(HttpStatus.TOO_MANY_REQUESTS)
    public ErrorResponse handleRateLimitException(final RateLimitException e) {
        log.warn("429 Too Many Requests: {}", e.getMessage());
        return new ErrorResponse("slow_down: " + e.getMessage());
    }

    @ExceptionHandler(Throwable.class)
    @ResponseStatus(HttpStatus.INTERNAL_SERVER_ERROR)
    public ErrorResponse handleThrowable(final Throwable e) {
        log.error("500 Internal Server Error", e);
        return new ErrorResponse("server_error: Произошла непредвиденная ошибка на сервере.");
    }
}

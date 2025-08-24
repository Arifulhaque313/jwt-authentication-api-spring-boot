package com.ariful.jwtauth.exception;

import com.ariful.jwtauth.dto.response.ErrorResponse;
import jakarta.validation.ConstraintViolation;
import jakarta.validation.ConstraintViolationException;
import lombok.extern.slf4j.Slf4j;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.DisabledException;
import org.springframework.security.authentication.LockedException;
import org.springframework.security.core.AuthenticationException;
import org.springframework.validation.FieldError;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;
import org.springframework.web.context.request.WebRequest;

import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.List;

@RestControllerAdvice
@Slf4j
public class GlobalExceptionHandler {

    @ExceptionHandler(ResourceNotFoundException.class)
    public ResponseEntity<ErrorResponse> handleResourceNotFoundException(
            ResourceNotFoundException ex, WebRequest request) {

        log.error("Resource not found: {}", ex.getMessage());

        ErrorResponse errorResponse = ErrorResponse.builder()
                .success(false)
                .message(ex.getMessage())
                .error("Resource Not Found")
                .status(HttpStatus.NOT_FOUND.value())
                .path(getPath(request))
                .timestamp(LocalDateTime.now())
                .build();

        return new ResponseEntity<>(errorResponse, HttpStatus.NOT_FOUND);
    }

    @ExceptionHandler(BadRequestException.class)
    public ResponseEntity<ErrorResponse> handleBadRequestException(
            BadRequestException ex, WebRequest request) {

        log.error("Bad request: {}", ex.getMessage());

        ErrorResponse errorResponse = ErrorResponse.builder()
                .success(false)
                .message(ex.getMessage())
                .error("Bad Request")
                .status(HttpStatus.BAD_REQUEST.value())
                .path(getPath(request))
                .timestamp(LocalDateTime.now())
                .build();

        return new ResponseEntity<>(errorResponse, HttpStatus.BAD_REQUEST);
    }

    @ExceptionHandler(UnauthorizedException.class)
    public ResponseEntity<ErrorResponse> handleUnauthorizedException(
            UnauthorizedException ex, WebRequest request) {

        log.error("Unauthorized: {}", ex.getMessage());

        ErrorResponse errorResponse = ErrorResponse.builder()
                .success(false)
                .message(ex.getMessage())
                .error("Unauthorized")
                .status(HttpStatus.UNAUTHORIZED.value())
                .path(getPath(request))
                .timestamp(LocalDateTime.now())
                .build();

        return new ResponseEntity<>(errorResponse, HttpStatus.UNAUTHORIZED);
    }

    @ExceptionHandler(JwtException.class)
    public ResponseEntity<ErrorResponse> handleJwtException(
            JwtException ex, WebRequest request) {

        log.error("JWT error: {}", ex.getMessage());

        ErrorResponse errorResponse = ErrorResponse.builder()
                .success(false)
                .message("Authentication failed: " + ex.getMessage())
                .error("JWT Error")
                .status(HttpStatus.UNAUTHORIZED.value())
                .path(getPath(request))
                .timestamp(LocalDateTime.now())
                .build();

        return new ResponseEntity<>(errorResponse, HttpStatus.UNAUTHORIZED);
    }

    @ExceptionHandler(AccessDeniedException.class)
    public ResponseEntity<ErrorResponse> handleAccessDeniedException(
            AccessDeniedException ex, WebRequest request) {

        log.error("Access denied: {}", ex.getMessage());

        ErrorResponse errorResponse = ErrorResponse.builder()
                .success(false)
                .message("Access denied - Insufficient privileges")
                .error("Forbidden")
                .status(HttpStatus.FORBIDDEN.value())
                .path(getPath(request))
                .timestamp(LocalDateTime.now())
                .build();

        return new ResponseEntity<>(errorResponse, HttpStatus.FORBIDDEN);
    }

    @ExceptionHandler(AuthenticationException.class)
    public ResponseEntity<ErrorResponse> handleAuthenticationException(
            AuthenticationException ex, WebRequest request) {

        log.error("Authentication error: {}", ex.getMessage());

        String message = "Authentication failed";
        if (ex instanceof BadCredentialsException) {
            message = "Invalid username or password";
        } else if (ex instanceof DisabledException) {
            message = "Account is disabled";
        } else if (ex instanceof LockedException) {
            message = "Account is locked";
        }

        ErrorResponse errorResponse = ErrorResponse.builder()
                .success(false)
                .message(message)
                .error("Authentication Error")
                .status(HttpStatus.UNAUTHORIZED.value())
                .path(getPath(request))
                .timestamp(LocalDateTime.now())
                .build();

        return new ResponseEntity<>(errorResponse, HttpStatus.UNAUTHORIZED);
    }

    @ExceptionHandler(MethodArgumentNotValidException.class)
    public ResponseEntity<ErrorResponse> handleValidationExceptions(
            MethodArgumentNotValidException ex, WebRequest request) {

        log.error("Validation error: {}", ex.getMessage());

        List<ErrorResponse.ValidationError> validationErrors = new ArrayList<>();

        ex.getBindingResult().getAllErrors().forEach(error -> {
            String fieldName = ((FieldError) error).getField();
            String errorMessage = error.getDefaultMessage();
            Object rejectedValue = ((FieldError) error).getRejectedValue();

            validationErrors.add(ErrorResponse.ValidationError.builder()
                    .field(fieldName)
                    .message(errorMessage)
                    .rejectedValue(rejectedValue)
                    .build());
        });

        ErrorResponse errorResponse = ErrorResponse.builder()
                .success(false)
                .message("Validation failed")
                .error("Validation Error")
                .status(HttpStatus.BAD_REQUEST.value())
                .path(getPath(request))
                .timestamp(LocalDateTime.now())
                .validationErrors(validationErrors)
                .build();

        return new ResponseEntity<>(errorResponse, HttpStatus.BAD_REQUEST);
    }

    @ExceptionHandler(ConstraintViolationException.class)
    public ResponseEntity<ErrorResponse> handleConstraintViolationException(
            ConstraintViolationException ex, WebRequest request) {

        log.error("Constraint violation: {}", ex.getMessage());

        List<ErrorResponse.ValidationError> validationErrors = new ArrayList<>();

        for (ConstraintViolation<?> violation : ex.getConstraintViolations()) {
            validationErrors.add(ErrorResponse.ValidationError.builder()
                    .field(violation.getPropertyPath().toString())
                    .message(violation.getMessage())
                    .rejectedValue(violation.getInvalidValue())
                    .build());
        }

        ErrorResponse errorResponse = ErrorResponse.builder()
                .success(false)
                .message("Validation failed")
                .error("Constraint Violation")
                .status(HttpStatus.BAD_REQUEST.value())
                .path(getPath(request))
                .timestamp(LocalDateTime.now())
                .validationErrors(validationErrors)
                .build();

        return new ResponseEntity<>(errorResponse, HttpStatus.BAD_REQUEST);
    }

    @ExceptionHandler(DataIntegrityViolationException.class)
    public ResponseEntity<ErrorResponse> handleDataIntegrityViolationException(
            DataIntegrityViolationException ex, WebRequest request) {

        log.error("Data integrity violation: {}", ex.getMessage());

        String message = "Data integrity violation";
        if (ex.getMessage().contains("username")) {
            message = "Username already exists";
        } else if (ex.getMessage().contains("email")) {
            message = "Email already exists";
        }

        ErrorResponse errorResponse = ErrorResponse.builder()
                .success(false)
                .message(message)
                .error("Data Integrity Violation")
                .status(HttpStatus.CONFLICT.value())
                .path(getPath(request))
                .timestamp(LocalDateTime.now())
                .build();

        return new ResponseEntity<>(errorResponse, HttpStatus.CONFLICT);
    }

    @ExceptionHandler(Exception.class)
    public ResponseEntity<ErrorResponse> handleGlobalException(
            Exception ex, WebRequest request) {

        log.error("Unexpected error: ", ex);

        ErrorResponse errorResponse = ErrorResponse.builder()
                .success(false)
                .message("An unexpected error occurred")
                .error("Internal Server Error")
                .status(HttpStatus.INTERNAL_SERVER_ERROR.value())
                .path(getPath(request))
                .timestamp(LocalDateTime.now())
                .build();

        return new ResponseEntity<>(errorResponse, HttpStatus.INTERNAL_SERVER_ERROR);
    }

    private String getPath(WebRequest request) {
        return request.getDescription(false).replace("uri=", "");
    }
}
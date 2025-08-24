package com.ariful.jwtauth.Security;

import com.ariful.jwtauth.dto.response.ErrorResponse;
import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.MediaType;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.web.access.AccessDeniedHandler;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.time.LocalDateTime;

@Component
@Slf4j
public class CustomAccessDeniedHandler implements AccessDeniedHandler {

    private final ObjectMapper objectMapper = new ObjectMapper();

    @Override
    public void handle(HttpServletRequest request,
                       HttpServletResponse response,
                       AccessDeniedException accessDeniedException) throws IOException {

        log.error("Access denied error: {}", accessDeniedException.getMessage());

        response.setContentType(MediaType.APPLICATION_JSON_VALUE);
        response.setStatus(HttpServletResponse.SC_FORBIDDEN);

        ErrorResponse errorResponse = ErrorResponse.builder()
                .success(false)
                .message("Access denied - Insufficient privileges")
                .error("Forbidden")
                .status(HttpServletResponse.SC_FORBIDDEN)
                .path(request.getRequestURI())
                .timestamp(LocalDateTime.now())
                .build();

        objectMapper.writeValue(response.getOutputStream(), errorResponse);
    }
}

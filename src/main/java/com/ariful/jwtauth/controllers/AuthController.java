package com.ariful.jwtauth.controllers;

import com.ariful.jwtauth.dto.request.*;
import com.ariful.jwtauth.dto.response.ApiResponse;
import com.ariful.jwtauth.dto.response.JwtAuthResponse;
import com.ariful.jwtauth.service.AuthService;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/auth")
@RequiredArgsConstructor
public class AuthController {

    private final AuthService authService;

    @PostMapping("/login")
    public ResponseEntity<ApiResponse<JwtAuthResponse>> login(@Valid @RequestBody LoginRequest request) {
        ApiResponse<JwtAuthResponse> response = authService.login(request);
        return ResponseEntity.ok(response);
    }

    @PostMapping("/register")
    public ResponseEntity<ApiResponse<Void>> register(@Valid @RequestBody RegisterRequest request) {
        ApiResponse<Void> response = authService.register(request);
        return new ResponseEntity<>(response, HttpStatus.CREATED);
    }

    @PostMapping("/refresh")
    public ResponseEntity<ApiResponse<JwtAuthResponse>> refreshToken(@Valid @RequestBody RefreshTokenRequest request) {
        ApiResponse<JwtAuthResponse> response = authService.refreshToken(request);
        return ResponseEntity.ok(response);
    }

    @PostMapping("/logout")
    public ResponseEntity<ApiResponse<Void>> logout(Authentication authentication) {
        ApiResponse<Void> response = authService.logout(authentication.getName());
        return ResponseEntity.ok(response);
    }

    @PostMapping("/forgot-password")
    public ResponseEntity<ApiResponse<Void>> forgotPassword(@RequestParam String email) {
        ApiResponse<Void> response = authService.forgotPassword(email);
        return ResponseEntity.ok(response);
    }

    @PostMapping("/reset-password")
    public ResponseEntity<ApiResponse<Void>> resetPassword(@Valid @RequestBody PasswordResetRequest request) {
        ApiResponse<Void> response = authService.resetPassword(request);
        return ResponseEntity.ok(response);
    }

    @GetMapping("/verify-email")
    public ResponseEntity<ApiResponse<Void>> verifyEmail(@RequestParam String token) {
        ApiResponse<Void> response = authService.verifyEmail(token);
        return ResponseEntity.ok(response);
    }

    @PostMapping("/resend-verification")
    public ResponseEntity<ApiResponse<Void>> resendVerificationEmail(@RequestParam String email) {
        ApiResponse<Void> response = authService.resendVerificationEmail(email);
        return ResponseEntity.ok(response);
    }
}

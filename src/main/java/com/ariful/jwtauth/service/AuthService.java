package com.ariful.jwtauth.service;

import com.ariful.jwtauth.dto.request.*;
import com.example.jwtauth.dto.response.JwtAuthResponse;
import com.example.jwtauth.dto.response.ApiResponse;

public interface AuthService {

    ApiResponse<JwtAuthResponse> login(LoginRequest request);

    ApiResponse<Void> register(RegisterRequest request);

    ApiResponse<JwtAuthResponse> refreshToken(RefreshTokenRequest request);

    ApiResponse<Void> logout(String username);

    ApiResponse<Void> forgotPassword(String email);

    ApiResponse<Void> resetPassword(PasswordResetRequest request);

    ApiResponse<Void> verifyEmail(String token);

    ApiResponse<Void> resendVerificationEmail(String email);
}
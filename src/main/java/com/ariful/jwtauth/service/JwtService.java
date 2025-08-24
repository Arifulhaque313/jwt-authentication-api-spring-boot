package com.ariful.jwtauth.service;

import com.ariful.jwtauth.dto.response.JwtAuthResponse;
import com.ariful.jwtauth.entity.User;
import org.springframework.security.core.userdetails.UserDetails;

public interface JwtService {

    JwtAuthResponse generateTokens(User user);

    JwtAuthResponse generateTokens(UserDetails userDetails, User user);

    JwtAuthResponse refreshTokens(String refreshToken);

    String extractUsernameFromToken(String token);

    boolean validateToken(String token, UserDetails userDetails);

    boolean isTokenExpired(String token);

    void invalidateUserTokens(String username);

    void invalidateAllUserTokens(Long userId);
}

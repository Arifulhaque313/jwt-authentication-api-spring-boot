package com.ariful.jwtauth.service.impl;

import com.ariful.jwtauth.dto.response.JwtAuthResponse;
import com.ariful.jwtauth.dto.response.UserResponse;
import com.ariful.jwtauth.entity.User;
import com.ariful.jwtauth.exception.JwtException;
import com.ariful.jwtauth.repository.UserRepository;
import com.ariful.jwtauth.service.CustomUserDetailsService;
import com.ariful.jwtauth.service.JwtService;
import com.ariful.jwtauth.util.JwtUtil;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;
import java.util.HashMap;
import java.util.Map;

@Service
@RequiredArgsConstructor
@Slf4j
public class JwtServiceImpl implements JwtService {

    private final JwtUtil jwtUtil;
    private final CustomUserDetailsService userDetailsService;
    private final UserRepository userRepository;

    @Override
    @Transactional
    public JwtAuthResponse generateTokens(User user) {
        UserDetails userDetails = userDetailsService.loadUserByUsername(user.getUsername());
        return generateTokens(userDetails, user);
    }

    @Override
    @Transactional
    public JwtAuthResponse generateTokens(UserDetails userDetails, User user) {
        Map<String, Object> extraClaims = new HashMap<>();
        extraClaims.put("userId", user.getId());
        extraClaims.put("email", user.getEmail());
        extraClaims.put("tokenVersion", user.getTokenVersion());

        String accessToken = jwtUtil.generateAccessToken(userDetails, extraClaims);
        String refreshToken = jwtUtil.generateRefreshToken(userDetails, extraClaims);

        // Save refresh token to database
        user.setRefreshToken(refreshToken);
        user.setRefreshTokenExpiry(LocalDateTime.now().plusSeconds(jwtUtil.getRefreshTokenExpiration() / 1000));
        userRepository.save(user);

        UserResponse userResponse = buildUserResponse(user);

        return JwtAuthResponse.builder()
                .accessToken(accessToken)
                .refreshToken(refreshToken)
                .tokenType("Bearer")
                .expiresIn(jwtUtil.getAccessTokenExpiration() / 1000)
                .user(userResponse)
                .build();
    }

    @Override
    @Transactional
    public JwtAuthResponse refreshTokens(String refreshToken) {
        try {
            if (!jwtUtil.isRefreshToken(refreshToken)) {
                throw new JwtException("Invalid refresh token type");
            }

            String username = jwtUtil.extractUsername(refreshToken);

            User user = userRepository.findByUsername(username)
                    .orElseThrow(() -> new JwtException("User not found"));

            // Validate refresh token
            if (!refreshToken.equals(user.getRefreshToken()) || !user.isRefreshTokenValid()) {
                throw new JwtException("Invalid or expired refresh token");
            }

            UserDetails userDetails = userDetailsService.loadUserByUsername(username);

            if (!jwtUtil.isValidToken(refreshToken, userDetails)) {
                throw new JwtException("Invalid refresh token");
            }

            // Generate new tokens
            return generateTokens(userDetails, user);

        } catch (Exception e) {
            log.error("Error refreshing tokens: {}", e.getMessage());
            throw new JwtException("Failed to refresh tokens: " + e.getMessage());
        }
    }

    @Override
    public String extractUsernameFromToken(String token) {
        try {
            return jwtUtil.extractUsername(token);
        } catch (Exception e) {
            log.error("Error extracting username from token: {}", e.getMessage());
            throw new JwtException("Invalid token");
        }
    }

    @Override
    public boolean validateToken(String token, UserDetails userDetails) {
        return jwtUtil.isValidToken(token, userDetails);
    }

    @Override
    public boolean isTokenExpired(String token) {
        return jwtUtil.isTokenExpired(token);
    }

    @Override
    @Transactional
    public void invalidateUserTokens(String username) {
        User user = userRepository.findByUsername(username)
                .orElseThrow(() -> new JwtException("User not found"));

        user.setRefreshToken(null);
        user.setRefreshTokenExpiry(null);
        user.incrementTokenVersion();
        userRepository.save(user);

        log.info("Invalidated tokens for user: {}", username);
    }

    @Override
    @Transactional
    public void invalidateAllUserTokens(Long userId) {
        User user = userRepository.findById(userId)
                .orElseThrow(() -> new JwtException("User not found"));

        user.setRefreshToken(null);
        user.setRefreshTokenExpiry(null);
        user.incrementTokenVersion();
        userRepository.save(user);

        log.info("Invalidated all tokens for user ID: {}", userId);
    }

    private UserResponse buildUserResponse(User user) {
        return UserResponse.builder()
                .id(user.getId())
                .username(user.getUsername())
                .email(user.getEmail())
                .firstName(user.getFirstName())
                .lastName(user.getLastName())
                .phoneNumber(user.getPhoneNumber())
                .fullName(user.getFullName())
                .isEnabled(user.getIsEnabled())
                .emailVerified(user.getEmailVerified())
                .lastLogin(user.getLastLogin())
                .createdAt(user.getCreatedAt())
                .build();
    }
}
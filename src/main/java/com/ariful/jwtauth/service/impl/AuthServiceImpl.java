package com.ariful.jwtauth.service.impl;

import com.ariful.jwtauth.dto.request.*;
import com.ariful.jwtauth.dto.response.ApiResponse;
import com.ariful.jwtauth.dto.response.JwtAuthResponse;
import com.ariful.jwtauth.entity.Role;
import com.ariful.jwtauth.entity.User;
import com.ariful.jwtauth.exception.BadRequestException;
import com.ariful.jwtauth.exception.ResourceNotFoundException;
import com.ariful.jwtauth.exception.UnauthorizedException;
import com.ariful.jwtauth.repository.RoleRepository;
import com.ariful.jwtauth.repository.UserRepository;
import com.ariful.jwtauth.service.AuthService;
import com.ariful.jwtauth.service.JwtService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.DisabledException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;
import java.util.Set;
import java.util.UUID;

@Service
@RequiredArgsConstructor
@Slf4j
public class AuthServiceImpl implements AuthService {

    private final AuthenticationManager authenticationManager;
    private final UserRepository userRepository;
    private final RoleRepository roleRepository;
    private final PasswordEncoder passwordEncoder;
    private final JwtService jwtService;

    @Value("${app.security.email-verification-token-expiration}")
    private long emailVerificationTokenExpiration;

    @Override
    @Transactional
    public ApiResponse<JwtAuthResponse> login(LoginRequest request) {
        try {
            User user = userRepository.findByUsernameOrEmail(request.getUsernameOrEmail(), request.getUsernameOrEmail())
                    .orElseThrow(() -> new BadCredentialsException("Invalid credentials"));

            // Check if account is locked
            if (!user.getIsAccountNonLocked()) {
                throw new DisabledException("Account is locked due to multiple failed login attempts");
            }

            // Check if account is enabled
            if (!user.getIsEnabled()) {
                throw new DisabledException("Account is disabled");
            }

            // Authenticate user
            authenticationManager.authenticate(
                    new UsernamePasswordAuthenticationToken(request.getUsernameOrEmail(), request.getPassword())
            );

            // Reset failed login attempts on successful login
            user.resetFailedLoginAttempts();
            user.updateLastLogin();
            userRepository.save(user);

            // Generate tokens
            JwtAuthResponse jwtResponse = jwtService.generateTokens(user);

            log.info("User {} logged in successfully", user.getUsername());
            return ApiResponse.success("Login successful", jwtResponse);

        } catch (BadCredentialsException e) {
            handleFailedLogin(request.getUsernameOrEmail());
            throw new UnauthorizedException("Invalid username or password");
        } catch (DisabledException e) {
            throw new UnauthorizedException(e.getMessage());
        }
    }

    @Override
    @Transactional
    public ApiResponse<Void> register(RegisterRequest request) {
        // Validate passwords match
        if (!request.getPassword().equals(request.getConfirmPassword())) {
            throw new BadRequestException("Passwords do not match");
        }

        // Check if username exists
        if (userRepository.existsByUsername(request.getUsername())) {
            throw new BadRequestException("Username already exists");
        }

        // Check if email exists
        if (userRepository.existsByEmail(request.getEmail())) {
            throw new BadRequestException("Email already exists");
        }

        // Get default USER role
        Role userRole = roleRepository.findByName("USER")
                .orElseThrow(() -> new ResourceNotFoundException("Default USER role not found"));

        // Create new user
        User user = User.builder()
                .username(request.getUsername())
                .email(request.getEmail())
                .password(passwordEncoder.encode(request.getPassword()))
                .firstName(request.getFirstName())
                .lastName(request.getLastName())
                .phoneNumber(request.getPhoneNumber())
                .roles(Set.of(userRole))
                .emailVerificationToken(generateToken())
                .emailVerificationTokenExpiry(LocalDateTime.now().plusSeconds(emailVerificationTokenExpiration / 1000))
                .build();

        userRepository.save(user);

        // TODO: Send verification email
        log.info("User {} registered successfully", user.getUsername());
        return ApiResponse.success("Registration successful. Please check your email for verification.");
    }

    @Override
    @Transactional
    public ApiResponse<JwtAuthResponse> refreshToken(RefreshTokenRequest request) {
        JwtAuthResponse response = jwtService.refreshTokens(request.getRefreshToken());
        return ApiResponse.success("Token refreshed successfully", response);
    }

    @Override
    @Transactional
    public ApiResponse<Void> logout(String username) {
        jwtService.invalidateUserTokens(username);
        log.info("User {} logged out successfully", username);
        return ApiResponse.success("Logout successful");
    }

    @Override
    @Transactional
    public ApiResponse<Void> forgotPassword(String email) {
        User user = userRepository.findByEmail(email)
                .orElseThrow(() -> new ResourceNotFoundException("User not found with email: " + email));

        // Generate password reset token
        String resetToken = generateToken();
        user.setPasswordResetToken(resetToken);
        user.setPasswordResetTokenExpiry(LocalDateTime.now().plusSeconds(passwordResetTokenExpiration / 1000));
        userRepository.save(user);

        // TODO: Send password reset email
        log.info("Password reset requested for user: {}", user.getUsername());
        return ApiResponse.success("Password reset email sent successfully");
    }

    @Override
    @Transactional
    public ApiResponse<Void> resetPassword(PasswordResetRequest request) {
        // Validate passwords match
        if (!request.getNewPassword().equals(request.getConfirmPassword())) {
            throw new BadRequestException("Passwords do not match");
        }

        User user = userRepository.findByPasswordResetToken(request.getToken())
                .orElseThrow(() -> new BadRequestException("Invalid password reset token"));

        if (!user.isPasswordResetTokenValid()) {
            throw new BadRequestException("Password reset token has expired");
        }

        // Update password
        user.setPassword(passwordEncoder.encode(request.getNewPassword()));
        user.setPasswordResetToken(null);
        user.setPasswordResetTokenExpiry(null);
        user.setLastPasswordChange(LocalDateTime.now());
        user.incrementTokenVersion(); // Invalidate all existing tokens
        userRepository.save(user);

        log.info("Password reset successfully for user: {}", user.getUsername());
        return ApiResponse.success("Password reset successful");
    }

    @Override
    @Transactional
    public ApiResponse<Void> verifyEmail(String token) {
        User user = userRepository.findByEmailVerificationToken(token)
                .orElseThrow(() -> new BadRequestException("Invalid email verification token"));

        if (!user.isEmailVerificationTokenValid()) {
            throw new BadRequestException("Email verification token has expired");
        }

        user.setEmailVerified(true);
        user.setEmailVerificationToken(null);
        user.setEmailVerificationTokenExpiry(null);
        userRepository.save(user);

        log.info("Email verified successfully for user: {}", user.getUsername());
        return ApiResponse.success("Email verified successfully");
    }

    @Override
    @Transactional
    public ApiResponse<Void> resendVerificationEmail(String email) {
        User user = userRepository.findByEmail(email)
                .orElseThrow(() -> new ResourceNotFoundException("User not found with email: " + email));

        if (user.getEmailVerified()) {
            throw new BadRequestException("Email is already verified");
        }

        // Generate new verification token
        user.setEmailVerificationToken(generateToken());
        user.setEmailVerificationTokenExpiry(LocalDateTime.now().plusSeconds(emailVerificationTokenExpiration / 1000));
        userRepository.save(user);

        // TODO: Send verification email
        log.info("Verification email resent for user: {}", user.getUsername());
        return ApiResponse.success("Verification email sent successfully");
    }

    private void handleFailedLogin(String usernameOrEmail) {
        userRepository.findByUsernameOrEmail(usernameOrEmail, usernameOrEmail)
                .ifPresent(user -> {
                    user.incrementFailedLoginAttempts();

                    if (user.getFailedLoginAttempts() >= maxLoginAttempts) {
                        user.setIsAccountNonLocked(false);
                        log.warn("Account locked for user: {} due to {} failed login attempts",
                                user.getUsername(), user.getFailedLoginAttempts());
                    }

                    userRepository.save(user);
                });
    }

    private String generateToken() {
        return UUID.randomUUID().toString();
    }
}

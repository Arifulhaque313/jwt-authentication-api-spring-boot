package com.ariful.jwtauth.service.impl;

import com.ariful.jwtauth.dto.request.ChangePasswordRequest;
import com.ariful.jwtauth.dto.request.UpdateUserRequest;
import com.ariful.jwtauth.dto.response.ApiResponse;
import com.ariful.jwtauth.dto.response.PermissionResponse;
import com.ariful.jwtauth.dto.response.RoleResponse;
import com.ariful.jwtauth.dto.response.UserResponse;
import com.ariful.jwtauth.entity.Role;
import com.ariful.jwtauth.entity.User;
import com.ariful.jwtauth.exception.BadRequestException;
import com.ariful.jwtauth.exception.ResourceNotFoundException;
import com.ariful.jwtauth.repository.RoleRepository;
import com.ariful.jwtauth.repository.UserRepository;
import com.ariful.jwtauth.service.JwtService;
import com.ariful.jwtauth.service.UserService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

@Service
@RequiredArgsConstructor
@Slf4j

public class UserServiceImpl implements UserService {
    private final UserRepository userRepository;
    private final RoleRepository roleRepository;
    private final PasswordEncoder passwordEncoder;
    private final JwtService jwtService;

    @Override
    @Transactional(readOnly = true)
    public ApiResponse<UserResponse> getCurrentUser(String username) {
        User user = findUserByUsername(username);
        UserResponse userResponse = mapToUserResponse(user);
        return ApiResponse.success("User profile retrieved successfully", userResponse);
    }

    @Override
    @Transactional
    public ApiResponse<UserResponse> updateProfile(String username, UpdateUserRequest request) {
        User user = findUserByUsername(username);

        // Check if email is being changed and if it already exists
        if (request.getEmail() != null && !request.getEmail().equals(user.getEmail())) {
            if (userRepository.existsByEmail(request.getEmail())) {
                throw new BadRequestException("Email already exists");
            }
            user.setEmail(request.getEmail());
            user.setEmailVerified(false); // Require re-verification
        }

        if (request.getFirstName() != null) {
            user.setFirstName(request.getFirstName());
        }

        if (request.getLastName() != null) {
            user.setLastName(request.getLastName());
        }

        if (request.getPhoneNumber() != null) {
            user.setPhoneNumber(request.getPhoneNumber());
        }

        userRepository.save(user);

        UserResponse userResponse = mapToUserResponse(user);
        log.info("Profile updated for user: {}", username);
        return ApiResponse.success("Profile updated successfully", userResponse);
    }

    @Override
    @Transactional
    public ApiResponse<Void> changePassword(String username, ChangePasswordRequest request) {
        User user = findUserByUsername(username);

        // Validate passwords match
        if (!request.getNewPassword().equals(request.getConfirmNewPassword())) {
            throw new BadRequestException("New passwords do not match");
        }

        // Verify current password
        if (!passwordEncoder.matches(request.getCurrentPassword(), user.getPassword())) {
            throw new BadRequestException("Current password is incorrect");
        }

        // Update password
        user.setPassword(passwordEncoder.encode(request.getNewPassword()));
        user.setLastPasswordChange(LocalDateTime.now());
        user.incrementTokenVersion(); // Invalidate all existing tokens
        userRepository.save(user);

        log.info("Password changed for user: {}", username);
        return ApiResponse.success("Password changed successfully");
    }

    @Override
    @Transactional
    public ApiResponse<Void> deleteAccount(String username) {
        User user = findUserByUsername(username);

        // Invalidate all tokens
        jwtService.invalidateAllUserTokens(user.getId());

        // Delete user
        userRepository.delete(user);

        log.info("Account deleted for user: {}", username);
        return ApiResponse.success("Account deleted successfully");
    }

    @Override
    @Transactional(readOnly = true)
    public ApiResponse<Page<UserResponse>> getAllUsers(Pageable pageable) {
        Page<User> users = userRepository.findAll(pageable);
        Page<UserResponse> userResponses = users.map(this::mapToUserResponse);
        return ApiResponse.success("Users retrieved successfully", userResponses);
    }

    @Override
    @Transactional(readOnly = true)
    public ApiResponse<UserResponse> getUserById(Long id) {
        User user = userRepository.findById(id)
                .orElseThrow(() -> new ResourceNotFoundException("User not found with ID: " + id));

        UserResponse userResponse = mapToUserResponse(user);
        return ApiResponse.success("User retrieved successfully", userResponse);
    }

    @Override
    @Transactional
    public ApiResponse<Void> updateUserStatus(Long id, Boolean enabled) {
        User user = userRepository.findById(id)
                .orElseThrow(() -> new ResourceNotFoundException("User not found with ID: " + id));

        user.setIsEnabled(enabled);
        if (!enabled) {
            // Invalidate all tokens when disabling user
            jwtService.invalidateAllUserTokens(user.getId());
        }
        userRepository.save(user);

        log.info("User status updated for user ID {}: enabled = {}", id, enabled);
        return ApiResponse.success("User status updated successfully");
    }

    @Override
    @Transactional
    public ApiResponse<Void> assignRolesToUser(Long userId, Set<String> roleNames) {
        User user = userRepository.findById(userId)
                .orElseThrow(() -> new ResourceNotFoundException("User not found with ID: " + userId));

        Set<Role> roles = roleRepository.findByNameIn(List.copyOf(roleNames));
        if (roles.size() != roleNames.size()) {
            throw new BadRequestException("One or more roles not found");
        }

        user.setRoles(roles);
        user.incrementTokenVersion(); // Invalidate existing tokens to apply new permissions
        userRepository.save(user);

        log.info("Roles assigned to user ID {}: {}", userId, roleNames);
        return ApiResponse.success("Roles assigned successfully");
    }

    private User findUserByUsername(String username) {
        return userRepository.findByUsername(username)
                .orElseThrow(() -> new ResourceNotFoundException("User not found: " + username));
    }

    private UserResponse mapToUserResponse(User user) {
        Set<RoleResponse> roles = user.getRoles().stream()
                .map(role -> RoleResponse.builder()
                        .id(role.getId())
                        .name(role.getName())
                        .description(role.getDescription())
                        .permissions(role.getPermissions().stream()
                                .map(permission -> PermissionResponse.builder()
                                        .id(permission.getId())
                                        .name(permission.getName())
                                        .description(permission.getDescription())
                                        .resource(permission.getResource())
                                        .action(permission.getAction())
                                        .build())
                                .collect(Collectors.toSet()))
                        .build())
                .collect(Collectors.toSet());

        Set<PermissionResponse> permissions = user.getAllPermissions().stream()
                .map(permission -> PermissionResponse.builder()
                        .id(permission.getId())
                        .name(permission.getName())
                        .description(permission.getDescription())
                        .resource(permission.getResource())
                        .action(permission.getAction())
                        .build())
                .collect(Collectors.toSet());

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
                .roles(roles)
                .permissions(permissions)
                .build();
    }
}

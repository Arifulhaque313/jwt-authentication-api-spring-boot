package com.ariful.jwtauth.controllers;

import com.ariful.jwtauth.dto.request.ChangePasswordRequest;
import com.ariful.jwtauth.dto.request.UpdateUserRequest;
import com.ariful.jwtauth.dto.response.ApiResponse;
import com.ariful.jwtauth.dto.response.UserResponse;
import com.ariful.jwtauth.service.UserService;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/users")
@RequiredArgsConstructor
public class UserController {

    private final UserService userService;

    @GetMapping("/profile")
    @PreAuthorize("isAuthenticated()")
    public ResponseEntity<ApiResponse<UserResponse>> getCurrentUserProfile(Authentication authentication) {
        ApiResponse<UserResponse> response = userService.getCurrentUser(authentication.getName());
        return ResponseEntity.ok(response);
    }

    @PutMapping("/profile")
    @PreAuthorize("isAuthenticated()")
    public ResponseEntity<ApiResponse<UserResponse>> updateProfile(
            Authentication authentication,
            @Valid @RequestBody UpdateUserRequest request) {
        ApiResponse<UserResponse> response = userService.updateProfile(authentication.getName(), request);
        return ResponseEntity.ok(response);
    }

    @PostMapping("/change-password")
    @PreAuthorize("isAuthenticated()")
    public ResponseEntity<ApiResponse<Void>> changePassword(
            Authentication authentication,
            @Valid @RequestBody ChangePasswordRequest request) {
        ApiResponse<Void> response = userService.changePassword(authentication.getName(), request);
        return ResponseEntity.ok(response);
    }

    @DeleteMapping("/account")
    @PreAuthorize("isAuthenticated()")
    public ResponseEntity<ApiResponse<Void>> deleteAccount(Authentication authentication) {
        ApiResponse<Void> response = userService.deleteAccount(authentication.getName());
        return ResponseEntity.ok(response);
    }

    @GetMapping("/me/permissions")
    @PreAuthorize("isAuthenticated()")
    public ResponseEntity<ApiResponse<UserResponse>> getUserPermissions(Authentication authentication) {
        ApiResponse<UserResponse> response = userService.getCurrentUser(authentication.getName());
        return ResponseEntity.ok(response);
    }
}
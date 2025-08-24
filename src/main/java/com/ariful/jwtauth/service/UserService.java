package com.ariful.jwtauth.service;

import com.ariful.jwtauth.dto.request.ChangePasswordRequest;
import com.ariful.jwtauth.dto.request.UpdateUserRequest;
import com.ariful.jwtauth.dto.response.ApiResponse;
import com.ariful.jwtauth.dto.response.UserResponse;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;

import java.util.Set;

public interface UserService {

    ApiResponse<UserResponse> getCurrentUser(String username);

    ApiResponse<UserResponse> updateProfile(String username, UpdateUserRequest request);

    ApiResponse<Void> changePassword(String username, ChangePasswordRequest request);

    ApiResponse<Void> deleteAccount(String username);

    ApiResponse<Page<UserResponse>> getAllUsers(Pageable pageable);

    ApiResponse<UserResponse> getUserById(Long id);

    ApiResponse<Void> updateUserStatus(Long id, Boolean enabled);

    ApiResponse<Void> assignRolesToUser(Long userId, Set<String> roleNames);
}
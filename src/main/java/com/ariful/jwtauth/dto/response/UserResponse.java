package com.ariful.jwtauth.dto.response;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.LocalDateTime;
import java.util.Set;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class UserResponse {
    
    private Long id;
    private String username;
    private String email;
    private String firstName;
    private String lastName;
    private String phoneNumber;
    private String fullName;
    private Boolean isEnabled;
    private Boolean emailVerified;
    private LocalDateTime lastLogin;
    private LocalDateTime createdAt;
    private Set<RoleResponse> roles;
    private Set<PermissionResponse> permissions;
}

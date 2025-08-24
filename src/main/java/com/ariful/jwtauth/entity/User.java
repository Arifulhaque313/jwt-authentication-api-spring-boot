package com.ariful.jwtauth.entity;

import jakarta.persistence.*;
import lombok.*;

import java.time.LocalDateTime;
import java.util.HashSet;
import java.util.Set;

@Entity
@Table(name = "users")
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class User extends BaseEntity {
    
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;
    
    @Column(nullable = false, unique = true, length = 50)
    private String username;
    
    @Column(nullable = false, unique = true, length = 100)
    private String email;
    
    @Column(nullable = false)
    private String password;
    
    @Column(name = "first_name", length = 50)
    private String firstName;
    
    @Column(name = "last_name", length = 50)  
    private String lastName;
    
    @Column(name = "phone_number", length = 20)
    private String phoneNumber;
    
    // Account status fields
    @Builder.Default
    @Column(name = "is_enabled", nullable = false)
    private Boolean isEnabled = true;
    
    @Builder.Default
    @Column(name = "is_account_non_expired", nullable = false)
    private Boolean isAccountNonExpired = true;
    
    @Builder.Default
    @Column(name = "is_account_non_locked", nullable = false)
    private Boolean isAccountNonLocked = true;
    
    @Builder.Default
    @Column(name = "is_credentials_non_expired", nullable = false)
    private Boolean isCredentialsNonExpired = true;
    
    @Builder.Default
    @Column(name = "email_verified", nullable = false)
    private Boolean emailVerified = false;
    
    // Security and tracking fields
    @Builder.Default
    @Column(name = "failed_login_attempts")
    private Integer failedLoginAttempts = 0;
    
    @Column(name = "last_login")
    private LocalDateTime lastLogin;
    
    @Column(name = "last_password_change")
    private LocalDateTime lastPasswordChange;
    
    @Column(name = "password_reset_token")
    private String passwordResetToken;
    
    @Column(name = "password_reset_token_expiry")
    private LocalDateTime passwordResetTokenExpiry;
    
    @Column(name = "email_verification_token")
    private String emailVerificationToken;
    
    @Column(name = "email_verification_token_expiry")
    private LocalDateTime emailVerificationTokenExpiry;
    
    // JWT specific fields
    @Column(name = "refresh_token", columnDefinition = "TEXT")
    private String refreshToken;
    
    @Column(name = "refresh_token_expiry")
    private LocalDateTime refreshTokenExpiry;
    
    @Builder.Default
    @Column(name = "token_version")
    private Long tokenVersion = 0L;
    
    // Roles relationship
    @ManyToMany(fetch = FetchType.EAGER)
    @JoinTable(
        name = "user_roles",
        joinColumns = @JoinColumn(name = "user_id"),
        inverseJoinColumns = @JoinColumn(name = "role_id")
    )
    @Builder.Default
    private Set<Role> roles = new HashSet<>();
    
    // Convenience methods
    public String getFullName() {
        if (firstName != null && lastName != null) {
            return firstName + " " + lastName;
        } else if (firstName != null) {
            return firstName;
        } else if (lastName != null) {
            return lastName;
        }
        return username;
    }
    
    public boolean isActive() {
        return isEnabled && isAccountNonExpired && isAccountNonLocked && isCredentialsNonExpired;
    }
    
    public void incrementFailedLoginAttempts() {
        this.failedLoginAttempts = (this.failedLoginAttempts == null) ? 1 : this.failedLoginAttempts + 1;
    }
    
    public void resetFailedLoginAttempts() {
        this.failedLoginAttempts = 0;
    }
    
    public void updateLastLogin() {
        this.lastLogin = LocalDateTime.now();
    }
    
    public void incrementTokenVersion() {
        this.tokenVersion = (this.tokenVersion == null) ? 1L : this.tokenVersion + 1L;
    }
    
    public boolean isRefreshTokenValid() {
        return refreshToken != null && 
               refreshTokenExpiry != null && 
               refreshTokenExpiry.isAfter(LocalDateTime.now());
    }
    
    public boolean isPasswordResetTokenValid() {
        return passwordResetToken != null && 
               passwordResetTokenExpiry != null && 
               passwordResetTokenExpiry.isAfter(LocalDateTime.now());
    }
    
    public boolean isEmailVerificationTokenValid() {
        return emailVerificationToken != null && 
               emailVerificationTokenExpiry != null && 
               emailVerificationTokenExpiry.isAfter(LocalDateTime.now());
    }
    
    public void addRole(Role role) {
        roles.add(role);
        role.getUsers().add(this);
    }
    
    public void removeRole(Role role) {
        roles.remove(role);
        role.getUsers().remove(this);
    }
    
    public Set<Permission> getAllPermissions() {
        Set<Permission> permissions = new HashSet<>();
        for (Role role : roles) {
            permissions.addAll(role.getPermissions());
        }
        return permissions;
    }
    
    public boolean hasRole(String roleName) {
        return roles.stream().anyMatch(role -> role.getName().equals(roleName));
    }
    
    public boolean hasPermission(String permissionName) {
        return getAllPermissions().stream()
                .anyMatch(permission -> permission.getName().equals(permissionName));
    }
    
    @PrePersist
    @Override
    protected void onCreate() {
        super.onCreate();
        if (lastPasswordChange == null) {
            lastPasswordChange = LocalDateTime.now();
        }
    }
}
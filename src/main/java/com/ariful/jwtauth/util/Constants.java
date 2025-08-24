package com.ariful.jwtauth.util;

public final class Constants {

    // JWT Constants
    public static final String TOKEN_PREFIX = "Bearer ";
    public static final String HEADER_STRING = "Authorization";
    public static final String TOKEN_TYPE = "JWT";

    // Role Constants
    public static final String ROLE_USER = "USER";
    public static final String ROLE_ADMIN = "ADMIN";
    public static final String ROLE_MANAGER = "MANAGER";

    // Permission Constants
    public static final String PERMISSION_READ_USER = "READ_USER";
    public static final String PERMISSION_WRITE_USER = "WRITE_USER";
    public static final String PERMISSION_DELETE_USER = "DELETE_USER";
    public static final String PERMISSION_READ_ADMIN = "READ_ADMIN";
    public static final String PERMISSION_WRITE_ADMIN = "WRITE_ADMIN";
    public static final String PERMISSION_DELETE_ADMIN = "DELETE_ADMIN";
    public static final String PERMISSION_MANAGE_ROLES = "MANAGE_ROLES";
    public static final String PERMISSION_MANAGE_PERMISSIONS = "MANAGE_PERMISSIONS";

    // API Response Messages
    public static final String LOGIN_SUCCESS = "Login successful";
    public static final String LOGOUT_SUCCESS = "Logout successful";
    public static final String REGISTRATION_SUCCESS = "Registration successful";
    public static final String PASSWORD_CHANGED = "Password changed successfully";
    public static final String PROFILE_UPDATED = "Profile updated successfully";
    public static final String TOKEN_REFRESHED = "Token refreshed successfully";
    public static final String EMAIL_VERIFIED = "Email verified successfully";

    // Error Messages
    public static final String INVALID_CREDENTIALS = "Invalid username or password";
    public static final String ACCOUNT_DISABLED = "Account is disabled";
    public static final String ACCOUNT_LOCKED = "Account is locked";
    public static final String TOKEN_EXPIRED = "Token has expired";
    public static final String INVALID_TOKEN = "Invalid token";
    public static final String ACCESS_DENIED = "Access denied";
    public static final String USER_NOT_FOUND = "User not found";
    public static final String EMAIL_ALREADY_EXISTS = "Email already exists";
    public static final String USERNAME_ALREADY_EXISTS = "Username already exists";

    // Email Templates
    public static final String EMAIL_VERIFICATION_SUBJECT = "Verify your email address";
    public static final String PASSWORD_RESET_SUBJECT = "Reset your password";

    private Constants() {
        // Utility class
    }
}

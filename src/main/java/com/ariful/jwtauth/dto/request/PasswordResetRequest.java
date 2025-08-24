package com.ariful.jwtauth.dto.request;

import com.example.jwtauth.validation.ValidEmail;
import com.example.jwtauth.validation.ValidPassword;
import jakarta.validation.constraints.NotBlank;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class PasswordResetRequest {
    
    @NotBlank(message = "Token is required")
    private String token;
    
    @NotBlank(message = "New password is required")
    @ValidPassword
    private String newPassword;
    
    @NotBlank(message = "Confirm password is required")
    private String confirmPassword;
}


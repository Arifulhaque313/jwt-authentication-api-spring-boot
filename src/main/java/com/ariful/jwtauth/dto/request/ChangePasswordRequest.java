package com.ariful.jwtauth.dto.request;

import com.ariful.jwtauth.validation.ValidPassword;
import jakarta.validation.constraints.NotBlank;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class ChangePasswordRequest {
    
    @NotBlank(message = "Current password is required")
    private String currentPassword;
    
    @NotBlank(message = "New password is required")
    @ValidPassword
    private String newPassword;
    
    @NotBlank(message = "Confirm new password is required")
    private String confirmNewPassword;
}
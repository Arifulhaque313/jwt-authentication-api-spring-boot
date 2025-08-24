package com.ariful.jwtauth.dto.request;

import com.ariful.jwtauth.validation.ValidEmail;
import jakarta.validation.constraints.Size;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class UpdateUserRequest {
    
    @ValidEmail
    private String email;
    
    @Size(max = 50, message = "First name cannot exceed 50 characters")
    private String firstName;
    
    @Size(max = 50, message = "Last name cannot exceed 50 characters")
    private String lastName;
    
    @Size(max = 20, message = "Phone number cannot exceed 20 characters")
    private String phoneNumber;
}
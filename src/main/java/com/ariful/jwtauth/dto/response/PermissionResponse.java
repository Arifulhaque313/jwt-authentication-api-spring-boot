package com.ariful.jwtauth.dto.response;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class PermissionResponse {

    private Long id;
    private String name;
    private String description;
    private String resource;
    private String action;
}

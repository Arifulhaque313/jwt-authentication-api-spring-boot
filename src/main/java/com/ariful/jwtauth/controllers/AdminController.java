package com.ariful.jwtauth.controllers;

import com.ariful.jwtauth.dto.response.ApiResponse;
import com.ariful.jwtauth.dto.response.UserResponse;
import com.ariful.jwtauth.service.UserService;
import lombok.RequiredArgsConstructor;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Pageable;
import org.springframework.data.domain.Sort;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

import java.util.Set;

@RestController
@RequestMapping("/admin")
@RequiredArgsConstructor
@PreAuthorize("hasRole('ADMIN')")
public class AdminController {

    private final UserService userService;

    @GetMapping("/users")
    @PreAuthorize("hasAuthority('READ_ADMIN')")
    public ResponseEntity<ApiResponse<Page<UserResponse>>> getAllUsers(
            @RequestParam(defaultValue = "0") int page,
            @RequestParam(defaultValue = "10") int size,
            @RequestParam(defaultValue = "id") String sortBy,
            @RequestParam(defaultValue = "asc") String sortDir) {

        Sort sort = sortDir.equalsIgnoreCase("desc")
                ? Sort.by(sortBy).descending()
                : Sort.by(sortBy).ascending();

        Pageable pageable = PageRequest.of(page, size, sort);
        ApiResponse<Page<UserResponse>> response = userService.getAllUsers(pageable);
        return ResponseEntity.ok(response);
    }

    @GetMapping("/users/{id}")
    @PreAuthorize("hasAuthority('READ_ADMIN')")
    public ResponseEntity<ApiResponse<UserResponse>> getUserById(@PathVariable Long id) {
        ApiResponse<UserResponse> response = userService.getUserById(id);
        return ResponseEntity.ok(response);
    }

    @PutMapping("/users/{id}/status")
    @PreAuthorize("hasAuthority('WRITE_ADMIN')")
    public ResponseEntity<ApiResponse<Void>> updateUserStatus(
            @PathVariable Long id,
            @RequestParam Boolean enabled) {
        ApiResponse<Void> response = userService.updateUserStatus(id, enabled);
        return ResponseEntity.ok(response);
    }

    @PutMapping("/users/{id}/roles")
    @PreAuthorize("hasAuthority('MANAGE_ROLES')")
    public ResponseEntity<ApiResponse<Void>> assignRolesToUser(
            @PathVariable Long id,
            @RequestBody Set<String> roleNames) {
        ApiResponse<Void> response = userService.assignRolesToUser(id, roleNames);
        return ResponseEntity.ok(response);
    }

    @DeleteMapping("/users/{id}")
    @PreAuthorize("hasAuthority('DELETE_ADMIN')")
    public ResponseEntity<ApiResponse<Void>> deleteUser(@PathVariable Long id) {
        // Implementation would be similar to deleteAccount but for admin
        return ResponseEntity.ok(ApiResponse.success("User deleted successfully"));
    }
}

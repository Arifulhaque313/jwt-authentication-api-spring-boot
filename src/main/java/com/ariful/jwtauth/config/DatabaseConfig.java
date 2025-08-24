package com.ariful.jwtauth.config;

import com.ariful.jwtauth.entity.Permission;
import com.ariful.jwtauth.entity.Role;
import com.ariful.jwtauth.entity.User;
import com.ariful.jwtauth.repository.PermissionRepository;
import com.ariful.jwtauth.repository.RoleRepository;
import com.ariful.jwtauth.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.CommandLineRunner;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.time.LocalDateTime;
import java.util.Set;

@Configuration
@RequiredArgsConstructor
@Slf4j
public class DatabaseConfig {

    private final PermissionRepository permissionRepository;
    private final RoleRepository roleRepository;
    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;

    @Bean
    public CommandLineRunner initDatabase() {
        return args -> {
            initializePermissions();
            initializeRoles();
            initializeAdminUser();
        };
    }

    private void initializePermissions() {
        if (permissionRepository.count() == 0) {
            log.info("Initializing permissions...");

            Permission[] permissions = {
                    new Permission("READ_USER", "Read user information", "USER", "READ"),
                    new Permission("WRITE_USER", "Create/Update user information", "USER", "WRITE"),
                    new Permission("DELETE_USER", "Delete user", "USER", "DELETE"),
                    new Permission("READ_ADMIN", "Read admin data", "ADMIN", "READ"),
                    new Permission("WRITE_ADMIN", "Create/Update admin data", "ADMIN", "WRITE"),
                    new Permission("DELETE_ADMIN", "Delete admin data", "ADMIN", "DELETE"),
                    new Permission("MANAGE_ROLES", "Manage user roles", "ROLE", "MANAGE"),
                    new Permission("MANAGE_PERMISSIONS", "Manage permissions", "PERMISSION", "MANAGE")
            };

            for (Permission permission : permissions) {
                permissionRepository.save(permission);
            }

            log.info("Permissions initialized successfully");
        }
    }

    private void initializeRoles() {
        if (roleRepository.count() == 0) {
            log.info("Initializing roles...");

            // Create USER role
            Role userRole = new Role("USER", "Basic user role");
            userRole.getPermissions().add(permissionRepository.findByName("READ_USER").orElseThrow());
            userRole.getPermissions().add(permissionRepository.findByName("WRITE_USER").orElseThrow());
            roleRepository.save(userRole);

            // Create MANAGER role
            Role managerRole = new Role("MANAGER", "Manager role with extended permissions");
            managerRole.getPermissions().add(permissionRepository.findByName("READ_USER").orElseThrow());
            managerRole.getPermissions().add(permissionRepository.findByName("WRITE_USER").orElseThrow());
            managerRole.getPermissions().add(permissionRepository.findByName("READ_ADMIN").orElseThrow());
            roleRepository.save(managerRole);

            // Create ADMIN role
            Role adminRole = new Role("ADMIN", "Administrator role with full permissions");
            adminRole.getPermissions().addAll(permissionRepository.findAll());
            roleRepository.save(adminRole);

            log.info("Roles initialized successfully");
        }
    }

    private void initializeAdminUser() {
        if (userRepository.count() == 0) {
            log.info("Creating default admin user...");

            Role adminRole = roleRepository.findByName("ADMIN").orElseThrow();

            User adminUser = User.builder()
                    .username("admin")
                    .email("admin@example.com")
                    .password(passwordEncoder.encode("Admin@123"))
                    .firstName("System")
                    .lastName("Administrator")
                    .isEnabled(true)
                    .emailVerified(true)
                    .roles(Set.of(adminRole))
                    .lastPasswordChange(LocalDateTime.now())
                    .build();

            userRepository.save(adminUser);

            log.info("Default admin user created successfully");
            log.info("Default admin credentials - Username: admin, Password: Admin@123");
        }
    }
}

package com.ariful.jwtauth.repository;

import com.ariful.jwtauth.entity.User;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.time.LocalDateTime;
import java.util.List;
import java.util.Optional;

@Repository
public interface UserRepository extends JpaRepository<User, Long> {
    
    Optional<User> findByUsername(String username);
    
    Optional<User> findByEmail(String email);
    
    Optional<User> findByUsernameOrEmail(String username, String email);
    
    Optional<User> findByPasswordResetToken(String token);
    
    Optional<User> findByEmailVerificationToken(String token);
    
    boolean existsByUsername(String username);
    
    boolean existsByEmail(String email);
    
    @Query("SELECT u FROM User u WHERE u.isEnabled = :enabled")
    Page<User> findByIsEnabled(@Param("enabled") Boolean enabled, Pageable pageable);
    
    @Query("SELECT u FROM User u WHERE u.emailVerified = :verified")
    Page<User> findByEmailVerified(@Param("verified") Boolean verified, Pageable pageable);
    
    @Query("SELECT u FROM User u WHERE u.lastLogin < :date")
    List<User> findUsersInactiveSince(@Param("date") LocalDateTime date);
    
    @Query("SELECT u FROM User u JOIN u.roles r WHERE r.name = :roleName")
    Page<User> findByRoleName(@Param("roleName") String roleName, Pageable pageable);
    
    @Query("SELECT u FROM User u WHERE " +
           "LOWER(u.username) LIKE LOWER(CONCAT('%', :search, '%')) OR " +
           "LOWER(u.email) LIKE LOWER(CONCAT('%', :search, '%')) OR " +
           "LOWER(u.firstName) LIKE LOWER(CONCAT('%', :search, '%')) OR " +
           "LOWER(u.lastName) LIKE LOWER(CONCAT('%', :search, '%'))")
    Page<User> searchUsers(@Param("search") String search, Pageable pageable);
    
    @Query("SELECT COUNT(u) FROM User u WHERE u.isEnabled = true")
    long countActiveUsers();
    
    @Query("SELECT COUNT(u) FROM User u WHERE u.createdAt >= :date")
    long countUsersCreatedSince(@Param("date") LocalDateTime date);
}
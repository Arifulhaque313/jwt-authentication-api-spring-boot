package com.ariful.jwtauth.repository;

import com.ariful.jwtauth.entity.Role;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;
import java.util.Set;

@Repository
public interface RoleRepository extends JpaRepository<Role, Long> {
    
    Optional<Role> findByName(String name);
    
    boolean existsByName(String name);
    
    @Query("SELECT r FROM Role r WHERE r.name IN :names")
    Set<Role> findByNameIn(@Param("names") List<String> names);
    
    @Query("SELECT r FROM Role r JOIN FETCH r.permissions")
    List<Role> findAllWithPermissions();
    
    @Query("SELECT r FROM Role r WHERE r.name LIKE %:search% OR r.description LIKE %:search%")
    List<Role> searchRoles(@Param("search") String search);
    
    @Query("SELECT COUNT(u) FROM User u JOIN u.roles r WHERE r.id = :roleId")
    long countUsersByRoleId(@Param("roleId") Long roleId);
}
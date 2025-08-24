package com.ariful.jwtauth.repository;

import com.ariful.jwtauth.entity.Permission;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;
import java.util.Set;

@Repository
public interface PermissionRepository extends JpaRepository<Permission, Long> {
    
    Optional<Permission> findByName(String name);
    
    boolean existsByName(String name);
    
    @Query("SELECT p FROM Permission p WHERE p.name IN :names")
    Set<Permission> findByNameIn(@Param("names") List<String> names);
    
    @Query("SELECT p FROM Permission p WHERE p.resource = :resource")
    List<Permission> findByResource(@Param("resource") String resource);
    
    @Query("SELECT p FROM Permission p WHERE p.action = :action")
    List<Permission> findByAction(@Param("action") String action);
    
    @Query("SELECT p FROM Permission p WHERE p.resource = :resource AND p.action = :action")
    Optional<Permission> findByResourceAndAction(@Param("resource") String resource, 
                                               @Param("action") String action);
    
    @Query("SELECT p FROM Permission p WHERE " +
           "p.name LIKE %:search% OR " +
           "p.description LIKE %:search% OR " +
           "p.resource LIKE %:search% OR " +
           "p.action LIKE %:search%")
    List<Permission> searchPermissions(@Param("search") String search);
    
    @Query("SELECT COUNT(r) FROM Role r JOIN r.permissions p WHERE p.id = :permissionId")
    long countRolesByPermissionId(@Param("permissionId") Long permissionId);
}
package com.ariful.jwtauth.util;

import io.jsonwebtoken.*;
import io.jsonwebtoken.security.Keys;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;

import javax.crypto.SecretKey;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.function.Function;

@Component
@Slf4j
public class JwtUtil {

    @Value("${app.jwt.secret}")
    private String jwtSecret;

    @Value("${app.jwt.access-token-expiration}")
    private long accessTokenExpiration;

    @Value("${app.jwt.refresh-token-expiration}")
    private long refreshTokenExpiration;

    private SecretKey getSigningKey() {
        return Keys.hmacShaKeyFor(jwtSecret.getBytes());
    }

    public String generateAccessToken(UserDetails userDetails) {
        return generateAccessToken(userDetails, new HashMap<>());
    }

    public String generateAccessToken(UserDetails userDetails, Map<String, Object> extraClaims) {
        return generateToken(userDetails, extraClaims, accessTokenExpiration, "ACCESS");
    }

    public String generateRefreshToken(UserDetails userDetails) {
        return generateToken(userDetails, new HashMap<>(), refreshTokenExpiration, "REFRESH");
    }

    public String generateRefreshToken(UserDetails userDetails, Map<String, Object> extraClaims) {
        return generateToken(userDetails, extraClaims, refreshTokenExpiration, "REFRESH");
    }

    private String generateToken(UserDetails userDetails, Map<String, Object> extraClaims,
                                 long expiration, String tokenType) {
        Date now = new Date();
        Date expiryDate = new Date(now.getTime() + expiration);

        return Jwts.builder()
                .subject(userDetails.getUsername())
                .issuedAt(now)
                .expiration(expiryDate)
                .claim("type", tokenType)
                .claim("authorities", userDetails.getAuthorities())
                .claims(extraClaims)
                .signWith(getSigningKey())
                .compact();
    }

    public String extractUsername(String token) {
        return extractClaim(token, Claims::getSubject);
    }

    public Date extractExpiration(String token) {
        return extractClaim(token, Claims::getExpiration);
    }

    public String extractTokenType(String token) {
        return extractClaim(token, claims -> claims.get("type", String.class));
    }

    public <T> T extractClaim(String token, Function<Claims, T> claimsResolver) {
        final Claims claims = extractAllClaims(token);
        return claimsResolver.apply(claims);
    }

    private Claims extractAllClaims(String token) {
        try {
            return Jwts.parser()
                    .verifyWith(getSigningKey())
                    .build()
                    .parseSignedClaims(token)
                    .getPayload();
        } catch (JwtException e) {
            log.error("Error parsing JWT token: {}", e.getMessage());
            throw e;
        }
    }

    public boolean isTokenExpired(String token) {
        try {
            return extractExpiration(token).before(new Date());
        } catch (JwtException e) {
            return true;
        }
    }

    public boolean isValidToken(String token, UserDetails userDetails) {
        try {
            final String username = extractUsername(token);
            return username.equals(userDetails.getUsername()) && !isTokenExpired(token);
        } catch (JwtException e) {
            log.error("Invalid JWT token: {}", e.getMessage());
            return false;
        }
    }

    public boolean isRefreshToken(String token) {
        try {
            String tokenType = extractTokenType(token);
            return "REFRESH".equals(tokenType);
        } catch (JwtException e) {
            return false;
        }
    }

    public boolean isAccessToken(String token) {
        try {
            String tokenType = extractTokenType(token);
            return "ACCESS".equals(tokenType);
        } catch (JwtException e) {
            return false;
        }
    }

    public long getAccessTokenExpiration() {
        return accessTokenExpiration;
    }

    public long getRefreshTokenExpiration() {
        return refreshTokenExpiration;
    }
}

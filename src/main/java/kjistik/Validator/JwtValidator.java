package kjistik.Validator; // Update with your package

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.Jws;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import io.jsonwebtoken.security.SecurityException;
import kjistik.Validator.Exceptions.JwtAuthorizationException;
import io.jsonwebtoken.MalformedJwtException;

import javax.crypto.SecretKey;
import java.util.Base64;
import java.util.Collections;
import java.util.List;
import java.util.UUID;
import java.util.Arrays;

public class JwtValidator {

    private final SecretKey secretKey;

    public JwtValidator(SecretKey secretKey) {
        this.secretKey = secretKey;
    }

    // Validate token structure and signature (throws on expiration)
    public Jws<Claims> validateToken(String token) {
        try {
            return Jwts.parser()
                    .verifyWith(secretKey)
                    .build()
                    .parseSignedClaims(token);
        } catch (ExpiredJwtException e) {
            throw new JwtAuthorizationException("Token expired", e);
        } catch (SecurityException | MalformedJwtException e) {
            throw new JwtAuthorizationException("Invalid token signature or format", e);
        } catch (JwtException | IllegalArgumentException e) {
            throw new JwtAuthorizationException("Invalid JWT", e);
        }
    }

    // Extract roles from valid token
    public List<String> extractRoles(String token) {
        Claims claims = validateToken(token).getPayload();
        return parseRolesClaim(claims.get("roles"));
    }

    // Extract user ID from valid token
    public UUID extractUserId(String token) {
        try {
            String subject = validateToken(token).getPayload().getSubject();
            return UUID.fromString(subject);
        } catch (IllegalArgumentException e) {
            throw new JwtAuthorizationException("Invalid user ID format in token", e);
        }
    }

    // Helper to create SecretKey from base64 string (optional but useful)
    public static SecretKey createSecretKey(String base64EncodedKey) {
        byte[] keyBytes = Base64.getDecoder().decode(base64EncodedKey);
        return Keys.hmacShaKeyFor(keyBytes);
    }

    // Private helper to handle different role claim formats
    private List<String> parseRolesClaim(Object rolesClaim) {
        if (rolesClaim instanceof List) {
            return ((List<?>) rolesClaim).stream()
                    .filter(String.class::isInstance)
                    .map(String.class::cast)
                    .toList();
        } else if (rolesClaim instanceof String) {
            return Arrays.asList(((String) rolesClaim).split(","));
        }
        return Collections.emptyList();
    }
}
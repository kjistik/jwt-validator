package kjistik.Validator;

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

/**
 * Validates JSON Web Tokens (JWT) and extracts claims from valid tokens.
 * <p>
 * This class provides functionality to:
 * </p>
 * <ul>
 *   <li>Validate JWT signatures and structure</li>
 *   <li>Extract user roles from token claims</li>
 *   <li>Retrieve user IDs from token subjects</li>
 *   <li>Handle common JWT validation exceptions</li>
 * </ul>
 * 
 * @see Jwts
 * @see SecretKey
 */
public class JwtValidator {

    private final SecretKey secretKey;

    /**
     * Constructs a JWT validator with the specified secret key.
     * 
     * @param secretKey The secret key used to verify token signatures
     *                  (must match the key used to sign the tokens)
     */
    public JwtValidator(SecretKey secretKey) {
        this.secretKey = secretKey;
    }

    /**
     * Validates a JWT token's structure and signature.
     * 
     * @param token The JWT token to validate
     * @return Parsed JWT claims if validation succeeds
     * @throws JwtAuthorizationException If the token is:
     *         <ul>
     *           <li>Expired (with root {@link ExpiredJwtException})</li>
     *           <li>Malformed or has invalid signature</li>
     *           <li>Other JWT-related validation failure</li>
     *         </ul>
     */
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

    /**
     * Extracts roles from a valid JWT token's claims.
     * 
     * @param token Valid JWT token containing roles claim
     * @return List of roles (empty list if no roles claim found)
     * @throws JwtAuthorizationException If token validation fails
     * @see #parseRolesClaim(Object) for supported claim formats
     */
    public List<String> extractRoles(String token) {
        Claims claims = validateToken(token).getPayload();
        return parseRolesClaim(claims.get("roles"));
    }

    /**
     * Extracts user ID from a valid JWT token's subject claim.
     * 
     * @param token Valid JWT token with subject claim
     * @return UUID parsed from token's subject
     * @throws JwtAuthorizationException If:
     *         <ul>
     *           <li>Token validation fails</li>
     *           <li>Subject is not a valid UUID</li>
     *         </ul>
     */
    public UUID extractUserId(String token) {
        try {
            String subject = validateToken(token).getPayload().getSubject();
            return UUID.fromString(subject);
        } catch (IllegalArgumentException e) {
            throw new JwtAuthorizationException("Invalid user ID format in token", e);
        }
    }

    /**
     * Creates a SecretKey from a Base64-encoded string.
     * 
     * @param base64EncodedKey Base64-encoded secret key
     * @return HMAC-SHA SecretKey
     * @throws IllegalArgumentException If the key cannot be decoded
     */
    public static SecretKey createSecretKey(String base64EncodedKey) {
        byte[] keyBytes = Base64.getDecoder().decode(base64EncodedKey);
        return Keys.hmacShaKeyFor(keyBytes);
    }

    /**
     * Parses roles claim from different formats. Supports:
     * <ul>
     *   <li>List of strings</li>
     *   <li>Comma-separated string</li>
     * </ul>
     * 
     * @param rolesClaim The raw roles claim object from JWT
     * @return List of role strings (empty list if invalid format)
     */
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

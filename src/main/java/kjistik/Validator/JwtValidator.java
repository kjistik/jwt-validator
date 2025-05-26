package kjistik.Validator;

import java.io.IOException;
import java.io.StringReader;
import java.security.Key;
import java.security.PublicKey;
import java.util.Arrays;
import java.util.Base64;
import java.util.Collections;
import java.util.List;
import java.util.UUID;
import java.util.stream.Collectors;
import javax.crypto.SecretKey;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.Jws;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.MalformedJwtException;
import io.jsonwebtoken.security.Keys;
import io.jsonwebtoken.security.SecurityException;
import kjistik.Validator.Exceptions.JwtAuthorizationException;

/**
 * Validates JSON Web Tokens (JWT) and extracts claims from valid tokens.
 * <p>
 * Supports both symmetric (HMAC) and asymmetric (RSA/ECDSA) algorithms.
 * Provides functionality to:
 * </p>
 * <ul>
 *   <li>Validate JWT signatures and structure</li>
 *   <li>Extract user roles from token claims</li>
 *   <li>Retrieve user IDs from token subjects</li>
 *   <li>Handle common JWT validation exceptions</li>
 *   <li>Convert keys between different formats</li>
 * </ul>
 * 
 * @see Jwts
 * @see SecretKey
 * @see PublicKey
 */
public class JwtValidator {

    /** The cryptographic key used for verification (HMAC or RSA/ECDSA) */
    private final Key key;

    /**
     * Constructs a validator for symmetric HMAC-SHA algorithms.
     * 
     * @param secretKey The shared secret key for HMAC verification
     * @throws IllegalArgumentException if secretKey is null
     */
    public JwtValidator(SecretKey secretKey) {
        this.key = secretKey;
    }

    /**
     * Constructs a validator for asymmetric algorithms (RSA/ECDSA).
     * 
     * @param publicKey The public key for signature verification
     * @throws IllegalArgumentException if publicKey is null
     */
    public JwtValidator(PublicKey publicKey) {
        this.key = publicKey;
    }

    /**
     * Validates a JWT's signature and parses its claims.
     * 
     * @param token The JWT string to validate
     * @return Verified claims contained in the token
     * @throws JwtAuthorizationException for:
     *         <ul>
     *           <li>Expired tokens ({@link ExpiredJwtException})</li>
     *           <li>Invalid signatures ({@link SecurityException})</li>
     *           <li>Malformed JWTs ({@link MalformedJwtException})</li>
     *           <li>General validation failures</li>
     *         </ul>
     */
    public Jws<Claims> validateToken(String token) {
        try {
            if (key instanceof SecretKey) {
                return Jwts.parser()
                        .verifyWith((SecretKey) key)
                        .build()
                        .parseSignedClaims(token);
            } else if (key instanceof PublicKey) {
                return Jwts.parser()
                        .verifyWith((PublicKey) key)
                        .build()
                        .parseSignedClaims(token);
            }
            throw new JwtAuthorizationException("Unsupported key type: " + key.getClass().getName());
        } catch (ExpiredJwtException e) {
            throw new JwtAuthorizationException("Token expired", e);
        } catch (SecurityException | MalformedJwtException e) {
            throw new JwtAuthorizationException("Invalid token signature or format", e);
        } catch (JwtException | IllegalArgumentException e) {
            throw new JwtAuthorizationException("Invalid JWT", e);
        }
    }

    /**
     * Extracts role claims from a validated token.
     * 
     * @param token Valid JWT string
     * @return List of role strings, empty list if no valid roles found
     * @throws JwtAuthorizationException if token validation fails
     * @see #parseRolesClaim(Object)
     */
    public List<String> extractRoles(String token) {
        Claims claims = validateToken(token).getPayload();
        return parseRolesClaim(claims.get("roles"));
    }

    /**
     * Extracts and parses the subject claim as a UUID.
     * 
     * @param token Valid JWT string
     * @return UUID from subject claim
     * @throws JwtAuthorizationException for:
     *         <ul>
     *           <li>Invalid token</li>
     *           <li>Missing/invalid subject</li>
     *           <li>Non-UUID subject format</li>
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
     * Creates HMAC-SHA SecretKey from Base64 string.
     * 
     * @param base64EncodedKey Base64-encoded key bytes
     * @return HMAC-compatible SecretKey
     * @throws IllegalArgumentException for invalid Base64 input
     */
    public static SecretKey createSecretKey(String base64EncodedKey) {
        byte[] keyBytes = Base64.getDecoder().decode(base64EncodedKey);
        return Keys.hmacShaKeyFor(keyBytes);
    }

    /**
     * Parses role claims from JWT payload.
     * 
     * @param rolesClaim Raw claim object from JWT
     * @return Normalized list of role strings. Supports:
     *         <ul>
     *           <li>String arrays/lists</li>
     *           <li>Comma-separated strings</li>
     *         </ul>
     */
    private List<String> parseRolesClaim(Object rolesClaim) {
        if (rolesClaim instanceof List) {
            return ((List<?>) rolesClaim).stream()
                    .filter(String.class::isInstance)
                    .map(String.class::cast)
                    .map(String::trim)
                    .filter(s -> !s.isEmpty())
                    .collect(Collectors.toList());
        } else if (rolesClaim instanceof String) {
            return Arrays.stream(((String) rolesClaim).split(","))
                    .map(String::trim)
                    .filter(s -> !s.isEmpty())
                    .collect(Collectors.toList());
        }
        return Collections.emptyList();
    }

    /**
     * Creates PublicKey from PEM-formatted string.
     * <p>
     * Supports both raw public keys and X.509 certificates.
     * Requires BouncyCastle dependency.
     * </p>
     * 
     * @param pemKey PEM content (public key or certificate)
     * @return Extracted public key
     * @throws IllegalArgumentException for:
     *         <ul>
     *           <li>Invalid PEM content</li>
     *           <li>Unsupported PEM object types</li>
     *         </ul>
     */
    public static PublicKey createPublicKeyFromPem(String pemKey) {
        try (PEMParser parser = new PEMParser(new StringReader(pemKey))) {
            Object parsed = parser.readObject();
            JcaPEMKeyConverter converter = new JcaPEMKeyConverter();

            if (parsed instanceof SubjectPublicKeyInfo) {
                return converter.getPublicKey((SubjectPublicKeyInfo) parsed);
            } else if (parsed instanceof X509CertificateHolder) {
                return converter.getPublicKey(
                    ((X509CertificateHolder) parsed).getSubjectPublicKeyInfo()
                );
            }
            throw new IllegalArgumentException("Unsupported PEM type: " + 
                (parsed != null ? parsed.getClass().getName() : "null"));
        } catch (IOException e) {
            throw new IllegalArgumentException("Invalid PEM key", e);
        }
    }
}

package kjistik.Validator.Exceptions;

/**
 * Exception thrown when JWT validation or claim extraction fails.
 * <p>
 * Wraps root causes like expired tokens, invalid signatures, or malformed claims.
 * </p>
 */
public class JwtAuthorizationException extends RuntimeException {
    
    /**
     * Constructs exception with specified detail message.
     * 
     * @param msg The detail message
     */
    public JwtAuthorizationException(String msg) {
        super(msg);
    }

    /**
     * Constructs exception with detail message and root cause.
     * 
     * @param msg The detail message
     * @param cause The root cause of the exception
     */
    public JwtAuthorizationException(String msg, Throwable cause) {
        super(msg, cause);
    }
}
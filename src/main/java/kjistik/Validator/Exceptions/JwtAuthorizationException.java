package kjistik.Validator.Exceptions;

public class JwtAuthorizationException extends RuntimeException {
    public JwtAuthorizationException(String msg) {
        super(msg);
    }

    public JwtAuthorizationException(String msg, Throwable cause) {
        super(msg, cause);
    }
}

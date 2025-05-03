class TokenRefreshError(Exception):
    """Exception raised when token refresh fails."""
    pass

class SessionError(Exception):
    """Exception raised when session operations fail."""
    pass

class RateLimitError(Exception):
    """Exception raised when rate limit is exceeded."""
    pass

class AuthError(Exception):
    """Base exception for authentication errors."""
    pass

class InvalidCredentialsError(AuthError):
    """Exception raised when credentials are invalid."""
    pass

class TokenExpiredError(AuthError):
    """Exception raised when token is expired."""
    pass

class TokenInvalidError(AuthError):
    """Exception raised when token is invalid."""
    pass

class PermissionDeniedError(AuthError):
    """Exception raised when user doesn't have required permissions."""
    pass 
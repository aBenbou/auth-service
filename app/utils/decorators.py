from functools import wraps
from flask import request, jsonify, g, current_app
from flask_jwt_extended import verify_jwt_in_request, get_jwt_identity

from app.services.auth_service import get_user_by_id
from app.services.token_service import validate_app_token
from app.services.session_service import SessionService
from app.utils.exceptions import RateLimitError, PermissionDeniedError, TokenInvalidError

def get_session_service():
    """Get or create a session service instance."""
    if not hasattr(g, 'session_service'):
        g.session_service = SessionService()
    return g.session_service

def jwt_required_with_permissions(permissions=None, service_name=None):
    """Decorator to check JWT and verify required permissions"""
    def decorator(fn):
        @wraps(fn)
        def wrapper(*args, **kwargs):
            try:
                verify_jwt_in_request()
                user_id = get_jwt_identity()
                
                # Get user and verify permissions
                user = get_user_by_id(user_id)
                if not user:
                    raise TokenInvalidError("User not found")
                
                if permissions:
                    if not user.has_permissions(permissions, service_name):
                        raise PermissionDeniedError("Insufficient permissions")
                
                # Store user in g for access in route
                g.user = user
                g.user_id = user_id
                
                return fn(*args, **kwargs)
            except Exception as e:
                return jsonify({'error': str(e)}), 401
        return wrapper
    return decorator

def app_token_required(fn):
    """Decorator to verify app token"""
    @wraps(fn)
    def wrapper(*args, **kwargs):
        try:
            token = request.headers.get('X-App-Token')
            if not token:
                return jsonify({'error': 'App token is required'}), 401
            
            if not validate_app_token(token):
                return jsonify({'error': 'Invalid app token'}), 401
            
            return fn(*args, **kwargs)
        except Exception as e:
            return jsonify({'error': str(e)}), 401
        
    return wrapper

def rate_limit(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        try:
            user_id = getattr(g, 'user_id', None)
            if user_id:
                endpoint = request.endpoint
                session_service = get_session_service()
                if not session_service.check_rate_limit(user_id, endpoint):
                    raise RateLimitError("Rate limit exceeded")
        except RateLimitError as e:
            return jsonify({'error': str(e)}), 429
        except Exception as e:
            # Log error but allow request to proceed
            current_app.logger.error(f"Rate limit check failed: {str(e)}")

        return f(*args, **kwargs)
    return decorated_function

from functools import wraps
from flask import request, jsonify, g, current_app
from flask_jwt_extended import verify_jwt_in_request, get_jwt_identity

from app.services.auth_service import get_user_by_id
from app.services.token_service import validate_app_token
from app.services.session_service import SessionService
from app.services.service_service import get_service_by_name
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
                    # Get service ID from request path if not provided
                    service_id = None
                    
                    # First try to get service from service_name parameter
                    if service_name:
                        current_app.logger.info(f"Trying to get service by name: {service_name}")
                        service = get_service_by_name(service_name)
                        if not service:
                            raise PermissionDeniedError(f"Service '{service_name}' not found")
                        service_id = service.id
                    
                    # If no service_name provided, try to get from URL parameters
                    if not service_id:
                        current_app.logger.info(f"Trying to get service_id from URL parameters: {request.view_args}")
                        service_id = request.view_args.get('service_id')
                    
                    # If still no service_id, try to get from request path
                    if not service_id:
                        # Try to extract service name from the endpoint
                        endpoint = request.endpoint
                        current_app.logger.info(f"Trying to get service from endpoint: {endpoint}")
                        
                        # Special case for roles blueprint - use auth_service
                        if endpoint and endpoint.startswith('roles.'):
                            current_app.logger.info("Using auth_service for roles blueprint")
                            service = get_service_by_name('auth_service')
                            if service:
                                service_id = service.id
                                current_app.logger.info(f"Found auth_service with ID: {service_id}")
                        else:
                            # Try to get service from the first part of the URL path
                            path_parts = request.path.strip('/').split('/')
                            if len(path_parts) >= 2:  # /api/service_name/...
                                possible_service = path_parts[1]  # Get the service name from the path
                                current_app.logger.info(f"Trying service name from path: {possible_service}")
                                service = get_service_by_name(possible_service)
                                if service:
                                    service_id = service.id
                                    current_app.logger.info(f"Found service with ID: {service_id}")
                    
                    if not service_id:
                        current_app.logger.error("Could not determine service ID from any source")
                        raise PermissionDeniedError("Service ID is required for permission check")
                    
                    current_app.logger.info(f"Checking permissions {permissions} for service {service_id}")
                    if not user.has_permissions(permissions, service_id):
                        raise PermissionDeniedError("Insufficient permissions")
                
                # Store user in g for access in route
                g.user = user
                g.user_id = user_id
                
                return fn(*args, **kwargs)
            except Exception as e:
                current_app.logger.error(f"Permission check failed: {str(e)}")
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

from jose import jwt, jwk
from jose.utils import base64url_decode
from flask import request, jsonify, g
from functools import wraps
import time
import logging


def cognito_jwt_required(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        auth_header = request.headers.get('Authorization', None)
        if not auth_header or not auth_header.startswith("Bearer "):
            return jsonify({"msg": "Missing or invalid Authorization header"}), 401

        token = auth_header.replace("Bearer ", "")
        try:
            # Decode header
            unverified_header = jwt.get_unverified_header(token)
            kid = unverified_header['kid']
            
            # Use the jwks variable that should be defined above or imported correctly
            key = next((k for k in jwks if k['kid'] == kid), None)
            if not key:
                return jsonify({"msg": "Public key not found"}), 401

            # Construct the public key
            public_key = jwk.construct(key)
            message, encoded_signature = str(token).rsplit('.', 1)
            decoded_signature = base64url_decode(encoded_signature.encode('utf-8'))

            if not public_key.verify(message.encode("utf8"), decoded_signature):
                return jsonify({"msg": "Signature verification failed"}), 401

            # Decode token with verification
            claims = jwt.get_unverified_claims(token)
            
            # Check token expiration
            current_time = time.time()
            if claims.get("exp") < current_time:
                return jsonify({"msg": "Token is expired"}), 401

            # Set user info globally
            g.current_user = claims
            # Also set user_id for convenience
            g.user_id = claims.get('sub')

        except Exception as e:
            logging.error(f"Token validation error: {str(e)}")
            return jsonify({"msg": f"Token validation failed: {str(e)}"}), 401

        return fn(*args, **kwargs)
    return wrapper
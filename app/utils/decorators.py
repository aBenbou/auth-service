from functools import wraps
from flask import request, jsonify, g, current_app
from flask_jwt_extended import verify_jwt_in_request, get_jwt_identity

from app.services.auth_service import get_user_by_id
from app.services.token_service import validate_app_token
from app.services.session_service import SessionService
from app.services.service_service import get_service_by_name, get_service_by_id
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
                current_app.logger.info(f"JWT verification successful for user ID: {user_id}")
                current_app.logger.info(f"Checking permissions: {permissions} for service: {service_name}")

                # Get user and verify existence
                user = get_user_by_id(user_id)
                if not user:
                    current_app.logger.error(f"User {user_id} not found")
                    raise TokenInvalidError("User not found")

                # If no permissions required, just authenticate the user
                if not permissions:
                    g.user = user
                    g.current_user = user
                    g.user_id = user_id
                    return fn(*args, **kwargs)

                # Resolve service_id based on available information
                service_id = None

                # 1. Try to get service from provided service_name parameter
                if service_name:
                    current_app.logger.info(f"Looking up service by name: {service_name}")
                    service = get_service_by_name(service_name)
                    if service:
                        service_id = service.id
                        print(service, 'serviceserviceservice')
                        print(service_id, 'serviceserviceserviceservice')
                        current_app.logger.info(f"Found service by name: {service_name}, ID: {service_id}")

                # 2. If no service_id yet, try to get from URL parameters
                if not service_id:
                    service_id_param = request.view_args.get('service_id')
                    if service_id_param:
                        current_app.logger.info(f"Found service_id in URL parameters: {service_id_param}")
                        # Handle both numeric IDs and UUID strings
                        if isinstance(service_id_param, str) and not service_id_param.isdigit():
                            service = get_service_by_id(service_id_param)
                            if service:
                                service_id = service.id
                        else:
                            service_id = service_id_param

                # 3. If still no service_id, check endpoint for special cases
                if not service_id:
                    endpoint = request.endpoint
                    current_app.logger.info(f"Checking endpoint for service info: {endpoint}")

                    auth_related_patterns = [
                        'roles.', 'permissions.', 'services.', 'users.', 'auth.',
                        'login', 'register', 'reset_password', 'verify_email',
                        'app_token', 'user_service_role'
                    ]

                    is_auth_endpoint = False
                    if endpoint:
                        for pattern in auth_related_patterns:
                            if pattern in endpoint:
                                is_auth_endpoint = True
                                break

                    # Check if URL path contains auth-related segments
                    if not is_auth_endpoint:
                        path = request.path.lower()
                        auth_url_patterns = [
                            '/api/auth/', '/api/roles/', '/api/permissions/',
                            '/api/services/', '/api/users/', '/api/app-tokens/',
                            '/auth/', '/roles/', '/permissions/'
                        ]
                        for pattern in auth_url_patterns:
                            if pattern in path:
                                is_auth_endpoint = True
                                break

                    if is_auth_endpoint:
                        current_app.logger.info("Detected auth service related endpoint, using auth_service")
                        service = get_service_by_name('auth_service')
                        if service:
                            service_id = service.id

                    # Try to derive service name from endpoint prefix if still no service_id
                    elif endpoint:
                        parts = endpoint.split('.')
                        if parts and len(parts) > 0:
                            possible_service = parts[0]
                            current_app.logger.info(
                                f"Trying to derive service from endpoint prefix: {possible_service}")
                            service = get_service_by_name(possible_service)
                            if service:
                                service_id = service.id

                # 4. Last resort: try to extract from URL path
                if not service_id:
                    path_parts = request.path.strip('/').split('/')
                    if len(path_parts) >= 2:
                        possible_service = path_parts[1]
                        current_app.logger.info(f"Trying to extract service from URL path: {possible_service}")
                        service = get_service_by_name(possible_service)
                        if service:
                            service_id = service.id

                # If we still couldn't determine service_id, fail with clear error
                if not service_id:
                    current_app.logger.error(f"Failed to determine service ID for permission check: {request.path}")
                    raise PermissionDeniedError("Could not determine which service to check permissions for")

                # Check permissions
                current_app.logger.info(
                    f"Checking if user {user_id} has permissions {permissions} for service {service_id}")
                if not user.has_permissions(permissions, service_id):
                    current_app.logger.warning(
                        f"Permission denied: User {user_id} lacks permissions {permissions} for service {service_id}")
                    raise PermissionDeniedError("Insufficient permissions")

                # Store user in g for access in route
                g.user = user
                g.current_user = user
                g.user_id = user_id

                return fn(*args, **kwargs)

            except TokenInvalidError as e:
                current_app.logger.error(f"Token invalid: {str(e)}")
                return jsonify({'error': 'Invalid token', 'message': str(e)}), 401

            except PermissionDeniedError as e:
                current_app.logger.error(f"Permission denied: {str(e)}")
                return jsonify({'error': 'Permission denied', 'message': str(e)}), 403

            except Exception as e:
                current_app.logger.error(f"Authentication error: {str(e)}")
                return jsonify({'error': 'Authentication failed', 'message': str(e)}), 401

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
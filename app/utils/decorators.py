from functools import wraps
from flask import request, jsonify, g
from flask_jwt_extended import verify_jwt_in_request, get_jwt_identity

from app.services.auth_service import get_user_by_id
from app.services.token_service import validate_app_token


def jwt_required_with_permissions(permissions=None, service_name=None):
    """Decorator to check JWT and verify required permissions"""
    def decorator(fn):
        @wraps(fn)
        def wrapper(*args, **kwargs):
            try:
                # Verify JWT is present and valid
                verify_jwt_in_request()
                
                # Get user identity from JWT
                user_id = get_jwt_identity()
                
                # Get user from database
                user = get_user_by_id(user_id)
                if not user:
                    return jsonify({'success': False, 'message': 'User not found'}), 404
                
                # Store user in g for access in the route
                g.current_user = user
                
                # If no permissions required, proceed
                if not permissions:
                    return fn(*args, **kwargs)
                
                # Get service ID if needed for permission check
                service = None
                if service_name:
                    from app.models.service import Service
                    service = Service.query.filter_by(name=service_name).first()
                    
                    if not service:
                        return jsonify({'success': False, 'message': 'Service not found'}), 404
                
                # Use auth_service if no service specified
                service_id = service.id if service else 1  # Assuming auth_service has ID 1
                
                # Check if user has all required permissions
                for permission in permissions:
                    if not user.has_permission(permission, service_id):
                        return jsonify({
                            'success': False, 
                            'message': f'Permission denied: {permission} required'
                        }), 403
                
                return fn(*args, **kwargs)
                
            except Exception as e:
                return jsonify({'success': False, 'message': f'Authentication error: {str(e)}'}), 401
                
        return wrapper
    return decorator


def app_token_required(fn):
    """Decorator to check for valid app token in Authorization header"""
    @wraps(fn)
    def wrapper(*args, **kwargs):
        auth_header = request.headers.get('Authorization')
        
        if not auth_header or not auth_header.startswith('Bearer '):
            return jsonify({'success': False, 'message': 'Missing or invalid Authorization header'}), 401
        
        # Extract token
        token = auth_header.split('Bearer ')[1]
        
        # Validate token
        service = validate_app_token(token)
        
        if not service:
            return jsonify({'success': False, 'message': 'Invalid or expired token'}), 401
        
        # Store service in g for access in the route
        g.current_service = service
        
        return fn(*args, **kwargs)
        
    return wrapper 
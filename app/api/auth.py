from flask import Blueprint, request, jsonify, g
from flask_jwt_extended import (
    get_jwt_identity, 
    jwt_required, 
    get_jwt,
    create_access_token
)
from app.services.auth_service import (
    register_user,
    verify_email,
    login_user,
    logout_user,
    change_password,
    get_user_by_id
)
from app.services.redis_service import (
    get_user_sessions,
    remove_user_session,
    invalidate_all_user_sessions,
    get_active_sessions_count
)
from app.utils.decorators import jwt_required_with_permissions, rate_limit
from app.services.session_service import SessionService
from app.utils.exceptions import TokenRefreshError, RateLimitError

auth_bp = Blueprint('auth', __name__)
session_service = SessionService()

@auth_bp.route('/register', methods=['POST'])
def register():
    """Register a new user"""
    data = request.get_json()
    
    # Validate required fields
    if not data or not data.get('email') or not data.get('password'):
        return jsonify({'success': False, 'message': 'Email and password are required'}), 400
    
    result = register_user(
        email=data.get('email'),
        password=data.get('password'),
        first_name=data.get('first_name'),
        last_name=data.get('last_name')
    )
    
    if result['success']:
        return jsonify(result), 201
    else:
        return jsonify(result), 400


@auth_bp.route('/verify-email/<token>', methods=['GET'])
def verify_email_route(token):
    """Verify a user's email using token"""
    result = verify_email(token)
    
    if result['success']:
        return jsonify(result), 200
    else:
        return jsonify(result), 400


@auth_bp.route('/login', methods=['POST'])
def login():
    """Authenticate a user and return JWT tokens"""
    data = request.get_json()
    
    # Validate required fields
    if not data or not data.get('email') or not data.get('password'):
        return jsonify({'success': False, 'message': 'Email and password are required'}), 400
    
    result = login_user(
        email=data.get('email'),
        password=data.get('password')
    )
    
    if result['success']:
        return jsonify(result), 200
    elif result.get('needs_verification'):
        return jsonify(result), 403
    else:
        return jsonify(result), 401


@auth_bp.route('/logout', methods=['POST'])
@jwt_required()
@rate_limit
def logout():
    """Invalidate user session"""
    try:
        user_id = get_jwt_identity()
        session_service.invalidate_session(user_id)
        return jsonify({'message': 'Successfully logged out'}), 200
    except Exception as e:
        return jsonify({'error': 'Internal server error'}), 500


@auth_bp.route('/refresh', methods=['POST'])
@rate_limit
def refresh_token():
    """Refresh access token using refresh token"""
    try:
        refresh_token = request.json.get('refresh_token')
        if not refresh_token:
            return jsonify({'error': 'Refresh token is required'}), 400
        
        result = session_service.refresh_session(refresh_token)
        return jsonify(result), 200
    except TokenRefreshError as e:
        return jsonify({'error': str(e)}), 401
    except Exception as e:
        return jsonify({'error': 'Internal server error'}), 500


@auth_bp.route('/change-password', methods=['POST'])
@jwt_required()
def change_password_route():
    """Change user's password (requires current password)"""
    user_id = get_jwt_identity()
    jti = get_jwt()['jti']
    data = request.get_json()
    
    # Validate required fields
    if not data or not data.get('current_password') or not data.get('new_password'):
        return jsonify({
            'success': False, 
            'message': 'Current password and new password are required'
        }), 400
    
    result = change_password(
        user_id=user_id,
        current_password=data.get('current_password'),
        new_password=data.get('new_password')
    )
    
    if result['success']:
        # Keep current session but invalidate all others
        user = get_user_by_id(user_id)
        invalidate_all_user_sessions(user.id)
        
        # Add back the current session
        from app.services.redis_service import add_user_session
        add_user_session(user.id, jti)
        
        return jsonify(result), 200
    else:
        return jsonify(result), 400


@auth_bp.route('/sessions', methods=['GET'])
@jwt_required_with_permissions()
def get_user_sessions_route():
    """Get all active sessions for the current user"""
    user = g.current_user
    
    sessions = get_user_sessions(user.id)
    
    return jsonify({
        'success': True,
        'sessions': sessions
    }), 200


@auth_bp.route('/sessions/<session_id>', methods=['DELETE'])
@jwt_required_with_permissions()
def delete_session(session_id):
    """Delete a specific session"""
    user = g.current_user
    
    success = remove_user_session(user.id, session_id)
    
    if success:
        return jsonify({
            'success': True,
            'message': 'Session deleted successfully'
        }), 200
    else:
        return jsonify({
            'success': False,
            'message': 'Session not found or already deleted'
        }), 404


@auth_bp.route('/sessions', methods=['DELETE'])
@jwt_required_with_permissions()
def delete_all_sessions():
    """Delete all sessions except the current one"""
    user = g.current_user
    jti = get_jwt()['jti']
    
    # Invalidate all sessions
    invalidate_all_user_sessions(user.id)
    
    # Add back the current session
    from app.services.redis_service import add_user_session
    add_user_session(user.id, jti)
    
    return jsonify({
        'success': True,
        'message': 'All other sessions deleted successfully'
    }), 200


@auth_bp.route('/me', methods=['GET'])
@jwt_required()
def get_user_profile():
    """Get the current user's profile"""
    user_id = get_jwt_identity()
    
    # Get user from database
    user = get_user_by_id(user_id)
    if not user:
        return jsonify({'success': False, 'message': 'User not found'}), 404
    
    return jsonify({
        'success': True,
        'user': user.to_dict()
    }), 200


@auth_bp.route('/sessions/stats', methods=['GET'])
@jwt_required_with_permissions(['user:read'])
def get_sessions_stats():
    """Get statistics about active sessions"""
    active_count = get_active_sessions_count()
    
    return jsonify({
        'success': True,
        'active_sessions': active_count
    }), 200 

@auth_bp.route('/validate-jwt', methods=['GET'])
@jwt_required()
def validate_jwt():
    """Validate a user JWT token (used by other microservices)"""
    user_id = get_jwt_identity()
    user = get_user_by_id(user_id)
    
    if not user:
        return jsonify({'success': False, 'message': 'User not found'}), 404
    
    return jsonify({
        'success': True,
        'user_id': user_id,
        'user': user.to_dict()
    }), 200
import boto3
import os
import jwt 
import logging
from flask import Blueprint, request, jsonify, g, current_app
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
    change_password,
    get_user_by_id,
    get_secret_hash,
    logout_user,
    cognito_login_user,
    change_password_authenticated
)
from app.services.redis_service import (
    get_user_sessions,
    remove_user_session,
    invalidate_all_user_sessions,
    get_active_sessions_count
)
from app.utils.decorators import (
    jwt_required_with_permissions, 
    rate_limit,
    cognito_jwt_required
)


auth_bp = Blueprint('auth', __name__)


USER_POOL_ID = os.getenv('USER_POOL_ID')
CLIENT_ID = os.getenv('CLIENT_ID')
CLIENT_SECRET = os.getenv('CLIENT_SECRET')
client=boto3.client('cognito-idp', region_name='us-east-1')


@auth_bp.route('/register', methods=['POST'])
def register():
    """Register a new user"""
    data = request.get_json()
    current_app.logger.info("Registering new user")
    # Validate required fields
    if not data or not data.get('email') or not data.get('password'):
        current_app.logger.warning("Missing email or password during registration")
        return jsonify({'success': False, 'message': 'Email and password are required'}), 400
    try:
        secret_hash = get_secret_hash(data.get('email'), CLIENT_ID, CLIENT_SECRET)
        # Create user in AWS Cognito
        response = client.sign_up(
            ClientId=CLIENT_ID,
            SecretHash=secret_hash,
            Username=data.get('email'),
            Password=data.get('password'),
            UserAttributes=[
                {'Name': 'email', 'Value': data.get('email')},
                {'Name': 'given_name', 'Value': data.get('first_name') or ''},
                {'Name': 'family_name', 'Value': data.get('last_name') or ''}
            ]
        )
        print("Cognito sign_up response:", response)

        # Register user in local DB (no password saved locally)
        current_app.logger.info("Cognito sign_up response: %s", response)
        result = register_user(
            email=data.get('email'),
            first_name=data.get('first_name'),
            last_name=data.get('last_name'),
            password=data.get('password')
        )
        if result['success']:
            current_app.logger.info("User registered successfully")
            return jsonify(result), 201
        else:
            current_app.logger.warning("User registration failed in DB: %s", result)
            return jsonify(result), 400

    except client.exceptions.UsernameExistsException:
        current_app.logger.warning("User already exists in Cognito")
        return jsonify({'success': False, 'message': 'User already exists in Cognito'}), 400
    except Exception as e:
        current_app.logger.error("Error registering user: %s", str(e))
        return jsonify({'success': False, 'message': f'Error registering user: {str(e)}'}), 500


@auth_bp.route('/verify-email/<token>', methods=['POST'])
def verify_email_route(token):
    """Verify a user's email using token"""
    current_app.logger.info("Verifying email with token")
    data = request.get_json()
    email = data.get('email')
    if not email:
        current_app.logger.warning("Email missing in verify-email request")
        return jsonify({'success': False, 'message': 'Username is required'}), 400

    result = verify_email(email, token, CLIENT_ID)

    if result['success']:
        current_app.logger.info("Email verified successfully")
        return jsonify(result), 200
    else:
        current_app.logger.warning("Email verification failed: %s", result)
        return jsonify(result), 400


@auth_bp.route('/login', methods=['POST'])
def login():
    """Authenticate a user and return JWT tokens"""
    current_app.logger.info("User login attempt")
    data = request.get_json()

    # Validate required fields
    if not data or not data.get('email') or not data.get('password'):
        current_app.logger.warning("Missing email or password during login")
        return jsonify({'success': False, 'message': 'Email and password are required'}), 400

    result = login_user(
        email=data.get('email'),
        password=data.get('password')
    )

    if result['success']:
        current_app.logger.info("Login successful for user: %s", data.get('email'))
        return jsonify(result), 200
    elif result.get('needs_verification'):
        current_app.logger.warning("Login failed, email needs verification: %s", data.get('email'))
        return jsonify(result), 403
    else:
        current_app.logger.warning("Login failed: %s", data.get('email'))
        return jsonify(result), 401


@auth_bp.route('/logout', methods=['POST'])
@jwt_required()
def logout():
    """Log out the current user"""
    user_id = get_jwt_identity()
    jti = get_jwt()['jti']
    current_app.logger.info("Logging out user: %s", user_id)
    result = logout_user(user_id, jti)

    if result['success']:
        current_app.logger.info("Logout successful")
        return jsonify(result), 200
    else:
        current_app.logger.warning("Logout failed")
        return jsonify(result), 400


@auth_bp.route('/refresh', methods=['POST'])
@jwt_required(refresh=True)
@rate_limit
def refresh_token():
    """Get a new access token using refresh token"""
    user_id = get_jwt_identity()

    # Verify user exists
    user = get_user_by_id(user_id)
    current_app.logger.info("Refreshing token for user: %s", user_id)
    if not user:
        current_app.logger.warning("User not found during token refresh: %s", user_id)
        return jsonify({'success': False, 'message': 'User not found'}), 404

    # Create a new access token
    access_token = create_access_token(identity=user_id)
    current_app.logger.info("Access token refreshed successfully")
    return jsonify({
        'success': True,
        'access_token': access_token
    }), 200


@auth_bp.route('/change-password', methods=['POST'])
@jwt_required()
def change_password_route():
    """Change user's password (requires current password)"""
    user_id = get_jwt_identity()
    jti = get_jwt()['jti']
    data = request.get_json()

    user = get_user_by_id(user_id)
    email = user.email
    current_app.logger.info("Changing password for user: %s", user_id)

    # Validate required fields
    if not data or not data.get('current_password') or not data.get('new_password'):
        current_app.logger.warning("Missing current or new password")
        return jsonify({
            'success': False,
            'message': 'Current password and new password are required'
        }), 400

    result = cognito_login_user(email, data.get('current_password'))
    access_token = result['access_token']
    change_password_authenticated(access_token, data.get('current_password'), data.get('new_password'))
    result = change_password(
        user_id=user_id,
        current_password=data.get('current_password'),
        new_password=data.get('new_password')
    )

    if result['success']:
        current_app.logger.info("Password changed successfully")
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
    current_app.logger.info("Fetching sessions for user: %s", user.id)
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
    current_app.logger.info("Deleting session %s for user: %s", session_id, user.id)
    if success:
        current_app.logger.info("Session deleted successfully")
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
    current_app.logger.info("Deleting all sessions for user: %s", user.id)
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
    current_app.logger.info("Fetching profile for user: %s", user_id)

    if not user:
        current_app.logger.warning("User not found: %s", user_id)
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
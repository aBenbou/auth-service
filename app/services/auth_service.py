import uuid
import secrets
import requests
from datetime import datetime, timedelta
from flask import current_app
from flask_jwt_extended import create_access_token, create_refresh_token, decode_token, verify_jwt_in_request
from app import db
from app.models.user import User
from app.services.redis_service import add_user_session, remove_user_session, invalidate_all_user_sessions
from app.services.email_service import send_password_reset_email, send_verification_email
from typing import Dict, Any, Optional
from jwt.exceptions import PyJWTError

def register_user(email, password, first_name=None, last_name=None):
    """Register a new user and send verification email"""
    # Check if user already exists
    if User.query.filter_by(email=email).first():
        return {'success': False, 'message': 'Email already registered'}
    
    # Create new user
    user = User(
        email=email,
        first_name=first_name,
        last_name=last_name,
        is_email_verified=False,
        email_verification_token=secrets.token_urlsafe(32)
    )
    user.password = password
    
    db.session.add(user)
    db.session.commit()
    
    # Send verification email
    send_verification_email(user)
    
    return {'success': True, 'message': 'User registered successfully', 'user_id': user.public_id}


def verify_email(token):
    """Verify a user's email using the verification token"""
    user = User.query.filter_by(email_verification_token=token).first()
    
    if not user:
        return {'success': False, 'message': 'Invalid verification token'}
    
    user.is_email_verified = True
    user.email_verification_token = None
    db.session.commit()
    
    return {'success': True, 'message': 'Email verified successfully'}


def login_user(email, password):
    """Authenticate a user and return JWT tokens"""
    user = User.query.filter_by(email=email).first()
    
    if not user or not user.verify_password(password):
        return {'success': False, 'message': 'Invalid email or password'}
    
    if not user.is_active:
        return {'success': False, 'message': 'Account is deactivated'}
    
    if not user.is_email_verified:
        return {'success': False, 'message': 'Email not verified', 'needs_verification': True}
    
    # Update last login time
    user.last_login = datetime.utcnow()
    db.session.commit()
    
    # Create JWT tokens
    access_token = create_access_token(identity=user.public_id)
    refresh_token = create_refresh_token(identity=user.public_id)
    
    # Add session to Redis for tracking
    add_user_session(user.id, access_token)
    
    return {
        'success': True,
        'access_token': access_token,
        'refresh_token': refresh_token,
        'user': user.to_dict()
    }


def logout_user(user_id, token_jti):
    """Log out a user by invalidating their session"""
    user = User.query.filter_by(public_id=user_id).first()
    
    if not user:
        return {'success': False, 'message': 'User not found'}
    
    # Remove the session from Redis
    if remove_user_session(user.id, token_jti):
        return {'success': True, 'message': 'Logged out successfully'}
    
    return {'success': False, 'message': 'Session not found'}


def get_user_by_id(user_id):
    """Get user by their public ID"""
    user = User.query.filter_by(public_id=user_id).first()
    
    if not user:
        return None
    
    return user


def request_password_reset(email):
    """Generate a password reset token and send reset email"""
    user = User.query.filter_by(email=email).first()
    
    if not user:
        # Don't reveal whether the email exists for security reasons
        return {'success': True, 'message': 'If your email is registered, you will receive a password reset link'}
    
    # Generate reset token
    reset_token = secrets.token_urlsafe(32)
    expires = datetime.utcnow() + timedelta(seconds=current_app.config['PASSWORD_RESET_TOKEN_EXPIRES'])
    
    user.password_reset_token = reset_token
    user.password_reset_expires = expires
    db.session.commit()
    
    # Send reset email
    send_password_reset_email(user)
    
    return {'success': True, 'message': 'If your email is registered, you will receive a password reset link'}


def reset_password(token, new_password):
    """Reset a user's password using a valid reset token"""
    user = User.query.filter_by(password_reset_token=token).first()
    
    if not user:
        return {'success': False, 'message': 'Invalid or expired reset token'}
    
    if user.password_reset_expires and user.password_reset_expires < datetime.utcnow():
        return {'success': False, 'message': 'Reset token has expired'}
    
    # Update password
    user.password = new_password
    user.password_reset_token = None
    user.password_reset_expires = None
    db.session.commit()
    
    # Invalidate all sessions for security
    invalidate_all_user_sessions(user.id)
    
    return {'success': True, 'message': 'Password reset successful'}


def change_password(user_id, current_password, new_password):
    """Change a user's password (requires current password)"""
    user = User.query.filter_by(public_id=user_id).first()
    
    if not user:
        return {'success': False, 'message': 'User not found'}
    
    if not user.verify_password(current_password):
        return {'success': False, 'message': 'Current password is incorrect'}
    
    # Update password
    user.password = new_password
    db.session.commit()
    
    # Invalidate all other sessions for security
    # We'll keep the current session active
    # This will be handled by the API endpoint
    
    return {'success': True, 'message': 'Password changed successfully'}

def validate_token(token: str) -> Dict[str, Any]:
    """Validate a JWT token directly without making an HTTP request"""
    try:
        # Decode and verify the token directly
        decoded_token = decode_token(token)
        user_id = decoded_token['sub']
        
        # Check if user exists
        user = User.query.filter_by(public_id=user_id).first()
        if not user:
            return {
                'success': False,
                'message': 'User not found'
            }
            
        return {
            'success': True,
            'user_id': user_id,
            'user': user.to_dict()
        }
    except PyJWTError as e:
        current_app.logger.error(f"Invalid token: {str(e)}")
        return {
            'success': False,
            'message': 'Invalid token'
        }
    except Exception as e:
        current_app.logger.error(f"Error validating token: {str(e)}")
        return {
            'success': False,
            'message': 'Error validating token'
        }
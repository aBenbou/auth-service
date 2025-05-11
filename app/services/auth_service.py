import json
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
import hmac
import hashlib
import base64
import boto3
import os

from botocore.exceptions import ClientError

def get_secret(secret_name: str):
    session = boto3.session.Session()
    client = session.client(service_name="secretsmanager", region_name="us-east-1")
    try:
        secret = client.get_secret_value(SecretId=secret_name)
        return secret["SecretString"]

    except ClientError as err:
        print("EXCEPTION: While fetching Secrets: ", err)
        raise err


client=boto3.client('cognito-idp', region_name='us-east-1')

AUTH_SECRETS = json.loads(get_secret("auth_secrets"))
CLIENT_ID = AUTH_SECRETS.get('CLIENT_ID')
CLIENT_SECRET = AUTH_SECRETS.get('CLIENT_SECRET')

def get_secret_hash(username, client_id, client_secret):
    message = username + client_id
    dig = hmac.new(
        str(client_secret).encode('utf-8'),
        msg=message.encode('utf-8'),
        digestmod=hashlib.sha256
    ).digest()
    return base64.b64encode(dig).decode()


def register_user(email, first_name=None, last_name=None, password=None):
    """Register a new Cognito user in the local database"""
    # Check if user already exists in local DB
    if User.query.filter_by(email=email).first():
        return {'success': False, 'message': 'Email already registered'}


    user = User(
        email=email,
        first_name=first_name,
        last_name=last_name,
        is_email_verified=False,
    )
    user.password = password
    
    db.session.add(user)
    db.session.commit()

    return {'success': True, 'message': 'User registered successfully', 'user_id': user.public_id}



def verify_email_with_cognito(username, confirmation_code, client_id):
    """
    Verify the email address of a user using the confirmation code sent by AWS Cognito.
    This method confirms the user's email address based on the confirmation code.

    Args:
    username (str): The email or username of the user.
    confirmation_code (str): The confirmation code the user received via email.
    client_id (str): Your AWS Cognito Client ID.

    Returns:
    dict: Success or failure response with a message.
    """

    try:
        # Call the confirm_sign_up API from AWS Cognito
        secret_hash = get_secret_hash(username, client_id, CLIENT_SECRET)
            
        response = client.confirm_sign_up(
            ClientId=client_id,
            Username=username,
            ConfirmationCode=confirmation_code,
            SecretHash=secret_hash
        )

        return {'success': True, 'message': 'Email verified successfully'}

    except client.exceptions.CodeMismatchException:
        return {'success': False, 'message': 'Invalid confirmation code'}
    except client.exceptions.ExpiredCodeException:
        return {'success': False, 'message': 'Confirmation code expired'}


def verify_email(username, confirmation_code, client_id):
    """Verify a user's email using the verification token"""
    verify_email_with_cognito(username, confirmation_code, client_id)
    user = User.query.filter_by(email=username).first()
    
    if not user:
        return {'success': False, 'message': 'User Not Found'}
    
    user.is_email_verified = True
    user.email_verification_token = None
    db.session.commit()
    
    return {'success': True, 'message': 'Email verified successfully'}


def cognito_login_user(email, password):
    try:

        secret_hash = get_secret_hash(email, CLIENT_ID, CLIENT_SECRET)

        response = client.initiate_auth(
            AuthFlow='USER_PASSWORD_AUTH',
            AuthParameters={
                'USERNAME': email,
                'PASSWORD': password,
                'SECRET_HASH': secret_hash
            },
            ClientId=CLIENT_ID
        )
        # Add session to Redis for tracking
        user = User.query.filter_by(email=email).first()
        add_user_session(user.id, response['AuthenticationResult']['AccessToken'])
        user.last_login = datetime.utcnow()
        db.session.commit()

        return {
            'success': True,
            'message': 'Login successful',
            'access_token': response['AuthenticationResult']['AccessToken'],
            'id_token': response['AuthenticationResult']['IdToken'],
            'refresh_token': response['AuthenticationResult']['RefreshToken']
        }

    except client.exceptions.NotAuthorizedException:
        return {'success': False, 'message': 'Incorrect username or password'}

    except client.exceptions.UserNotConfirmedException:
        return {'success': False, 'message': 'Email not verified', 'needs_verification': True}


def login_user(email, password):

    try:
        """Authenticate a user and return JWT tokens"""
    
        secret_hash = get_secret_hash(email, CLIENT_ID, CLIENT_SECRET)

        response = client.initiate_auth(
            AuthFlow='USER_PASSWORD_AUTH',
            AuthParameters={
                'USERNAME': email,
                'PASSWORD': password,
                'SECRET_HASH': secret_hash
            },
            ClientId=CLIENT_ID
        )

        if 'AuthenticationResult' not in response:
            return {'success': False, 'message': 'Authentication failed: No authentication result'}, 401
            
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
    
    except client.exceptions.NotAuthorizedException:
        return {'success': False, 'message': 'Incorrect username or password'}

    except client.exceptions.UserNotConfirmedException:
        return {'success': False, 'message': 'Email not verified', 'needs_verification': True}


def logout_user(user_id, token_jti):
    """Log out a user by invalidating their session"""
    user = User.query.filter_by(public_id=user_id).first()
    
    if not user:
        return {'success': False, 'message': 'User not found'}
    
    # Remove the session from Redis
    if remove_user_session(user.id, token_jti):
        return {'success': True, 'message': 'Logged out successfully'}
    
    return {'success': False, 'message': 'Session not found'}


def change_password_authenticated(access_token, current_password, new_password):
    """
    Change password for an authenticated user (requires valid access token)
    
    Args:
        access_token: Cognito access token (not JWT)
        current_password: User's current password
        new_password: User's new password
        
    Returns:
        tuple: (success_dict, status_code)
    """
    try:
        # Call Cognito API to change password
        response = client.change_password(
            PreviousPassword=current_password,
            ProposedPassword=new_password,
            AccessToken=access_token
        )
        
        print(f"Cognito change_password response: {response}")
        
        # If we reach here, the operation was successful
        return {'success': True, 'message': 'Password changed successfully'}, 200
        
    except client.exceptions.InvalidPasswordException as e:
        print(f"InvalidPasswordException: {str(e)}")
        return {
            'success': False, 
            'message': 'Password does not meet requirements',
            'details': str(e)
        }, 400
        
    except client.exceptions.NotAuthorizedException as e:
        print(f"NotAuthorizedException: {str(e)}")
        return {'success': False, 'message': 'Incorrect current password'}, 401
        
    except client.exceptions.LimitExceededException as e:
        print(f"LimitExceededException: {str(e)}")
        return {
            'success': False, 
            'message': 'Attempt limit exceeded, please try again later'
        }, 429
        
    except Exception as e:
        print(f"Unexpected error changing password: {str(e)}")
        return {'success': False, 'message': 'Password change failed'}, 500


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

    print(CLIENT_ID)
    secret_hash = get_secret_hash(email, CLIENT_ID, CLIENT_SECRET)

    try:
        response = client.forgot_password(
            ClientId=CLIENT_ID,
            Username=email,
            SecretHash=secret_hash,
        )

    except Exception as e:
        print("Unexpected error:", str(e))
        return {"error": str(e)}

    return {'success': True, 'message': 'If your email is registered, you will receive a token'}


def reset_password(token, new_password, email):
    """Reset a user's password using a valid reset token"""
    user = User.query.filter_by(email=email).first()
    
    if not user:
        return {'success': False, 'message': 'User email not found'}

    try:
        secret_hash = get_secret_hash(email, CLIENT_ID, CLIENT_SECRET)
        response = client.confirm_forgot_password(
            ClientId=CLIENT_ID,
            Username=email,
            ConfirmationCode=token,
            Password=new_password,
            SecretHash=secret_hash,
        )
    except Exception as e:
        print("Unexpected error:", str(e))
        return {"error": str(e)}

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
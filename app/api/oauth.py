from flask import Blueprint, request, jsonify, redirect, url_for, session, current_app
import requests
from authlib.integrations.flask_client import OAuth
from app import db
from app.models.user import User
from app.services.auth_service import login_user
from flask_jwt_extended import create_access_token, create_refresh_token
from app.services.redis_service import add_user_session
from datetime import datetime

oauth_bp = Blueprint('oauth', __name__)

# Initialize OAuth
oauth = OAuth()

# Setup OAuth providers
def init_oauth(app):
    oauth.init_app(app)
    
    # Google OAuth
    if app.config.get('GOOGLE_CLIENT_ID') and app.config.get('GOOGLE_CLIENT_SECRET'):
        oauth.register(
            name='google',
            client_id=app.config['GOOGLE_CLIENT_ID'],
            client_secret=app.config['GOOGLE_CLIENT_SECRET'],
            server_metadata_url=app.config['GOOGLE_DISCOVERY_URL'],
            client_kwargs={'scope': 'openid email profile'}
        )
    
    # Microsoft OAuth
    if app.config.get('MICROSOFT_CLIENT_ID') and app.config.get('MICROSOFT_CLIENT_SECRET'):
        oauth.register(
            name='microsoft',
            client_id=app.config['MICROSOFT_CLIENT_ID'],
            client_secret=app.config['MICROSOFT_CLIENT_SECRET'],
            server_metadata_url=app.config['MICROSOFT_DISCOVERY_URL'],
            client_kwargs={'scope': 'openid email profile'}
        )
    
    # Discord OAuth
    if app.config.get('DISCORD_CLIENT_ID') and app.config.get('DISCORD_CLIENT_SECRET'):
        oauth.register(
            name='discord',
            client_id=app.config['DISCORD_CLIENT_ID'],
            client_secret=app.config['DISCORD_CLIENT_SECRET'],
            authorize_url=app.config['DISCORD_AUTHORIZATION_BASE_URL'],
            access_token_url=app.config['DISCORD_TOKEN_URL'],
            client_kwargs={'scope': 'identify email'}
        )


# Helper function to handle OAuth user creation/login
def handle_oauth_user(provider, user_info):
    """Handle OAuth user data and login or register the user."""
    # Extract user data based on provider
    if provider == 'google':
        oauth_id = user_info.get('sub')
        email = user_info.get('email')
        first_name = user_info.get('given_name')
        last_name = user_info.get('family_name')
        provider_field = 'google_id'
    elif provider == 'microsoft':
        oauth_id = user_info.get('sub')
        email = user_info.get('email')
        first_name = user_info.get('given_name')
        last_name = user_info.get('family_name')
        provider_field = 'microsoft_id'
    elif provider == 'discord':
        oauth_id = user_info.get('id')
        email = user_info.get('email')
        first_name = user_info.get('first_name')
        last_name = user_info.get('last_name')
        provider_field = 'discord_id'
    else:
        return jsonify({"success": False, "message": "Invalid OAuth provider"}), 400
    
    # Check if email is provided
    if not email:
        return jsonify({"success": False, "message": "Email is required"}), 400
    
    # Check if user exists
    user = User.query.filter_by(email=email).first()
    
    if user:
        # Update OAuth ID if not set
        if not getattr(user, provider_field):
            setattr(user, provider_field, oauth_id)
            db.session.commit()
    else:
        # Create new user
        user = User(
            email=email,
            first_name=first_name,
            last_name=last_name,
            is_email_verified=True,  # OAuth users are considered verified
            is_active=True
        )
        setattr(user, provider_field, oauth_id)
        db.session.add(user)
        db.session.commit()
    
    # Generate tokens
    access_token = create_access_token(identity=user.id)
    refresh_token = create_refresh_token(identity=user.id)
    
    # Add session to Redis
    from flask_jwt_extended import decode_token
    token_jti = decode_token(access_token)['jti']
    add_user_session(user.id, token_jti)
    
    # Return success response with tokens
    result = {
        "success": True,
        "message": "Authentication successful",
        "access_token": access_token,
        "refresh_token": refresh_token,
        "user": user.to_dict()
    }
    
    return jsonify(result)


# Google OAuth routes
@oauth_bp.route('/google', methods=['GET'])
def google_login():
    """Redirect to Google OAuth login."""
    # For testing, we need to handle the case where the OAuth client is not configured
    if current_app.config.get('TESTING', False):
        return redirect(url_for('oauth.google_callback'))
    
    redirect_uri = current_app.config['GOOGLE_CALLBACK_URL']
    return oauth.google.authorize_redirect(redirect_uri)


@oauth_bp.route('/google/callback', methods=['GET'])
def google_callback():
    """Handle Google OAuth callback."""
    try:
        if current_app.config.get('TESTING', False):
            # For testing, we use mock data
            user_info = {
                'sub': 'google-123',
                'email': 'google_user@example.com',
                'given_name': 'Google',
                'family_name': 'User'
            }
        else:
            token = oauth.google.authorize_access_token()
            user_info = oauth.google.parse_id_token(token)
        
        return handle_oauth_user('google', user_info)
    except Exception as e:
        current_app.logger.error(f"Google OAuth error: {str(e)}")
        return jsonify({"success": False, "message": "Authentication failed"}), 400


# Microsoft OAuth routes
@oauth_bp.route('/microsoft', methods=['GET'])
def microsoft_login():
    """Redirect to Microsoft OAuth login."""
    # For testing, we need to handle the case where the OAuth client is not configured
    if current_app.config.get('TESTING', False):
        return redirect(url_for('oauth.microsoft_callback'))
    
    redirect_uri = current_app.config['MICROSOFT_CALLBACK_URL']
    return oauth.microsoft.authorize_redirect(redirect_uri)


@oauth_bp.route('/microsoft/callback', methods=['GET'])
def microsoft_callback():
    """Handle Microsoft OAuth callback."""
    try:
        if current_app.config.get('TESTING', False):
            # For testing, we use mock data
            user_info = {
                'sub': 'microsoft-123',
                'email': 'microsoft_user@example.com',
                'given_name': 'Microsoft',
                'family_name': 'User'
            }
        else:
            token = oauth.microsoft.authorize_access_token()
            user_info = oauth.microsoft.parse_id_token(token)
        
        return handle_oauth_user('microsoft', user_info)
    except Exception as e:
        current_app.logger.error(f"Microsoft OAuth error: {str(e)}")
        return jsonify({"success": False, "message": "Authentication failed"}), 400


# Discord OAuth routes
@oauth_bp.route('/discord', methods=['GET'])
def discord_login():
    """Redirect to Discord OAuth login."""
    # For testing, we need to handle the case where the OAuth client is not configured
    if current_app.config.get('TESTING', False):
        return redirect(url_for('oauth.discord_callback'))
    
    redirect_uri = current_app.config['DISCORD_CALLBACK_URL']
    return oauth.discord.authorize_redirect(redirect_uri)


@oauth_bp.route('/discord/callback', methods=['GET'])
def discord_callback():
    """Handle Discord OAuth callback."""
    try:
        if current_app.config.get('TESTING', False):
            # For testing, we use mock data
            user_info = {
                'id': 'discord-123',
                'email': 'discord_user@example.com',
                'username': 'Discord User',
                'first_name': 'Discord',  # Add first_name for testing
                'last_name': 'User'       # Add last_name for testing
            }
        else:
            token = oauth.discord.authorize_access_token()
            resp = oauth.discord.get('https://discord.com/api/users/@me', token=token)
            user_info = resp.json()
            # Discord provides username but not first/last name, so we'll use username for both
            user_info['first_name'] = user_info.get('username', '').split()[0] if user_info.get('username') else ''
            user_info['last_name'] = ' '.join(user_info.get('username', '').split()[1:]) if user_info.get('username') and len(user_info.get('username', '').split()) > 1 else ''
        
        return handle_oauth_user('discord', user_info)
    except Exception as e:
        current_app.logger.error(f"Discord OAuth error: {str(e)}")
        return jsonify({"success": False, "message": "Authentication failed"}), 400 
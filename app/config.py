import os
from datetime import timedelta

class Config:
    # Flask configuration
    SECRET_KEY = os.getenv('SECRET_KEY', 'dev-key-change-in-production')
    DEBUG = os.getenv('DEBUG', 'False').lower() in ('true', '1', 't')
    
    # Database configuration
    SQLALCHEMY_DATABASE_URI = os.getenv('DATABASE_URI', 'sqlite:///auth.db')
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    
    # Redis configuration
    REDIS_HOST = os.getenv('REDIS_HOST', 'localhost')
    REDIS_PORT = int(os.getenv('REDIS_PORT', 6379))
    REDIS_DB = int(os.getenv('REDIS_DB', 0))
    REDIS_PASSWORD = os.getenv('REDIS_PASSWORD', None)
    
    # Helper function to parse integer values from env vars that might have comments
    @staticmethod
    def _parse_int_env(env_var, default):
        value = os.getenv(env_var, str(default))
        # Remove any comments (anything after #)
        if '#' in value:
            value = value.split('#')[0].strip()
        return int(value)
    
    # JWT configuration
    JWT_SECRET_KEY = os.getenv('JWT_SECRET_KEY', 'jwt-dev-key-change-in-production')
    JWT_ACCESS_TOKEN_EXPIRES = timedelta(seconds=_parse_int_env('JWT_ACCESS_TOKEN_EXPIRES', 3600))
    JWT_REFRESH_TOKEN_EXPIRES = timedelta(seconds=_parse_int_env('JWT_REFRESH_TOKEN_EXPIRES', 2592000))
    JWT_TOKEN_LOCATION = ['headers']
    
    # Mail configuration
    MAIL_SERVER = os.getenv('MAIL_SERVER', 'smtp.example.com')
    MAIL_PORT = _parse_int_env('MAIL_PORT', 587)
    MAIL_USE_TLS = os.getenv('MAIL_USE_TLS', 'True').lower() in ('true', '1', 't')
    MAIL_USERNAME = os.getenv('MAIL_USERNAME', 'user@example.com')
    MAIL_PASSWORD = os.getenv('MAIL_PASSWORD', 'password')
    MAIL_DEFAULT_SENDER = os.getenv('MAIL_DEFAULT_SENDER', 'noreply@example.com')
    
    # OAuth configuration
    # Google OAuth
    GOOGLE_CLIENT_ID = os.getenv('GOOGLE_CLIENT_ID')
    GOOGLE_CLIENT_SECRET = os.getenv('GOOGLE_CLIENT_SECRET')
    GOOGLE_DISCOVERY_URL = os.getenv('GOOGLE_DISCOVERY_URL', 'https://accounts.google.com/.well-known/openid-configuration')
    
    # Microsoft OAuth
    MICROSOFT_CLIENT_ID = os.getenv('MICROSOFT_CLIENT_ID')
    MICROSOFT_CLIENT_SECRET = os.getenv('MICROSOFT_CLIENT_SECRET')
    MICROSOFT_DISCOVERY_URL = os.getenv('MICROSOFT_DISCOVERY_URL', 'https://login.microsoftonline.com/common/v2.0/.well-known/openid-configuration')
    
    # Discord OAuth
    DISCORD_CLIENT_ID = os.getenv('DISCORD_CLIENT_ID')
    DISCORD_CLIENT_SECRET = os.getenv('DISCORD_CLIENT_SECRET')
    DISCORD_AUTHORIZATION_BASE_URL = os.getenv('DISCORD_AUTHORIZATION_BASE_URL', 'https://discord.com/api/oauth2/authorize')
    DISCORD_TOKEN_URL = os.getenv('DISCORD_TOKEN_URL', 'https://discord.com/api/oauth2/token')
    
    # Application settings
    APP_NAME = os.getenv('APP_NAME', 'Authentication API')
    APP_BASE_URL = os.getenv('APP_BASE_URL', 'http://localhost:5000')
    PASSWORD_RESET_TOKEN_EXPIRES = _parse_int_env('PASSWORD_RESET_TOKEN_EXPIRES', 3600)
    SESSION_LIMIT_PER_USER = _parse_int_env('SESSION_LIMIT_PER_USER', 5)
    
    # OAuth callback URLs
    GOOGLE_CALLBACK_URL = f"{APP_BASE_URL}/api/oauth/google/callback"
    MICROSOFT_CALLBACK_URL = f"{APP_BASE_URL}/api/oauth/microsoft/callback"
    DISCORD_CALLBACK_URL = f"{APP_BASE_URL}/api/oauth/discord/callback" 
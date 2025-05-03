import redis
from datetime import datetime, timedelta
from flask import current_app
from flask_jwt_extended import create_access_token, create_refresh_token, get_jwt_identity, get_jwt
from app.models.user import User
from app.utils.exceptions import TokenRefreshError, SessionError, TokenExpiredError, TokenInvalidError
from app.services.redis_service import get_redis

class SessionService:
    def __init__(self):
        self.redis_client = get_redis()
        self.session_prefix = 'session:'
        self.refresh_prefix = 'refresh:'
        self.rate_limit_prefix = 'rate_limit:'

    def create_session(self, user_id, device_info=None):
        """Create a new session with access and refresh tokens"""
        try:
            # Create tokens
            access_token = create_access_token(identity=user_id)
            refresh_token = create_refresh_token(identity=user_id)
            
            # Store session data
            session_data = {
                'user_id': user_id,
                'device_info': device_info or {},
                'created_at': datetime.utcnow().isoformat(),
                'last_activity': datetime.utcnow().isoformat()
            }
            
            # Store in Redis with expiration
            session_key = f"{self.session_prefix}{user_id}"
            self.redis_client.hmset(session_key, session_data)
            self.redis_client.expire(session_key, current_app.config.get('JWT_ACCESS_TOKEN_EXPIRES', timedelta(hours=1)))
            
            # Store refresh token
            refresh_key = f"{self.refresh_prefix}{refresh_token}"
            self.redis_client.set(refresh_key, user_id, ex=current_app.config.get('JWT_REFRESH_TOKEN_EXPIRES', timedelta(days=30)))
            
            return {
                'access_token': access_token,
                'refresh_token': refresh_token,
                'expires_in': current_app.config.get('JWT_ACCESS_TOKEN_EXPIRES', timedelta(hours=1)).total_seconds()
            }
        except Exception as e:
            raise SessionError(f"Failed to create session: {str(e)}")

    def refresh_session(self, refresh_token):
        """Refresh an existing session"""
        try:
            # Verify refresh token exists
            refresh_key = f"{self.refresh_prefix}{refresh_token}"
            user_id = self.redis_client.get(refresh_key)
            
            if not user_id:
                raise TokenInvalidError("Invalid refresh token")
            
            # Create new access token
            access_token = create_access_token(identity=user_id)
            
            # Update session
            session_key = f"{self.session_prefix}{user_id}"
            self.redis_client.hset(session_key, 'last_activity', datetime.utcnow().isoformat())
            
            return {
                'access_token': access_token,
                'expires_in': current_app.config.get('JWT_ACCESS_TOKEN_EXPIRES', timedelta(hours=1)).total_seconds()
            }
        except TokenInvalidError:
            raise
        except Exception as e:
            raise TokenRefreshError(f"Failed to refresh session: {str(e)}")

    def check_rate_limit(self, user_id, endpoint):
        """Check if user has exceeded rate limit for an endpoint"""
        try:
            if not current_app.config.get('RATE_LIMIT_ENABLED', False):
                return True

            key = f"{self.rate_limit_prefix}{user_id}:{endpoint}"
            current = self.redis_client.get(key)

            if current is None:
                self.redis_client.setex(key, 60, 1)  # 1 request per minute
                return True

            limit = current_app.config.get('RATE_LIMIT_DEFAULT', '1/minute')
            max_requests = int(limit.split('/')[0])

            if int(current) >= max_requests:
                return False

            self.redis_client.incr(key)
            return True
        except Exception as e:
            current_app.logger.error(f"Rate limit check failed: {str(e)}")
            return True

    def invalidate_session(self, user_id):
        """Invalidate a user's session"""
        try:
            session_key = f"{self.session_prefix}{user_id}"
            self.redis_client.delete(session_key)

            # Find and delete all refresh tokens for this user
            pattern = f"{self.refresh_prefix}*"
            for key in self.redis_client.scan_iter(pattern):
                if self.redis_client.get(key) == str(user_id):
                    self.redis_client.delete(key)
        except Exception as e:
            raise SessionError(f"Failed to invalidate session: {str(e)}")

    def update_session_activity(self, user_id):
        """Update last activity timestamp for a session"""
        try:
            session_key = f"{self.session_prefix}{user_id}"
            if self.redis_client.exists(session_key):
                self.redis_client.hset(session_key, 'last_activity', datetime.utcnow().isoformat())
        except Exception as e:
            current_app.logger.error(f"Failed to update session activity: {str(e)}") 
import pytest
from datetime import datetime, timedelta
from unittest.mock import patch, MagicMock
from app.services.session_service import SessionService
from app.utils.exceptions import TokenRefreshError, SessionError

@pytest.fixture
def session_service(mock_redis):
    """Create a session service instance with mocked Redis."""
    service = SessionService()
    service.redis_client = mock_redis
    return service

@pytest.fixture
def mock_redis():
    """Create a mock Redis client."""
    redis_mock = MagicMock()
    redis_mock.hmset = MagicMock()
    redis_mock.expire = MagicMock()
    redis_mock.set = MagicMock()
    redis_mock.get = MagicMock()
    redis_mock.hset = MagicMock()
    redis_mock.delete = MagicMock()
    redis_mock.exists = MagicMock()
    redis_mock.scan_iter = MagicMock()
    redis_mock.incr = MagicMock()
    return redis_mock

def test_create_session(session_service, mock_redis):
    """Test session creation."""
    user_id = "test_user"
    device_info = {"device": "test_device"}
    
    # Mock token creation
    with patch('flask_jwt_extended.create_access_token', return_value='access_token'):
        with patch('flask_jwt_extended.create_refresh_token', return_value='refresh_token'):
            result = session_service.create_session(user_id, device_info)
    
    assert result['access_token'] == 'access_token'
    assert result['refresh_token'] == 'refresh_token'
    assert 'expires_in' in result
    
    # Verify Redis calls
    mock_redis.hmset.assert_called_once()
    mock_redis.expire.assert_called_once()
    mock_redis.set.assert_called_once()

def test_refresh_session_valid(session_service, mock_redis):
    """Test valid session refresh."""
    user_id = "test_user"
    refresh_token = "valid_refresh_token"
    
    # Mock Redis response
    mock_redis.get.return_value = user_id
    
    # Mock token creation
    with patch('flask_jwt_extended.create_access_token', return_value='new_access_token'):
        result = session_service.refresh_session(refresh_token)
    
    assert result['access_token'] == 'new_access_token'
    assert 'expires_in' in result
    mock_redis.hset.assert_called_once()

def test_refresh_session_invalid(session_service, mock_redis):
    """Test invalid session refresh."""
    refresh_token = "invalid_refresh_token"
    mock_redis.get.return_value = None
    
    with pytest.raises(TokenRefreshError):
        session_service.refresh_session(refresh_token)

def test_check_rate_limit(session_service, mock_redis):
    """Test rate limiting functionality."""
    user_id = "test_user"
    endpoint = "test_endpoint"
    
    # Test first request
    mock_redis.get.return_value = None
    assert session_service.check_rate_limit(user_id, endpoint) is True
    mock_redis.setex.assert_called_once()
    
    # Test subsequent requests
    mock_redis.get.return_value = "1"
    assert session_service.check_rate_limit(user_id, endpoint) is True
    mock_redis.incr.assert_called_once()

def test_invalidate_session(session_service, mock_redis):
    """Test session invalidation."""
    user_id = "test_user"
    
    # Mock scan_iter to return a refresh token key
    mock_redis.scan_iter.return_value = [f"refresh:{user_id}"]
    mock_redis.get.return_value = user_id
    
    session_service.invalidate_session(user_id)
    
    # Verify Redis calls
    mock_redis.delete.assert_called()
    assert mock_redis.delete.call_count == 2  # Once for session, once for refresh token

def test_update_session_activity(session_service, mock_redis):
    """Test session activity update."""
    user_id = "test_user"
    mock_redis.exists.return_value = True
    
    session_service.update_session_activity(user_id)
    
    mock_redis.hset.assert_called_once()
    assert 'last_activity' in mock_redis.hset.call_args[1] 
import pytest
from freezegun import freeze_time
from datetime import datetime
from app.services.redis_service import (
    add_user_session,
    remove_user_session,
    invalidate_all_user_sessions,
    get_active_sessions_count,
    get_user_sessions
)


def test_add_user_session(app, mock_redis):
    """Test adding a user session."""
    with app.app_context():
        user_id = 1
        token_jti = 'test-token'
        
        success = add_user_session(user_id, token_jti)
        
        assert success is True
        assert mock_redis.get('active_sessions_count') == '1'
        assert mock_redis.sismember(f'user_sessions:{user_id}', token_jti) == 1
        assert mock_redis.hget(f'session:{token_jti}', 'user_id') == str(user_id)


def test_add_user_session_with_limit(app, mock_redis):
    """Test adding a user session when limit is reached."""
    with app.app_context():
        app.config['SESSION_LIMIT_PER_USER'] = 3
        user_id = 1
        
        # Reset the active sessions count
        mock_redis.set('active_sessions_count', '0')
        
        # Add sessions up to the limit (3 in test config)
        add_user_session(user_id, 'token1')
        
        # Set created_at for token1 to make it the oldest
        mock_redis.hset(f'session:token1', 'created_at', '1000')
        
        with freeze_time("2023-01-01 12:00:00"):
            add_user_session(user_id, 'token2')
        with freeze_time("2023-01-01 12:30:00"):
            add_user_session(user_id, 'token3')
        
        # Adding a 4th session should remove the oldest (token1)
        with freeze_time("2023-01-01 13:00:00"):
            add_user_session(user_id, 'token4')
        
        # We should still have 3 active sessions
        assert mock_redis.get('active_sessions_count') == '3'
        
        # Check that token1 was removed and the others remain
        assert mock_redis.sismember(f'user_sessions:{user_id}', 'token1') == 0
        assert mock_redis.sismember(f'user_sessions:{user_id}', 'token2') == 1
        assert mock_redis.sismember(f'user_sessions:{user_id}', 'token3') == 1
        assert mock_redis.sismember(f'user_sessions:{user_id}', 'token4') == 1


def test_remove_user_session(app, mock_redis):
    """Test removing a user session."""
    with app.app_context():
        user_id = 1
        token_jti = 'test-token'
        
        # Add session
        mock_redis.incr('active_sessions_count')
        mock_redis.sadd(f'user_sessions:{user_id}', token_jti)
        mock_redis.hset(f'session:{token_jti}', 'user_id', user_id)
        
        success = remove_user_session(user_id, token_jti)
        
        assert success is True
        assert mock_redis.get('active_sessions_count') == '0'
        assert mock_redis.sismember(f'user_sessions:{user_id}', token_jti) == 0
        assert mock_redis.exists(f'session:{token_jti}') == 0


def test_remove_user_session_nonexistent(app, mock_redis):
    """Test removing a nonexistent session."""
    with app.app_context():
        user_id = 1
        token_jti = 'nonexistent-token'
        
        success = remove_user_session(user_id, token_jti)
        
        assert success is True  # Should not fail even if session doesn't exist


def test_invalidate_all_user_sessions(app, mock_redis):
    """Test invalidating all sessions for a user."""
    with app.app_context():
        user_id = 1
        
        # Add multiple sessions
        mock_redis.incr('active_sessions_count', 3)
        mock_redis.sadd(f'user_sessions:{user_id}', 'token1')
        mock_redis.sadd(f'user_sessions:{user_id}', 'token2')
        mock_redis.sadd(f'user_sessions:{user_id}', 'token3')
        mock_redis.hset(f'session:token1', 'user_id', user_id)
        mock_redis.hset(f'session:token2', 'user_id', user_id)
        mock_redis.hset(f'session:token3', 'user_id', user_id)
        
        success = invalidate_all_user_sessions(user_id)
        
        assert success is True
        assert mock_redis.get('active_sessions_count') == '0'
        assert mock_redis.scard(f'user_sessions:{user_id}') == 0
        assert mock_redis.exists(f'session:token1') == 0
        assert mock_redis.exists(f'session:token2') == 0
        assert mock_redis.exists(f'session:token3') == 0


def test_get_active_sessions_count(app, mock_redis):
    """Test getting active sessions count."""
    with app.app_context():
        # Set counter in Redis
        mock_redis.set('active_sessions_count', 42)
        
        count = get_active_sessions_count()
        
        assert count == 42


def test_get_active_sessions_count_none(app, mock_redis):
    """Test getting active sessions count when no counter exists."""
    with app.app_context():
        count = get_active_sessions_count()
        
        assert count == 0


def test_get_user_sessions(app, mock_redis):
    """Test getting all sessions for a user."""
    with app.app_context():
        user_id = 1
        
        # Add sessions with timestamps
        with freeze_time("2023-01-01 12:00:00"):
            mock_redis.sadd(f'user_sessions:{user_id}', 'token1')
            mock_redis.hset(f'session:token1', mapping={
                'user_id': str(user_id),
                'created_at': str(datetime.utcnow().timestamp()),
                'user_agent': 'test-agent-1'
            })
        
        with freeze_time("2023-01-01 13:00:00"):
            mock_redis.sadd(f'user_sessions:{user_id}', 'token2')
            mock_redis.hset(f'session:token2', mapping={
                'user_id': str(user_id),
                'created_at': str(datetime.utcnow().timestamp()),
                'user_agent': 'test-agent-2'
            })
        
        sessions = get_user_sessions(user_id)
        
        assert len(sessions) == 2
        
        # Sort sessions by created_at for predictable order
        sessions.sort(key=lambda x: x['created_at'])
        
        assert sessions[0]['jti'] == 'token1'
        assert sessions[0]['user_id'] == str(user_id)
        assert sessions[0]['user_agent'] == 'test-agent-1'
        assert sessions[0]['created_at'] == '2023-01-01T12:00:00'
        
        assert sessions[1]['jti'] == 'token2'
        assert sessions[1]['user_id'] == str(user_id)
        assert sessions[1]['user_agent'] == 'test-agent-2'
        assert sessions[1]['created_at'] == '2023-01-01T13:00:00'


def test_get_user_sessions_empty(app, mock_redis):
    """Test getting sessions for a user with no sessions."""
    with app.app_context():
        user_id = 1
        
        sessions = get_user_sessions(user_id)
        
        assert len(sessions) == 0 
import pytest
import json
from datetime import datetime, timedelta
from freezegun import freeze_time
from app.models.user import User


def test_forgot_password(client, test_user, mock_mail):
    """Test requesting a password reset."""
    response = client.post(
        '/api/password/forgot',
        json={'email': test_user.email}
    )
    
    assert response.status_code == 200
    data = json.loads(response.data)
    assert data['success'] is True
    
    # Check user in database
    updated_user = User.query.get(test_user.id)
    assert updated_user.password_reset_token is not None
    assert updated_user.password_reset_expires is not None
    
    # Check email sent
    assert len(mock_mail) == 1
    assert mock_mail[0]['recipients'] == [test_user.email]
    assert 'Reset your password' in mock_mail[0]['subject']


def test_forgot_password_nonexistent_email(client, mock_mail):
    """Test requesting password reset with non-existent email."""
    response = client.post(
        '/api/password/forgot',
        json={'email': 'nonexistent@example.com'}
    )
    
    # Should still return success for security reasons
    assert response.status_code == 200
    data = json.loads(response.data)
    assert data['success'] is True
    
    # But no email should be sent
    assert len(mock_mail) == 0


def test_forgot_password_missing_email(client):
    """Test requesting password reset without email."""
    response = client.post(
        '/api/password/forgot',
        json={}
    )
    
    assert response.status_code == 400
    data = json.loads(response.data)
    assert data['success'] is False
    assert 'Email is required' in data['message']


def test_reset_password(client, db_session, mock_redis):
    """Test resetting password with token."""
    with freeze_time("2023-01-01 12:00:00"):
        # Create user with reset token
        user = User(
            email='reset@example.com',
            is_email_verified=True,
            password_reset_token='test-reset-token',
            password_reset_expires=datetime.utcnow() + timedelta(hours=1)
        )
        user.password = 'old_password'
        db_session.add(user)
        db_session.commit()
        
        # Add a session to Redis
        mock_redis.incr('active_sessions_count')
        mock_redis.sadd(f'user_sessions:{user.id}', 'test-token')
        mock_redis.hset(f'session:test-token', 'user_id', user.id)
        
        response = client.post(
            '/api/password/reset',
            json={
                'token': 'test-reset-token',
                'password': 'new_password'
            }
        )
        
        assert response.status_code == 200
        data = json.loads(response.data)
        assert data['success'] is True
        
        # Check user in database
        updated_user = User.query.get(user.id)
        assert updated_user.password_reset_token is None
        assert updated_user.password_reset_expires is None
        assert updated_user.verify_password('new_password') is True
        assert updated_user.verify_password('old_password') is False
        
        # All sessions should be invalidated
        assert mock_redis.get('active_sessions_count') == '0'
        assert mock_redis.sismember(f'user_sessions:{user.id}', 'test-token') == 0


def test_reset_password_expired_token(client, db_session):
    """Test resetting password with expired token."""
    with freeze_time("2023-01-01 12:00:00"):
        # Create user with reset token that will expire
        user = User(
            email='reset@example.com',
            is_email_verified=True,
            password_reset_token='test-reset-token',
            password_reset_expires=datetime.utcnow() + timedelta(hours=1)
        )
        user.password = 'old_password'
        db_session.add(user)
        db_session.commit()
    
    # Move time forward 2 hours to expire token
    with freeze_time("2023-01-01 14:00:00"):
        response = client.post(
            '/api/password/reset',
            json={
                'token': 'test-reset-token',
                'password': 'new_password'
            }
        )
        
        assert response.status_code == 400
        data = json.loads(response.data)
        assert data['success'] is False
        assert 'expired' in data['message']


def test_reset_password_invalid_token(client):
    """Test resetting password with invalid token."""
    response = client.post(
        '/api/password/reset',
        json={
            'token': 'invalid-token',
            'password': 'new_password'
        }
    )
    
    assert response.status_code == 400
    data = json.loads(response.data)
    assert data['success'] is False
    assert 'Invalid' in data['message']


def test_reset_password_missing_fields(client):
    """Test resetting password with missing fields."""
    # Missing password
    response = client.post(
        '/api/password/reset',
        json={'token': 'test-token'}
    )
    
    assert response.status_code == 400
    data = json.loads(response.data)
    assert data['success'] is False
    assert 'required' in data['message']
    
    # Missing token
    response = client.post(
        '/api/password/reset',
        json={'password': 'new_password'}
    )
    
    assert response.status_code == 400
    data = json.loads(response.data)
    assert data['success'] is False
    assert 'required' in data['message'] 
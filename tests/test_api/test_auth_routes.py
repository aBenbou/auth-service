import pytest
import json
from flask import url_for
from app.models.user import User


def test_register_success(client, db_session, mock_mail):
    """Test successful user registration."""
    response = client.post(
        '/api/auth/register',
        json={
            'email': 'new@example.com',
            'password': 'password123',
            'first_name': 'New',
            'last_name': 'User'
        }
    )
    
    assert response.status_code == 201
    data = json.loads(response.data)
    assert data['success'] is True
    assert 'user_id' in data
    
    # Check database
    user = User.query.filter_by(email='new@example.com').first()
    assert user is not None
    
    # Check email sent
    assert len(mock_mail) == 1
    assert mock_mail[0]['recipients'] == ['new@example.com']


def test_register_missing_fields(client):
    """Test registration with missing fields."""
    response = client.post(
        '/api/auth/register',
        json={
            'email': 'new@example.com'
            # Missing password
        }
    )
    
    assert response.status_code == 400
    data = json.loads(response.data)
    assert data['success'] is False
    assert 'required' in data['message']


def test_register_duplicate_email(client, test_user):
    """Test registration with duplicate email."""
    response = client.post(
        '/api/auth/register',
        json={
            'email': test_user.email,
            'password': 'password123'
        }
    )
    
    assert response.status_code == 400
    data = json.loads(response.data)
    assert data['success'] is False
    assert 'already registered' in data['message']


def test_verify_email_success(client, db_session):
    """Test successful email verification."""
    # Create user with verification token
    user = User(
        email='unverified@example.com',
        email_verification_token='test-token',
        is_email_verified=False
    )
    db_session.add(user)
    db_session.commit()
    
    response = client.get('/api/auth/verify-email/test-token')
    
    assert response.status_code == 200
    data = json.loads(response.data)
    assert data['success'] is True
    
    # Check database
    updated_user = User.query.filter_by(email='unverified@example.com').first()
    assert updated_user.is_email_verified is True
    assert updated_user.email_verification_token is None


def test_verify_email_invalid_token(client):
    """Test email verification with invalid token."""
    response = client.get('/api/auth/verify-email/invalid-token')
    
    assert response.status_code == 400
    data = json.loads(response.data)
    assert data['success'] is False
    assert 'Invalid verification token' in data['message']


def test_login_success(client, test_user, mock_redis):
    """Test successful login."""
    response = client.post(
        '/api/auth/login',
        json={
            'email': test_user.email,
            'password': 'password123'
        }
    )
    
    assert response.status_code == 200
    data = json.loads(response.data)
    assert data['success'] is True
    assert 'access_token' in data
    assert 'refresh_token' in data
    assert data['user']['email'] == test_user.email
    
    # Check Redis session
    assert mock_redis.get('active_sessions_count') == '1'


def test_login_invalid_credentials(client, test_user):
    """Test login with invalid credentials."""
    response = client.post(
        '/api/auth/login',
        json={
            'email': test_user.email,
            'password': 'wrong_password'
        }
    )
    
    assert response.status_code == 401
    data = json.loads(response.data)
    assert data['success'] is False


def test_login_unverified_email(client, db_session):
    """Test login with unverified email."""
    # Create unverified user
    user = User(
        email='unverified@example.com',
        is_email_verified=False
    )
    user.password = 'password123'
    db_session.add(user)
    db_session.commit()
    
    response = client.post(
        '/api/auth/login',
        json={
            'email': 'unverified@example.com',
            'password': 'password123'
        }
    )
    
    assert response.status_code == 403
    data = json.loads(response.data)
    assert data['success'] is False
    assert 'Email not verified' in data['message']
    assert data['needs_verification'] is True


def test_logout(client, test_user, user_token, mock_redis):
    """Test logout."""
    # Add session to Redis
    mock_redis.incr('active_sessions_count')
    mock_redis.sadd(f'user_sessions:{test_user.id}', 'test-jti')
    mock_redis.hset(f'session:test-jti', 'user_id', test_user.id)
    
    # Extract JTI from real token
    from flask_jwt_extended import decode_token
    token_data = decode_token(user_token['access_token'])
    jti = token_data['jti']
    
    # Set up session in Redis with the actual JTI
    mock_redis.sadd(f'user_sessions:{test_user.id}', jti)
    mock_redis.hset(f'session:{jti}', 'user_id', test_user.id)
    
    response = client.post(
        '/api/auth/logout',
        headers={'Authorization': f'Bearer {user_token["access_token"]}'}
    )
    
    assert response.status_code == 200
    data = json.loads(response.data)
    assert data['success'] is True
    
    # Check Redis (session should be removed)
    assert mock_redis.sismember(f'user_sessions:{test_user.id}', jti) == 0


def test_refresh_token(client, test_user, user_token):
    """Test refreshing access token."""
    response = client.post(
        '/api/auth/refresh',
        headers={'Authorization': f'Bearer {user_token["refresh_token"]}'}
    )
    
    assert response.status_code == 200
    data = json.loads(response.data)
    assert data['success'] is True
    assert 'access_token' in data


def test_change_password(client, test_user, user_token, mock_redis):
    """Test changing password."""
    # Set up session in Redis
    from flask_jwt_extended import decode_token
    token_data = decode_token(user_token['access_token'])
    jti = token_data['jti']
    
    mock_redis.sadd(f'user_sessions:{test_user.id}', jti)
    mock_redis.hset(f'session:{jti}', 'user_id', test_user.id)
    
    response = client.post(
        '/api/auth/change-password',
        json={
            'current_password': 'password123',
            'new_password': 'new_password123'
        },
        headers={'Authorization': f'Bearer {user_token["access_token"]}'}
    )
    
    assert response.status_code == 200
    data = json.loads(response.data)
    assert data['success'] is True
    
    # Check user in database
    updated_user = User.query.get(test_user.id)
    assert updated_user.verify_password('new_password123') is True
    assert updated_user.verify_password('password123') is False


def test_get_user_profile(client, test_user, user_token):
    """Test getting user profile."""
    response = client.get(
        '/api/auth/me',
        headers={'Authorization': f'Bearer {user_token["access_token"]}'}
    )
    
    assert response.status_code == 200
    data = json.loads(response.data)
    assert data['success'] is True
    assert data['user']['email'] == test_user.email


def test_get_sessions(client, test_user, user_token, mock_redis):
    """Test getting user sessions."""
    # Add sessions to Redis
    mock_redis.sadd(f'user_sessions:{test_user.id}', 'token1')
    mock_redis.hset(f'session:token1', mapping={
        'user_id': test_user.id,
        'created_at': '1609459200',  # 2021-01-01 00:00:00
        'user_agent': 'test-agent'
    })
    
    response = client.get(
        '/api/auth/sessions',
        headers={'Authorization': f'Bearer {user_token["access_token"]}'}
    )
    
    assert response.status_code == 200
    data = json.loads(response.data)
    assert data['success'] is True
    assert len(data['sessions']) == 1
    assert data['sessions'][0]['jti'] == 'token1'


def test_delete_session(client, test_user, user_token, mock_redis):
    """Test deleting a specific session."""
    # Add session to Redis
    mock_redis.incr('active_sessions_count')
    mock_redis.sadd(f'user_sessions:{test_user.id}', 'token-to-delete')
    mock_redis.hset(f'session:token-to-delete', 'user_id', test_user.id)
    
    response = client.delete(
        '/api/auth/sessions/token-to-delete',
        headers={'Authorization': f'Bearer {user_token["access_token"]}'}
    )
    
    assert response.status_code == 200
    data = json.loads(response.data)
    assert data['success'] is True
    
    # Check Redis (session should be removed)
    assert mock_redis.sismember(f'user_sessions:{test_user.id}', 'token-to-delete') == 0
    assert mock_redis.get('active_sessions_count') == '0'


def test_delete_all_sessions(client, test_user, user_token, mock_redis):
    """Test deleting all sessions except current."""
    # Extract JTI from token
    from flask_jwt_extended import decode_token
    token_data = decode_token(user_token['access_token'])
    jti = token_data['jti']
    
    # Add multiple sessions to Redis
    mock_redis.incr('active_sessions_count', 3)
    mock_redis.sadd(f'user_sessions:{test_user.id}', jti)  # Current session
    mock_redis.sadd(f'user_sessions:{test_user.id}', 'token1')
    mock_redis.sadd(f'user_sessions:{test_user.id}', 'token2')
    mock_redis.hset(f'session:{jti}', 'user_id', test_user.id)
    mock_redis.hset(f'session:token1', 'user_id', test_user.id)
    mock_redis.hset(f'session:token2', 'user_id', test_user.id)
    
    response = client.delete(
        '/api/auth/sessions',
        headers={'Authorization': f'Bearer {user_token["access_token"]}'}
    )
    
    assert response.status_code == 200
    data = json.loads(response.data)
    assert data['success'] is True
    
    # Check Redis (only current session should remain)
    assert mock_redis.scard(f'user_sessions:{test_user.id}') == 1
    assert mock_redis.sismember(f'user_sessions:{test_user.id}', jti) == 1
    assert mock_redis.sismember(f'user_sessions:{test_user.id}', 'token1') == 0
    assert mock_redis.sismember(f'user_sessions:{test_user.id}', 'token2') == 0
    assert mock_redis.get('active_sessions_count') == '1'


def test_get_sessions_stats(client, admin_token, mock_redis):
    """Test getting session statistics."""
    # Set active sessions count in Redis
    mock_redis.set('active_sessions_count', 42)
    
    response = client.get(
        '/api/auth/sessions/stats',
        headers={'Authorization': f'Bearer {admin_token["access_token"]}'}
    )
    
    assert response.status_code == 200
    data = json.loads(response.data)
    assert data['success'] is True
    assert data['active_sessions'] == 42 
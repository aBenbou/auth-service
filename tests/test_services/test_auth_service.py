import pytest
from freezegun import freeze_time
from datetime import datetime, timedelta
from app.services.auth_service import (
    register_user,
    verify_email,
    login_user,
    logout_user,
    get_user_by_id,
    request_password_reset,
    reset_password,
    change_password
)
from app.models.user import User


def test_register_user(db_session, mock_mail):
    """Test registering a new user."""
    result = register_user(
        email='new@example.com',
        password='password123',
        first_name='New',
        last_name='User'
    )
    
    assert result['success'] is True
    assert 'user_id' in result
    
    # Check database
    user = User.query.filter_by(email='new@example.com').first()
    assert user is not None
    assert user.first_name == 'New'
    assert user.last_name == 'User'
    assert user.is_email_verified is False
    assert user.email_verification_token is not None
    
    # Check that verification email was sent
    assert len(mock_mail) == 1
    assert mock_mail[0]['subject'].startswith('Verify your email')
    assert mock_mail[0]['recipients'] == ['new@example.com']


def test_register_user_duplicate_email(db_session, test_user):
    """Test registering with an existing email."""
    result = register_user(
        email=test_user.email,
        password='password123',
        first_name='New',
        last_name='User'
    )
    
    assert result['success'] is False
    assert 'already registered' in result['message']


def test_verify_email(db_session):
    """Test email verification."""
    # Create user with verification token
    user = User(
        email='unverified@example.com',
        email_verification_token='test-token',
        is_email_verified=False
    )
    db_session.add(user)
    db_session.commit()
    
    # Verify email
    result = verify_email('test-token')
    
    assert result['success'] is True
    
    # Check database
    updated_user = User.query.filter_by(email='unverified@example.com').first()
    assert updated_user.is_email_verified is True
    assert updated_user.email_verification_token is None


def test_verify_email_invalid_token(db_session):
    """Test email verification with invalid token."""
    result = verify_email('invalid-token')
    
    assert result['success'] is False
    assert 'Invalid verification token' in result['message']


def test_login_user_success(db_session, test_user, mock_redis):
    """Test successful login."""
    result = login_user(test_user.email, 'password123')
    
    assert result['success'] is True
    assert 'access_token' in result
    assert 'refresh_token' in result
    assert result['user']['email'] == test_user.email
    
    # Check last login updated
    updated_user = User.query.get(test_user.id)
    assert updated_user.last_login is not None
    
    # Check Redis session
    assert mock_redis.get('active_sessions_count') == '1'


def test_login_user_wrong_password(db_session, test_user):
    """Test login with wrong password."""
    result = login_user(test_user.email, 'wrong_password')
    
    assert result['success'] is False
    assert 'Invalid email or password' in result['message']


def test_login_user_unverified_email(db_session):
    """Test login with unverified email."""
    user = User(
        email='unverified@example.com',
        is_email_verified=False
    )
    user.password = 'password123'
    db_session.add(user)
    db_session.commit()
    
    result = login_user('unverified@example.com', 'password123')
    
    assert result['success'] is False
    assert 'Email not verified' in result['message']
    assert result.get('needs_verification') is True


def test_login_user_inactive(db_session):
    """Test login with inactive account."""
    user = User(
        email='inactive@example.com',
        is_email_verified=True,
        is_active=False
    )
    user.password = 'password123'
    db_session.add(user)
    db_session.commit()
    
    result = login_user('inactive@example.com', 'password123')
    
    assert result['success'] is False
    assert 'Account is deactivated' in result['message']


def test_logout_user(db_session, test_user, mock_redis):
    """Test logging out."""
    # Add a session to Redis
    mock_redis.incr('active_sessions_count')
    mock_redis.sadd(f'user_sessions:{test_user.id}', 'test-token')
    mock_redis.hset(f'session:test-token', 'user_id', test_user.id)
    
    result = logout_user(test_user.public_id, 'test-token')
    
    assert result['success'] is True
    assert mock_redis.get('active_sessions_count') == '0'
    assert mock_redis.sismember(f'user_sessions:{test_user.id}', 'test-token') == 0


def test_get_user_by_id(db_session, test_user):
    """Test getting user by ID."""
    user = get_user_by_id(test_user.public_id)
    
    assert user is not None
    assert user.id == test_user.id
    assert user.email == test_user.email


def test_get_user_by_id_not_found(db_session):
    """Test getting a non-existent user."""
    user = get_user_by_id('non-existent-id')
    
    assert user is None


def test_request_password_reset(db_session, test_user, mock_mail):
    """Test requesting a password reset."""
    result = request_password_reset(test_user.email)
    
    assert result['success'] is True
    
    # Check user in database
    updated_user = User.query.get(test_user.id)
    assert updated_user.password_reset_token is not None
    assert updated_user.password_reset_expires is not None
    
    # Check email sent
    assert len(mock_mail) == 1
    assert mock_mail[0]['subject'].startswith('Reset your password')
    assert mock_mail[0]['recipients'] == [test_user.email]


def test_request_password_reset_nonexistent_email(db_session, mock_mail):
    """Test requesting password reset for non-existent email."""
    result = request_password_reset('nonexistent@example.com')
    
    # Should still return success for security reasons
    assert result['success'] is True
    
    # But no email should be sent
    assert len(mock_mail) == 0


def test_reset_password(db_session, mock_redis):
    """Test resetting password with token."""
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
    
    # Reset password
    result = reset_password('test-reset-token', 'new_password')
    
    assert result['success'] is True
    
    # Check user in database
    updated_user = User.query.get(user.id)
    assert updated_user.password_reset_token is None
    assert updated_user.password_reset_expires is None
    assert updated_user.verify_password('new_password') is True
    assert updated_user.verify_password('old_password') is False
    
    # All sessions should be invalidated
    assert mock_redis.get('active_sessions_count') == '0'
    assert mock_redis.sismember(f'user_sessions:{user.id}', 'test-token') == 0


def test_reset_password_expired_token(db_session):
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
        # Try to reset password
        result = reset_password('test-reset-token', 'new_password')
        
        assert result['success'] is False
        assert 'expired' in result['message']
        
        # Check user in database (password should not be changed)
        updated_user = User.query.get(user.id)
        assert updated_user.verify_password('old_password') is True
        assert updated_user.verify_password('new_password') is False


def test_change_password(db_session, test_user):
    """Test changing password."""
    result = change_password(
        test_user.public_id,
        'password123',
        'new_password123'
    )
    
    assert result['success'] is True
    
    # Check user in database
    updated_user = User.query.get(test_user.id)
    assert updated_user.verify_password('new_password123') is True
    assert updated_user.verify_password('password123') is False


def test_change_password_wrong_current(db_session, test_user):
    """Test changing password with wrong current password."""
    result = change_password(
        test_user.public_id,
        'wrong_current_password',
        'new_password123'
    )
    
    assert result['success'] is False
    assert 'Current password is incorrect' in result['message']
    
    # Check user in database (password should not be changed)
    updated_user = User.query.get(test_user.id)
    assert updated_user.verify_password('password123') is True
    assert updated_user.verify_password('new_password123') is False 
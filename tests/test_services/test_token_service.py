import pytest
from datetime import datetime, timedelta
from freezegun import freeze_time
from app.services.token_service import (
    create_app_token,
    validate_app_token,
    get_service_tokens,
    revoke_token,
    delete_token
)
from app.models.app_token import AppToken


def test_create_app_token(db_session, test_service):
    """Test creating an application token."""
    result = create_app_token(
        service_id=test_service.id,
        name='Test Token'
    )
    
    assert result['success'] is True
    assert 'token_data' in result
    assert result['token_data']['name'] == 'Test Token'
    assert result['token_data']['service_id'] == test_service.public_id
    assert 'token' in result['token_data']  # Raw token is returned
    
    # Check database
    token = AppToken.query.filter_by(name='Test Token').first()
    assert token is not None
    assert token.service_id == test_service.id
    assert token.is_active is True
    assert token.expires_at is None


def test_create_app_token_with_expiration(db_session, test_service):
    """Test creating a token with expiration date."""
    with freeze_time("2023-01-01 12:00:00"):
        result = create_app_token(
            service_id=test_service.id,
            name='Expiring Token',
            expires_in_days=30
        )
        
        assert result['success'] is True
        
        # Check expiration date in response (should be 30 days from now)
        expected_expiry = datetime.utcnow() + timedelta(days=30)
        assert result['token_data']['expires_at'] == expected_expiry.isoformat()
        
        # Check database
        token = AppToken.query.filter_by(name='Expiring Token').first()
        assert token is not None
        assert token.expires_at is not None
        assert token.expires_at.date() == expected_expiry.date()


def test_create_app_token_service_not_found(db_session):
    """Test creating a token with non-existent service."""
    result = create_app_token(
        service_id=999,  # Non-existent ID
        name='Test Token'
    )
    
    assert result['success'] is False
    assert 'Service not found' in result['message']


def test_create_app_token_duplicate_name(db_session, test_service, test_app_token):
    """Test creating a token with duplicate name."""
    result = create_app_token(
        service_id=test_service.id,
        name=test_app_token.name  # Use same name as existing token
    )
    
    assert result['success'] is False
    assert 'already exists' in result['message']


def test_validate_app_token(db_session, test_app_token):
    """Test validating an application token."""
    service = validate_app_token(test_app_token.token)
    
    assert service is not None
    assert service.id == test_app_token.service_id
    
    # Check that last_used was updated
    updated_token = AppToken.query.get(test_app_token.id)
    assert updated_token.last_used is not None


def test_validate_app_token_nonexistent(db_session):
    """Test validating a non-existent token."""
    service = validate_app_token('nonexistent-token')
    
    assert service is None


def test_validate_app_token_inactive(db_session, test_app_token):
    """Test validating an inactive token."""
    # Deactivate token
    test_app_token.is_active = False
    db_session.commit()
    
    service = validate_app_token(test_app_token.token)
    
    assert service is None


def test_validate_app_token_expired(db_session, test_service):
    """Test validating an expired token."""
    with freeze_time("2023-01-01 12:00:00"):
        # Create token that expires in 1 hour
        token = AppToken(
            name='Expiring Token',
            service_id=test_service.id,
            is_active=True,
            expires_at=datetime.utcnow() + timedelta(hours=1)
        )
        db_session.add(token)
        db_session.commit()
        
        # Token should be valid now
        service = validate_app_token(token.token)
        assert service is not None
    
    # Move time forward 2 hours to expire token
    with freeze_time("2023-01-01 14:00:00"):
        # Token should now be invalid
        service = validate_app_token(token.token)
        assert service is None


def test_get_service_tokens(db_session, test_service):
    """Test getting all tokens for a service."""
    # Create multiple tokens
    token1 = AppToken(name='Token 1', service_id=test_service.id)
    token2 = AppToken(name='Token 2', service_id=test_service.id)
    db_session.add_all([token1, token2])
    db_session.commit()
    
    tokens = get_service_tokens(test_service.id)
    
    assert len(tokens) == 2
    token_names = [t['name'] for t in tokens]
    assert 'Token 1' in token_names
    assert 'Token 2' in token_names
    
    # Verify token values are not included
    for token in tokens:
        assert 'token' not in token


def test_revoke_token(db_session, test_app_token):
    """Test revoking a token."""
    result = revoke_token(test_app_token.id)
    
    assert result['success'] is True
    
    # Check database
    updated_token = AppToken.query.get(test_app_token.id)
    assert updated_token.is_active is False


def test_revoke_token_not_found(db_session):
    """Test revoking a non-existent token."""
    result = revoke_token(999)  # Non-existent ID
    
    assert result['success'] is False
    assert 'Token not found' in result['message']


def test_delete_token(db_session, test_app_token):
    """Test deleting a token."""
    result = delete_token(test_app_token.id)
    
    assert result['success'] is True
    
    # Check database
    deleted_token = AppToken.query.get(test_app_token.id)
    assert deleted_token is None


def test_delete_token_not_found(db_session):
    """Test deleting a non-existent token."""
    result = delete_token(999)  # Non-existent ID
    
    assert result['success'] is False
    assert 'Token not found' in result['message'] 
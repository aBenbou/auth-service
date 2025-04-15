import pytest
from datetime import datetime, timedelta
from freezegun import freeze_time
from app.models.app_token import AppToken
from app.models.service import Service


def test_app_token_creation(db_session):
    """Test creating an application token."""
    # Create service first
    service = Service(name='test_service')
    db_session.add(service)
    db_session.commit()
    
    # Create token
    token = AppToken(
        name='test_token',
        service_id=service.id,
        is_active=True
    )
    db_session.add(token)
    db_session.commit()
    
    saved_token = AppToken.query.filter_by(name='test_token').first()
    assert saved_token is not None
    assert saved_token.name == 'test_token'
    assert saved_token.service_id == service.id
    assert saved_token.is_active is True
    assert saved_token.token is not None  # Token should be auto-generated
    assert len(saved_token.token) == 64  # Token should be 64 characters (32 bytes hex)


def test_app_token_relationships(db_session):
    """Test app token relationships."""
    # Create service
    service = Service(name='test_service')
    db_session.add(service)
    db_session.commit()
    
    # Create token
    token = AppToken(name='test_token', service_id=service.id)
    db_session.add(token)
    db_session.commit()
    
    # Test relationship
    assert token.service is not None
    assert token.service.name == 'test_service'
    
    # Test reverse relationship
    assert service.app_tokens[0].name == 'test_token'


def test_token_is_valid_active(db_session):
    """Test is_valid method with active token."""
    service = Service(name='test_service')
    db_session.add(service)
    db_session.commit()
    
    # Create active token with no expiration
    token = AppToken(
        name='test_token',
        service_id=service.id,
        is_active=True,
        expires_at=None
    )
    db_session.add(token)
    db_session.commit()
    
    assert token.is_valid() is True


def test_token_is_valid_inactive(db_session):
    """Test is_valid method with inactive token."""
    service = Service(name='test_service')
    db_session.add(service)
    db_session.commit()
    
    # Create inactive token
    token = AppToken(
        name='test_token',
        service_id=service.id,
        is_active=False
    )
    db_session.add(token)
    db_session.commit()
    
    assert token.is_valid() is False


def test_token_is_valid_expired(db_session):
    """Test is_valid method with expired token."""
    with freeze_time("2023-01-01 12:00:00"):
        service = Service(name='test_service')
        db_session.add(service)
        db_session.commit()
        
        # Create token that expires in 1 hour
        expiration = datetime.utcnow() + timedelta(hours=1)
        token = AppToken(
            name='test_token',
            service_id=service.id,
            is_active=True,
            expires_at=expiration
        )
        db_session.add(token)
        db_session.commit()
        
        # Token should be valid now
        assert token.is_valid() is True
    
    # Jump ahead 2 hours
    with freeze_time("2023-01-01 14:00:00"):
        # Now token should be expired
        assert token.is_valid() is False


def test_update_last_used(db_session):
    """Test update_last_used method."""
    service = Service(name='test_service')
    db_session.add(service)
    db_session.commit()
    
    token = AppToken(name='test_token', service_id=service.id)
    db_session.add(token)
    db_session.commit()
    
    assert token.last_used is None
    
    with freeze_time("2023-01-01 12:00:00"):
        token.update_last_used()
        
        saved_token = AppToken.query.get(token.id)
        assert saved_token.last_used == datetime(2023, 1, 1, 12, 0, 0)


def test_app_token_to_dict(db_session):
    """Test the to_dict method."""
    service = Service(name='test_service')
    db_session.add(service)
    db_session.commit()
    
    with freeze_time("2023-01-01 12:00:00"):
        expiration = datetime.utcnow() + timedelta(days=30)
        token = AppToken(
            name='test_token',
            service_id=service.id,
            is_active=True,
            expires_at=expiration,
            last_used=datetime.utcnow()
        )
        db_session.add(token)
        db_session.commit()
        
        token_dict = token.to_dict()
        assert token_dict['name'] == 'test_token'
        assert token_dict['service_id'] == service.public_id
        assert token_dict['service_name'] == 'test_service'
        assert token_dict['is_active'] is True
        assert token_dict['expires_at'] == expiration.isoformat()
        assert token_dict['last_used'] == datetime(2023, 1, 1, 12, 0, 0).isoformat()
        assert 'token' not in token_dict  # Token should not be included in to_dict 
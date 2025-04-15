import pytest
from app.models.service import Service


def test_service_creation(db_session):
    """Test creating a service."""
    service = Service(
        name='test_service',
        description='Test service description',
        is_active=True
    )
    db_session.add(service)
    db_session.commit()
    
    saved_service = Service.query.filter_by(name='test_service').first()
    assert saved_service is not None
    assert saved_service.name == 'test_service'
    assert saved_service.description == 'Test service description'
    assert saved_service.is_active is True
    assert saved_service.public_id is not None


def test_service_relationships(db_session):
    """Test service relationships."""
    service = Service(name='test_service')
    db_session.add(service)
    db_session.commit()
    
    # Roles will be tested in role tests
    # App tokens will be tested in app token tests
    # Just verify the relationship attributes exist
    assert hasattr(service, 'roles')
    assert hasattr(service, 'app_tokens')
    assert hasattr(service, 'user_service_roles')


def test_service_to_dict(db_session):
    """Test the to_dict method."""
    service = Service(
        name='test_service',
        description='Test service description',
        is_active=True
    )
    db_session.add(service)
    db_session.commit()
    
    service_dict = service.to_dict()
    assert service_dict['name'] == 'test_service'
    assert service_dict['description'] == 'Test service description'
    assert service_dict['is_active'] is True
    assert service_dict['id'] == service.public_id
    assert 'created_at' in service_dict
    assert 'updated_at' in service_dict 
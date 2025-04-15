import pytest
from app.services.service_service import (
    create_service,
    create_default_roles_for_service,
    get_service_by_id,
    update_service,
    delete_service,
    get_all_services,
    get_services_for_user
)
from app.models.service import Service
from app.models.role import Role
from app.models.user_service_role import UserServiceRole


def test_create_service(db_session):
    """Test creating a new service."""
    result = create_service(
        name='test_service',
        description='Test service description'
    )
    
    assert result['success'] is True
    assert 'service_id' in result
    
    # Check database
    service = Service.query.filter_by(name='test_service').first()
    assert service is not None
    assert service.description == 'Test service description'
    
    # Check default roles were created
    roles = Role.query.filter_by(service_id=service.id).all()
    assert len(roles) == 3
    role_names = [role.name for role in roles]
    assert 'admin' in role_names
    assert 'user' in role_names
    assert 'readonly' in role_names


def test_create_service_duplicate_name(db_session, test_service):
    """Test creating a service with an existing name."""
    result = create_service(
        name=test_service.name,
        description='Another description'
    )
    
    assert result['success'] is False
    assert 'already exists' in result['message']


def test_create_default_roles_for_service(db_session, test_service):
    """Test creating default roles for a service."""
    # Delete any existing roles first
    Role.query.filter_by(service_id=test_service.id).delete()
    db_session.commit()
    
    create_default_roles_for_service(test_service.id)
    
    # Check roles in database
    roles = Role.query.filter_by(service_id=test_service.id).all()
    assert len(roles) == 3
    
    admin_role = next((r for r in roles if r.name == 'admin'), None)
    assert admin_role is not None
    assert admin_role.description == 'Administrator with full access to this service'
    assert admin_role.is_default is False
    
    user_role = next((r for r in roles if r.name == 'user'), None)
    assert user_role is not None
    assert user_role.is_default is True


def test_get_service_by_id(db_session, test_service):
    """Test getting a service by ID."""
    # Test with public ID
    service = get_service_by_id(test_service.public_id)
    assert service is not None
    assert service.id == test_service.id
    assert service.name == test_service.name
    
    # Test with numeric ID
    service = get_service_by_id(str(test_service.id))
    assert service is not None
    assert service.id == test_service.id


def test_get_service_by_id_not_found(db_session):
    """Test getting a non-existent service."""
    service = get_service_by_id('non-existent-id')
    assert service is None


def test_update_service(db_session, test_service):
    """Test updating a service."""
    result = update_service(
        service_id=test_service.public_id,
        name='updated_service',
        description='Updated description',
        is_active=False
    )
    
    assert result['success'] is True
    
    # Check database
    updated_service = Service.query.get(test_service.id)
    assert updated_service.name == 'updated_service'
    assert updated_service.description == 'Updated description'
    assert updated_service.is_active is False


def test_update_service_not_found(db_session):
    """Test updating a non-existent service."""
    result = update_service(
        service_id='non-existent-id',
        name='updated_service'
    )
    
    assert result['success'] is False
    assert 'not found' in result['message']


def test_update_service_duplicate_name(db_session, test_service):
    """Test updating a service with a duplicate name."""
    # Create another service first
    other_service = Service(name='other_service')
    db_session.add(other_service)
    db_session.commit()
    
    result = update_service(
        service_id=test_service.public_id,
        name='other_service'
    )
    
    assert result['success'] is False
    assert 'already exists' in result['message']


def test_delete_service(db_session):
    """Test deleting a service."""
    # Create a service to delete
    service = Service(name='service_to_delete')
    db_session.add(service)
    db_session.commit()
    
    result = delete_service(service.public_id)
    
    assert result['success'] is True
    
    # Check database
    deleted_service = Service.query.get(service.id)
    assert deleted_service is None


def test_delete_service_not_found(db_session):
    """Test deleting a non-existent service."""
    result = delete_service('non-existent-id')
    
    assert result['success'] is False
    assert 'not found' in result['message']


def test_delete_auth_service(db_session):
    """Test attempting to delete the auth service."""
    # Get or create auth service
    auth_service = Service.query.filter_by(name='auth_service').first()
    if not auth_service:
        auth_service = Service(name='auth_service')
        db_session.add(auth_service)
        db_session.commit()
    
    result = delete_service(auth_service.public_id)
    
    assert result['success'] is False
    assert 'Cannot delete the auth service' in result['message']
    
    # Check database (service should still exist)
    service = Service.query.get(auth_service.id)
    assert service is not None


def test_get_all_services(db_session):
    """Test getting all services."""
    # Create some services
    services = [
        Service(name='service1'),
        Service(name='service2'),
        Service(name='service3')
    ]
    db_session.add_all(services)
    db_session.commit()
    
    result = get_all_services()
    
    assert len(result) >= 3
    service_names = [s['name'] for s in result]
    assert 'service1' in service_names
    assert 'service2' in service_names
    assert 'service3' in service_names


def test_get_services_for_user(db_session, test_user, test_service):
    """Test getting services for a user."""
    # Create another service
    other_service = Service(name='other_service')
    db_session.add(other_service)
    db_session.commit()
    
    # Create a role for each service
    role1 = Role(name='role1', service_id=test_service.id)
    role2 = Role(name='role2', service_id=other_service.id)
    db_session.add_all([role1, role2])
    db_session.commit()
    
    # Assign roles to user
    user_roles = [
        UserServiceRole(user_id=test_user.id, service_id=test_service.id, role_id=role1.id),
        UserServiceRole(user_id=test_user.id, service_id=other_service.id, role_id=role2.id)
    ]
    db_session.add_all(user_roles)
    db_session.commit()
    
    result = get_services_for_user(test_user.id)
    
    assert len(result) == 2
    service_names = [s['name'] for s in result]
    assert test_service.name in service_names
    assert other_service.name in service_names
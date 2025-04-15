import pytest
from app.models.user_service_role import UserServiceRole
from app.models.user import User
from app.models.service import Service
from app.models.role import Role


def test_user_service_role_creation(db_session):
    """Test creating a user-service-role association."""
    # Create user
    user = User(email='user@example.com')
    db_session.add(user)
    
    # Create service
    service = Service(name='test_service')
    db_session.add(service)
    
    db_session.commit()
    
    # Create role
    role = Role(name='test_role', service_id=service.id)
    db_session.add(role)
    db_session.commit()
    
    # Create association
    user_role = UserServiceRole(
        user_id=user.id,
        service_id=service.id,
        role_id=role.id
    )
    db_session.add(user_role)
    db_session.commit()
    
    saved_user_role = UserServiceRole.query.filter_by(
        user_id=user.id,
        service_id=service.id,
        role_id=role.id
    ).first()
    
    assert saved_user_role is not None
    assert saved_user_role.user_id == user.id
    assert saved_user_role.service_id == service.id
    assert saved_user_role.role_id == role.id


def test_user_service_role_relationships(db_session):
    """Test user-service-role relationships."""
    # Create user
    user = User(email='user@example.com')
    db_session.add(user)
    
    # Create service
    service = Service(name='test_service')
    db_session.add(service)
    
    db_session.commit()
    
    # Create role
    role = Role(name='test_role', service_id=service.id)
    db_session.add(role)
    db_session.commit()
    
    # Create association
    user_role = UserServiceRole(
        user_id=user.id,
        service_id=service.id,
        role_id=role.id
    )
    db_session.add(user_role)
    db_session.commit()
    
    # Test relationships
    assert user_role.user is not None
    assert user_role.user.email == 'user@example.com'
    
    assert user_role.service is not None
    assert user_role.service.name == 'test_service'
    
    assert user_role.role is not None
    assert user_role.role.name == 'test_role'
    
    # Test reverse relationships
    assert len(user.service_roles) == 1
    assert user.service_roles[0].role.name == 'test_role'
    
    assert len(service.user_service_roles) == 1
    assert service.user_service_roles[0].user.email == 'user@example.com'
    
    assert len(role.user_service_roles) == 1
    assert role.user_service_roles[0].user.email == 'user@example.com'


def test_user_service_role_unique_constraint(db_session):
    """Test that a user can have a role only once per service."""
    # Create user
    user = User(email='user@example.com')
    db_session.add(user)
    
    # Create service
    service = Service(name='test_service')
    db_session.add(service)
    
    db_session.commit()
    
    # Create role
    role = Role(name='test_role', service_id=service.id)
    db_session.add(role)
    db_session.commit()
    
    # Create first association
    user_role1 = UserServiceRole(
        user_id=user.id,
        service_id=service.id,
        role_id=role.id
    )
    db_session.add(user_role1)
    db_session.commit()
    
    # Try to create duplicate association
    user_role2 = UserServiceRole(
        user_id=user.id,
        service_id=service.id,
        role_id=role.id
    )
    db_session.add(user_role2)
    
    # Should raise integrity error due to unique constraint
    with pytest.raises(Exception):  # Could be IntegrityError or similar
        db_session.commit()
    
    db_session.rollback()


def test_user_service_role_to_dict(db_session):
    """Test the to_dict method."""
    # Create user
    user = User(email='user@example.com')
    db_session.add(user)
    
    # Create service
    service = Service(name='test_service')
    db_session.add(service)
    
    db_session.commit()
    
    # Create role
    role = Role(name='test_role', service_id=service.id)
    db_session.add(role)
    db_session.commit()
    
    # Create association
    user_role = UserServiceRole(
        user_id=user.id,
        service_id=service.id,
        role_id=role.id
    )
    db_session.add(user_role)
    db_session.commit()
    
    # Test to_dict
    user_role_dict = user_role.to_dict()
    assert user_role_dict['user_id'] == user.id
    assert user_role_dict['service_id'] == service.id
    assert user_role_dict['role_id'] == role.id
    assert user_role_dict['role_name'] == 'test_role'
    assert 'created_at' in user_role_dict 
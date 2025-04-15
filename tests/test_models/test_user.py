import pytest
from app.models.user import User
from app.models.service import Service
from app.models.role import Role, Permission
from app.models.user_service_role import UserServiceRole


def test_user_creation(db_session):
    """Test creating a new user."""
    user = User(
        email='user@example.com',
        first_name='Test',
        last_name='User'
    )
    user.password = 'password123'
    db_session.add(user)
    db_session.commit()
    
    saved_user = User.query.filter_by(email='user@example.com').first()
    assert saved_user is not None
    assert saved_user.email == 'user@example.com'
    assert saved_user.first_name == 'Test'
    assert saved_user.last_name == 'User'
    assert saved_user.public_id is not None
    assert saved_user.is_active is True
    assert saved_user.is_email_verified is False


def test_user_password_hashing(db_session):
    """Test password hashing."""
    user = User(email='user@example.com')
    user.password = 'password123'
    db_session.add(user)
    db_session.commit()
    
    saved_user = User.query.filter_by(email='user@example.com').first()
    assert saved_user.verify_password('password123') is True
    assert saved_user.verify_password('wrong_password') is False
    
    # Test that password is not readable
    with pytest.raises(AttributeError):
        password = saved_user.password


def test_user_roles_and_permissions(db_session):
    """Test user roles and permissions."""
    # Create service
    service = Service(name='test_service')
    db_session.add(service)
    db_session.commit()
    
    # Create permissions
    read_perm = Permission(name='test:read', description='Test read permission')
    write_perm = Permission(name='test:write', description='Test write permission')
    db_session.add_all([read_perm, write_perm])
    db_session.commit()
    
    # Create role with permissions
    role = Role(name='test_role', service_id=service.id)
    db_session.add(role)
    db_session.commit()
    
    # Add permissions to role
    role.add_permission(read_perm)
    role.add_permission(write_perm)
    db_session.commit()
    
    # Create user
    user = User(email='user@example.com')
    db_session.add(user)
    db_session.commit()
    
    # Assign role to user
    user_role = UserServiceRole(user_id=user.id, service_id=service.id, role_id=role.id)
    db_session.add(user_role)
    db_session.commit()
    
    # Test permissions
    assert user.has_permission('test:read', service.id) is True
    assert user.has_permission('test:write', service.id) is True
    assert user.has_permission('nonexistent:perm', service.id) is False
    
    # Test getting roles for service
    roles = user.get_roles_for_service(service.id)
    assert len(roles) == 1
    assert roles[0].name == 'test_role'


def test_user_to_dict(db_session):
    """Test the to_dict method."""
    user = User(
        email='user@example.com',
        first_name='Test',
        last_name='User',
        is_active=True,
        is_email_verified=True
    )
    db_session.add(user)
    db_session.commit()
    
    user_dict = user.to_dict()
    assert user_dict['email'] == 'user@example.com'
    assert user_dict['first_name'] == 'Test'
    assert user_dict['last_name'] == 'User'
    assert user_dict['is_active'] is True
    assert user_dict['is_email_verified'] is True
    assert 'password' not in user_dict 
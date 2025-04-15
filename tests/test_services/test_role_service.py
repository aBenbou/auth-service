import pytest
from app.services.role_service import (
    initialize_default_roles,
    get_user_roles,
    assign_role_to_user,
    remove_role_from_user,
    create_role,
    update_role,
    delete_role
)
from app.models.role import Role, Permission, RolePermission
from app.models.service import Service
from app.models.user_service_role import UserServiceRole


def test_initialize_default_roles(db_session):
    """Test initializing default roles and permissions."""
    initialize_default_roles()
    
    # Check that auth service was created
    auth_service = Service.query.filter_by(name='auth_service').first()
    assert auth_service is not None
    
    # Check that default permissions were created
    permissions = Permission.query.all()
    assert len(permissions) >= 12  # At least the default permissions
    
    # Check that default roles were created
    roles = Role.query.filter_by(service_id=auth_service.id).all()
    assert len(roles) >= 5  # admin, user_manager, service_manager, token_manager, readonly
    
    # Check that admin role has all permissions
    admin_role = Role.query.filter_by(name='admin', service_id=auth_service.id).first()
    assert admin_role is not None
    assert len(admin_role.permissions) == 12  # All permissions
    
    # Check that readonly is set as default
    readonly_role = Role.query.filter_by(name='readonly', service_id=auth_service.id).first()
    assert readonly_role is not None
    assert readonly_role.is_default is True


def test_get_user_roles(db_session, test_user, test_service, test_role):
    """Test getting user roles."""
    # Create another service and role
    other_service = Service(name='other_service')
    db_session.add(other_service)
    db_session.commit()
    
    other_role = Role(name='other_role', service_id=other_service.id)
    db_session.add(other_role)
    db_session.commit()
    
    # Assign roles to user
    user_roles = [
        UserServiceRole(user_id=test_user.id, service_id=test_service.id, role_id=test_role.id),
        UserServiceRole(user_id=test_user.id, service_id=other_service.id, role_id=other_role.id)
    ]
    db_session.add_all(user_roles)
    db_session.commit()
    
    # Test getting all roles
    all_roles = get_user_roles(test_user.id)
    assert len(all_roles) == 2
    
    # Test filtering by service
    service_roles = get_user_roles(test_user.id, test_service.id)
    assert len(service_roles) == 1
    assert service_roles[0].role_id == test_role.id


def test_assign_role_to_user(db_session, test_user, test_service, test_role):
    """Test assigning a role to a user."""
    result = assign_role_to_user(test_user.id, test_service.id, test_role.id)
    
    assert result['success'] is True
    
    # Check database
    user_role = UserServiceRole.query.filter_by(
        user_id=test_user.id,
        service_id=test_service.id,
        role_id=test_role.id
    ).first()
    assert user_role is not None


def test_assign_role_to_user_already_assigned(db_session, test_user, test_service, test_role):
    """Test assigning a role that's already assigned."""
    # First assign the role
    user_role = UserServiceRole(
        user_id=test_user.id,
        service_id=test_service.id,
        role_id=test_role.id
    )
    db_session.add(user_role)
    db_session.commit()
    
    # Try to assign again
    result = assign_role_to_user(test_user.id, test_service.id, test_role.id)
    
    assert result['success'] is False
    assert 'already assigned' in result['message']


def test_remove_role_from_user(db_session, test_user, test_service, test_role):
    """Test removing a role from a user."""
    # First assign the role
    user_role = UserServiceRole(
        user_id=test_user.id,
        service_id=test_service.id,
        role_id=test_role.id
    )
    db_session.add(user_role)
    db_session.commit()
    
    # Remove the role
    result = remove_role_from_user(test_user.id, test_service.id, test_role.id)
    
    assert result['success'] is True
    
    # Check database
    user_role = UserServiceRole.query.filter_by(
        user_id=test_user.id,
        service_id=test_service.id,
        role_id=test_role.id
    ).first()
    assert user_role is None


def test_remove_role_from_user_not_assigned(db_session, test_user, test_service, test_role):
    """Test removing a role that's not assigned."""
    result = remove_role_from_user(test_user.id, test_service.id, test_role.id)
    
    assert result['success'] is False
    assert 'not assigned' in result['message']


def test_create_role(db_session, test_service):
    """Test creating a new role."""
    # Create some permissions
    perm1 = Permission(name='test:read', description='Test read permission')
    perm2 = Permission(name='test:write', description='Test write permission')
    db_session.add_all([perm1, perm2])
    db_session.commit()
    
    result = create_role(
        test_service.id,
        'test_role',
        'Test role description',
        [perm1.id, perm2.id]
    )
    
    assert result['success'] is True
    assert 'role_id' in result
    
    # Check database
    role = Role.query.filter_by(name='test_role', service_id=test_service.id).first()
    assert role is not None
    assert role.description == 'Test role description'
    assert len(role.permissions) == 2
    perm_names = [p.name for p in role.permissions]
    assert 'test:read' in perm_names
    assert 'test:write' in perm_names


def test_create_role_duplicate_name(db_session, test_service, test_role):
    """Test creating a role with a duplicate name."""
    result = create_role(
        test_service.id,
        test_role.name,  # Use existing role name
        'Another description'
    )
    
    assert result['success'] is False
    assert 'already exists' in result['message']


def test_update_role(db_session, test_service):
    """Test updating a role."""
    # Create a role
    role = Role(name='update_role', description='Original description', service_id=test_service.id)
    db_session.add(role)
    db_session.commit()
    
    # Create some permissions
    perm1 = Permission(name='update:read', description='Update read permission')
    perm2 = Permission(name='update:write', description='Update write permission')
    db_session.add_all([perm1, perm2])
    db_session.commit()
    
    # Update the role
    result = update_role(
        role.id,
        name='updated_role',
        description='Updated description',
        permissions=[perm1.id, perm2.id]
    )
    
    assert result['success'] is True
    
    # Check database
    updated_role = Role.query.get(role.id)
    assert updated_role.name == 'updated_role'
    assert updated_role.description == 'Updated description'
    assert len(updated_role.permissions) == 2
    perm_names = [p.name for p in updated_role.permissions]
    assert 'update:read' in perm_names
    assert 'update:write' in perm_names


def test_update_role_not_found(db_session):
    """Test updating a non-existent role."""
    result = update_role(999, name='nonexistent')
    
    assert result['success'] is False
    assert 'not found' in result['message']


def test_update_role_duplicate_name(db_session, test_service):
    """Test updating a role with a duplicate name."""
    # Create two roles
    role1 = Role(name='role1', service_id=test_service.id)
    role2 = Role(name='role2', service_id=test_service.id)
    db_session.add_all([role1, role2])
    db_session.commit()
    
    # Try to update role2 to have the same name as role1
    result = update_role(role2.id, name='role1')
    
    assert result['success'] is False
    assert 'already exists' in result['message']


def test_delete_role(db_session, test_service):
    """Test deleting a role."""
    # Create a role
    role = Role(name='delete_role', service_id=test_service.id)
    db_session.add(role)
    db_session.commit()
    
    result = delete_role(role.id)
    
    assert result['success'] is True
    
    # Check database
    deleted_role = Role.query.get(role.id)
    assert deleted_role is None


def test_delete_role_not_found(db_session):
    """Test deleting a non-existent role."""
    result = delete_role(999)
    
    assert result['success'] is False
    assert 'not found' in result['message']


def test_delete_default_role(db_session, test_service):
    """Test deleting a default role."""
    # Create a default role
    role = Role(name='default_role', service_id=test_service.id, is_default=True)
    db_session.add(role)
    db_session.commit()
    
    result = delete_role(role.id)
    
    assert result['success'] is False
    assert 'default role' in result['message']
    
    # Check database - role should still exist
    role = Role.query.get(role.id)
    assert role is not None

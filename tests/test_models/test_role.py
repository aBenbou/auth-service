import pytest
from app.models.role import Role, Permission, RolePermission
from app.models.service import Service


def test_permission_creation(db_session):
    """Test creating permissions."""
    perm = Permission(name='test:perm', description='Test permission')
    db_session.add(perm)
    db_session.commit()
    
    saved_perm = Permission.query.filter_by(name='test:perm').first()
    assert saved_perm is not None
    assert saved_perm.name == 'test:perm'
    assert saved_perm.description == 'Test permission'


def test_role_creation(db_session):
    """Test creating roles."""
    # Create service first
    service = Service(name='test_service')
    db_session.add(service)
    db_session.commit()
    
    # Create role
    role = Role(
        name='test_role',
        description='Test role',
        service_id=service.id,
        is_default=True
    )
    db_session.add(role)
    db_session.commit()
    
    saved_role = Role.query.filter_by(name='test_role').first()
    assert saved_role is not None
    assert saved_role.name == 'test_role'
    assert saved_role.description == 'Test role'
    assert saved_role.service_id == service.id
    assert saved_role.is_default is True


def test_role_permission_association(db_session):
    """Test associating permissions with roles."""
    # Create service
    service = Service(name='test_service')
    db_session.add(service)
    db_session.commit()
    
    # Create role
    role = Role(name='test_role', service_id=service.id)
    db_session.add(role)
    db_session.commit()
    
    # Create permissions
    perm1 = Permission(name='test:read', description='Test read')
    perm2 = Permission(name='test:write', description='Test write')
    db_session.add_all([perm1, perm2])
    db_session.commit()
    
    # Add permissions to role
    role.add_permission(perm1)
    role.add_permission(perm2)
    db_session.commit()
    
    # Check permissions
    saved_role = Role.query.get(role.id)
    assert len(saved_role.permissions) == 2
    perm_names = [p.name for p in saved_role.permissions]
    assert 'test:read' in perm_names
    assert 'test:write' in perm_names
    
    # Test has_permission method
    assert role.has_permission('test:read') is True
    assert role.has_permission('test:write') is True
    assert role.has_permission('test:nonexistent') is False
    
    # Test removing permission
    role.remove_permission(perm1)
    db_session.commit()
    saved_role = Role.query.get(role.id)
    assert len(saved_role.permissions) == 1
    assert saved_role.permissions[0].name == 'test:write'


def test_role_to_dict(db_session):
    """Test the to_dict method."""
    # Create service
    service = Service(name='test_service')
    db_session.add(service)
    db_session.commit()
    
    # Create role
    role = Role(
        name='test_role',
        description='Test role',
        service_id=service.id
    )
    db_session.add(role)
    db_session.commit()
    
    # Create permission
    perm = Permission(name='test:perm', description='Test permission')
    db_session.add(perm)
    db_session.commit()
    
    # Add permission to role
    role.add_permission(perm)
    db_session.commit()
    
    # Test to_dict
    role_dict = role.to_dict()
    assert role_dict['name'] == 'test_role'
    assert role_dict['description'] == 'Test role'
    assert role_dict['service_id'] == service.id
    assert len(role_dict['permissions']) == 1
    assert role_dict['permissions'][0]['name'] == 'test:perm'


def test_permission_to_dict(db_session):
    """Test the Permission to_dict method."""
    perm = Permission(name='test:perm', description='Test permission')
    db_session.add(perm)
    db_session.commit()
    
    perm_dict = perm.to_dict()
    assert perm_dict['name'] == 'test:perm'
    assert perm_dict['description'] == 'Test permission' 
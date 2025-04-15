import pytest
import json
from app.models.role import Role, Permission
from app.models.user_service_role import UserServiceRole
from app.models.service import Service


def test_get_user_roles(client, test_user, test_service, test_role, admin_token, db_session):
    """Test getting user roles for a service."""
    # Assign role to user
    user_role = UserServiceRole(
        user_id=test_user.id,
        service_id=test_service.id,
        role_id=test_role.id
    )
    db_session.add(user_role)
    db_session.commit()
    
    response = client.get(
        f'/api/roles/user/{test_user.public_id}/service/{test_service.public_id}',
        headers={'Authorization': f'Bearer {admin_token["access_token"]}'}
    )
    
    assert response.status_code == 200
    data = json.loads(response.data)
    assert data['success'] is True
    assert len(data['roles']) == 1
    assert data['roles'][0]['role_id'] == test_role.id
    assert data['roles'][0]['role_name'] == test_role.name


def test_assign_role(client, test_user, test_service, test_role, admin_token, db_session):
    """Test assigning a role to a user."""
    response = client.post(
        f'/api/roles/user/{test_user.public_id}/service/{test_service.public_id}/role/{test_role.id}',
        headers={'Authorization': f'Bearer {admin_token["access_token"]}'}
    )
    
    assert response.status_code == 201
    data = json.loads(response.data)
    assert data['success'] is True
    
    # Check database
    user_role = UserServiceRole.query.filter_by(
        user_id=test_user.id,
        service_id=test_service.id,
        role_id=test_role.id
    ).first()
    
    assert user_role is not None


def test_remove_role(client, test_user, test_service, test_role, admin_token, db_session):
    """Test removing a role from a user."""
    # First assign the role
    user_role = UserServiceRole(
        user_id=test_user.id,
        service_id=test_service.id,
        role_id=test_role.id
    )
    db_session.add(user_role)
    db_session.commit()
    
    response = client.delete(
        f'/api/roles/user/{test_user.public_id}/service/{test_service.public_id}/role/{test_role.id}',
        headers={'Authorization': f'Bearer {admin_token["access_token"]}'}
    )
    
    assert response.status_code == 200
    data = json.loads(response.data)
    assert data['success'] is True
    
    # Check database
    user_role = UserServiceRole.query.filter_by(
        user_id=test_user.id,
        service_id=test_service.id,
        role_id=test_role.id
    ).first()
    
    assert user_role is None


def test_create_role(client, test_service, admin_token, db_session):
    """Test creating a new role."""
    # Create permissions for the role
    perm1 = Permission(name='test:read', description='Test read permission')
    perm2 = Permission(name='test:write', description='Test write permission')
    db_session.add_all([perm1, perm2])
    db_session.commit()
    
    role_data = {
        'name': 'Test Role',
        'description': 'A test role',
        'permissions': [perm1.id, perm2.id]
    }
    
    response = client.post(
        f'/api/roles/service/{test_service.public_id}',
        headers={'Authorization': f'Bearer {admin_token["access_token"]}'},
        json=role_data
    )
    
    assert response.status_code == 201
    data = json.loads(response.data)
    assert data['success'] is True
    assert 'role_id' in data
    
    # Check database
    role = Role.query.filter_by(name=role_data['name'], service_id=test_service.id).first()
    assert role is not None
    assert role.description == role_data['description']
    assert len(role.permissions) == 2
    perm_ids = [p.id for p in role.permissions]
    assert perm1.id in perm_ids
    assert perm2.id in perm_ids


def test_update_role(client, test_role, admin_token, db_session):
    """Test updating a role."""
    # Create permissions for the role
    perm1 = Permission(name='test:update:read', description='Test update read permission')
    perm2 = Permission(name='test:update:admin', description='Test update admin permission')
    db_session.add_all([perm1, perm2])
    db_session.commit()
    
    role_data = {
        'name': 'Updated Role',
        'description': 'An updated role',
        'permissions': [perm1.id, perm2.id]
    }
    
    response = client.put(
        f'/api/roles/{test_role.id}',
        headers={'Authorization': f'Bearer {admin_token["access_token"]}'},
        json=role_data
    )
    
    assert response.status_code == 200
    data = json.loads(response.data)
    assert data['success'] is True
    
    # Check database
    db_session.refresh(test_role)
    assert test_role.name == role_data['name']
    assert test_role.description == role_data['description']
    perm_ids = [p.id for p in test_role.permissions]
    assert perm1.id in perm_ids
    assert perm2.id in perm_ids


def test_delete_role(client, admin_token, db_session):
    """Test deleting a role."""
    # Create a role to delete
    service = Service(name='delete_role_test_service')
    db_session.add(service)
    db_session.commit()
    
    role = Role(
        name='Role to Delete',
        description='This role will be deleted',
        service_id=service.id
    )
    db_session.add(role)
    db_session.commit()
    
    response = client.delete(
        f'/api/roles/{role.id}',
        headers={'Authorization': f'Bearer {admin_token["access_token"]}'}
    )
    
    assert response.status_code == 200
    data = json.loads(response.data)
    assert data['success'] is True
    
    # Check database
    deleted_role = Role.query.get(role.id)
    assert deleted_role is None


def test_get_service_roles(client, test_service, test_role, admin_token):
    """Test getting all roles for a service."""
    response = client.get(
        f'/api/roles/service/{test_service.public_id}',
        headers={'Authorization': f'Bearer {admin_token["access_token"]}'}
    )
    
    assert response.status_code == 200
    data = json.loads(response.data)
    assert data['success'] is True
    assert len(data['roles']) >= 1
    
    # Find our test role in the list
    test_role_data = None
    for role in data['roles']:
        if role['id'] == test_role.id:
            test_role_data = role
            break
    
    assert test_role_data is not None
    assert test_role_data['name'] == test_role.name


def test_get_permissions(client, admin_token, db_session):
    """Test getting all available permissions."""
    # Add a permission for testing
    perm = Permission(name='api:test:perm', description='API test permission')
    db_session.add(perm)
    db_session.commit()
    
    response = client.get(
        '/api/roles/permissions',
        headers={'Authorization': f'Bearer {admin_token["access_token"]}'}
    )
    
    assert response.status_code == 200
    data = json.loads(response.data)
    assert data['success'] is True
    assert len(data['permissions']) >= 1
    
    # Find our test permission in the list
    test_perm = None
    for p in data['permissions']:
        if p['name'] == 'api:test:perm':
            test_perm = p
            break
    
    assert test_perm is not None
    assert test_perm['description'] == 'API test permission'


def test_get_services(client, test_service, admin_token):
    """Test getting all services."""
    response = client.get(
        '/api/roles/services',
        headers={'Authorization': f'Bearer {admin_token["access_token"]}'}
    )
    
    assert response.status_code == 200
    data = json.loads(response.data)
    assert data['success'] is True
    assert len(data['services']) >= 1
    
    # Find our test service in the list
    test_service_data = None
    for service in data['services']:
        if service['id'] == test_service.public_id:
            test_service_data = service
            break
    
    assert test_service_data is not None
    assert test_service_data['name'] == test_service.name


def test_get_user_services(client, test_user, test_service, test_role, user_token, db_session):
    """Test getting services for a user."""
    # Assign role to user
    user_role = UserServiceRole(
        user_id=test_user.id,
        service_id=test_service.id,
        role_id=test_role.id
    )
    db_session.add(user_role)
    db_session.commit()
    
    response = client.get(
        '/api/roles/services/user',
        headers={'Authorization': f'Bearer {user_token["access_token"]}'}
    )
    
    assert response.status_code == 200
    data = json.loads(response.data)
    assert data['success'] is True
    assert len(data['services']) >= 1
    
    # Find our test service in the list
    test_service_data = None
    for service in data['services']:
        if service['id'] == test_service.public_id:
            test_service_data = service
            break
    
    assert test_service_data is not None
    assert test_service_data['name'] == test_service.name


def test_create_service(client, admin_token, db_session):
    """Test creating a new service."""
    service_data = {
        'name': 'API Created Service',
        'description': 'Service created via API'
    }
    
    response = client.post(
        '/api/roles/services',
        headers={'Authorization': f'Bearer {admin_token["access_token"]}'},
        json=service_data
    )
    
    assert response.status_code == 201
    data = json.loads(response.data)
    assert data['success'] is True
    assert 'service_id' in data
    
    # Check database
    service = Service.query.filter_by(name=service_data['name']).first()
    assert service is not None
    assert service.description == service_data['description']
    
    # Check default roles created
    roles = Role.query.filter_by(service_id=service.id).all()
    assert len(roles) >= 1


def test_update_service(client, test_service, admin_token, db_session):
    """Test updating a service."""
    service_data = {
        'name': 'Updated Service',
        'description': 'An updated service',
        'is_active': False
    }
    
    response = client.put(
        f'/api/roles/services/{test_service.public_id}',
        headers={'Authorization': f'Bearer {admin_token["access_token"]}'},
        json=service_data
    )
    
    assert response.status_code == 200
    data = json.loads(response.data)
    assert data['success'] is True
    
    # Check database
    db_session.refresh(test_service)
    assert test_service.name == service_data['name']
    assert test_service.description == service_data['description']
    assert test_service.is_active is False


def test_delete_service(client, admin_token, db_session):
    """Test deleting a service."""
    # Create a service to delete
    service = Service(name='service_to_delete_api')
    db_session.add(service)
    db_session.commit()
    
    response = client.delete(
        f'/api/roles/services/{service.public_id}',
        headers={'Authorization': f'Bearer {admin_token["access_token"]}'}
    )
    
    assert response.status_code == 200
    data = json.loads(response.data)
    assert data['success'] is True
    
    # Check database
    deleted_service = Service.query.get(service.id)
    assert deleted_service is None 
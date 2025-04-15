import pytest
import json
from app.models.app_token import AppToken


def test_create_token(client, test_service, admin_token):
    """Test creating an application token."""
    response = client.post(
        '/api/tokens/',
        json={
            'service_id': test_service.public_id,
            'name': 'Test API Token'
        },
        headers={'Authorization': f'Bearer {admin_token["access_token"]}'}
    )
    
    assert response.status_code == 201
    data = json.loads(response.data)
    assert data['success'] is True
    assert 'token_data' in data
    assert data['token_data']['name'] == 'Test API Token'
    assert 'token' in data['token_data']  # Raw token is returned
    
    # Check database
    token = AppToken.query.filter_by(name='Test API Token').first()
    assert token is not None
    assert token.service_id == test_service.id
    assert token.is_active is True


def test_create_token_missing_fields(client, admin_token):
    """Test creating a token with missing fields."""
    response = client.post(
        '/api/tokens/',
        json={
            'name': 'Test API Token'
            # Missing service_id
        },
        headers={'Authorization': f'Bearer {admin_token["access_token"]}'}
    )
    
    assert response.status_code == 400
    data = json.loads(response.data)
    assert data['success'] is False
    assert 'required' in data['message']


def test_create_token_service_not_found(client, admin_token):
    """Test creating a token with non-existent service."""
    response = client.post(
        '/api/tokens/',
        json={
            'service_id': 'non-existent-id',
            'name': 'Test API Token'
        },
        headers={'Authorization': f'Bearer {admin_token["access_token"]}'}
    )
    
    assert response.status_code == 404
    data = json.loads(response.data)
    assert data['success'] is False
    assert 'Service not found' in data['message']


def test_get_service_tokens(client, test_service, test_app_token, admin_token):
    """Test getting all tokens for a service."""
    response = client.get(
        f'/api/tokens/service/{test_service.public_id}',
        headers={'Authorization': f'Bearer {admin_token["access_token"]}'}
    )
    
    assert response.status_code == 200
    data = json.loads(response.data)
    assert data['success'] is True
    assert len(data['tokens']) >= 1
    
    # Find our test token in the list
    test_token = None
    for token in data['tokens']:
        if token['name'] == test_app_token.name:
            test_token = token
            break
    
    assert test_token is not None
    assert test_token['service_id'] == test_service.public_id
    assert 'token' not in test_token  # Raw token should not be returned


def test_get_service_tokens_service_not_found(client, admin_token):
    """Test getting tokens for a non-existent service."""
    response = client.get(
        '/api/tokens/service/non-existent-id',
        headers={'Authorization': f'Bearer {admin_token["access_token"]}'}
    )
    
    assert response.status_code == 404
    data = json.loads(response.data)
    assert data['success'] is False
    assert 'Service not found' in data['message']


def test_revoke_token(client, test_app_token, admin_token):
    """Test revoking a token."""
    response = client.post(
        f'/api/tokens/{test_app_token.id}/revoke',
        headers={'Authorization': f'Bearer {admin_token["access_token"]}'}
    )
    
    assert response.status_code == 200
    data = json.loads(response.data)
    assert data['success'] is True
    
    # Check database
    updated_token = AppToken.query.get(test_app_token.id)
    assert updated_token.is_active is False


def test_revoke_token_not_found(client, admin_token):
    """Test revoking a non-existent token."""
    response = client.post(
        '/api/tokens/999/revoke',
        headers={'Authorization': f'Bearer {admin_token["access_token"]}'}
    )
    
    assert response.status_code == 404
    data = json.loads(response.data)
    assert data['success'] is False
    assert 'Token not found' in data['message']


def test_delete_token(client, test_app_token, admin_token):
    """Test deleting a token."""
    response = client.delete(
        f'/api/tokens/{test_app_token.id}',
        headers={'Authorization': f'Bearer {admin_token["access_token"]}'}
    )
    
    assert response.status_code == 200
    data = json.loads(response.data)
    assert data['success'] is True
    
    # Check database
    deleted_token = AppToken.query.get(test_app_token.id)
    assert deleted_token is None


def test_delete_token_not_found(client, admin_token):
    """Test deleting a non-existent token."""
    response = client.delete(
        '/api/tokens/999',
        headers={'Authorization': f'Bearer {admin_token["access_token"]}'}
    )
    
    assert response.status_code == 404
    data = json.loads(response.data)
    assert data['success'] is False
    assert 'Token not found' in data['message']


def test_validate_token(client, test_app_token):
    """Test validating a token."""
    response = client.get(
        '/api/tokens/validate',
        headers={'Authorization': f'Bearer {test_app_token.token}'}
    )
    
    assert response.status_code == 200
    data = json.loads(response.data)
    assert data['success'] is True
    assert data['service']['id'] == test_app_token.service.public_id
    assert data['service']['name'] == test_app_token.service.name


def test_validate_token_invalid(client):
    """Test validating an invalid token."""
    response = client.get(
        '/api/tokens/validate',
        headers={'Authorization': 'Bearer invalid-token'}
    )
    
    assert response.status_code == 401
    data = json.loads(response.data)
    assert data['success'] is False
    assert 'Invalid' in data['message']


def test_validate_token_missing_auth_header(client):
    """Test validating a token without Authorization header."""
    response = client.get('/api/tokens/validate')
    
    assert response.status_code == 401
    data = json.loads(response.data)
    assert data['success'] is False
    assert 'Missing' in data['message'] 
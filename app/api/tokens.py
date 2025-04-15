from flask import Blueprint, request, jsonify, g
from app.utils.decorators import jwt_required_with_permissions, app_token_required
from app.services.token_service import (
    create_app_token,
    get_service_tokens,
    revoke_token,
    delete_token
)
from app.services.service_service import get_service_by_id

tokens_bp = Blueprint('tokens', __name__)

@tokens_bp.route('/', methods=['POST'])
@jwt_required_with_permissions(['token:write'])
def create_token():
    """Create a new application token for a service"""
    data = request.get_json()
    
    # Validate required fields
    if not data or not data.get('service_id') or not data.get('name'):
        return jsonify({'success': False, 'message': 'Service ID and name are required'}), 400
    
    # Get service
    service = get_service_by_id(data.get('service_id'))
    if not service:
        return jsonify({'success': False, 'message': 'Service not found'}), 404
    
    # Create token
    result = create_app_token(
        service_id=service.id,
        name=data.get('name'),
        expires_in_days=data.get('expires_in_days')
    )
    
    if result['success']:
        return jsonify(result), 201
    else:
        return jsonify(result), 400


@tokens_bp.route('/service/<service_id>', methods=['GET'])
@jwt_required_with_permissions(['token:read'])
def get_tokens(service_id):
    """Get all tokens for a service"""
    # Get service
    service = get_service_by_id(service_id)
    if not service:
        return jsonify({'success': False, 'message': 'Service not found'}), 404
    
    # Get tokens
    tokens = get_service_tokens(service.id)
    
    return jsonify({
        'success': True,
        'tokens': tokens
    }), 200


@tokens_bp.route('/<token_id>/revoke', methods=['POST'])
@jwt_required_with_permissions(['token:write'])
def revoke_token_route(token_id):
    """Revoke a token"""
    result = revoke_token(token_id)
    
    if result['success']:
        return jsonify(result), 200
    else:
        return jsonify(result), 404


@tokens_bp.route('/<token_id>', methods=['DELETE'])
@jwt_required_with_permissions(['token:delete'])
def delete_token_route(token_id):
    """Delete a token"""
    result = delete_token(token_id)
    
    if result['success']:
        return jsonify(result), 200
    else:
        return jsonify(result), 404


@tokens_bp.route('/validate', methods=['GET'])
@app_token_required
def validate_token():
    """Validate an app token (used by other microservices)"""
    service = g.current_service
    
    return jsonify({
        'success': True,
        'service': service.to_dict()
    }), 200 
from flask import Blueprint, request, jsonify, g
from app.utils.decorators import jwt_required_with_permissions
from app.services.role_service import (
    get_user_roles,
    assign_role_to_user,
    remove_role_from_user,
    create_role,
    update_role,
    delete_role
)
from app.services.service_service import (
    get_service_by_id,
    get_all_services,
    create_service,
    update_service,
    delete_service,
    get_services_for_user
)
from app.models.role import Role, Permission
from app.models.user import User
from app import db

roles_bp = Blueprint('roles', __name__)

# Role management endpoints
@roles_bp.route('/user/<user_id>/service/<service_id>', methods=['GET'])
@jwt_required_with_permissions(['role:read'])
def get_user_roles_route(user_id, service_id):
    """Get all roles for a user in a specific service"""
    # Get user
    user = User.query.filter_by(public_id=user_id).first()
    if not user:
        return jsonify({'success': False, 'message': 'User not found'}), 404
    
    # Get service
    service = get_service_by_id(service_id)
    if not service:
        return jsonify({'success': False, 'message': 'Service not found'}), 404
    
    # Get roles
    user_roles = get_user_roles(user.id, service.id)
    
    return jsonify({
        'success': True,
        'roles': [ur.to_dict() for ur in user_roles]
    }), 200


@roles_bp.route('/user/<user_id>/service/<service_id>/role/<role_id>', methods=['POST'])
@jwt_required_with_permissions(['role:write'])
def assign_role(user_id, service_id, role_id):
    """Assign a role to a user for a specific service"""
    # Get user
    user = User.query.filter_by(public_id=user_id).first()
    if not user:
        return jsonify({'success': False, 'message': 'User not found'}), 404
    
    # Get service
    service = get_service_by_id(service_id)
    if not service:
        return jsonify({'success': False, 'message': 'Service not found'}), 404
    
    # Get role
    role = Role.query.get(role_id)
    if not role:
        return jsonify({'success': False, 'message': 'Role not found'}), 404
    
    # Assign role
    result = assign_role_to_user(user.id, service.id, role.id)
    
    if result['success']:
        return jsonify(result), 201
    else:
        return jsonify(result), 400


@roles_bp.route('/user/<user_id>/service/<service_id>/role/<role_id>', methods=['DELETE'])
@jwt_required_with_permissions(['role:write'])
def remove_role(user_id, service_id, role_id):
    """Remove a role from a user for a specific service"""
    # Get user
    user = User.query.filter_by(public_id=user_id).first()
    if not user:
        return jsonify({'success': False, 'message': 'User not found'}), 404
    
    # Get service
    service = get_service_by_id(service_id)
    if not service:
        return jsonify({'success': False, 'message': 'Service not found'}), 404
    
    # Get role
    role = Role.query.get(role_id)
    if not role:
        return jsonify({'success': False, 'message': 'Role not found'}), 404
    
    # Remove role
    result = remove_role_from_user(user.id, service.id, role.id)
    
    if result['success']:
        return jsonify(result), 200
    else:
        return jsonify(result), 400


@roles_bp.route('/service/<service_id>', methods=['POST'])
@jwt_required_with_permissions(['role:write'])
def create_role_route(service_id):
    """Create a new role for a service"""
    data = request.get_json()
    
    # Validate required fields
    if not data or not data.get('name'):
        return jsonify({'success': False, 'message': 'Role name is required'}), 400
    
    # Get service
    service = get_service_by_id(service_id)
    if not service:
        return jsonify({'success': False, 'message': 'Service not found'}), 404
    
    # Create role
    result = create_role(
        service_id=service.id,
        name=data.get('name'),
        description=data.get('description'),
        permissions=data.get('permissions')
    )
    
    if result['success']:
        return jsonify(result), 201
    else:
        return jsonify(result), 400


@roles_bp.route('/<role_id>', methods=['PUT'])
@jwt_required_with_permissions(['role:write'])
def update_role_route(role_id):
    """Update a role"""
    data = request.get_json()
    
    # Update role
    result = update_role(
        role_id=role_id,
        name=data.get('name'),
        description=data.get('description'),
        permissions=data.get('permissions')
    )
    
    if result['success']:
        return jsonify(result), 200
    else:
        return jsonify(result), 400


@roles_bp.route('/<role_id>', methods=['DELETE'])
@jwt_required_with_permissions(['role:delete'])
def delete_role_route(role_id):
    """Delete a role"""
    result = delete_role(role_id)
    
    if result['success']:
        return jsonify(result), 200
    else:
        return jsonify(result), 400


@roles_bp.route('/service/<service_id>', methods=['GET'])
@jwt_required_with_permissions(['role:read'])
def get_service_roles(service_id):
    """Get all roles for a service"""
    # Get service
    service = get_service_by_id(service_id)
    if not service:
        return jsonify({'success': False, 'message': 'Service not found'}), 404
    
    # Get roles
    roles = Role.query.filter_by(service_id=service.id).all()
    
    return jsonify({
        'success': True,
        'roles': [role.to_dict() for role in roles]
    }), 200


@roles_bp.route('/permissions', methods=['GET'])
@jwt_required_with_permissions(['role:read'])
def get_permissions():
    """Get all available permissions"""
    permissions = Permission.query.all()
    
    return jsonify({
        'success': True,
        'permissions': [perm.to_dict() for perm in permissions]
    }), 200


# Service management endpoints
@roles_bp.route('/services', methods=['GET'])
@jwt_required_with_permissions(['service:read'])
def get_services():
    """Get all services"""
    services = get_all_services()
    
    return jsonify({
        'success': True,
        'services': services
    }), 200


@roles_bp.route('/services/user', methods=['GET'])
@jwt_required_with_permissions()
def get_user_services():
    """Get all services for the current user"""
    user = g.current_user
    
    services = get_services_for_user(user.id)
    
    return jsonify({
        'success': True,
        'services': services
    }), 200


@roles_bp.route('/services', methods=['POST'])
@jwt_required_with_permissions(['service:write'])
def create_service_route():
    """Create a new service"""
    data = request.get_json()
    
    # Validate required fields
    if not data or not data.get('name'):
        return jsonify({'success': False, 'message': 'Service name is required'}), 400
    
    # Create service
    result = create_service(
        name=data.get('name'),
        description=data.get('description')
    )
    
    if result['success']:
        return jsonify(result), 201
    else:
        return jsonify(result), 400


@roles_bp.route('/services/<service_id>', methods=['PUT'])
@jwt_required_with_permissions(['service:write'])
def update_service_route(service_id):
    """Update a service"""
    data = request.get_json()
    
    # Update service
    result = update_service(
        service_id=service_id,
        name=data.get('name'),
        description=data.get('description'),
        is_active=data.get('is_active')
    )
    
    if result['success']:
        return jsonify(result), 200
    else:
        return jsonify(result), 400


@roles_bp.route('/services/<service_id>', methods=['DELETE'])
@jwt_required_with_permissions(['service:delete'])
def delete_service_route(service_id):
    """Delete a service"""
    result = delete_service(service_id)
    
    if result['success']:
        return jsonify(result), 200
    else:
        return jsonify(result), 400 
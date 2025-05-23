from flask import Blueprint, request, jsonify, g, current_app
from app.utils.decorators import jwt_required_with_permissions
from app.services.role_service import (
    get_user_roles,
    assign_role_to_user,
    remove_role_from_user,
    create_role,
    update_role,
    delete_role,
    assign_default_role_to_users,
    promote_to_validator
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
from app.models.service import Service
from app.models.user_service_role import UserServiceRole

roles_bp = Blueprint('roles', __name__)

# Role management endpoints
@roles_bp.route('/user/<user_id>/service/<service_id>', methods=['GET'])
@jwt_required_with_permissions(['role:read'])
def get_user_roles_route(user_id, service_id):
    """Get all roles for a user in a specific service"""
    # Get user
    user = User.query.filter_by(public_id=user_id).first()
    current_app.logger.info(f'Fetching roles for user {user_id} and service {service_id}')
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
    current_app.logger.info(f'Assigning role {role_id} to user {user_id} for service {service_id}')
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
    current_app.logger.info(f'Removing role {role_id} from user {user_id} for service {service_id}')
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
    current_app.logger.info(f'Creating new role for service {service_id} with data: {request.get_json()}')
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
    current_app.logger.info(f'Updating role {role_id} with data: {request.get_json()}')
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
    current_app.logger.info(f'Deleting role {role_id}')
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
    current_app.logger.info(f'Fetching roles for service {service_id}')
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
    print("Fetching all permissions")
    permissions = Permission.query.all()
    current_app.logger.info('Fetching all permissions')
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


@roles_bp.route('/assign-default-roles', methods=['POST'])
@jwt_required_with_permissions(['role:write'])
def assign_default_roles():
    """Assign default roles to users who don't have any roles"""
    result = assign_default_role_to_users()
    if result['success']:
        return jsonify(result), 200
    return jsonify(result), 400


@roles_bp.route('/user/<user_id>/promote-to-validator', methods=['POST'])
@jwt_required_with_permissions(['role:write'])
def promote_to_validator_route(user_id):
    """Promote a user to validator role"""
    result = promote_to_validator(user_id)
    if result['success']:
        return jsonify(result), 200
    return jsonify(result), 400


@roles_bp.route('/debug/user-permissions', methods=['GET'])
@jwt_required_with_permissions()
def debug_user_permissions():
    """Debug endpoint to check user permissions"""
    user = g.user
    auth_service = Service.query.filter_by(name='auth_service').first()
    
    if not auth_service:
        return jsonify({'error': 'Auth service not found'}), 404
    
    # Get user's roles for auth_service
    user_roles = UserServiceRole.query.filter_by(
        user_id=user.id,
        service_id=auth_service.id
    ).all()
    
    # Get all permissions for these roles
    permissions = set()
    for user_role in user_roles:
        role = Role.query.get(user_role.role_id)
        if role:
            for perm in role.permissions:
                permissions.add(perm.name)
    
    return jsonify({
        'user_id': user.public_id,
        'roles': [ur.role.name for ur in user_roles],
        'permissions': list(permissions)
    }), 200

from app import db
from app.models.role import Role, Permission, RolePermission
from app.models.service import Service
from app.models.user_service_role import UserServiceRole
from flask import current_app
from app.models.user import User

def initialize_default_roles():
    """Initialize default roles and permissions for the auth service itself"""
    # Create default permissions if they don't exist
    default_permissions = [
        # Existing Auth Service Permissions
        {'name': 'user:read', 'description': 'Read user information'},
        {'name': 'user:write', 'description': 'Create and update users'},
        {'name': 'user:delete', 'description': 'Delete users'},
        {'name': 'role:read', 'description': 'Read roles and permissions'},
        {'name': 'role:write', 'description': 'Create and update roles and permissions'},
        {'name': 'role:delete', 'description': 'Delete roles'},
        {'name': 'service:read', 'description': 'Read service information'},
        {'name': 'service:write', 'description': 'Create and update services'},
        {'name': 'service:delete', 'description': 'Delete services'},
        {'name': 'token:read', 'description': 'Read tokens'},
        {'name': 'token:write', 'description': 'Create and update tokens'},
        {'name': 'token:delete', 'description': 'Delete tokens'},
        
        # Model Management Permissions
        {'name': 'model:read', 'description': 'View deployed models'},
        {'name': 'model:deploy', 'description': 'Deploy new models'},
        {'name': 'model:delete', 'description': 'Remove deployed models'},
        
        # Dimension Management Permissions
        {'name': 'dimension:read', 'description': 'View evaluation dimensions'},
        {'name': 'dimension:write', 'description': 'Create and update dimensions'},
        {'name': 'dimension:delete', 'description': 'Delete evaluation dimensions'},
        
        # Interaction Permissions
        {'name': 'interaction:read', 'description': 'View model interactions'},
        {'name': 'interaction:write', 'description': 'Create interactions with models'},
        {'name': 'interaction:delete', 'description': 'Delete interactions'},
        
        # Feedback Permissions
        {'name': 'feedback:read', 'description': 'View user feedback'},
        {'name': 'feedback:write', 'description': 'Submit feedback on model outputs'},
        {'name': 'feedback:delete', 'description': 'Delete feedback entries'},
        
        # Validation Permissions
        {'name': 'validation:read', 'description': 'View validation status'},
        {'name': 'validation:write', 'description': 'Validate user feedback'},
        
        # Dataset Permissions
        {'name': 'dataset:read', 'description': 'View training datasets'},
        {'name': 'dataset:write', 'description': 'Manage dataset entries'},
        {'name': 'dataset:delete', 'description': 'Delete dataset entries'}
    ]
    
    for perm_data in default_permissions:
        if not Permission.query.filter_by(name=perm_data['name']).first():
            perm = Permission(name=perm_data['name'], description=perm_data['description'])
            db.session.add(perm)
    
    db.session.commit()
    
    # Create auth service if it doesn't exist
    auth_service = Service.query.filter_by(name='auth_service').first()
    if not auth_service:
        auth_service = Service(
            name='auth_service',
            description='Authentication and Authorization Service'
        )
        db.session.add(auth_service)
        db.session.commit()
    
    # Create default roles
    default_roles = [
        # Existing Admin Role (with expanded permissions)
        {
            'name': 'admin',
            'description': 'Administrator with full access',
            'permissions': [
                # Auth service permissions
                'user:read', 'user:write', 'user:delete', 
                'role:read', 'role:write', 'role:delete',
                'service:read', 'service:write', 'service:delete',
                'token:read', 'token:write', 'token:delete',
                # Model feedback system permissions
                'model:read', 'model:deploy', 'model:delete',
                'dimension:read', 'dimension:write', 'dimension:delete',
                'interaction:read', 'interaction:write', 'interaction:delete',
                'feedback:read', 'feedback:write', 'feedback:delete',
                'validation:read', 'validation:write',
                'dataset:read', 'dataset:write', 'dataset:delete'
            ]
        },
        
        # Existing Auth Service Roles
        {
            'name': 'user_manager',
            'description': 'Can manage users',
            'permissions': ['user:read', 'user:write', 'user:delete']
        },
        {
            'name': 'service_manager',
            'description': 'Can manage services',
            'permissions': ['service:read', 'service:write']
        },
        {
            'name': 'token_manager',
            'description': 'Can manage tokens',
            'permissions': ['token:read', 'token:write', 'token:delete']
        },
        {
            'name': 'readonly',
            'description': 'Read-only access',
            'permissions': ['user:read', 'role:read', 'service:read', 'token:read']
        },
        
        # New Roles for Model Feedback System
        {
            'name': 'model_admin',
            'description': 'Can deploy and manage models',
            'permissions': [
                'model:read', 'model:deploy', 'model:delete', 
                'dimension:read', 'dimension:write', 'dimension:delete'
            ]
        },
        {
            'name': 'regular_user',
            'description': 'Can interact with models and provide feedback',
            'permissions': [
                'model:read',
                'dimension:read',
                'interaction:read',   # Usually limited to own interactions
                'interaction:write',  # To create new interactions
                'feedback:read',      # To view their own feedback
                'feedback:write'      # To submit feedback
            ]
        },
        {
            'name': 'validator',
            'description': 'Can interact with models, provide auto-validated feedback, and validate others\' feedback',
            'permissions': [
                # All regular user permissions
                'model:read',
                'dimension:read',
                'interaction:read',   
                'interaction:write',  
                'feedback:read',      
                'feedback:write',
                # Additional validator permissions     
                'validation:read',    # To view validation queue
                'validation:write',   # To validate others' feedback
                'dataset:read'        # To view resulting datasets
            ]
        },
        {
            'name': 'dataset_manager',
            'description': 'Can manage model training datasets',
            'permissions': [
                'dataset:read',
                'dataset:write',
                'dataset:delete',
                'feedback:read'       # To view feedback that becomes part of datasets
            ]
        }
    ]
    
    # Get all permissions
    all_permissions = {p.name: p for p in Permission.query.all()}
    
    for role_data in default_roles:
        role = Role.query.filter_by(name=role_data['name'], service_id=auth_service.id).first()
        
        if not role:
            role = Role(
                name=role_data['name'],
                description=role_data['description'],
                service_id=auth_service.id,
                is_default=(role_data['name'] == 'regular_user')  # Set regular_user as default role
            )
            db.session.add(role)
            db.session.commit()
            
            # Add permissions to role
            for perm_name in role_data['permissions']:
                perm = all_permissions.get(perm_name)
                if perm:
                    role.add_permission(perm)
            
            db.session.commit()


def get_user_roles(user_id, service_id=None):
    """Get all roles for a user, optionally filtered by service"""
    query = UserServiceRole.query.filter_by(user_id=user_id)
    
    if service_id:
        query = query.filter_by(service_id=service_id)
    
    user_roles = query.all()
    return user_roles


def assign_role_to_user(user_id, service_id, role_id):
    """Assign a role to a user for a specific service"""
    # Check if the role already assigned
    existing = UserServiceRole.query.filter_by(
        user_id=user_id,
        service_id=service_id,
        role_id=role_id
    ).first()
    
    if existing:
        return {'success': False, 'message': 'Role already assigned to user'}
    
    # Create the new assignment
    user_role = UserServiceRole(
        user_id=user_id,
        service_id=service_id,
        role_id=role_id
    )
    
    db.session.add(user_role)
    db.session.commit()
    
    return {'success': True, 'message': 'Role assigned successfully'}


def remove_role_from_user(user_id, service_id, role_id):
    """Remove a role from a user for a specific service"""
    user_role = UserServiceRole.query.filter_by(
        user_id=user_id,
        service_id=service_id,
        role_id=role_id
    ).first()
    
    if not user_role:
        return {'success': False, 'message': 'Role not assigned to user'}
    
    db.session.delete(user_role)
    db.session.commit()
    
    return {'success': True, 'message': 'Role removed successfully'}


def create_role(service_id, name, description, permissions=None):
    """Create a new role with optional permissions"""
    # Check if role already exists for this service
    existing = Role.query.filter_by(service_id=service_id, name=name).first()
    if existing:
        return {'success': False, 'message': 'Role with this name already exists for this service'}
    
    # Create new role
    role = Role(
        name=name,
        description=description,
        service_id=service_id
    )
    
    db.session.add(role)
    db.session.commit()
    
    # Add permissions if provided
    if permissions:
        for perm_id in permissions:
            perm = Permission.query.get(perm_id)
            if perm:
                role.add_permission(perm)
        
        db.session.commit()
    
    return {'success': True, 'message': 'Role created successfully', 'role_id': role.id}


def update_role(role_id, name=None, description=None, permissions=None):
    """Update an existing role"""
    role = Role.query.get(role_id)
    
    if not role:
        return {'success': False, 'message': 'Role not found'}
    
    if name:
        # Check for name conflicts
        existing = Role.query.filter_by(service_id=role.service_id, name=name).first()
        if existing and existing.id != role_id:
            return {'success': False, 'message': 'Another role with this name already exists for this service'}
        
        role.name = name
    
    if description:
        role.description = description
    
    # Update permissions if provided
    if permissions is not None:  # Check if None to distinguish from empty list
        # Remove all current permissions
        RolePermission.query.filter_by(role_id=role.id).delete()
        
        # Add new permissions
        for perm_id in permissions:
            perm = Permission.query.get(perm_id)
            if perm:
                role.add_permission(perm)
    
    db.session.commit()
    
    return {'success': True, 'message': 'Role updated successfully'}


def delete_role(role_id):
    """Delete a role"""
    role = Role.query.get(role_id)
    
    if not role:
        return {'success': False, 'message': 'Role not found'}
    
    # Check if it's a default role
    if role.is_default:
        return {'success': False, 'message': 'Cannot delete a default role'}
    
    db.session.delete(role)
    db.session.commit()
    
    return {'success': True, 'message': 'Role deleted successfully'}


def assign_default_role_to_users():
    """Assign the readonly role to users who don't have any roles"""

    auth_service = Service.query.filter_by(name='auth_service').first()
    if not auth_service:
        current_app.logger.error("Auth service not found")
        return {'success': False, 'message': 'Auth service not found'}
    
    # Get the readonly role
    readonly_role = Role.query.filter_by(name='readonly', service_id=auth_service.id).first()
    if not readonly_role:
        current_app.logger.error("Readonly role not found")
        return {'success': False, 'message': 'Readonly role not found'}
    
    # Get all users
    users = User.query.all()
    assigned_count = 0
    
    for user in users:
        existing_role = UserServiceRole.query.filter_by(
            user_id=user.id,
            service_id=auth_service.id
        ).first()
        
        if not existing_role:
            user_role = UserServiceRole(
                user_id=user.id,
                service_id=auth_service.id,
                role_id=readonly_role.id
            )
            db.session.add(user_role)
            assigned_count += 1
    
    if assigned_count > 0:
        db.session.commit()
        current_app.logger.info(f"Assigned readonly role to {assigned_count} users")
    
    return {'success': True, 'message': 'Role added successfully'}

def promote_to_validator(user_id):
    """Promote a user to validator role"""
    from app.models.user import User
    from app.models.service import Service
    from app.models.role import Role
    
    # Get the auth_service
    auth_service = Service.query.filter_by(name='auth_service').first()
    if not auth_service:
        return {'success': False, 'message': 'Auth service not found'}
    
    # Get the validator role
    validator_role = Role.query.filter_by(name='validator', service_id=auth_service.id).first()
    if not validator_role:
        return {'success': False, 'message': 'Validator role not found'}
    
    # Get the user
    user = User.query.filter_by(public_id=user_id).first()
    if not user:
        return {'success': False, 'message': 'User not found'}
    
    # Check if user already has validator role
    existing_role = UserServiceRole.query.filter_by(
        user_id=user.id,
        service_id=auth_service.id,
        role_id=validator_role.id
    ).first()
    
    if existing_role:
        return {'success': False, 'message': 'User already has validator role'}
    
    # Assign validator role
    user_role = UserServiceRole(
        user_id=user.id,
        service_id=auth_service.id,
        role_id=validator_role.id
    )
    db.session.add(user_role)
    db.session.commit()
    
    return {'success': True, 'message': 'User promoted to validator successfully'}
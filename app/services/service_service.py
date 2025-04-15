from app import db
from app.models.service import Service
from app.models.role import Role
from app.models.user_service_role import UserServiceRole

def create_service(name, description=None):
    """Create a new service/microservice"""
    # Check if service already exists
    existing = Service.query.filter_by(name=name).first()
    if existing:
        return {'success': False, 'message': 'Service with this name already exists'}
    
    # Create new service
    service = Service(
        name=name,
        description=description
    )
    
    db.session.add(service)
    db.session.commit()
    
    # Create default roles for this service
    create_default_roles_for_service(service.id)
    
    return {
        'success': True, 
        'message': 'Service created successfully', 
        'service_id': service.public_id
    }


def create_default_roles_for_service(service_id):
    """Create default roles for a new service"""
    default_roles = [
        {
            'name': 'admin',
            'description': 'Administrator with full access to this service'
        },
        {
            'name': 'user',
            'description': 'Regular user of this service',
            'is_default': True
        },
        {
            'name': 'readonly',
            'description': 'Read-only access to this service'
        }
    ]
    
    for role_data in default_roles:
        role = Role(
            name=role_data['name'],
            description=role_data['description'],
            service_id=service_id,
            is_default=role_data.get('is_default', False)
        )
        db.session.add(role)
    
    db.session.commit()


def get_service_by_id(service_id):
    """Get a service by its ID or public ID"""
    # Try to find by public ID first
    service = Service.query.filter_by(public_id=service_id).first()
    
    # If not found, try by numeric ID
    if not service and service_id.isdigit():
        service = Service.query.get(int(service_id))
    
    return service


def update_service(service_id, name=None, description=None, is_active=None):
    """Update a service's details"""
    service = get_service_by_id(service_id)
    
    if not service:
        return {'success': False, 'message': 'Service not found'}
    
    if name:
        # Check for name conflicts
        existing = Service.query.filter_by(name=name).first()
        if existing and existing.id != service.id:
            return {'success': False, 'message': 'Another service with this name already exists'}
        
        service.name = name
    
    if description is not None:
        service.description = description
    
    if is_active is not None:
        service.is_active = is_active
    
    db.session.commit()
    
    return {'success': True, 'message': 'Service updated successfully'}


def delete_service(service_id):
    """Delete a service and all associated data"""
    service = get_service_by_id(service_id)
    
    if not service:
        return {'success': False, 'message': 'Service not found'}
    
    # Check if it's the auth service, which shouldn't be deleted
    if service.name == 'auth_service':
        return {'success': False, 'message': 'Cannot delete the auth service'}
    
    # The cascading delete will handle related entities
    db.session.delete(service)
    db.session.commit()
    
    return {'success': True, 'message': 'Service deleted successfully'}


def get_all_services():
    """Get all services"""
    services = Service.query.all()
    return [service.to_dict() for service in services]


def get_services_for_user(user_id):
    """Get all services a user has roles for"""
    user_service_roles = UserServiceRole.query.filter_by(user_id=user_id).distinct(UserServiceRole.service_id).all()
    service_ids = [usr.service_id for usr in user_service_roles]
    services = Service.query.filter(Service.id.in_(service_ids)).all()
    return [service.to_dict() for service in services] 
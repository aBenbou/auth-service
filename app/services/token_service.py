from datetime import datetime, timedelta
from app import db
from app.models.app_token import AppToken
from app.models.service import Service

def create_app_token(service_id, name, expires_in_days=None):
    """Create a new application token for a service"""
    # Check if service exists
    service = Service.query.get(service_id)
    if not service:
        return {'success': False, 'message': 'Service not found'}
    
    # Check if token with this name already exists
    existing = AppToken.query.filter_by(service_id=service_id, name=name).first()
    if existing:
        return {'success': False, 'message': 'Token with this name already exists for this service'}
    
    # Create expiration date if provided
    expires_at = None
    if expires_in_days:
        expires_at = datetime.utcnow() + timedelta(days=expires_in_days)
    
    # Create new token
    token = AppToken(
        name=name,
        service_id=service_id,
        expires_at=expires_at
    )
    
    db.session.add(token)
    db.session.commit()
    
    # Return token data including the actual token value
    # This is the only time the raw token value will be returned
    return {
        'success': True, 
        'message': 'Token created successfully',
        'token_data': {
            'id': token.id,
            'token': token.token,  # Return the actual token value
            'name': token.name,
            'service_id': service.public_id,
            'service_name': service.name,
            'expires_at': token.expires_at.isoformat() if token.expires_at else None
        }
    }


def validate_app_token(token_value):
    """Validate an application token and return associated service"""
    token = AppToken.query.filter_by(token=token_value).first()
    
    if not token:
        return None
    
    if not token.is_valid():
        return None
    
    # Update last used timestamp
    token.update_last_used()
    
    return token.service


def get_service_tokens(service_id):
    """Get all tokens for a service"""
    tokens = AppToken.query.filter_by(service_id=service_id).all()
    return [token.to_dict() for token in tokens]


def revoke_token(token_id):
    """Revoke a token by setting it inactive"""
    token = AppToken.query.get(token_id)
    
    if not token:
        return {'success': False, 'message': 'Token not found'}
    
    token.is_active = False
    db.session.commit()
    
    return {'success': True, 'message': 'Token revoked successfully'}


def delete_token(token_id):
    """Delete a token completely"""
    token = AppToken.query.get(token_id)
    
    if not token:
        return {'success': False, 'message': 'Token not found'}
    
    db.session.delete(token)
    db.session.commit()
    
    return {'success': True, 'message': 'Token deleted successfully'} 
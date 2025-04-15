from flask import Blueprint, request, jsonify
from app.services.auth_service import request_password_reset, reset_password

password_bp = Blueprint('password', __name__)

@password_bp.route('/forgot', methods=['POST'])
def forgot_password():
    """Request a password reset link"""
    data = request.get_json()
    
    # Validate required fields
    if not data or not data.get('email'):
        return jsonify({'success': False, 'message': 'Email is required'}), 400
    
    # Process the request
    result = request_password_reset(data.get('email'))
    
    # Always return success to avoid email enumeration
    return jsonify(result), 200


@password_bp.route('/reset', methods=['POST'])
def reset_password_route():
    """Reset password using token"""
    data = request.get_json()
    
    # Validate required fields
    if not data or not data.get('token') or not data.get('password'):
        return jsonify({'success': False, 'message': 'Token and new password are required'}), 400
    
    # Process the request
    result = reset_password(data.get('token'), data.get('password'))
    
    if result['success']:
        return jsonify(result), 200
    else:
        return jsonify(result), 400 
from flask import Blueprint, request, jsonify , current_app
from app.services.auth_service import request_password_reset, reset_password

password_bp = Blueprint('password', __name__)

@password_bp.route('/forgot', methods=['POST'])
def forgot_password():
    """Request a password reset link"""
    data = request.get_json()
    current_app.logger.info(data)
    # Validate required fields
    if not data or not data.get('email'):
        current_app.logger.warning("Email is required.")
        return jsonify({'success': False, 'message': 'Email is required'}), 400

    result = request_password_reset(data.get('email'))

    return jsonify(result), 200


@password_bp.route('/reset', methods=['POST'])
def reset_password_route():
    """Reset password using token"""
    data = request.get_json()

    # Validate required fields
    if not data or not data.get('token') or not data.get('password') or not data.get('email'):
        return jsonify({'success': False, 'message': 'Token and new password are required'}), 400
    
    # Process the request
    result = reset_password(data.get('token'), data.get('password'), data.get('email'))
    
    if result['success']:
        return jsonify(result), 200
    else:
        return jsonify(result), 400 
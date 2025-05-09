from flask import Blueprint, request, jsonify
from flask_jwt_extended import (
    create_access_token,
    create_refresh_token,
    jwt_required,
    get_jwt_identity
)
from models.user import User
from app import db
from datetime import datetime
from validators import UserCreate, UserLogin, UserResponse, TokenResponse
from pydantic import ValidationError

auth_bp = Blueprint('auth', __name__)

@auth_bp.route('/register', methods=['POST'])
def register():
    """Register a new user."""
    try:
        data = UserCreate.model_validate(request.get_json())
    except ValidationError as e:
        return jsonify({'error': e.errors()}), 400

    # Check if user already exists
    if User.query.filter_by(username=data.username).first():
        return jsonify({'error': 'Username already exists'}), 409
    if User.query.filter_by(email=data.email).first():
        return jsonify({'error': 'Email already exists'}), 409

    # Create new user
    user = User(
        username=data.username,
        email=data.email
    )
    user.set_password(data.password)

    db.session.add(user)
    db.session.commit()

    return jsonify({'message': 'User created successfully'}), 201

@auth_bp.route('/login', methods=['POST'])
def login():
    """Authenticate user and return tokens."""
    try:
        data = UserLogin.model_validate(request.get_json())
    except ValidationError as e:
        return jsonify({'error': e.errors()}), 400

    # Find user
    user = User.query.filter_by(email=data.email).first()
    if not user or not user.check_password(data.password):
        return jsonify({'error': 'Invalid credentials'}), 401

    # Update last login
    user.last_login = datetime.utcnow()
    db.session.commit()

    # Create tokens
    access_token = create_access_token(identity=user.id)
    refresh_token = create_refresh_token(identity=user.id)

    response = TokenResponse(
        access_token=access_token,
        refresh_token=refresh_token,
        user=UserResponse.model_validate(user)
    )
    return jsonify(response.model_dump()), 200

@auth_bp.route('/refresh', methods=['POST'])
@jwt_required(refresh=True)
def refresh():
    """Refresh access token."""
    current_user_id = get_jwt_identity()
    access_token = create_access_token(identity=current_user_id)
    return jsonify({'access_token': access_token}), 200

@auth_bp.route('/me', methods=['GET'])
@jwt_required()
def get_user_info():
    """Get current user information."""
    current_user_id = get_jwt_identity()
    user = User.query.get(current_user_id)
    if not user:
        return jsonify({'error': 'User not found'}), 404
    return jsonify(UserResponse.model_validate(user).model_dump()), 200 
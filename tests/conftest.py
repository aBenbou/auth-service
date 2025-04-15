import os
import pytest
import fakeredis
from datetime import datetime, timedelta
from flask_jwt_extended import create_access_token, create_refresh_token
from unittest.mock import patch, MagicMock

from app import create_app, db
from app.models.user import User
from app.models.role import Role, Permission, RolePermission
from app.models.service import Service
from app.models.user_service_role import UserServiceRole
from app.models.app_token import AppToken
from app.services.redis_service import redis_client


@pytest.fixture
def app():
    """Create and configure a Flask app for testing."""
    # Set test configurations
    os.environ["FLASK_ENV"] = "testing"
    os.environ["TESTING"] = "True"
    os.environ["SECRET_KEY"] = "test-key"
    os.environ["JWT_SECRET_KEY"] = "test-jwt-key"
    os.environ["SQLALCHEMY_DATABASE_URI"] = "sqlite:///:memory:"
    
    app = create_app()
    
    # Configure the app for testing
    app.config.update({
        'TESTING': True,
        'SQLALCHEMY_DATABASE_URI': 'sqlite:///:memory:',
        'SQLALCHEMY_TRACK_MODIFICATIONS': False,
        'JWT_SECRET_KEY': 'test-jwt-key',
        'SECRET_KEY': 'test-key',
        'SESSION_LIMIT_PER_USER': 3,
        'APP_BASE_URL': 'http://localhost:5000',
        'PASSWORD_RESET_TOKEN_EXPIRES': 3600,
        'MAIL_DEFAULT_SENDER': 'test@example.com',
        'APP_NAME': 'Test Auth API'
    })
    
    # Create a test context
    ctx = app.app_context()
    ctx.push()
    
    # Set up the test database
    db.create_all()
    
    yield app
    
    # Clean up
    db.session.remove()
    db.drop_all()
    
    # Pop the context
    ctx.pop()


@pytest.fixture
def client(app):
    """A test client for the app."""
    return app.test_client()


@pytest.fixture
def db_session(app):
    """Create a new database session for a test."""
    yield db.session


@pytest.fixture
def mock_redis(monkeypatch):
    """Mock Redis client for testing."""
    fake_redis = fakeredis.FakeRedis(decode_responses=True)
    monkeypatch.setattr('app.services.redis_service.redis_client', fake_redis)
    monkeypatch.setattr('app.services.redis_service.get_redis', lambda: fake_redis)
    return fake_redis


@pytest.fixture
def test_user(db_session):
    """Create a test user."""
    user = User(
        email='test@example.com',
        first_name='Test',
        last_name='User',
        is_active=True,
        is_email_verified=True
    )
    user.password = 'password123'
    db_session.add(user)
    db_session.commit()
    return user


@pytest.fixture
def admin_user(db_session, auth_service):
    """Create an admin user with all permissions."""
    user = User(
        email='admin@example.com',
        first_name='Admin',
        last_name='User',
        is_active=True,
        is_email_verified=True
    )
    user.password = 'admin123'
    db_session.add(user)
    db_session.commit()
    
    # Get admin role
    admin_role = Role.query.filter_by(name='admin', service_id=auth_service.id).first()
    
    # Assign admin role to user
    user_role = UserServiceRole(
        user_id=user.id,
        service_id=auth_service.id,
        role_id=admin_role.id
    )
    db_session.add(user_role)
    db_session.commit()
    
    return user


@pytest.fixture
def auth_service(db_session):
    """Create the auth service for testing."""
    # Check if service already exists
    service = Service.query.filter_by(name='auth_service').first()
    if not service:
        service = Service(
            name='auth_service',
            description='Authentication and Authorization Service',
            is_active=True
        )
        db_session.add(service)
        db_session.commit()
    return service


@pytest.fixture
def test_service(db_session):
    """Create a test microservice."""
    service = Service(
        name='test_service',
        description='Test Microservice',
        is_active=True
    )
    db_session.add(service)
    db_session.commit()
    return service


@pytest.fixture
def test_app_token(db_session, test_service):
    """Create a test application token."""
    token = AppToken(
        name='Test Token',
        service_id=test_service.id,
        is_active=True
    )
    db_session.add(token)
    db_session.commit()
    return token


@pytest.fixture
def test_role(db_session, test_service):
    """Create a test role."""
    role = Role(
        name='test_role',
        description='Test Role',
        service_id=test_service.id
    )
    db_session.add(role)
    db_session.commit()
    return role


@pytest.fixture
def user_token(app, test_user):
    """Generate a JWT token for the test user."""
    with app.app_context():
        access_token = create_access_token(identity=test_user.public_id)
        refresh_token = create_refresh_token(identity=test_user.public_id)
        return {
            'access_token': access_token,
            'refresh_token': refresh_token
        }


@pytest.fixture
def admin_token(app, admin_user):
    """Generate a JWT token for the admin user."""
    with app.app_context():
        access_token = create_access_token(identity=admin_user.public_id)
        refresh_token = create_refresh_token(identity=admin_user.public_id)
        return {
            'access_token': access_token,
            'refresh_token': refresh_token
        }


@pytest.fixture
def mock_mail(app, monkeypatch):
    """Mock the mail service."""
    sent_emails = []
    
    # Create a mock for the send_email function
    def mock_send_email(subject, recipients, text_body, html_body=None):
        sent_emails.append({
            'subject': subject,
            'recipients': recipients,
            'text_body': text_body,
            'html_body': html_body
        })
    
    # Patch the send_email function in the email_service module
    with patch('app.services.email_service.send_email', side_effect=mock_send_email):
        yield sent_emails 
import pytest
from unittest.mock import patch, MagicMock
from app.services.email_service import (
    send_email,
    send_verification_email,
    send_password_reset_email
)
from app.models.user import User
from datetime import datetime, timedelta


def test_send_email(app, mock_mail):
    """Test sending a basic email."""
    with app.app_context():
        send_email(
            subject='Test Subject',
            recipients=['test@example.com'],
            text_body='Test body content'
        )
        
        # In test mode, no actual email is sent, but we log it
        # The mock_mail fixture should capture this


def test_send_email_with_html(app, mock_mail):
    """Test sending an email with HTML content."""
    with app.app_context():
        send_email(
            subject='Test HTML Email',
            recipients=['test@example.com'],
            text_body='Plain text content',
            html_body='<p>HTML content</p>'
        )
        
        # In test mode, no actual email is sent, but we log it
        # The mock_mail fixture should capture this


def test_send_verification_email(app, db_session, mock_mail):
    """Test sending a verification email."""
    # Create a user with verification token
    user = User(
        email='verify@example.com',
        first_name='Verify',
        last_name='User',
        email_verification_token='test-verify-token'
    )
    db_session.add(user)
    db_session.commit()
    
    with app.app_context():
        send_verification_email(user)
        
        # In test mode, no actual email is sent, but we log it
        # The mock_mail fixture should capture this


def test_send_password_reset_email(app, db_session, mock_mail):
    """Test sending a password reset email."""
    # Create a user with reset token
    user = User(
        email='reset@example.com',
        first_name='Reset',
        last_name='User',
        password_reset_token='test-reset-token',
        password_reset_expires=datetime.utcnow() + timedelta(hours=1)
    )
    db_session.add(user)
    db_session.commit()
    
    with app.app_context():
        send_password_reset_email(user)
        
        # In test mode, no actual email is sent, but we log it
        # The mock_mail fixture should capture this

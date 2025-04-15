from flask import current_app, render_template_string
from flask_mail import Message
from threading import Thread
from app import mail

def send_async_email(app, msg):
    """Send email asynchronously"""
    with app.app_context():
        mail.send(msg)


def send_email(subject, recipients, text_body, html_body=None):
    """Send an email"""
    try:
        # Get app context to use in background thread
        app = current_app._get_current_object()
        
        # Check if we're in testing mode
        if app.config.get('TESTING', False):
            # In testing, just log the email instead of sending it
            app.logger.info(f"TEST EMAIL: To: {recipients}, Subject: {subject}")
            return
            
        msg = Message(subject, recipients=recipients)
        msg.body = text_body
        
        if html_body:
            msg.html = html_body
            
        # Send email in background thread to avoid blocking
        Thread(target=send_async_email, args=(app, msg)).start()
    except RuntimeError:
        # Handle case where there's no app context (e.g., in tests)
        print(f"Would send email: To: {recipients}, Subject: {subject}")


def send_verification_email(user):
    """Send email verification link to user"""
    try:
        app = current_app._get_current_object()
        token = user.email_verification_token
        verification_url = f"{app.config['APP_BASE_URL']}/api/auth/verify-email/{token}"
        app_name = app.config['APP_NAME']
    except RuntimeError:
        # Handle case where there's no app context (e.g., in tests)
        token = user.email_verification_token
        verification_url = f"http://localhost:5000/api/auth/verify-email/{token}"
        app_name = "Authentication API"
    
    subject = f"Verify your email for {app_name}"
    
    text_body = f"""
    Hello {user.first_name or user.email},
    
    Please verify your email address by clicking on the link below:
    
    {verification_url}
    
    This link will expire in 24 hours.
    
    If you did not sign up for {app_name}, please ignore this email.
    
    Best regards,
    The {app_name} Team
    """
    
    html_body = f"""
    <p>Hello {user.first_name or user.email},</p>
    
    <p>Please verify your email address by clicking on the link below:</p>
    
    <p><a href="{verification_url}">Verify Email</a></p>
    
    <p>This link will expire in 24 hours.</p>
    
    <p>If you did not sign up for {app_name}, please ignore this email.</p>
    
    <p>Best regards,<br>
    The {app_name} Team</p>
    """
    
    send_email(subject, [user.email], text_body, html_body)


def send_password_reset_email(user):
    """Send password reset link to user"""
    try:
        app = current_app._get_current_object()
        token = user.password_reset_token
        reset_url = f"{app.config['APP_BASE_URL']}/reset-password/{token}"
        app_name = app.config['APP_NAME']
        expires_in_hours = app.config['PASSWORD_RESET_TOKEN_EXPIRES'] // 3600
    except RuntimeError:
        # Handle case where there's no app context (e.g., in tests)
        token = user.password_reset_token
        reset_url = f"http://localhost:5000/reset-password/{token}"
        app_name = "Authentication API"
        expires_in_hours = 1
    
    subject = f"Reset your password for {app_name}"
    
    text_body = f"""
    Hello {user.first_name or user.email},
    
    You recently requested to reset your password for your {app_name} account.
    Click the link below to reset it:
    
    {reset_url}
    
    This link will expire in {expires_in_hours} hours.
    
    If you did not request a password reset, please ignore this email or contact support if you have questions.
    
    Best regards,
    The {app_name} Team
    """
    
    html_body = f"""
    <p>Hello {user.first_name or user.email},</p>
    
    <p>You recently requested to reset your password for your {app_name} account.
    Click the link below to reset it:</p>
    
    <p><a href="{reset_url}">Reset Password</a></p>
    
    <p>This link will expire in {expires_in_hours} hours.</p>
    
    <p>If you did not request a password reset, please ignore this email or contact support if you have questions.</p>
    
    <p>Best regards,<br>
    The {app_name} Team</p>
    """
    
    send_email(subject, [user.email], text_body, html_body) 
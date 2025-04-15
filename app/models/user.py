from datetime import datetime
from app import db, bcrypt
from sqlalchemy.ext.hybrid import hybrid_property
import uuid

class User(db.Model):
    __tablename__ = 'users'
    
    id = db.Column(db.Integer, primary_key=True)
    public_id = db.Column(db.String(36), unique=True, nullable=False, default=lambda: str(uuid.uuid4()))
    email = db.Column(db.String(255), unique=True, nullable=False)
    _password = db.Column('password', db.String(128))
    first_name = db.Column(db.String(50))
    last_name = db.Column(db.String(50))
    is_active = db.Column(db.Boolean, default=True)
    is_email_verified = db.Column(db.Boolean, default=False)
    email_verification_token = db.Column(db.String(255))
    password_reset_token = db.Column(db.String(255))
    password_reset_expires = db.Column(db.DateTime)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    last_login = db.Column(db.DateTime)
    
    # OAuth fields
    google_id = db.Column(db.String(255), unique=True)
    microsoft_id = db.Column(db.String(255), unique=True)
    discord_id = db.Column(db.String(255), unique=True)
    
    # Relationships
    service_roles = db.relationship('UserServiceRole', back_populates='user', cascade='all, delete-orphan')
    
    @hybrid_property
    def password(self):
        raise AttributeError('Password is not a readable attribute')
    
    @password.setter
    def password(self, password):
        self._password = bcrypt.generate_password_hash(password).decode('utf-8')
    
    def verify_password(self, password):
        if not self._password:
            return False
        return bcrypt.check_password_hash(self._password, password)
    
    def get_roles_for_service(self, service_id):
        """Get all roles for a specific service for this user"""
        from app.models.user_service_role import UserServiceRole
        user_service_roles = UserServiceRole.query.filter_by(user_id=self.id, service_id=service_id).all()
        return [usr.role for usr in user_service_roles]
    
    def has_permission(self, permission_name, service_id):
        """Check if user has a specific permission for a service"""
        roles = self.get_roles_for_service(service_id)
        for role in roles:
            if role.has_permission(permission_name):
                return True
        return False
    
    def to_dict(self):
        return {
            'id': self.public_id,
            'email': self.email,
            'first_name': self.first_name,
            'last_name': self.last_name,
            'is_active': self.is_active,
            'is_email_verified': self.is_email_verified,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'last_login': self.last_login.isoformat() if self.last_login else None
        }
    
    def __repr__(self):
        return f'<User {self.email}>' 
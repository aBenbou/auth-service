from app import db
from datetime import datetime
import uuid

class Service(db.Model):
    __tablename__ = 'services'
    
    id = db.Column(db.Integer, primary_key=True)
    public_id = db.Column(db.String(36), unique=True, nullable=False, default=lambda: str(uuid.uuid4()))
    name = db.Column(db.String(100), nullable=False, unique=True)
    description = db.Column(db.String(255))
    is_active = db.Column(db.Boolean, default=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    # Relationships
    app_tokens = db.relationship('AppToken', back_populates='service', cascade='all, delete-orphan')
    roles = db.relationship('Role', back_populates='service', cascade='all, delete-orphan')
    user_service_roles = db.relationship('UserServiceRole', back_populates='service', cascade='all, delete-orphan')
    
    def to_dict(self):
        return {
            'id': self.public_id,
            'name': self.name,
            'description': self.description,
            'is_active': self.is_active,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'updated_at': self.updated_at.isoformat() if self.updated_at else None
        }
    
    def __repr__(self):
        return f'<Service {self.name}>' 
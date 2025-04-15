from app import db
from datetime import datetime
import uuid
import secrets

class AppToken(db.Model):
    __tablename__ = 'app_tokens'
    
    id = db.Column(db.Integer, primary_key=True)
    token = db.Column(db.String(64), unique=True, nullable=False, default=lambda: secrets.token_hex(32))
    name = db.Column(db.String(100), nullable=False)
    service_id = db.Column(db.Integer, db.ForeignKey('services.id'), nullable=False)
    is_active = db.Column(db.Boolean, default=True)
    expires_at = db.Column(db.DateTime)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    last_used = db.Column(db.DateTime)
    
    # Relationships
    service = db.relationship('Service', back_populates='app_tokens')
    
    def is_valid(self):
        """Check if token is active and not expired"""
        if not self.is_active:
            return False
        
        if self.expires_at and self.expires_at <= datetime.utcnow():
            return False
            
        return True
    
    def update_last_used(self):
        """Update last used timestamp"""
        self.last_used = datetime.utcnow()
        db.session.commit()
    
    def to_dict(self):
        return {
            'id': self.id,
            'name': self.name,
            'service_id': self.service.public_id,
            'service_name': self.service.name,
            'is_active': self.is_active,
            'expires_at': self.expires_at.isoformat() if self.expires_at else None,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'last_used': self.last_used.isoformat() if self.last_used else None
        }
    
    def __repr__(self):
        return f'<AppToken {self.name} for {self.service.name if self.service else "unknown"}>' 
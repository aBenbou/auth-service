from app import db
from datetime import datetime

class UserServiceRole(db.Model):
    __tablename__ = 'user_service_roles'
    
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    service_id = db.Column(db.Integer, db.ForeignKey('services.id'), nullable=False)
    role_id = db.Column(db.Integer, db.ForeignKey('roles.id'), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    # Relationships
    user = db.relationship('User', back_populates='service_roles')
    service = db.relationship('Service', back_populates='user_service_roles')
    role = db.relationship('Role', back_populates='user_service_roles')
    
    # Enforce uniqueness: a user can have each role only once per service
    __table_args__ = (db.UniqueConstraint('user_id', 'service_id', 'role_id', name='unique_user_service_role'),)
    
    def to_dict(self):
        return {
            'id': self.id,
            'user_id': self.user_id,
            'service_id': self.service_id,
            'role_id': self.role_id,
            'role_name': self.role.name if self.role else None,
            'created_at': self.created_at.isoformat() if self.created_at else None
        }
    
    def __repr__(self):
        return f'<UserServiceRole user_id={self.user_id} service_id={self.service_id} role_id={self.role_id}>' 
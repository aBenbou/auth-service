from app import db
from datetime import datetime

# Association table for Role and Permission
class RolePermission(db.Model):
    __tablename__ = 'role_permissions'
    
    id = db.Column(db.Integer, primary_key=True)
    role_id = db.Column(db.Integer, db.ForeignKey('roles.id'), nullable=False)
    permission_id = db.Column(db.Integer, db.ForeignKey('permissions.id'), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    # Relationships
    role = db.relationship('Role', back_populates='role_permissions')
    permission = db.relationship('Permission', back_populates='role_permissions')
    
    __table_args__ = (db.UniqueConstraint('role_id', 'permission_id', name='unique_role_permission'),)


class Role(db.Model):
    __tablename__ = 'roles'
    
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(50), nullable=False)
    description = db.Column(db.String(255))
    service_id = db.Column(db.Integer, db.ForeignKey('services.id'), nullable=False)
    is_default = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    # Relationships
    service = db.relationship('Service', back_populates='roles')
    role_permissions = db.relationship('RolePermission', back_populates='role', cascade='all, delete-orphan')
    user_service_roles = db.relationship('UserServiceRole', back_populates='role', cascade='all, delete-orphan')
    
    # Make service_id and name unique together
    __table_args__ = (db.UniqueConstraint('service_id', 'name', name='unique_role_name_per_service'),)
    
    @property
    def permissions(self):
        return [rp.permission for rp in self.role_permissions]
    
    def add_permission(self, permission):
        """Add a permission to this role"""
        if not self.has_permission(permission.name):
            role_perm = RolePermission(role=self, permission=permission)
            db.session.add(role_perm)
    
    def remove_permission(self, permission):
        """Remove a permission from this role"""
        role_perm = RolePermission.query.filter_by(role_id=self.id, permission_id=permission.id).first()
        if role_perm:
            db.session.delete(role_perm)
    
    def has_permission(self, permission_name):
        """Check if role has specific permission by name"""
        return any(p.name == permission_name for p in self.permissions)
    
    def to_dict(self):
        return {
            'id': self.id,
            'name': self.name,
            'description': self.description,
            'service_id': self.service_id,
            'is_default': self.is_default,
            'permissions': [p.to_dict() for p in self.permissions]
        }
    
    def __repr__(self):
        return f'<Role {self.name}>'


class Permission(db.Model):
    __tablename__ = 'permissions'
    
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(50), nullable=False, unique=True)
    description = db.Column(db.String(255))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    # Relationships
    role_permissions = db.relationship('RolePermission', back_populates='permission', cascade='all, delete-orphan')
    
    def to_dict(self):
        return {
            'id': self.id,
            'name': self.name,
            'description': self.description
        }
    
    def __repr__(self):
        return f'<Permission {self.name}>' 
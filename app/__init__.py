import os
from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from flask_jwt_extended import JWTManager
from flask_bcrypt import Bcrypt
from flask_mail import Mail
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

# Initialize extensions
db = SQLAlchemy()
migrate = Migrate()
jwt = JWTManager()
bcrypt = Bcrypt()
mail = Mail()

def create_app():
    app = Flask(__name__)
    
    # Load configuration
    app.config.from_object('app.config.Config')
    
    # Initialize extensions with app
    db.init_app(app)
    migrate.init_app(app, db)
    jwt.init_app(app)
    bcrypt.init_app(app)
    mail.init_app(app)
    
    # Import and register blueprints
    from app.api.auth import auth_bp
    from app.api.oauth import oauth_bp
    from app.api.password import password_bp
    from app.api.tokens import tokens_bp
    from app.api.roles import roles_bp
    
    app.register_blueprint(auth_bp, url_prefix='/api/auth')
    app.register_blueprint(oauth_bp, url_prefix='/api/oauth')
    app.register_blueprint(password_bp, url_prefix='/api/password')
    app.register_blueprint(tokens_bp, url_prefix='/api/tokens')
    app.register_blueprint(roles_bp, url_prefix='/api/roles')
    
    # Initialize Redis session tracking
    from app.services.redis_service import init_redis
    init_redis(app)
    
    # Create database tables if they don't exist
    with app.app_context():
        # Check if we're in testing mode with SQLite
        if app.config['SQLALCHEMY_DATABASE_URI'].startswith('sqlite'):
            # SQLite doesn't enforce foreign keys by default
            from sqlalchemy import event
            from sqlalchemy.engine import Engine
            
            @event.listens_for(Engine, "connect")
            def set_sqlite_pragma(dbapi_connection, connection_record):
                cursor = dbapi_connection.cursor()
                cursor.execute("PRAGMA foreign_keys=ON")
                cursor.close()
        
        db.create_all()
        
        # Initialize default roles and permissions if needed
        # Only do this in production, not in testing
        if not app.config.get('TESTING', False):
            from app.services.role_service import initialize_default_roles
            initialize_default_roles()
    
    return app 
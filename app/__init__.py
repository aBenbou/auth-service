import os
from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from flask_jwt_extended import JWTManager
from flask_bcrypt import Bcrypt
from flask_mail import Mail
from flask_cors import CORS
from dotenv import load_dotenv
from app.log_config import configure_logging
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
    configure_logging(app)
    # Initialize extensions with app
    db.init_app(app)
    migrate.init_app(app, db)
    jwt.init_app(app)
    bcrypt.init_app(app)
    mail.init_app(app)
    
    # Initialize CORS
    CORS(app, resources={r"/api/*": {"origins": app.config.get('CORS_ORIGINS', '*')}})
    
    # Import and register blueprints
    from app.api.auth import auth_bp
    from app.api.oauth import oauth_bp, init_oauth  # Make sure to import init_oauth
    from app.api.password import password_bp
    from app.api.tokens import tokens_bp
    from app.api.roles import roles_bp
    from app.api.health import health_bp
    
    app.register_blueprint(auth_bp, url_prefix='/api/auth')
    app.register_blueprint(oauth_bp, url_prefix='/api/oauth')
    app.register_blueprint(password_bp, url_prefix='/api/password')
    app.register_blueprint(tokens_bp, url_prefix='/api/tokens')
    app.register_blueprint(roles_bp, url_prefix='/api/roles')
    app.register_blueprint(health_bp, url_prefix='/api/health')
    
    # Initialize OAuth
    init_oauth(app)
    
    # Initialize Redis session tracking
    from app.services.redis_service import init_redis
    init_redis(app)
    
    # Create database tables if they don't exist
    with app.app_context():
        import time
        from sqlalchemy import text
        
        # Database initialization with retry logic
        max_retries = 10  # Increase retries
        retry_count = 0
        
        while retry_count < max_retries:
            try:
                # Check database type for specific configurations
                db_uri = app.config['SQLALCHEMY_DATABASE_URI']
                
                # For SQLite, enable foreign key support
                if db_uri.startswith('sqlite'):
                    from sqlalchemy import event
                    from sqlalchemy.engine import Engine
                    
                    @event.listens_for(Engine, "connect")
                    def set_sqlite_pragma(dbapi_connection, connection_record):
                        cursor = dbapi_connection.cursor()
                        cursor.execute("PRAGMA foreign_keys=ON")
                        cursor.close()
                
                # For PostgreSQL, create needed extensions
                elif db_uri.startswith('postgresql') or db_uri.startswith('postgres'):
                    # Check if we're in a context where we can create tables
                    with db.engine.connect() as conn:
                        conn.execute(text("SELECT 1"))  # Test connection
                        
                        # Create extensions if needed (these require superuser privileges in PostgreSQL)
                        try:
                            conn.execute(text("CREATE EXTENSION IF NOT EXISTS pg_trgm"))
                            conn.execute(text("CREATE EXTENSION IF NOT EXISTS unaccent"))
                            conn.commit()
                        except Exception as ext_error:
                            app.logger.warning(f"Could not create PostgreSQL extensions: {str(ext_error)}")
                
                # Create all tables
                db.create_all()
                
                # Initialize default roles and permissions if needed
                if not app.config.get('TESTING', False):
                    from app.services.role_service import initialize_default_roles
                    initialize_default_roles()
                    
                app.logger.info("Database initialization completed successfully")
                break  # Success, exit the retry loop
                
            except Exception as e:
                retry_count += 1
                if retry_count >= max_retries:
                    app.logger.error(f"Error during database initialization after {max_retries} attempts: {str(e)}")
                    break
                else:
                    wait_time = 2 ** retry_count
                    app.logger.info(f"Database connection attempt {retry_count} failed. Retrying in {wait_time} seconds...")
                    time.sleep(wait_time)
    
    return app
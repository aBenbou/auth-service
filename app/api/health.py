from flask import Blueprint, jsonify, current_app
import psycopg2
import redis
import time

health_bp = Blueprint('health', __name__)

@health_bp.route('/', methods=['GET'])
def health_check():
    """Check the health of the service and its dependencies"""
    result = {
        'success': True,
        'service': 'auth_api',
        'version': '1.0.0',
        'status': 'ok',
        'dependencies': {}
    }
    
    # Check database connection
    db_status = check_database()
    result['dependencies']['database'] = db_status
    
    # Check Redis connection
    redis_status = check_redis()
    result['dependencies']['redis'] = redis_status
    
    # Overall status
    if not all(dep['status'] == 'ok' for dep in result['dependencies'].values()):
        result['status'] = 'degraded'
        
    return jsonify(result)

def check_database():
    """Check the database connection"""
    start_time = time.time()
    status = {
        'status': 'ok',
        'message': 'Connected successfully',
        'latency_ms': 0
    }
    
    try:
        # Get database URI
        db_uri = current_app.config['SQLALCHEMY_DATABASE_URI']
        
        # Check if we're using PostgreSQL
        if db_uri.startswith('postgresql://') or db_uri.startswith('postgres://'):
            # Parse connection string
            import re
            match = re.match(r'postgres(?:ql)?://([^:]+):([^@]+)@([^:]+):(\d+)/([^?]+)', db_uri)
            if match:
                user, password, host, port, dbname = match.groups()
                conn = psycopg2.connect(
                    host=host,
                    port=port,
                    dbname=dbname,
                    user=user,
                    password=password,
                    connect_timeout=3
                )
                cursor = conn.cursor()
                cursor.execute("SELECT 1")  # Simple query to test connection
                cursor.close()
                conn.close()
        else:
            # We're using SQLite or another database
            # Use SQLAlchemy to test connection
            from app import db
            db.session.execute("SELECT 1").scalar()
            
    except Exception as e:
        status['status'] = 'error'
        status['message'] = str(e)
    
    # Calculate latency
    status['latency_ms'] = round((time.time() - start_time) * 1000, 2)
    
    return status

def check_redis():
    """Check the Redis connection"""
    start_time = time.time()
    status = {
        'status': 'ok',
        'message': 'Connected successfully',
        'latency_ms': 0
    }
    
    try:
        # Get Redis configuration
        redis_host = current_app.config['REDIS_HOST']
        redis_port = current_app.config['REDIS_PORT']
        redis_db = current_app.config['REDIS_DB']
        redis_password = current_app.config['REDIS_PASSWORD']
        
        # Connect to Redis
        r = redis.Redis(
            host=redis_host,
            port=redis_port,
            db=redis_db,
            password=redis_password,
            socket_timeout=3
        )
        
        # Test connection with PING
        r.ping()
        
    except Exception as e:
        status['status'] = 'error'
        status['message'] = str(e)
    
    # Calculate latency
    status['latency_ms'] = round((time.time() - start_time) * 1000, 2)
    
    return status
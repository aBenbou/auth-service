import pytest
from unittest.mock import patch, MagicMock
from flask import Flask, jsonify, g
from app.utils.decorators import rate_limit
from app.utils.exceptions import RateLimitError

@pytest.fixture
def app():
    """Create a test Flask app."""
    app = Flask(__name__)
    app.config['TESTING'] = True
    return app

@pytest.fixture
def client(app):
    """Create a test client."""
    return app.test_client()

@pytest.fixture
def mock_session_service():
    """Create a mock session service."""
    with patch('app.utils.decorators.session_service') as mock:
        yield mock

def test_rate_limit_allows_request(app, mock_session_service):
    """Test that rate limit allows request when under limit."""
    mock_session_service.check_rate_limit.return_value = True
    
    @app.route('/test')
    @rate_limit
    def test_route():
        return jsonify({'message': 'success'})
    
    with app.test_request_context('/test'):
        g.user_id = 'test_user'
        response = test_route()
        assert response[1] == 200
        assert response[0].json['message'] == 'success'

def test_rate_limit_blocks_request(app, mock_session_service):
    """Test that rate limit blocks request when limit exceeded."""
    mock_session_service.check_rate_limit.return_value = False
    
    @app.route('/test')
    @rate_limit
    def test_route():
        return jsonify({'message': 'success'})
    
    with app.test_request_context('/test'):
        g.user_id = 'test_user'
        response = test_route()
        assert response[1] == 429
        assert 'error' in response[0].json

def test_rate_limit_no_user_id(app, mock_session_service):
    """Test rate limit behavior when no user_id is present."""
    @app.route('/test')
    @rate_limit
    def test_route():
        return jsonify({'message': 'success'})
    
    with app.test_request_context('/test'):
        response = test_route()
        assert response[1] == 200
        assert response[0].json['message'] == 'success'
        mock_session_service.check_rate_limit.assert_not_called()

def test_rate_limit_redis_error(app, mock_session_service):
    """Test rate limit behavior when Redis check fails."""
    mock_session_service.check_rate_limit.side_effect = Exception("Redis error")
    
    @app.route('/test')
    @rate_limit
    def test_route():
        return jsonify({'message': 'success'})
    
    with app.test_request_context('/test'):
        g.user_id = 'test_user'
        response = test_route()
        assert response[1] == 200
        assert response[0].json['message'] == 'success' 
import pytest
import requests
import time
from datetime import datetime, timedelta

BASE_URL = "http://localhost:5000/api/auth"

def test_token_refresh_flow():
    """Test the complete token refresh flow"""
    # 1. Login to get initial tokens
    login_response = requests.post(f"{BASE_URL}/login", json={
        "email": "test@example.com",
        "password": "testpassword"
    })
    assert login_response.status_code == 200
    tokens = login_response.json()
    
    # 2. Use refresh token to get new access token
    refresh_response = requests.post(f"{BASE_URL}/refresh", json={
        "refresh_token": tokens["refresh_token"]
    })
    assert refresh_response.status_code == 200
    new_tokens = refresh_response.json()
    assert "access_token" in new_tokens
    
    # 3. Verify new access token works
    headers = {"Authorization": f"Bearer {new_tokens['access_token']}"}
    profile_response = requests.get(f"{BASE_URL}/me", headers=headers)
    assert profile_response.status_code == 200

def test_rate_limiting():
    """Test rate limiting functionality"""
    # 1. Login to get token
    login_response = requests.post(f"{BASE_URL}/login", json={
        "email": "test@example.com",
        "password": "testpassword"
    })
    assert login_response.status_code == 200
    tokens = login_response.json()
    
    # 2. Make multiple requests to trigger rate limit
    headers = {"Authorization": f"Bearer {tokens['access_token']}"}
    for _ in range(65):  # Assuming rate limit is 60 requests per minute
        response = requests.get(f"{BASE_URL}/me", headers=headers)
        if response.status_code == 429:
            break
    
    # 3. Verify rate limit was triggered
    assert response.status_code == 429
    assert "Rate limit exceeded" in response.json()["error"]

def test_session_management():
    """Test session management features"""
    # 1. Login to create session
    login_response = requests.post(f"{BASE_URL}/login", json={
        "email": "test@example.com",
        "password": "testpassword"
    })
    assert login_response.status_code == 200
    tokens = login_response.json()
    
    # 2. Get active sessions
    headers = {"Authorization": f"Bearer {tokens['access_token']}"}
    sessions_response = requests.get(f"{BASE_URL}/sessions", headers=headers)
    assert sessions_response.status_code == 200
    sessions = sessions_response.json()
    assert len(sessions["sessions"]) > 0
    
    # 3. Logout to invalidate session
    logout_response = requests.post(f"{BASE_URL}/logout", headers=headers)
    assert logout_response.status_code == 200
    
    # 4. Verify session is invalidated
    profile_response = requests.get(f"{BASE_URL}/me", headers=headers)
    assert profile_response.status_code == 401

def test_oauth_integration():
    """Test OAuth integration"""
    # Test Google OAuth
    google_response = requests.get(f"{BASE_URL}/oauth/google/authorize")
    assert google_response.status_code == 302
    assert "accounts.google.com" in google_response.headers["Location"]
    
    # Test Microsoft OAuth
    microsoft_response = requests.get(f"{BASE_URL}/oauth/microsoft/authorize")
    assert microsoft_response.status_code == 302
    assert "login.microsoftonline.com" in microsoft_response.headers["Location"]
    
    # Test Discord OAuth
    discord_response = requests.get(f"{BASE_URL}/oauth/discord/authorize")
    assert discord_response.status_code == 302
    assert "discord.com" in discord_response.headers["Location"] 
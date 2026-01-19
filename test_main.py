from fastapi.testclient import TestClient
from main import app
import pytest

client = TestClient(app)

def test_read_root():
    """Test de la route racine"""
    response = client.get("/")
    assert response.status_code == 200
    assert response.json() == {"message": "Bienvenue sur l'API FINVO!"}

def test_create_user():
    """Test de création d'utilisateur"""
    user_data = {
        "email": "test@example.com",
        "password": "testpassword123",
        "first_name": "Test",
        "last_name": "User"
    }
    response = client.post("/users/", json=user_data)
    assert response.status_code == 200
    assert "user" in response.json()
    assert response.json()["user"]["email"] == "test@example.com"

def test_login_invalid_credentials():
    """Test de connexion avec identifiants invalides"""
    login_data = {
        "email": "invalid@example.com",
        "password": "wrongpassword"
    }
    response = client.post("/login/", json=login_data)
    assert response.status_code == 401

def test_get_current_user_without_auth():
    """Test d'accès aux infos utilisateur sans authentification"""
    response = client.get("/users/me/")
    assert response.status_code == 403  # Forbidden sans token
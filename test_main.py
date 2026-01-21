from fastapi.testclient import TestClient
from sqlmodel import SQLModel, Session, create_engine
from sqlmodel.pool import StaticPool
import pytest
from main import app, get_current_user
from main import User, Account, Transaction, Beneficiary

# Configuration de la base de données de test
@pytest.fixture(name="session", scope="function")
def session_fixture():
    """Crée une base de données en mémoire pour chaque test"""
    engine = create_engine(
        "sqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    SQLModel.metadata.create_all(engine)
    with Session(engine) as session:
        yield session
    SQLModel.metadata.drop_all(engine)

@pytest.fixture(name="client", scope="function")
def client_fixture(session: Session):
    """Crée un client de test avec une session de base de données"""
    def get_session_override():
        return session
    
    # Remplacer la dépendance de session dans l'app
    from main import engine as main_engine
    import main
    
    # Sauvegarder l'engine original
    original_engine = main.engine
    
    # Utiliser l'engine de test
    test_engine = create_engine(
        "sqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    main.engine = test_engine
    SQLModel.metadata.create_all(test_engine)
    
    client = TestClient(app)
    yield client
    
    # Restaurer l'engine original
    main.engine = original_engine
    SQLModel.metadata.drop_all(test_engine)

def test_read_root(client: TestClient):
    """Test de la route racine"""
    response = client.get("/")
    assert response.status_code == 200
    assert response.json() == {"message": "Bienvenue sur l'API FINVO!"}

def test_create_user(client: TestClient):
    """Test de création d'utilisateur"""
    user_data = {
        "email": "test@example.com",
        "password": "testpassword123",
        "first_name": "Test",
        "last_name": "User"
    }
    response = client.post("/users/", json=user_data)
    assert response.status_code == 200
    data = response.json()
    assert "user" in data
    assert data["user"]["email"] == "test@example.com"
    assert "main_account" in data
    assert data["main_account"]["balance"] == 100.0

def test_login_invalid_credentials(client: TestClient):
    """Test de connexion avec identifiants invalides"""
    login_data = {
        "email": "invalid@example.com",
        "password": "wrongpassword"
    }
    response = client.post("/login/", json=login_data)
    assert response.status_code == 401

def test_get_current_user_without_auth(client: TestClient):
    """Test d'accès aux infos utilisateur sans authentification"""
    response = client.get("/users/me/")
    assert response.status_code == 403  # Forbidden sans token

def test_create_user_and_login(client: TestClient):
    """Test complet : création + connexion"""
    # Créer un utilisateur
    user_data = {
        "email": "newuser@example.com",
        "password": "securepassword",
        "first_name": "New",
        "last_name": "User"
    }
    response = client.post("/users/", json=user_data)
    assert response.status_code == 200
    
    # Se connecter
    login_data = {
        "email": "newuser@example.com",
        "password": "securepassword"
    }
    response = client.post("/login/", json=login_data)
    assert response.status_code == 200
    data = response.json()
    assert "access_token" in data
    assert data["user"]["email"] == "newuser@example.com"

def test_deposit_money(client: TestClient):
    """Test de dépôt d'argent"""
    # Créer un utilisateur
    user_data = {
        "email": "depositor@example.com",
        "password": "password123",
        "first_name": "Depositor",
        "last_name": "Test"
    }
    create_response = client.post("/users/", json=user_data)
    assert create_response.status_code == 200
    account_id = create_response.json()["main_account"]["id"]
    
    # Se connecter pour obtenir le token
    login_response = client.post("/login/", json={
        "email": "depositor@example.com",
        "password": "password123"
    })
    token = login_response.json()["access_token"]
    
    # Faire un dépôt
    deposit_response = client.post(
        f"/accounts/{account_id}/deposit/?amount=500",
        headers={"Authorization": f"Bearer {token}"}
    )
    assert deposit_response.status_code == 200
    assert deposit_response.json()["account"]["balance"] == 600.0  # 100 + 500
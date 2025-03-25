import sys
import os

# Add the parent directory of the app module to the system path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '../..')))

from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
import sys
import os
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '../..')))
from fastapi.testclient import TestClient

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from app.database import Base, get_db
from app.main import app


# Set up the test database
SQLALCHEMY_DATABASE_URL = "postgresql+psycopg2://postgres:yash1009@localhost:5432/test_db"
engine = create_engine(SQLALCHEMY_DATABASE_URL, connect_args={"check_same_thread": False})
TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

# Create the database tables
Base.metadata.create_all(bind=engine)

engine = create_engine(SQLALCHEMY_DATABASE_URL, connect_args={"check_same_thread": False})
TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

# Create the database tables
Base.metadata.create_all(bind=engine)

# Dependency override
def override_get_db():
    db = TestingSessionLocal()
    try:
        yield db
    finally:
        db.close()

# Dependency override
def override_get_db():
    db = TestingSessionLocal()
    try:
        yield db
    finally:
        db.close()

app.dependency_overrides[get_db] = override_get_db


client = TestClient(app)

def test_login_employee():
    response = client.post("/login", data={"username": "employee@example.com", "password": "testpassword"})
    assert response.status_code == 200
    assert "access_token" in response.json()
    assert response.json()["role"] == "employee"

def test_login_client():
    response = client.post("/login", data={"username": "client@example.com", "password": "testpassword"})
    assert response.status_code == 200
    assert "access_token" in response.json()
    assert response.json()["role"] == "client"

def test_get_user_data_employee():
    login_response = client.post("/login", data={"username": "employee@example.com", "password": "testpassword"})
    access_token = login_response.json()["access_token"]
    response = client.get("/data", headers={"Authorization": f"Bearer {access_token}"})
    assert response.status_code == 200
    assert "user_data" in response.json()

def test_get_user_data_client():
    login_response = client.post("/login", data={"username": "client@example.com", "password": "testpassword"})
    access_token = login_response.json()["access_token"]
    response = client.get("/data", headers={"Authorization": f"Bearer {access_token}"})
    assert response.status_code == 200
    assert "user_data" in response.json()

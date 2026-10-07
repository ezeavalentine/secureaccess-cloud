import secrets
from datetime import datetime
import pytest
from cryptography.fernet import Fernet
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from fastapi.testclient import TestClient
from app.config import settings
from app.models import Base, AuditHead, get_db
from app.main import app
import app.main as main

@pytest.fixture
def client(tmp_path, monkeypatch):
    url = f"sqlite:///{tmp_path / 'test.db'}"
    engine = create_engine(url, connect_args={"check_same_thread": False, "timeout": 30})
    from sqlalchemy import event
    @event.listens_for(engine, "connect")
    def fk(conn, record): conn.execute("PRAGMA foreign_keys=ON")
    local = sessionmaker(bind=engine, autoflush=False, expire_on_commit=False)
    monkeypatch.setattr(settings, "DATABASE_URL", url)
    monkeypatch.setattr(settings, "SECRET_KEY", secrets.token_urlsafe(48))
    monkeypatch.setattr(settings, "AUDIT_HMAC_KEY", secrets.token_urlsafe(48))
    monkeypatch.setattr(settings, "ENCRYPTION_KEY", Fernet.generate_key().decode())
    monkeypatch.setattr(settings, "DEMO_MODE", True)
    monkeypatch.setattr(settings, "APP_ENV", "development")
    monkeypatch.setattr(settings, "AUDIT_DYNAMODB_TABLE", "")
    monkeypatch.setattr(main, "SessionLocal", local)
    monkeypatch.setattr(main, "engine", engine)
    def override_db():
        with local() as db: yield db
    app.dependency_overrides[get_db] = override_db
    with TestClient(app, headers={"X-SecureAccess-CSRF": "1"}) as c:
        c.db = local
        yield c
    app.dependency_overrides.clear()
    engine.dispose()

@pytest.fixture
def login(client):
    def perform(username="alex.dev", password="Password123!", otp=None):
        response = client.post("/api/auth/login", json={"username": username, "password": password, "otp": otp})
        assert response.status_code == 200, response.text
        return response
    return perform

@pytest.fixture
def payload():
    return {"aws_account_id": "123456789012", "aws_account_name": "Dev-Sandbox", "iam_role": "JIT-Access-ReadOnly", "duration_minutes": 60, "justification": "Inspect application deployment", "ticket_ref": None}


@pytest.fixture
def postgres_db():
    """Each concurrency test owns a disposable schema, never application data."""
    import os
    import uuid
    from sqlalchemy import text
    from sqlalchemy.engine import make_url
    from test_migrations import config
    from alembic import command
    base_url = os.environ.get('TEST_POSTGRES_URL')
    if not base_url:
        pytest.skip('TEST_POSTGRES_URL is required for PostgreSQL concurrency tests')
    base = create_engine(base_url)
    schema = 'test_' + uuid.uuid4().hex
    with base.begin() as db:
        db.execute(text('CREATE SCHEMA ' + schema))
    url = make_url(base_url).update_query_dict({'options': '-csearch_path=' + schema}).render_as_string(hide_password=False)
    engine = create_engine(url)
    local = sessionmaker(bind=engine, autoflush=False, expire_on_commit=False)
    try:
        command.upgrade(config(url), 'head')
        yield local
    finally:
        engine.dispose()
        with base.begin() as db:
            db.execute(text('DROP SCHEMA ' + schema + ' CASCADE'))
        base.dispose()

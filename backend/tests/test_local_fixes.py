from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta
import threading

import pytest
from fastapi import HTTPException
from starlette.requests import Request
from sqlalchemy import select

from app.models import AccessRequest, User, WorkerState
from app.models.database import transaction
from app.routes.request_routes import cancel
from app.services import session_service
from app.services.rate_limit_service import allow
from app.worker import run_once


@pytest.fixture
def no_embedded_worker(monkeypatch):
    from app.config import settings
    monkeypatch.setattr(settings, 'WORKER_MODE', 'external')


def test_mfa_enrollment_requires_current_password(client, login):
    login('sarah.sec')
    assert client.post('/api/auth/mfa/setup').status_code == 422
    assert client.post('/api/auth/mfa/setup', json={'current_password': 'wrong'}).status_code == 400
    with client.db() as db:
        assert db.query(User).filter_by(username='sarah.sec').one().mfa_secret is None
    assert client.post('/api/auth/mfa/setup', json={'current_password': 'Password123!'}).status_code == 200


def test_recovered_privileged_user_must_change_password_before_reading(client, login):
    login('admin.sys')
    target = next(u for u in client.get('/api/users').json() if u['username'] == 'sarah.sec')
    result = client.post('/api/users/' + target['id'] + '/recover', json={
        'reason': 'Verified identity in person', 'temporary_password': 'Temporary-password-123!',
    })
    assert result.status_code == 200
    login('sarah.sec', 'Temporary-password-123!')
    for path in ['/api/requests', '/api/sessions/active', '/api/sessions/history',
                 '/api/system/status', '/api/notifications', '/api/users/roles/catalog']:
        assert client.get(path).status_code == 403
    assert client.get('/api/auth/me').status_code == 200
    assert client.post('/api/auth/password', json={
        'current_password': 'Temporary-password-123!', 'new_password': 'Changed-password-123!',
    }).status_code == 200
    login('sarah.sec', 'Changed-password-123!')
    assert client.get('/api/requests').status_code == 200


def test_account_login_limit_applies_across_client_addresses(client):
    # Fill the account bucket without touching the independent IP bucket.
    with client.db() as db:
        for _ in range(10):
            assert allow(db, 'alex.dev', 'login-account', 10)
    result = client.post('/api/auth/login', json={'username': 'alex.dev', 'password': 'Password123!'})
    assert result.status_code == 429
    assert result.headers['Retry-After'] == '60'
    assert client.post('/api/auth/login', json={'username': 'sarah.sec', 'password': 'Password123!'}).status_code == 200


def test_readiness_accepts_running_worker_but_rejects_stale_heartbeat(client):
    with client.db() as db, transaction(db):
        state = db.get(WorkerState, 1)
        state.status, state.heartbeat = 'RUNNING', datetime.utcnow()
    assert client.get('/api/ready').status_code == 200
    with client.db() as db, transaction(db):
        db.get(WorkerState, 1).heartbeat = datetime.utcnow() - timedelta(minutes=10)
    assert client.get('/api/ready').status_code == 503


def test_worker_lease_excludes_second_owner(no_embedded_worker, client, monkeypatch):
    with client.db() as db, transaction(db):
        db.get(WorkerState, 1).lease_until = None
    entered, release = threading.Event(), threading.Event()

    def cycle(db):
        entered.set()
        assert release.wait(5)

    from app.services import audit_service
    monkeypatch.setattr(audit_service, 'archive_pending', cycle)
    with ThreadPoolExecutor(max_workers=2) as pool:
        first = pool.submit(run_once, client.db, 'first')
        try:
            assert entered.wait(5)
            second = pool.submit(run_once, client.db, 'second')
            second.result(timeout=5)
        finally:
            release.set()
        first.result(timeout=5)
    with client.db() as db:
        assert db.get(WorkerState, 1).owner == 'first'


def test_postgres_cancel_waits_for_request_lock(postgres_db):
    local = postgres_db
    with local() as db, transaction(db):
        user = User(username='cancel.dev', email='cancel@example.com', full_name='Cancel Developer',
                    hashed_password='unused', role='REQUESTER', department='Engineering')
        db.add(user)
        db.flush()
        user_id = user.id
        req = AccessRequest(user_id=user.id, username=user.username, aws_account_id='123456789012',
                            aws_account_name='Dev-Sandbox', iam_role='JIT-Access-PowerUser',
                            duration_minutes=60, justification='Test cancellation serialization',
                            expires_at=datetime.utcnow() + timedelta(minutes=60))
        db.add(req)
        db.flush()
        request_id = req.id
    started = threading.Event()

    def cancel_request():
        with local() as db:
            user = db.get(User, user_id)
            request = Request({'type': 'http', 'method': 'POST', 'path': '/api/requests/' + request_id + '/cancel',
                               'headers': [], 'client': ('127.0.0.1', 1234),
                               'state': {'user': user, 'token_version': user.token_version}})
            started.set()
            try:
                cancel(request_id, request, user, db)
                return 200
            except HTTPException as exc:
                return exc.status_code

    with ThreadPoolExecutor(max_workers=1) as pool:
        with local() as db, transaction(db):
            req = db.execute(select(AccessRequest).where(AccessRequest.id == request_id).with_for_update()).scalar_one()
            pending_cancel = pool.submit(cancel_request)
            assert started.wait(5)
            with pytest.raises(TimeoutError):
                pending_cancel.result(timeout=0.2)
            req.status = 'APPROVED'
        assert pending_cancel.result(timeout=5) == 409
    with local() as db:
        assert db.get(AccessRequest, request_id).status == 'APPROVED'


def test_postgres_concurrent_worker_lease_acquisition(postgres_db, monkeypatch):
    local = postgres_db
    barrier = threading.Barrier(2)
    from app.services import audit_service
    import app.worker as worker
    cycles = []
    monkeypatch.setattr(session_service, 'check_and_expire_sessions', lambda db: cycles.append(True))
    monkeypatch.setattr(audit_service, 'archive_pending', lambda db: None)
    monkeypatch.setattr(worker, 'deliver_pending', lambda db: None)

    def attempt(owner):
        barrier.wait(timeout=5)
        run_once(local, owner)

    with ThreadPoolExecutor(max_workers=2) as pool:
        futures = [pool.submit(attempt, owner) for owner in ['first', 'second']]
        for future in futures:
            future.result(timeout=10)
    with local() as db:
        assert db.get(WorkerState, 1).owner in ['first', 'second']
    assert len(cycles) == 1

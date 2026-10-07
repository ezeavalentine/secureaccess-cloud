import uuid
import pytest
import pyotp
from sqlalchemy import text
from sqlalchemy.exc import IntegrityError
from app.models import User,AuditLog,ActiveSession
from app.models.database import transaction
from app.services import audit_service
from app.config import settings

def test_login_fails_without_mock_fallback(client):
    response=client.post('/api/auth/login',json={'username':'admin.sys','password':'wrong'})
    assert response.status_code==401 and 'secureaccess_session' not in response.cookies
    assert client.get('/api/auth/me').status_code==401

def test_cookie_logout_invalidates_copied_token(client,login):
    response=login(); token=response.cookies['secureaccess_session']
    assert 'HttpOnly' in response.headers['set-cookie'] and 'SameSite=strict' in response.headers['set-cookie']
    assert client.post('/api/auth/logout').status_code==200
    assert client.get('/api/auth/me',headers={'Authorization':f'Bearer {token}'}).status_code==401

def test_csrf(client,login):
    assert client.post('/api/auth/login',json={'username':'alex.dev','password':'Password123!'},headers={'X-SecureAccess-CSRF':''}).status_code==403
    assert client.post('/api/auth/login',json={'username':'alex.dev','password':'Password123!'},headers={'Origin':'https://evil.example'}).status_code==403

def test_role_boundaries_and_audit_valid(client,login):
    login()
    for path in ['/api/users','/api/approvals/pending','/api/audit/logs','/api/audit/cloudtrail','/api/audit/verify-chain']:
        assert client.get(path).status_code==403
    login('audit.user')
    assert client.get('/api/audit/verify-chain').json()['status']=='VALID'

def test_request_id_ownership(client,login,payload):
    login('sarah.sec')
    req=client.post('/api/requests',json=payload,headers={'Idempotency-Key':str(uuid.uuid4())}).json()
    login()
    assert client.get('/api/requests/'+req['id']).status_code==404

def test_required_ticket_and_validation(client,login,payload):
    login()
    payload.update(aws_account_id='555444333222',aws_account_name='Prod-US-East-1')
    assert client.post('/api/requests',json=payload,headers={'Idempotency-Key':str(uuid.uuid4())}).status_code==400
    payload['aws_account_id']='broken'
    assert client.post('/api/requests',json=payload,headers={'Idempotency-Key':str(uuid.uuid4())}).status_code==422

def test_user_provision_update_duplicate_email(client,login):
    login('admin.sys')
    data={'username':'new.dev','email':'new@example.com','full_name':'New Developer','password':'A-strong-password-123','role':'REQUESTER'}
    response=client.post('/api/users',json=data);assert response.status_code==200,response.text
    data['username']='another.dev'
    assert client.post('/api/users',json=data).status_code==409
    response=client.patch('/api/users/'+response.json()['id'],json={'is_active':False})
    assert response.status_code==200 and not response.json()['is_active']
    assert client.post('/api/auth/login',json={'username':'new.dev','password':data['password']}).status_code==401
    data['role']='SUPERUSER';data['email']='other@example.com'
    assert client.post('/api/users',json=data).status_code==422

def test_audit_signature_and_append_only(client,login):
    login('audit.user')
    assert client.get('/api/audit/verify-chain').json()['status']=='VALID'
    with client.db() as db:
        with pytest.raises(IntegrityError): db.execute(text("UPDATE audit_logs SET actor='attacker'"))
        db.rollback()
        with pytest.raises(IntegrityError): db.execute(text("DELETE FROM audit_logs"))
        db.rollback()
        # Simulate an attacker with permission to remove DB enforcement.
        db.execute(text('DROP TRIGGER audit_no_update'))
        db.execute(text("UPDATE audit_logs SET ip_address='tampered' WHERE sequence=1"));db.commit()
        assert not audit_service.verify_chain_integrity(db)

def test_mfa_enrollment_and_replay(client,login):
    login('sarah.sec')
    setup=client.post('/api/auth/mfa/setup',json={'current_password':'Password123!'}).json()
    otp=pyotp.TOTP(setup['secret']).now()
    assert client.post('/api/auth/mfa/enable',json={'otp':otp}).status_code==200
    assert client.post('/api/auth/mfa/verify',json={'otp':otp}).status_code==400
    assert client.get('/api/auth/me').json()['mfa_enabled']
    assert client.post('/api/auth/login',json={'username':'sarah.sec','password':'Password123!'}).status_code==401

def test_rate_limit(client):
    for _ in range(10): client.post('/api/auth/login',json={'username':'missing','password':'bad'})
    assert client.post('/api/auth/login',json={'username':'missing','password':'bad'}).status_code==429

def test_cloudtrail_demo_is_explicit(client,login):
    login('audit.user');response=client.get('/api/audit/cloudtrail').json()
    assert response['mode']=='demo' and response['events']==[]

def test_utc_serialization(client,login,payload):
    login();response=client.post('/api/requests',json=payload,headers={'Idempotency-Key':str(uuid.uuid4())})
    assert response.json()['created_at'].endswith('Z')

def test_live_privileged_actions_require_mfa(client,login,monkeypatch):
    login('sarah.sec');monkeypatch.setattr(settings,'DEMO_MODE',False)
    assert client.get('/api/approvals/pending').status_code==403

def test_password_change_invalidates_session(client,login):
    login();response=client.post('/api/auth/password',json={'current_password':'Password123!','new_password':'New-Secure-Password123!'})
    assert response.status_code==200 and client.get('/api/auth/me').status_code==401
    assert client.post('/api/auth/login',json={'username':'alex.dev','password':'New-Secure-Password123!'}).status_code==200

def test_policy_editor_tightens_and_enforces_current_policy(client,login,payload):
    login('admin.sys')
    role='JIT-Access-ReadOnly'
    data={'max_duration_minutes':30,'base_risk':25,'allowed_environments':['development']}
    assert client.patch('/api/users/roles/'+role,json=data).status_code==200
    login()
    assert client.post('/api/requests',json=payload,headers={'Idempotency-Key':str(uuid.uuid4())}).status_code==400
    payload['duration_minutes']=30
    assert client.post('/api/requests',json=payload,headers={'Idempotency-Key':str(uuid.uuid4())}).status_code==200
    login('admin.sys');data['base_risk']=1
    assert client.patch('/api/users/roles/'+role,json=data).status_code==422

def test_export_is_complete_and_valid_json(client,login):
    login('audit.user');response=client.get('/api/audit/export')
    assert response.status_code==200 and response.json()['valid']
    with client.db() as db: assert len(response.json()['records'])==db.query(AuditLog).count()

def test_user_deactivation_retries_external_failure(client,login,payload,monkeypatch):
    from app.aws.sts_service import sts_service,AWSOperationError
    from app.services import session_service
    login();response=client.post('/api/requests',json=payload,headers={'Idempotency-Key':str(uuid.uuid4())});assert response.status_code==200
    session=client.get('/api/sessions/active').json()[0]
    login('admin.sys')
    original=sts_service.revoke_session_policy
    def failure(*args,**kwargs): raise AWSOperationError('Temporary AWS outage')
    monkeypatch.setattr(sts_service,'revoke_session_policy',failure)
    response=client.patch('/api/users/'+session['user_id'],json={'is_active':False})
    assert response.status_code==200
    assert not response.json()['is_active'] and response.json()['sessions_revocation_pending']
    with client.db() as db: assert db.get(ActiveSession,session['id']).status=='ACTIVE'
    monkeypatch.setattr(sts_service,'revoke_session_policy',original)
    with client.db() as db: session_service.revoke_user_sessions(db,session['user_id'])
    with client.db() as db:
        assert not db.get(User,session['user_id']).sessions_revocation_pending
        assert db.get(ActiveSession,session['id']).status=='REVOKED'

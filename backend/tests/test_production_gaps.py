import json
import uuid
from datetime import datetime, timedelta
from types import SimpleNamespace
import pytest
from fastapi import HTTPException
from starlette.requests import Request
from app.config import settings
from app.models import User, Approval, AuditLog, AuditExport, WorkerState, Entitlement
from app.models.database import transaction, read_snapshot
from app.services import audit_service
from app.services.client_identity import client_ip
from app.aws.sts_service import STSService
from app.aws.safety_policy import safety_policy


def submit(client, payload):
    return client.post('/api/requests', json=payload, headers={'Idempotency-Key': str(uuid.uuid4())})


def test_ungranted_user_cannot_evaluate_or_request(client, login, payload):
    login('admin.sys')
    data={'username':'limited.dev','email':'limited@example.com','full_name':'Limited Developer','password':'Limited-password-123!'}
    created=client.post('/api/users',json=data).json()
    login('limited.dev',data['password'])
    assert client.post('/api/requests/evaluate',json=payload).status_code == 403
    assert submit(client,payload).status_code == 403
    login('admin.sys')
    grant={'aws_account_id':payload['aws_account_id'],'iam_role':payload['iam_role'],'max_duration_minutes':30}
    assert client.post(f"/api/users/{created['id']}/entitlements",json=grant).status_code == 200
    login('limited.dev',data['password'])
    assert submit(client,payload).status_code == 403
    payload['duration_minutes']=30
    assert submit(client,payload).status_code == 200


def test_changed_requester_cannot_receive_pending_credentials(client, login, payload):
    login();payload.update(aws_account_id='555444333222',aws_account_name='Prod-US-East-1',iam_role='JIT-Access-AdministratorAccess',ticket_ref='SEC-123')
    req=submit(client,payload).json()
    login('admin.sys')
    assert client.patch('/api/users/'+req['user_id'],json={'role':'AUDITOR'}).status_code == 200
    login('sarah.sec')
    assert client.post('/api/approvals/'+req['id']+'/decide',json={'approved':True}).status_code in (400,403)
    assert client.get('/api/sessions/active').json() == []


def test_demoted_approvers_old_vote_is_not_counted(client, login, payload):
    login();payload.update(aws_account_id='555444333222',aws_account_name='Prod-US-East-1',iam_role='JIT-Access-AdministratorAccess',ticket_ref='SEC-123')
    req=submit(client,payload).json()
    login('sarah.sec')
    assert client.post('/api/approvals/'+req['id']+'/decide',json={'approved':True}).json()['approval_count']==1
    login('admin.sys')
    sarah=next(u for u in client.get('/api/users').json() if u['username']=='sarah.sec')
    client.patch('/api/users/'+sarah['id'],json={'role':'REQUESTER'})
    result=client.post('/api/approvals/'+req['id']+'/decide',json={'approved':True}).json()
    assert result['status']=='PENDING' and result['approval_count']==1
    assert client.get('/api/sessions/active').json()==[]


def test_decided_queue_excludes_my_vote(client,login,payload):
    login();payload.update(aws_account_id='555444333222',aws_account_name='Prod-US-East-1',iam_role='JIT-Access-AdministratorAccess',ticket_ref='SEC-123')
    req=submit(client,payload).json();login('sarah.sec')
    client.post('/api/approvals/'+req['id']+'/decide',json={'approved':True})
    assert client.get('/api/approvals/pending').json()==[]


def test_cancellation_is_owner_only_and_prevents_approval(client,login,payload):
    login();payload.update(aws_account_id='987654321098',aws_account_name='Staging-EU',iam_role='JIT-Access-PowerUser')
    req=submit(client,payload).json();login('sarah.sec')
    assert client.post('/api/requests/'+req['id']+'/cancel').status_code==404
    login();assert client.post('/api/requests/'+req['id']+'/cancel').status_code==200
    login('sarah.sec');assert client.post('/api/approvals/'+req['id']+'/decide',json={'approved':True}).status_code==400


def test_mfa_recovery_codes_are_hashed_and_single_use(client,login):
    import pyotp
    login('sarah.sec');setup=client.post('/api/auth/mfa/setup',json={'current_password':'Password123!'}).json()
    result=client.post('/api/auth/mfa/enable',json={'otp':pyotp.TOTP(setup['secret']).now()}).json()
    code=result['recovery_codes'][0]
    with client.db() as db:
        assert code not in db.query(User).filter_by(username='sarah.sec').one().recovery_codes_json
    assert client.post('/api/auth/login',json={'username':'sarah.sec','password':'Password123!','recovery_code':code}).status_code==200
    assert client.post('/api/auth/login',json={'username':'sarah.sec','password':'Password123!','recovery_code':code}).status_code==401


def test_account_recovery_forces_password_change_and_revokes(client,login,payload):
    login();req=submit(client,payload).json();login('admin.sys')
    result=client.post('/api/users/'+req['user_id']+'/recover',json={'reason':'Verified identity in person','temporary_password':'Temporary-Password-123!'}).json()
    assert result['must_change_password']
    login('alex.dev','Temporary-Password-123!')
    assert submit(client,payload).status_code==403
    assert client.get('/api/sessions/active').status_code==403
    assert client.post('/api/auth/password',json={'current_password':'Temporary-Password-123!','new_password':'Changed-Password-123!'}).status_code==200
    login('alex.dev','Changed-Password-123!');assert submit(client,payload).status_code==200


def test_password_change_revokes_issued_aws_session(client,login,payload):
    login();submit(client,payload)
    assert client.post('/api/auth/password',json={'current_password':'Password123!','new_password':'Changed-Password-123!'}).status_code==200
    login('alex.dev','Changed-Password-123!')
    assert client.get('/api/sessions/active').json()==[]
    assert client.get('/api/sessions/history').json()[0]['status']=='REVOKED'


def test_grant_revocation_persists_and_revokes_sessions(client,login,payload):
    login();req=submit(client,payload).json();login('admin.sys')
    grant={'aws_account_id':payload['aws_account_id'],'iam_role':payload['iam_role'],'max_duration_minutes':480}
    assert client.post('/api/users/'+req['user_id']+'/entitlements/revoke',json=grant).status_code==200
    login();assert submit(client,payload).status_code==403
    assert client.get('/api/sessions/active').json()==[]


def test_deleted_external_archive_records_detected(client,login,monkeypatch):
    login('audit.user')
    with client.db() as db,transaction(db):
        for row in db.query(AuditExport): row.archived=True
    class Table:
        def scan(self,**kwargs): return {'Items':[]}
    monkeypatch.setattr(settings,'AUDIT_DYNAMODB_TABLE','secureaccess_audit_logs')
    import boto3
    monkeypatch.setattr(boto3,'resource',lambda *a,**k:SimpleNamespace(Table=lambda _:Table()))
    result=client.get('/api/audit/verify-chain').json()
    assert result['archive']['status']=='TAMPER_DETECTED'


def test_live_duration_is_capped_before_aws(monkeypatch,payload):
    from app.aws.iam_service import iam_service
    from app.schemas import AccessRequestCreate
    monkeypatch.setattr(settings,'DEMO_MODE',False)
    monkeypatch.setattr(settings,'AWS_ACCOUNTS_JSON',json.dumps([{'id':payload['aws_account_id'],'name':payload['aws_account_name'],'environment':'development','risk_multiplier':1}]))
    payload['duration_minutes']=120
    with pytest.raises(ValueError):iam_service.validate(AccessRequestCreate(**payload))
    with pytest.raises(ValueError):STSService().assume_role_jit(payload['aws_account_id'],payload['iam_role'],'alex.dev',120,str(uuid.uuid4()))


def test_role_verification_requires_boundary_and_trusted_principal(monkeypatch):
    service=STSService();arn='arn:aws:iam::123456789012:role/Broker'
    monkeypatch.setattr(settings,'AWS_ORCHESTRATOR_ARN',arn)
    monkeypatch.setattr(settings,'AWS_EXTERNAL_ID','external')
    role={'PermissionsBoundary':{'PermissionsBoundaryArn':'arn:boundary'},'AssumeRolePolicyDocument':{'Statement':[{'Effect':'Allow','Principal':{'AWS':arn},'Condition':{'StringEquals':{'sts:ExternalId':'external','aws:RequestTag/ManagedBy':'SecureAccessCloud'}}}]}}
    class IAM:
        def get_role(self,**kwargs):return {'Role':role}
        def get_policy(self,**kwargs):return {'Policy':{'DefaultVersionId':'v1'}}
        def get_policy_version(self,**kwargs):return {'PolicyVersion':{'Document':safety_policy()}}
    monkeypatch.setattr(service,'target_client',lambda *a:IAM())
    service.verify_target_role('123456789012','JIT-Access-ReadOnly')
    role['AssumeRolePolicyDocument']['Statement'][0]['Principal']['AWS']='*'
    with pytest.raises(ValueError):service.verify_target_role('123456789012','JIT-Access-ReadOnly')
    role.pop('PermissionsBoundary')
    with pytest.raises(ValueError):service.verify_target_role('123456789012','JIT-Access-ReadOnly')


def test_proxy_headers_only_accepted_from_trusted_hops(monkeypatch):
    monkeypatch.setattr(settings,'TRUSTED_PROXY_CIDRS',['127.0.0.1/32','10.0.0.0/24'])
    def request(peer,header):return Request({'type':'http','client':(peer,1),'headers':[(b'x-forwarded-for',header.encode())]})
    assert client_ip(request('198.51.100.2','1.1.1.1'))=='198.51.100.2'
    assert client_ip(request('127.0.0.1','1.1.1.1, 198.51.100.2, 10.0.0.1'))=='198.51.100.2'
    assert client_ip(request('127.0.0.1','invalid'))=='127.0.0.1'


def test_readiness_fails_when_worker_stale(client):
    with client.db() as db,transaction(db):
        state=db.get(WorkerState,1);state.status='HEALTHY';state.heartbeat=datetime.utcnow()-timedelta(minutes=10)
    assert client.get('/api/ready').status_code==503


def test_websocket_requires_origin_and_checks_logout(client,login):
    from starlette.websockets import WebSocketDisconnect
    login()
    with pytest.raises(WebSocketDisconnect):
        with client.websocket_connect('/api/events',headers={'Origin':'https://evil.example'}):pass
    with client.websocket_connect('/api/events',headers={'Origin':'http://localhost:3000'}) as socket:
        assert socket.receive_json()=={'type':'refresh'}
        client.post('/api/auth/logout')
        socket.send_text('ping')
        with pytest.raises(WebSocketDisconnect):socket.receive_json()


def test_ticket_provider_verifies_and_fails_closed(monkeypatch):
    from app.services.ticket_service import verify_ticket
    monkeypatch.setattr(settings,'DEMO_MODE',False)
    monkeypatch.setattr(settings,'JIRA_URL','https://jira.example.com')
    monkeypatch.setattr(settings,'TICKET_VERIFICATION_REQUIRED',True)
    import httpx
    monkeypatch.setattr(httpx,'get',lambda *a,**k:SimpleNamespace(status_code=200,json=lambda:{'key':'SEC-123','fields':{'status':{'statusCategory':{'key':'done'}}}}))
    with pytest.raises(ValueError):verify_ticket('SEC-123')
    monkeypatch.setattr(httpx,'get',lambda *a,**k:SimpleNamespace(status_code=200,json=lambda:{'key':'SEC-123','fields':{'status':{'statusCategory':{'key':'indeterminate'}}}}))
    verify_ticket('SEC-123')

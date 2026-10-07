import uuid
from datetime import datetime,timedelta
from app.models import ActiveSession,AccessRequest
from app.models.database import transaction
from app.services import session_service
from app.aws.sts_service import sts_service,AWSOperationError
from app.config import settings

def new_session(client,payload):
    result=client.post('/api/requests',json=payload,headers={'Idempotency-Key':str(uuid.uuid4())})
    assert result.status_code==200,result.text
    return client.get('/api/sessions/active').json()[-1]

def test_credentials_encrypted_and_not_in_lists(client,login,payload):
    login();sess=new_session(client,payload)
    assert 'aws_secret_access_key' not in sess
    with client.db() as db:
        record=db.get(ActiveSession,sess['id'])
        assert 'DEMO-NOT-VALID' not in record.credentials_encrypted
    own=client.post(f"/api/sessions/{sess['id']}/credentials")
    assert own.status_code==200 and own.json()['is_demo']
    login('audit.user')
    assert client.post(f"/api/sessions/{sess['id']}/credentials").status_code==403
    login('sarah.sec')
    assert client.post(f"/api/sessions/{sess['id']}/credentials").status_code==404

def test_revocation_clears_credentials(client,login,payload):
    login();sess=new_session(client,payload)
    response=client.post(f"/api/sessions/{sess['id']}/revoke")
    assert response.status_code==200 and response.json()['status']=='REVOKED'
    assert client.post(f"/api/sessions/{sess['id']}/credentials").status_code==400
    with client.db() as db: assert db.get(ActiveSession,sess['id']).credentials_encrypted is None

def test_expiry_filters_immediately_and_worker_clears(client,login,payload):
    login();sess=new_session(client,payload)
    with client.db() as db,transaction(db): db.get(ActiveSession,sess['id']).expires_at=datetime.utcnow()-timedelta(seconds=1)
    assert client.get('/api/sessions/active').json()==[]
    assert client.post(f"/api/sessions/{sess['id']}/credentials").status_code==400
    with client.db() as db,transaction(db): session_service.check_and_expire_sessions(db)
    with client.db() as db:
        session=db.get(ActiveSession,sess['id']);assert session.status=='EXPIRED' and session.credentials_encrypted is None
        assert db.get(AccessRequest,session.request_id).status=='EXPIRED'

def test_aws_failure_does_not_issue_or_approve(client,login,payload,monkeypatch):
    login()
    def fail(*a,**kw): raise AWSOperationError('AWS credential issuance failed')
    monkeypatch.setattr(sts_service,'assume_role_jit',fail)
    response=client.post('/api/requests',json=payload,headers={'Idempotency-Key':str(uuid.uuid4())})
    assert response.status_code==502
    with client.db() as db: assert db.query(AccessRequest).count()==0 and db.query(ActiveSession).count()==0

def test_failed_revocation_preserves_active_state(client,login,payload,monkeypatch):
    login();sess=new_session(client,payload)
    def fail(*a,**kw): raise AWSOperationError('AWS revocation failed')
    monkeypatch.setattr(sts_service,'revoke_session_policy',fail)
    assert client.post(f"/api/sessions/{sess['id']}/revoke").status_code==502
    with client.db() as db: assert db.get(ActiveSession,sess['id']).status=='ACTIVE'

def test_session_cap(client,login,payload):
    login()
    for _ in range(settings.MAX_ACTIVE_SESSIONS_PER_USER): new_session(client,payload)
    response=client.post('/api/requests',json=payload,headers={'Idempotency-Key':str(uuid.uuid4())})
    assert response.status_code==400 and 'Maximum active sessions' in response.json()['detail']

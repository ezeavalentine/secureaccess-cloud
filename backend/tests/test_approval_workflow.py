import uuid
from app.models import ActiveSession, User, Approval, AccessRequest
from app.services import get_password_hash

def submit(client, payload): return client.post("/api/requests", json=payload, headers={"Idempotency-Key":str(uuid.uuid4())})

def test_dual_approval_requires_distinct_approvers(client, login, payload):
    login()
    payload.update(aws_account_id="555444333222", aws_account_name="Prod-US-East-1", iam_role="JIT-Access-AdministratorAccess", ticket_ref="SEC-123")
    request = submit(client,payload).json()
    assert request["status"] == "PENDING"
    login("sarah.sec")
    decision = client.post(f"/api/approvals/{request['id']}/decide", json={"approved":True})
    assert decision.status_code == 200 and decision.json()["status"] == "PENDING" and decision.json()["approval_count"] == 1
    duplicate = client.post(f"/api/approvals/{request['id']}/decide", json={"approved":True})
    assert duplicate.status_code == 400
    login("admin.sys")
    final = client.post(f"/api/approvals/{request['id']}/decide", json={"approved":True})
    assert final.status_code == 200 and final.json()["status"] == "APPROVED"
    with client.db() as db: assert db.query(ActiveSession).count()==1 and db.query(Approval).count()==2
    assert client.get("/api/audit/verify-chain").json()["status"]=="VALID"

def test_self_approval_forbidden(client,login,payload):
    login("sarah.sec")
    payload.update(aws_account_id="987654321098",aws_account_name="Staging-EU",iam_role="JIT-Access-PowerUser")
    req=submit(client,payload).json()
    assert client.post(f"/api/approvals/{req['id']}/decide",json={"approved":True}).status_code==400

def test_reject_requires_reason(client,login,payload):
    login()
    payload.update(aws_account_id="987654321098",aws_account_name="Staging-EU",iam_role="JIT-Access-PowerUser")
    req=submit(client,payload).json();login("sarah.sec")
    assert client.post(f"/api/approvals/{req['id']}/decide",json={"approved":False}).status_code==400
    response=client.post(f"/api/approvals/{req['id']}/decide",json={"approved":False,"reason":"Not justified"})
    assert response.status_code==200 and response.json()["status"]=="REJECTED"

def test_idempotency(client,login,payload):
    login();headers={"Idempotency-Key":"same-request-key"}
    a=client.post('/api/requests',json=payload,headers=headers)
    b=client.post('/api/requests',json=payload,headers=headers)
    assert a.status_code==200 and a.json()['id']==b.json()['id']
    payload['duration_minutes']=30
    assert client.post('/api/requests',json=payload,headers=headers).status_code==409
    with client.db() as db: assert db.query(ActiveSession).count()==1

def test_concurrent_approval_issues_exactly_one_session(client,login,payload):
    from concurrent.futures import ThreadPoolExecutor
    login();payload.update(aws_account_id='987654321098',aws_account_name='Staging-EU',iam_role='JIT-Access-PowerUser')
    req=submit(client,payload).json();login('sarah.sec')
    def decide(): return client.post(f"/api/approvals/{req['id']}/decide",json={'approved':True}).status_code
    with ThreadPoolExecutor(max_workers=2) as executor: results=list(executor.map(lambda _:decide(),range(2)))
    assert sorted(results)==[200,400]
    with client.db() as db: assert db.query(ActiveSession).count()==1

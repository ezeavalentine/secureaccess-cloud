import json
from datetime import datetime,timezone,timedelta
from types import SimpleNamespace
import boto3
from botocore.stub import Stubber
import pytest
from app.aws.sts_service import STSService,AWSOperationError
from app.config import settings

def sdk(service):
    return boto3.client(service,region_name='us-east-1',aws_access_key_id='testing',aws_secret_access_key='testing')

def test_sts_passes_trust_tags_externalid_and_session_boundary(monkeypatch):
    monkeypatch.setattr(settings,'DEMO_MODE',False)
    monkeypatch.setattr(settings,'AWS_ACCOUNTS_JSON',json.dumps([{'id':'123456789012','name':'Development','environment':'development','risk_multiplier':1.0}]))
    monkeypatch.setattr(settings,'AWS_EXTERNAL_ID','random-external-id-for-tests')
    client=sdk('sts');service=STSService();monkeypatch.setattr(service,'client',lambda _:client)
    monkeypatch.setattr(service, 'verify_target_role', lambda *_: None)
    request_id='12345678-1234-1234-1234-123456789012'
    name='JIT-'+request_id
    with Stubber(client) as stub:
        stub.add_response('assume_role',{'Credentials':{'AccessKeyId':'ASIAABCDEFGHIJKLMNOP','SecretAccessKey':'x'*40,'SessionToken':'token','Expiration':datetime.now(timezone.utc)+timedelta(hours=1)},'AssumedRoleUser':{'AssumedRoleId':'AROAEXAMPLE:'+name,'Arn':'arn:aws:sts::123456789012:assumed-role/JIT-Access-ReadOnly/'+name}},expected_params=None)
        response=service.assume_role_jit('123456789012','JIT-Access-ReadOnly','alex.dev',60,request_id)
        assert response['assumed_role_id']=='AROAEXAMPLE:'+name and response['session_name']==name
        stub.assert_no_pending_responses()
    # Inspect request parameters through a separate capture client; this also
    # verifies the permission-restricting session policy is actually supplied.
    captured={}
    class Capture:
        def assume_role(self,**kwargs): captured.update(kwargs);raise RuntimeError('Denied')
    monkeypatch.setattr(service,'client',lambda _:Capture())
    with pytest.raises(AWSOperationError):service.assume_role_jit('123456789012','JIT-Access-ReadOnly','alex.dev',60,request_id)
    assert captured['ExternalId']==settings.AWS_EXTERNAL_ID and captured['SourceIdentity']=='alex.dev'
    assert {'Key':'ManagedBy','Value':'SecureAccessCloud'} in captured['Tags']
    assert 'sts:AssumeRole*' in json.loads(captured['Policy'])['Statement'][1]['Action']

def test_aws_denial_never_falls_back_to_demo(monkeypatch):
    monkeypatch.setattr(settings,'DEMO_MODE',False)
    monkeypatch.setattr(settings,'AWS_ACCOUNTS_JSON','[{"id":"123456789012","name":"Dev","environment":"development","risk_multiplier":1.0}]')
    client=sdk('sts');service=STSService();monkeypatch.setattr(service,'client',lambda _:client)
    monkeypatch.setattr(service, 'verify_target_role', lambda *_: None)
    with Stubber(client) as stub:
        stub.add_client_error('assume_role',service_error_code='AccessDenied')
        with pytest.raises(AWSOperationError):service.assume_role_jit('123456789012','JIT-Access-ReadOnly','alex.dev',60,'12345678-1234-1234-1234-123456789012')

def test_revocation_is_scoped_to_aws_role_identity(monkeypatch):
    client=sdk('iam');service=STSService();monkeypatch.setattr(service,'target_client',lambda *_:client)
    session=SimpleNamespace(id='12345678',iam_role='JIT-Access-ReadOnly',assumed_role_id='AROAXYZ:JIT-request',aws_account_id='123456789012',is_demo=False)
    policy={'Version':'2012-10-17','Statement':[{'Effect':'Deny','Action':'*','Resource':'*','Condition':{'StringEquals':{'aws:userid':'AROAXYZ:JIT-request'}}}]}
    with Stubber(client) as stub:
        stub.add_response('put_role_policy',{}, {'RoleName':session.iam_role,'PolicyName':'JITRevoke-12345678','PolicyDocument':json.dumps(policy)})
        assert service.revoke_session_policy(session)=='JITRevoke-12345678'
        stub.assert_no_pending_responses()

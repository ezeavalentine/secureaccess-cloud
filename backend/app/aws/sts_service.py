import json
import secrets
import uuid
from datetime import datetime, timedelta
from urllib.parse import urlencode
import boto3
import httpx
from botocore.config import Config
from app.config import settings
from app.aws.iam_service import iam_service
from app.aws.safety_policy import safety_policy
class AWSOperationError(Exception): pass
class STSService:
    def client(self, service): return boto3.client(service, region_name=settings.AWS_REGION, config=Config(connect_timeout=5, read_timeout=15, retries={"max_attempts": 2}))
    def assume_role_jit(self, account_id, role_name, requester_username, duration_minutes, request_id):
        name = f"JIT-{request_id}"
        if settings.DEMO_MODE:
            return {"access_key_id": "DEMO" + secrets.token_hex(8).upper(), "secret_access_key": "DEMO-NOT-VALID-AWS-CREDENTIALS", "session_token": "DEMO-NOT-VALID-AWS-TOKEN", "expires_at": datetime.utcnow() + timedelta(minutes=duration_minutes), "session_name": name, "assumed_role_id": f"DEMO:{name}"}
        iam_service.account(account_id)
        if not 15 <= duration_minutes <= settings.LIVE_MAX_DURATION_MINUTES:
            raise ValueError("Live AWS sessions cannot exceed the configured role-chaining limit")
        try:
            self.verify_target_role(account_id, role_name)
            client = self.client("sts")
            tags = [{"Key": "ManagedBy", "Value": "SecureAccessCloud"}, {"Key": "RequestId", "Value": request_id}]
            response = client.assume_role(RoleArn=f"arn:aws:iam::{account_id}:role/{role_name}", RoleSessionName=name, DurationSeconds=duration_minutes * 60, ExternalId=settings.AWS_EXTERNAL_ID, Tags=tags, SourceIdentity=requester_username,
                Policy=json.dumps(safety_policy(), separators=(",", ":")))
            creds = response["Credentials"]
            return {"access_key_id": creds["AccessKeyId"], "secret_access_key": creds["SecretAccessKey"], "session_token": creds["SessionToken"], "expires_at": creds["Expiration"].replace(tzinfo=None), "session_name": name, "assumed_role_id": response["AssumedRoleUser"]["AssumedRoleId"]}
        except Exception as exc:
            raise AWSOperationError("AWS credential issuance failed; no session was issued") from exc
    def verify_target_role(self, account_id, role_name):
        client = self.target_client(account_id, "iam")
        role = client.get_role(RoleName=role_name)["Role"]
        boundary = role.get("PermissionsBoundary", {}).get("PermissionsBoundaryArn")
        if not boundary: raise ValueError("Target role has no permission boundary")
        policy = client.get_policy(PolicyArn=boundary)["Policy"]
        document = client.get_policy_version(PolicyArn=boundary, VersionId=policy["DefaultVersionId"])["PolicyVersion"]["Document"]
        if isinstance(document, str):
            from urllib.parse import unquote
            document = json.loads(unquote(document))
        # Require every reviewed deny, including resource scopes and conditions.
        for required in safety_policy()["Statement"][1:]:
            covered = set()
            expected = required["Resource"]
            expected = [expected] if isinstance(expected, str) else expected
            for statement in document.get("Statement", []):
                actions = statement.get("Action", [])
                resources = statement.get("Resource", [])
                actions = [actions] if isinstance(actions, str) else actions
                resources = [resources] if isinstance(resources, str) else resources
                if statement.get("Effect") == "Deny" and not statement.get("Condition") and set(expected).issubset(resources):
                    covered.update(actions)
            if not set(required["Action"]).issubset(covered):
                raise ValueError("Target boundary is missing reviewed restrictions")
        trust = role["AssumeRolePolicyDocument"]
        if isinstance(trust, str):
            from urllib.parse import unquote
            trust = json.loads(unquote(trust))
        allows = [s for s in trust.get("Statement", []) if s.get("Effect") == "Allow"]
        if not allows or not settings.AWS_ORCHESTRATOR_ARN: raise ValueError("Trusted orchestrator is not configured")
        for statement in allows:
            principal = statement.get("Principal")
            condition = statement.get("Condition", {}).get("StringEquals", {})
            if principal != {"AWS": settings.AWS_ORCHESTRATOR_ARN} or condition.get("sts:ExternalId") != settings.AWS_EXTERNAL_ID or condition.get("aws:RequestTag/ManagedBy") != "SecureAccessCloud":
                raise ValueError("Target trust permits an unreviewed principal or lacks broker conditions")

    def target_client(self, account_id, service, region=None):
        account = iam_service.account(account_id)
        arn = account.get("management_role_arn", f"arn:aws:iam::{account_id}:role/SecureAccessRevokerRole")
        creds = self.client("sts").assume_role(RoleArn=arn, RoleSessionName="SecureAccessManagement", DurationSeconds=900, ExternalId=settings.AWS_EXTERNAL_ID)["Credentials"]
        return boto3.client(service, region_name=region or settings.AWS_REGION, aws_access_key_id=creds["AccessKeyId"], aws_secret_access_key=creds["SecretAccessKey"], aws_session_token=creds["SessionToken"], config=Config(connect_timeout=5, read_timeout=15, retries={"max_attempts": 2}))
    def revoke_session_policy(self, session):
        if session.is_demo: return None
        name = f"JITRevoke-{session.id}"
        policy = {"Version": "2012-10-17", "Statement": [{"Effect": "Deny", "Action": "*", "Resource": "*", "Condition": {"StringEquals": {"aws:userid": session.assumed_role_id}}}]}
        try: self.target_client(session.aws_account_id, "iam").put_role_policy(RoleName=session.iam_role, PolicyName=name, PolicyDocument=json.dumps(policy))
        except Exception as exc: raise AWSOperationError("AWS revocation failed; session has not been marked revoked") from exc
        return name
    def cleanup_revocation(self, session):
        if session.is_demo or not session.revocation_policy: return
        try: self.target_client(session.aws_account_id, "iam").delete_role_policy(RoleName=session.iam_role, PolicyName=session.revocation_policy)
        except Exception as exc:
            if getattr(exc, "response", {}).get("Error", {}).get("Code") != "NoSuchEntity": raise AWSOperationError("AWS revocation policy cleanup failed") from exc
    def console_url(self, credentials):
        if settings.DEMO_MODE: raise ValueError("Demo credentials cannot open the AWS console")
        session = {"sessionId": credentials["access_key_id"], "sessionKey": credentials["secret_access_key"], "sessionToken": credentials["session_token"]}
        try:
            response = httpx.get("https://signin.aws.amazon.com/federation", params={"Action": "getSigninToken", "Session": json.dumps(session)}, timeout=15)
            response.raise_for_status()
            token = response.json()["SigninToken"]
        except Exception as exc: raise AWSOperationError("AWS console federation failed") from exc
        return "https://signin.aws.amazon.com/federation?" + urlencode({"Action": "login", "Issuer": settings.PUBLIC_URL, "Destination": f"https://console.aws.amazon.com/console/home?region={settings.AWS_REGION}", "SigninToken": token})
sts_service = STSService()

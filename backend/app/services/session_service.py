import json
from datetime import datetime
from sqlalchemy import select, func
from app.models import ActiveSession, AccessRequest, User
from app.config import settings
from app.aws import sts_service
from app.services.crypto import encrypt, decrypt
from app.services.audit_service import audit_service
class SessionService:
    def assert_capacity(self, db, user_id, account_id, role):
        # Lock the requester on server databases; SQLite writes are serialized.
        db.execute(select(User).where(User.id == user_id).with_for_update()).scalar_one()
        now = datetime.utcnow()
        count = db.query(ActiveSession).filter(ActiveSession.user_id == user_id, ActiveSession.status == "ACTIVE", ActiveSession.expires_at > now).count()
        if count >= settings.MAX_ACTIVE_SESSIONS_PER_USER: raise ValueError("Maximum active sessions reached for this user")
        # Count all unexpired credentials, including revoked sessions, until IAM
        # revocation-policy cleanup can occur. PostgreSQL locks capacity by
        # account/role rather than blocking all roles on the audit chain.
        if db.bind.dialect.name == "postgresql":
            from sqlalchemy import text
            db.execute(text("SELECT pg_advisory_xact_lock(hashtext(:role))"), {"role": account_id + ":" + role})
        count = db.query(ActiveSession).filter(ActiveSession.aws_account_id == account_id, ActiveSession.iam_role == role, ActiveSession.expires_at > now).count()
        if count >= settings.MAX_SESSIONS_PER_ROLE: raise ValueError("Maximum concurrent sessions reached for this role")
    def create_session_from_request(self, db, access_request, ip="system"):
        from app.services.entitlement_service import assert_entitled
        assert_entitled(db, db.get(User, access_request.user_id), access_request)
        existing = db.query(ActiveSession).filter_by(request_id=access_request.id).first()
        if existing: return existing
        self.assert_capacity(db, access_request.user_id, access_request.aws_account_id, access_request.iam_role)
        response = sts_service.assume_role_jit(access_request.aws_account_id, access_request.iam_role, access_request.username, access_request.duration_minutes, access_request.id)
        session = ActiveSession(request_id=access_request.id, user_id=access_request.user_id, username=access_request.username, aws_account_id=access_request.aws_account_id, iam_role=access_request.iam_role, credentials_encrypted=encrypt(json.dumps({k: response[k] for k in ["access_key_id", "secret_access_key", "session_token"]})), aws_session_name=response["session_name"], assumed_role_id=response["assumed_role_id"], expires_at=response["expires_at"], status="ACTIVE", is_demo=settings.DEMO_MODE)
        db.add(session)
        access_request.status, access_request.approved_at = "APPROVED", datetime.utcnow()
        db.flush()
        audit_service.log_event(db, "SESSION_CREATED", access_request.username, f"session:{session.id}", {"request_id": access_request.id, "duration_minutes": access_request.duration_minutes, "mode": "demo" if settings.DEMO_MODE else "aws"}, access_request.risk_level, ip)
        return session
    def credentials(self, session):
        if session.status != "ACTIVE" or session.expires_at <= datetime.utcnow() or not session.credentials_encrypted: raise ValueError("Session is no longer active")
        credentials = json.loads(decrypt(session.credentials_encrypted))
        return {"aws_access_key_id": credentials["access_key_id"], "aws_secret_access_key": credentials["secret_access_key"], "aws_session_token": credentials["session_token"], "aws_region": settings.AWS_REGION, "is_demo": session.is_demo}
    def revoke_session(self, db, session_id, revoked_by, ip="system"):
        session = db.execute(select(ActiveSession).where(ActiveSession.id == session_id).with_for_update()).scalar_one_or_none()
        if not session or session.status != "ACTIVE" or session.expires_at <= datetime.utcnow(): raise ValueError("Session is not active")
        session.revocation_policy = sts_service.revoke_session_policy(session)
        session.status, session.revoked_at, session.revoked_by = "REVOKED", datetime.utcnow(), revoked_by
        session.credentials_encrypted = None
        req = db.get(AccessRequest, session.request_id)
        req.status = "REVOKED"
        audit_service.log_event(db, "SESSION_REVOKED", revoked_by, f"session:{session.id}", {"username": session.username, "mode": "demo" if session.is_demo else "aws", "aws_policy": session.revocation_policy}, "HIGH", ip)
        return session
    def revoke_user_sessions(self, db, user_id, actor="SYSTEM", ip="system"):
        from app.models.database import transaction
        import logging
        session_ids = [s.id for s in db.query(ActiveSession).filter(ActiveSession.user_id == user_id, ActiveSession.status == "ACTIVE", ActiveSession.expires_at > datetime.utcnow()).all()]
        for session_id in session_ids:
            try:
                with transaction(db):
                    current = db.get(ActiveSession, session_id)
                    if current.status == "ACTIVE" and current.expires_at > datetime.utcnow(): self.revoke_session(db, session_id, actor, ip)
            except Exception:
                logging.getLogger(__name__).exception("User session revocation will be retried")
        with transaction(db):
            remaining = db.query(ActiveSession).filter(ActiveSession.user_id == user_id, ActiveSession.status == "ACTIVE", ActiveSession.expires_at > datetime.utcnow()).count()
            db.get(User, user_id).sessions_revocation_pending = remaining > 0
    def check_and_expire_sessions(self, db):
        now = datetime.utcnow()
        sessions = db.execute(select(ActiveSession).where(ActiveSession.status == "ACTIVE", ActiveSession.expires_at <= now).with_for_update()).scalars().all()
        for session in sessions:
            session.status, session.credentials_encrypted = "EXPIRED", None
            req = db.get(AccessRequest, session.request_id)
            if req.status == "APPROVED": req.status = "EXPIRED"
            audit_service.log_event(db, "SESSION_EXPIRED", "SYSTEM", f"session:{session.id}", {"username": session.username})
        for req in db.query(AccessRequest).filter(AccessRequest.status == "PENDING", AccessRequest.expires_at <= now).all():
            req.status = "EXPIRED"
            audit_service.log_event(db, "REQUEST_EXPIRED", "SYSTEM", f"request:{req.id}", {})
        for session in db.query(ActiveSession).filter(ActiveSession.expires_at <= now, ActiveSession.revocation_policy != None).all():
            try:
                sts_service.cleanup_revocation(session)
                session.revocation_policy = None
            except Exception:
                import logging
                logging.getLogger(__name__).exception("Revocation policy cleanup will be retried")
session_service = SessionService()

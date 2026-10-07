import uuid
from datetime import datetime
from sqlalchemy import Column, String, DateTime, Text, ForeignKey, CheckConstraint, Boolean
from app.models.database import Base
class ActiveSession(Base):
    __tablename__ = "active_sessions"
    __table_args__ = (CheckConstraint("status IN ('ACTIVE','EXPIRED','REVOKED')", name="valid_session_status"),)
    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    request_id = Column(String(36), ForeignKey("access_requests.id"), nullable=False, unique=True)
    user_id = Column(String(36), ForeignKey("users.id"), nullable=False, index=True)
    username = Column(String(50), nullable=False)
    aws_account_id = Column(String(12), nullable=False)
    iam_role = Column(String(100), nullable=False)
    credentials_encrypted = Column(Text)
    aws_session_name = Column(String(64), nullable=False)
    assumed_role_id = Column(String(150), nullable=False)
    issued_at = Column(DateTime, nullable=False, default=datetime.utcnow)
    expires_at = Column(DateTime, nullable=False, index=True)
    revoked_at = Column(DateTime)
    revoked_by = Column(String(50))
    status = Column(String(20), nullable=False, default="ACTIVE", index=True)
    is_demo = Column(Boolean, nullable=False)
    revocation_policy = Column(String(128))

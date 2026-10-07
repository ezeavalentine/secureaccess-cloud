import uuid
from datetime import datetime
from sqlalchemy import Column, String, Integer, DateTime, Text, ForeignKey, CheckConstraint
from app.models.database import Base
class AccessRequest(Base):
    __tablename__ = "access_requests"
    __table_args__ = (CheckConstraint("duration_minutes BETWEEN 15 AND 480", name="valid_duration"), CheckConstraint("status IN ('PENDING','APPROVED','REJECTED','EXPIRED','REVOKED')", name="valid_request_status"))
    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    user_id = Column(String(36), ForeignKey("users.id"), nullable=False, index=True)
    username = Column(String(50), nullable=False)
    aws_account_id = Column(String(12), nullable=False)
    aws_account_name = Column(String(50), nullable=False)
    iam_role = Column(String(100), nullable=False)
    duration_minutes = Column(Integer, nullable=False)
    justification = Column(Text, nullable=False)
    ticket_ref = Column(String(50))
    risk_score = Column(Integer, nullable=False, default=10)
    risk_level = Column(String(20), nullable=False, default="LOW")
    auto_approved = Column(String(10), nullable=False, default="FALSE")
    status = Column(String(20), nullable=False, default="PENDING", index=True)
    rejection_reason = Column(Text)
    approver_username = Column(String(50))
    required_approvals = Column(Integer, nullable=False, default=1)
    created_at = Column(DateTime, nullable=False, default=datetime.utcnow)
    approved_at = Column(DateTime)
    expires_at = Column(DateTime, nullable=False)
    idempotency_key = Column(String(128), unique=True)

class Approval(Base):
    __tablename__ = "approvals"
    from sqlalchemy import UniqueConstraint
    __table_args__ = (UniqueConstraint("request_id", "approver_id", name="unique_approver"),)
    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    request_id = Column(String(36), ForeignKey("access_requests.id"), nullable=False, index=True)
    approver_id = Column(String(36), ForeignKey("users.id"), nullable=False)
    approver_username = Column(String(50), nullable=False)
    approver_version = Column(Integer, nullable=False, default=-1)
    approved = Column(Integer, nullable=False)
    reason = Column(Text)
    created_at = Column(DateTime, nullable=False, default=datetime.utcnow)

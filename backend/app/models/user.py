import uuid
from datetime import datetime
from sqlalchemy import Column, String, Boolean, DateTime, Integer, CheckConstraint, Text
from app.models.database import Base
class User(Base):
    __tablename__ = "users"
    __table_args__ = (CheckConstraint("role IN ('REQUESTER','APPROVER','SECURITY_ADMIN','AUDITOR')", name="valid_user_role"),)
    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    username = Column(String(50), unique=True, index=True, nullable=False)
    email = Column(String(254), unique=True, index=True, nullable=False)
    full_name = Column(String(100), nullable=False)
    hashed_password = Column(String(255), nullable=False)
    role = Column(String(20), nullable=False, default="REQUESTER")
    department = Column(String(50), nullable=False, default="Engineering")
    is_active = Column(Boolean, nullable=False, default=True)
    sessions_revocation_pending = Column(Boolean, nullable=False, default=False)
    token_version = Column(Integer, nullable=False, default=0)
    mfa_secret = Column(String(512), nullable=True)
    mfa_enabled = Column(Boolean, nullable=False, default=False)
    last_totp_step = Column(Integer, nullable=True)
    recovery_codes_json = Column(Text, nullable=False, default="[]")
    must_change_password = Column(Boolean, nullable=False, default=False)
    created_at = Column(DateTime, nullable=False, default=datetime.utcnow)

import uuid
from datetime import datetime
from sqlalchemy import Column, String, DateTime, Text, Integer, Boolean, ForeignKey
from app.models.database import Base
class AuditLog(Base):
    __tablename__ = "audit_logs"
    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    sequence = Column(Integer, unique=True, nullable=False)
    event_type = Column(String(50), nullable=False)
    actor = Column(String(50), nullable=False)
    target_resource = Column(String(200), nullable=False)
    details = Column(Text, nullable=False)
    ip_address = Column(String(45), nullable=False)
    risk_score = Column(String(10), nullable=False)
    previous_hash = Column(String(64), nullable=False)
    hash_signature = Column(String(64), nullable=False)
    timestamp = Column(DateTime, nullable=False, default=datetime.utcnow)

class AuditHead(Base):
    __tablename__ = "audit_head"
    id = Column(Integer, primary_key=True, default=1)
    sequence = Column(Integer, nullable=False, default=0)
    signature = Column(String(64), nullable=False, default="0" * 64)

class AuditExport(Base):
    __tablename__ = "audit_exports"
    event_id = Column(String(36), ForeignKey("audit_logs.id"), primary_key=True)
    archived = Column(Boolean, nullable=False, default=False)

class Notification(Base):
    __tablename__ = "notifications"
    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    user_id = Column(String(36), ForeignKey("users.id"), nullable=False, index=True)
    message = Column(Text, nullable=False)
    request_id = Column(String(36))
    read = Column(Boolean, nullable=False, default=False)
    email_sent = Column(Boolean, nullable=False, default=False)
    email_attempts = Column(Integer, nullable=False, default=0)
    email_next_attempt = Column(DateTime)
    created_at = Column(DateTime, nullable=False, default=datetime.utcnow)

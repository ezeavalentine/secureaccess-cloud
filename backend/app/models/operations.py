from sqlalchemy import Column, Integer, String, DateTime, Text
from app.models.database import Base


class WorkerState(Base):
    __tablename__ = "worker_state"
    id = Column(Integer, primary_key=True)
    status = Column(String(40), nullable=False, default="STARTING")
    heartbeat = Column(DateTime)
    lease_until = Column(DateTime)
    owner = Column(String(36))


class RateBucket(Base):
    __tablename__ = "rate_buckets"
    key = Column(String(64), primary_key=True)
    timestamps_json = Column(Text, nullable=False)
    updated_at = Column(DateTime, nullable=False, index=True)

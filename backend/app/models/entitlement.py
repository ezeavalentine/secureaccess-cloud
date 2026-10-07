from sqlalchemy import Column, String, Integer, ForeignKey, CheckConstraint
from app.models.database import Base


class Entitlement(Base):
    __tablename__ = "entitlements"
    __table_args__ = (CheckConstraint("max_duration_minutes BETWEEN 15 AND 480", name="valid_entitlement_duration"),)
    user_id = Column(String(36), ForeignKey("users.id"), primary_key=True)
    aws_account_id = Column(String(12), primary_key=True)
    iam_role = Column(String(100), primary_key=True)
    max_duration_minutes = Column(Integer, nullable=False)

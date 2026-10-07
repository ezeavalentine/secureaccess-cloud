from sqlalchemy import Column, String, Integer, Text, CheckConstraint
from app.models.database import Base
class RolePolicy(Base):
    __tablename__ = "role_policies"
    __table_args__ = (CheckConstraint("max_duration_minutes BETWEEN 15 AND 480", name="valid_policy_duration"), CheckConstraint("base_risk BETWEEN 15 AND 100", name="valid_policy_risk"))
    role_name = Column(String(100), primary_key=True)
    max_duration_minutes = Column(Integer, nullable=False)
    base_risk = Column(Integer, nullable=False)
    allowed_environments_json = Column(Text, nullable=False)

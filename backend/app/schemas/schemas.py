from datetime import datetime, timezone
from typing import Literal
from pydantic import BaseModel, ConfigDict, Field, EmailStr, field_serializer, field_validator
Role = Literal["REQUESTER", "APPROVER", "SECURITY_ADMIN", "AUDITOR"]
class Output(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    @field_serializer("*", check_fields=False)
    def serialize_utc(self, value):
        if isinstance(value, datetime): return value.replace(tzinfo=timezone.utc).isoformat().replace("+00:00", "Z")
        return value
class LoginRequest(BaseModel):
    username: str = Field(min_length=1, max_length=50)
    password: str = Field(min_length=1, max_length=128)
    otp: str | None = Field(default=None, pattern=r"^\d{6}$")
    recovery_code: str | None = Field(default=None, min_length=16, max_length=64)
class Token(BaseModel):
    username: str
    role: Role
    expires_in: int
    demo_mode: bool
class UserCreate(BaseModel):
    username: str = Field(pattern=r"^[a-zA-Z0-9._-]{3,50}$")
    email: EmailStr
    full_name: str = Field(min_length=1, max_length=100)
    password: str = Field(min_length=12, max_length=128)
    role: Role = "REQUESTER"
    department: str = Field(default="Engineering", max_length=50)
class UserUpdate(BaseModel):
    role: Role | None = None
    is_active: bool | None = None
    department: str | None = Field(default=None, max_length=50)
class UserOut(Output):
    id: str
    username: str
    email: str
    full_name: str
    role: Role
    department: str
    is_active: bool
    mfa_enabled: bool
    sessions_revocation_pending: bool
    must_change_password: bool
    created_at: datetime
class AccessRequestCreate(BaseModel):
    model_config = ConfigDict(extra="forbid")
    aws_account_id: str = Field(pattern=r"^\d{12}$")
    aws_account_name: str = Field(min_length=1, max_length=50)
    iam_role: str = Field(pattern=r"^JIT-Access-[A-Za-z0-9_-]+$", max_length=100)
    duration_minutes: int = Field(ge=15, le=480)
    justification: str = Field(min_length=5, max_length=2000)
    ticket_ref: str | None = Field(default=None, max_length=50)
    @field_validator("justification")
    @classmethod
    def useful_justification(cls, value):
        if len(value.strip()) < 5: raise ValueError("Provide a meaningful justification")
        return value.strip()
class AccessRequestOut(Output):
    id: str
    user_id: str
    username: str
    aws_account_id: str
    aws_account_name: str
    iam_role: str
    duration_minutes: int
    justification: str
    ticket_ref: str | None
    risk_score: int
    risk_level: str
    auto_approved: str
    status: str
    rejection_reason: str | None
    approver_username: str | None
    required_approvals: int
    created_at: datetime
    approved_at: datetime | None
    expires_at: datetime
    approval_count: int = 0
    my_decision: bool | None = None
class ApprovalDecision(BaseModel):
    approved: bool
    reason: str | None = Field(default=None, max_length=1000)
class ActiveSessionOut(Output):
    id: str
    request_id: str
    user_id: str
    username: str
    aws_account_id: str
    iam_role: str
    issued_at: datetime
    expires_at: datetime
    status: str
    is_demo: bool
    revoked_at: datetime | None
    revoked_by: str | None
class AuditLogOut(Output):
    id: str
    sequence: int
    event_type: str
    actor: str
    target_resource: str
    details: str
    ip_address: str
    risk_score: str
    previous_hash: str
    hash_signature: str
    timestamp: datetime
class PolicyEvaluationResult(BaseModel):
    risk_score: int
    risk_level: str
    auto_approved: bool
    reasons: list[str]
    requires_ticket: bool
    required_approvals: int
class PasswordChange(BaseModel):
    current_password: str
    new_password: str = Field(min_length=12, max_length=128)
class OTP(BaseModel):
    otp: str = Field(pattern=r"^\d{6}$")

class MFASetupRequest(BaseModel):
    current_password: str = Field(min_length=1, max_length=128)

class EntitlementCreate(BaseModel):
    aws_account_id: str = Field(pattern=r"^\d{12}$")
    iam_role: str = Field(pattern=r"^JIT-Access-[A-Za-z0-9_-]+$", max_length=100)
    max_duration_minutes: int = Field(ge=15, le=480)

class AccountRecovery(BaseModel):
    reason: str = Field(min_length=10, max_length=500)
    temporary_password: str | None = Field(default=None, min_length=12, max_length=128)
    reset_mfa: bool = False

class RecoveryCodesRequest(BaseModel):
    current_password: str = Field(max_length=128)
    otp: str = Field(pattern=r"^\d{6}$")

class RolePolicyUpdate(BaseModel):
    max_duration_minutes: int = Field(ge=15, le=480)
    base_risk: int = Field(ge=15, le=100)
    allowed_environments: list[Literal["development", "staging", "production", "security"]] = Field(min_length=1, max_length=4)

from fastapi import HTTPException
from app.models import Entitlement, User, Approval

REQUEST_ROLES = ("REQUESTER", "APPROVER", "SECURITY_ADMIN")
APPROVAL_ROLES = ("APPROVER", "SECURITY_ADMIN")


def assert_entitled(db, user, data):
    if not user.is_active or user.role not in REQUEST_ROLES or user.sessions_revocation_pending or user.must_change_password:
        raise HTTPException(403, "Requester is no longer eligible for AWS access")
    grant = db.get(Entitlement, (user.id, data.aws_account_id, data.iam_role))
    if not grant or data.duration_minutes > grant.max_duration_minutes:
        raise HTTPException(403, "This account, role, or duration is outside your access grants")


def valid_approvals(db, request_id):
    # Any intervening account/security change invalidates the old decision.
    return db.query(Approval).join(User, User.id == Approval.approver_id).filter(
        Approval.request_id == request_id, Approval.approved == 1,
        User.is_active == True, User.role.in_(APPROVAL_ROLES),
        User.sessions_revocation_pending == False, User.must_change_password == False,
        Approval.approver_version == User.token_version)

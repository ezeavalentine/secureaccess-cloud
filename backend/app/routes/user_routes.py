from datetime import datetime
from fastapi import APIRouter, Depends, HTTPException, Request, Query
from sqlalchemy import or_
from app.models import get_db, User, ActiveSession, Entitlement, AccessRequest, Approval
from app.models.database import transaction
from app.schemas import UserOut, UserCreate, UserUpdate, RolePolicyUpdate, EntitlementCreate, AccountRecovery
from app.services import get_current_user, get_password_hash, audit_service, session_service
from app.services.auth_service import require_roles, ip_address
from app.aws import iam_service
from app.config import settings
router = APIRouter(prefix="/users", tags=["Users and Catalog"])
@router.get("", response_model=list[UserOut])
def users(limit: int = Query(25, ge=1, le=200), offset: int = Query(0, ge=0), user=Depends(require_roles("SECURITY_ADMIN", "APPROVER", "AUDITOR")), db=Depends(get_db)):
    return db.query(User).order_by(User.created_at.desc(), User.id).offset(offset).limit(limit).all()
@router.post("", response_model=UserOut)
def create(data: UserCreate, request: Request, user=Depends(require_roles("SECURITY_ADMIN")), db=Depends(get_db)):
    with transaction(db, request=request):
        if db.query(User).filter(or_(User.username == data.username, User.email == str(data.email))).first(): raise HTTPException(409, "Username or email already exists")
        new = User(**data.model_dump(exclude={"password"}), hashed_password=get_password_hash(data.password))
        db.add(new)
        db.flush()
        audit_service.log_event(db, "USER_CREATED", user.username, f"user:{new.id}", {"username": new.username, "role": new.role}, ip_address=ip_address(request))
        result = UserOut.model_validate(new)
    return result
@router.patch("/{user_id}", response_model=UserOut)
def update(user_id: str, data: UserUpdate, request: Request, user=Depends(require_roles("SECURITY_ADMIN")), db=Depends(get_db)):
    with transaction(db, request=request):
        target = db.get(User, user_id)
        if not target: raise HTTPException(404, "User not found")
        if target.id == user.id and (data.is_active is False or data.role not in [None, "SECURITY_ADMIN"]): raise HTTPException(400, "You cannot deactivate or demote your own administrator account")
        needs_revocation = (data.role is not None and data.role != target.role) or data.is_active is False or target.sessions_revocation_pending
        for key, value in data.model_dump(exclude_none=True).items(): setattr(target, key, value)
        target.token_version += 1
        if needs_revocation: target.sessions_revocation_pending = True
        if needs_revocation:
            for req in db.query(AccessRequest).filter_by(user_id=target.id, status="PENDING"):
                req.status, req.rejection_reason = "REJECTED", "Access eligibility changed"
                audit_service.log_event(db, "REQUEST_INVALIDATED", user.username, f"request:{req.id}", {"user_id": target.id}, ip_address=ip_address(request))
        audit_service.log_event(db, "USER_UPDATED", user.username, f"user:{target.id}", data.model_dump(exclude_none=True), ip_address=ip_address(request))
    # Persist the account change and revoke each AWS session independently.
    # A failure cannot undo already-applied IAM denies; pending intent survives
    # and blocks access until the worker successfully retries every session.
    if needs_revocation:
        session_service.revoke_user_sessions(db, user_id, user.username, ip_address(request))
    return UserOut.model_validate(db.get(User, user_id))
@router.get("/roles/catalog")
def roles(user=Depends(get_current_user), db=Depends(get_db)): return iam_service.list_available_roles(db)
@router.get("/accounts/catalog")
def accounts(user=Depends(get_current_user)):
    return [{k: account[k] for k in ["id", "name", "environment"]} for account in settings.accounts()]

@router.patch("/roles/{role_name}")
def update_policy(role_name: str, data: RolePolicyUpdate, request: Request, user=Depends(require_roles("SECURITY_ADMIN")), db=Depends(get_db)):
    import json
    from app.models import RolePolicy
    baseline = iam_service.role(role_name)
    if data.max_duration_minutes > baseline["max_duration_minutes"] or data.base_risk < baseline["base_risk"] or not set(data.allowed_environments).issubset(baseline["allowed_environments"]):
        raise HTTPException(400, "Policies may only tighten the reviewed IAM catalog: shorter TTL, greater risk, or fewer environments")
    with transaction(db, request=request):
        policy = db.get(RolePolicy, role_name)
        if not policy:
            policy = RolePolicy(role_name=role_name)
            db.add(policy)
        policy.max_duration_minutes = data.max_duration_minutes
        policy.base_risk = data.base_risk
        policy.allowed_environments_json = json.dumps(sorted(set(data.allowed_environments)))
        audit_service.log_event(db, "POLICY_UPDATED", user.username, role_name, data.model_dump(), ip_address=ip_address(request))
        db.flush()
        return iam_service.role(role_name, db)

@router.get("/{user_id}/entitlements")
def entitlements(user_id: str, user=Depends(get_current_user), db=Depends(get_db)):
    if user.id != user_id and user.role not in ["SECURITY_ADMIN", "APPROVER", "AUDITOR"]:
        raise HTTPException(404, "User not found")
    return [{"aws_account_id": g.aws_account_id, "iam_role": g.iam_role, "max_duration_minutes": g.max_duration_minutes}
            for g in db.query(Entitlement).filter_by(user_id=user_id).order_by(Entitlement.aws_account_id, Entitlement.iam_role)]

@router.post("/{user_id}/entitlements")
def grant(user_id: str, data: EntitlementCreate, request: Request, user=Depends(require_roles("SECURITY_ADMIN")), db=Depends(get_db)):
    account, role = iam_service.account(data.aws_account_id), iam_service.role(data.iam_role, db)
    if account["environment"] not in role["allowed_environments"] or data.max_duration_minutes > role["max_duration_minutes"]:
        raise HTTPException(400, "Grant exceeds the account/role policy")
    with transaction(db, request=request):
        target = db.get(User, user_id)
        if not target or target.role == "AUDITOR": raise HTTPException(400, "Access grants require a provisioned requester, approver, or administrator")
        item = db.get(Entitlement, (user_id, data.aws_account_id, data.iam_role))
        revoke_existing = bool(item and data.max_duration_minutes < item.max_duration_minutes)
        if not item:
            item = Entitlement(user_id=user_id, **data.model_dump())
            db.add(item)
        else: item.max_duration_minutes = data.max_duration_minutes
        if revoke_existing: target.sessions_revocation_pending = True
        audit_service.log_event(db, "ENTITLEMENT_GRANTED", user.username, f"user:{user_id}", data.model_dump(), ip_address=ip_address(request))
    if revoke_existing: session_service.revoke_user_sessions(db, user_id, user.username, ip_address(request))
    return {"status": "GRANTED"}

@router.post("/{user_id}/entitlements/revoke")
def revoke_grant(user_id: str, data: EntitlementCreate, request: Request, user=Depends(require_roles("SECURITY_ADMIN")), db=Depends(get_db)):
    with transaction(db, request=request):
        target = db.get(User, user_id)
        item = db.get(Entitlement, (user_id, data.aws_account_id, data.iam_role))
        if not target or not item: raise HTTPException(404, "Grant not found")
        db.delete(item)
        target.sessions_revocation_pending = True
        for req in db.query(AccessRequest).filter_by(user_id=user_id, aws_account_id=data.aws_account_id, iam_role=data.iam_role, status="PENDING"):
            req.status, req.rejection_reason = "REJECTED", "Access grant revoked"
        audit_service.log_event(db, "ENTITLEMENT_REVOKED", user.username, f"user:{user_id}", data.model_dump(), ip_address=ip_address(request))
    session_service.revoke_user_sessions(db, user_id, user.username, ip_address(request))
    return {"status": "REVOKED"}

@router.post("/{user_id}/recover", response_model=UserOut)
def recover(user_id: str, data: AccountRecovery, request: Request, user=Depends(require_roles("SECURITY_ADMIN")), db=Depends(get_db)):
    if user_id == user.id: raise HTTPException(400, "Use self-service recovery codes or the local operator recovery command")
    if not data.temporary_password and not data.reset_mfa: raise HTTPException(400, "Choose password or MFA recovery")
    with transaction(db, request=request):
        target = db.get(User, user_id)
        if not target: raise HTTPException(404, "User not found")
        if data.temporary_password:
            target.hashed_password = get_password_hash(data.temporary_password)
            target.must_change_password = True
        if data.reset_mfa:
            target.mfa_enabled, target.mfa_secret, target.last_totp_step = False, None, None
            target.recovery_codes_json = "[]"
        target.token_version += 1
        target.sessions_revocation_pending = True
        audit_service.log_event(db, "ACCOUNT_RECOVERED", user.username, f"user:{user_id}",
            {"reason": data.reason.strip(), "password_reset": bool(data.temporary_password), "mfa_reset": data.reset_mfa}, ip_address=ip_address(request))
    session_service.revoke_user_sessions(db, user_id, user.username, ip_address(request))
    return db.get(User, user_id)

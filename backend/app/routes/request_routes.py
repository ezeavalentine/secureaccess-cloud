from datetime import datetime, timedelta
from fastapi import APIRouter, Depends, HTTPException, Request, Header, Query
from app.models import get_db, AccessRequest, Approval, User, Notification
from app.models.database import transaction
from app.schemas import AccessRequestCreate, AccessRequestOut, PolicyEvaluationResult
from app.services import get_current_user, policy_engine, session_service, audit_service
from app.services.auth_service import require_roles, ip_address
from app.config import settings
from app.services.entitlement_service import assert_entitled, valid_approvals
from sqlalchemy import select
router = APIRouter(prefix="/requests", tags=["Access Requests"])
def output(db, req, user=None):
    data = AccessRequestOut.model_validate(req)
    data.approval_count = valid_approvals(db, req.id).count()
    if user:
        decision = db.query(Approval).filter_by(request_id=req.id, approver_id=user.id, approver_version=user.token_version).first()
        data.my_decision = bool(decision.approved) if decision else None
    return data
@router.post("/evaluate", response_model=PolicyEvaluationResult)
def evaluate(data: AccessRequestCreate, user=Depends(get_current_user), db=Depends(get_db)):
    assert_entitled(db, user, data)
    return policy_engine.evaluate_request(data, db)
@router.post("", response_model=AccessRequestOut)
def create_request(data: AccessRequestCreate, request: Request, key: str = Header(..., alias="Idempotency-Key", min_length=8, max_length=64), user=Depends(require_roles("REQUESTER", "APPROVER", "SECURITY_ADMIN")), db=Depends(get_db)):
    user_id = user.id
    with transaction(db, request=request):
        user = db.get(User, user_id)
        assert_entitled(db, user, data)
        existing = db.query(AccessRequest).filter_by(idempotency_key=f"{user.id}:{key}").first()
        if existing:
            original = {field: getattr(existing, field) for field in AccessRequestCreate.model_fields}
            if original != data.model_dump(): raise HTTPException(409, "Idempotency key was already used with different request data")
            return output(db, existing)
        evaluation = policy_engine.evaluate_request(data, db)
        policy_engine.enforce_ticket(data, evaluation)
        pending = db.query(AccessRequest).filter(AccessRequest.user_id == user.id, AccessRequest.status == "PENDING", AccessRequest.expires_at > datetime.utcnow()).count()
        if pending >= 10: raise HTTPException(429, "Maximum pending requests reached")
        req = AccessRequest(**data.model_dump(), user_id=user.id, username=user.username, risk_score=evaluation.risk_score, risk_level=evaluation.risk_level, auto_approved="TRUE" if evaluation.auto_approved else "FALSE", status="PENDING", required_approvals=evaluation.required_approvals, expires_at=datetime.utcnow() + timedelta(minutes=settings.REQUEST_TTL_MINUTES), idempotency_key=f"{user.id}:{key}")
        db.add(req)
        db.flush()
        audit_service.log_event(db, "ACCESS_REQUESTED", user.username, f"request:{req.id}", {"account_id": req.aws_account_id, "iam_role": req.iam_role, "auto_approved": evaluation.auto_approved, "ticket_ref": req.ticket_ref}, req.risk_level, ip_address(request))
        if evaluation.auto_approved:
            session_service.create_session_from_request(db, req, ip_address(request))
        else:
            for approver in db.query(User).filter(User.role.in_(["APPROVER", "SECURITY_ADMIN"]), User.is_active == True, User.id != user.id).all():
                db.add(Notification(user_id=approver.id, request_id=req.id, message=f"{user.username} requests {req.iam_role} in {req.aws_account_name}; {req.required_approvals} approval(s) required"))
        result = output(db, req)
    return result
@router.get("", response_model=list[AccessRequestOut])
def list_requests(status: str | None = None, limit: int = Query(100, ge=1, le=200), offset: int = Query(0, ge=0), user=Depends(get_current_user), db=Depends(get_db)):
    query = db.query(AccessRequest)
    if user.role == "REQUESTER": query = query.filter_by(user_id=user.id)
    if status: query = query.filter_by(status=status.upper())
    return [output(db, req, user) for req in query.order_by(AccessRequest.created_at.desc(), AccessRequest.id).offset(offset).limit(limit).all()]
@router.get("/{request_id}", response_model=AccessRequestOut)
def get_request(request_id: str, user=Depends(get_current_user), db=Depends(get_db)):
    req = db.get(AccessRequest, request_id)
    if not req or (user.role == "REQUESTER" and req.user_id != user.id): raise HTTPException(404, "Request not found")
    return output(db, req)

@router.post("/{request_id}/cancel", response_model=AccessRequestOut)
def cancel(request_id: str, request: Request, user=Depends(get_current_user), db=Depends(get_db)):
    with transaction(db, request=request):
        req = db.execute(select(AccessRequest).where(AccessRequest.id == request_id).with_for_update()).scalar_one_or_none()
        if not req or req.user_id != user.id: raise HTTPException(404, "Request not found")
        if req.status != "PENDING" or req.expires_at <= datetime.utcnow(): raise HTTPException(409, "Only pending requests can be cancelled")
        req.status, req.rejection_reason = "REJECTED", "Cancelled by requester"
        audit_service.log_event(db, "REQUEST_CANCELLED", user.username, f"request:{req.id}", {}, ip_address=ip_address(request))
        return output(db, req, user)

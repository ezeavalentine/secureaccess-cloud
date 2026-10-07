from datetime import datetime
from fastapi import APIRouter, Depends, Request, Query
from app.models import get_db, AccessRequest, Approval
from app.models.database import transaction
from app.schemas import AccessRequestOut, ApprovalDecision
from app.services import approval_service
from app.services.auth_service import require_roles, ip_address
from app.routes.request_routes import output
router = APIRouter(prefix="/approvals", tags=["Approvals"])
@router.get("/pending", response_model=list[AccessRequestOut])
def pending(limit: int = Query(100, ge=1, le=200), offset: int = Query(0, ge=0), user=Depends(require_roles("APPROVER", "SECURITY_ADMIN")), db=Depends(get_db)):
    decided = db.query(Approval.request_id).filter(Approval.approver_id == user.id, Approval.approver_version == user.token_version)
    return [output(db, req, user) for req in db.query(AccessRequest).filter(AccessRequest.status == "PENDING", AccessRequest.expires_at > datetime.utcnow(), AccessRequest.user_id != user.id, ~AccessRequest.id.in_(decided)).order_by(AccessRequest.created_at, AccessRequest.id).offset(offset).limit(limit).all()]
@router.post("/{request_id}/decide", response_model=AccessRequestOut)
def decide(request_id: str, data: ApprovalDecision, request: Request, user=Depends(require_roles("APPROVER", "SECURITY_ADMIN")), db=Depends(get_db)):
    with transaction(db, request=request):
        updated = approval_service.process_approval(db, request_id, user, data.approved, data.reason, ip_address(request))
        result = output(db, updated)
    return result

from datetime import datetime
import json
from fastapi import APIRouter, Depends, HTTPException, Request, Query
from app.models import get_db, ActiveSession
from app.models.database import transaction
from app.schemas import ActiveSessionOut
from app.services import get_current_user, session_service, audit_service
from app.services.auth_service import require_roles, ip_address
from app.services.crypto import decrypt
from app.aws import sts_service
router = APIRouter(prefix="/sessions", tags=["Sessions"])
@router.get("/active", response_model=list[ActiveSessionOut])
def active(limit: int = Query(100, ge=1, le=200), offset: int = Query(0, ge=0), user=Depends(get_current_user), db=Depends(get_db)):
    query = db.query(ActiveSession).filter(ActiveSession.status == "ACTIVE", ActiveSession.expires_at > datetime.utcnow())
    if user.role == "REQUESTER": query = query.filter_by(user_id=user.id)
    return query.order_by(ActiveSession.expires_at, ActiveSession.id).offset(offset).limit(limit).all()

@router.get("/history", response_model=list[ActiveSessionOut])
def history(limit: int = Query(25, ge=1, le=200), offset: int = Query(0, ge=0), user=Depends(get_current_user), db=Depends(get_db)):
    query = db.query(ActiveSession).filter((ActiveSession.status != "ACTIVE") | (ActiveSession.expires_at <= datetime.utcnow()))
    if user.role == "REQUESTER": query = query.filter_by(user_id=user.id)
    return query.order_by(ActiveSession.issued_at.desc(), ActiveSession.id).offset(offset).limit(limit).all()
def own_session(db, session_id, user):
    session = db.get(ActiveSession, session_id)
    if not session or session.user_id != user.id: raise HTTPException(404, "Session not found")
    return session
@router.post("/{session_id}/credentials")
def credentials(session_id: str, request: Request, user=Depends(require_roles("REQUESTER", "APPROVER", "SECURITY_ADMIN")), db=Depends(get_db)):
    with transaction(db, request=request):
        session = own_session(db, session_id, user)
        result = session_service.credentials(session)
        audit_service.log_event(db, "CREDENTIALS_RETRIEVED", user.username, f"session:{session_id}", {}, ip_address=ip_address(request))
    return result
@router.post("/{session_id}/console")
def console(session_id: str, request: Request, user=Depends(require_roles("REQUESTER", "APPROVER", "SECURITY_ADMIN")), db=Depends(get_db)):
    with transaction(db, request=request):
        session = own_session(db, session_id, user)
        session_service.credentials(session)
        if session.is_demo: raise HTTPException(400, "AWS console access is unavailable in demo mode")
        url = sts_service.console_url(json.loads(decrypt(session.credentials_encrypted)))
        audit_service.log_event(db, "CONSOLE_URL_CREATED", user.username, f"session:{session_id}", {}, ip_address=ip_address(request))
    return {"url": url}
@router.post("/{session_id}/revoke", response_model=ActiveSessionOut)
def revoke(session_id: str, request: Request, user=Depends(get_current_user), db=Depends(get_db)):
    with transaction(db, request=request):
        session = db.get(ActiveSession, session_id)
        if not session: raise HTTPException(404, "Session not found")
        if user.role == "AUDITOR" or (session.user_id != user.id and user.role not in ["SECURITY_ADMIN", "APPROVER"]): raise HTTPException(403, "Insufficient permissions")
        if user.role in ["SECURITY_ADMIN", "APPROVER"]:
            require_roles("SECURITY_ADMIN", "APPROVER")(request, user)
        session = session_service.revoke_session(db, session_id, user.username, ip_address(request))
        result = ActiveSessionOut.model_validate(session)
    return result

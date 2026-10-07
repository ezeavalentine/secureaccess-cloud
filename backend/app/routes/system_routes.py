from datetime import datetime, timezone
from fastapi import APIRouter, Depends, HTTPException, Request
from app.models import get_db, ActiveSession, AccessRequest, Notification, AuditLog, AuditExport, WorkerState
from app.models.database import transaction, read_snapshot
from app.services import get_current_user, audit_service
from app.config import settings
router = APIRouter(tags=["System"])
@router.get("/system/status")
def status(request: Request, user=Depends(get_current_user), db=Depends(get_db)):
    user_id, role, version = user.id, user.role, user.token_version
    with read_snapshot(db):
        sessions = db.query(ActiveSession).filter(ActiveSession.status == "ACTIVE", ActiveSession.expires_at > datetime.utcnow())
        requests = db.query(AccessRequest)
        if role == "REQUESTER":
            sessions, requests = sessions.filter_by(user_id=user_id), requests.filter_by(user_id=user_id)
        state = db.get(WorkerState, 1)
        approvals_count = 0
        if role in ["APPROVER", "SECURITY_ADMIN"]:
            from app.models import Approval
            decided = db.query(Approval.request_id).filter(Approval.approver_id == user_id, Approval.approver_version == version)
            approvals_count = db.query(AccessRequest).filter(AccessRequest.status == "PENDING", AccessRequest.expires_at > datetime.utcnow(), AccessRequest.user_id != user_id, ~AccessRequest.id.in_(decided)).count()
        return {"demo_mode": settings.DEMO_MODE, "aws_region": settings.AWS_REGION, "policy_engine": "ACTIVE",
            "audit_chain": "VALID" if audit_service.verify_chain_integrity(db) else "TAMPER_DETECTED", "audit_records": db.query(AuditLog).count(),
            "archive_configured": bool(settings.AUDIT_DYNAMODB_TABLE), "archive_pending": db.query(AuditExport).filter_by(archived=False).count() if settings.AUDIT_DYNAMODB_TABLE else None,
            "cloudtrail": "DISABLED_DEMO" if settings.DEMO_MODE else "ON_DEMAND", "worker": state.status if state else "UNAVAILABLE",
            "mfa_required": not settings.DEMO_MODE and settings.REQUIRE_APPROVER_MFA, "sso_enabled": bool(settings.OIDC_CLIENT_ID),
            "server_time": datetime.now(timezone.utc).isoformat(), "local_audit_retention": "APPEND_ONLY_NO_AUTOMATIC_DELETION",
            "active_sessions_count": sessions.count(), "requests_count": requests.count(), "pending_approvals_count": approvals_count,
            "email_configured": bool(settings.SMTP_HOST), "ticket_verification_required": not settings.DEMO_MODE and settings.TICKET_VERIFICATION_REQUIRED}
@router.get("/notifications")
def notifications(user=Depends(get_current_user), db=Depends(get_db)):
    return [{"id": n.id, "message": n.message, "request_id": n.request_id, "read": n.read, "created_at": n.created_at.isoformat() + "Z"} for n in db.query(Notification).filter_by(user_id=user.id).order_by(Notification.created_at.desc()).limit(50).all()]
@router.post("/notifications/{notification_id}/read")
def read(notification_id: str, request: Request, user=Depends(get_current_user), db=Depends(get_db)):
    with transaction(db, request=request):
        item = db.get(Notification, notification_id)
        if not item or item.user_id != user.id: raise HTTPException(404, "Notification not found")
        item.read = True
    return {"status": "READ"}

import asyncio
from fastapi import WebSocket, WebSocketDisconnect
from app.services.auth_service import get_current_user

@router.websocket("/events")
async def events(socket: WebSocket, db=Depends(get_db)):
    if socket.headers.get("origin") not in settings.ALLOWED_ORIGINS or not socket.cookies.get("secureaccess_session"):
        await socket.close(code=1008)
        return
    previous = None
    await socket.accept()
    try:
        while True:
            def check():
                db.rollback()
                get_current_user(socket, db)
                from app.models import AuditHead
                return db.get(AuditHead, 1).sequence
            try: signature = await asyncio.to_thread(check)
            except HTTPException:
                await socket.close(code=1008)
                return
            if signature != previous:
                await socket.send_json({"type": "refresh"})
                previous = signature
            try:
                message = await asyncio.wait_for(socket.receive_text(), timeout=10)
                if message != "ping":
                    await socket.close(code=1008)
                    return
            except asyncio.TimeoutError: pass
    except WebSocketDisconnect: pass

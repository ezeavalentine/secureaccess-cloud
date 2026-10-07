import json
from datetime import datetime, timezone
from fastapi import APIRouter, Depends, Query, Response
from app.models import get_db, AuditLog, AuditHead, AuditExport
from app.schemas import AuditLogOut
from app.services import audit_service
from app.services.auth_service import require_roles
from app.aws import cloudtrail_service
from app.models.database import read_snapshot
router = APIRouter(prefix="/audit", tags=["Audit"])
audit_user = require_roles("AUDITOR", "SECURITY_ADMIN", "APPROVER")
@router.get("/logs", response_model=list[AuditLogOut])
def logs(limit: int = Query(50, ge=1, le=200), offset: int = Query(0, ge=0), user=Depends(audit_user), db=Depends(get_db)):
    return db.query(AuditLog).order_by(AuditLog.sequence.desc()).offset(offset).limit(limit).all()
@router.get("/cloudtrail")
def trail(limit: int = Query(15, ge=1, le=50), account_id: str | None = None, user=Depends(audit_user), db=Depends(get_db)):
    return cloudtrail_service.get_recent_trail_events(db, limit, account_id)
@router.get("/verify-chain")
def verify(user=Depends(audit_user), db=Depends(get_db)):
    with read_snapshot(db):
        valid = audit_service.verify_chain_integrity(db)
        return {"status": "VALID" if valid else "TAMPER_DETECTED", "hash_algorithm": "HMAC-SHA256", "verification_timestamp": datetime.now(timezone.utc).isoformat(), "record_count": db.query(AuditLog).count(), "archive": audit_service.verify_external(db)}
@router.get("/export")
def export(user=Depends(audit_user), db=Depends(get_db)):
    from fastapi.responses import StreamingResponse
    def stream():
        with read_snapshot(db):
            valid = audit_service.verify_chain_integrity(db)
            yield '{"algorithm":"HMAC-SHA256","valid":' + json.dumps(valid) + ',"records":['
            first = True
            for row in db.query(AuditLog).order_by(AuditLog.sequence).yield_per(500):
                if not first: yield ','
                first = False
                yield AuditLogOut.model_validate(row).model_dump_json()
            yield ']}'
    return StreamingResponse(stream(), media_type="application/json", headers={"Content-Disposition": 'attachment; filename="secureaccess-audit.json"'})

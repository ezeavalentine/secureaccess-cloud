from datetime import datetime
from sqlalchemy import select
from app.models import AccessRequest, Approval, User, Notification
from app.services.session_service import session_service
from app.services.audit_service import audit_service
from app.services.entitlement_service import assert_entitled, valid_approvals
class ApprovalService:
    def process_approval(self, db, request_id, approver, approved, reason=None, ip="system"):
        req = db.execute(select(AccessRequest).where(AccessRequest.id == request_id).with_for_update()).scalar_one_or_none()
        if not req: raise ValueError("Request not found")
        if req.status != "PENDING" or req.expires_at <= datetime.utcnow(): raise ValueError("Request is not pending or has expired")
        if req.user_id == approver.id: raise ValueError("You cannot approve or reject your own request")
        requester = db.get(User, req.user_id)
        assert_entitled(db, requester, req)
        if not approver.is_active or approver.role not in ["APPROVER", "SECURITY_ADMIN"] or approver.sessions_revocation_pending or approver.must_change_password:
            raise ValueError("Approver is no longer authorized")
        prior = db.query(Approval).filter_by(request_id=req.id, approver_id=approver.id).first()
        if prior and prior.approver_version == approver.token_version: raise ValueError("You have already decided this request")
        if not approved and not (reason or "").strip(): raise ValueError("A rejection reason is required")
        if prior:
            prior.approved, prior.reason, prior.approver_version = int(approved), reason, approver.token_version
            prior.created_at = datetime.utcnow()
        else:
            db.add(Approval(request_id=req.id, approver_id=approver.id, approver_username=approver.username, approver_version=approver.token_version, approved=int(approved), reason=reason))
        db.flush()
        req.approver_username = approver.username
        if approved:
            from app.schemas import AccessRequestCreate
            from app.services.policy_engine import policy_engine
            current = AccessRequestCreate(**{key: getattr(req, key) for key in AccessRequestCreate.model_fields})
            evaluation = policy_engine.evaluate_request(current, db)
            policy_engine.enforce_ticket(current, evaluation)
            req.required_approvals = max(req.required_approvals, evaluation.required_approvals)
            req.risk_score, req.risk_level = evaluation.risk_score, evaluation.risk_level
            count = valid_approvals(db, req.id).count()
            audit_service.log_event(db, "ACCESS_APPROVED", approver.username, f"request:{req.id}", {"approval_count": count, "required_approvals": req.required_approvals}, req.risk_level, ip)
            if count >= req.required_approvals: session_service.create_session_from_request(db, req, ip)
            message = f"Request {req.id[:8]}: {count}/{req.required_approvals} approvals" + ("; credentials ready" if req.status == "APPROVED" else "")
        else:
            req.status, req.rejection_reason = "REJECTED", reason.strip()
            audit_service.log_event(db, "ACCESS_REJECTED", approver.username, f"request:{req.id}", {"reason": reason}, req.risk_level, ip)
            message = f"Request {req.id[:8]} rejected: {reason}"
        db.add(Notification(user_id=req.user_id, request_id=req.id, message=message))
        return req
approval_service = ApprovalService()

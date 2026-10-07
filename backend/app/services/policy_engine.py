import re
from app.schemas import PolicyEvaluationResult
from app.aws.iam_service import iam_service
class PolicyEngine:
    def evaluate_request(self, request_data, db=None):
        account, role = iam_service.validate(request_data, db)
        score = min(100, int(role["base_risk"] * account["risk_multiplier"]) + (15 if request_data.duration_minutes > 240 else 0))
        level = "LOW" if score <= 30 else "MEDIUM" if score <= 60 else "HIGH" if score <= 85 else "CRITICAL"
        auto = level == "LOW" and account["environment"] in ["development", "staging"]
        ticket = level in ["HIGH", "CRITICAL"] or account["environment"] == "production"
        required = 2 if request_data.iam_role == "JIT-Access-AdministratorAccess" or level == "CRITICAL" else 1
        reasons = [f"Trusted account: {account['name']}", f"Risk: {score}/100 ({level})", "Eligible for automatic approval" if auto else f"Requires {required} distinct approver(s)"]
        if ticket: reasons.append("A Jira-style or ServiceNow incident reference is required")
        return PolicyEvaluationResult(risk_score=score, risk_level=level, auto_approved=auto, requires_ticket=ticket, required_approvals=0 if auto else required, reasons=reasons)
    def enforce_ticket(self, request, evaluation):
        if evaluation.requires_ticket and not re.fullmatch(r"(?:[A-Z][A-Z0-9]{1,15}-[0-9]+|INC[0-9]{5,15})", request.ticket_ref or ""):
            raise ValueError("Supply a valid Jira reference (SEC-123) or ServiceNow incident (INC123456)")
        if evaluation.requires_ticket:
            from app.services.ticket_service import verify_ticket
            verify_ticket(request.ticket_ref)
policy_engine = PolicyEngine()

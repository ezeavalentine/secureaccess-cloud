from app.config import settings
DEFAULT_ROLE_CATALOG = [
    {"role_name": "JIT-Access-ReadOnly", "description": "Read-only inspection", "allowed_environments": ["development", "staging", "production", "security"], "max_duration_minutes": 480, "default_risk": "LOW", "base_risk": 15},
    {"role_name": "JIT-Access-PowerUser", "description": "Engineering deployments, without IAM or role chaining", "allowed_environments": ["development", "staging"], "max_duration_minutes": 240, "default_risk": "MEDIUM", "base_risk": 40},
    {"role_name": "JIT-Access-DBAdmin", "description": "Database maintenance", "allowed_environments": ["staging", "production"], "max_duration_minutes": 120, "default_risk": "HIGH", "base_risk": 70},
    {"role_name": "JIT-Access-AdministratorAccess", "description": "Elevated operations within the JIT permission boundary; two distinct approvals", "allowed_environments": ["development", "staging", "production", "security"], "max_duration_minutes": 60, "default_risk": "CRITICAL", "base_risk": 90},
]
class IAMService:
    def list_available_roles(self, db=None):
        import json
        from app.models import RolePolicy
        roles = [dict(r) for r in DEFAULT_ROLE_CATALOG]
        if db:
            for role in roles:
                policy = db.get(RolePolicy, role["role_name"])
                if policy:
                    role.update(max_duration_minutes=policy.max_duration_minutes, base_risk=policy.base_risk, allowed_environments=json.loads(policy.allowed_environments_json))
        if not settings.DEMO_MODE:
            for role in roles:
                role["max_duration_minutes"] = min(role["max_duration_minutes"], settings.LIVE_MAX_DURATION_MINUTES)
        return roles
    def validate_role_exists(self, role_name): return any(r["role_name"] == role_name for r in DEFAULT_ROLE_CATALOG)
    def account(self, account_id):
        account = next((a for a in settings.accounts() if a["id"] == account_id), None)
        if not account: raise ValueError("Account is not in the trusted account catalog")
        return account
    def role(self, role_name, db=None):
        role = next((r for r in self.list_available_roles(db) if r["role_name"] == role_name), None)
        if not role: raise ValueError("Role is not in the JIT role catalog")
        return role
    def validate(self, request, db=None):
        account, role = self.account(request.aws_account_id), self.role(request.iam_role, db)
        if request.aws_account_name != account["name"]: raise ValueError("Account ID and name do not match")
        if account["environment"] not in role["allowed_environments"]: raise ValueError("Role is not allowed in this account")
        if request.duration_minutes > role["max_duration_minutes"]: raise ValueError(f"Maximum duration for this role is {role['max_duration_minutes']} minutes")
        return account, role
iam_service = IAMService()

import json
import os
import secrets
from pathlib import Path
from cryptography.fernet import Fernet
from pydantic_settings import BaseSettings, SettingsConfigDict

DATA_DIR = Path(__file__).resolve().parents[1] / "data"

class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")
    PROJECT_NAME: str = "SecureAccess Cloud"
    VERSION: str = "2.0.0"
    API_PREFIX: str = "/api"
    APP_ENV: str = "development"
    DEMO_MODE: bool = True
    SECRET_KEY: str = ""
    ENCRYPTION_KEY: str = ""
    AUDIT_HMAC_KEY: str = ""
    DATABASE_URL: str = f"sqlite:///{DATA_DIR / 'secureaccess.db'}"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 30
    COOKIE_SECURE: bool = False
    ALLOWED_ORIGINS: list[str] = ["http://localhost:3000", "http://127.0.0.1:3000"]
    AWS_REGION: str = "us-east-1"
    AWS_EXTERNAL_ID: str = ""
    AWS_ORCHESTRATOR_ARN: str = ""
    AWS_ACCOUNTS_JSON: str = ""
    AUDIT_DYNAMODB_TABLE: str = ""
    MAX_ACTIVE_SESSIONS_PER_USER: int = 3
    MAX_SESSIONS_PER_ROLE: int = 5
    REQUEST_TTL_MINUTES: int = 60
    AUDIT_RETENTION_DAYS: int = 365
    OIDC_CLIENT_ID: str = ""
    OIDC_CLIENT_SECRET: str = ""
    OIDC_DISCOVERY_URL: str = ""
    PUBLIC_URL: str = "http://localhost:3000"
    REQUIRE_APPROVER_MFA: bool = True
    # ECS role credentials chain into target roles; AWS caps these at one hour.
    LIVE_MAX_DURATION_MINUTES: int = 60
    TRUSTED_PROXY_CIDRS: list[str] = ["127.0.0.1/32", "::1/128"]
    CLOUDTRAIL_REGIONS: list[str] = []
    CLOUDTRAIL_MAX_PAGES: int = 20
    TICKET_VERIFICATION_REQUIRED: bool = True
    JIRA_URL: str = ""
    JIRA_USERNAME: str = ""
    JIRA_TOKEN: str = ""
    SERVICENOW_URL: str = ""
    SERVICENOW_USERNAME: str = ""
    SERVICENOW_PASSWORD: str = ""
    SMTP_HOST: str = ""
    SMTP_PORT: int = 587
    SMTP_USERNAME: str = ""
    SMTP_PASSWORD: str = ""
    SMTP_FROM: str = ""
    SMTP_STARTTLS: bool = True
    WORKER_MODE: str = "embedded"
    AUTO_MIGRATE: bool = True

    def initialize_keys(self):
        import ipaddress
        from urllib.parse import urlparse
        if self.APP_ENV not in ["development", "test", "production"]:
            raise RuntimeError("APP_ENV must be development, test, or production")
        if not 15 <= self.LIVE_MAX_DURATION_MINUTES <= 60:
            raise RuntimeError("Live duration must be between 15 and 60 minutes")
        if self.WORKER_MODE not in ["embedded", "external"]:
            raise RuntimeError("WORKER_MODE must be embedded or external")
        for cidr in self.TRUSTED_PROXY_CIDRS: ipaddress.ip_network(cidr)
        for url in [self.JIRA_URL, self.SERVICENOW_URL, self.OIDC_DISCOVERY_URL]:
            if url and (urlparse(url).scheme != "https" or not urlparse(url).hostname):
                raise RuntimeError("Identity and ticket providers require HTTPS URLs")
        if self.SMTP_HOST and (not self.SMTP_FROM or not self.SMTP_STARTTLS):
            raise RuntimeError("Email requires SMTP_FROM and STARTTLS")
        if not 1 <= self.CLOUDTRAIL_MAX_PAGES <= 100:
            raise RuntimeError("CloudTrail page budget must be between 1 and 100")
        if self.APP_ENV == "production":
            if self.DEMO_MODE or not self.COOKIE_SECURE:
                raise RuntimeError("Production requires DEMO_MODE=false and COOKIE_SECURE=true")
            if not all([self.SECRET_KEY, self.ENCRYPTION_KEY, self.AUDIT_HMAC_KEY, self.AWS_ACCOUNTS_JSON, self.AWS_EXTERNAL_ID]):
                raise RuntimeError("Production requires explicit keys and AWS account configuration")
            if len(self.SECRET_KEY) < 32 or len(self.AUDIT_HMAC_KEY) < 32:
                raise RuntimeError("Signing keys must contain at least 32 characters")
            if self.SECRET_KEY == self.AUDIT_HMAC_KEY:
                raise RuntimeError("Authentication and audit signing keys must be independent")
            if not self.PUBLIC_URL.startswith("https://") or any(not o.startswith("https://") for o in self.ALLOWED_ORIGINS):
                raise RuntimeError("Production requires HTTPS public URL and origins")
            if self.TICKET_VERIFICATION_REQUIRED and not (self.JIRA_URL or self.SERVICENOW_URL):
                raise RuntimeError("Configure a ticket provider or explicitly disable ticket verification")
            if not self.AWS_ORCHESTRATOR_ARN:
                raise RuntimeError("Production requires the trusted AWS_ORCHESTRATOR_ARN")
            if self.AUDIT_DYNAMODB_TABLE != "secureaccess_audit_logs":
                raise RuntimeError("Production requires the protected secureaccess_audit_logs archive")
        else:
            DATA_DIR.mkdir(parents=True, exist_ok=True, mode=0o700)
            path = DATA_DIR / "local-keys.json"
            if not path.exists():
                keys = {"SECRET_KEY": secrets.token_urlsafe(48), "AUDIT_HMAC_KEY": secrets.token_urlsafe(48), "ENCRYPTION_KEY": Fernet.generate_key().decode()}
                try:
                    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
                    with os.fdopen(fd, "w") as f: json.dump(keys, f)
                except FileExistsError: pass
            keys = json.loads(path.read_text())
            for name, value in keys.items():
                if not getattr(self, name): setattr(self, name, value)
        Fernet(self.ENCRYPTION_KEY.encode())
        import re
        accounts = self.accounts()
        if len({a.get("id") for a in accounts}) != len(accounts) or len({a.get("name") for a in accounts}) != len(accounts):
            raise RuntimeError("AWS account IDs and names must be unique")
        for account in accounts:
            if not re.fullmatch(r"\d{12}", account.get("id", "")) or not account.get("name") or account.get("environment") not in ["development", "staging", "production", "security"] or not 1 <= float(account.get("risk_multiplier", 0)) <= 3:
                raise RuntimeError("Invalid trusted AWS account configuration")
        if self.APP_ENV == "production" and self.DATABASE_URL.startswith("sqlite"):
            raise RuntimeError("Production requires a durable PostgreSQL database")
        if self.OIDC_CLIENT_ID and not all([self.OIDC_CLIENT_SECRET, self.OIDC_DISCOVERY_URL]):
            raise RuntimeError("SSO requires client secret and discovery URL")
        if not self.DEMO_MODE and not self.AWS_ACCOUNTS_JSON:
            raise RuntimeError("Live AWS mode requires AWS_ACCOUNTS_JSON")
        if self.JIRA_URL and not (self.JIRA_USERNAME and self.JIRA_TOKEN):
            raise RuntimeError("Jira requires username and API token")
        if self.SERVICENOW_URL and not (self.SERVICENOW_USERNAME and self.SERVICENOW_PASSWORD):
            raise RuntimeError("ServiceNow requires credentials")

    def accounts(self):
        if self.AWS_ACCOUNTS_JSON:
            return json.loads(self.AWS_ACCOUNTS_JSON)
        if not self.DEMO_MODE: return []
        return [
            {"id": "123456789012", "name": "Dev-Sandbox", "environment": "development", "risk_multiplier": 1.0},
            {"id": "987654321098", "name": "Staging-EU", "environment": "staging", "risk_multiplier": 1.2},
            {"id": "555444333222", "name": "Prod-US-East-1", "environment": "production", "risk_multiplier": 1.5},
            {"id": "111222333444", "name": "Security-Audit", "environment": "security", "risk_multiplier": 1.3},
        ]
settings = Settings()

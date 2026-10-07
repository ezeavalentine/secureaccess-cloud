# Deployment and local operations

## Local demo

Follow README.md for Python 3.14 and Node 22.12+ setup or Docker Compose.
No AWS connection is required for DEMO_MODE=true. Do not expose the demo publicly:
its four seed accounts use the documented shared demo password.

Startup normally applies migrations, seeds explicit demo grants once, verifies the
audit chain, and starts an embedded worker. To migrate explicitly from backend/:

```bash
.venv/bin/python manage.py migrate
.venv/bin/python manage.py verify-audit
```

Back up existing data and local-keys.json before migrations. SQLite backup:

```bash
.venv/bin/python manage.py backup /path/to/protected-backup.db
```

Protect a copy of backend/data/local-keys.json separately with mode 0600. The
operator CLI also supports create-admin, grant-access and recover-user; consult
its --help. Never commit database files, keys, .env files or Terraform state.

## Tests

Run backend pytest from backend/. PostgreSQL tests require TEST_POSTGRES_URL
pointing to a disposable database where schemas may be created/deleted. Browser
tests require Chromium and its system libraries; installation can require sudo.
PLAYWRIGHT_WS_ENDPOINT can connect tests to a compatible remote Playwright browser
server; keep it local/private. BACKEND_PYTHON overrides the backend interpreter.
Browser tests start temporary servers and an isolated SQLite database.

## Production prerequisites

The supplied Terraform is an optional starting point, not a complete deployment.
Provide a VPC, subnets with outbound AWS/provider connectivity, PostgreSQL,
Secrets Manager configuration, reviewed IAM trusts/boundaries, TLS certificate,
DNS/public HTTPS URL and container images. Configure backend/.env.example settings
through a secret manager. Apply target role/trust resources in each target account.

Production requires DEMO_MODE=false, COOKIE_SECURE=true, independent signing/audit
keys, a Fernet encryption key, explicit account configuration, external ID, broker
ARN, PostgreSQL and the protected secureaccess_audit_logs DynamoDB table.
Required tickets need Jira/ServiceNow configuration unless verification is explicitly
disabled. OIDC and SMTP are optional. Use immutable container image digests.

For multiple API processes, migrate once, set AUTO_MIGRATE=false and
WORKER_MODE=external, and run python -m app.worker separately. /api/health is liveness;
/api/ready verifies database/audit integrity and worker freshness. Extremely long
worker cycles and AWS/SQL failure reconciliation still need further hardening.

Create the first live administrator with manage.py create-admin and enroll MFA.
Use identity-verified admin/operator recovery if locked out. Establish alarms,
PostgreSQL backups, protected key backups, restore drills and key-rotation procedures
before deployment. These operations are not fully automated by this repository.

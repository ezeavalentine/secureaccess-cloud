# SecureAccess Cloud

SecureAccess Cloud brokers time-bound AWS access through reviewed account/role grants, policy evaluation, distinct approvals, STS credentials, and tamper-evident audit records. The default local demo simulates AWS credentials and cannot access AWS.

## Architecture

- React 18/Vite frontend with Axios, state-based navigation, paginated tables, and WebSocket change signals with polling fallback.
- FastAPI backend with Pydantic validation, SQLAlchemy, and Alembic migrations.
- SQLite for local demos; PostgreSQL for production.
- AWS STS issuance, IAM session-scoped deny policies, CloudTrail correlation, and a DynamoDB audit archive.
- An embedded worker by default; a separate leased worker is available for production deployments.

## Local setup

Use Python 3.14 and Node 22.12 or newer. Run from the project root:

```bash
python3 -m venv backend/.venv
backend/.venv/bin/python -m pip install -r backend/requirements-dev.txt
cd backend
.venv/bin/python -m uvicorn app.main:app --reload --port 8000
```

In another terminal:

```bash
cd frontend
npm ci
npm run dev
```

Open http://localhost:3000. The frontend proxies `/api` and `/api/events` to the backend. API documentation is at http://localhost:8000/docs.

Startup migrates the database, seeds demo identities and their explicit demo grants, verifies the audit chain, and starts the worker. Back up an existing database and its keys before upgrading. Revoked demo grants are not recreated on restart.

Demo users all use `Password123!`:

| User | Role |
|---|---|
| `alex.dev` | REQUESTER |
| `sarah.sec` | APPROVER |
| `admin.sys` | SECURITY_ADMIN |
| `audit.user` | AUDITOR |

New users have **no AWS access grants** until an administrator grants an account, role, and maximum duration. Approvers and administrators can request access only within their own grants.

## Containers

With the Docker Compose plugin installed:

```bash
docker compose up --build
```

Frontend and backend are bound to loopback ports 3000 and 8000. SQLite and local keys persist in the backend volume. Both images run without root privileges. `/api/health` is liveness; `/api/ready` checks the database, audit chain, and recent worker heartbeat.

## Tests

```bash
cd backend
.venv/bin/python -m pytest -q
```

PostgreSQL integration is enabled with `TEST_POSTGRES_URL` pointing to a disposable PostgreSQL database. The tests create and remove an isolated schema; never point this setting at production.

```bash
cd frontend
npx playwright install --with-deps chromium
npm test
npm run build
```

Playwright starts isolated servers on ports 8001/3001 and uses a unique temporary SQLite database. Set `BACKEND_PYTHON` if the backend environment is elsewhere. `PLAYWRIGHT_WS_ENDPOINT` optionally connects to a compatible remote browser server.

If installing Chromium's host libraries requires unavailable sudo access, use a
local Docker browser instead. After `npm ci`, run from the project root in one terminal:

```bash
docker run --rm --name secureaccess-test-browser --network host --ipc host \
  --user "$(id -u):$(id -g)" -v "$PWD/frontend:/work:ro" -w /work \
  --entrypoint node mcr.microsoft.com/playwright:v1.63.0-noble \
  node_modules/playwright/cli.js run-server --host 127.0.0.1 --port 3333
```

In another terminal:

```bash
cd frontend
PLAYWRIGHT_WS_ENDPOINT=ws://127.0.0.1:3333/ npm test
```

This example uses Linux host networking. Keep the browser server on loopback and
match the image version to the installed Playwright version. Stop it with Ctrl+C
after testing. MFA enrollment now requires the user's current password. Recovered
users must change their temporary password before accessing application data.

## Production

See [deployment and operations](docs/deployment.md), [architecture](docs/architecture.md), [database design](docs/database-design.md), [API reference](docs/api-reference.md), and [security tests](docs/security-test-plan.md).

Production requires HTTPS, independent signing/encryption keys, PostgreSQL, reviewed target-account trusts and permission boundaries, an explicit broker ARN, and the protected DynamoDB audit table. Live sessions are capped at 60 minutes because the ECS broker assumes target roles using role chaining.

Configure Jira and/or ServiceNow to verify required ticket references. An explicit `TICKET_VERIFICATION_REQUIRED=false` disables provider verification; ticket syntax is still enforced. OIDC and STARTTLS SMTP are optional and need their respective provider credentials. SMTP notifications contain only a sign-in link, never AWS credentials or request details.

The application has no public password-reset link. Security administrators perform identity-verified recovery; users save one-time MFA recovery codes. The local operator CLI supports recovery when all administrators are locked out.

Audit records are append-only and HMAC chained. An external archive adds deletion detection, but DynamoDB is not an object-lock/WORM service. CloudTrail S3 logs use compliance Object Lock in the supplied Terraform. AWS deny propagation and CloudTrail delivery are asynchronous; console/API integration must be validated against your own AWS and identity providers before deployment.

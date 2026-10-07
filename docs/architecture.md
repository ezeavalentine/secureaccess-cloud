# SecureAccess Cloud architecture

SecureAccess Cloud is an AWS just-in-time access broker. The default local demo
uses deliberately invalid credentials and makes no AWS calls for session issuance.

## Components

- React 18/Vite SPA: hook-based state, state-based navigation, Axios requests,
  WebSocket refresh signals, and polling every ten seconds.
- FastAPI/Uvicorn API: Pydantic validation, SQLAlchemy persistence, Alembic migrations.
- SQLite for local development; PostgreSQL with Psycopg for production.
- Embedded or external worker: expiration, revocation retries, audit archival,
  notification email delivery, and rate-bucket cleanup.
- Optional integrations: AWS STS/IAM/CloudTrail/DynamoDB, OIDC, Jira, ServiceNow,
  and STARTTLS SMTP. Integration code does not establish live-provider compatibility.

## Access lifecycle

1. An administrator grants a user an account, catalog role, and maximum duration.
2. The requester submits justification and an idempotency key to POST /api/requests.
3. The API checks grants, catalog constraints, and risk. Risk is the role base risk
   multiplied by account risk, plus 15 for durations over 240 minutes, capped at 100.
4. Low risk (up to 30) in development/staging is automatically approved. Other
   requests need one approval; AdministratorAccess or critical risk needs two
   distinct approvers. This does not require distinct organizational job roles.
5. Production or high/critical requests require a ticket. Configured live providers
   verify that required tickets are open unless verification is explicitly disabled.
6. Manual decisions use POST /api/approvals/{request_id}/decide. Self-decisions are
   rejected. Grants, policies, tickets, and approver eligibility are checked again.
7. A successful decision creates a session. Credentials are retrieved separately
   by its owner; they are not returned in request/session list responses.
8. Live STS calls include external ID, source identity, request tags, and a restrictive
   session policy. Live duration is capped at 60 minutes for role chaining.
9. Expiration removes stored credentials. Live revocation attaches an IAM explicit
   deny scoped to the assumed-role ID through aws:userid. Propagation is asynchronous.

## Identity and audit

Passwords use Argon2. Application tokens use HS256 JWTs in HttpOnly cookies,
with token-version invalidation, optional TOTP, and hashed single-use recovery codes.
Live approvers/admins require MFA for privileged actions by default. Initial MFA
setup also requires the current password. Temporary-password users can access only
identity, password-change, and logout endpoints until they change their password.

Audit records are HMAC-SHA256 chained over canonical event fields, previous hash,
sequence, and timestamp. Database triggers prohibit updates and deletes. A configured
DynamoDB archive adds comparison against an external copy, but is not WORM storage.
Browser credentials are cleared from application state; secure memory zeroing or
clearing credentials already copied to a clipboard/terminal is not guaranteed.

## Operational limits

Worker lease acquisition and cancellation lock rows on PostgreSQL. SQLite serializes
writes. A lease is time-limited; extremely long worker cycles require further lease
renewal/fencing work. AWS effects and SQL commits are not atomic; durable reconciliation
is still required before claiming resilience to every network/database failure.
Readiness verifies the full local audit chain, which becomes costly for large histories.
See deployment.md for setup and api-reference.md for routes.

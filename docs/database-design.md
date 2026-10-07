# Database design

SQLAlchemy models live in backend/app/models. Alembic migrations 0001 through 0005
are the schema source of truth. Local development defaults to
backend/data/secureaccess.db; Docker stores it in the backend_data volume.
Production requires PostgreSQL. DynamoDB is an optional external audit archive,
not the primary application database.

| Table | Purpose |
| --- | --- |
| users | Identity, Argon2 password hash, role, token version, encrypted MFA secret, hashed recovery codes, recovery/revocation flags |
| entitlements | Composite key of user/account/role with maximum permitted duration |
| access_requests | Request context, risk, status, required approvals, expiry, user-scoped idempotency key |
| approvals | Unique request/approver decision and the approver token version when recorded |
| active_sessions | One session per request; encrypted credential bundle, assumed-role identity, expiry, revocation metadata |
| role_policies | Restrictive overrides of the reviewed role catalog |
| audit_logs | Ordered HMAC-chained audit events |
| audit_head | Singleton sequence/signature checkpoint |
| audit_exports | Archive delivery tracking for each audit event |
| notifications | User inbox and email retry/delivery state |
| worker_state | Singleton worker owner, lease, status and heartbeat |
| rate_buckets | Shared sliding-window rate limits keyed by hashed identity/category |
| alembic_version | Applied migration revision |

Foreign keys and uniqueness/check constraints protect identity and workflow links.
SQLite enables foreign keys and a 30-second busy timeout. SQLite transactions use
BEGIN IMMEDIATE; PostgreSQL uses row/advisory locks. Audit UPDATE/DELETE triggers
exist on both databases. Privileged database operators can bypass those controls.

All three AWS credential values are encrypted together with Fernet. MFA secrets
also use Fernet; passwords and recovery codes use Argon2. Audit signatures use
an independent HMAC key over canonical JSON, including the previous signature.
Timestamps are stored as naive UTC and serialized as UTC for API responses.

Local audit records are not automatically deleted. Downgrades are deliberately
rejected. Legacy databases without the Alembic schema need an explicit migration
plan rather than automatic destructive conversion. Back up the database and its
signing/encryption keys together before upgrades; protect keys separately from
ordinary database backups.

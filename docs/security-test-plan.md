# Security validation

Automated checks live in backend/tests and frontend/tests. Run them as described
in README.md; their existence is not evidence that live integrations are validated.

## Implemented automated coverage

- Credential rejection, HttpOnly cookies, logout/token invalidation, CSRF and RBAC.
- Owner-only request/credential access, explicit grants and trusted catalog validation.
- Risk evaluation, ticket syntax, distinct approvals and rejection reasons.
- Idempotency, concurrent decisions, capacity limits, expiration and revocation.
- Encrypted credentials, audit signatures and database append-only enforcement.
- MFA enrollment/replay, password reauthentication for setup, single-use recovery codes.
- Temporary-password restrictions, account recovery and revocation retries.
- IP and account login throttling, trusted proxy handling, WebSocket authentication.
- Readiness with running/stale workers and exclusion of competing worker owners.
- SQLite migration preservation and optional PostgreSQL workflow/concurrency checks.
- Browser sign-in/restore, requests, credentials, revocation, administration,
  two-person approval, MFA setup and forced-password-change navigation.

AWS contract tests use stubs/captures. They do not demonstrate real STS permissions,
console federation, IAM deny propagation, CloudTrail delivery or archive durability.

## Required live validation before production

Use dedicated sandbox accounts and reviewed target trusts/boundaries. Verify
issuance, owner credentials, console access, deny propagation, expiry/cleanup,
CloudTrail correlation, DynamoDB archive recovery and provider outages.
Validate OIDC identity matching and MFA, ticket provider responses, SMTP retries,
PostgreSQL recovery and database/key restore. Test failures between AWS operations
and SQL commits: durable reconciliation for those windows remains outstanding.

JWTs use HS256, not RSA signatures. React state cleanup is not secure memory zeroing.
DynamoDB is not WORM storage. Broad role boundaries require a separate threat review;
this project does not establish an unconditional zero-trust security guarantee.

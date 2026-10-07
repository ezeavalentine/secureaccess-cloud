# API reference

The API prefix is /api. /docs, /redoc and /openapi.json expose FastAPI's detailed
schemas. Authentication uses the secureaccess_session HttpOnly cookie; bearer
JWTs are also accepted. Mutation requests require X-SecureAccess-CSRF: 1, and
browser origins must be allowed. Access request creation additionally requires
an Idempotency-Key (8–64 characters).

| Method | Path | Purpose |
| --- | --- | --- |
| POST | /auth/login | Username/password and optional MFA/recovery code |
| GET | /auth/me | Current identity |
| POST | /auth/logout | Invalidate login tokens; existing AWS sessions remain until revoked/expired |
| POST | /auth/password | Change password, invalidate tokens and revoke AWS sessions |
| POST | /auth/mfa/setup | Start enrollment; current_password required |
| POST | /auth/mfa/enable | Confirm enrollment OTP; return recovery codes once |
| POST | /auth/mfa/verify | Verify fresh OTP for this login session |
| POST | /auth/mfa/recovery-codes | Rotate codes with current_password and fresh otp |
| GET | /auth/sso | Start configured OIDC sign-in |
| GET | /auth/sso/callback | OIDC callback |
| POST | /requests/evaluate | Preview entitled request risk |
| POST | /requests | Submit request |
| GET | /requests | List requests |
| GET | /requests/{request_id} | Request detail |
| POST | /requests/{request_id}/cancel | Cancel an owned pending request |
| GET | /approvals/pending | Undecided eligible queue |
| POST | /approvals/{request_id}/decide | approved boolean and optional reason; rejection needs reason |
| GET | /sessions/active | Active unexpired sessions |
| GET | /sessions/history | Expired/revoked sessions |
| POST | /sessions/{session_id}/credentials | Owner-only decrypted credentials |
| POST | /sessions/{session_id}/console | Owner-only live console federation |
| POST | /sessions/{session_id}/revoke | Revoke owned session, or privileged session revocation |
| GET | /audit/logs | Paginated internal audit |
| GET | /audit/cloudtrail | Correlated recent management events |
| GET | /audit/verify-chain | Local chain and configured archive verification |
| GET | /audit/export | Complete JSON audit export |
| GET, POST | /users | List or provision users |
| PATCH | /users/{user_id} | Change role, active status or department |
| GET | /users/roles/catalog | Reviewed catalog with restrictive policy overrides |
| GET | /users/accounts/catalog | Trusted account catalog |
| PATCH | /users/roles/{role_name} | Update restrictive role policy |
| GET, POST | /users/{user_id}/entitlements | Inspect or grant access |
| POST | /users/{user_id}/entitlements/revoke | Remove grant and revoke user sessions |
| POST | /users/{user_id}/recover | Identity-verified password/MFA recovery |
| GET | /system/status | Authenticated overview |
| GET | /notifications | Latest 50 own notifications |
| POST | /notifications/{notification_id}/read | Mark owned notification read |
| WebSocket | /events | Cookie/origin-authenticated refresh signals |
| GET | /health | Public liveness and mode |
| GET | /ready | Public database/audit/worker readiness |

GET / outside the prefix returns service information. Many list endpoints support
limit and offset; consult OpenAPI for bounds. Requesters see only their own request
and session records. Credential retrieval always requires ownership. Approver/admin
actions require their role and, in live mode, MFA by default. Auditors cannot request
credentials. User, grant, policy and recovery mutations require SECURITY_ADMIN.
Temporary-password users are restricted to /auth/me, /auth/password and /auth/logout.

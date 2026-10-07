# SecureAccess Cloud — Project demonstration and screenshot guide

Prepared against the existing application on 5 October 2026. The UI and authentication/authorization architecture are preserved. All application pages use **http://127.0.0.1:3000/** and state-based sidebar navigation. There are no implemented `/login`, `/dashboard`, or `/approvals` frontend routes. Reloading normally returns to Dashboard. Use different browser profiles for simultaneous accounts, not two tabs sharing the same cookies.

## Verified accounts

| Display name | Username | Application role | Verified demo password | MFA |
|---|---|---|---|---|
| Ebuka Rivera | alex.dev | REQUESTER | Password123! | Unchanged; disabled |
| Amara Chen | sarah.sec | APPROVER | Password123! | Unchanged; disabled |
| System Administrator | admin.sys | SECURITY_ADMIN | Password123! | Unchanged; disabled |
| Audit Lead | audit.user | AUDITOR | Password123! | Unchanged; disabled |
| Chika Joseph (stored with two spaces) | Chika | APPROVER | Unknown; stored hash only, not reset | Unchanged; disabled |
| Project Security Demonstrator | demo.security | REQUESTER | Demo-project-123! | Enabled via supported enrollment |

The first four passwords were verified by successful API and browser login, not merely inferred from seed data. Use usernames, not emails, at login. Ebuka's and Amara's surnames were retained because the requested changes concerned their first names. Display names appear in user management; existing request/session identifiers continue to display the unchanged usernames.

The separate demo.security account was created through `POST /api/users`. Its authenticator key, enrollment URI and remaining recovery codes are stored privately at `/tmp/secureaccess-demo-mfa-private.json` (mode 0600). Import the URI/key into an authenticator; use a current code. Do not include the private file in your dissertation or screenshots. An authenticator code cannot be reused within the same 30-second step. The file is temporary; save it securely yourself if you need it after cleanup/reboot. Rotating or resetting MFA makes this saved material stale.

## Existing roles and exact implemented authority

| Role | Pages | Allowed actions | Forbidden actions |
|---|---|---|---|
| REQUESTER | Dashboard; Access Requests; Active JIT Sessions; Account Security | Own requests and sessions/history; request/evaluate granted account-role-duration combinations; cancel own pending request; retrieve own active credentials; revoke own session; own MFA, recovery-code rotation, password change, notifications, logout | Approval decisions/inbox; audit APIs; user listing/administration; other users' requests; other users' credentials or session revocation; ungranted access |
| APPROVER | All requester pages; Approvals Inbox; Audit Trail & Compliance; User & Policy Management (read-only) | Global request/session/history visibility; approve or reject someone else's eligible request; revoke global sessions; read users/catalog/grants; view/verify/export audit; own granted requests and credentials | Self-approval/rejection; count the same person twice; issue critical administrator access after only one approval; provision/update/recover users; change policies or grants; retrieve someone else's credentials |
| SECURITY_ADMIN | All pages | Approver actions plus provision users; change role/department/active status; recover other accounts; grant/revoke entitlements; tighten catalog policies; request own granted access | Approve own request; count one person as two; retrieve others' credentials; deactivate/demote self; bypass grants, tickets, time bounds, capacities, reviewed policy baseline or pending revocation |
| AUDITOR | Dashboard; Access Requests; Active JIT Sessions; Audit Trail & Compliance; User & Policy Management (read-only); Account Security | Global read visibility; audit verification/export; own authentication/MFA/password/notifications | Create/evaluate AWS access requests; approvals; retrieve credentials; revoke sessions; user/grant/policy mutation or recovery |

All dashboards are the same Access overview component with role-specific controls and data scope, not four independently routed dashboards. Application roles control broker authority; AWS JIT roles control target permission scope. Approvers/admins still require their own AWS entitlements. Live-mode approver/admin privileged APIs require verified MFA; demo mode does not enforce this requirement. MFA-enabled accounts still require MFA at sign-in in demo mode.

## Reviewed target catalog

| AWS role | Scope described by the reviewed catalog | Environments | Demo maximum minutes | Base risk |
|---|---|---|---:|---:|
| JIT-Access-ReadOnly | Read-only inspection | development, staging, production, security | 480 | 15 |
| JIT-Access-PowerUser | Engineering deployment without IAM or role chaining | development, staging | 240 | 40 |
| JIT-Access-DBAdmin | Database maintenance | staging, production | 120 | 70 |
| JIT-Access-AdministratorAccess | Elevated operations within a permission boundary; two distinct approvals | development, staging, production, security | 60 | 90 |

Accounts: Dev-Sandbox `123456789012` (risk multiplier 1.0), Staging-EU `987654321098` (1.2), Prod-US-East-1 `555444333222` (1.5), Security-Audit `111222333444` (1.3). These are demo catalog entries, not verified real AWS resources.

Risk = min(100, integer base-risk × account multiplier + 15 when duration >240 minutes). LOW ≤30; MEDIUM ≤60; HIGH ≤85; otherwise CRITICAL. LOW development/staging requests auto-approve. HIGH/CRITICAL or production requests require a syntactically valid ticket (`SEC-123` or `INC123456`). AdministratorAccess or CRITICAL requests require two distinct current approvers. Live AWS role chaining caps sessions at 60 minutes. Minimum request duration is 15 minutes; pending requests time out after 60 minutes. Capacity is three active sessions per user and five unexpired sessions per account/role, including revoked credentials until their original expiry.

## Existing demonstrable features and API inventory

The meaningful UI actions are covered individually below. The complete existing API surface is:

| Area | Implemented endpoints/actions |
|---|---|
| Authentication | POST `/api/auth/login`, `/logout`, `/password`; GET `/api/auth/me`; GET `/api/auth/sso` and `/sso/callback` |
| MFA | POST `/api/auth/mfa/setup`, `/enable`, `/verify`, `/recovery-codes`; login accepts TOTP or a single-use recovery code |
| Users | GET/POST `/api/users`; PATCH `/api/users/{id}`; POST `/api/users/{id}/recover` |
| Catalog/policies | GET `/api/users/roles/catalog`, `/accounts/catalog`; PATCH `/api/users/roles/{role_name}` |
| Grants | GET/POST `/api/users/{id}/entitlements`; POST `/api/users/{id}/entitlements/revoke` |
| Requests | POST `/api/requests/evaluate`; GET/POST `/api/requests`; GET `/api/requests/{id}`; POST `/api/requests/{id}/cancel`; idempotency key on creation |
| Decisions | GET `/api/approvals/pending`; POST `/api/approvals/{id}/decide` |
| Sessions | GET `/api/sessions/active`, `/history`; POST `/api/sessions/{id}/credentials`, `/console`, `/revoke` |
| Audit | GET `/api/audit/logs`, `/cloudtrail`, `/verify-chain`, `/export` |
| Operations | GET `/api/health`, `/ready`, `/system/status`, `/notifications`; POST `/api/notifications/{id}/read`; authenticated WebSocket `/api/events`; GET `/` backend service info; generated `/docs` and `/openapi.json` |

Security controls include role dependencies, own-record access, explicit grants, current eligibility checks at approval/issuance, distinct approvals, rejection reason, mandatory ticket syntax, maximum duration, capacities, pending expiry, MFA and TOTP replay rejection, one-use recovery codes, cookie HttpOnly/SameSite, token invalidation on logout/account change, CSRF/origin checking, shared rate limiting, encrypted credential storage, and append-only HMAC-linked audit records. Not every rejected authorization/schema-validation probe generates an audit event; login failures and the explicitly implemented workflow events do.

## Prepared records

These were created through authenticated normal APIs, not direct fabricated request/session inserts. The only direct existing-user data update changed the two full_name values, with a transaction, USER_UPDATED audit events, and assertions that every other field was unchanged. A database backup was saved before updates.

| Prepared justification suffix | Owner | Target | Result after preparation | Ticket | Request ID |
|---|---|---|---|---|---|
| Natural 15-minute expiry | alex.dev | Staging-EU / JIT-Access-ReadOnly | APPROVED (0/0 approvals) | — | `d95f64d2-2522-4a3f-9456-6734f72ae17f` |
| Approved deployment and revocation | alex.dev | Dev-Sandbox / JIT-Access-PowerUser | REVOKED (1/1 approvals) | — | `0a6c3757-175c-4423-98a3-34cb9fd73608` |
| Rejected database maintenance | alex.dev | Staging-EU / JIT-Access-DBAdmin | REJECTED (0/1 approvals) | SEC-402 | `a4c8cd26-756f-4d70-8c67-55265fe6c6e8` |
| Requester cancellation | alex.dev | Staging-EU / JIT-Access-DBAdmin | REJECTED (0/1 approvals) | SEC-403 | `b597d278-9050-4d7a-975e-4057d43186fa` |
| Two-person production elevation | alex.dev | Prod-US-East-1 / JIT-Access-AdministratorAccess | APPROVED (2/2 approvals) | SEC-404 | `01e2e771-266d-4927-8305-cd2fffe5600c` |
| Automatic sandbox read-only access | alex.dev | Dev-Sandbox / JIT-Access-ReadOnly | APPROVED (0/0 approvals) | — | `8c9d9e19-6524-491d-8940-bc02d7d6ee99` |
| Pending staging deployment review | alex.dev | Staging-EU / JIT-Access-PowerUser | PENDING (0/1 approvals) | SEC-405 | `cb647296-225d-49ca-9a86-19cdf73536d2` |
| One of two approvals recorded | alex.dev | Dev-Sandbox / JIT-Access-AdministratorAccess | PENDING (1/2 approvals) | SEC-406 | `8367b85d-073d-4f34-8189-6f15e8e5fa77` |
| Self-approval prevention | sarah.sec | Staging-EU / JIT-Access-PowerUser | PENDING (0/1 approvals) | — | `43f76295-6635-44f8-b9d3-ccacf8ce11fe` |

Prepared records are time-sensitive. Expired/revoked/rejected history persists, but active sessions and pending approvals do not remain indefinitely. After expiration, recreate only the necessary examples through the guide's normal workflows. Avoid exceeding capacity, and wait for a revoked session's original expiry if an account/role has five unexpired records. Search/filter only applies to the current 25-row frontend page.

## PROJECT SCREENSHOT GUIDE

For entries saying “Sign in as …”, begin at `http://127.0.0.1:3000/`, sign out if needed, enter the username and the password specified for that entry, then click **Sign in**. For demo.security also enter a fresh authenticator code (or the indicated unused recovery code). Use separate browser profiles for concurrent roles. Existing app pages have URL `/`; the “navigation” identifies the tab/dialog. Screenshot titles can be numbered as Figure 4.1 onward in Chapter 4, and verification/denial evidence as Figure 5.1 onward in Chapter 5. No UI is fabricated.

### SCREENSHOT 01

**Title:** SecureAccess Cloud Authentication Interface

**Purpose / PAM relevance:** Document the authentication entry point.

**Account / role:** SECURITY_ADMIN

**Username:** `admin.sys`

**Password:** `Password123!`.

**Exact URL:** `http://127.0.0.1:3000/`

**Navigation:** Signed-out login screen

**Prerequisite/data:** Sign out of the current session; no records are required.

**Steps and values:**

1. Open http://127.0.0.1:3000/.
2. Enter username admin.sys and password Password123!; leave the optional MFA code blank.
3. Do not submit until the screenshot is taken.

**Expected result:** Username, password, authenticator-code field, recovery-code disclosure, and demo presets are visible.

**Take the screenshot when:** Before clicking Sign in; the password stays masked.

### SCREENSHOT 02

**Title:** Rejection of Invalid Login Credentials

**Purpose / PAM relevance:** Show that invalid credentials do not grant access.

**Account / role:** SECURITY_ADMIN

**Username:** `admin.sys`

**Password:** `Password123!`.

**Exact URL:** `http://127.0.0.1:3000/`

**Navigation:** Signed-out login screen

**Prerequisite/data:** Signed-out browser.

**Steps and values:**

1. Open the base URL.
2. Enter admin.sys and Wrong-project-password!.
3. Click Sign in.

**Expected result:** An Invalid credentials error appears; no dashboard opens.

**Take the screenshot when:** While the error is visible; then replace the password with Password123!.

### SCREENSHOT 03

**Title:** Requester Access Overview

**Purpose / PAM relevance:** Show Ebuka’s requester view and scoped session/request totals.

**Account / role:** REQUESTER (Ebuka)

**Username:** `alex.dev`

**Password:** `Password123!`.

**Exact URL:** `http://127.0.0.1:3000/`

**Navigation:** Dashboard

**Prerequisite/data:** Prepared demo requests exist.

**Steps and values:**

1. Sign in using alex.dev and Password123!.
2. Click Dashboard.
3. Wait for System status to load.

**Expected result:** Signed in as alex.dev · REQUESTER, local-demo banner, scoped metrics, and system status. Approvals, audit, and user administration are absent from the sidebar.

**Take the screenshot when:** With the sidebar and status panel visible.

### SCREENSHOT 04

**Title:** Approver Security Operations Dashboard

**Purpose / PAM relevance:** Show Amara’s approval responsibilities.

**Account / role:** APPROVER (Amara)

**Username:** `sarah.sec`

**Password:** `Password123!`.

**Exact URL:** `http://127.0.0.1:3000/`

**Navigation:** Dashboard

**Prerequisite/data:** Pending requests exist; credentials remain unchanged.

**Steps and values:**

1. Sign in using sarah.sec and Password123!.
2. Click Dashboard.
3. Scroll to Notifications if needed.

**Expected result:** APPROVER role, Pending approvals metric, Approvals Inbox, audit and read-only user/catalog pages.

**Take the screenshot when:** With role, pending count, and approval notification visible.

### SCREENSHOT 05

**Title:** Security Administrator Dashboard

**Purpose / PAM relevance:** Show the administrator’s system oversight.

**Account / role:** SECURITY_ADMIN

**Username:** `admin.sys`

**Password:** `Password123!`.

**Exact URL:** `http://127.0.0.1:3000/`

**Navigation:** Dashboard

**Prerequisite/data:** Backend and embedded worker running.

**Steps and values:**

1. Sign in using admin.sys and Password123!.
2. Click Dashboard.
3. Inspect System status.

**Expected result:** SECURITY_ADMIN, policy engine ACTIVE, worker HEALTHY, audit chain VALID, and all administration navigation.

**Take the screenshot when:** After status loads.

### SCREENSHOT 06

**Title:** Auditor Monitoring Dashboard

**Purpose / PAM relevance:** Show the auditor’s observational role.

**Account / role:** AUDITOR

**Username:** `audit.user`

**Password:** `Password123!`.

**Exact URL:** `http://127.0.0.1:3000/`

**Navigation:** Dashboard

**Prerequisite/data:** Audit and access records exist.

**Steps and values:**

1. Sign in using audit.user and Password123!.
2. Click Dashboard.

**Expected result:** AUDITOR can observe global request/session counts, audit, and users; no Request JIT access or approval inbox is offered.

**Take the screenshot when:** With the role and sidebar visible.

### SCREENSHOT 07

**Title:** Existing Demo Identities and Role Assignments

**Purpose / PAM relevance:** Verify the renamed identities and all four application roles.

**Account / role:** SECURITY_ADMIN

**Username:** `admin.sys`

**Password:** `Password123!`.

**Exact URL:** `http://127.0.0.1:3000/`

**Navigation:** User & Policy Management

**Prerequisite/data:** Display-name updates already applied.

**Steps and values:**

1. Sign in as admin.sys.
2. Click User & Policy Management.
3. Locate alex.dev / Ebuka Rivera and sarah.sec / Amara Chen.

**Expected result:** Existing usernames remain unchanged; full names are Ebuka Rivera and Amara Chen. Administrator, auditor, Chika, and the separate security demonstrator are also listed.

**Take the screenshot when:** With both renamed rows, their roles, and MFA status visible.

### SCREENSHOT 08

**Title:** Reviewed AWS JIT Role Catalog

**Purpose / PAM relevance:** Explain the permitted AWS role scopes, environments, and time limits.

**Account / role:** SECURITY_ADMIN

**Username:** `admin.sys`

**Password:** `Password123!`.

**Exact URL:** `http://127.0.0.1:3000/`

**Navigation:** User & Policy Management

**Prerequisite/data:** Existing catalog; no edits needed.

**Steps and values:**

1. Sign in as admin.sys.
2. Click User & Policy Management.
3. Scroll to Enforced role catalog.

**Expected result:** ReadOnly, PowerUser, DBAdmin, and AdministratorAccess cards show descriptions, maximum durations, and allowed environments.

**Take the screenshot when:** With the four role cards visible; do not claim these are four more application user roles.

### SCREENSHOT 09

**Title:** Low-Risk Access Request and Policy Preview

**Purpose / PAM relevance:** Show justification, explicit grants, time bounding, and policy evaluation before submission.

**Account / role:** REQUESTER (Ebuka)

**Username:** `alex.dev`

**Password:** `Password123!`.

**Exact URL:** `http://127.0.0.1:3000/`

**Navigation:** Dashboard → Request JIT access

**Prerequisite/data:** Ebuka already has the corresponding seeded grant.

**Steps and values:**

1. Sign in as alex.dev.
2. Click Request JIT access.
3. Select Dev-Sandbox (123456789012), JIT-Access-ReadOnly, and 15 minutes.
4. Enter Business justification: PROJECT DEFENSE: Inspect sandbox deployment configuration.
5. Leave Ticket reference blank; wait for the policy preview.

**Expected result:** Risk 15/100 LOW, eligibility for automatic approval, target account/role, and a duration bound.

**Take the screenshot when:** Before Submit request. Close with Cancel if no new record is needed.

### SCREENSHOT 10

**Title:** Automatically Approved Read-Only Request

**Purpose / PAM relevance:** Show supported low-risk automatic JIT issuance.

**Account / role:** REQUESTER (Ebuka)

**Username:** `alex.dev`

**Password:** `Password123!`.

**Exact URL:** `http://127.0.0.1:3000/`

**Navigation:** Access Requests

**Prerequisite/data:** Prepared Automatic sandbox read-only access record, or create the request in Screenshot 09 after ensuring session capacity.

**Steps and values:**

1. Sign in as alex.dev.
2. Click Access Requests.
3. Choose Approved in All Statuses; locate JIT-Access-ReadOnly in Dev-Sandbox.
4. Click its Details button.

**Expected result:** APPROVED, LOW risk, account, duration, and business justification.

**Take the screenshot when:** With the request details open; do not submit again just to reproduce an existing example.

### SCREENSHOT 11

**Title:** Pending Privileged Access Request

**Purpose / PAM relevance:** Show approval gating before privilege is issued.

**Account / role:** REQUESTER (Ebuka)

**Username:** `alex.dev`

**Password:** `Password123!`.

**Exact URL:** `http://127.0.0.1:3000/`

**Navigation:** Access Requests

**Prerequisite/data:** Prepared Pending staging deployment review record; pending records expire after 60 minutes.

**Steps and values:**

1. Sign in as alex.dev.
2. Click Access Requests.
3. Select Pending; search SEC-405.
4. Click Details for the staging PowerUser request.

**Expected result:** PENDING, Staging-EU, PowerUser, 60 minutes, and the justification; this request has no session.

**Take the screenshot when:** With Details open. If it has expired, submit a new staging PowerUser request with the same values and a fresh justification.

### SCREENSHOT 12

**Title:** Approver Review of Business Justification

**Purpose / PAM relevance:** Show review of request scope, risk, duration, and ticket.

**Account / role:** APPROVER (Amara)

**Username:** `sarah.sec`

**Password:** `Password123!`.

**Exact URL:** `http://127.0.0.1:3000/`

**Navigation:** Approvals Inbox

**Prerequisite/data:** A pending request by a different user; use SEC-405.

**Steps and values:**

1. Sign in as sarah.sec.
2. Click Approvals Inbox.
3. Locate alex.dev’s Staging-EU PowerUser request by its justification/ticket.
4. Read its justification and requested TTL; do not click a decision for the review screenshot.

**Expected result:** Request card with requester, target environment, requested IAM role, duration, justification, and Record Approval / Reject Request buttons.

**Take the screenshot when:** Before deciding. This card demonstrates review, not automatic assignment of privileges.

### SCREENSHOT 13

**Title:** Single-Approver Decision and Credential Issuance

**Purpose / PAM relevance:** Show a manual approval for a medium-risk request.

**Account / role:** APPROVER (Amara)

**Username:** `sarah.sec`

**Password:** `Password123!`.

**Exact URL:** `http://127.0.0.1:3000/`

**Navigation:** Approvals Inbox

**Prerequisite/data:** Use a fresh Dev-Sandbox PowerUser request by alex.dev, 15 minutes, justification PROJECT DEFENSE: Approved deployment. Ebuka must have fewer than three active sessions.

**Steps and values:**

1. Sign in as sarah.sec.
2. Click Approvals Inbox.
3. Locate the specified request.
4. Click Record Approval.

**Expected result:** Approved; credentials issued. toast; request becomes APPROVED and an owner session exists.

**Take the screenshot when:** Immediately on the success toast; then log in as alex.dev to view the session. This consumes the chosen pending example.

### SCREENSHOT 14

**Title:** First Approval in a Two-Person Authorization Workflow

**Purpose / PAM relevance:** Show separation of duties for administrator-level AWS elevation.

**Account / role:** SECURITY_ADMIN

**Username:** `admin.sys`

**Password:** `Password123!`.

**Exact URL:** `http://127.0.0.1:3000/`

**Navigation:** Approvals Inbox

**Prerequisite/data:** Prepared One of two approvals recorded record SEC-406. Amara’s first approval is already recorded.

**Steps and values:**

1. Sign in as admin.sys.
2. Click Approvals Inbox.
3. Locate SEC-406 / JIT-Access-AdministratorAccess in Dev-Sandbox.
4. Observe Approvals: 1/2 without recording the second approval yet.

**Expected result:** PENDING with 1/2 approvals; no credentials issued for this request.

**Take the screenshot when:** With the 1/2 count and role visible. Keep Amara signed in until the second decision if recreating the example.

### SCREENSHOT 15

**Title:** Completed Dual Approval for Production Elevation

**Purpose / PAM relevance:** Show two distinct approvals for critical access.

**Account / role:** REQUESTER (Ebuka)

**Username:** `alex.dev`

**Password:** `Password123!`.

**Exact URL:** `http://127.0.0.1:3000/`

**Navigation:** Access Requests

**Prerequisite/data:** Prepared Two-person production elevation record SEC-404; while its session is active it is APPROVED.

**Steps and values:**

1. Sign in as alex.dev.
2. Click Access Requests; search SEC-404.
3. Click Details.

**Expected result:** AdministratorAccess, Prod-US-East-1, CRITICAL 100/100, 60-minute duration, and APPROVED (or EXPIRED after its original hour).

**Take the screenshot when:** With Details visible; for a new complete two-person sequence use the defense workflow below.

### SCREENSHOT 16

**Title:** Explicit Rejection of a Privileged Request

**Purpose / PAM relevance:** Show a security reviewer rejecting inappropriate access with an explanation.

**Account / role:** APPROVER (Amara)

**Username:** `sarah.sec`

**Password:** `Password123!`.

**Exact URL:** `http://127.0.0.1:3000/`

**Navigation:** Approvals Inbox

**Prerequisite/data:** Submit a fresh alex.dev request: Staging-EU, DBAdmin, 15 minutes, ticket SEC-502, justification PROJECT DEFENSE: Database maintenance outside approved window.

**Steps and values:**

1. Sign in as sarah.sec.
2. Click Approvals Inbox and find SEC-502.
3. Click Reject Request.
4. Enter Reason for Rejection: Maintenance window is not approved; reschedule after least privilege review.
5. Take the dialog screenshot; then click Confirm Rejection if demonstrating the complete action.

**Expected result:** Rejection dialog with mandatory reason; successful confirmation rejects the request and creates an audit event.

**Take the screenshot when:** With the reason filled, before Confirm Rejection.

### SCREENSHOT 17

**Title:** Rejected Request and Recorded Security Reason

**Purpose / PAM relevance:** Show feedback to the requester and denial of privilege issuance.

**Account / role:** REQUESTER (Ebuka)

**Username:** `alex.dev`

**Password:** `Password123!`.

**Exact URL:** `http://127.0.0.1:3000/`

**Navigation:** Access Requests

**Prerequisite/data:** Prepared Rejected database maintenance record SEC-402, or the new rejection from Screenshot 16.

**Steps and values:**

1. Sign in as alex.dev.
2. Click Access Requests; select Rejected and search SEC-402.
3. Click Details.

**Expected result:** REJECTED plus Maintenance window is not approved; least privilege review requires rescheduling. No session was issued for the request.

**Take the screenshot when:** With the rejection reason visible.

### SCREENSHOT 18

**Title:** Requester Cancellation of Pending Access

**Purpose / PAM relevance:** Show withdrawal of an unnecessary request.

**Account / role:** REQUESTER (Ebuka)

**Username:** `alex.dev`

**Password:** `Password123!`.

**Exact URL:** `http://127.0.0.1:3000/`

**Navigation:** Access Requests

**Prerequisite/data:** Prepared Requester cancellation record SEC-403 already shows cancellation. To show the click, submit a fresh Staging-EU PowerUser request, 15 minutes, justification PROJECT DEFENSE: Cancel obsolete deployment.

**Steps and values:**

1. Sign in as alex.dev.
2. Click Access Requests.
3. For the fresh pending own request, click Cancel request.
4. Select Rejected and open Details for that request (or existing SEC-403).

**Expected result:** Status is REJECTED with Cancelled by requester; the application has no separate CANCELLED status.

**Take the screenshot when:** With cancellation reason visible.

### SCREENSHOT 19

**Title:** Active Time-Bound Privileged Sessions

**Purpose / PAM relevance:** Show temporary privilege and expiration countdown.

**Account / role:** REQUESTER (Ebuka)

**Username:** `alex.dev`

**Password:** `Password123!`.

**Exact URL:** `http://127.0.0.1:3000/`

**Navigation:** Active JIT Sessions

**Prerequisite/data:** An unexpired approved session; prepared sandbox read-only and production administrator sessions initially exist.

**Steps and values:**

1. Sign in as alex.dev.
2. Click Active JIT Sessions.
3. Click Refresh.

**Expected result:** Owner sessions show account, role, countdown, Demo mode, Credentials, and Revoke.

**Take the screenshot when:** With Time remaining and Mode visible. Recreate via normal approval if all prepared sessions have expired.

### SCREENSHOT 20

**Title:** Owner-Only Temporary Credential Retrieval

**Purpose / PAM relevance:** Show encrypted-at-rest credentials revealed only to the owner.

**Account / role:** REQUESTER (Ebuka)

**Username:** `alex.dev`

**Password:** `Password123!`.

**Exact URL:** `http://127.0.0.1:3000/`

**Navigation:** Active JIT Sessions → Credentials

**Prerequisite/data:** Any active session owned by alex.dev.

**Steps and values:**

1. Sign in as alex.dev.
2. Click Active JIT Sessions.
3. Click Credentials on your session.
4. Switch between Bash and PowerShell; Copy is available.

**Expected result:** Temporary credentials dialog and DEMO ONLY notice. The snippet contains simulated AWS values; live AWS console is unavailable.

**Take the screenshot when:** With the Demo notice and snippet visible. Click Close and clear afterwards; do not execute the simulated credentials against AWS.

### SCREENSHOT 21

**Title:** Revoked Session History

**Purpose / PAM relevance:** Show privilege removal and preserved history.

**Account / role:** AUDITOR

**Username:** `audit.user`

**Password:** `Password123!`.

**Exact URL:** `http://127.0.0.1:3000/`

**Navigation:** Active JIT Sessions

**Prerequisite/data:** Prepared Approved deployment and revocation session was revoked by sarah.sec.

**Steps and values:**

1. Sign in as audit.user.
2. Click Active JIT Sessions; click Refresh.
3. Scroll to Session history.

**Expected result:** alex.dev / PowerUser / REVOKED, with an end time. Auditor has no Revoke or Credentials button.

**Take the screenshot when:** With the revoked history row and auditor role visible. To demonstrate the actual click, an owner, approver, or administrator can click Revoke on a fresh active session.

### SCREENSHOT 22

**Title:** Natural Session Expiration

**Purpose / PAM relevance:** Show automatic expiry without manually editing timestamps.

**Account / role:** REQUESTER (Ebuka)

**Username:** `alex.dev`

**Password:** `Password123!`.

**Exact URL:** `http://127.0.0.1:3000/`

**Navigation:** Active JIT Sessions

**Prerequisite/data:** Natural 15-minute expiry staging ReadOnly session created via the request API; wait until its recorded expires_at plus the worker’s approximately 10-second cycle.

**Steps and values:**

1. Sign in as alex.dev.
2. Click Active JIT Sessions and Refresh.
3. Scroll to Session history; locate Staging-EU ReadOnly.
4. Open Access Requests and select Expired for a second view if desired.

**Expected result:** Session EXPIRED, absent from active sessions, with credentials no longer retrievable; corresponding request EXPIRED.

**Take the screenshot when:** With the expired row visible. Minimum request duration is 15 minutes; no accelerated timer was added.

### SCREENSHOT 23

**Title:** Security Audit Events and Privileged Access Accountability

**Purpose / PAM relevance:** Show real access and security events created by workflows.

**Account / role:** AUDITOR

**Username:** `audit.user`

**Password:** `Password123!`.

**Exact URL:** `http://127.0.0.1:3000/`

**Navigation:** Audit Trail & Compliance → Internal audit

**Prerequisite/data:** Prepared login, request, approval, rejection, session, user, grant, recovery, and MFA events.

**Steps and values:**

1. Sign in as audit.user.
2. Click Audit Trail & Compliance.
3. Click Internal audit.
4. Use Search actor, event or resource, for example SESSION_REVOKED; use Next/Previous to find older events.

**Expected result:** Sequence, timestamp, event, actor, resource, IP, and signature. Search applies only to the current page.

**Take the screenshot when:** With meaningful events visible; clear search if the current page has none.

### SCREENSHOT 24

**Title:** HMAC Audit-Chain Integrity Verification

**Purpose / PAM relevance:** Show tamper-evident local audit verification.

**Account / role:** AUDITOR

**Username:** `audit.user`

**Password:** `Password123!`.

**Exact URL:** `http://127.0.0.1:3000/`

**Navigation:** Audit Trail & Compliance

**Prerequisite/data:** Valid existing audit chain.

**Steps and values:**

1. Sign in as audit.user.
2. Click Audit Trail & Compliance.
3. Click Refresh and verify.

**Expected result:** HMAC-SHA256 chain: VALID, record count, and external archive status.

**Take the screenshot when:** After verification completes. Local HMAC evidence is not proof of a configured external immutable archive.

### SCREENSHOT 25

**Title:** Export of Audit Evidence for Evaluation

**Purpose / PAM relevance:** Show supported evidence extraction for Chapter 5.

**Account / role:** AUDITOR

**Username:** `audit.user`

**Password:** `Password123!`.

**Exact URL:** `http://127.0.0.1:3000/`

**Navigation:** Audit Trail & Compliance → Export JSON

**Prerequisite/data:** Existing audit records.

**Steps and values:**

1. Sign in as audit.user.
2. Click Audit Trail & Compliance.
3. Click Export JSON.
4. Open the downloaded secureaccess-audit.json in a JSON viewer.

**Expected result:** Export contains algorithm HMAC-SHA256, valid: true, and audit records with chain fields.

**Take the screenshot when:** Capture the UI export control or actual downloaded JSON; do not alter records or claim export itself creates an audit event.

### SCREENSHOT 26

**Title:** CloudTrail Availability in Local Demonstration Mode

**Purpose / PAM relevance:** Document the live-integration boundary honestly.

**Account / role:** AUDITOR

**Username:** `audit.user`

**Password:** `Password123!`.

**Exact URL:** `http://127.0.0.1:3000/`

**Navigation:** Audit Trail & Compliance → CloudTrail

**Prerequisite/data:** Default demo mode.

**Steps and values:**

1. Sign in as audit.user.
2. Click Audit Trail & Compliance.
3. Click CloudTrail.

**Expected result:** AWS CloudTrail is unavailable in demo mode and no fabricated AWS events.

**Take the screenshot when:** With the availability message visible; this is a limitation screenshot, not proof of AWS monitoring.

### SCREENSHOT 27

**Title:** Workflow Notifications

**Purpose / PAM relevance:** Show review notifications generated by requests.

**Account / role:** APPROVER (Amara)

**Username:** `sarah.sec`

**Password:** `Password123!`.

**Exact URL:** `http://127.0.0.1:3000/`

**Navigation:** Dashboard → Notifications

**Prerequisite/data:** Prepared requests generated approver notifications; approval/rejection generated requester notifications.

**Steps and values:**

1. Sign in as sarah.sec.
2. Click Dashboard; scroll to Notifications.
3. Capture an unread access-request notification.
4. Click Mark read if showing acknowledgment.

**Expected result:** Notification identifies requester, role, account, and approval requirement; Mark read disappears after acknowledgment.

**Take the screenshot when:** Before or after Mark read. Notifications are internal; email delivery is not configured.

### SCREENSHOT 28

**Title:** MFA-Enabled Account Security

**Purpose / PAM relevance:** Show actual authenticator enrollment status without changing the main demo users.

**Account / role:** REQUESTER with MFA

**Username:** `demo.security`

**Password:** `Demo-project-123!` plus a fresh MFA/recovery code.

**Exact URL:** `http://127.0.0.1:3000/`

**Navigation:** Account Security

**Prerequisite/data:** Existing demo.security account is MFA-enabled. Import the private provisioning_uri/secret from /tmp/secureaccess-demo-mfa-private.json into an authenticator locally.

**Steps and values:**

1. Open the base URL; enter demo.security and Demo-project-123!.
2. Enter a fresh six-digit Authenticator code (if MFA enabled); click Sign in.
3. Click Account Security.

**Expected result:** MFA is enabled, Verify MFA form, Replace recovery codes form, and password-change form.

**Take the screenshot when:** With enabled status visible; do not include authenticator secrets or recovery codes in the academic report.

### SCREENSHOT 29

**Title:** MFA Enforcement at Sign-In

**Purpose / PAM relevance:** Show that the correct password alone is insufficient for an MFA-enabled user.

**Account / role:** REQUESTER with MFA

**Username:** `demo.security`

**Password:** `Demo-project-123!` plus a fresh MFA/recovery code.

**Exact URL:** `http://127.0.0.1:3000/`

**Navigation:** Signed-out login screen

**Prerequisite/data:** Existing MFA-enabled account.

**Steps and values:**

1. Sign out.
2. Enter demo.security and Demo-project-123!.
3. Leave authenticator and recovery codes blank.
4. Click Sign in.

**Expected result:** A valid, unused MFA code is required; no dashboard.

**Take the screenshot when:** With the error visible; then sign in with a fresh authenticator code.

### SCREENSHOT 30

**Title:** Single-Use MFA Recovery Login

**Purpose / PAM relevance:** Show recovery using the normal authentication workflow.

**Account / role:** REQUESTER with MFA

**Username:** `demo.security`

**Password:** `Demo-project-123!` plus a fresh MFA/recovery code.

**Exact URL:** `http://127.0.0.1:3000/`

**Navigation:** Signed-out login screen → Use an MFA recovery code

**Prerequisite/data:** Choose an unused recovery code from the private file. One original code was already consumed during testing; the file lists the remaining codes.

**Steps and values:**

1. Open the base URL while signed out.
2. Enter demo.security and Demo-project-123!.
3. Expand Use an MFA recovery code.
4. Leave authenticator code blank; enter an unused Recovery code.
5. Click Sign in.

**Expected result:** Dashboard opens; the code is consumed. Reusing the same code at another login is denied.

**Take the screenshot when:** Capture the disclosure with the code concealed, then the authenticated dashboard. Do not publish the raw recovery code.

### SCREENSHOT 31

**Title:** Authenticator Enrollment and Recovery-Code Rotation

**Purpose / PAM relevance:** Document enrollment and replacement workflows already implemented and tested.

**Account / role:** REQUESTER with MFA

**Username:** `demo.security`

**Password:** `Demo-project-123!` plus a fresh MFA/recovery code.

**Exact URL:** `http://127.0.0.1:3000/`

**Navigation:** Account Security

**Prerequisite/data:** Account is already enrolled. For an enrollment screenshot only, an administrator must intentionally reset this disposable account’s MFA using Recover account, reason Project demonstration of authenticator enrollment, and Reset lost authenticator and recovery codes. This is optional future user work; existing main users stay unchanged.

**Steps and values:**

1. For rotation, sign in as demo.security with a fresh authenticator code; click Account Security.
2. Fill Password to replace recovery codes with Demo-project-123! and Authenticator code for recovery codes with a new unused code.
3. Click Generate new recovery codes; save the returned codes privately and retire the previous list.
4. For optional reenrollment after the prerequisite reset: sign in with the password, enter Current password to set up MFA, click Set up MFA, import the displayed key into your authenticator, enter Six-digit code, and click Enable MFA.

**Expected result:** Rotation shows new single-use recovery codes. Enrollment shows an enrollment key/URI then enabled status. These operations invalidate old recovery material.

**Take the screenshot when:** Prefer enabled-status/rotation-control screenshots. If capturing returned secrets, mask them in the report; screenshots must still come from the real UI.

### SCREENSHOT 32

**Title:** Denial of Access Without Explicit Grants

**Purpose / PAM relevance:** Show least privilege for a provisioned user without AWS permissions.

**Account / role:** REQUESTER with MFA

**Username:** `demo.security`

**Password:** `Demo-project-123!` plus a fresh MFA/recovery code.

**Exact URL:** `http://127.0.0.1:3000/`

**Navigation:** Dashboard → Request JIT access

**Prerequisite/data:** demo.security has no grants; it remains active and MFA-enabled.

**Steps and values:**

1. Sign in as demo.security with password and a fresh MFA code.
2. Click Request JIT access.

**Expected result:** No eligible access grants. Ask your administrator to grant an account and role.

**Take the screenshot when:** With the message visible. Application role alone does not grant AWS access.

### SCREENSHOT 33

**Title:** Administrator Management of Explicit Access Grants

**Purpose / PAM relevance:** Show account/role/duration entitlements controlled by an administrator.

**Account / role:** SECURITY_ADMIN

**Username:** `admin.sys`

**Password:** `Password123!`.

**Exact URL:** `http://127.0.0.1:3000/`

**Navigation:** User & Policy Management → Access grants

**Prerequisite/data:** Use demo.security for experiments; Ebuka and Amara’s existing grants remain intact.

**Steps and values:**

1. Sign in as admin.sys.
2. Click User & Policy Management.
3. Click Access grants on demo.security’s row.
4. Select Dev-Sandbox, JIT-Access-ReadOnly, Grant maximum minutes 15.
5. Capture before Save grant. If demonstrating persistence, click Save grant, then sign in as demo.security and open Request JIT access; only that account/role is eligible.
6. Use Remove grant on the same demonstrator grant to restore the prepared no-grants state.

**Expected result:** Grant list with limits; save/removal enforce entitlement and generate audit events. Shortening/removing grants revokes that user’s active sessions.

**Take the screenshot when:** With the grant dialog visible; do not remove main users’ grants for screenshots.

### SCREENSHOT 34

**Title:** Administrator User Provisioning Form

**Purpose / PAM relevance:** Show supported user onboarding with an explicit application role.

**Account / role:** SECURITY_ADMIN

**Username:** `admin.sys`

**Password:** `Password123!`.

**Exact URL:** `http://127.0.0.1:3000/`

**Navigation:** User & Policy Management → Provision user

**Prerequisite/data:** No new user is required for the screenshot. demo.security was already provisioned through this workflow’s API.

**Steps and values:**

1. Sign in as admin.sys.
2. Click User & Policy Management; click Provision user.
3. For a form-only screenshot enter username defense.observer, email defense.observer@example.com, full name Defense Observer, password Defense-observer-123!, department Project Demonstration, role AUDITOR.
4. Capture the form without clicking Create user unless you intentionally want another account.

**Expected result:** Provisioning fields and four allowed application roles; new users get no automatic AWS grants.

**Take the screenshot when:** Before Create user. Do not duplicate alex.dev or sarah.sec.

### SCREENSHOT 35

**Title:** User Role and Activation Administration

**Purpose / PAM relevance:** Show role changes, activation controls, and session invalidation.

**Account / role:** SECURITY_ADMIN

**Username:** `admin.sys`

**Password:** `Password123!`.

**Exact URL:** `http://127.0.0.1:3000/`

**Navigation:** User & Policy Management

**Prerequisite/data:** Use the separate demo.security row; changing original user roles is unnecessary.

**Steps and values:**

1. Sign in as admin.sys.
2. Click User & Policy Management.
3. Capture Role for demo.security dropdown and Deactivate button.
4. For a live experiment choose APPROVER then restore REQUESTER; deactivate then Activate the same account.
5. Attempt its normal login during deactivation to show Invalid credentials.

**Expected result:** Changed roles invalidate login tokens; deactivation prevents sign-in and revokes sessions. Own administrator account cannot be deactivated or demoted.

**Take the screenshot when:** With administrator controls visible. Live experiment already passed during preparation; future changes affect the disposable user only.

### SCREENSHOT 36

**Title:** Identity-Verified Administrator Recovery

**Purpose / PAM relevance:** Show supported recovery and forced password change.

**Account / role:** SECURITY_ADMIN

**Username:** `admin.sys`

**Password:** `Password123!`.

**Exact URL:** `http://127.0.0.1:3000/`

**Navigation:** User & Policy Management → Recover account

**Prerequisite/data:** Use demo.security only. Existing usernames/passwords for Ebuka and Amara are preserved.

**Steps and values:**

1. Sign in as admin.sys.
2. Click User & Policy Management; Recover account on demo.security.
3. Enter Identity verification and recovery reason: Verified demonstration account identity for password recovery.
4. For a form screenshot enter temporary password Demo-temporary-123! and leave Reset lost authenticator unchecked.
5. Capture before Recover account. If proceeding, the account must log in with the temporary password plus its existing MFA, then use Account Security to change to Demo-project-123!.

**Expected result:** Recovery dialog; successful recovery invalidates tokens, revokes sessions, and limits the user to password-change/logout until the temporary password is changed.

**Take the screenshot when:** With recovery fields visible. Do not reset a main user to reproduce this screen.

### SCREENSHOT 37

**Title:** Password Change and Required Recovery Completion

**Purpose / PAM relevance:** Show self-service password change and mandatory completion after recovery.

**Account / role:** REQUESTER with MFA

**Username:** `demo.security`

**Password:** `Demo-project-123!` plus a fresh MFA/recovery code.

**Exact URL:** `http://127.0.0.1:3000/`

**Navigation:** Account Security

**Prerequisite/data:** Normal form is available now; mandatory-only view requires intentionally performing the optional disposable-account recovery in Screenshot 36.

**Steps and values:**

1. Sign in as demo.security with the current password and fresh MFA code.
2. Click Account Security; scroll to Change password.
3. For the normal form screenshot leave fields blank.
4. For optional recovery completion enter current password Demo-temporary-123!, new password Demo-project-123!, click Change password and sign out, then sign in again with the new password and a fresh MFA code.

**Expected result:** Password-change form; in mandatory mode other navigation is absent. Successful change signs out and revokes the user’s AWS sessions.

**Take the screenshot when:** Capture the required Account Security screen before completion or the normal form without changing anything.

### SCREENSHOT 38

**Title:** Restrictive Role Policy Administration

**Purpose / PAM relevance:** Show administrator policy controls and inability to loosen reviewed limits.

**Account / role:** SECURITY_ADMIN

**Username:** `admin.sys`

**Password:** `Password123!`.

**Exact URL:** `http://127.0.0.1:3000/`

**Navigation:** User & Policy Management → Edit policy

**Prerequisite/data:** Existing ReadOnly policy matches the reviewed baseline; no persistent change needed.

**Steps and values:**

1. Sign in as admin.sys.
2. Click User & Policy Management; scroll to Enforced role catalog.
3. Click Edit policy for JIT-Access-ReadOnly.
4. Observe Maximum minutes 480, Base risk 15, and environment checkboxes; capture the dialog.
5. For a denial demonstration try Maximum minutes 480 and Base risk 14 via the API: schema rejects risk below 15. A PowerUser policy maximum 241 with base risk 40 and environments development/staging is rejected as loosening the 240-minute baseline.
6. Click Cancel to keep the existing policy.

**Expected result:** Policy controls permit only tighter duration, higher risk, or fewer reviewed environments. Pending requests are rechecked at approval.

**Take the screenshot when:** With the dialog visible; do not save restrictive experimental policies on the main catalog solely for screenshots.

### SCREENSHOT 39

**Title:** Mandatory Ticket and Time-Limit Enforcement

**Purpose / PAM relevance:** Show request-level validation and high-risk policy requirements.

**Account / role:** REQUESTER (Ebuka)

**Username:** `alex.dev`

**Password:** `Password123!`.

**Exact URL:** `http://127.0.0.1:3000/`

**Navigation:** Request JIT access

**Prerequisite/data:** Existing production AdministratorAccess grant.

**Steps and values:**

1. Sign in as alex.dev; click Request JIT access.
2. Select Prod-US-East-1, JIT-Access-AdministratorAccess, 15 minutes.
3. Enter justification PROJECT DEFENSE: Diagnose production incident.
4. Observe required Ticket reference and critical-risk preview.
5. Enter invalid ticket invalid-ticket and click Submit request to show rejection; then replace with SEC-501 for a valid workflow.
6. Observe the duration slider cannot exceed the role’s 60-minute maximum.

**Expected result:** Invalid ticket is rejected; required reference and duration cap are visible. Server also enforces grants and limits independently of the UI.

**Take the screenshot when:** With critical risk, required ticket, and validation visible. Do not submit valid production access merely to show validation.

### SCREENSHOT 40

**Title:** Server-Side Role-Based Access Denial

**Purpose / PAM relevance:** Demonstrate backend authorization independently of hidden menus.

**Account / role:** REQUESTER (Ebuka)

**Username:** `alex.dev`

**Password:** `Password123!`.

**Exact URL:** `http://127.0.0.1:3000/`

**Navigation:** Dashboard plus browser developer console

**Prerequisite/data:** Authenticated requester; no record creation required.

**Steps and values:**

1. Sign in as alex.dev.
2. Capture the restricted sidebar.
3. Open browser Developer Tools → Console.
4. Run fetch("/api/audit/logs", {credentials:"include"}).then(async r => console.log(r.status, await r.json())).
5. For an auditor test sign in as audit.user and substitute /api/approvals/pending.

**Expected result:** HTTP 403 and Insufficient permissions. Requester cannot access another requester’s request (404); other users cannot retrieve another user’s credentials (404). These API checks passed during preparation.

**Take the screenshot when:** With the actual 403 response and role visible; this read-only probe uses normal authentication and does not bypass controls.

### SCREENSHOT 41

**Title:** Backend Health, Readiness, and API Documentation

**Purpose / PAM relevance:** Show that the existing backend and worker are operational.

**Account / role:** Not required

**Username:** `None`

**Password:** `Not required`.

**Exact URL:** Backend URLs listed in the steps.

**Navigation:** Backend API browser URLs

**Prerequisite/data:** Backend running on port 8000.

**Steps and values:**

1. Open http://127.0.0.1:8000/api/health.
2. Open http://127.0.0.1:8000/api/ready.
3. Open http://127.0.0.1:8000/docs for implemented endpoints; http://127.0.0.1:3000/api/health verifies the frontend proxy.

**Expected result:** Health status ok, readiness ready, demo_mode true, SSO false, and existing OpenAPI documentation.

**Take the screenshot when:** Capture health/readiness response or endpoint inventory; do not label unexecuted OpenAPI endpoints as successful tests.

### SCREENSHOT 42

**Title:** Secure Logout and Session Termination

**Purpose / PAM relevance:** Show termination of the application login session.

**Account / role:** REQUESTER (Ebuka)

**Username:** `alex.dev`

**Password:** `Password123!`.

**Exact URL:** `http://127.0.0.1:3000/`

**Navigation:** Dashboard → Sign Out

**Prerequisite/data:** Signed-in requester; browser tests also verified copied-token invalidation.

**Steps and values:**

1. Sign in as alex.dev.
2. Click Sign Out.
3. Reload the page.

**Expected result:** Login screen remains; authenticated UI does not restore. Logout invalidates the application token, but does not itself revoke AWS JIT sessions.

**Take the screenshot when:** After logout/reload, with the login screen visible.

## Complete end-to-end defense workflow

This sequence demonstrates brokered PAM in **simulated AWS mode**. It cannot demonstrate access to a real AWS resource. Use four separate browser profiles: Ebuka, Amara, administrator, auditor. Ordinary tabs within one profile share the same authentication cookie and are not separate users. **Do not sign Amara out between her first approval and the administrator's second approval**: logout increments the approver's token version, invalidating her outstanding approval. Close a browser/profile window without Sign Out if switching devices after recording a first approval, or keep it open for the complete sequence.

| Step | Account / password | Navigation and exact action | Expected result and screenshot point |
|---:|---|---|---|
| 1 | admin.sys / Password123! | Log in; User & Policy Management; show Ebuka Rivera / alex.dev and Amara Chen / sarah.sec. Inspect catalog and existing Ebuka grants; close dialogs without edits. | Existing four user roles and reviewed entitlements. Capture Screenshots 07–08. |
| 2 | alex.dev / Password123! | In a separate profile sign in; Dashboard. Check Active JIT Sessions. If three active owner sessions exist, revoke an obsolete one or wait for expiry; preserve a chosen evidence session as needed. | Requester scope and least privilege. Capture 03. |
| 3 | alex.dev / Password123! | Click Request JIT access. Choose Prod-US-East-1 (555444333222), JIT-Access-AdministratorAccess, duration 15 minutes, justification PROJECT DEFENSE: Diagnose a production incident under supervised temporary elevation, ticket SEC-501. Wait for preview. | CRITICAL risk 100/100, valid ticket required, two distinct approvals. Capture 39 before submission. |
| 4 | alex.dev | Click Submit request; Access Requests; select Pending; search SEC-501; Details. | PENDING; no JIT session yet. Capture 11. Record the displayed request ID so reviewers choose the correct record. |
| 5 | sarah.sec / Password123! | Second profile: sign in; Dashboard notifications; Approvals Inbox. Find alex.dev / SEC-501, review scope/justification/TTL, click Record Approval. Keep this profile logged in. | Approval recorded (1/2); still PENDING. Capture 12 and the toast. |
| 6 | admin.sys / Password123! | Administrator profile: Approvals Inbox; locate the same SEC-501; show Approvals 1/2; click Record Approval. | Second distinct approval issues the owner session; Approved; credentials issued. Capture 14 before clicking, then the success toast. |
| 7 | alex.dev | Requester profile: Active JIT Sessions; Refresh. Find AdministratorAccess / 555444333222. Click Credentials; inspect Bash/PowerShell; Close and clear. | Active 15-minute demo session and simulated owner-only temporary credentials. Capture 19–20. State clearly that these values cannot access AWS. |
| 8 | alex.dev | Open Developer Tools console; execute the read-only fetch(`/api/audit/logs`, {credentials:"include"}) response probe from Screenshot 40. Alternatively show missing admin/approval menus. | HTTP 403 for prohibited broker action. This proves application authorization, not AWS IAM enforcement. Capture 40. |
| 9 | sarah.sec or admin.sys | Active JIT Sessions; find the chosen owner/account/role row; click Revoke. | Session removed from active view, history REVOKED, credentials cleared, linked request REVOKED. Capture 21. |
| 10 | alex.dev | For a separate expiration branch, Request JIT access → Dev-Sandbox → ReadOnly → 15 minutes; justification PROJECT DEFENSE: Observe natural expiry; ticket blank; Submit request. Observe countdown, wait 15 minutes plus worker cycle; Refresh. | Auto-approved active session becomes EXPIRED naturally. Capture 09–10, 19, then 22. A prepared naturally expired session can be shown immediately to save defense time. |
| 11 | alex.dev then sarah.sec | Optional rejection branch: requester submits Staging-EU DBAdmin, 15 minutes, SEC-502, justification PROJECT DEFENSE: Unapproved database maintenance. Amara finds it in Approvals Inbox → Reject Request → reason Maintenance window is not approved; reschedule → Confirm Rejection. Requester opens Details. | REJECTED with reason and no credentials issued. Capture 16–17. |
| 12 | audit.user / Password123! | Fourth profile: sign in; Active JIT Sessions → Session history; Audit Trail & Compliance → Refresh and verify; Internal audit; locate ACCESS_REQUESTED, ACCESS_APPROVED, SESSION_CREATED, CREDENTIALS_RETRIEVED, SESSION_REVOKED/EXPIRED. Export JSON. | Auditor read-only monitoring, actual workflow events, HMAC chain VALID. Capture 06, 21–25. |
| 13 | demo.security / Demo-project-123! + MFA | Separate profile: show password-only login denial; then fresh authenticator login; Account Security; Request JIT access. | MFA enforcement and enabled status; no eligible AWS grants. Capture 28–29 and 32. Use an unused recovery code for Screenshot 30 if needed. |
| 14 | Any signed-in account | Click Sign Out; reload. | Login interface remains. Capture 42. |

Approve only the intended defense request. The prepared 1/2 example SEC-406 can be retained as comparison; pending examples expire after one hour. Session time starts at issuance, not request submission. Revocation is immediate in the broker's demo state; in live AWS mode deny-policy propagation is asynchronous.

## What cannot be demonstrated in this local setup

- Real AWS resource inspection, deployment/database operations, live STS identity, AWS console federation, target-account IAM permission enforcement, and live AWS revocation propagation: credentials are simulated. Reviewed AWS catalog/infrastructure and mocked contract tests do not constitute live execution evidence.
- CloudTrail correlation with actual AWS activity: deliberately disabled in demo mode.
- External DynamoDB archive/deletion detection: no archive configured. Local HMAC and append-only database enforcement are available; do not claim WORM/DynamoDB archiving was demonstrated.
- Company SSO: no OIDC client configured. The endpoints exist but SSO is not available here.
- SMTP email delivery and external Jira/ServiceNow verification: providers are not configured. Internal notifications and ticket syntax validation work; demo ticket references are not validated against real tickets.
- Emergency/break-glass access: no implemented special workflow or bypass. Do not relabel the AdministratorAccess role or local operator account recovery as break-glass authorization.
- Real AWS resource browsing: there is a trusted account/role catalog, not a resource explorer.
- Chika login: no known existing plaintext credential; password was not recovered or reset.
- PostgreSQL concurrency integration tests need a disposable TEST_POSTGRES_URL; default development uses existing SQLite.

## Changes and operation

- Code source changed: `backend/app/main.py` — two seed full_name strings only. Existing frontend/authentication/authorization code was not changed.
- Existing database records changed: alex.dev full_name Alex Rivera → Ebuka Rivera; sarah.sec full_name Sarah Chen → Amara Chen. Every other column was asserted unchanged during this transaction.
- Added supported demo data: demo.security user; request, approval, session, notification, rate-limit and audit records from real workflows. Its role/active/grants/recovery/password/MFA lifecycle was tested through APIs; final state is active REQUESTER, no grants, MFA enabled, password Demo-project-123!. Main users' roles/passwords/MFA/grants were not altered.
- Backup: `backend/data/backups/before-project-demo-20261005-223244.db`, before name/demo changes. Existing key file remains in place; no restore was performed.
- Guide and verification report: `docs/project-demo-guide.md`, `docs/project-demo-verification.json`.
- Authentic browser captures: `docs/demo-screenshots/`. These are actual app screenshots, not mockups; the filenames describe the view and are independent of the full suggested screenshot numbering.
- Build/test outputs: existing frontend build generates `frontend/dist/`; existing Playwright tests generate `frontend/test-results/`. Temporary isolated test databases/scripts are under `/tmp`; they are not the application database.

Intended startup from the project root, if services stop:

```bash
cd backend
.venv/bin/python -m uvicorn app.main:app --reload --port 8000
```

In a separate terminal:

```bash
cd frontend
npm run dev
```

The existing SQLite database has no separate daemon. Worker mode is embedded and needs no separate worker process. Development settings and local keys already exist; no .env changes were required. Frontend uses relative `/api`, proxied to `http://127.0.0.1:8000`; localhost and 127.0.0.1:3000 are allowed origins. This is local development, not production deployment.

Services left running and final verification counts are recorded in `project-demo-verification.json`. The temporary Docker Playwright server on port 3333 is a test aid, not an application dependency. Isolated test servers use 8001/3001 and stop when the suite finishes. After completion, no additional application/data changes will be made without further instruction; running worker/polling activity continues normally, including session expiration and rate-bucket cleanup.

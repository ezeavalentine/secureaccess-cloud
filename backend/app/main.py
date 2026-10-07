import logging
import threading
from datetime import datetime, timedelta
from contextlib import asynccontextmanager
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from starlette.middleware.sessions import SessionMiddleware
from sqlalchemy.exc import IntegrityError, OperationalError
from app.config import settings
from app.models import SessionLocal, engine, User, Entitlement, WorkerState
from app.models.database import transaction, read_snapshot
from app.services import get_password_hash, audit_service, session_service
from app.aws.sts_service import AWSOperationError
from app.services.client_identity import client_ip
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("secureaccess")

def migrate():
    from alembic.config import Config
    from alembic import command
    from pathlib import Path
    base = Path(__file__).resolve().parents[1]
    config = Config(str(base / "alembic.ini"))
    config.set_main_option("script_location", str(base / "migrations"))
    config.set_main_option("sqlalchemy.url", settings.DATABASE_URL.replace("%", "%%"))
    command.upgrade(config, "head")

def seed_demo_users():
    if not settings.DEMO_MODE: return
    with SessionLocal() as db, transaction(db):
        for username, role, name, dept in [("alex.dev", "REQUESTER", "Ebuka Rivera", "Engineering"), ("sarah.sec", "APPROVER", "Amara Chen", "Security Operations"), ("admin.sys", "SECURITY_ADMIN", "System Administrator", "IT Security"), ("audit.user", "AUDITOR", "Audit Lead", "Internal Audit")]:
            if not db.query(User).filter_by(username=username).first():
                user = User(username=username, email=f"{username}@secureaccess.io", full_name=name, department=dept, role=role, hashed_password=get_password_hash("Password123!"))
                db.add(user)
                db.flush()
                audit_service.log_event(db, "DEMO_USER_SEEDED", "SYSTEM", f"user:{user.id}", {"username": username, "role": role})
            user = db.query(User).filter_by(username=username).first()
            from app.models import AuditLog
            seeded = db.query(AuditLog).filter_by(event_type="DEMO_GRANTS_SEEDED", target_resource=f"user:{user.id}").first()
            if not seeded and user.role != "AUDITOR":
                from app.aws.iam_service import iam_service
                for account in settings.accounts():
                    for catalog_role in iam_service.list_available_roles(db):
                        if account["environment"] in catalog_role["allowed_environments"]:
                            db.add(Entitlement(user_id=user.id, aws_account_id=account["id"], iam_role=catalog_role["role_name"], max_duration_minutes=catalog_role["max_duration_minutes"]))
                audit_service.log_event(db, "DEMO_GRANTS_SEEDED", "SYSTEM", f"user:{user.id}", {})

def worker(app, stop):
    from app.worker import run
    run(SessionLocal, stop)

@asynccontextmanager
async def lifespan(app):
    settings.initialize_keys()
    if settings.AUTO_MIGRATE: migrate()
    seed_demo_users()
    with SessionLocal() as db, read_snapshot(db):
        if not audit_service.verify_chain_integrity(db): raise RuntimeError("Audit chain verification failed; investigate before starting")
    app.state.worker_status = "HEALTHY"
    stop = threading.Event()
    thread = threading.Thread(target=worker, args=(app, stop), name="session-worker", daemon=True)
    if settings.WORKER_MODE == "embedded": thread.start()
    try: yield
    finally:
        stop.set()
        if thread.is_alive(): thread.join(timeout=30)
        engine.dispose()

app = FastAPI(title=settings.PROJECT_NAME, version=settings.VERSION, lifespan=lifespan)
app.add_middleware(CORSMiddleware, allow_origins=settings.ALLOWED_ORIGINS, allow_credentials=True, allow_methods=["GET", "POST", "PATCH"], allow_headers=["Content-Type", "Authorization", "X-SecureAccess-CSRF", "Idempotency-Key"])
# SessionMiddleware stores only OIDC state, never AWS credentials or access tokens.
# The signing secret is resolved on request after lifespan initialization.
class OIDCSessionMiddleware:
    def __init__(self, app): self.app = app; self.middleware = None
    async def __call__(self, scope, receive, send):
        if scope["type"] == "lifespan":
            await self.app(scope, receive, send)
            return
        if self.middleware is None:
            self.middleware = SessionMiddleware(self.app, secret_key=settings.SECRET_KEY, session_cookie="secureaccess_oidc", same_site="lax", https_only=settings.COOKIE_SECURE)
        await self.middleware(scope, receive, send)
app.add_middleware(OIDCSessionMiddleware)

@app.middleware("http")
async def security(request: Request, call_next):
    response = None
    if request.method in ["POST", "PATCH", "DELETE", "PUT"]:
        origin = request.headers.get("origin")
        if (origin and origin not in settings.ALLOWED_ORIGINS) or request.headers.get("X-SecureAccess-CSRF") != "1":
            response = JSONResponse({"detail": "CSRF validation failed"}, status_code=403)
    if response is None and request.method in ["POST", "PATCH", "DELETE", "PUT"]:
        from app.services.rate_limit_service import allow
        category = "login" if request.url.path.endswith("/auth/login") else "write"
        try:
            with SessionLocal() as db:
                permitted = allow(db, client_ip(request), category, 10 if category == "login" else 60)
            if not permitted:
                response = JSONResponse({"detail": "Rate limit exceeded; try again in one minute"}, status_code=429, headers={"Retry-After": "60"})
        except Exception:
            logger.exception("Rate-limit database unavailable")
            response = JSONResponse({"detail": "Authentication service temporarily unavailable"}, status_code=503)
    if response is None: response = await call_next(request)
    if response.status_code == 403 and getattr(request.state, "user", None) and request.headers.get("X-SecureAccess-CSRF") == "1":
        try:
            with SessionLocal() as db, transaction(db):
                audit_service.log_event(db, "AUTHORIZATION_DENIED", request.state.user.username, request.url.path, {"method": request.method}, ip_address=client_ip(request))
        except Exception: logger.exception("Could not audit authorization denial")
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["Cache-Control"] = "no-store"
    if settings.COOKIE_SECURE: response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
    return response

@app.exception_handler(ValueError)
async def validation_error(request, exc): return JSONResponse({"detail": str(exc)}, status_code=400)
@app.exception_handler(AWSOperationError)
async def aws_error(request, exc):
    logger.error("AWS operation failed: %s", exc)
    return JSONResponse({"detail": str(exc)}, status_code=502)
@app.exception_handler(IntegrityError)
async def conflict(request, exc): return JSONResponse({"detail": "Operation conflicts with an existing record"}, status_code=409)
@app.exception_handler(OperationalError)
async def database_unavailable(request, exc):
    logger.exception("Database operation failed")
    return JSONResponse({"detail": "Database temporarily unavailable"}, status_code=503)

from app.routes import auth_router, request_router, approval_router, session_router, audit_router, user_router
from app.routes.system_routes import router as system_router
for router in [auth_router, request_router, approval_router, session_router, audit_router, user_router, system_router]: app.include_router(router, prefix=settings.API_PREFIX)
@app.get("/")
def root(): return {"status": "ONLINE", "service": settings.PROJECT_NAME, "version": settings.VERSION, "demo_mode": settings.DEMO_MODE}
@app.get("/api/health")
def health(): return {"status": "ok", "demo_mode": settings.DEMO_MODE, "sso_enabled": bool(settings.OIDC_CLIENT_ID)}

@app.get("/api/ready")
def ready():
    try:
        with SessionLocal() as db, read_snapshot(db):
            state = db.get(WorkerState, 1)
            if not state or not state.heartbeat or state.heartbeat < datetime.utcnow() - timedelta(seconds=90) or state.status not in ["HEALTHY", "RUNNING", "RETRYING_REVOCATIONS"]:
                return JSONResponse({"status": "not_ready", "reason": "Session worker unavailable"}, status_code=503)
            if not audit_service.verify_chain_integrity(db):
                return JSONResponse({"status": "not_ready", "reason": "Audit integrity check failed"}, status_code=503)
        return {"status": "ready"}
    except Exception:
        logger.exception("Readiness check failed")
        return JSONResponse({"status": "not_ready", "reason": "Database unavailable"}, status_code=503)

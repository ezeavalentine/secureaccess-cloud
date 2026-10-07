from app.routes.auth_routes import router as auth_router
from app.routes.request_routes import router as request_router
from app.routes.approval_routes import router as approval_router
from app.routes.session_routes import router as session_router
from app.routes.audit_routes import router as audit_router
from app.routes.user_routes import router as user_router

__all__ = [
    "auth_router",
    "request_router",
    "approval_router",
    "session_router",
    "audit_router",
    "user_router"
]

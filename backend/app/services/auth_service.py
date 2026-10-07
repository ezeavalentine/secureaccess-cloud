from datetime import datetime, timedelta, timezone
import hashlib
import secrets
import jwt
from pwdlib import PasswordHash
from fastapi import Depends, HTTPException, Request
from app.config import settings
from app.models import User, get_db
password_hash = PasswordHash.recommended()
DUMMY_HASH = password_hash.hash(secrets.token_urlsafe(32))
def get_password_hash(password): return password_hash.hash(password)
def verify_password(password, hashed):
    try: return password_hash.verify(password, hashed)
    except Exception: return False

def create_access_token(user, mfa=False):
    now = datetime.now(timezone.utc)
    return jwt.encode({"sub": user.id, "ver": user.token_version, "mfa": mfa, "iat": now, "exp": now + timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES), "jti": secrets.token_hex(16), "iss": "secureaccess", "aud": "secureaccess-ui"}, settings.SECRET_KEY, algorithm="HS256")

def get_current_user(request: Request, db=Depends(get_db)):
    token = request.cookies.get("secureaccess_session")
    if not token and request.headers.get("Authorization", "").startswith("Bearer "):
        token = request.headers["Authorization"][7:]
    try:
        payload = jwt.decode(token or "", settings.SECRET_KEY, algorithms=["HS256"], issuer="secureaccess", audience="secureaccess-ui", options={"require": ["exp", "iat", "sub", "ver", "jti"]})
        user = db.get(User, payload["sub"])
        if not user or not user.is_active or user.token_version != payload["ver"]: raise ValueError()
    except (jwt.InvalidTokenError, ValueError): raise HTTPException(401, "Authentication required")
    if user.sessions_revocation_pending: raise HTTPException(403, "AWS session revocation is pending; contact your administrator")
    request.state.user = user
    request.state.mfa = payload.get("mfa", False)
    request.state.token_version = payload["ver"]
    recovery_paths = {settings.API_PREFIX + path for path in ["/auth/me", "/auth/password", "/auth/logout"]}
    if user.must_change_password and request.url.path not in recovery_paths:
        raise HTTPException(403, "Change your temporary password before continuing")
    return user

def require_roles(*roles):
    def dependency(request: Request, user=Depends(get_current_user)):
        if user.role not in roles: raise HTTPException(403, "Insufficient permissions")
        if user.must_change_password: raise HTTPException(403, "Change your temporary password before continuing")
        if settings.REQUIRE_APPROVER_MFA and not settings.DEMO_MODE and user.role in ["APPROVER", "SECURITY_ADMIN"] and not request.state.mfa:
            raise HTTPException(403, "MFA verification is required for privileged actions")
        return user
    return dependency

def set_session_cookie(response, user, mfa=False):
    response.set_cookie("secureaccess_session", create_access_token(user, mfa), httponly=True, secure=settings.COOKIE_SECURE, samesite="strict", max_age=settings.ACCESS_TOKEN_EXPIRE_MINUTES * 60, path="/")

def ip_address(request):
    from app.services.client_identity import client_ip
    return client_ip(request)

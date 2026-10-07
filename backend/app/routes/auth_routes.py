import time
import secrets
import pyotp
from fastapi import APIRouter, Depends, HTTPException, Request, Response
from sqlalchemy import or_
from app.models import User, get_db
from app.models.database import transaction
from app.schemas import LoginRequest, Token, UserOut, PasswordChange, OTP, RecoveryCodesRequest, MFASetupRequest
from app.services.auth_service import get_current_user, get_password_hash, verify_password, DUMMY_HASH, set_session_cookie, ip_address
from app.services.audit_service import audit_service
from app.services.crypto import encrypt, decrypt
from app.config import settings
from app.services.recovery_service import generate_codes, consume_code
router = APIRouter(prefix="/auth", tags=["Authentication"])

def verify_otp(user, otp):
    if not user.mfa_enabled or not user.mfa_secret: return False
    step = int(time.time()) // 30
    if user.last_totp_step is not None and user.last_totp_step >= step: return False
    if not pyotp.TOTP(decrypt(user.mfa_secret)).verify(otp or "", valid_window=0): return False
    user.last_totp_step = step
    return True

@router.post("/login", response_model=Token)
def login(data: LoginRequest, request: Request, response: Response, db=Depends(get_db)):
    from app.services.rate_limit_service import allow
    if not allow(db, data.username, "login-account", 10):
        raise HTTPException(429, "Too many sign-in attempts for this account; try again in one minute", headers={"Retry-After": "60"})
    failure = None
    with transaction(db, request=request):
        user = db.query(User).filter_by(username=data.username).with_for_update().first()
        valid = verify_password(data.password, user.hashed_password if user else DUMMY_HASH)
        if not user or not valid or not user.is_active:
            failure = "Invalid credentials"
        elif user.mfa_enabled and not (verify_otp(user, data.otp) or consume_code(user, data.recovery_code)):
            failure = "A valid, unused MFA code is required"
        audit_service.log_event(db, "LOGIN_FAILED" if failure else "LOGIN_SUCCEEDED", data.username, "authentication", {"result": "denied" if failure else "success"}, ip_address=ip_address(request))
    if failure: raise HTTPException(401, failure)
    set_session_cookie(response, user, user.mfa_enabled)
    return {"username": user.username, "role": user.role, "expires_in": settings.ACCESS_TOKEN_EXPIRE_MINUTES * 60, "demo_mode": settings.DEMO_MODE}

@router.get("/me", response_model=UserOut)
def me(user=Depends(get_current_user)): return user

@router.post("/logout")
def logout(request: Request, response: Response, user=Depends(get_current_user), db=Depends(get_db)):
    user_id = user.id
    with transaction(db, request=request):
        user = db.get(User, user_id)
        user.token_version += 1
        audit_service.log_event(db, "LOGOUT", user.username, "authentication", {}, ip_address=ip_address(request))
    response.delete_cookie("secureaccess_session", path="/")
    return {"status": "SIGNED_OUT"}

@router.post("/password")
def change_password(data: PasswordChange, request: Request, response: Response, user=Depends(get_current_user), db=Depends(get_db)):
    user_id = user.id
    with transaction(db, request=request):
        user = db.get(User, user_id)
        if not verify_password(data.current_password, user.hashed_password): raise HTTPException(400, "Current password is incorrect")
        user.hashed_password = get_password_hash(data.new_password)
        user.must_change_password = False
        user.token_version += 1
        user.sessions_revocation_pending = True
        audit_service.log_event(db, "PASSWORD_CHANGED", user.username, f"user:{user.id}", {}, ip_address=ip_address(request))
    from app.services.session_service import session_service
    session_service.revoke_user_sessions(db, user_id, user.username, ip_address(request))
    response.delete_cookie("secureaccess_session", path="/")
    return {"status": "PASSWORD_CHANGED", "message": "Sign in again"}

@router.post("/mfa/setup")
def setup_mfa(data: MFASetupRequest, request: Request, user=Depends(get_current_user), db=Depends(get_db)):
    user_id = user.id
    with transaction(db, request=request):
        user = db.get(User, user_id)
        if user.mfa_enabled: raise HTTPException(400, "MFA is already enabled")
        if not verify_password(data.current_password, user.hashed_password): raise HTTPException(400, "Current password is incorrect")
        secret = pyotp.random_base32()
        user.mfa_secret = encrypt(secret)
        audit_service.log_event(db, "MFA_ENROLLMENT_STARTED", user.username, f"user:{user.id}", {}, ip_address=ip_address(request))
    return {"secret": secret, "provisioning_uri": pyotp.TOTP(secret).provisioning_uri(name=user.username, issuer_name="SecureAccess Cloud")}

@router.post("/mfa/enable")
def enable_mfa(data: OTP, request: Request, response: Response, user=Depends(get_current_user), db=Depends(get_db)):
    user_id = user.id
    with transaction(db, request=request):
        user = db.get(User, user_id)
        if user.mfa_enabled or not user.mfa_secret or not pyotp.TOTP(decrypt(user.mfa_secret)).verify(data.otp): raise HTTPException(400, "Invalid enrollment code")
        user.mfa_enabled = True
        user.last_totp_step = int(time.time()) // 30
        user.token_version += 1
        codes = generate_codes(user)
        audit_service.log_event(db, "MFA_ENABLED", user.username, f"user:{user.id}", {}, ip_address=ip_address(request))
    set_session_cookie(response, user, True)
    return {"status": "MFA_ENABLED", "recovery_codes": codes}

@router.post("/mfa/recovery-codes")
def recovery_codes(data: RecoveryCodesRequest, request: Request, user=Depends(get_current_user), db=Depends(get_db)):
    user_id = user.id
    with transaction(db, request=request):
        user = db.get(User, user_id)
        if not verify_password(data.current_password, user.hashed_password) or not verify_otp(user, data.otp):
            raise HTTPException(400, "Current password and an unused authenticator code are required")
        codes = generate_codes(user)
        audit_service.log_event(db, "MFA_RECOVERY_CODES_ROTATED", user.username, f"user:{user.id}", {}, ip_address=ip_address(request))
    return {"recovery_codes": codes}

@router.post("/mfa/verify")
def verify_mfa(data: OTP, request: Request, response: Response, user=Depends(get_current_user), db=Depends(get_db)):
    user_id = user.id
    with transaction(db, request=request):
        user = db.get(User, user_id)
        if not verify_otp(user, data.otp): raise HTTPException(400, "Invalid or previously used MFA code")
        audit_service.log_event(db, "MFA_VERIFIED", user.username, f"user:{user.id}", {}, ip_address=ip_address(request))
    set_session_cookie(response, user, True)
    return {"status": "MFA_VERIFIED"}

@router.get("/sso")
async def sso_start(request: Request):
    if not settings.OIDC_CLIENT_ID: raise HTTPException(503, "SSO is not configured")
    from app.services.oidc_service import oauth
    return await oauth.company.authorize_redirect(request, settings.PUBLIC_URL + "/api/auth/sso/callback")

@router.get("/sso/callback")
async def sso_callback(request: Request, db=Depends(get_db)):
    from fastapi.responses import RedirectResponse
    from app.services.oidc_service import oauth
    if not settings.OIDC_CLIENT_ID: raise HTTPException(503, "SSO is not configured")
    try:
        token = await oauth.company.authorize_access_token(request)
        claims = token.get("userinfo", {})
        if claims.get("email_verified") is not True: raise ValueError("Unverified email")
        user = db.query(User).filter(User.email == claims.get("email"), User.is_active == True).first()
        if not user: raise ValueError("User must be pre-provisioned")
    except Exception: raise HTTPException(401, "SSO failed or user is not provisioned")
    with transaction(db, request=request):
        from sqlalchemy import select
        user = db.execute(select(User).where(User.id == user.id).with_for_update()).scalar_one()
        if not user.is_active or user.sessions_revocation_pending: raise HTTPException(401, "User is no longer eligible for sign-in")
        audit_service.log_event(db, "SSO_LOGIN", user.username, "authentication", {}, ip_address=ip_address(request))
    response = RedirectResponse(settings.PUBLIC_URL, status_code=303)
    # The local MFA requirement remains; do not trust arbitrary IdP amr claims.
    set_session_cookie(response, user, False)
    return response

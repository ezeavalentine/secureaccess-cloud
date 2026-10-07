"""Administrative commands; run from backend/."""
import argparse
import getpass
import json
import os
import sqlite3
from datetime import datetime
from pathlib import Path
from app.config import settings
from app.models import SessionLocal, User, Entitlement
from app.models.database import transaction
from app.services import get_password_hash, audit_service
from app.main import migrate

def main():
    parser = argparse.ArgumentParser()
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("migrate")
    admin = sub.add_parser("create-admin")
    admin.add_argument("--username", required=True)
    admin.add_argument("--email", required=True)
    backup = sub.add_parser("backup")
    backup.add_argument("destination")
    verify = sub.add_parser("verify-audit")
    grant = sub.add_parser("grant-access")
    grant.add_argument("--username", required=True)
    grant.add_argument("--account-id", required=True)
    grant.add_argument("--role", required=True)
    grant.add_argument("--minutes", type=int, required=True)
    recovery = sub.add_parser("recover-user")
    recovery.add_argument("--username", required=True)
    recovery.add_argument("--reason", required=True)
    recovery.add_argument("--reset-mfa", action="store_true")
    recovery.add_argument("--reset-password", action="store_true")
    args = parser.parse_args()
    settings.initialize_keys()
    if args.command == "migrate": migrate()
    elif args.command == "create-admin":
        from app.schemas import UserCreate
        password = getpass.getpass("Administrator password (minimum 12 characters): ")
        data = UserCreate(username=args.username, email=args.email, full_name="Administrator", role="SECURITY_ADMIN", password=password, department="Security")
        migrate()
        with SessionLocal() as db, transaction(db):
            if db.query(User).filter_by(username=data.username).first(): raise SystemExit("User already exists")
            user = User(**data.model_dump(exclude={"password"}), hashed_password=get_password_hash(password))
            db.add(user);db.flush()
            audit_service.log_event(db,"ADMIN_BOOTSTRAPPED","LOCAL_OPERATOR",f"user:{user.id}",{"username":user.username})
        print("Administrator created. Enroll MFA before performing live privileged actions.")
    elif args.command == "grant-access":
        from app.schemas import EntitlementCreate
        from app.aws.iam_service import iam_service
        data = EntitlementCreate(aws_account_id=args.account_id, iam_role=args.role, max_duration_minutes=args.minutes)
        with SessionLocal() as db, transaction(db):
            user = db.query(User).filter_by(username=args.username).with_for_update().first()
            if not user or user.role == "AUDITOR": raise SystemExit("An eligible provisioned user is required")
            account, role = iam_service.account(args.account_id), iam_service.role(args.role, db)
            if account["environment"] not in role["allowed_environments"] or args.minutes > role["max_duration_minutes"]:
                raise SystemExit("Grant exceeds reviewed role policy")
            if db.get(Entitlement, (user.id, args.account_id, args.role)):
                raise SystemExit("Grant already exists; use the administrator UI to update it")
            db.add(Entitlement(user_id=user.id, **data.model_dump()))
            audit_service.log_event(db, "ENTITLEMENT_GRANTED", "LOCAL_OPERATOR", f"user:{user.id}", data.model_dump())
        print("Access grant created")
    elif args.command == "recover-user":
        from app.schemas import AccountRecovery
        from app.services.session_service import session_service
        if not args.reset_mfa and not args.reset_password: raise SystemExit("Select --reset-mfa and/or --reset-password")
        password = getpass.getpass("Temporary password: ") if args.reset_password else None
        data = AccountRecovery(reason=args.reason, temporary_password=password, reset_mfa=args.reset_mfa)
        with SessionLocal() as db, transaction(db):
            user = db.query(User).filter_by(username=args.username).with_for_update().first()
            if not user: raise SystemExit("User not found")
            if data.temporary_password:
                user.hashed_password = get_password_hash(data.temporary_password)
                user.must_change_password = True
            if data.reset_mfa:
                user.mfa_enabled, user.mfa_secret, user.last_totp_step = False, None, None
                user.recovery_codes_json = "[]"
            user.token_version += 1
            user.sessions_revocation_pending = True
            audit_service.log_event(db, "ACCOUNT_RECOVERED", "LOCAL_OPERATOR", f"user:{user.id}", {"reason": data.reason, "password_reset": bool(password), "mfa_reset": data.reset_mfa})
            user_id = user.id
        with SessionLocal() as db: session_service.revoke_user_sessions(db, user_id, "LOCAL_OPERATOR")
        print("Recovery recorded; existing AWS sessions revoked or queued for retry")
    elif args.command == "backup":
        from sqlalchemy.engine import make_url
        url = make_url(settings.DATABASE_URL)
        if url.drivername != "sqlite": raise SystemExit("Use pg_dump and provider snapshots for PostgreSQL backups")
        destination = Path(args.destination)
        if destination.exists(): raise SystemExit("Backup destination already exists")
        with sqlite3.connect(url.database) as source:
            fd = os.open(destination, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600);os.close(fd)
            with sqlite3.connect(destination) as target: source.backup(target)
        print("Database backed up. Back up encryption/signing keys separately in a secure store.")
    else:
        from app.models.database import read_snapshot
        with SessionLocal() as db, read_snapshot(db):
            print(json.dumps({"valid":audit_service.verify_chain_integrity(db),"archive":audit_service.verify_external(db)},indent=2))
if __name__ == "__main__": main()

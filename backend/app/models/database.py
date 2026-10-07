from contextlib import contextmanager
from sqlalchemy import create_engine, event
from sqlalchemy.orm import declarative_base, sessionmaker
from app.config import settings
engine = create_engine(settings.DATABASE_URL, connect_args={"check_same_thread": False, "timeout": 30} if settings.DATABASE_URL.startswith("sqlite") else {}, pool_pre_ping=True)
if settings.DATABASE_URL.startswith("sqlite"):
    @event.listens_for(engine, "connect")
    def configure_sqlite(connection, record):
        connection.execute("PRAGMA foreign_keys=ON")
        connection.execute("PRAGMA busy_timeout=30000")
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine, expire_on_commit=False)
Base = declarative_base()

@contextmanager
def read_snapshot(db):
    """Read the chain, head, and export flags from one committed database view."""
    db.rollback()
    if db.bind.dialect.name == "sqlite":
        db.connection().exec_driver_sql("BEGIN")
    else:
        db.connection().exec_driver_sql("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY")
    try:
        yield
    finally:
        db.rollback()

def get_db():
    with SessionLocal() as db: yield db

@contextmanager
def transaction(db, request=None):
    # SQLite serializes writes. PostgreSQL uses domain row/advisory locks,
    # and the audit head is locked only while committing queued audit events.
    db.rollback()
    if db.bind.dialect.name == "sqlite":
        db.connection().exec_driver_sql("BEGIN IMMEDIATE")
    try:
        if request is not None and getattr(request.state, "user", None):
            from fastapi import HTTPException
            from app.models.user import User
            from sqlalchemy import select
            user = db.execute(select(User).where(User.id == request.state.user.id).with_for_update()).scalar_one_or_none()
            if not user or not user.is_active or user.sessions_revocation_pending or user.token_version != request.state.token_version:
                raise HTTPException(401, "Authentication changed; sign in again")
        yield
        from app.services.audit_service import audit_service
        audit_service.flush_pending(db)
        db.commit()
    except Exception:
        db.info.pop("audit_pending", None)
        db.rollback()
        raise

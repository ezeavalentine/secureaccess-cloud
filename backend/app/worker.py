"""Run separately with python -m app.worker when WORKER_MODE=external."""
import logging
import signal
import threading
import uuid
from datetime import datetime, timedelta
from sqlalchemy import select
from app.models import SessionLocal, WorkerState, User, RateBucket
from app.models.database import transaction
from app.services import audit_service, session_service
from app.services.notification_service import deliver_pending


def run_once(local, owner):
    now = datetime.utcnow()
    with local() as db, transaction(db):
        state = db.execute(select(WorkerState).where(WorkerState.id == 1).with_for_update()).scalar_one()
        if state.lease_until and state.lease_until > now and state.owner != owner: return
        state.owner, state.lease_until = owner, now + timedelta(minutes=5)
        state.status, state.heartbeat = "RUNNING", now
    status = "HEALTHY"
    try:
        with local() as db, transaction(db):
            session_service.check_and_expire_sessions(db)
            db.query(RateBucket).filter(RateBucket.updated_at < now - timedelta(minutes=5)).delete()
        with local() as db:
            ids = [u.id for u in db.query(User).filter_by(sessions_revocation_pending=True)]
            for user_id in ids: session_service.revoke_user_sessions(db, user_id)
            if db.query(User).filter_by(sessions_revocation_pending=True).count(): status = "RETRYING_REVOCATIONS"
        with local() as db: audit_service.archive_pending(db)
        with local() as db: deliver_pending(db)
    except Exception:
        status = "ERROR"
        logging.getLogger(__name__).exception("Worker cycle failed; retrying")
    finally:
        with local() as db, transaction(db):
            state = db.execute(select(WorkerState).where(WorkerState.id == 1).with_for_update()).scalar_one()
            if state.owner == owner:
                state.status, state.heartbeat = status, datetime.utcnow()
                state.lease_until = datetime.utcnow() + timedelta(seconds=30)


def run(local, stop):
    owner = str(uuid.uuid4())
    while not stop.is_set():
        try: run_once(local, owner)
        except Exception: logging.getLogger(__name__).exception("Worker database unavailable")
        stop.wait(10)
    try:
        with local() as db, transaction(db):
            state = db.execute(select(WorkerState).where(WorkerState.id == 1).with_for_update()).scalar_one()
            if state.owner == owner: state.lease_until = None
    except Exception: logging.getLogger(__name__).exception("Could not release worker lease")


if __name__ == "__main__":
    from app.config import settings
    settings.initialize_keys()
    stop = threading.Event()
    signal.signal(signal.SIGTERM, lambda *_: stop.set())
    signal.signal(signal.SIGINT, lambda *_: stop.set())
    run(SessionLocal, stop)

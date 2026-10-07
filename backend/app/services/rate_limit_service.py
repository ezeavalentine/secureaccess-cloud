import hashlib
import json
import time
from datetime import datetime
from app.models import RateBucket
from app.models.database import transaction


def allow(db, identity, category, limit):
    key = hashlib.sha256((identity + ":" + category).encode()).hexdigest()
    now = time.time()
    with transaction(db):
        if db.bind.dialect.name == "postgresql":
            from sqlalchemy import text
            db.execute(text("SELECT pg_advisory_xact_lock(hashtext(:key))"), {"key": "rate:" + key})
        bucket = db.get(RateBucket, key)
        entries = [stamp for stamp in json.loads(bucket.timestamps_json) if stamp > now - 60] if bucket else []
        permitted = len(entries) < limit
        if permitted: entries.append(now)
        if not bucket:
            bucket = RateBucket(key=key)
            db.add(bucket)
        bucket.timestamps_json, bucket.updated_at = json.dumps(entries), datetime.utcnow()
    return permitted

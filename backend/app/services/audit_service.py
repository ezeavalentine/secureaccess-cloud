import hashlib
import hmac
import json
from datetime import datetime
from sqlalchemy import select
from app.models import AuditLog, AuditHead, AuditExport
from app.config import settings
GENESIS = "0" * 64
class AuditService:
    def payload(self, log):
        return json.dumps({k: getattr(log, k).isoformat(timespec="microseconds") if k == "timestamp" else getattr(log, k) for k in ["id", "sequence", "previous_hash", "event_type", "actor", "target_resource", "details", "ip_address", "risk_score", "timestamp"]}, sort_keys=True, separators=(",", ":"))
    def sign(self, log): return hmac.new(settings.AUDIT_HMAC_KEY.encode(), self.payload(log).encode(), hashlib.sha256).hexdigest()
    def log_event(self, db, event_type, actor, target_resource, details, risk_score="LOW", ip_address="system"):
        import uuid
        entry = AuditLog(id=str(uuid.uuid4()), event_type=event_type, actor=actor, target_resource=target_resource, details=json.dumps(details, sort_keys=True, separators=(",", ":")), risk_score=risk_score, ip_address=ip_address, timestamp=datetime.utcnow())
        db.info.setdefault("audit_pending", []).append(entry)
        return entry

    def flush_pending(self, db):
        pending = db.info.pop("audit_pending", [])
        if not pending: return
        # Take the global chain lock only after network operations complete.
        # Domain locks still serialize competing approvals and role capacity.
        head = db.execute(select(AuditHead).where(AuditHead.id == 1).with_for_update()).scalar_one()
        for entry in pending:
            entry.sequence, entry.previous_hash = head.sequence + 1, head.signature
            entry.hash_signature = self.sign(entry)
            db.add(entry)
            head.sequence, head.signature = entry.sequence, entry.hash_signature
            db.flush()
            db.add(AuditExport(event_id=entry.id))
            db.flush()
    def verify_chain_integrity(self, db):
        # Capture a head and verify only that prefix. Later appends cannot make
        # a valid chain fail; callers needing export flags use read_snapshot.
        head = db.get(AuditHead, 1)
        if head is None: return False
        target_sequence, target_signature = head.sequence, head.signature
        if db.query(AuditLog).filter(AuditLog.sequence > target_sequence).first(): return False
        previous, sequence = GENESIS, 0
        for entry in db.query(AuditLog).filter(AuditLog.sequence <= target_sequence).order_by(AuditLog.sequence).yield_per(500):
            sequence += 1
            if entry.sequence != sequence or entry.previous_hash != previous or not hmac.compare_digest(entry.hash_signature, self.sign(entry)): return False
            previous = entry.hash_signature
        return target_sequence == sequence and hmac.compare_digest(target_signature, previous)
    def archive_pending(self, db):
        if not settings.AUDIT_DYNAMODB_TABLE: return
        import boto3
        table = boto3.resource("dynamodb", region_name=settings.AWS_REGION).Table(settings.AUDIT_DYNAMODB_TABLE)
        entries = db.query(AuditLog, AuditExport).join(AuditExport, AuditExport.event_id == AuditLog.id).filter(AuditExport.archived == False).order_by(AuditLog.sequence).limit(100).all()
        from botocore.exceptions import ClientError
        for entry, export in entries:
            item = {"event_id": entry.id, "timestamp": entry.timestamp.isoformat(), "sequence": entry.sequence, "actor": entry.actor, "payload": self.payload(entry), "signature": entry.hash_signature}
            try: table.put_item(Item=item, ConditionExpression="attribute_not_exists(event_id)")
            except ClientError as exc:
                if exc.response["Error"]["Code"] != "ConditionalCheckFailedException": raise
                if table.get_item(Key={"event_id": item["event_id"], "timestamp": item["timestamp"]}, ConsistentRead=True).get("Item") != item:
                    raise RuntimeError("External audit record does not match local record")
            export.archived = True
        db.commit()
    def verify_external(self, db):
        if not settings.AUDIT_DYNAMODB_TABLE: return {"status": "NOT_CONFIGURED", "limitation": "Local-only audit cannot prove absence of tail truncation by a database administrator"}
        import boto3
        table = boto3.resource("dynamodb", region_name=settings.AWS_REGION).Table(settings.AUDIT_DYNAMODB_TABLE)
        # Strongly consistent archive scan also detects records removed from the local tail.
        seen = set()
        args = {"ConsistentRead": True}
        while True:
            response = table.scan(**args)
            for item in response.get("Items", []):
                entry = db.get(AuditLog, item["event_id"])
                if not entry or item.get("timestamp") != entry.timestamp.isoformat() or item.get("payload") != self.payload(entry) or item.get("signature") != entry.hash_signature or entry.id in seen:
                    return {"status": "TAMPER_DETECTED"}
                seen.add(entry.id)
            if "LastEvaluatedKey" not in response: break
            args["ExclusiveStartKey"] = response["LastEvaluatedKey"]
        pending = db.query(AuditExport).filter(AuditExport.archived == False).count()
        expected = {row.event_id for row in db.query(AuditExport).filter_by(archived=True)}
        if not expected.issubset(seen):
            return {"status": "TAMPER_DETECTED", "missing_count": len(expected - seen)}
        if db.query(AuditExport).count() != db.query(AuditLog).count():
            return {"status": "TAMPER_DETECTED", "limitation": "Audit export tracking is incomplete"}
        return {"status": "SYNC_PENDING" if pending else "VERIFIED", "archived_count": len(seen), "pending_count": pending}
audit_service = AuditService()

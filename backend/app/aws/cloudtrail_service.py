import json
from datetime import datetime, timedelta, timezone
from app.config import settings
from app.aws.sts_service import sts_service, AWSOperationError


class CloudTrailService:
    def get_recent_trail_events(self, db, limit=15, account_id=None):
        if settings.DEMO_MODE:
            return {"mode": "demo", "events": [], "message": "AWS CloudTrail is unavailable in demo mode", "truncated": False}
        from app.aws.iam_service import iam_service
        accounts = [iam_service.account(account_id)] if account_id else settings.accounts()
        from app.models import ActiveSession
        cutoff = datetime.now(timezone.utc) - timedelta(hours=24)
        sessions = {(s.aws_account_id, s.aws_session_name): s for s in db.query(ActiveSession).filter(ActiveSession.expires_at >= cutoff.replace(tzinfo=None)).all()}
        events, seen, truncated = [], set(), False
        regions = settings.CLOUDTRAIL_REGIONS or [settings.AWS_REGION]
        try:
            for account in accounts:
                for region in regions:
                    client = sts_service.target_client(account['id'], 'cloudtrail', region=region)
                    args = {'StartTime': cutoff, 'MaxResults': 50}
                    for _ in range(settings.CLOUDTRAIL_MAX_PAGES):
                        response = client.lookup_events(**args)
                        for event in response.get('Events', []):
                            raw = json.loads(event['CloudTrailEvent'])
                            name = raw.get('userIdentity', {}).get('arn', '').rsplit('/', 1)[-1]
                            if raw.get('eventName') == 'AssumeRole': name = raw.get('requestParameters', {}).get('roleSessionName', name)
                            linked = sessions.get((account['id'], name))
                            identifier = (account['id'], event['EventId'])
                            if not linked or identifier in seen: continue
                            seen.add(identifier)
                            events.append({'event_id': event['EventId'], 'event_name': raw.get('eventName'), 'event_time': event['EventTime'].isoformat(),
                                'actor': linked.username, 'session_id': linked.id, 'request_id': linked.request_id, 'source_ip': raw.get('sourceIPAddress', 'unknown'),
                                'user_agent': raw.get('userAgent', 'unknown'), 'aws_region': raw.get('awsRegion'), 'aws_account_id': account['id'], 'status': raw.get('errorCode', 'Success')})
                        if not response.get('NextToken'): break
                        args['NextToken'] = response['NextToken']
                    else:
                        truncated = truncated or bool(response.get('NextToken'))
        except Exception as exc:
            raise AWSOperationError('CloudTrail lookup failed') from exc
        events.sort(key=lambda e: e['event_time'], reverse=True)
        return {'mode': 'aws', 'events': events[:limit], 'truncated': truncated or len(events) > limit,
            'regions': regions, 'message': 'Correlated management events from configured regions (last 24 hours); AWS delivery can be delayed'}


cloudtrail_service = CloudTrailService()

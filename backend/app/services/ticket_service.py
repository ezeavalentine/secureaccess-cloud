"""Verify references against explicitly configured providers; never follow redirects."""
import httpx
from app.config import settings
from app.aws.sts_service import AWSOperationError


def verify_ticket(reference):
    if settings.DEMO_MODE or not settings.TICKET_VERIFICATION_REQUIRED:
        return
    try:
        if reference.startswith("INC"):
            if not settings.SERVICENOW_URL: raise ValueError("ServiceNow verification is not configured")
            response = httpx.get(settings.SERVICENOW_URL.rstrip("/") + "/api/now/table/incident",
                params={"sysparm_query": "number=" + reference, "sysparm_fields": "number,active", "sysparm_limit": 1},
                auth=(settings.SERVICENOW_USERNAME, settings.SERVICENOW_PASSWORD), timeout=10, follow_redirects=False)
            if response.status_code == 200:
                rows = response.json().get("result", [])
                if rows and rows[0].get("number") == reference and str(rows[0].get("active")).lower() == "true": return
                raise ValueError("Incident does not exist or is closed")
        else:
            if not settings.JIRA_URL: raise ValueError("Jira verification is not configured")
            response = httpx.get(settings.JIRA_URL.rstrip("/") + "/rest/api/3/issue/" + reference,
                params={"fields": "status"}, auth=(settings.JIRA_USERNAME, settings.JIRA_TOKEN), timeout=10, follow_redirects=False)
            if response.status_code == 200:
                issue = response.json()
                if issue.get("key") == reference and issue.get("fields", {}).get("status", {}).get("statusCategory", {}).get("key") != "done": return
                raise ValueError("Ticket does not exist or is closed")
        if response.status_code == 404: raise ValueError("Ticket does not exist")
        raise AWSOperationError("Ticket provider could not verify the reference; access was not issued")
    except (httpx.HTTPError, KeyError) as exc:
        raise AWSOperationError("Ticket verification is temporarily unavailable") from exc

import pytest
from app.schemas import AccessRequestCreate
from app.services import policy_engine

def test_auto_approval_low_risk(payload):
    result = policy_engine.evaluate_request(AccessRequestCreate(**payload))
    assert result.risk_level == "LOW" and result.auto_approved

def test_critical_requires_two_approvals_and_ticket(payload):
    payload.update(aws_account_id="555444333222", aws_account_name="Prod-US-East-1", iam_role="JIT-Access-AdministratorAccess", duration_minutes=60, ticket_ref="SEC-9901")
    result = policy_engine.evaluate_request(AccessRequestCreate(**payload))
    assert result.risk_level == "CRITICAL" and not result.auto_approved
    assert result.requires_ticket and result.required_approvals == 2

@pytest.mark.parametrize("changes", [
    {"aws_account_id":"555444333222"},
    {"iam_role":"JIT-Access-Unknown"},
    {"aws_account_id":"999999999999"},
    {"iam_role":"JIT-Access-DBAdmin"},
    {"iam_role":"JIT-Access-AdministratorAccess", "duration_minutes":120},
])
def test_untrusted_policy_input_rejected(payload, changes):
    payload.update(changes)
    with pytest.raises(ValueError): policy_engine.evaluate_request(AccessRequestCreate(**payload))

def test_prod_readonly_is_not_auto_approved(payload):
    payload.update(aws_account_id="555444333222", aws_account_name="Prod-US-East-1")
    result = policy_engine.evaluate_request(AccessRequestCreate(**payload))
    assert not result.auto_approved and result.requires_ticket

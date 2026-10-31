import json

import pytest
import responses

from tests.conftest import SCIM

LEAVER = {
    "id": "U1",
    "userName": "o@mal.example",
    "groups": [
        {"value": "G1", "display": "Engineering"},
        {"value": "G2", "display": "Prod Secrets"},
        {"value": "G3", "display": "Owners"},
    ],
}


@responses.activate
def test_grant_vault_group_creates_user_and_adds_membership(op):
    responses.get(f"{SCIM}/scim/v2/Users", json={"Resources": []})
    responses.post(f"{SCIM}/scim/v2/Users", status=201, json={"id": "U9"})
    responses.get(f"{SCIM}/scim/v2/Groups", json={"Resources": [{"id": "G1", "displayName": "Engineering"}]})
    patch = responses.patch(f"{SCIM}/scim/v2/Groups/G1", status=204)

    out = op.grant_vault_group("a@mal.example", "Engineering", "Aisha", "Khan")

    assert out == {"user_id": "U9", "group": "Engineering", "user_created": True}
    body = json.loads(patch.calls[0].request.body)
    assert body["Operations"][0] == {"op": "add", "path": "members", "value": [{"value": "U9"}]}
    assert responses.calls[0].request.headers["Content-Type"] == "application/scim+json"


@responses.activate
def test_offboard_removes_groups_skips_protected_and_suspends(op):
    responses.get(f"{SCIM}/scim/v2/Users", json={"Resources": [LEAVER]})
    g1 = responses.patch(f"{SCIM}/scim/v2/Groups/G1", status=204)
    g2 = responses.patch(f"{SCIM}/scim/v2/Groups/G2", status=204)
    g3 = responses.patch(f"{SCIM}/scim/v2/Groups/G3", status=204)
    susp = responses.patch(f"{SCIM}/scim/v2/Users/U1", json={"active": False})

    out = op.offboard("o@mal.example")

    assert out["groups_removed"] == ["Engineering", "Prod Secrets"]
    assert out["needs_manual_review"] == ["Owners"]
    assert g3.call_count == 0 and g1.call_count == g2.call_count == 1
    assert json.loads(susp.calls[0].request.body)["Operations"][0]["value"] is False


@responses.activate
def test_offboard_still_suspends_when_a_group_removal_fails(op):
    responses.get(f"{SCIM}/scim/v2/Users", json={"Resources": [{**LEAVER, "groups": LEAVER["groups"][:2]}]})
    responses.patch(f"{SCIM}/scim/v2/Groups/G1", status=500, json={})
    responses.patch(f"{SCIM}/scim/v2/Groups/G2", status=204)
    susp = responses.patch(f"{SCIM}/scim/v2/Users/U1", json={})
    with pytest.raises(RuntimeError, match="group removal failed"):
        op.offboard("o@mal.example")
    assert susp.call_count == 1


@responses.activate
def test_offboard_unknown_user(op):
    responses.get(f"{SCIM}/scim/v2/Users", json={"Resources": []})
    with pytest.raises(LookupError):
        op.offboard("ghost@mal.example")

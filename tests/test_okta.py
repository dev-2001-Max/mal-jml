import json

import pytest
import responses

from jml.http import ApiError
from tests.conftest import OKTA

DUPLICATE = "login: An object with this field already exists in the current organization"
USER = {"id": "00u1", "status": "ACTIVE", "profile": {"login": "a@mal.example"}}


@responses.activate
def test_create_user_sends_profile_and_ssws_auth(okta):
    responses.post(f"{OKTA}/api/v1/users", json=USER)
    user = okta.create_user("Aisha", "Khan", "a@mal.example")
    req = responses.calls[0].request
    assert req.headers["Authorization"] == "SSWS t0ken"
    assert "activate=true" in req.url
    assert json.loads(req.body)["profile"]["login"] == "a@mal.example"
    assert user["_created"] is True


@responses.activate
def test_create_user_is_idempotent_on_existing_login(okta):
    responses.post(
        f"{OKTA}/api/v1/users",
        status=400,
        json={
            "errorCode": "E0000001",
            "errorCauses": [{"errorSummary": DUPLICATE}],
        },
    )
    responses.get(f"{OKTA}/api/v1/users/a%40mal.example", json=USER)
    user = okta.create_user("Aisha", "Khan", "a@mal.example")
    assert user["id"] == "00u1" and user["_created"] is False


@responses.activate
def test_add_user_to_group_resolves_exact_name(okta):
    responses.get(
        f"{OKTA}/api/v1/groups",
        json=[
            {"id": "g-mgr", "profile": {"name": "engineering-managers"}},
            {"id": "g-eng", "profile": {"name": "engineering"}},
        ],
    )
    put = responses.put(f"{OKTA}/api/v1/groups/g-eng/users/00u1", status=204)
    okta.add_user_to_group("00u1", okta.find_group("engineering")["id"])
    assert put.call_count == 1


@responses.activate
def test_find_group_missing_raises(okta):
    responses.get(f"{OKTA}/api/v1/groups", json=[])
    with pytest.raises(LookupError):
        okta.find_group("nope")


@responses.activate
def test_offboard_clears_sessions_then_suspends(okta):
    responses.get(f"{OKTA}/api/v1/users/a%40mal.example", json=USER)
    sess = responses.delete(f"{OKTA}/api/v1/users/00u1/sessions", status=204)
    susp = responses.post(f"{OKTA}/api/v1/users/00u1/lifecycle/suspend", json={})
    result = okta.offboard("a@mal.example")
    assert result["action"] == "suspended"
    assert "oauthTokens=true" in sess.calls[0].request.url
    order = [c.request.url for c in responses.calls]
    assert order.index(sess.calls[0].request.url) < order.index(susp.calls[0].request.url)


@responses.activate
def test_offboard_deactivates_non_active_user(okta):
    responses.get(f"{OKTA}/api/v1/users/a%40mal.example", json={**USER, "status": "STAGED"})
    responses.delete(f"{OKTA}/api/v1/users/00u1/sessions", status=204)
    deact = responses.post(f"{OKTA}/api/v1/users/00u1/lifecycle/deactivate", json={})
    assert okta.offboard("a@mal.example")["action"] == "deactivated"
    assert deact.call_count == 1


@responses.activate
def test_rate_limit_is_retried(okta):
    responses.get(f"{OKTA}/api/v1/users/x", status=429, headers={"Retry-After": "1"})
    responses.get(f"{OKTA}/api/v1/users/x", json=USER)
    assert okta.get_user("x")["id"] == "00u1"
    assert len(responses.calls) == 2


@responses.activate
def test_non_retryable_error_raises(okta):
    responses.get(f"{OKTA}/api/v1/users/x", status=403, json={"errorCode": "E0000006"})
    with pytest.raises(ApiError) as e:
        okta.get_user("x")
    assert e.value.status == 403

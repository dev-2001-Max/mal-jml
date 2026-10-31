import json

import pytest
import responses

from jml.gws import PartialFailure
from tests.conftest import GWS

EMAIL = "o@mal.example"


@responses.activate
def test_create_user_forces_password_change_and_never_returns_password(gws):
    responses.post(f"{GWS}/users", json={"id": "118", "primaryEmail": "a@mal.example"})
    out = gws.create_user("Aisha", "Khan", "a@mal.example", "/Engineering")
    body = json.loads(responses.calls[0].request.body)
    assert responses.calls[0].request.headers["Authorization"] == "Bearer gtoken"
    assert body["changePasswordAtNextLogin"] is True
    assert body["orgUnitPath"] == "/Engineering"
    assert len(body["password"]) >= 24
    assert "password" not in out


@responses.activate
def test_create_user_conflict_returns_existing(gws):
    responses.post(f"{GWS}/users", status=409, json={"error": {"code": 409}})
    responses.get(f"{GWS}/users/a%40mal.example", json={"id": "118"})
    assert gws.create_user("A", "K", "a@mal.example")["_created"] is False


@responses.activate
def test_revoke_all_tokens(gws):
    responses.get(
        f"{GWS}/users/o%40mal.example/tokens",
        json={
            "items": [{"clientId": "c1", "displayText": "Slack"}, {"clientId": "c2", "displayText": "Zoom"}]
        },
    )
    d1 = responses.delete(f"{GWS}/users/o%40mal.example/tokens/c1", status=204)
    d2 = responses.delete(f"{GWS}/users/o%40mal.example/tokens/c2", status=204)
    assert gws.revoke_all_tokens(EMAIL) == {"revoked": ["Slack", "Zoom"]}
    assert d1.call_count == d2.call_count == 1


@responses.activate
def test_revoke_continues_past_a_failed_token(gws):
    responses.get(
        f"{GWS}/users/o%40mal.example/tokens",
        json={"items": [{"clientId": "bad", "displayText": "Bad"}, {"clientId": "ok", "displayText": "Ok"}]},
    )
    responses.delete(f"{GWS}/users/o%40mal.example/tokens/bad", status=403, json={})
    ok = responses.delete(f"{GWS}/users/o%40mal.example/tokens/ok", status=204)
    with pytest.raises(PartialFailure) as e:
        gws.revoke_all_tokens(EMAIL)
    assert ok.call_count == 1
    assert e.value.succeeded == ["Ok"] and e.value.failed[0]["status"] == 403


@responses.activate
def test_no_tokens_is_success(gws):
    responses.get(f"{GWS}/users/o%40mal.example/tokens", json={"kind": "admin#directory#tokenList"})
    assert gws.revoke_all_tokens(EMAIL) == {"revoked": []}


@responses.activate
def test_sign_out(gws):
    so = responses.post(f"{GWS}/users/o%40mal.example/signOut", status=204)
    gws.sign_out(EMAIL)
    assert so.call_count == 1

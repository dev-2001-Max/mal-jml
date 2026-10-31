import json

import pytest

from jml.config import ConfigError, load_settings
from jml.http import MockSession, redact
from jml.models import Joiner, Leaver
from jml.workflow import build_clients, run_joiner, run_leaver


@pytest.fixture
def clients(settings):
    return build_clients(settings)


def test_joiner_end_to_end_mock(clients, settings):
    r = run_joiner(Joiner("Aisha", "Khan", "aisha.khan@mal.example"), clients, settings)
    assert r.ok, [s.detail for s in r.failures]
    assert [s.system for s in r.steps] == ["okta", "okta", "gws", "1password", "jamf", "alert"]
    jamf = next(s for s in r.steps if s.system == "jamf")
    assert jamf.data["enrollment_url"].startswith("https://mal-mock.jamfcloud.com/enroll")


def test_leaver_end_to_end_mock_writes_audit(clients, settings):
    r = run_leaver(Leaver("omar.haddad@mal.example"), clients, settings)
    assert r.ok
    assert r.steps[0].data["action"] == "suspended"
    assert r.steps[0].detail == "suspended (was ACTIVE)"
    line = json.loads(open(settings.audit_log).read().splitlines()[-1])
    assert line["flow"] == "leaver" and line["ok"] is True and line["run_id"] == r.run_id


def test_leaver_continues_after_a_system_fails(clients, settings):
    clients.okta.api.session = MockSession([])  # every Okta call -> 404
    r = run_leaver(Leaver("omar.haddad@mal.example"), clients, settings)
    assert not r.ok
    assert [s.system for s in r.failures] == ["okta"]
    assert any(s.system == "1password" and s.ok for s in r.steps)
    assert r.steps[-1].system == "alert" and r.steps[-1].ok


def test_joiner_skips_group_when_okta_user_fails(clients, settings):
    clients.okta.api.session = MockSession([])
    r = run_joiner(Joiner("A", "K", "a@mal.example"), clients, settings)
    skipped = r.steps[1]
    assert not skipped.ok and "skipped" in skipped.detail


def test_settings_auto_mode_uses_live_only_when_creds_present(monkeypatch):
    for k in ["OKTA_ORG_URL", "OKTA_API_TOKEN", "JML_MODE"]:
        monkeypatch.delenv(k, raising=False)
    monkeypatch.setenv("OKTA_ORG_URL", "https://x.okta.com")
    monkeypatch.setenv("OKTA_API_TOKEN", "t")
    s = load_settings(load_dotenv=False)
    assert s.mode["okta"] == "live"
    assert s.mode["jamf"] == "mock"


def test_settings_live_mode_fails_fast_without_creds(monkeypatch):
    monkeypatch.setenv("JML_MODE", "live")
    monkeypatch.delenv("OKTA_API_TOKEN", raising=False)
    with pytest.raises(ConfigError):
        load_settings(load_dotenv=False)


def test_settings_rejects_missing_gws_key_file(monkeypatch):
    monkeypatch.setenv("JML_MODE", "auto")
    monkeypatch.setenv("GWS_SERVICE_ACCOUNT_FILE", "/path/to/service-account.json")
    monkeypatch.setenv("GWS_ADMIN_SUBJECT", "admin@example.com")
    with pytest.raises(ConfigError, match="does not exist"):
        load_settings(load_dotenv=False)


def test_redact_hides_secrets():
    assert redact({"password": "x", "nested": [{"Authorization": "SSWS y"}], "ok": 1}) == {
        "password": "***",
        "nested": [{"Authorization": "***"}],
        "ok": 1,
    }

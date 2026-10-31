from unittest.mock import MagicMock, patch

import pytest
import requests
import responses

from jml.models import RunReport, StepResult
from jml.notify import Notifier, build_slack_payload

HOOK = "https://hooks.slack.test/services/T/B/X"


def report(ok=True):
    r = RunReport("leaver", "o@mal.example", {"okta": "live", "jamf": "mock"})
    r.finished_at = "2026-10-31T06:00:00+00:00"
    r.steps = [
        StepResult("okta", "clear sessions + suspend", True),
        StepResult("gws", "revoke OAuth tokens", ok, "" if ok else "1 token(s) not revoked"),
    ]
    return r


def test_slack_payload_contains_user_time_actions_and_failures():
    p = build_slack_payload(report(ok=False))
    text = str(p)
    assert "o@mal.example" in text and "2026-10-31T06:00:00" in text
    assert "revoke OAuth tokens" in text and "1 failure(s)" in text
    assert "Mocked systems: jamf" in text


@responses.activate
def test_send_posts_to_webhook():
    hook = responses.post(HOOK, body="ok")
    assert Notifier(slack_webhook_url=HOOK).send(report()) == {"channel": "slack"}
    assert hook.call_count == 1


@responses.activate
def test_falls_back_to_email_when_slack_fails():
    responses.post(HOOK, body=requests.ConnectionError("down"))
    n = Notifier(
        slack_webhook_url=HOOK,
        smtp_host="smtp.test",
        email_to="sec@mal.example",
        email_from="jml@mal.example",
    )
    with patch("jml.notify.smtplib.SMTP") as smtp:
        server = MagicMock()
        smtp.return_value.__enter__.return_value = server
        out = n.send(report())
    assert out["channel"] == "email" and out["fallback_reason"]
    sent = server.send_message.call_args[0][0]
    assert "o@mal.example" in sent["Subject"]


@responses.activate
def test_slack_failure_without_fallback_raises():
    responses.post(HOOK, status=500)
    with pytest.raises(RuntimeError):
        Notifier(slack_webhook_url=HOOK).send(report())


def test_no_channels_configured_logs_mock():
    assert Notifier().send(report())["channel"] == "mock-log"

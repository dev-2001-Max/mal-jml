"""Joiner / Leaver orchestration.

Design rules:
* Every step is isolated — one failing system never stops the others. For a leaver,
  partial revocation is strictly better than none.
* Leaver order closes the widest door first: Okta sessions (kills SSO into everything)
  -> GWS tokens + cookies -> 1Password -> alert.
* Every run ends in the audit log and an alert that names failures explicitly.
"""

from __future__ import annotations

import logging
import os
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

from .audit import write_audit
from .config import Settings
from .gws import GwsClient, PartialFailure, service_account_token_provider
from .http import MockSession
from .mdm import JamfClient
from .models import Joiner, Leaver, RunReport, StepResult, utcnow
from .notify import Notifier
from .okta import OktaClient
from .onepassword import OnePasswordScimClient

log = logging.getLogger(__name__)


@dataclass
class Clients:
    okta: OktaClient
    gws: GwsClient
    onepassword: OnePasswordScimClient
    jamf: JamfClient
    notifier: Notifier


def build_clients(settings: Settings) -> Clients:
    env = os.environ.get
    m = settings.mode

    def mock(name: str) -> tuple[MockSession, str]:
        return MockSession.from_fixture(name)

    if m["okta"] == "live":
        okta = OktaClient(env("OKTA_ORG_URL"), env("OKTA_API_TOKEN"))
    else:
        s, base = mock("okta")
        okta = OktaClient(base, "mock-token", session=s)

    if m["gws"] == "live":
        tp = service_account_token_provider(env("GWS_SERVICE_ACCOUNT_FILE"), env("GWS_ADMIN_SUBJECT"))
        gws = GwsClient(tp)
    else:
        s, base = mock("gws")
        gws = GwsClient(lambda: "mock-token", base_url=base, session=s)

    if m["1password"] == "live":
        op = OnePasswordScimClient(env("OP_SCIM_BRIDGE_URL"), env("OP_SCIM_TOKEN"))
    else:
        s, base = mock("onepassword")
        op = OnePasswordScimClient(base, "mock-token", session=s)

    if m["jamf"] == "live":
        jamf = JamfClient(env("JAMF_URL"), env("JAMF_CLIENT_ID"), env("JAMF_CLIENT_SECRET"))
    else:
        s, base = mock("jamf")
        jamf = JamfClient(base, "mock-client", "mock-secret", session=s)

    notifier = Notifier(
        slack_webhook_url=env("SLACK_WEBHOOK_URL"),
        smtp_host=env("SMTP_HOST"),
        smtp_port=int(env("SMTP_PORT") or 587),
        smtp_user=env("SMTP_USER"),
        smtp_password=env("SMTP_PASSWORD"),
        email_from=env("ALERT_EMAIL_FROM"),
        email_to=env("ALERT_EMAIL_TO"),
    )
    return Clients(okta, gws, op, jamf, notifier)


def _step(report: RunReport, system: str, action: str, fn: Callable[[], Any]) -> Any:
    try:
        data = fn()
        detail = ""
        if isinstance(data, dict) and data.get("needs_manual_review"):
            detail = f"manual review: {data['needs_manual_review']}"
        report.steps.append(StepResult(system, action, True, detail, data or {}))
        return data
    except PartialFailure as e:
        report.steps.append(
            StepResult(system, action, False, str(e), {"succeeded": e.succeeded, "failed": e.failed})
        )
    except Exception as e:  # noqa: BLE001 — isolation is the point
        log.exception("%s/%s failed", system, action)
        report.steps.append(StepResult(system, action, False, f"{type(e).__name__}: {e}"))
    return None


def run_joiner(j: Joiner, c: Clients, settings: Settings, alert: bool = True) -> RunReport:
    r = RunReport("joiner", j.email, dict(settings.mode))

    user = _step(r, "okta", "create user", lambda: c.okta.create_user(j.first_name, j.last_name, j.email))
    if user:
        _step(
            r,
            "okta",
            f"add to group '{j.okta_group}'",
            lambda: c.okta.add_user_to_group(user["id"], c.okta.find_group(j.okta_group)["id"]),
        )
    else:
        r.steps.append(StepResult("okta", f"add to group '{j.okta_group}'", False, "skipped: no Okta user"))

    _step(
        r,
        "gws",
        "create user",
        lambda: c.gws.create_user(j.first_name, j.last_name, j.email, settings.gws_org_unit),
    )
    _step(
        r,
        "1password",
        f"grant vault group '{j.vault_group}'",
        lambda: c.onepassword.grant_vault_group(j.email, j.vault_group, j.first_name, j.last_name),
    )
    _step(r, "jamf", "send enrollment invitation", lambda: c.jamf.send_enrollment_invitation(j.email))
    return _finish(r, c, settings, alert)


def run_leaver(lv: Leaver, c: Clients, settings: Settings, alert: bool = True) -> RunReport:
    r = RunReport("leaver", lv.email, dict(settings.mode))
    verb = "deactivate" if lv.deactivate else "suspend"
    _step(r, "okta", f"clear sessions + {verb}", lambda: c.okta.offboard(lv.email, lv.deactivate))
    _step(r, "gws", "revoke OAuth tokens", lambda: c.gws.revoke_all_tokens(lv.email))
    _step(r, "gws", "sign out all sessions", lambda: c.gws.sign_out(lv.email))
    _step(r, "1password", "remove from groups + suspend", lambda: c.onepassword.offboard(lv.email))
    return _finish(r, c, settings, alert)


def _finish(r: RunReport, c: Clients, settings: Settings, alert: bool) -> RunReport:
    r.finished_at = utcnow()
    if alert:
        # The alert reports on the steps above; its own result is appended afterwards.
        snapshot = RunReport(r.flow, r.subject, r.mode, r.run_id, r.started_at, r.finished_at, list(r.steps))
        _step(r, "alert", "post summary", lambda: c.notifier.send(snapshot))
    write_audit(r, settings.audit_log)
    return r

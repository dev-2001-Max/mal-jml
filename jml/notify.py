"""Completion alert: Slack incoming webhook, with SMTP email as fallback."""

from __future__ import annotations

import logging
import smtplib
from dataclasses import dataclass
from email.message import EmailMessage
from typing import Any

import requests

from .models import RunReport

log = logging.getLogger(__name__)


def build_slack_payload(report: RunReport) -> dict:
    status = ":white_check_mark: completed" if report.ok else ":warning: completed with failures"
    lines = [
        f"{'✅' if s.ok else '❌'} *{s.system}* — {s.action}" + (f": {s.detail}" if s.detail else "")
        for s in report.steps
    ]
    fields = [
        {"type": "mrkdwn", "text": f"*User:*\n{report.subject}"},
        {"type": "mrkdwn", "text": f"*Run ID:*\n`{report.run_id}`"},
        {"type": "mrkdwn", "text": f"*Started:*\n{report.started_at}"},
        {"type": "mrkdwn", "text": f"*Finished:*\n{report.finished_at}"},
    ]
    blocks: list[dict[str, Any]] = [
        {"type": "header", "text": {"type": "plain_text", "text": f"JML {report.flow}: {report.subject}"}},
        {"type": "section", "text": {"type": "mrkdwn", "text": f"Status: {status}"}, "fields": fields},
        {"type": "section", "text": {"type": "mrkdwn", "text": "\n".join(lines) or "_no steps_"}},
    ]
    mocked = ", ".join(k for k, v in report.mode.items() if v == "mock") or "none"
    note = f"Mocked systems: {mocked}"
    if report.failures:
        note = f"*{len(report.failures)} failure(s) — manual follow-up required.* " + note
    blocks.append({"type": "context", "elements": [{"type": "mrkdwn", "text": note}]})
    return {"text": f"JML {report.flow} for {report.subject}: {status}", "blocks": blocks}


def build_email_body(report: RunReport) -> str:
    out = [
        f"JML {report.flow} — {report.subject}",
        f"Run ID: {report.run_id}",
        f"Started: {report.started_at}  Finished: {report.finished_at}",
        f"Result: {'OK' if report.ok else f'{len(report.failures)} FAILURE(S)'}",
        "",
    ]
    for s in report.steps:
        out.append(f"[{'OK ' if s.ok else 'FAIL'}] {s.system}: {s.action} {s.detail}".rstrip())
    return "\n".join(out)


@dataclass
class Notifier:
    slack_webhook_url: str | None = None
    smtp_host: str | None = None
    smtp_port: int = 587
    smtp_user: str | None = None
    smtp_password: str | None = None
    email_from: str | None = None
    email_to: str | None = None
    session: Any = None

    def send(self, report: RunReport) -> dict:
        errors = []
        if self.slack_webhook_url:
            try:
                resp = (self.session or requests).post(
                    self.slack_webhook_url, json=build_slack_payload(report), timeout=10
                )
                if resp.status_code == 200:
                    return {"channel": "slack"}
                errors.append(f"slack HTTP {resp.status_code}")
            except requests.RequestException as e:
                errors.append(f"slack {type(e).__name__}")
        if self.smtp_host and self.email_to:
            self._send_email(report)
            return {"channel": "email", "fallback_reason": errors or None}
        if errors:
            raise RuntimeError("; ".join(errors) + " and no email fallback configured")
        log.info("MOCK alert (no Slack/SMTP configured):\n%s", build_email_body(report))
        return {"channel": "mock-log"}

    def _send_email(self, report: RunReport) -> None:
        msg = EmailMessage()
        msg["Subject"] = f"[JML] {report.flow} {report.subject} — {'OK' if report.ok else 'FAILURES'}"
        msg["From"] = self.email_from or self.smtp_user
        msg["To"] = self.email_to
        msg.set_content(build_email_body(report))
        with smtplib.SMTP(self.smtp_host, self.smtp_port, timeout=15) as s:
            s.starttls()
            if self.smtp_user:
                s.login(self.smtp_user, self.smtp_password or "")
            s.send_message(msg)

"""Shared HTTP plumbing: one client used by every provider, in live and mock mode.

The same ``ApiClient`` code path runs against real APIs and against the fixture-backed
``MockSession``, so "mock mode" exercises request building, error handling and retries
rather than short-circuiting them.
"""

from __future__ import annotations

import json
import logging
import re
import time
from collections.abc import Callable, Iterable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

import requests

log = logging.getLogger(__name__)

RETRYABLE = {429, 500, 502, 503, 504}
SENSITIVE_KEYS = {"authorization", "password", "client_secret", "token", "access_token"}


class ApiError(Exception):
    def __init__(self, system: str, method: str, url: str, status: int, body: Any):
        self.system, self.method, self.url, self.status, self.body = (
            system,
            method,
            url,
            status,
            body,
        )
        super().__init__(f"{system} {method} {urlparse(url).path} -> HTTP {status}: {body}")


def redact(obj: Any) -> Any:
    """Recursively blank out secret-looking keys before anything is logged."""
    if isinstance(obj, dict):
        return {k: ("***" if k.lower() in SENSITIVE_KEYS else redact(v)) for k, v in obj.items()}
    if isinstance(obj, list):
        return [redact(v) for v in obj]
    return obj


class ApiClient:
    def __init__(
        self,
        system: str,
        base_url: str,
        auth_headers: Callable[[], dict[str, str]],
        session: Any = None,
        timeout: float = 15.0,
        max_retries: int = 3,
        sleep: Callable[[float], None] = time.sleep,
    ):
        self.system = system
        self.base_url = base_url.rstrip("/")
        self.auth_headers = auth_headers
        self.session = session or requests.Session()
        self.timeout = timeout
        self.max_retries = max_retries
        self.sleep = sleep

    def request(
        self,
        method: str,
        path: str,
        *,
        params: dict | None = None,
        json_body: Any = None,
        data: Any = None,
        headers: dict[str, str] | None = None,
        expected: Iterable[int] = (200, 201, 204),
        raw: bool = False,
    ) -> Any:
        url = path if path.startswith("http") else f"{self.base_url}{path}"
        merged = {**self.auth_headers(), **(headers or {})}
        resp = None
        for attempt in range(self.max_retries + 1):
            resp = self.session.request(
                method,
                url,
                params=params,
                json=json_body,
                data=data,
                headers=merged,
                timeout=self.timeout,
            )
            if resp.status_code in RETRYABLE and attempt < self.max_retries:
                delay = _retry_delay(resp, attempt)
                log.warning(
                    "%s %s %s -> %s, retry in %.1fs", self.system, method, url, resp.status_code, delay
                )
                self.sleep(delay)
                continue
            break

        if resp.status_code not in tuple(expected):
            raise ApiError(self.system, method, url, resp.status_code, _body(resp))
        if raw:
            return resp.text
        return _body(resp) if resp.content else None


def _retry_delay(resp: Any, attempt: int) -> float:
    retry_after = resp.headers.get("Retry-After")
    if retry_after and str(retry_after).isdigit():
        return min(float(retry_after), 30.0)
    # Okta sends an epoch reset time rather than Retry-After.
    reset = resp.headers.get("X-Rate-Limit-Reset")
    if reset and str(reset).isdigit():
        return max(0.0, min(float(reset) - time.time(), 30.0))
    return 0.5 * (2**attempt)


def _body(resp: Any) -> Any:
    try:
        return resp.json()
    except ValueError:
        return resp.text


# --------------------------------------------------------------------------- mocks


@dataclass
class MockResponse:
    status_code: int
    body: Any = None
    text_body: str | None = None
    headers: dict[str, str] = field(default_factory=dict)

    @property
    def text(self) -> str:
        if self.text_body is not None:
            return self.text_body
        return "" if self.body is None else json.dumps(self.body)

    @property
    def content(self) -> bytes:
        return self.text.encode()

    def json(self) -> Any:
        if self.body is None:
            raise ValueError("no JSON body")
        return self.body


class MockSession:
    """Drop-in for ``requests.Session`` that answers from a fixture route table.

    Every call is recorded (with secrets redacted) so the audit log shows exactly what
    payload would have been sent to the real API.
    """

    def __init__(self, routes: list[dict]):
        self.routes = [{**r, "_re": re.compile(r["path_regex"])} for r in routes]
        self.calls: list[dict] = []

    @classmethod
    def from_fixture(cls, name: str) -> tuple[MockSession, str]:
        path = Path(__file__).parent / "fixtures" / f"{name}.json"
        spec = json.loads(path.read_text())
        return cls(spec["routes"]), spec["base_url"]

    def request(self, method: str, url: str, **kwargs: Any) -> MockResponse:
        parsed = urlparse(url)
        self.calls.append(
            {
                "method": method,
                "path": parsed.path,
                "params": kwargs.get("params"),
                "json": redact(kwargs.get("json")),
                "data": "<redacted form/xml>" if kwargs.get("data") else None,
            }
        )
        query = f"{parsed.query} {kwargs.get('params') or ''}"
        for r in self.routes:
            if r.get("query_contains") and r["query_contains"] not in query:
                continue
            if r["method"] == method and r["_re"].fullmatch(parsed.path):
                return MockResponse(r.get("status", 200), r.get("body"), r.get("text"))
        return MockResponse(404, {"error": f"no mock route for {method} {parsed.path}"})

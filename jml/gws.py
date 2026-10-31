"""Google Workspace Admin SDK Directory API (users, tokens, signOut)."""

from __future__ import annotations

import secrets
from collections.abc import Callable
from typing import Any
from urllib.parse import quote

from .http import ApiClient, ApiError

BASE_URL = "https://admin.googleapis.com/admin/directory/v1"
SCOPES = [
    "https://www.googleapis.com/auth/admin.directory.user",
    "https://www.googleapis.com/auth/admin.directory.user.security",
]


def service_account_token_provider(sa_file: str, admin_subject: str) -> Callable[[], str]:
    """Domain-wide-delegated service account impersonating a GWS admin."""
    from google.auth.transport.requests import Request
    from google.oauth2 import service_account

    creds = service_account.Credentials.from_service_account_file(
        sa_file, scopes=SCOPES, subject=admin_subject
    )

    def token() -> str:
        if not creds.valid:
            creds.refresh(Request())
        return creds.token

    return token


class GwsClient:
    def __init__(self, token_provider: Callable[[], str], base_url: str = BASE_URL, **kwargs: Any):
        self.api = ApiClient(
            "gws",
            base_url,
            lambda: {"Authorization": f"Bearer {token_provider()}"},
            **kwargs,
        )

    def create_user(self, first: str, last: str, email: str, org_unit: str = "/") -> dict:
        """Create the mailbox with a throwaway random password.

        The password is never logged or returned: users sign in through Okta SSO, and
        changePasswordAtNextLogin covers break-glass direct login.
        """
        body = {
            "primaryEmail": email,
            "name": {"givenName": first, "familyName": last},
            "password": secrets.token_urlsafe(24),
            "changePasswordAtNextLogin": True,
            "orgUnitPath": org_unit,
        }
        try:
            user = self.api.request("POST", "/users", json_body=body)
            return {"id": user.get("id"), "primaryEmail": email, "_created": True}
        except ApiError as e:
            if e.status == 409:
                user = self.api.request("GET", f"/users/{quote(email)}")
                return {"id": user.get("id"), "primaryEmail": email, "_created": False}
            raise

    def list_tokens(self, email: str) -> list[dict]:
        resp = self.api.request("GET", f"/users/{quote(email)}/tokens") or {}
        return resp.get("items", [])

    def revoke_token(self, email: str, client_id: str) -> None:
        self.api.request(
            "DELETE",
            f"/users/{quote(email)}/tokens/{quote(client_id, safe='')}",
            expected=(204,),
        )

    def revoke_all_tokens(self, email: str) -> dict:
        """Revoke every third-party OAuth grant; one bad token must not stop the rest."""
        revoked, failed = [], []
        for t in self.list_tokens(email):
            cid = t["clientId"]
            try:
                self.revoke_token(email, cid)
                revoked.append(t.get("displayText") or cid)
            except ApiError as e:
                failed.append({"client": t.get("displayText") or cid, "status": e.status})
        if failed:
            raise PartialFailure(f"{len(failed)} token(s) not revoked", revoked, failed)
        return {"revoked": revoked}

    def sign_out(self, email: str) -> None:
        """Invalidate web and device sessions (cookies) — tokens alone leave these alive."""
        self.api.request("POST", f"/users/{quote(email)}/signOut", expected=(204,))


class PartialFailure(Exception):
    def __init__(self, msg: str, succeeded: list, failed: list):
        super().__init__(msg)
        self.succeeded, self.failed = succeeded, failed

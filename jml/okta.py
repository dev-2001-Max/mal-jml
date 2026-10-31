"""Okta Users / Groups / Lifecycle API (https://developer.okta.com/docs/api/)."""

from __future__ import annotations

from typing import Any
from urllib.parse import quote

from .http import ApiClient, ApiError


class OktaClient:
    def __init__(self, org_url: str, api_token: str, **kwargs: Any):
        self.api = ApiClient(
            "okta",
            org_url,
            lambda: {
                "Authorization": f"SSWS {api_token}",
                "Accept": "application/json",
                "Content-Type": "application/json",
            },
            **kwargs,
        )

    def create_user(self, first: str, last: str, email: str) -> dict:
        """Create and activate a user. Idempotent: an existing login is returned, not duplicated."""
        body = {"profile": {"firstName": first, "lastName": last, "email": email, "login": email}}
        try:
            user = self.api.request("POST", "/api/v1/users", params={"activate": "true"}, json_body=body)
            return {**user, "_created": True}
        except ApiError as e:
            if e.status == 400 and _already_exists(e.body):
                return {**self.get_user(email), "_created": False}
            raise

    def get_user(self, login: str) -> dict:
        return self.api.request("GET", f"/api/v1/users/{quote(login, safe='')}")

    def find_group(self, name: str) -> dict:
        groups = self.api.request("GET", "/api/v1/groups", params={"q": name}) or []
        for g in groups:
            if g.get("profile", {}).get("name", "").lower() == name.lower():
                return g
        raise LookupError(f"Okta group '{name}' not found")

    def add_user_to_group(self, user_id: str, group_id: str) -> None:
        self.api.request("PUT", f"/api/v1/groups/{group_id}/users/{user_id}", expected=(204,))

    def suspend_user(self, user_id: str) -> None:
        self.api.request("POST", f"/api/v1/users/{user_id}/lifecycle/suspend", expected=(200,))

    def deactivate_user(self, user_id: str) -> None:
        self.api.request("POST", f"/api/v1/users/{user_id}/lifecycle/deactivate", expected=(200,))

    def clear_sessions(self, user_id: str) -> None:
        """Kill all IdP sessions and Okta-issued OAuth tokens for the user."""
        self.api.request(
            "DELETE",
            f"/api/v1/users/{user_id}/sessions",
            params={"oauthTokens": "true"},
            expected=(204,),
        )

    def offboard(self, login: str, deactivate: bool = False) -> dict:
        """Sessions first (closes the live-session window), then lifecycle change.

        Suspend only works on ACTIVE users, so anything else is deactivated.
        """
        user = self.get_user(login)
        uid, status = user["id"], user.get("status")
        self.clear_sessions(uid)
        if deactivate or status != "ACTIVE":
            self.deactivate_user(uid)
            action = "deactivated"
        else:
            self.suspend_user(uid)
            action = "suspended"
        return {"user_id": uid, "previous_status": status, "action": action}


def _already_exists(body: Any) -> bool:
    if not isinstance(body, dict):
        return False
    causes = body.get("errorCauses") or []
    return any("already exists" in c.get("errorSummary", "") for c in causes)

"""1Password vault access via the 1Password SCIM Bridge (SCIM 2.0).

Why SCIM and not Connect/Events: the Connect API only reads/writes vault *items* and the
Events API is read-only audit data — neither can change who has access to a vault. In
1Password Business, vault access is granted to *groups*, and group membership plus user
suspension are exactly what the SCIM bridge exposes. See README "1Password" for detail.
"""

from __future__ import annotations

from typing import Any

from .http import ApiClient, ApiError

PATCH_OP = "urn:ietf:params:scim:api:messages:2.0:PatchOp"
USER_SCHEMA = "urn:ietf:params:scim:schemas:core:2.0:User"
# Built-in groups that SCIM cannot (and should not) strip automatically.
PROTECTED_GROUPS = {"Owners", "Recovery"}


class OnePasswordScimClient:
    def __init__(self, bridge_url: str, bearer_token: str, **kwargs: Any):
        self.api = ApiClient(
            "1password",
            bridge_url,
            lambda: {
                "Authorization": f"Bearer {bearer_token}",
                "Content-Type": "application/scim+json",
                "Accept": "application/scim+json",
            },
            **kwargs,
        )

    def find_user(self, email: str) -> dict | None:
        resp = self.api.request("GET", "/scim/v2/Users", params={"filter": f'userName eq "{email}"'})
        res = (resp or {}).get("Resources") or []
        return res[0] if res else None

    def find_group(self, name: str) -> dict:
        resp = self.api.request("GET", "/scim/v2/Groups", params={"filter": f'displayName eq "{name}"'})
        res = (resp or {}).get("Resources") or []
        if not res:
            raise LookupError(f"1Password group '{name}' not found")
        return res[0]

    def create_user(self, first: str, last: str, email: str) -> dict:
        """Provision (invite) the user. Returns the existing user if already present."""
        existing = self.find_user(email)
        if existing:
            return {**existing, "_created": False}
        body = {
            "schemas": [USER_SCHEMA],
            "userName": email,
            "displayName": f"{first} {last}",
            "name": {"givenName": first, "familyName": last},
            "emails": [{"value": email, "primary": True}],
            "active": True,
        }
        return {**self.api.request("POST", "/scim/v2/Users", json_body=body), "_created": True}

    def add_user_to_group(self, group_id: str, user_id: str) -> None:
        self.api.request(
            "PATCH",
            f"/scim/v2/Groups/{group_id}",
            json_body={
                "schemas": [PATCH_OP],
                "Operations": [{"op": "add", "path": "members", "value": [{"value": user_id}]}],
            },
        )

    def remove_user_from_group(self, group_id: str, user_id: str) -> None:
        self.api.request(
            "PATCH",
            f"/scim/v2/Groups/{group_id}",
            json_body={
                "schemas": [PATCH_OP],
                "Operations": [{"op": "remove", "path": f'members[value eq "{user_id}"]'}],
            },
        )

    def suspend_user(self, user_id: str) -> None:
        self.api.request(
            "PATCH",
            f"/scim/v2/Users/{user_id}",
            json_body={
                "schemas": [PATCH_OP],
                "Operations": [{"op": "replace", "path": "active", "value": False}],
            },
        )

    def grant_vault_group(self, email: str, group_name: str, first: str, last: str) -> dict:
        user = self.create_user(first, last, email)
        group = self.find_group(group_name)
        self.add_user_to_group(group["id"], user["id"])
        return {"user_id": user["id"], "group": group_name, "user_created": user["_created"]}

    def offboard(self, email: str) -> dict:
        """Strip every group (and therefore every group-granted vault), then suspend.

        Suspension is the backstop: a suspended 1Password user cannot unlock any vault,
        including ones granted directly to the user rather than via a group.
        """
        user = self.find_user(email)
        if not user:
            raise LookupError(f"1Password user {email} not found")
        uid = user["id"]
        removed, skipped, failed = [], [], []
        for g in user.get("groups", []):
            name = g.get("display", g["value"])
            if name in PROTECTED_GROUPS:
                skipped.append(name)
                continue
            try:
                self.remove_user_from_group(g["value"], uid)
                removed.append(name)
            except ApiError as e:
                failed.append({"group": name, "status": e.status})
        self.suspend_user(uid)
        result = {"user_id": uid, "groups_removed": removed, "suspended": True}
        if skipped:
            result["needs_manual_review"] = skipped
        if failed:
            result["groups_failed"] = failed
            raise RuntimeError(f"suspended, but group removal failed: {failed}")
        return result

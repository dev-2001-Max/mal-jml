"""Jamf Pro enrollment invitation (mocked by default — no free Jamf tenant).

Flow modelled on Jamf Pro: obtain an OAuth token from an API client, create a computer
enrollment invitation via the Classic API, then email the user-initiated enrollment URL.
"""

from __future__ import annotations

import xml.etree.ElementTree as ET
from datetime import UTC, datetime, timedelta
from typing import Any

from .http import ApiClient


class JamfClient:
    def __init__(self, base_url: str, client_id: str, client_secret: str, **kwargs: Any):
        self.base_url = base_url.rstrip("/")
        self._client_id, self._client_secret = client_id, client_secret
        self._token: str | None = None
        self.api = ApiClient("jamf", base_url, self._auth, **kwargs)

    def _auth(self) -> dict[str, str]:
        if self._token is None:
            return {}
        return {"Authorization": f"Bearer {self._token}"}

    def authenticate(self) -> None:
        resp = self.api.request(
            "POST",
            "/api/v1/oauth/token",
            data={
                "grant_type": "client_credentials",
                "client_id": self._client_id,
                "client_secret": self._client_secret,
            },
            headers={"Content-Type": "application/x-www-form-urlencoded"},
        )
        self._token = resp["access_token"]

    @staticmethod
    def build_invitation_xml(expires_days: int = 7, site_id: int = -1) -> str:
        expiry = datetime.now(UTC) + timedelta(days=expires_days)
        root = ET.Element("computer_invitation")
        for tag, value in [
            ("invitation_type", "USER_INITIATED_EMAIL"),
            ("expiration_date_utc", expiry.strftime("%Y-%m-%dT%H:%M:%S.000+0000")),
            ("multiple_users_allowed", "false"),
            ("create_account_if_does_not_exist", "false"),
            ("keep_existing_site_membership", "false"),
        ]:
            ET.SubElement(root, tag).text = value
        site = ET.SubElement(root, "enroll_into_site")
        ET.SubElement(site, "id").text = str(site_id)
        return ET.tostring(root, encoding="unicode")

    def send_enrollment_invitation(self, email: str, expires_days: int = 7) -> dict:
        self.authenticate()
        payload = self.build_invitation_xml(expires_days)
        xml = self.api.request(
            "POST",
            "/JSSResource/computerinvitations/id/0",
            data=payload,
            headers={"Content-Type": "application/xml"},
            expected=(201,),
            raw=True,
        )
        node = ET.fromstring(xml)
        inv_id = node.findtext("id")
        code = node.findtext("invitation") or inv_id
        return {
            "recipient": email,
            "invitation_id": inv_id,
            "enrollment_url": f"{self.base_url}/enroll?invitation={code}",
            "expires_in_days": expires_days,
        }

import xml.etree.ElementTree as ET

import responses

from jml.mdm import JamfClient
from tests.conftest import JAMF


def test_invitation_payload_shape():
    root = ET.fromstring(JamfClient.build_invitation_xml(expires_days=7))
    assert root.tag == "computer_invitation"
    assert root.findtext("invitation_type") == "USER_INITIATED_EMAIL"
    assert root.findtext("multiple_users_allowed") == "false"
    assert root.findtext("expiration_date_utc").endswith("+0000")


@responses.activate
def test_send_invitation_authenticates_then_posts_xml(jamf):
    tok = responses.post(f"{JAMF}/api/v1/oauth/token", json={"access_token": "abc", "expires_in": 299})
    inv = responses.post(
        f"{JAMF}/JSSResource/computerinvitations/id/0",
        status=201,
        body="<computer_invitation><id>42</id><invitation>777</invitation></computer_invitation>",
    )
    out = jamf.send_enrollment_invitation("a@mal.example")

    assert "client_credentials" in tok.calls[0].request.body
    req = inv.calls[0].request
    assert req.headers["Authorization"] == "Bearer abc"
    assert req.headers["Content-Type"] == "application/xml"
    assert out == {
        "recipient": "a@mal.example",
        "invitation_id": "42",
        "enrollment_url": f"{JAMF}/enroll?invitation=777",
        "expires_in_days": 7,
    }

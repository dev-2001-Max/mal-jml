import pytest

from jml.config import Settings
from jml.gws import GwsClient
from jml.mdm import JamfClient
from jml.okta import OktaClient
from jml.onepassword import OnePasswordScimClient

OKTA = "https://test.okta.com"
SCIM = "https://scim.test"
JAMF = "https://test.jamfcloud.com"
GWS = "https://admin.googleapis.com/admin/directory/v1"


def no_sleep(_):
    return None


@pytest.fixture
def okta():
    return OktaClient(OKTA, "t0ken", sleep=no_sleep)


@pytest.fixture
def gws():
    return GwsClient(lambda: "gtoken", sleep=no_sleep)


@pytest.fixture
def op():
    return OnePasswordScimClient(SCIM, "scimtoken", sleep=no_sleep)


@pytest.fixture
def jamf():
    return JamfClient(JAMF, "cid", "csecret", sleep=no_sleep)


@pytest.fixture
def settings(tmp_path):
    mode = {k: "mock" for k in ("okta", "gws", "1password", "jamf")}
    return Settings(mode=mode, audit_log=str(tmp_path / "audit.jsonl"), gws_org_unit="/")

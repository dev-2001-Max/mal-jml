"""Settings come only from environment variables (optionally via a local .env file).

JML_MODE:
  auto (default) — a provider runs live when its credentials are set, otherwise mocked
  mock           — every provider mocked, regardless of credentials
  live           — every provider except MDM must have credentials, or startup fails
"""

from __future__ import annotations

import os
from dataclasses import dataclass

REQUIRED = {
    "okta": ["OKTA_ORG_URL", "OKTA_API_TOKEN"],
    "gws": ["GWS_SERVICE_ACCOUNT_FILE", "GWS_ADMIN_SUBJECT"],
    "1password": ["OP_SCIM_BRIDGE_URL", "OP_SCIM_TOKEN"],
    "jamf": ["JAMF_URL", "JAMF_CLIENT_ID", "JAMF_CLIENT_SECRET"],
}
ALWAYS_MOCK_UNLESS_SET = {"jamf"}


class ConfigError(Exception):
    pass


@dataclass
class Settings:
    mode: dict[str, str]
    audit_log: str
    gws_org_unit: str


def load_settings(load_dotenv: bool = True) -> Settings:
    if load_dotenv:
        try:
            from dotenv import load_dotenv as _ld

            _ld(override=False)
        except ImportError:  # pragma: no cover
            pass

    global_mode = (os.environ.get("JML_MODE") or "auto").lower()
    if global_mode not in {"auto", "mock", "live"}:
        raise ConfigError(f"JML_MODE must be auto|mock|live, got {global_mode!r}")

    mode: dict[str, str] = {}
    for system, keys in REQUIRED.items():
        configured = all(os.environ.get(k) for k in keys)
        if global_mode == "mock":
            mode[system] = "mock"
        elif global_mode == "live" and system not in ALWAYS_MOCK_UNLESS_SET:
            if not configured:
                missing = [k for k in keys if not os.environ.get(k)]
                raise ConfigError(f"JML_MODE=live but {system} is missing {missing}")
            mode[system] = "live"
        else:
            mode[system] = "live" if configured else "mock"

    sa_file = os.environ.get("GWS_SERVICE_ACCOUNT_FILE")
    if mode["gws"] == "live" and not os.path.isfile(sa_file):
        raise ConfigError(
            f"GWS_SERVICE_ACCOUNT_FILE points to {sa_file!r}, which does not exist. "
            "Fix the path, or leave the GWS_* values blank in .env to mock Google Workspace."
        )

    return Settings(
        mode=mode,
        audit_log=os.environ.get("JML_AUDIT_LOG") or "logs/jml_audit.jsonl",
        gws_org_unit=os.environ.get("GWS_DEFAULT_ORG_UNIT") or "/",
    )

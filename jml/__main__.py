"""CLI: python -m jml joiner|leaver ..."""

from __future__ import annotations

import argparse
import json
import logging
import sys

from .config import ConfigError, load_settings
from .models import Joiner, Leaver
from .workflow import build_clients, run_joiner, run_leaver


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="jml", description="Mal joiner/leaver security workflow")
    p.add_argument("-v", "--verbose", action="store_true")
    sub = p.add_subparsers(dest="flow", required=True)

    j = sub.add_parser("joiner", help="onboard a new hire")
    j.add_argument("--first", required=True)
    j.add_argument("--last", required=True)
    j.add_argument("--email", required=True)
    j.add_argument("--okta-group", default="engineering")
    j.add_argument("--vault-group", default="Engineering")

    lv = sub.add_parser("leaver", help="offboard a departing employee")
    lv.add_argument("--email", required=True)
    lv.add_argument("--deactivate", action="store_true", help="deactivate instead of suspend")

    args = p.parse_args(argv)
    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )

    try:
        settings = load_settings()
    except ConfigError as e:
        print(f"config error: {e}", file=sys.stderr)
        return 2

    clients = build_clients(settings)
    if args.flow == "joiner":
        report = run_joiner(
            Joiner(args.first, args.last, args.email, args.okta_group, args.vault_group),
            clients,
            settings,
        )
    else:
        report = run_leaver(Leaver(args.email, args.deactivate), clients, settings)

    print(json.dumps(report.to_dict(), indent=2, default=str))
    return 0 if report.ok else 1


if __name__ == "__main__":
    sys.exit(main())

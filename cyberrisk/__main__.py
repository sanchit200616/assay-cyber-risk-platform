"""CLI: python -m cyberrisk [serve|seed|migrate|verify-ledger]"""
import argparse
import json
import sys

from .config import ConfigError, load_settings
from .observability import configure_logging
from .seed import seed_demo
from .server import build_platform, serve


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="cyberrisk")
    ap.add_argument("command", choices=["serve", "seed", "migrate", "verify-ledger"])
    ap.add_argument("--no-worker", action="store_true")
    args = ap.parse_args(argv)
    try:
        settings = load_settings()
    except ConfigError as exc:
        print(f"configuration error: {exc}", file=sys.stderr)
        return 2
    if args.command == "serve":
        serve(settings, with_worker=not args.no_worker)
    elif args.command == "migrate":
        print("applied migrations:", build_platform(settings).db.schema_version())
    elif args.command == "seed":
        configure_logging()
        out = seed_demo(build_platform(settings))
        print("Seeded SYNTHETIC demo data. Credentials (shown once; store them now):")
        for email, pw in out["credentials"].items():
            print(f"  {email}  {pw}")
    elif args.command == "verify-ledger":
        res = build_platform(settings).ledger.verify()
        print(json.dumps(res, indent=2))
        return 0 if res["ok"] else 1
    return 0


if __name__ == "__main__":
    sys.exit(main())

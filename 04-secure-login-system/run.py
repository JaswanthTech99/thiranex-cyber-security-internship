"""Entry point.

  python run.py                          # normal, safe defaults
  python run.py --insecure-cookies       # local plain-HTTP development only
  python run.py --demo-vulnerable        # mounts the intentionally injectable
                                         # endpoint. Read the warning it prints.
"""

from __future__ import annotations

import argparse
import json
import sys

from src.app import create_app
from src.config import Config


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description="Secure Login System")
    p.add_argument("--host", default="127.0.0.1",
                   help="bind address (default 127.0.0.1, i.e. localhost only)")
    p.add_argument("--port", type=int, default=5000)
    p.add_argument("--db", default=None, help="SQLite path (default app.db)")
    p.add_argument("--insecure-cookies", action="store_true",
                   help="clear the Secure flag on the session cookie. Needed to "
                        "sign in over plain HTTP, because browsers and clients "
                        "will not send a Secure cookie to an http:// origin. "
                        "Development only.")
    p.add_argument("--no-rate-limit", action="store_true",
                   help="disable lockout and per-IP throttling. Only for the "
                        "measurement harnesses, which need hundreds of requests.")
    p.add_argument("--no-enum-mitigation", action="store_true",
                   help="skip the dummy Argon2 verify on the unknown-user path, "
                        "reintroducing the user-enumeration timing leak. Exists "
                        "so tests/test_enumeration.py can measure the leak.")
    p.add_argument("--no-breach-check", action="store_true",
                   help="skip the Have I Been Pwned lookup at registration "
                        "(offline use)")
    p.add_argument("--argon2-max-concurrent", type=int, default=None,
                   help="cap on simultaneous Argon2 operations, which is what "
                        "bounds peak memory (cap x 64 MiB). Default 4. Set very "
                        "high to remove the bound, which the benchmark does for "
                        "its no-cap comparison.")
    p.add_argument("--demo-vulnerable", action="store_true",
                   help="DANGEROUS. Mount /demo/vulnerable/login, which builds "
                        "SQL by string concatenation against plaintext "
                        "passwords. It is an authentication bypass by design.")
    p.add_argument("--print-config", action="store_true",
                   help="print the effective security configuration and exit")
    return p


def config_from_args(args: argparse.Namespace) -> Config:
    config = Config()
    if args.db:
        config.database_path = args.db
    if args.insecure_cookies:
        config.cookie_secure = False
    if args.no_rate_limit:
        config.rate_limit_enabled = False
    if args.no_enum_mitigation:
        config.enum_mitigation = False
    if args.no_breach_check:
        config.require_breach_check = False
    if args.argon2_max_concurrent is not None:
        config.argon2_max_concurrent = args.argon2_max_concurrent
    config.demo_vulnerable = args.demo_vulnerable
    return config


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    config = config_from_args(args)

    if args.print_config:
        json.dump(config.describe(), sys.stdout, indent=2, sort_keys=True)
        sys.stdout.write("\n")
        return 0

    app = create_app(config)
    # threaded=True so the concurrency measurements exercise more than one
    # in-flight Argon2 hash. debug is never enabled: the Werkzeug debugger is
    # remote code execution for anyone who can reach a traceback.
    app.run(host=args.host, port=args.port, debug=False, threaded=True,
            use_reloader=False)
    return 0


if __name__ == "__main__":
    sys.exit(main())

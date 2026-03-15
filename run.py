#!/usr/bin/env python3
"""Entry point for the PCAP Reader application.

Automatically detects available libraries and picks the best backend:
  - Flask installed    -> uses Flask web server
  - Flask not installed -> uses Python stdlib http.server

  - scapy installed    -> uses scapy for pcap parsing
  - scapy not installed -> uses stdlib struct-based parser

  - paramiko installed  -> uses paramiko for SSH
  - paramiko not installed -> uses subprocess + system ssh/scp

No third-party packages are required. To install them (in a venv):
  ./setup.sh --install-deps
"""

import sys


def _check_virtualenv():
    """Warn if running outside a virtual environment."""
    if sys.prefix == sys.base_prefix:
        print(
            "NOTE: You are not running inside a virtual environment.\n"
            "This is fine — the app works with standard library only.\n"
            "To install optional third-party packages, use a venv:\n"
            "  ./setup.sh --install-deps\n"
        )


def _print_backends():
    """Print which backends are being used."""
    from utils import PCAP_BACKEND, SSH_BACKEND
    print(f"  PCAP parser : {PCAP_BACKEND}")
    print(f"  SSH handler : {SSH_BACKEND}")


if __name__ == "__main__":
    _check_virtualenv()

    print("=== PCAP Reader ===")
    _print_backends()

    try:
        import flask  # noqa: F401
        print(f"  Web server  : Flask")
        print()
        from app import create_app
        app = create_app()
        app.run(host="0.0.0.0", port=5000, debug=True)
    except ImportError:
        print(f"  Web server  : stdlib (http.server)")
        print()
        from app.server_stdlib import run_stdlib_server
        run_stdlib_server(host="0.0.0.0", port=5000)

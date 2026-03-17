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

from __future__ import annotations

import logging
import sys

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    datefmt="%H:%M:%S",
)
logger = logging.getLogger("pcap_reader")


def _check_virtualenv() -> None:
    """Warn if running outside a virtual environment."""
    if sys.prefix == sys.base_prefix:
        logger.info(
            "Not running inside a virtual environment. "
            "This is fine — the app works with standard library only. "
            "To install optional third-party packages, use a venv: "
            "./setup.sh --install-deps"
        )


def _print_backends() -> None:
    """Log which backends are being used."""
    from utils import PCAP_BACKEND, SSH_BACKEND

    logger.info("PCAP parser : %s", PCAP_BACKEND)
    logger.info("SSH handler : %s", SSH_BACKEND)


def main() -> None:
    """Application entry point."""
    _check_virtualenv()

    logger.info("=== PCAP Reader ===")
    _print_backends()

    try:
        import flask  # noqa: F401

        logger.info("Web server  : Flask")
        from app import create_app

        app = create_app()
        app.run(host="0.0.0.0", port=5000, debug=True)
    except ImportError:
        logger.info("Web server  : stdlib (http.server)")
        from app.server_stdlib import run_stdlib_server

        run_stdlib_server(host="0.0.0.0", port=5000)


if __name__ == "__main__":
    main()

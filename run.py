#!/usr/bin/env python3
"""Entry point for the PCAP Reader application."""

import sys


def _check_virtualenv():
    """Warn if running outside a virtual environment."""
    if sys.prefix == sys.base_prefix:
        print(
            "WARNING: You are not running inside a virtual environment.\n"
            "It is strongly recommended to activate the venv first:\n"
            "  source venv/bin/activate\n"
            "Or run ./setup.sh to create one.\n"
        )


if __name__ == "__main__":
    _check_virtualenv()
    from app import create_app
    app = create_app()
    app.run(host="0.0.0.0", port=5000, debug=True)

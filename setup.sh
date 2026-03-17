#!/usr/bin/env bash
# Setup script for PCAP Reader.
#
# Usage:
#   ./setup.sh                 — Run without installing third-party packages
#   ./setup.sh --install-deps  — Create venv and install third-party packages

set -e

VENV_DIR="venv"

echo "=== PCAP Reader Setup ==="
echo ""

if [ "$1" = "--install-deps" ]; then
    # --- Full setup: venv + third-party packages ---
    echo "Mode: Full setup (with third-party packages in virtual environment)"
    echo ""

    if [ ! -d "$VENV_DIR" ]; then
        echo "[1/3] Creating virtual environment in $VENV_DIR/ ..."
        python3 -m venv "$VENV_DIR"
    else
        echo "[1/3] Virtual environment already exists."
    fi

    echo "[2/3] Activating virtual environment ..."
    source "$VENV_DIR/bin/activate"

    echo "[3/3] Installing third-party dependencies inside virtual environment ..."
    pip install --upgrade pip
    pip install -e ".[full]"

    echo ""
    echo "=== Setup complete (third-party packages installed in venv) ==="
    echo ""
    echo "Installed packages: flask, scapy, paramiko, werkzeug"
    echo ""
    echo "To start the application:"
    echo "  source venv/bin/activate"
    echo "  python run.py"
else
    # --- Minimal setup: stdlib only ---
    echo "Mode: Standard library only (no third-party packages)"
    echo ""
    echo "The application will run using:"
    echo "  - Python http.server  (instead of Flask)"
    echo "  - struct-based parser (instead of scapy)"
    echo "  - subprocess + ssh    (instead of paramiko)"
    echo ""
    echo "No installation needed. Just run:"
    echo "  python3 run.py"
    echo ""
    echo "To enable third-party packages later, run:"
    echo "  ./setup.sh --install-deps"
fi

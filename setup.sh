#!/usr/bin/env bash
# Setup script for PCAP Reader — installs everything in a virtual environment.

set -e

VENV_DIR="venv"

echo "=== PCAP Reader Setup ==="

# Create virtual environment if it doesn't exist
if [ ! -d "$VENV_DIR" ]; then
    echo "[1/3] Creating virtual environment in $VENV_DIR/ ..."
    python3 -m venv "$VENV_DIR"
else
    echo "[1/3] Virtual environment already exists."
fi

# Activate it
echo "[2/3] Activating virtual environment ..."
source "$VENV_DIR/bin/activate"

# Install dependencies
echo "[3/3] Installing dependencies inside virtual environment ..."
pip install --upgrade pip
pip install -r requirements.txt

echo ""
echo "=== Setup complete ==="
echo "To start the application:"
echo "  source venv/bin/activate"
echo "  python run.py"

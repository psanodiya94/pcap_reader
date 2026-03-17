"""Utility package — auto-detects available backends.

If third-party libraries (scapy, paramiko) are installed, uses them.
Otherwise falls back to standard library implementations.
"""

from __future__ import annotations

import importlib
from typing import Any

# --- PCAP Parser ---
try:
    importlib.import_module("scapy")
    from utils.pcap_parser import parse_pcap
    PCAP_BACKEND: str = "scapy"
except ImportError:
    from utils.pcap_parser_stdlib import parse_pcap  # type: ignore[assignment]
    PCAP_BACKEND = "stdlib"

# --- SSH Handler ---
try:
    importlib.import_module("paramiko")
    from utils.ssh_handler import SSHHandler
    SSH_BACKEND: str = "paramiko"
except ImportError:
    from utils.ssh_handler_stdlib import SSHHandlerStdlib as SSHHandler  # type: ignore[assignment]
    SSH_BACKEND = "subprocess"

# --- Hex Dump (uses scapy when available, falls back to stdlib) ---
from utils.hex_dump import get_packet_hexdump

__all__ = [
    "parse_pcap",
    "SSHHandler",
    "get_packet_hexdump",
    "PCAP_BACKEND",
    "SSH_BACKEND",
]

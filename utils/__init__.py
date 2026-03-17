"""Utility package — auto-detects available backends.

If third-party libraries (scapy, paramiko) are installed, uses them.
Otherwise falls back to standard library implementations.
"""

import importlib

# --- PCAP Parser ---
try:
    importlib.import_module("scapy")
    from utils.pcap_parser import parse_pcap
    PCAP_BACKEND = "scapy"
except ImportError:
    from utils.pcap_parser_stdlib import parse_pcap
    PCAP_BACKEND = "stdlib"

# --- SSH Handler ---
try:
    importlib.import_module("paramiko")
    from utils.ssh_handler import SSHHandler
    SSH_BACKEND = "paramiko"
except ImportError:
    from utils.ssh_handler_stdlib import SSHHandlerStdlib as SSHHandler
    SSH_BACKEND = "subprocess"

# --- Hex Dump (uses scapy when available, falls back to stdlib) ---
from utils.hex_dump import get_packet_hexdump

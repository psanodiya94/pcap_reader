"""Hex dump utility for pcap files.

Reads raw packet bytes from a pcap file and produces a hex dump
with the header and payload sections clearly separated.

Uses scapy for byte extraction when available (handles pcap, pcapng,
and all scapy-supported formats). Falls back to stdlib struct-based
reader for classic pcap when scapy is not installed.
"""

import struct
import socket

# Try to use scapy for raw byte extraction (handles pcapng + all formats)
try:
    from scapy.all import rdpcap, raw as scapy_raw
    _HAS_SCAPY = True
except ImportError:
    _HAS_SCAPY = False

# Pcap magic numbers (for stdlib fallback)
PCAP_MAGIC_LE = 0xA1B2C3D4
PCAP_MAGIC_BE = 0xD4C3B2A1
PCAP_MAGIC_NS_LE = 0xA1B23C4D  # nanosecond-resolution pcap
PCAP_MAGIC_NS_BE = 0x4D3CB2A1
PCAPNG_MAGIC = 0x0A0D0D0A

# Ethernet types
ETHERTYPE_IP = 0x0800
ETHERTYPE_IPV6 = 0x86DD
ETHERTYPE_ARP = 0x0806
ETHERTYPE_VLAN = 0x8100

# IP protocols
PROTO_ICMP = 1
PROTO_TCP = 6
PROTO_UDP = 17
PROTO_ICMPV6 = 58


def get_packet_hexdump(file_path, packet_no):
    """Extract a single packet from a pcap file and return its hex dump.

    Returns a dict with:
      - packet_no: requested packet number
      - total_length: total packet bytes
      - sections: list of {name, offset, length, hex_lines}
      - raw_hex: full hex dump of the entire packet (for reference)
    """
    raw_bytes = _extract_packet_bytes(file_path, packet_no)
    if raw_bytes is None:
        raise ValueError(f"Packet #{packet_no} not found in file")

    sections = _split_into_sections(raw_bytes)
    raw_hex = _format_hex_block(raw_bytes, 0)

    return {
        "packet_no": packet_no,
        "total_length": len(raw_bytes),
        "sections": sections,
        "raw_hex": raw_hex,
    }


def _extract_packet_bytes(file_path, packet_no):
    """Read the raw bytes of a specific packet from a pcap file.

    Uses scapy when available (supports pcap, pcapng, and all formats).
    Falls back to stdlib struct-based reader for classic pcap.
    """
    if _HAS_SCAPY:
        return _extract_with_scapy(file_path, packet_no)
    return _extract_with_stdlib(file_path, packet_no)


def _extract_with_scapy(file_path, packet_no):
    """Extract raw bytes using scapy (handles all pcap formats)."""
    packets = rdpcap(file_path)

    if packet_no < 1 or packet_no > len(packets):
        return None

    pkt = packets[packet_no - 1]
    return scapy_raw(pkt)


def _extract_with_stdlib(file_path, packet_no):
    """Extract raw bytes using stdlib struct (classic pcap only)."""
    with open(file_path, "rb") as f:
        data = f.read()

    if len(data) < 24:
        raise ValueError("File too small to be a valid pcap file")

    magic = struct.unpack("<I", data[:4])[0]

    if magic == PCAPNG_MAGIC:
        raise ValueError(
            "pcapng format detected. Install scapy for pcapng hex dump support: "
            "pip install scapy"
        )

    if magic in (PCAP_MAGIC_LE, PCAP_MAGIC_NS_LE):
        endian = "<"
    elif magic in (PCAP_MAGIC_BE, PCAP_MAGIC_NS_BE):
        endian = ">"
    else:
        raise ValueError(
            f"Unsupported pcap format (magic: 0x{magic:08X}). "
            "Install scapy for broader format support: pip install scapy"
        )

    # Global header: 24 bytes
    _magic, _ver_maj, _ver_min, _tz, _sf, _snaplen, link_type = struct.unpack(
        f"{endian}IHHiIII", data[:24]
    )

    offset = 24
    current = 0

    while offset < len(data):
        if offset + 16 > len(data):
            break

        _ts_sec, _ts_usec, incl_len, _orig_len = struct.unpack(
            f"{endian}IIII", data[offset:offset + 16]
        )
        offset += 16

        if incl_len > 0xFFFF or offset + incl_len > len(data):
            break

        current += 1
        if current == packet_no:
            return data[offset:offset + incl_len]

        offset += incl_len

    return None


# ---------------------------------------------------------------------------
# Section splitting — dissect raw bytes into header + payload sections
# ---------------------------------------------------------------------------

def _split_into_sections(raw_bytes):
    """Split raw packet bytes into logical sections (headers + payload)."""
    sections = []

    if len(raw_bytes) < 14:
        sections.append(_make_section("Raw Data", raw_bytes, 0))
        return sections

    # Check if this looks like an Ethernet frame
    ethertype = struct.unpack("!H", raw_bytes[12:14])[0]

    # Heuristic: if ethertype is a known value, treat as Ethernet
    known_ethertypes = {
        ETHERTYPE_IP, ETHERTYPE_IPV6, ETHERTYPE_ARP, ETHERTYPE_VLAN,
    }

    if ethertype in known_ethertypes or ethertype > 0x0600:
        # Ethernet frame
        return _split_ethernet(raw_bytes)

    # Check if it starts with an IP version nibble (raw IP capture)
    version = (raw_bytes[0] >> 4) & 0x0F
    if version == 4 and len(raw_bytes) >= 20:
        return _split_from_ip(raw_bytes, 0, is_v6=False)
    if version == 6 and len(raw_bytes) >= 40:
        return _split_from_ip(raw_bytes, 0, is_v6=True)

    # Unknown format — dump everything as raw data
    sections.append(_make_section("Raw Data", raw_bytes, 0))
    return sections


def _split_ethernet(raw_bytes):
    """Split an Ethernet frame into sections."""
    sections = []
    pos = 0

    # Ethernet Header (14 bytes)
    eth_header = raw_bytes[:14]
    ethertype = struct.unpack("!H", raw_bytes[12:14])[0]
    sections.append(_make_section("Ethernet Header", eth_header, 0))
    pos = 14

    # Handle 802.1Q VLAN tag
    if ethertype == ETHERTYPE_VLAN and len(raw_bytes) >= 18:
        vlan_tag = raw_bytes[14:18]
        ethertype = struct.unpack("!H", raw_bytes[16:18])[0]
        sections.append(_make_section("VLAN Tag (802.1Q)", vlan_tag, 14))
        pos = 18

    remaining = raw_bytes[pos:]

    if ethertype == ETHERTYPE_IP and len(remaining) >= 20:
        ip_sections = _split_from_ip(remaining, pos, is_v6=False)
        sections.extend(ip_sections)
    elif ethertype == ETHERTYPE_IPV6 and len(remaining) >= 40:
        ip_sections = _split_from_ip(remaining, pos, is_v6=True)
        sections.extend(ip_sections)
    elif ethertype == ETHERTYPE_ARP and len(remaining) >= 28:
        sections.append(_make_section("ARP Header", remaining[:28], pos))
        if len(remaining) > 28:
            sections.append(_make_section("Payload", remaining[28:], pos + 28))
    elif remaining:
        sections.append(_make_section("Payload", remaining, pos))

    return sections


def _split_from_ip(data, base_offset, is_v6=False):
    """Split IP packet (v4 or v6) into header + transport + payload sections."""
    sections = []

    if is_v6:
        ipv6_header = data[:40]
        next_header = data[6] if len(data) > 6 else 0
        sections.append(_make_section("IPv6 Header", ipv6_header, base_offset))
        transport_data = data[40:]
        transport_offset = base_offset + 40
        proto = next_header
    else:
        ihl = (data[0] & 0x0F) * 4
        if ihl < 20:
            ihl = 20
        if ihl > len(data):
            ihl = len(data)
        ip_header = data[:ihl]
        proto = data[9] if len(data) > 9 else 0
        sections.append(_make_section("IPv4 Header", ip_header, base_offset))
        transport_data = data[ihl:]
        transport_offset = base_offset + ihl

    # Transport layer
    payload_data, payload_offset = _split_transport(
        proto, transport_data, transport_offset, sections
    )

    if payload_data:
        sections.append(_make_section("Payload", payload_data, payload_offset))

    return sections


def _split_transport(proto, data, base_offset, sections):
    """Parse TCP/UDP/ICMP header and return remaining payload."""
    if proto == PROTO_TCP and len(data) >= 20:
        data_offset_byte = data[12] if len(data) > 12 else 0
        tcp_header_len = ((data_offset_byte >> 4) & 0x0F) * 4
        if tcp_header_len < 20:
            tcp_header_len = 20
        if tcp_header_len > len(data):
            tcp_header_len = len(data)

        sections.append(_make_section("TCP Header", data[:tcp_header_len], base_offset))
        return data[tcp_header_len:], base_offset + tcp_header_len

    elif proto == PROTO_UDP and len(data) >= 8:
        sections.append(_make_section("UDP Header", data[:8], base_offset))
        return data[8:], base_offset + 8

    elif proto == PROTO_ICMP and len(data) >= 8:
        sections.append(_make_section("ICMP Header", data[:8], base_offset))
        return data[8:], base_offset + 8

    elif proto == PROTO_ICMPV6 and len(data) >= 8:
        sections.append(_make_section("ICMPv6 Header", data[:8], base_offset))
        return data[8:], base_offset + 8

    elif data:
        # Unknown transport — treat everything as payload
        return data, base_offset

    return b"", base_offset


# ---------------------------------------------------------------------------
# Formatting helpers
# ---------------------------------------------------------------------------

def _make_section(name, data, offset):
    """Create a section dict with hex dump lines."""
    return {
        "name": name,
        "offset": offset,
        "length": len(data),
        "hex_lines": _format_hex_block(data, offset),
    }


def _format_hex_block(data, start_offset):
    """Format bytes into hex dump lines (offset | hex bytes | ASCII).

    Each line covers 16 bytes, formatted like:
      0000  48 65 6C 6C 6F 20 57 6F  72 6C 64 21 00 00 00 00  |Hello World!....|
    """
    lines = []
    for i in range(0, len(data), 16):
        chunk = data[i:i + 16]
        offset_str = f"{start_offset + i:04X}"

        # Hex part — two groups of 8 bytes
        hex_left = " ".join(f"{b:02X}" for b in chunk[:8])
        hex_right = " ".join(f"{b:02X}" for b in chunk[8:])

        # Pad to consistent width
        hex_left = hex_left.ljust(23)
        hex_right = hex_right.ljust(23)

        # ASCII part
        ascii_chars = "".join(chr(b) if 0x20 <= b < 0x7F else "." for b in chunk)

        lines.append(f"{offset_str}  {hex_left}  {hex_right}  |{ascii_chars}|")

    return lines

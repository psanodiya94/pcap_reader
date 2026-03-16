"""Hex dump utility for pcap files — standard library only.

Reads raw packet bytes from a pcap file and produces a hex dump
with the header and payload sections clearly separated.
"""

import struct
import socket


# Pcap magic numbers
PCAP_MAGIC_LE = 0xA1B2C3D4
PCAP_MAGIC_BE = 0xD4C3B2A1

# Ethernet types
ETHERTYPE_IP = 0x0800
ETHERTYPE_IPV6 = 0x86DD
ETHERTYPE_ARP = 0x0806

# IP protocols
PROTO_TCP = 6
PROTO_UDP = 17


def get_packet_hexdump(file_path, packet_no):
    """Extract a single packet from a pcap file and return its hex dump.

    Returns a dict with:
      - packet_no: requested packet number
      - total_length: total packet bytes
      - sections: list of {name, offset, length, hex_lines, ascii_lines}
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
    """Read the raw bytes of a specific packet from a pcap file."""
    with open(file_path, "rb") as f:
        data = f.read()

    magic = struct.unpack("<I", data[:4])[0]
    if magic == PCAP_MAGIC_LE:
        endian = "<"
    elif magic == PCAP_MAGIC_BE:
        endian = ">"
    else:
        raise ValueError("Not a valid pcap file or unsupported format (pcapng requires scapy)")

    offset = 24  # skip global header
    current = 0

    while offset < len(data):
        if offset + 16 > len(data):
            break

        _ts_sec, _ts_usec, incl_len, _orig_len = struct.unpack(
            f"{endian}IIII", data[offset:offset + 16]
        )
        offset += 16

        if offset + incl_len > len(data):
            break

        current += 1
        if current == packet_no:
            return data[offset:offset + incl_len]

        offset += incl_len

    return None


def _split_into_sections(raw_bytes):
    """Split raw packet bytes into logical sections (headers + payload).

    Returns a list of dicts, each describing a section:
      {name, offset, length, hex_lines}
    """
    sections = []
    pos = 0

    if len(raw_bytes) < 14:
        sections.append(_make_section("Raw Data", raw_bytes, 0))
        return sections

    # --- Ethernet Header (14 bytes) ---
    eth_header = raw_bytes[:14]
    ethertype = struct.unpack("!H", raw_bytes[12:14])[0]
    sections.append(_make_section("Ethernet Header", eth_header, 0))
    pos = 14

    remaining = raw_bytes[pos:]

    # --- IPv4 ---
    if ethertype == ETHERTYPE_IP and len(remaining) >= 20:
        ihl = (remaining[0] & 0x0F) * 4
        if ihl < 20:
            ihl = 20
        if ihl > len(remaining):
            ihl = len(remaining)

        ip_header = remaining[:ihl]
        proto = remaining[9] if len(remaining) > 9 else 0
        sections.append(_make_section("IPv4 Header", ip_header, pos))
        pos += ihl
        remaining = raw_bytes[pos:]

        # Transport layer
        pos, remaining = _parse_transport_header(proto, remaining, pos, sections)

    # --- IPv6 ---
    elif ethertype == ETHERTYPE_IPV6 and len(remaining) >= 40:
        ipv6_header = remaining[:40]
        next_header = remaining[6] if len(remaining) > 6 else 0
        sections.append(_make_section("IPv6 Header", ipv6_header, pos))
        pos += 40
        remaining = raw_bytes[pos:]

        pos, remaining = _parse_transport_header(next_header, remaining, pos, sections)

    # --- ARP ---
    elif ethertype == ETHERTYPE_ARP and len(remaining) >= 28:
        arp_header = remaining[:28]
        sections.append(_make_section("ARP Header", arp_header, pos))
        pos += 28
        remaining = raw_bytes[pos:]

    # --- Payload (whatever is left) ---
    if pos < len(raw_bytes):
        payload = raw_bytes[pos:]
        sections.append(_make_section("Payload", payload, pos))

    return sections


def _parse_transport_header(proto, remaining, pos, sections):
    """Parse TCP or UDP header and append to sections list."""
    if proto == PROTO_TCP and len(remaining) >= 20:
        data_offset_byte = remaining[12] if len(remaining) > 12 else 0
        tcp_header_len = ((data_offset_byte >> 4) & 0x0F) * 4
        if tcp_header_len < 20:
            tcp_header_len = 20
        if tcp_header_len > len(remaining):
            tcp_header_len = len(remaining)

        tcp_header = remaining[:tcp_header_len]
        sections.append(_make_section("TCP Header", tcp_header, pos))
        pos += tcp_header_len
        remaining = remaining[tcp_header_len:]

    elif proto == PROTO_UDP and len(remaining) >= 8:
        udp_header = remaining[:8]
        sections.append(_make_section("UDP Header", udp_header, pos))
        pos += 8
        remaining = remaining[8:]

    return pos, remaining


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
      0000  48 65 6c 6c 6f 20 57 6f  72 6c 64 21 00 00 00 00  |Hello World!....|
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

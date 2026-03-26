"""Hex dump utility for pcap files.

Reads raw packet bytes from a pcap file and produces a hex dump
with the header and payload sections clearly separated.

Uses scapy for byte extraction when available (handles pcap, pcapng,
and all scapy-supported formats). Falls back to stdlib struct-based
reader for classic pcap when scapy is not installed.
"""

from __future__ import annotations

import struct
from typing import Any

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


def get_packet_hexdump(file_path: str, packet_no: int) -> dict[str, Any]:
    """Extract a single packet from a pcap file and return its hex dump.

    Returns a dict with:
      - packet_no: requested packet number
      - total_length: total packet bytes
      - sections: list of {name, offset, length, fields, hex_lines}
      - raw_hex: full hex dump of the entire packet (for reference)
      - bytes: list of raw byte values (integers) for interactive hex view
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
        "bytes": list(raw_bytes),
    }


def _extract_packet_bytes(file_path: str, packet_no: int) -> bytes | None:
    """Read the raw bytes of a specific packet from a pcap file.

    Uses scapy when available (supports pcap, pcapng, and all formats).
    Falls back to stdlib struct-based reader for classic pcap.
    """
    if _HAS_SCAPY:
        return _extract_with_scapy(file_path, packet_no)
    return _extract_with_stdlib(file_path, packet_no)


def _extract_with_scapy(file_path: str, packet_no: int) -> bytes | None:
    """Extract raw bytes using scapy (handles all pcap formats)."""
    packets = rdpcap(file_path)

    if packet_no < 1 or packet_no > len(packets):
        return None

    pkt = packets[packet_no - 1]
    return scapy_raw(pkt)


def _extract_with_stdlib(file_path: str, packet_no: int) -> bytes | None:
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
# Protocol field extraction — each returns list of field dicts
# ---------------------------------------------------------------------------

def _eth_fields(data: bytes, base: int) -> list[dict[str, Any]]:
    """Extract Ethernet header fields with packet-absolute offsets."""
    if len(data) < 14:
        return []
    dst_mac = ":".join(f"{b:02X}" for b in data[0:6])
    src_mac = ":".join(f"{b:02X}" for b in data[6:12])
    et = struct.unpack("!H", data[12:14])[0]
    et_name = {
        ETHERTYPE_IP: "IPv4",
        ETHERTYPE_IPV6: "IPv6",
        ETHERTYPE_ARP: "ARP",
        ETHERTYPE_VLAN: "VLAN (802.1Q)",
    }.get(et, f"0x{et:04X}")
    return [
        {"name": "Destination MAC", "offset": base,      "length": 6, "value": dst_mac},
        {"name": "Source MAC",       "offset": base + 6,  "length": 6, "value": src_mac},
        {"name": "EtherType",        "offset": base + 12, "length": 2, "value": f"{et_name} (0x{et:04X})"},
    ]


def _vlan_fields(data: bytes, base: int) -> list[dict[str, Any]]:
    """Extract 802.1Q VLAN tag fields."""
    if len(data) < 4:
        return []
    tci = struct.unpack("!H", data[0:2])[0]
    pcp = (tci >> 13) & 0x7
    dei = (tci >> 12) & 0x1
    vid = tci & 0xFFF
    et = struct.unpack("!H", data[2:4])[0]
    et_name = {ETHERTYPE_IP: "IPv4", ETHERTYPE_IPV6: "IPv6"}.get(et, f"0x{et:04X}")
    return [
        {"name": "PCP + DEI + VLAN ID", "offset": base,     "length": 2, "value": f"PCP={pcp}, DEI={dei}, VID={vid}"},
        {"name": "EtherType",           "offset": base + 2,  "length": 2, "value": f"{et_name} (0x{et:04X})"},
    ]


def _arp_fields(data: bytes, base: int) -> list[dict[str, Any]]:
    """Extract ARP header fields."""
    if len(data) < 28:
        return []
    hw_type = struct.unpack("!H", data[0:2])[0]
    proto = struct.unpack("!H", data[2:4])[0]
    hw_size = data[4]
    proto_size = data[5]
    op = struct.unpack("!H", data[6:8])[0]
    op_name = {1: "Request", 2: "Reply"}.get(op, str(op))
    sender_mac = ":".join(f"{b:02X}" for b in data[8:14])
    sender_ip = ".".join(str(b) for b in data[14:18])
    target_mac = ":".join(f"{b:02X}" for b in data[18:24])
    target_ip = ".".join(str(b) for b in data[24:28])
    return [
        {"name": "Hardware Type",   "offset": base,      "length": 2, "value": f"{'Ethernet' if hw_type == 1 else str(hw_type)} ({hw_type})"},
        {"name": "Protocol Type",   "offset": base + 2,  "length": 2, "value": f"{'IPv4' if proto == 0x0800 else f'0x{proto:04X}'}"},
        {"name": "Hardware Size",   "offset": base + 4,  "length": 1, "value": str(hw_size)},
        {"name": "Protocol Size",   "offset": base + 5,  "length": 1, "value": str(proto_size)},
        {"name": "Opcode",          "offset": base + 6,  "length": 2, "value": f"{op_name} ({op})"},
        {"name": "Sender MAC",      "offset": base + 8,  "length": 6, "value": sender_mac},
        {"name": "Sender IP",       "offset": base + 14, "length": 4, "value": sender_ip},
        {"name": "Target MAC",      "offset": base + 18, "length": 6, "value": target_mac},
        {"name": "Target IP",       "offset": base + 24, "length": 4, "value": target_ip},
    ]


def _ipv4_fields(data: bytes, base: int) -> list[dict[str, Any]]:
    """Extract IPv4 header fields."""
    if len(data) < 20:
        return []
    ver_ihl = data[0]
    ver = (ver_ihl >> 4) & 0xF
    ihl = (ver_ihl & 0xF) * 4
    dscp_ecn = data[1]
    total_len = struct.unpack("!H", data[2:4])[0]
    ident = struct.unpack("!H", data[4:6])[0]
    flags_frag = struct.unpack("!H", data[6:8])[0]
    flags = (flags_frag >> 13) & 0x7
    frag_offset = flags_frag & 0x1FFF
    ttl = data[8]
    proto = data[9]
    proto_name = {PROTO_ICMP: "ICMP", PROTO_TCP: "TCP", PROTO_UDP: "UDP", PROTO_ICMPV6: "ICMPv6"}.get(proto, str(proto))
    checksum = struct.unpack("!H", data[10:12])[0]
    src_ip = ".".join(str(b) for b in data[12:16])
    dst_ip = ".".join(str(b) for b in data[16:20])

    flag_parts = []
    if flags & 0x2:
        flag_parts.append("DF")
    if flags & 0x1:
        flag_parts.append("MF")
    flag_str = "|".join(flag_parts) if flag_parts else "None"

    return [
        {"name": f"Version ({ver}) + IHL ({ihl} bytes)",  "offset": base,      "length": 1, "value": f"0x{ver_ihl:02X}"},
        {"name": "DSCP + ECN",                             "offset": base + 1,  "length": 1, "value": f"0x{dscp_ecn:02X}"},
        {"name": "Total Length",                           "offset": base + 2,  "length": 2, "value": str(total_len)},
        {"name": "Identification",                         "offset": base + 4,  "length": 2, "value": f"0x{ident:04X}"},
        {"name": f"Flags ({flag_str}) + Fragment Offset",  "offset": base + 6,  "length": 2, "value": f"Flags=0x{flags:X}, FragOff={frag_offset}"},
        {"name": "TTL",                                    "offset": base + 8,  "length": 1, "value": str(ttl)},
        {"name": "Protocol",                               "offset": base + 9,  "length": 1, "value": f"{proto_name} ({proto})"},
        {"name": "Header Checksum",                        "offset": base + 10, "length": 2, "value": f"0x{checksum:04X}"},
        {"name": "Source IP",                              "offset": base + 12, "length": 4, "value": src_ip},
        {"name": "Destination IP",                         "offset": base + 16, "length": 4, "value": dst_ip},
    ]


def _ipv6_fields(data: bytes, base: int) -> list[dict[str, Any]]:
    """Extract IPv6 header fields."""
    if len(data) < 40:
        return []
    ver_tc_fl = struct.unpack("!I", data[0:4])[0]
    ver = (ver_tc_fl >> 28) & 0xF
    tc = (ver_tc_fl >> 20) & 0xFF
    fl = ver_tc_fl & 0xFFFFF
    payload_len = struct.unpack("!H", data[4:6])[0]
    next_header = data[6]
    hop_limit = data[7]
    nh_name = {PROTO_ICMP: "ICMP", PROTO_TCP: "TCP", PROTO_UDP: "UDP", PROTO_ICMPV6: "ICMPv6",
               43: "Routing", 44: "Fragment", 59: "No Next Header"}.get(next_header, str(next_header))

    def _fmt_ipv6(d: bytes) -> str:
        groups = [f"{struct.unpack('!H', d[i:i + 2])[0]:04X}" for i in range(0, 16, 2)]
        return ":".join(groups)

    src = _fmt_ipv6(data[8:24])
    dst = _fmt_ipv6(data[24:40])
    return [
        {"name": "Version + Traffic Class + Flow Label", "offset": base,      "length": 4,  "value": f"Ver={ver}, TC={tc}, FL=0x{fl:05X}"},
        {"name": "Payload Length",                       "offset": base + 4,  "length": 2,  "value": str(payload_len)},
        {"name": "Next Header",                          "offset": base + 6,  "length": 1,  "value": f"{nh_name} ({next_header})"},
        {"name": "Hop Limit",                            "offset": base + 7,  "length": 1,  "value": str(hop_limit)},
        {"name": "Source IPv6",                          "offset": base + 8,  "length": 16, "value": src},
        {"name": "Destination IPv6",                     "offset": base + 24, "length": 16, "value": dst},
    ]


def _tcp_fields(data: bytes, base: int) -> list[dict[str, Any]]:
    """Extract TCP header fields."""
    if len(data) < 20:
        return []
    src_port = struct.unpack("!H", data[0:2])[0]
    dst_port = struct.unpack("!H", data[2:4])[0]
    seq = struct.unpack("!I", data[4:8])[0]
    ack_num = struct.unpack("!I", data[8:12])[0]
    data_off_byte = data[12]
    data_off = ((data_off_byte >> 4) & 0xF) * 4
    flags_byte = data[13]
    flag_parts = []
    if flags_byte & 0x01: flag_parts.append("FIN")
    if flags_byte & 0x02: flag_parts.append("SYN")
    if flags_byte & 0x04: flag_parts.append("RST")
    if flags_byte & 0x08: flag_parts.append("PSH")
    if flags_byte & 0x10: flag_parts.append("ACK")
    if flags_byte & 0x20: flag_parts.append("URG")
    flag_str = "|".join(flag_parts) if flag_parts else "None"
    window = struct.unpack("!H", data[14:16])[0]
    checksum = struct.unpack("!H", data[16:18])[0]
    urg_ptr = struct.unpack("!H", data[18:20])[0]
    return [
        {"name": "Source Port",           "offset": base,      "length": 2, "value": str(src_port)},
        {"name": "Destination Port",      "offset": base + 2,  "length": 2, "value": str(dst_port)},
        {"name": "Sequence Number",       "offset": base + 4,  "length": 4, "value": str(seq)},
        {"name": "Acknowledgment Number", "offset": base + 8,  "length": 4, "value": str(ack_num)},
        {"name": f"Data Offset ({data_off} bytes) + Flags", "offset": base + 12, "length": 2, "value": f"Flags: {flag_str}"},
        {"name": "Window Size",           "offset": base + 14, "length": 2, "value": str(window)},
        {"name": "Checksum",              "offset": base + 16, "length": 2, "value": f"0x{checksum:04X}"},
        {"name": "Urgent Pointer",        "offset": base + 18, "length": 2, "value": str(urg_ptr)},
    ]


def _udp_fields(data: bytes, base: int) -> list[dict[str, Any]]:
    """Extract UDP header fields."""
    if len(data) < 8:
        return []
    src_port = struct.unpack("!H", data[0:2])[0]
    dst_port = struct.unpack("!H", data[2:4])[0]
    length = struct.unpack("!H", data[4:6])[0]
    checksum = struct.unpack("!H", data[6:8])[0]
    return [
        {"name": "Source Port",      "offset": base,     "length": 2, "value": str(src_port)},
        {"name": "Destination Port", "offset": base + 2, "length": 2, "value": str(dst_port)},
        {"name": "Length",           "offset": base + 4, "length": 2, "value": str(length)},
        {"name": "Checksum",         "offset": base + 6, "length": 2, "value": f"0x{checksum:04X}"},
    ]


def _icmp_fields(data: bytes, base: int) -> list[dict[str, Any]]:
    """Extract ICMP header fields."""
    if len(data) < 8:
        return []
    icmp_type = data[0]
    code = data[1]
    checksum = struct.unpack("!H", data[2:4])[0]
    rest = struct.unpack("!I", data[4:8])[0]
    type_name = {
        0: "Echo Reply", 3: "Destination Unreachable", 8: "Echo Request",
        11: "Time Exceeded", 12: "Parameter Problem",
    }.get(icmp_type, f"Type {icmp_type}")
    return [
        {"name": "Type",            "offset": base,     "length": 1, "value": f"{type_name} ({icmp_type})"},
        {"name": "Code",            "offset": base + 1, "length": 1, "value": str(code)},
        {"name": "Checksum",        "offset": base + 2, "length": 2, "value": f"0x{checksum:04X}"},
        {"name": "Rest of Header",  "offset": base + 4, "length": 4, "value": f"0x{rest:08X}"},
    ]


def _icmpv6_fields(data: bytes, base: int) -> list[dict[str, Any]]:
    """Extract ICMPv6 header fields."""
    if len(data) < 8:
        return []
    icmp_type = data[0]
    code = data[1]
    checksum = struct.unpack("!H", data[2:4])[0]
    rest = struct.unpack("!I", data[4:8])[0]
    type_name = {
        1: "Destination Unreachable", 2: "Packet Too Big", 3: "Time Exceeded",
        128: "Echo Request", 129: "Echo Reply", 133: "Router Solicitation",
        134: "Router Advertisement", 135: "Neighbor Solicitation",
        136: "Neighbor Advertisement",
    }.get(icmp_type, f"Type {icmp_type}")
    return [
        {"name": "Type",           "offset": base,     "length": 1, "value": f"{type_name} ({icmp_type})"},
        {"name": "Code",           "offset": base + 1, "length": 1, "value": str(code)},
        {"name": "Checksum",       "offset": base + 2, "length": 2, "value": f"0x{checksum:04X}"},
        {"name": "Rest of Header", "offset": base + 4, "length": 4, "value": f"0x{rest:08X}"},
    ]


# ---------------------------------------------------------------------------
# Section splitting — dissect raw bytes into header + payload sections
# ---------------------------------------------------------------------------

def _split_into_sections(raw_bytes: bytes) -> list[dict[str, Any]]:
    """Split raw packet bytes into logical sections (headers + payload)."""
    sections: list[dict[str, Any]] = []

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


def _split_ethernet(raw_bytes: bytes) -> list[dict[str, Any]]:
    """Split an Ethernet frame into sections."""
    sections: list[dict[str, Any]] = []
    pos = 0

    # Ethernet Header (14 bytes)
    eth_header = raw_bytes[:14]
    ethertype = struct.unpack("!H", raw_bytes[12:14])[0]
    sections.append(_make_section("Ethernet Header", eth_header, 0,
                                  fields=_eth_fields(eth_header, 0)))
    pos = 14

    # Handle 802.1Q VLAN tag
    if ethertype == ETHERTYPE_VLAN and len(raw_bytes) >= 18:
        vlan_tag = raw_bytes[14:18]
        ethertype = struct.unpack("!H", raw_bytes[16:18])[0]
        sections.append(_make_section("VLAN Tag (802.1Q)", vlan_tag, 14,
                                      fields=_vlan_fields(vlan_tag, 14)))
        pos = 18

    remaining = raw_bytes[pos:]

    if ethertype == ETHERTYPE_IP and len(remaining) >= 20:
        ip_sections = _split_from_ip(remaining, pos, is_v6=False)
        sections.extend(ip_sections)
    elif ethertype == ETHERTYPE_IPV6 and len(remaining) >= 40:
        ip_sections = _split_from_ip(remaining, pos, is_v6=True)
        sections.extend(ip_sections)
    elif ethertype == ETHERTYPE_ARP and len(remaining) >= 28:
        arp_data = remaining[:28]
        sections.append(_make_section("ARP Header", arp_data, pos,
                                      fields=_arp_fields(arp_data, pos)))
        if len(remaining) > 28:
            sections.append(_make_section("Payload", remaining[28:], pos + 28,
                                          payload_relative=True))
    elif remaining:
        sections.append(_make_section("Payload", remaining, pos,
                                      payload_relative=True))

    return sections


def _split_from_ip(
    data: bytes, base_offset: int, *, is_v6: bool = False,
) -> list[dict[str, Any]]:
    """Split IP packet (v4 or v6) into header + transport + payload sections."""
    sections: list[dict[str, Any]] = []

    if is_v6:
        ipv6_header = data[:40]
        next_header = data[6] if len(data) > 6 else 0
        sections.append(_make_section("IPv6 Header", ipv6_header, base_offset,
                                      fields=_ipv6_fields(ipv6_header, base_offset)))
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
        sections.append(_make_section("IPv4 Header", ip_header, base_offset,
                                      fields=_ipv4_fields(ip_header, base_offset)))
        transport_data = data[ihl:]
        transport_offset = base_offset + ihl

    # Transport layer
    payload_data, payload_offset = _split_transport(
        proto, transport_data, transport_offset, sections
    )

    if payload_data:
        sections.append(_make_section("Payload", payload_data, payload_offset,
                                      payload_relative=True))

    return sections


def _split_transport(
    proto: int,
    data: bytes,
    base_offset: int,
    sections: list[dict[str, Any]],
) -> tuple[bytes, int]:
    """Parse TCP/UDP/ICMP header and return remaining payload."""
    if proto == PROTO_TCP and len(data) >= 20:
        data_offset_byte = data[12] if len(data) > 12 else 0
        tcp_header_len = ((data_offset_byte >> 4) & 0x0F) * 4
        if tcp_header_len < 20:
            tcp_header_len = 20
        if tcp_header_len > len(data):
            tcp_header_len = len(data)

        tcp_hdr = data[:tcp_header_len]
        sections.append(_make_section("TCP Header", tcp_hdr, base_offset,
                                      fields=_tcp_fields(tcp_hdr, base_offset)))
        return data[tcp_header_len:], base_offset + tcp_header_len

    elif proto == PROTO_UDP and len(data) >= 8:
        udp_hdr = data[:8]
        sections.append(_make_section("UDP Header", udp_hdr, base_offset,
                                      fields=_udp_fields(udp_hdr, base_offset)))
        return data[8:], base_offset + 8

    elif proto == PROTO_ICMP and len(data) >= 8:
        icmp_hdr = data[:8]
        sections.append(_make_section("ICMP Header", icmp_hdr, base_offset,
                                      fields=_icmp_fields(icmp_hdr, base_offset)))
        return data[8:], base_offset + 8

    elif proto == PROTO_ICMPV6 and len(data) >= 8:
        icmpv6_hdr = data[:8]
        sections.append(_make_section("ICMPv6 Header", icmpv6_hdr, base_offset,
                                      fields=_icmpv6_fields(icmpv6_hdr, base_offset)))
        return data[8:], base_offset + 8

    elif data:
        # Unknown transport — treat everything as payload
        return data, base_offset

    return b"", base_offset


# ---------------------------------------------------------------------------
# Formatting helpers
# ---------------------------------------------------------------------------

def _make_section(
    name: str,
    data: bytes,
    offset: int,
    fields: list[dict[str, Any]] | None = None,
    *,
    payload_relative: bool = False,
) -> dict[str, Any]:
    """Create a section dict with hex dump lines and optional field breakdown.

    When payload_relative=True the hex dump offsets start from 0 (relative
    to the beginning of this section) instead of the absolute packet offset.
    This is used for the Payload section so consumers can index payload[0..N].
    """
    hex_start = 0 if payload_relative else offset
    return {
        "name": name,
        "offset": offset,
        "length": len(data),
        "payload_relative": payload_relative,
        "fields": fields or [],
        "hex_lines": _format_hex_block(data, hex_start),
    }


def _format_hex_block(data: bytes, start_offset: int) -> list[str]:
    """Format bytes into hex dump lines (offset | hex bytes | ASCII).

    Each line covers 16 bytes, formatted like:
      0000  48 65 6C 6C 6F 20 57 6F  72 6C 64 21 00 00 00 00  |Hello World!....|
    """
    lines: list[str] = []
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

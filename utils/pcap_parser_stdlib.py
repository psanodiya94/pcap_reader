"""PCAP file parser using only Python standard library (struct)."""

import struct
import socket


# Pcap magic numbers
PCAP_MAGIC_LE = 0xA1B2C3D4
PCAP_MAGIC_BE = 0xD4C3B2A1
PCAPNG_MAGIC = 0x0A0D0D0A

# Ethernet types
ETHERTYPE_IP = 0x0800
ETHERTYPE_IPV6 = 0x86DD
ETHERTYPE_ARP = 0x0806

# IP protocols
PROTO_ICMP = 1
PROTO_TCP = 6
PROTO_UDP = 17
PROTO_ICMPV6 = 58

# TCP flags
TCP_FLAGS = {
    0x01: "F", 0x02: "S", 0x04: "R", 0x08: "P",
    0x10: "A", 0x20: "U", 0x40: "E", 0x80: "C",
}


def parse_pcap(file_path):
    """Parse a pcap file using only the standard library."""
    with open(file_path, "rb") as f:
        data = f.read()

    magic = struct.unpack("<I", data[:4])[0]

    if magic == PCAPNG_MAGIC:
        raise ValueError(
            "pcapng format detected. The standard library parser only supports "
            "classic pcap format. Install scapy for pcapng support: "
            "pip install scapy"
        )

    if magic == PCAP_MAGIC_LE:
        endian = "<"
    elif magic == PCAP_MAGIC_BE:
        endian = ">"
    else:
        raise ValueError(f"Not a valid pcap file (magic: 0x{magic:08X})")

    # Global header: magic(4) + version_major(2) + version_minor(2) +
    #                thiszone(4) + sigfigs(4) + snaplen(4) + network(4) = 24 bytes
    _magic, ver_maj, ver_min, _tz, _sf, snaplen, link_type = struct.unpack(
        f"{endian}IHHiIII", data[:24]
    )

    offset = 24
    parsed = []
    pkt_no = 0

    while offset < len(data):
        # Packet header: ts_sec(4) + ts_usec(4) + incl_len(4) + orig_len(4) = 16
        if offset + 16 > len(data):
            break

        ts_sec, ts_usec, incl_len, orig_len = struct.unpack(
            f"{endian}IIII", data[offset:offset + 16]
        )
        offset += 16

        if offset + incl_len > len(data):
            break

        pkt_data = data[offset:offset + incl_len]
        offset += incl_len
        pkt_no += 1

        entry = {
            "no": pkt_no,
            "time": ts_sec + ts_usec / 1_000_000,
            "length": orig_len,
            "src": "",
            "dst": "",
            "protocol": "",
            "info": "",
            "layers": [],
        }

        # Link type 1 = Ethernet
        if link_type == 1 and len(pkt_data) >= 14:
            entry["layers"].append("Ethernet")
            _parse_ethernet(pkt_data, entry)
        # Link type 101 = Raw IP
        elif link_type == 101 and len(pkt_data) >= 20:
            entry["layers"].append("Raw IP")
            version = (pkt_data[0] >> 4) & 0x0F
            if version == 4:
                _parse_ipv4(pkt_data, entry)
            elif version == 6:
                _parse_ipv6(pkt_data, entry)
        else:
            entry["protocol"] = f"LinkType({link_type})"
            entry["info"] = f"Length: {orig_len}"

        if not entry["protocol"]:
            entry["protocol"] = "Unknown"
            entry["info"] = f"Length: {orig_len}"

        parsed.append(entry)

    summary = _build_summary(parsed)
    return {"packets": parsed, "summary": summary}


def _parse_ethernet(pkt_data, entry):
    """Parse an Ethernet frame."""
    dst_mac = _format_mac(pkt_data[0:6])
    src_mac = _format_mac(pkt_data[6:12])
    ethertype = struct.unpack("!H", pkt_data[12:14])[0]

    payload = pkt_data[14:]

    if ethertype == ETHERTYPE_IP and len(payload) >= 20:
        _parse_ipv4(payload, entry)
    elif ethertype == ETHERTYPE_IPV6 and len(payload) >= 40:
        _parse_ipv6(payload, entry)
    elif ethertype == ETHERTYPE_ARP and len(payload) >= 28:
        _parse_arp(payload, entry)
    else:
        entry["src"] = src_mac
        entry["dst"] = dst_mac
        entry["protocol"] = f"0x{ethertype:04X}"
        entry["info"] = f"EtherType: 0x{ethertype:04X}"


def _parse_ipv4(payload, entry):
    """Parse an IPv4 packet."""
    entry["layers"].append("IPv4")
    ihl = (payload[0] & 0x0F) * 4
    total_len, proto = struct.unpack("!xBH", payload[1:4])[1], payload[9]
    entry["src"] = socket.inet_ntoa(payload[12:16])
    entry["dst"] = socket.inet_ntoa(payload[16:20])

    ip_payload = payload[ihl:]
    _parse_transport(ip_payload, proto, entry)


def _parse_ipv6(payload, entry):
    """Parse an IPv6 packet."""
    entry["layers"].append("IPv6")
    next_header = payload[6]
    entry["src"] = _format_ipv6(payload[8:24])
    entry["dst"] = _format_ipv6(payload[24:40])

    ip_payload = payload[40:]
    _parse_transport(ip_payload, next_header, entry)


def _parse_transport(payload, proto, entry):
    """Parse transport layer (TCP/UDP/ICMP)."""
    if proto == PROTO_TCP and len(payload) >= 20:
        entry["layers"].append("TCP")
        entry["protocol"] = "TCP"
        sport, dport, seq, ack, offset_flags = struct.unpack("!HHIIH", payload[:14])
        data_offset = ((offset_flags >> 12) & 0x0F) * 4
        flags_val = offset_flags & 0x1FF
        window = struct.unpack("!H", payload[14:16])[0]

        flags = _decode_tcp_flags(flags_val)
        entry["info"] = f"{sport} -> {dport} [{flags}] Seq={seq} Ack={ack} Win={window}"

        # Simple DNS detection on port 53
        if (sport == 53 or dport == 53) and len(payload) > data_offset:
            entry["protocol"] = "DNS"
            _try_parse_dns(payload[data_offset:], entry)

        # Simple HTTP detection on port 80/8080
        if dport in (80, 8080) and len(payload) > data_offset:
            http_data = payload[data_offset:]
            if http_data[:3] in (b"GET", b"POS", b"PUT", b"DEL", b"HEA", b"PAT", b"OPT"):
                entry["protocol"] = "HTTP"
                try:
                    first_line = http_data.split(b"\r\n")[0].decode("ascii", errors="replace")
                    entry["info"] = first_line
                except Exception:
                    pass

    elif proto == PROTO_UDP and len(payload) >= 8:
        entry["layers"].append("UDP")
        entry["protocol"] = "UDP"
        sport, dport, udp_len = struct.unpack("!HHH", payload[:6])
        entry["info"] = f"{sport} -> {dport} Len={udp_len}"

        # DNS detection
        if (sport == 53 or dport == 53) and len(payload) > 8:
            entry["protocol"] = "DNS"
            _try_parse_dns(payload[8:], entry)

    elif proto == PROTO_ICMP and len(payload) >= 4:
        entry["layers"].append("ICMP")
        entry["protocol"] = "ICMP"
        icmp_type, icmp_code = struct.unpack("!BB", payload[:2])
        entry["info"] = f"Type={icmp_type} Code={icmp_code}"

    elif proto == PROTO_ICMPV6 and len(payload) >= 4:
        entry["layers"].append("ICMPv6")
        entry["protocol"] = "ICMPv6"
        icmp_type, icmp_code = struct.unpack("!BB", payload[:2])
        entry["info"] = f"Type={icmp_type} Code={icmp_code}"

    else:
        entry["protocol"] = f"IPProto({proto})"
        entry["info"] = f"IP Protocol: {proto}"


def _parse_arp(payload, entry):
    """Parse an ARP packet."""
    entry["layers"].append("ARP")
    entry["protocol"] = "ARP"
    hw_type, proto_type, hw_size, proto_size, opcode = struct.unpack("!HHBBH", payload[:8])

    if hw_size == 6 and proto_size == 4:
        sender_ip = socket.inet_ntoa(payload[14:18])
        target_ip = socket.inet_ntoa(payload[24:28])
        sender_mac = _format_mac(payload[8:14])
        entry["src"] = sender_ip
        entry["dst"] = target_ip
        if opcode == 1:
            entry["info"] = f"Who has {target_ip}? Tell {sender_ip}"
        elif opcode == 2:
            entry["info"] = f"{sender_ip} is at {sender_mac}"
        else:
            entry["info"] = f"ARP opcode {opcode}"
    else:
        entry["info"] = f"ARP hw_size={hw_size} proto_size={proto_size}"


def _try_parse_dns(payload, entry):
    """Try to parse DNS query/response name from raw bytes."""
    if len(payload) < 12:
        return
    flags = struct.unpack("!H", payload[2:4])[0]
    qr = (flags >> 15) & 1

    # Try to read the first query name starting at offset 12
    name = _read_dns_name(payload, 12)
    if qr == 0:
        entry["info"] = f"Query: {name}" if name else "DNS Query"
    else:
        entry["info"] = f"Response: {name}" if name else "DNS Response"


def _read_dns_name(data, offset):
    """Read a DNS name from raw bytes (no pointer support for simplicity)."""
    parts = []
    pos = offset
    for _ in range(64):  # safety limit
        if pos >= len(data):
            break
        length = data[pos]
        if length == 0:
            break
        if (length & 0xC0) == 0xC0:
            # Pointer — skip for stdlib parser
            break
        pos += 1
        if pos + length > len(data):
            break
        parts.append(data[pos:pos + length].decode("ascii", errors="replace"))
        pos += length
    return ".".join(parts) if parts else ""


def _decode_tcp_flags(flags_val):
    """Decode TCP flags integer to string."""
    parts = []
    for bit, char in sorted(TCP_FLAGS.items()):
        if flags_val & bit:
            parts.append(char)
    return "".join(parts) if parts else "none"


def _format_mac(raw):
    """Format 6 bytes as a MAC address string."""
    return ":".join(f"{b:02x}" for b in raw)


def _format_ipv6(raw):
    """Format 16 bytes as an IPv6 address."""
    try:
        return socket.inet_ntop(socket.AF_INET6, raw)
    except Exception:
        return ":".join(f"{raw[i]:02x}{raw[i+1]:02x}" for i in range(0, 16, 2))


def _build_summary(packets):
    """Build a summary of the pcap data."""
    protocols = {}
    src_addrs = set()
    dst_addrs = set()

    for pkt in packets:
        proto = pkt["protocol"]
        protocols[proto] = protocols.get(proto, 0) + 1
        if pkt["src"]:
            src_addrs.add(pkt["src"])
        if pkt["dst"]:
            dst_addrs.add(pkt["dst"])

    return {
        "total_packets": len(packets),
        "protocols": protocols,
        "unique_sources": len(src_addrs),
        "unique_destinations": len(dst_addrs),
        "source_addresses": sorted(src_addrs),
        "destination_addresses": sorted(dst_addrs),
    }

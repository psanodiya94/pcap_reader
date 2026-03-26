"""PCAP file parser using scapy."""

from __future__ import annotations

import struct
from collections import Counter
from decimal import Decimal
from typing import Any

from scapy.all import rdpcap, IP, TCP, UDP, ICMP, DNS, ARP, IPv6, Raw, Ether, Dot1Q
from scapy.layers.http import HTTPRequest, HTTPResponse

# eCPRI EtherType (O-RAN WG4 C/U-plane)
_ECPRI_ETHERTYPE = 0xAEFE
_ETHERTYPE_VLAN  = 0x8100   # 802.1Q
_ETHERTYPE_QINQ  = 0x88A8   # 802.1ad S-VLAN (double-tagged)

# eCPRI message type names
_ECPRI_MSG_TYPES: dict[int, str] = {
    0x00: "IQ Data",
    0x01: "Bit Sequence",
    0x02: "Real-Time Control Data",
    0x03: "Generic Data Transfer",
    0x04: "Remote Memory Access",
    0x05: "One-Way Delay Measurement",
    0x06: "Remote Reset",
    0x07: "Event Indication",
}


# Pcap magic numbers
_PCAP_MAGIC_LE    = 0xA1B2C3D4  # microsecond, little-endian
_PCAP_MAGIC_BE    = 0xD4C3B2A1  # microsecond, big-endian
_PCAP_MAGIC_NS_LE = 0xA1B23C4D  # nanosecond,  little-endian  ← TsNSec format
_PCAP_MAGIC_NS_BE = 0x4D3CB2A1  # nanosecond,  big-endian

# TAI–UTC leap-second offset (seconds to subtract from TAI to obtain UTC).
# PTP/IEEE 1588 clocks run on TAI; this value has been 37 s since Jan 2017.
# Stored as a module constant so it is easy to update if a new leap second
# is announced.
_TAI_UTC_OFFSET = 37

_LINK_TYPE_NAMES: dict[int, str] = {
    0: "NULL", 1: "Ethernet", 6: "Token Ring", 10: "FDDI",
    101: "Raw IP", 105: "IEEE 802.11 (Wi-Fi)", 113: "Linux SLL",
    127: "IEEE 802.11 RadioTap", 143: "IEEE 802.11 AVS",
}


def _read_pcap_global_header(file_path: str) -> dict[str, Any]:
    """Parse the 24-byte pcap global header.

    Layout (little-endian for normal pcap):
      Bytes  0- 3: MagicNumber  (uint32)
      Bytes  4- 5: VersionMajor (uint16)
      Bytes  6- 7: VersionMinor (uint16)
      Bytes  8-11: ThisZone     (int32)  — seconds to add to ts to get UTC
      Bytes 12-15: SigFigs      (uint32) — timestamp accuracy (usually 0)
      Bytes 16-19: SnapLen      (uint32) — max captured bytes per packet
      Bytes 20-23: Network      (uint32) — link-layer type (DLT_*)
    """
    try:
        with open(file_path, "rb") as f:
            raw = f.read(24)
    except OSError:
        return {}

    if len(raw) < 24:
        return {}

    magic = struct.unpack("<I", raw[:4])[0]
    if magic in (_PCAP_MAGIC_LE, _PCAP_MAGIC_NS_LE):
        endian = "<"
    elif magic in (_PCAP_MAGIC_BE, _PCAP_MAGIC_NS_BE):
        endian = ">"
    else:
        return {}  # pcapng or unrecognised format

    ns_precision = magic in (_PCAP_MAGIC_NS_LE, _PCAP_MAGIC_NS_BE)
    _, vmaj, vmin, thiszone, sigfigs, snaplen, network = struct.unpack(
        f"{endian}IHHiIII", raw
    )
    return {
        "magic": f"0x{magic:08X}",
        "version": f"{vmaj}.{vmin}",
        "thiszone": int(thiszone),
        "sigfigs": int(sigfigs),
        "snaplen": int(snaplen),
        "network": int(network),
        "link_type": _LINK_TYPE_NAMES.get(network, f"DLT_{network}"),
        "ns_precision": ns_precision,
        "timestamp_unit": "nanoseconds" if ns_precision else "microseconds",
    }


def _get_ecpri_payload(pkt: Any) -> bytes | None:
    """Return the raw eCPRI payload bytes for a packet, handling VLAN tags.

    5G-RAN fronthaul frames are usually VLAN-tagged (single 802.1Q or double
    802.1ad QinQ).  Walking the scapy layer chain handles all three cases:
      - Untagged:            Ether → Raw(eCPRI)
      - Single-tagged 802.1Q: Ether(0x8100) → Dot1Q(0xAEFE) → Raw(eCPRI)
      - Double-tagged QinQ:   Ether(0x88A8) → Dot1Q(0x8100) → Dot1Q(0xAEFE) → Raw(eCPRI)
    """
    if not pkt.haslayer(Ether):
        return None
    layer = pkt[Ether]
    # Walk through VLAN layers until we find eCPRI or a non-VLAN EtherType
    while layer is not None:
        et = layer.type if hasattr(layer, "type") else None
        if et == _ECPRI_ETHERTYPE:
            return bytes(layer.payload)
        if et in (_ETHERTYPE_VLAN, _ETHERTYPE_QINQ) and layer.payload:
            # Descend into the inner VLAN/S-VLAN layer (scapy uses Dot1Q for both)
            layer = layer.payload if isinstance(layer.payload, (Ether, Dot1Q)) else None
        else:
            break
    return None


def _parse_ecpri(raw_bytes: bytes) -> dict[str, Any] | None:
    """Parse eCPRI common header and O-RAN U-plane section header.

    Byte layout (O-RAN.WG4.CUS spec):
      Byte 0: ecpriVersion(4) | ecpriReserved(3) | ecpriC(1)
      Byte 1: ecpriMessage  (message type)
      Bytes 2-3: ecpriPayload (payload size in bytes)
    For IQ Data (msg type 0x00) — transport header continues:
      Bytes 4-5: PC_ID / eAxC_ID
      Bytes 6-7: Sequence ID
    O-RAN section header (octets 9-12, 0-indexed bytes 8-11):
      Byte  8: dataDirection(1) | payloadVersion(3) | filterIndex(4)
      Byte  9: frameId (8 bits)
      Byte 10: subframeId(4) | slotId[5:2](4)
      Byte 11: slotId[1:0](2) | symbolId(6)
    """
    if len(raw_bytes) < 4:
        return None

    byte0 = raw_bytes[0]
    ecpri_version = (byte0 >> 4) & 0xF
    ecpri_c = byte0 & 0x1
    ecpri_msg = raw_bytes[1]
    ecpri_payload_size = (raw_bytes[2] << 8) | raw_bytes[3]

    result: dict[str, Any] = {
        "ecpri_version": ecpri_version,
        "ecpri_concatenation": bool(ecpri_c),
        "ecpri_message_type": ecpri_msg,
        "ecpri_message_name": _ECPRI_MSG_TYPES.get(ecpri_msg, f"0x{ecpri_msg:02X}"),
        "ecpri_payload_size": ecpri_payload_size,
    }

    # IQ Data message — parse transport header + O-RAN section header
    if ecpri_msg == 0x00 and len(raw_bytes) >= 8:
        pc_id = (raw_bytes[4] << 8) | raw_bytes[5]
        seq_id = (raw_bytes[6] << 8) | raw_bytes[7]
        result["pc_id"] = pc_id
        result["seq_id"] = seq_id & 0x00FF        # lower 8 bits = sequence number
        result["e_bit"] = (raw_bytes[6] >> 7) & 0x1  # first-last indication

        if len(raw_bytes) >= 12:
            b8 = raw_bytes[8]
            result["data_direction"] = "DL" if (b8 >> 7) & 0x1 == 0 else "UL"
            result["payload_version"] = (b8 >> 4) & 0x7
            result["filter_index"] = b8 & 0xF

            result["frame_id"] = raw_bytes[9]

            b10 = raw_bytes[10]
            result["subframe_id"] = (b10 >> 4) & 0xF
            slot_hi = b10 & 0xF  # slotId bits [5:2]

            b11 = raw_bytes[11]
            slot_lo = (b11 >> 6) & 0x3   # slotId bits [1:0]
            result["slot_id"] = (slot_hi << 2) | slot_lo
            result["symbol_id"] = b11 & 0x3F

    return result


def parse_pcap(file_path: str) -> dict[str, Any]:
    """Parse a pcap file and return structured packet data."""
    file_header = _read_pcap_global_header(file_path)
    packets = rdpcap(file_path)
    parsed: list[dict[str, Any]] = []

    # thiszone: seconds to ADD to raw timestamp to get UTC.
    # If the capture is PTP/TAI-based (common in eCPRI/5G-RAN captures) the
    # raw TsSec value is TAI time, which runs _TAI_UTC_OFFSET seconds AHEAD
    # of UTC.  Subtracting the leap-second offset converts TAI → UTC.
    # thiszone in the global header can override this (standard pcap allows
    # negative values to signal a UTC correction, but most captures leave it 0).
    thiszone: int = file_header.get("thiszone", 0)

    for i, pkt in enumerate(packets, start=1):
        incl_len = len(bytes(pkt))
        orig_len = int(getattr(pkt, "wirelen", incl_len) or incl_len)

        # Use Decimal arithmetic to avoid float precision loss on nanosecond pcap.
        t: Decimal = Decimal(str(pkt.time))
        ts_sec_raw  = int(t)
        ts_nsec     = int((t - ts_sec_raw) * Decimal("1000000000"))

        # Apply global-header timezone correction then PTP TAI→UTC correction.
        ts_sec_utc  = ts_sec_raw + thiszone - _TAI_UTC_OFFSET

        entry: dict[str, Any] = {
            "no": i,
            "time": float(t),
            "ts_sec": ts_sec_utc,       # UTC seconds (corrected)
            "ts_sec_raw": ts_sec_raw,   # raw TAI seconds as stored in the file
            "ts_nsec": ts_nsec,
            "length": incl_len,
            "orig_len": orig_len,
            "src": "",
            "dst": "",
            "protocol": "",
            "info": "",
            "layers": [],
        }

        # Extract layers
        layer = pkt
        while layer:
            entry["layers"].append(layer.__class__.__name__)
            layer = layer.payload if layer.payload and not isinstance(layer.payload, (bytes, type(None))) else None
            if isinstance(layer, Raw):
                entry["layers"].append("Raw")
                break

        # IP layer
        if pkt.haslayer(IP):
            entry["src"] = pkt[IP].src
            entry["dst"] = pkt[IP].dst
        elif pkt.haslayer(IPv6):
            entry["src"] = pkt[IPv6].src
            entry["dst"] = pkt[IPv6].dst
        elif pkt.haslayer(ARP):
            entry["src"] = pkt[ARP].psrc
            entry["dst"] = pkt[ARP].pdst
            entry["protocol"] = "ARP"
            entry["info"] = (
                f"Who has {pkt[ARP].pdst}? Tell {pkt[ARP].psrc}"
                if pkt[ARP].op == 1
                else f"{pkt[ARP].psrc} is at {pkt[ARP].hwsrc}"
            )
        else:
            # Use Ethernet MAC addresses; annotate with VLAN ID(s) if present
            src_mac = pkt.src if hasattr(pkt, "src") else "N/A"
            dst_mac = pkt.dst if hasattr(pkt, "dst") else "N/A"
            if pkt.haslayer(Dot1Q):
                vlan_ids: list[int] = []
                layer = pkt[Dot1Q]
                while layer and hasattr(layer, "vlan"):
                    vlan_ids.append(layer.vlan)
                    layer = layer.payload if isinstance(layer.payload, Dot1Q) else None
                vlan_str = "/".join(str(v) for v in vlan_ids)
                entry["src"] = f"{src_mac} (VLAN {vlan_str})"
                entry["dst"] = dst_mac
            else:
                entry["src"] = src_mac
                entry["dst"] = dst_mac

        # eCPRI detection — handles untagged, 802.1Q VLAN, and QinQ double-tagged
        _ecpri_raw = _get_ecpri_payload(pkt)
        if _ecpri_raw is not None:
            ecpri = _parse_ecpri(_ecpri_raw)
            if ecpri:
                entry["ecpri"] = ecpri
                entry["protocol"] = "eCPRI"
                if ecpri.get("frame_id") is not None:
                    entry["info"] = (
                        f"{ecpri['ecpri_message_name']} "
                        f"{ecpri['data_direction']} "
                        f"frame={ecpri['frame_id']} "
                        f"subframe={ecpri['subframe_id']} "
                        f"slot={ecpri['slot_id']} "
                        f"sym={ecpri['symbol_id']} "
                        f"PC_ID=0x{ecpri['pc_id']:04X}"
                    )
                else:
                    entry["info"] = (
                        f"{ecpri['ecpri_message_name']} "
                        f"payload_size={ecpri['ecpri_payload_size']}"
                    )

        # Protocol detection
        if not entry["protocol"]:
            if pkt.haslayer(DNS):
                entry["protocol"] = "DNS"
                dns = pkt[DNS]
                if dns.qr == 0 and dns.qd:
                    entry["info"] = f"Query: {dns.qd.qname.decode() if dns.qd.qname else 'N/A'}"
                elif dns.qr == 1:
                    entry["info"] = f"Response: {dns.an.rdata if dns.an and hasattr(dns.an, 'rdata') else 'N/A'}"
            elif pkt.haslayer(HTTPRequest):
                entry["protocol"] = "HTTP"
                http = pkt[HTTPRequest]
                entry["info"] = f"{http.Method.decode()} {http.Path.decode()} {http.Host.decode() if http.Host else ''}"
            elif pkt.haslayer(HTTPResponse):
                entry["protocol"] = "HTTP"
                entry["info"] = f"Response {pkt[HTTPResponse].Status_Code.decode() if hasattr(pkt[HTTPResponse], 'Status_Code') else ''}"
            elif pkt.haslayer(TCP):
                entry["protocol"] = "TCP"
                tcp = pkt[TCP]
                flags = tcp.sprintf("%TCP.flags%")
                entry["info"] = f"{tcp.sport} -> {tcp.dport} [{flags}] Seq={tcp.seq} Ack={tcp.ack} Win={tcp.window}"
            elif pkt.haslayer(UDP):
                entry["protocol"] = "UDP"
                udp = pkt[UDP]
                entry["info"] = f"{udp.sport} -> {udp.dport} Len={udp.len}"
            elif pkt.haslayer(ICMP):
                entry["protocol"] = "ICMP"
                icmp = pkt[ICMP]
                entry["info"] = f"Type={icmp.type} Code={icmp.code}"
            else:
                entry["protocol"] = entry["layers"][0] if entry["layers"] else "Unknown"
                entry["info"] = f"Length: {len(pkt)}"

        parsed.append(entry)

    summary = _build_summary(parsed)
    return {"packets": parsed, "summary": summary, "file_header": file_header}


def _build_summary(packets: list[dict[str, Any]]) -> dict[str, Any]:
    """Build a summary of the pcap data."""
    protocol_counts = Counter(pkt["protocol"] for pkt in packets)
    src_addrs = {pkt["src"] for pkt in packets if pkt["src"]}
    dst_addrs = {pkt["dst"] for pkt in packets if pkt["dst"]}

    return {
        "total_packets": len(packets),
        "protocols": dict(protocol_counts),
        "unique_sources": len(src_addrs),
        "unique_destinations": len(dst_addrs),
        "source_addresses": sorted(src_addrs),
        "destination_addresses": sorted(dst_addrs),
    }

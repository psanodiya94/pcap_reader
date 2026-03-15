"""PCAP file parser using scapy."""

from scapy.all import rdpcap, IP, TCP, UDP, ICMP, DNS, ARP, IPv6, Raw
from scapy.layers.http import HTTPRequest, HTTPResponse


def parse_pcap(file_path):
    """Parse a pcap file and return structured packet data."""
    packets = rdpcap(file_path)
    parsed = []

    for i, pkt in enumerate(packets, start=1):
        entry = {
            "no": i,
            "time": float(pkt.time),
            "length": len(pkt),
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
            entry["info"] = f"Who has {pkt[ARP].pdst}? Tell {pkt[ARP].psrc}" if pkt[ARP].op == 1 else f"{pkt[ARP].psrc} is at {pkt[ARP].hwsrc}"
        else:
            entry["src"] = pkt.src if hasattr(pkt, "src") else "N/A"
            entry["dst"] = pkt.dst if hasattr(pkt, "dst") else "N/A"

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
    return {"packets": parsed, "summary": summary}


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

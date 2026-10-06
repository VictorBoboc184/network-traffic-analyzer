#!/usr/bin/env python3
"""
capture_traffic.py
-------------------
Captures live network traffic (or reads a .pcap/.pcapng file exported from
Wireshark) and writes a structured, per-packet log to a CSV file.

The CSV produced here is the input for analyze_logs.py, which scans it
for suspicious patterns (port scans, risky open ports, possible SYN
floods, DNS anomalies, large data transfers).

Uses Scapy, which relies on the same underlying capture mechanism
(libpcap/Npcap) as Wireshark -- so a live capture here is functionally
equivalent to a Wireshark capture, and this script can also load a
.pcap/.pcapng file that was captured in Wireshark directly.

ETHICAL USE NOTICE:
Only capture traffic on networks you own or have explicit permission to
monitor (e.g. your home network, or a lab/VM environment). Capturing
traffic on networks you do not control or do not have permission to
monitor may be illegal.

Usage:
    Live capture (requires admin/root privileges):
        sudo python3 capture_traffic.py --interface eth0 --duration 60 --output packet_logs.csv

    Analyze an existing Wireshark capture instead of sniffing live:
        python3 capture_traffic.py --pcap mycapture.pcapng --output packet_logs.csv
"""

import argparse
import csv
import sys
from datetime import datetime

from scapy.all import sniff, rdpcap, IP, TCP, UDP, DNS, DNSQR

CSV_FIELDS = [
    "timestamp", "src_ip", "dst_ip", "src_port", "dst_port",
    "protocol", "length", "tcp_flags", "dns_query",
]


def parse_packet(pkt):
    """Extract the fields we care about from a single packet.
    Returns a dict matching CSV_FIELDS, or None if the packet has no IP layer
    (e.g. pure ARP/Ethernet broadcast), since our detections are IP-based.
    """
    if IP not in pkt:
        return None

    row = {
        "timestamp": datetime.fromtimestamp(float(pkt.time)).isoformat(timespec="seconds"),
        "src_ip": pkt[IP].src,
        "dst_ip": pkt[IP].dst,
        "src_port": "",
        "dst_port": "",
        "protocol": "OTHER",
        "length": len(pkt),
        "tcp_flags": "",
        "dns_query": "",
    }

    if TCP in pkt:
        row["protocol"] = "TCP"
        row["src_port"] = pkt[TCP].sport
        row["dst_port"] = pkt[TCP].dport
        row["tcp_flags"] = pkt[TCP].flags.flagrepr()  # e.g. "S", "SA", "R", "PA"
    elif UDP in pkt:
        row["protocol"] = "UDP"
        row["src_port"] = pkt[UDP].sport
        row["dst_port"] = pkt[UDP].dport

    # If this is a DNS query, capture the queried domain name -- used later
    # to flag unusually long / high-entropy names (a common DNS tunneling sign)
    if pkt.haslayer(DNS) and pkt.haslayer(DNSQR):
        row["protocol"] = "DNS"
        try:
            row["dns_query"] = pkt[DNSQR].qname.decode(errors="ignore")
        except Exception:
            row["dns_query"] = str(pkt[DNSQR].qname)

    return row


def main():
    parser = argparse.ArgumentParser(description="Capture network traffic into a CSV log for later analysis.")
    parser.add_argument("--interface", help="Network interface to sniff on, e.g. eth0, wlan0 (live capture)")
    parser.add_argument("--pcap", help="Path to an existing .pcap/.pcapng file to read instead of sniffing live")
    parser.add_argument("--duration", type=int, default=60, help="Seconds to capture for (live capture only). Default: 60")
    parser.add_argument("--output", default="packet_logs.csv", help="CSV file to write results to")
    args = parser.parse_args()

    rows = []

    if args.pcap:
        print(f"[*] Reading packets from {args.pcap} ...")
        packets = rdpcap(args.pcap)
        for pkt in packets:
            row = parse_packet(pkt)
            if row:
                rows.append(row)
    else:
        print(f"[*] Starting live capture on interface={args.interface or 'default'} for {args.duration}s ...")
        print("[*] (requires administrator/root privileges)")

        def on_packet(pkt):
            row = parse_packet(pkt)
            if row:
                rows.append(row)

        try:
            sniff(iface=args.interface, timeout=args.duration, prn=on_packet, store=False)
        except PermissionError:
            print("[!] Permission denied. Run this script as administrator/root to capture live traffic.")
            sys.exit(1)

    with open(args.output, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=CSV_FIELDS)
        writer.writeheader()
        writer.writerows(rows)

    print(f"[+] Captured {len(rows)} IP packets. Log written to {args.output}")
    print(f"[+] Next step: python3 analyze_logs.py --input {args.output} --output alerts.txt")


if __name__ == "__main__":
    main()

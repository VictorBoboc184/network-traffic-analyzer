#!/usr/bin/env python3
"""
analyze_logs.py
----------------
Reads the CSV packet log produced by capture_traffic.py and scans it for
suspicious patterns, writing a human-readable alert report.

Detection rules implemented (each is a simplified version of a real
blue-team / IDS technique):

  1. Port scan detection   - one source IP hitting many distinct
                              destination ports in a short time window.
  2. High-risk open ports  - traffic to ports commonly targeted or
                              considered insecure (Telnet, FTP, SMB, RDP...).
  3. Possible SYN flood    - one source sending an unusually high number
                              of TCP SYN packets in a short window (a sign
                              of a SYN-flood DoS attempt or aggressive scan).
  4. Large data transfer   - a single source/destination pair moving an
                              unusually large volume of bytes (possible
                              exfiltration or large download).
  5. Suspicious DNS query  - unusually long domain names, a common
                              indicator of DNS tunneling / C2 beaconing.

This is a portfolio / learning project: the thresholds are simple and
tunable via CLI flags, not a production-grade detection engine. Real
SIEM/IDS tools (Suricata, Splunk, Zeek) use far more sophisticated,
statistically-tuned logic -- but the underlying ideas are the same ones
implemented here.

Usage:
    python3 analyze_logs.py --input packet_logs.csv --output alerts.txt
"""

import argparse
import csv
from collections import defaultdict
from datetime import datetime

HIGH_RISK_PORTS = {
    21: "FTP (unencrypted credentials)",
    23: "Telnet (unencrypted, legacy remote access)",
    135: "MS RPC",
    139: "NetBIOS",
    445: "SMB (common ransomware/lateral-movement target)",
    3389: "RDP (common brute-force target)",
    4444: "Common default Metasploit/malware listener port",
    5900: "VNC (often unauthenticated)",
}

DNS_QUERY_LENGTH_THRESHOLD = 50  # characters; long subdomains can hide tunneled data


def load_rows(path):
    with open(path, newline="") as f:
        reader = csv.DictReader(f)
        return list(reader)


def parse_ts(row):
    return datetime.fromisoformat(row["timestamp"])


def detect_port_scans(rows, port_threshold=15, window_seconds=10):
    """Flag a source IP that contacts many distinct destination ports
    on the same destination IP within a short time window."""
    alerts = []
    # group by (src_ip, dst_ip)
    by_pair = defaultdict(list)
    for row in rows:
        if row["dst_port"]:
            by_pair[(row["src_ip"], row["dst_ip"])].append(row)

    for (src, dst), pkts in by_pair.items():
        pkts.sort(key=parse_ts)
        window = []
        for pkt in pkts:
            window.append(pkt)
            window = [p for p in window if (parse_ts(pkt) - parse_ts(p)).total_seconds() <= window_seconds]
            distinct_ports = {p["dst_port"] for p in window}
            if len(distinct_ports) >= port_threshold:
                alerts.append(
                    f"[HIGH] Possible port scan: {src} -> {dst} contacted "
                    f"{len(distinct_ports)} distinct ports within {window_seconds}s "
                    f"(first seen {window[0]['timestamp']})"
                )
                window = []  # avoid re-flagging the same burst repeatedly
    return alerts


def detect_high_risk_ports(rows):
    alerts = []
    seen = set()
    for row in rows:
        try:
            port = int(row["dst_port"])
        except (ValueError, TypeError):
            continue
        if port in HIGH_RISK_PORTS:
            key = (row["src_ip"], row["dst_ip"], port)
            if key in seen:
                continue
            seen.add(key)
            alerts.append(
                f"[MEDIUM] Traffic to high-risk port: {row['src_ip']} -> "
                f"{row['dst_ip']}:{port} ({HIGH_RISK_PORTS[port]})"
            )
    return alerts


def detect_syn_flood(rows, syn_threshold=50, window_seconds=5):
    """Flag a source IP sending an unusually high rate of bare SYN packets."""
    alerts = []
    syns = [r for r in rows if r.get("tcp_flags") == "S"]
    by_src = defaultdict(list)
    for row in syns:
        by_src[row["src_ip"]].append(row)

    for src, pkts in by_src.items():
        pkts.sort(key=parse_ts)
        window = []
        for pkt in pkts:
            window.append(pkt)
            window = [p for p in window if (parse_ts(pkt) - parse_ts(p)).total_seconds() <= window_seconds]
            if len(window) >= syn_threshold:
                alerts.append(
                    f"[HIGH] Possible SYN flood: {src} sent {len(window)} SYN packets "
                    f"within {window_seconds}s (around {window[-1]['timestamp']})"
                )
                window = []
    return alerts


def detect_large_transfers(rows, byte_threshold=5_000_000):
    """Flag source/destination pairs whose total transferred bytes exceed a threshold."""
    alerts = []
    totals = defaultdict(int)
    for row in rows:
        try:
            totals[(row["src_ip"], row["dst_ip"])] += int(row["length"])
        except (ValueError, TypeError):
            continue

    for (src, dst), total in totals.items():
        if total >= byte_threshold:
            alerts.append(
                f"[MEDIUM] Large data volume: {src} -> {dst} totaled "
                f"{total:,} bytes (threshold: {byte_threshold:,})"
            )
    return alerts


def detect_suspicious_dns(rows, length_threshold=DNS_QUERY_LENGTH_THRESHOLD):
    alerts = []
    for row in rows:
        query = row.get("dns_query", "")
        if query and len(query) >= length_threshold:
            alerts.append(
                f"[LOW] Unusually long DNS query ({len(query)} chars) from "
                f"{row['src_ip']}: {query[:80]}..."
            )
    return alerts


def main():
    parser = argparse.ArgumentParser(description="Analyze a packet CSV log and flag suspicious activity.")
    parser.add_argument("--input", default="packet_logs.csv", help="CSV log produced by capture_traffic.py")
    parser.add_argument("--output", default="alerts.txt", help="File to write the alert report to")
    parser.add_argument("--port-scan-threshold", type=int, default=15)
    parser.add_argument("--syn-threshold", type=int, default=50)
    parser.add_argument("--large-transfer-bytes", type=int, default=5_000_000)
    args = parser.parse_args()

    rows = load_rows(args.input)
    print(f"[*] Loaded {len(rows)} packets from {args.input}")

    all_alerts = []
    all_alerts += detect_port_scans(rows, port_threshold=args.port_scan_threshold)
    all_alerts += detect_high_risk_ports(rows)
    all_alerts += detect_syn_flood(rows, syn_threshold=args.syn_threshold)
    all_alerts += detect_large_transfers(rows, byte_threshold=args.large_transfer_bytes)
    all_alerts += detect_suspicious_dns(rows)

    severity_order = {"[HIGH]": 0, "[MEDIUM]": 1, "[LOW]": 2}
    all_alerts.sort(key=lambda a: severity_order.get(a[:6], 3))

    with open(args.output, "w") as f:
        f.write(f"Network Traffic Analysis Report\n")
        f.write(f"Source log: {args.input}\n")
        f.write(f"Packets analyzed: {len(rows)}\n")
        f.write(f"Alerts found: {len(all_alerts)}\n")
        f.write("=" * 60 + "\n\n")
        if not all_alerts:
            f.write("No suspicious activity detected with current thresholds.\n")
        else:
            for alert in all_alerts:
                f.write(alert + "\n")

    print(f"[+] {len(all_alerts)} alert(s) written to {args.output}")


if __name__ == "__main__":
    main()

# Network Traffic Analyzer

A Python tool for blue team practice: it captures network traffic (live or from a Wireshark .pcap file) and detects suspicious patterns using 5 configurable rules.

## How it works

1. `capture_traffic.py` captures packets with Scapy (libpcap, the same engine behind Wireshark) or reads an existing `.pcap` / `.pcapng` file. Every IP packet is saved to a CSV with: timestamp, source/destination IP, source/destination port, protocol, length, TCP flags and DNS query (if present).
2. `analyze_logs.py` reads the CSV, applies the detection rules and writes a report (`alerts.txt`) sorted by severity.

## Detection rules

| Severity | Rule | What it looks for |
|---|---|---|
| HIGH | Port scan | One source IP contacting many distinct ports on the same target within a short time window |
| HIGH | SYN flood | Abnormally high rate of SYN packets from the same source |
| MEDIUM | Risky ports | Traffic to Telnet, FTP, SMB, RDP, VNC and similar services |
| MEDIUM | Large data transfer | Unusually high byte volume between a source/destination pair |
| LOW | Suspicious DNS | Unusually long DNS queries (possible DNS tunneling) |

All thresholds are configurable from the command line.

## Requirements

- Python 3.x
- Scapy (`pip install -r requirements.txt`)
- Root privileges for live capture (`sudo`)

## Usage

Live capture:
```
sudo python3 capture_traffic.py
```

Read a Wireshark capture:
```
python3 capture_traffic.py capture.pcap
```

Analyze the CSV:
```
python3 analyze_logs.py
```

## Demo

The `sample_logs/` folder contains **synthetic** demo data (not real traffic) with all 5 patterns deliberately included:

- `sample_packet_logs.csv`: demo input
- `sample_alerts.txt`: the report generated from it (8 alerts)

## Testing

- Demo data: all 5 rules triggered correctly (8 alerts).
- Real traffic: a 30-second live capture on a home network (130 packets) produced 0 alerts, as expected for normal traffic.

## Disclaimer

For educational purposes only. Use it only on networks you own or have permission to monitor.

## Author

Victor Boboc, cybersecurity student.

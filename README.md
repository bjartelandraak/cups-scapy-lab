# CUPS Printer Discovery — Attack & Detection with Scapy

DAT505 — Ethical Hacking, University of Stavanger (UiS).  
**Author: Bjarte Landråk**

Investigation of the 2024 CUPS `cups-browsed` vulnerabilities
(**CVE-2024-47176**, **CVE-2024-47076**, **CVE-2024-47175**) using custom
Scapy tooling. The project contains an attack tool that demonstrates the
insecure printer-discovery mechanism and a detection tool that identifies
suspicious CUPS network activity.

> **Ethical / legal notice.** These tools are for an isolated, authorised lab
> only. Run them exclusively against a host you own and have permission to
> test. Do not use them on networks or systems you are not authorised to test.
> Full remote code execution is intentionally out of scope.

---

## Repository layout

```
cups-scapy-lab/
├── cups_attack.py        # Scapy attack tool (rogue printer advertisement)
├── cups_detector.py      # Scapy detection tool (live / offline PCAP)
├── requirements.txt
├── README.md
├── pcap_files/           # Captured / crafted network traffic
├── evidence/             # Logs and screenshots from the experiments
└── report/               # PDF report
```

## Requirements

- Python 3.9+
- Scapy (`pip install -r requirements.txt`)
- Linux with root/`sudo` for live sending and sniffing (raw sockets)
- Lab: Docker (Vulhub CUPS environment), Wireshark/tcpdump

```bash
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

## Lab environment (Task 1)

- **Attacker:** Kali/Ubuntu with Python, Scapy, Wireshark/tcpdump.
- **Victim:** Vulnerable `cups-browsed` container from Vulhub
  (`cups-browsed/CVE-2024-47177`). Exposes UDP/631.
- **Virtual printer:** OpenPrinting `ippserver` (software IPP server), so no
  physical printer is needed.
- All hosts on an isolated bridge network (e.g. `192.168.56.0/24`).

Start the victim:

```bash
git clone https://github.com/vulhub/vulhub
cd vulhub/cups-browsed/CVE-2024-47177
docker compose up -d
```

## Attack tool — `cups_attack.py` (Task 2)

Crafts and sends legacy CUPS *Browse* advertisement packets to the victim's
UDP/631, advertising an attacker-controlled virtual printer. Supports
command-line arguments, logging and PCAP export.

A browse advertisement is a single text line:

```
<type-hex> <state-hex> ipp://<host>:<port>/printers/<name> "loc" "info" "make-model"
```

Examples:

```bash
# Single rogue advertisement to the victim, advertising our virtual printer
sudo python3 cups_attack.py -t 192.168.56.20 \
    --listener-ip 192.168.56.10 --listener-port 8631 \
    -n EvilPrinter -m "Rogue IPP Everywhere"

# Three crafted variations (Task 4) + write them to a PCAP
sudo python3 cups_attack.py -t 192.168.56.20 \
    --listener-ip 192.168.56.10 --variations \
    --pcap pcap_files/attack_variations.pcap

# Craft packets to a PCAP WITHOUT transmitting (safe demo / reproducible)
python3 cups_attack.py -t 192.168.56.20 --listener-ip 192.168.56.10 \
    --variations --dry-run --pcap pcap_files/attack_variations.pcap
```

Key options: `-t/--target`, `--listener-ip`, `--listener-port`, `-n/--name`,
`-m/--make-model`, `-c/--count`, `-i/--interval`, `--variations`, `--pcap`,
`--dry-run`, `--log`, `-v`.

### The three crafted variations

| # | Label | What is manipulated |
|---|-------|---------------------|
| 1 | `baseline` | Straightforward rogue advertisement. |
| 2 | `alt-port-spoofed-model` | Changed IPP port + spoofed trusted make/model + altered state field. |
| 3 | `malformed-fields` | Out-of-range type/state values and oversized fields (parser robustness). |

## Detection tool — `cups_detector.py` (Task 3)

Monitors CUPS discovery traffic live or from a PCAP and raises alerts for:

1. **Unauthorized printer advertisements** — source IP not on the allowlist.
2. **Suspicious IPP connections/URIs** — URI host/port outside allowed ranges.
3. **Repeated/abnormal discovery rate** — too many advertisements per window.
4. **Malformed/unexpected protocol fields** — unparseable or out-of-range.

Alerts are printed and exported to CSV or JSON.

```bash
# Offline analysis of a captured attack PCAP -> JSON alerts
python3 cups_detector.py -r pcap_files/attack_variations.pcap \
    --allow 192.168.56.0/24 --allowed-ports 631 \
    --format json -o evidence/alerts_attack.json

# Live monitoring on eth0
sudo python3 cups_detector.py -l eth0 \
    --allow 192.168.56.20 --allowed-ports 631 -o evidence/alerts_live.csv
```

Key options: `-r/--read` (PCAP) or `-l/--live` (iface), `--allow`,
`--allowed-ports`, `--rate-threshold`, `--window`, `-o/--output`,
`--format {csv,json}`.

## Experiments (Task 4)

1. **Normal traffic** — legitimate CUPS ↔ virtual printer discovery captured
   to `pcap_files/normal.pcap`.
2. **Unauthorized discovery** — attack tool advertises a rogue printer
   (`pcap_files/attack_variations.pcap`).
3. **Packet manipulation** — the three variations above.
4. **Detection** — run the detector over both captures; see
   `evidence/alerts_*.{csv,json}`.

The report discusses successful detections, false positives and missed attacks.

## Mitigations (Task 5)

- Restrict/block UDP/631 at the host firewall (allow only trusted printer
  subnets).
- Disable `cups-browsed` where automatic discovery is not needed
  (`systemctl disable --now cups-browsed`).
- Allowlist authorised printer addresses only.
- Apply vendor security patches and segment the printer network.

The report compares detector/behaviour **before and after** blocking UDP/631
with `iptables`/`ufw`.

## Reproducing the deliverable artifacts

The committed PCAP and alert files were generated with:

```bash
python3 cups_attack.py -t 192.168.56.20 --listener-ip 192.168.56.10 \
    --variations --dry-run --pcap pcap_files/attack_variations.pcap
python3 cups_attack.py -t 192.168.56.20 --listener-ip 192.168.56.20 \
    --name OfficePrinter --dry-run --pcap pcap_files/normal.pcap
python3 cups_detector.py -r pcap_files/attack_variations.pcap \
    --allow 192.168.56.0/24 --format json -o evidence/alerts_attack.json
```

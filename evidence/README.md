# Evidence

Generated tool output from the experiments (Task 4) and mitigation (Task 5).

| File | Description |
|------|-------------|
| `attack_normal.log` | Attack tool log — legitimate baseline advertisement run |
| `attack_variations.log` | Attack tool log — the three crafted variations |
| `detector_normal.log` | Detector console output on normal traffic (0 alerts) |
| `detector_attack.log` | Detector console output on attack traffic |
| `alerts_normal.csv` | Exported alerts for normal traffic (empty = no false positives) |
| `alerts_attack.json` | Exported alerts for attack traffic (37 alerts, all categories) |
| `pcap_readout_normal.txt` | Human-readable packet dump of normal.pcap |
| `pcap_readout_attack_variations.txt` | Human-readable packet dump of attack_variations.pcap |
| `mitigation.md` | Task 5 before/after mitigation evidence |

> Add your own Wireshark / terminal screenshots from the live lab run here
> (e.g. `wireshark_normal.png`, `wireshark_attack.png`) for full marks.

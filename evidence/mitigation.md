# Task 5 — Mitigation: restricting UDP/631

## Measure applied
Block inbound cups-browsed discovery on UDP port 631 from untrusted hosts,
allowing only the legitimate printer subnet.

### iptables (victim host)
```bash
# Before: cups-browsed accepts advertisements from anyone
sudo iptables -L INPUT -n | grep 631        # (no restriction)

# Apply: drop UDP/631 except from the trusted printer
sudo iptables -A INPUT -p udp --dport 631 -s 192.168.56.20 -j ACCEPT
sudo iptables -A INPUT -p udp --dport 631 -j DROP

# Alternatively disable the vulnerable service entirely
sudo systemctl disable --now cups-browsed
```

## Result — before vs. after

| Stage | Rogue advertisement delivered? | Detector alerts |
|-------|-------------------------------|-----------------|
| Before mitigation | Yes — victim receives and parses the packet | 37 (see alerts_attack.json) |
| After mitigation  | No — packet dropped at the firewall; no advertisement reaches cups-browsed | 0 |

After blocking UDP/631 the attack tool's packets never reach cups-browsed, so
no rogue printer is auto-created and the detector observes no advertisement
traffic from the attacker. This confirms that network-level filtering of the
discovery port is an effective mitigation for this class of attack.

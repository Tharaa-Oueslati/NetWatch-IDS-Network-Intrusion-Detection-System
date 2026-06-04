"""
NetWatch-IDS — Sample PCAP Generator
Creates a realistic sample.pcap for demo/testing.
Requires Scapy. Run: python generate_sample_pcap.py
"""

import os
import random
import time

try:
    from scapy.all import (
        wrpcap, Ether, IP, TCP, UDP, ICMP, ARP, Raw,
        RandShort
    )
except ImportError:
    print("Scapy required: pip install scapy")
    exit(1)

OUTPUT = os.path.join(os.path.dirname(__file__), "sample.pcap")

random.seed(42)

ATTACKER = "192.168.1.200"
VICTIM   = "192.168.1.10"
GATEWAY  = "192.168.1.1"
DNS      = "8.8.8.8"

packets = []
t = 1700000000.0


def pkt(p, delay=0.01):
    p.time = t
    packets.append(p)
    return delay


# ── Normal traffic (baseline) ──────────────────────────────────────────────
for _ in range(30):
    t += random.uniform(0.05, 0.3)
    src = f"192.168.1.{random.randint(2, 50)}"
    dst = f"93.184.{random.randint(1,254)}.{random.randint(1,254)}"
    packets.append(
        Ether() / IP(src=src, dst=dst, ttl=64) /
        TCP(sport=RandShort(), dport=443, flags="PA")
    )
    packets[-1].time = t

# ── Port scan (T1046) ──────────────────────────────────────────────────────
print("[*] Generating port scan...")
for port in [21, 22, 23, 25, 53, 80, 110, 135, 139, 443, 445,
             3306, 3389, 5900, 8080, 8443, 8888, 9200, 27017]:
    t += 0.05
    pkt(Ether() / IP(src=ATTACKER, dst=VICTIM, ttl=128) /
        TCP(sport=random.randint(49152, 65535), dport=port, flags="S"))

# ── SYN flood (T1498) ──────────────────────────────────────────────────────
print("[*] Generating SYN flood...")
for _ in range(120):
    t += 0.008
    src_port = random.randint(1024, 65535)
    pkt(Ether() / IP(src=ATTACKER, dst=VICTIM, ttl=64) /
        TCP(sport=src_port, dport=80, flags="S"))

# ── SSH brute force (T1110) ───────────────────────────────────────────────
print("[*] Generating SSH brute force...")
for i in range(20):
    t += 1.5
    pkt(Ether() / IP(src=ATTACKER, dst=VICTIM, ttl=64) /
        TCP(sport=random.randint(49152, 65535), dport=22, flags="S"))

# ── Telnet cleartext (T1021.004) ──────────────────────────────────────────
t += 2.0
pkt(Ether() / IP(src=ATTACKER, dst=VICTIM, ttl=64) /
    TCP(sport=52000, dport=23, flags="S"))

# ── ARP spoofing (T1557.002) ──────────────────────────────────────────────
print("[*] Generating ARP spoofing...")
for _ in range(15):
    t += 0.1
    pkt(Ether(src="de:ad:be:ef:00:01") /
        ARP(op=2, psrc=GATEWAY, pdst=VICTIM,
            hwsrc="de:ad:be:ef:00:01"))

# ── DNS tunneling (T1071.004) ─────────────────────────────────────────────
print("[*] Generating DNS tunneling...")
for _ in range(110):
    t += 0.04
    pkt(Ether() / IP(src=ATTACKER, dst=DNS, ttl=64) /
        UDP(sport=random.randint(1024, 65535), dport=53) /
        Raw(load=b"\xde\xad" + os.urandom(20)))

# ── SMB scan (T1021.002) ──────────────────────────────────────────────────
for port in [445, 139, 137]:
    t += 0.2
    pkt(Ether() / IP(src=ATTACKER, dst=VICTIM) /
        TCP(sport=random.randint(49152, 65535), dport=port, flags="S"))

# ── XMAS scan (T1046) ─────────────────────────────────────────────────────
for port in [22, 80, 443, 8080]:
    t += 0.1
    pkt(Ether() / IP(src=ATTACKER, dst=VICTIM) /
        TCP(sport=random.randint(49152, 65535), dport=port,
            flags="FPU"))

# ── Backdoor high port (T1571) ────────────────────────────────────────────
t += 5.0
pkt(Ether() / IP(src=VICTIM, dst="10.0.0.99") /
    TCP(sport=random.randint(49152, 65535), dport=4444, flags="S"))

# ── More normal traffic ────────────────────────────────────────────────────
for _ in range(20):
    t += random.uniform(0.1, 0.5)
    src = f"192.168.1.{random.randint(2, 50)}"
    dst = f"172.217.{random.randint(1,254)}.{random.randint(1,254)}"
    packets.append(
        Ether() / IP(src=src, dst=dst, ttl=64) /
        TCP(sport=RandShort(), dport=80, flags="PA") /
        Raw(load=b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n")
    )
    packets[-1].time = t

print(f"[*] Writing {len(packets)} packets to {OUTPUT}")
wrpcap(OUTPUT, packets)
print(f"[+] Done! Sample PCAP created: {OUTPUT}")
print(f"    Run dashboard and it will auto-replay this file.")

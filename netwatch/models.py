"""
NetWatch-IDS — Data Models
Lightweight dataclasses; no ORM required for a portfolio project.
"""

from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional
import threading
import collections


@dataclass
class Packet:
    timestamp: datetime
    proto: str          # TCP / UDP / ICMP / ARP / OTHER
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    length: int
    flags: str          # e.g. "SA", "S", "FA"
    payload_preview: str
    raw_summary: str
    ttl: int = 64
    id: int = field(default_factory=lambda: id(object()))


@dataclass
class Alert:
    timestamp: datetime
    severity: str       # CRITICAL / HIGH / MEDIUM / LOW / INFO
    rule_name: str
    description: str
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    proto: str
    mitre_technique: str = ""   # e.g. "T1046"
    mitre_tactic: str = ""      # e.g. "Discovery"
    packet_summary: str = ""
    id: int = field(default_factory=lambda: id(object()))

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "timestamp": self.timestamp.isoformat(),
            "severity": self.severity,
            "rule_name": self.rule_name,
            "description": self.description,
            "src_ip": self.src_ip,
            "dst_ip": self.dst_ip,
            "src_port": self.src_port,
            "dst_port": self.dst_port,
            "proto": self.proto,
            "mitre_technique": self.mitre_technique,
            "mitre_tactic": self.mitre_tactic,
            "packet_summary": self.packet_summary,
        }


class PacketStore:
    """Thread-safe circular buffer for recent packets."""

    def __init__(self, maxlen: int = 10_000):
        self._packets: collections.deque[Packet] = collections.deque(maxlen=maxlen)
        self._lock = threading.Lock()
        self.total_seen = 0

    def add(self, pkt: Packet):
        with self._lock:
            self._packets.append(pkt)
            self.total_seen += 1

    def recent(self, n: int = 100) -> list[Packet]:
        with self._lock:
            return list(self._packets)[-n:]

    def all(self) -> list[Packet]:
        with self._lock:
            return list(self._packets)

    def __len__(self):
        with self._lock:
            return len(self._packets)


class AlertStore:
    """Thread-safe alert log with severity index."""

    def __init__(self, maxlen: int = 5_000):
        self._alerts: collections.deque[Alert] = collections.deque(maxlen=maxlen)
        self._lock = threading.Lock()
        self._severity_counts: dict[str, int] = {
            "CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0
        }

    def add(self, alert: Alert):
        with self._lock:
            self._alerts.append(alert)
            self._severity_counts[alert.severity] = \
                self._severity_counts.get(alert.severity, 0) + 1

    def recent(self, n: int = 50, severity: Optional[str] = None) -> list[Alert]:
        with self._lock:
            alerts = list(self._alerts)
        if severity:
            alerts = [a for a in alerts if a.severity == severity]
        return alerts[-n:]

    def all(self) -> list[Alert]:
        with self._lock:
            return list(self._alerts)

    def severity_counts(self) -> dict:
        with self._lock:
            return dict(self._severity_counts)

    def __len__(self):
        with self._lock:
            return len(self._alerts)

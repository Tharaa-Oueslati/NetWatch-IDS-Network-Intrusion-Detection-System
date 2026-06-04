"""
NetWatch-IDS — Main IDS Orchestrator
Wires together PacketCapture, RuleEngine, and stores.
"""

import logging
import os
from .capture import PacketCapture
from .engine import RuleEngine
from .models import PacketStore, AlertStore, Packet, Alert

logger = logging.getLogger(__name__)

# Global shared state — imported by Flask app
packet_store = PacketStore(maxlen=10_000)
alert_store = AlertStore(maxlen=5_000)

_capture: PacketCapture = None
_engine: RuleEngine = None


def get_rules_path() -> str:
    base = os.path.dirname(os.path.dirname(__file__))
    return os.path.join(base, "rules", "default_rules.json")


def _on_packet(pkt: Packet):
    """Called for every captured packet — runs rule evaluation."""
    _engine.evaluate(pkt)


def start_live(interface: str = None, bpf_filter: str = ""):
    """Start live capture on a network interface."""
    global _capture, _engine
    _engine = RuleEngine(get_rules_path(), alert_store)
    _capture = PacketCapture(packet_store, interface=interface)
    _capture.add_callback(_on_packet)
    _capture.start_live(filter_str=bpf_filter)
    logger.info("NetWatch-IDS live capture started.")


def start_replay(pcap_path: str, speed: float = 1.0):
    """Replay a PCAP file for demo/testing purposes."""
    global _capture, _engine
    _engine = RuleEngine(get_rules_path(), alert_store)
    _capture = PacketCapture(packet_store)
    _capture.add_callback(_on_packet)
    _capture.replay_pcap(pcap_path, speed=speed)
    logger.info(f"NetWatch-IDS replay started: {pcap_path}")


def stop():
    if _capture:
        _capture.stop()


def is_running() -> bool:
    return _capture is not None and _capture.is_running()


def get_stats() -> dict:
    return {
        "packets_captured": packet_store.total_seen,
        "packets_in_buffer": len(packet_store),
        "alerts_total": len(alert_store),
        "severity_counts": alert_store.severity_counts(),
        "running": is_running(),
        "capture_stats": _capture.stats if _capture else {},
    }

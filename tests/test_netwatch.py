"""
NetWatch-IDS — Test Suite
Tests rule engine, models, and detection logic.
Run: pytest tests/ -v
"""

import sys
import os
import json
import pytest
from datetime import datetime

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from netwatch.models import Packet, Alert, PacketStore, AlertStore
from netwatch.engine import RuleEngine


# ─── Fixtures ────────────────────────────────────────────────────────────────

RULES_PATH = os.path.join(os.path.dirname(os.path.dirname(__file__)),
                           "rules", "default_rules.json")


def make_packet(**kwargs) -> Packet:
    defaults = dict(
        timestamp=datetime.utcnow(),
        proto="TCP",
        src_ip="192.168.1.100",
        dst_ip="192.168.1.10",
        src_port=54321,
        dst_port=80,
        length=64,
        flags="S",
        payload_preview="",
        raw_summary="test packet",
        ttl=64,
    )
    defaults.update(kwargs)
    return Packet(**defaults)


@pytest.fixture
def alert_store():
    return AlertStore()


@pytest.fixture
def engine(alert_store, tmp_path):
    # Copy rules to a temp location so we can test hot-reload
    rules_file = tmp_path / "rules.json"
    with open(RULES_PATH) as f:
        rules_file.write_text(f.read())
    return RuleEngine(str(rules_file), alert_store)


# ─── Model tests ─────────────────────────────────────────────────────────────

class TestModels:

    def test_packet_creation(self):
        pkt = make_packet()
        assert pkt.proto == "TCP"
        assert pkt.src_ip == "192.168.1.100"

    def test_packet_store_add_and_retrieve(self):
        store = PacketStore(maxlen=100)
        for i in range(10):
            store.add(make_packet(src_port=i))
        assert len(store) == 10
        assert store.total_seen == 10

    def test_packet_store_maxlen(self):
        store = PacketStore(maxlen=5)
        for i in range(10):
            store.add(make_packet())
        assert len(store) == 5
        assert store.total_seen == 10

    def test_alert_store_severity_counts(self):
        store = AlertStore()
        alert = Alert(
            timestamp=datetime.utcnow(),
            severity="HIGH",
            rule_name="Test",
            description="Test alert",
            src_ip="1.2.3.4",
            dst_ip="5.6.7.8",
            src_port=1234,
            dst_port=80,
            proto="TCP",
        )
        store.add(alert)
        counts = store.severity_counts()
        assert counts["HIGH"] == 1
        assert counts["CRITICAL"] == 0

    def test_alert_to_dict(self):
        alert = Alert(
            timestamp=datetime(2024, 1, 1, 12, 0, 0),
            severity="MEDIUM",
            rule_name="Test Rule",
            description="desc",
            src_ip="1.2.3.4",
            dst_ip="5.6.7.8",
            src_port=1234,
            dst_port=443,
            proto="TCP",
            mitre_technique="T1046",
            mitre_tactic="Discovery",
        )
        d = alert.to_dict()
        assert d["severity"] == "MEDIUM"
        assert d["mitre_technique"] == "T1046"
        assert "timestamp" in d


# ─── Rule engine tests ────────────────────────────────────────────────────────

class TestRuleEngine:

    def test_telnet_detection(self, engine):
        pkt = make_packet(proto="TCP", dst_port=23, flags="S")
        alert = engine.evaluate(pkt)
        assert alert is not None
        assert "Telnet" in alert.rule_name

    def test_rdp_detection(self, engine):
        pkt = make_packet(proto="TCP", dst_port=3389, flags="S")
        alert = engine.evaluate(pkt)
        assert alert is not None
        assert "RDP" in alert.rule_name

    def test_smb_detection(self, engine):
        pkt = make_packet(proto="TCP", dst_port=445, flags="S")
        alert = engine.evaluate(pkt)
        assert alert is not None
        assert "SMB" in alert.rule_name

    def test_backdoor_port_detection(self, engine):
        pkt = make_packet(proto="TCP", dst_port=4444, flags="S")
        alert = engine.evaluate(pkt)
        assert alert is not None
        # Should fire Suspicious High Port (or at minimum some alert)
        assert alert.severity in ("LOW", "MEDIUM", "HIGH", "CRITICAL")

    def test_xmas_scan_detection(self, engine):
        pkt = make_packet(proto="TCP", dst_port=80, flags="FPU")
        alert = engine.evaluate(pkt)
        assert alert is not None
        assert "XMAS" in alert.rule_name or "Scan" in alert.rule_name

    def test_no_alert_normal_https(self, engine):
        """Normal HTTPS traffic should not trigger any alert."""
        pkt = make_packet(proto="TCP", dst_port=443, flags="PA")
        alert = engine.evaluate(pkt)
        assert alert is None

    def test_arp_spoof_threshold(self, engine, alert_store):
        """ARP spoof rule needs threshold (10 packets in 5s) to fire."""
        pkt = make_packet(proto="ARP", src_ip="192.168.1.200", dst_ip="192.168.1.10",
                          src_port=0, dst_port=0)
        # First 9 should not trigger
        for _ in range(9):
            engine.evaluate(pkt)
        count_before = len(alert_store)
        # 10th should trigger
        engine.evaluate(pkt)
        assert len(alert_store) > count_before

    def test_ftp_detection(self, engine):
        pkt = make_packet(proto="TCP", dst_port=21, flags="S")
        alert = engine.evaluate(pkt)
        assert alert is not None
        assert "FTP" in alert.rule_name

    def test_mitre_tag_present(self, engine):
        pkt = make_packet(proto="TCP", dst_port=23)
        alert = engine.evaluate(pkt)
        assert alert is not None
        assert alert.mitre_technique.startswith("T")

    def test_rules_load(self, engine):
        assert len(engine.rules) > 0

    def test_disabled_rule_skipped(self, engine, tmp_path):
        """Disabling a rule should prevent it from firing."""
        # Load rules, disable Telnet rule
        with open(engine.rules_path) as f:
            data = json.load(f)
        for r in data["rules"]:
            if r["id"] == "NW-003":
                r["enabled"] = False
        with open(engine.rules_path, "w") as f:
            json.dump(data, f)

        import time; time.sleep(0.05)  # Allow mtime to update
        import os; os.utime(engine.rules_path, None)

        engine._last_mtime = 0  # Force reload
        engine.load_rules()

        pkt = make_packet(proto="TCP", dst_port=23)
        alert = engine.evaluate(pkt)
        assert alert is None


# ─── Run ──────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    pytest.main([__file__, "-v", "--tb=short"])

"""
NetWatch-IDS — Rule Engine
Loads detection rules from JSON and evaluates each packet.
Inspired by Snort rule structure; fully configurable without code changes.
"""

import json
import logging
import os
import threading
import time
from datetime import datetime, timedelta
from typing import Optional

from .models import Packet, Alert, AlertStore

logger = logging.getLogger(__name__)


class RuleEngine:
    """
    Evaluates packets against a set of detection rules.
    Rules are loaded from a JSON file; hot-reload is supported.
    """

    def __init__(self, rules_path: str, alert_store: AlertStore):
        self.rules_path = rules_path
        self.alert_store = alert_store
        self.rules: list[dict] = []
        self._lock = threading.Lock()
        self._last_mtime = 0.0

        # Rate-tracking for threshold rules: {rule_id: deque of timestamps}
        self._rate_tracker: dict[str, list] = {}

        self.load_rules()

    def load_rules(self):
        """Load (or reload) rules from JSON file."""
        try:
            mtime = os.path.getmtime(self.rules_path)
            if mtime == self._last_mtime:
                return
            with open(self.rules_path) as f:
                data = json.load(f)
            with self._lock:
                self.rules = data.get("rules", [])
                self._last_mtime = mtime
            logger.info(f"Loaded {len(self.rules)} rules from {self.rules_path}")
        except FileNotFoundError:
            logger.warning(f"Rules file not found: {self.rules_path}")
        except json.JSONDecodeError as e:
            logger.error(f"Invalid rules JSON: {e}")

    def evaluate(self, pkt: Packet) -> Optional[Alert]:
        """
        Evaluate a packet against all enabled rules.
        Returns the first matching Alert, or None.
        """
        self.load_rules()  # Check for hot-reload

        with self._lock:
            rules = list(self.rules)

        for rule in rules:
            if not rule.get("enabled", True):
                continue
            try:
                alert = self._match(pkt, rule)
                if alert:
                    self.alert_store.add(alert)
                    return alert
            except Exception as e:
                logger.error(f"Rule {rule.get('id')} error: {e}")
        return None

    def _match(self, pkt: Packet, rule: dict) -> Optional[Alert]:
        """Check if a packet matches a single rule."""
        conditions = rule.get("conditions", {})

        # --- Protocol check ---
        if "proto" in conditions:
            if pkt.proto not in conditions["proto"]:
                return None

        # --- Port checks ---
        if "dst_ports" in conditions:
            if pkt.dst_port not in conditions["dst_ports"]:
                return None
        if "src_ports" in conditions:
            if pkt.src_port not in conditions["src_ports"]:
                return None

        # --- TCP flag check ---
        if "flags" in conditions:
            required = set(conditions["flags"])
            present = set(pkt.flags)
            if required:
                # Some flags required — all must be present
                if not required.issubset(present):
                    return None
            else:
                # Empty list means "no flags set at all" (null scan)
                if present:
                    return None

        # --- Flag exclusion (e.g. SYN only, not SYN-ACK) ---
        if "flags_not" in conditions:
            excluded = set(conditions["flags_not"])
            present = set(pkt.flags)
            if excluded & present:
                return None

        # --- IP ranges (CIDR matching) ---
        if "src_ip_not" in conditions:
            import ipaddress
            for cidr in conditions["src_ip_not"]:
                try:
                    if ipaddress.ip_address(pkt.src_ip) in ipaddress.ip_network(cidr):
                        return None
                except ValueError:
                    pass

        # --- Payload content match ---
        if "payload_contains" in conditions:
            payload_lower = pkt.payload_preview.lower()
            if not any(s.lower() in payload_lower for s in conditions["payload_contains"]):
                return None

        # --- Threshold / rate limiting ---
        if "threshold" in conditions:
            thresh = conditions["threshold"]
            key = f"{rule['id']}:{pkt.src_ip}"
            count_field = thresh.get("track", "count")
            window_sec = thresh.get("seconds", 10)
            limit = thresh.get("count", 5)

            now = datetime.utcnow()
            if key not in self._rate_tracker:
                self._rate_tracker[key] = []
            self._rate_tracker[key].append(now)

            # Prune old timestamps outside the window
            cutoff = now - timedelta(seconds=window_sec)
            self._rate_tracker[key] = [
                t for t in self._rate_tracker[key] if t > cutoff
            ]

            if len(self._rate_tracker[key]) < limit:
                return None  # Threshold not reached yet

        # --- All conditions matched → generate alert ---
        return Alert(
            timestamp=datetime.utcnow(),
            severity=rule.get("severity", "MEDIUM"),
            rule_name=rule.get("name", rule.get("id", "UNKNOWN")),
            description=rule.get("description", ""),
            src_ip=pkt.src_ip,
            dst_ip=pkt.dst_ip,
            src_port=pkt.src_port,
            dst_port=pkt.dst_port,
            proto=pkt.proto,
            mitre_technique=rule.get("mitre_technique", ""),
            mitre_tactic=rule.get("mitre_tactic", ""),
            packet_summary=pkt.raw_summary,
        )

"""
NetWatch-IDS — Packet Capture Engine
Either sniffs live traffic using Scapy or replays the sample.pcap.
Converts raw packets into clean Packet objects.
"""

import threading
import time
import logging
from datetime import datetime
from typing import Callable, Optional

try:
    from scapy.all import sniff, rdpcap, IP, TCP, UDP, ICMP, ARP, Raw
    from scapy.layers.http import HTTP
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False

from .models import Packet, PacketStore

logger = logging.getLogger(__name__)


class PacketCapture:
    """
    Live or PCAP-based packet capture.
    Calls registered callbacks for each packet.
    """

    def __init__(self, store: PacketStore, interface: str = None):
        self.store = store
        self.interface = interface
        self._callbacks: list[Callable] = []
        self._running = False
        self._thread: Optional[threading.Thread] = None
        self.stats = {
            "captured": 0,
            "dropped": 0,
            "start_time": None,
        }

    def add_callback(self, fn: Callable):
        self._callbacks.append(fn)

    def _process(self, raw_pkt):
        """Convert a Scapy packet to our Packet model and run callbacks."""
        try:
            pkt = self._parse(raw_pkt)
            if pkt is None:
                return
            self.store.add(pkt)
            self.stats["captured"] += 1
            for cb in self._callbacks:
                try:
                    cb(pkt)
                except Exception as e:
                    logger.error(f"Callback error: {e}")
        except Exception as e:
            logger.error(f"Packet parse error: {e}")
            self.stats["dropped"] += 1

    def _parse(self, raw) -> Optional[Packet]:
        """Extract fields from a Scapy packet into our model."""
        if not raw.haslayer(IP):
            # Still capture ARP
            if raw.haslayer(ARP):
                return Packet(
                    timestamp=datetime.utcnow(),
                    proto="ARP",
                    src_ip=raw[ARP].psrc,
                    dst_ip=raw[ARP].pdst,
                    src_port=0,
                    dst_port=0,
                    length=len(raw),
                    flags="",
                    payload_preview="",
                    raw_summary=raw.summary(),
                )
            return None

        ip = raw[IP]
        proto = "OTHER"
        src_port = dst_port = 0
        flags = ""
        payload_preview = ""

        if raw.haslayer(TCP):
            tcp = raw[TCP]
            proto = "TCP"
            src_port = tcp.sport
            dst_port = tcp.dport
            # TCP flag string
            flag_map = {0x01: "F", 0x02: "S", 0x04: "R",
                        0x08: "P", 0x10: "A", 0x20: "U"}
            flags = "".join(v for k, v in flag_map.items() if tcp.flags & k)
            if raw.haslayer(Raw):
                payload_preview = bytes(raw[Raw].load)[:64].hex()

        elif raw.haslayer(UDP):
            udp = raw[UDP]
            proto = "UDP"
            src_port = udp.sport
            dst_port = udp.dport

        elif raw.haslayer(ICMP):
            proto = "ICMP"

        return Packet(
            timestamp=datetime.utcnow(),
            proto=proto,
            src_ip=ip.src,
            dst_ip=ip.dst,
            src_port=src_port,
            dst_port=dst_port,
            length=len(raw),
            flags=flags,
            payload_preview=payload_preview,
            raw_summary=raw.summary(),
            ttl=ip.ttl,
        )

    def start_live(self, count: int = 0, filter_str: str = ""):
        """Start live capture on the configured interface."""
        if not SCAPY_AVAILABLE:
            raise RuntimeError("Scapy not installed. Run: pip install scapy")

        self._running = True
        self.stats["start_time"] = datetime.utcnow()
        kwargs = dict(prn=self._process, store=False)
        if self.interface:
            kwargs["iface"] = self.interface
        if count:
            kwargs["count"] = count
        if filter_str:
            kwargs["filter"] = filter_str

        logger.info(f"Starting live capture on {self.interface or 'default interface'}")
        self._thread = threading.Thread(
            target=sniff, kwargs=kwargs, daemon=True
        )
        self._thread.start()

    def replay_pcap(self, path: str, speed: float = 1.0):
        """Replay packets from a PCAP file (for testing/demo)."""
        if not SCAPY_AVAILABLE:
            raise RuntimeError("Scapy not installed.")

        def _replay():
            self.stats["start_time"] = datetime.utcnow()
            packets = rdpcap(path)
            logger.info(f"Replaying {len(packets)} packets from {path}")
            prev_time = None
            for pkt in packets:
                if not self._running:
                    break
                # Maintain timing between packets (scaled by speed)
                if prev_time is not None:
                    delta = float(pkt.time) - float(prev_time)
                    time.sleep(max(0, delta / speed))
                prev_time = pkt.time
                self._process(pkt)
            logger.info("PCAP replay complete.")

        self._running = True
        self._thread = threading.Thread(target=_replay, daemon=True)
        self._thread.start()

    def stop(self):
        self._running = False
        logger.info("Capture stopped.")

    def is_running(self) -> bool:
        return self._running and (self._thread is not None and self._thread.is_alive())

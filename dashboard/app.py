"""
NetWatch-IDS — Flask Dashboard Backend
Serves the web UI and provides REST API endpoints.
"""

import os
import sys
import logging
from flask import Flask, jsonify, render_template, request

# Allow running from project root
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from netwatch import ids

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger(__name__)

app = Flask(__name__, template_folder="templates", static_folder="static")


# ─── Pages ────────────────────────────────────────────────────────────────────

@app.route("/")
def index():
    return render_template("index.html")


# ─── API ──────────────────────────────────────────────────────────────────────

@app.route("/api/stats")
def api_stats():
    return jsonify(ids.get_stats())


@app.route("/api/alerts")
def api_alerts():
    n = int(request.args.get("n", 50))
    severity = request.args.get("severity")
    alerts = ids.alert_store.recent(n=n, severity=severity or None)
    return jsonify([a.to_dict() for a in reversed(alerts)])


@app.route("/api/alerts/counts")
def api_alert_counts():
    """Return alert counts bucketed by minute for the timeline chart."""
    from collections import defaultdict
    from datetime import datetime, timedelta

    alerts = ids.alert_store.all()
    now = datetime.utcnow()
    buckets = defaultdict(lambda: {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0})

    for a in alerts:
        # Round down to nearest minute
        minute = a.timestamp.replace(second=0, microsecond=0)
        buckets[minute][a.severity] += 1

    # Build last 30 minutes of buckets (fill gaps with zeros)
    result = []
    for i in range(29, -1, -1):
        t = (now - timedelta(minutes=i)).replace(second=0, microsecond=0)
        b = buckets.get(t, {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0})
        result.append({
            "time": t.strftime("%H:%M"),
            **b
        })
    return jsonify(result)


@app.route("/api/packets")
def api_packets():
    n = int(request.args.get("n", 20))
    packets = ids.packet_store.recent(n=n)
    return jsonify([
        {
            "timestamp": p.timestamp.isoformat(),
            "proto": p.proto,
            "src": f"{p.src_ip}:{p.src_port}" if p.src_port else p.src_ip,
            "dst": f"{p.dst_ip}:{p.dst_port}" if p.dst_port else p.dst_ip,
            "length": p.length,
            "flags": p.flags,
            "summary": p.raw_summary,
        }
        for p in reversed(packets)
    ])


@app.route("/api/top-sources")
def api_top_sources():
    """Top source IPs by alert count."""
    from collections import Counter
    alerts = ids.alert_store.all()
    counter = Counter(a.src_ip for a in alerts)
    return jsonify([
        {"ip": ip, "count": count}
        for ip, count in counter.most_common(10)
    ])


@app.route("/api/control/start", methods=["POST"])
def api_start():
    data = request.json or {}
    mode = data.get("mode", "replay")
    if mode == "live":
        interface = data.get("interface")
        bpf = data.get("filter", "")
        try:
            ids.start_live(interface=interface, bpf_filter=bpf)
            return jsonify({"status": "started", "mode": "live"})
        except Exception as e:
            return jsonify({"error": str(e)}), 500
    else:
        pcap = data.get("pcap", "pcap_samples/sample.pcap")
        speed = float(data.get("speed", 5.0))
        try:
            ids.start_replay(pcap, speed=speed)
            return jsonify({"status": "started", "mode": "replay"})
        except Exception as e:
            return jsonify({"error": str(e)}), 500


@app.route("/api/control/stop", methods=["POST"])
def api_stop():
    ids.stop()
    return jsonify({"status": "stopped"})


if __name__ == "__main__":
    # Auto-start replay mode if a sample PCAP exists
    sample = os.path.join(os.path.dirname(os.path.dirname(__file__)),
                          "pcap_samples", "sample.pcap")
    if os.path.exists(sample):
        logger.info("Auto-starting PCAP replay for demo...")
        ids.start_replay(sample, speed=10.0)

    app.run(host="0.0.0.0", port=5000, debug=False)

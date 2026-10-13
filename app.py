import threading
from datetime import datetime
from flask import Flask, jsonify, render_template, request

app = Flask(__name__)

data_lock = threading.Lock()

# Central In-Memory Telemetry State
telemetry_data = {
    "stats": {
        "total_arp": 0,
        "active_hosts": 0,
        "total_alerts": 0
    },
    "ml_status": {
        "verdict": "NOMINAL",
        "color": "green",
        "confidence": 99.4,
        "reason": "Cloud receiver active. Awaiting local sensor telemetry stream.",
        "features": {
            "packet_rate": 0.0,
            "time_delta": 0.0,
            "burst_count": 0,
            "is_gratuitous": 0
        }
    },
    "traffic": [0] * 15,
    "alerts": [],
    "devices": {}
}

sim_counter = 0

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/api/telemetry', methods=['GET'])
def get_telemetry():
    with data_lock:
        return jsonify(telemetry_data)

@app.route('/api/ingest', methods=['POST'])
def ingest():
    """Receives live network metrics and alerts from the local sensor.py."""
    global telemetry_data
    payload = request.get_json(silent=True)
    
    if not payload:
        return jsonify({"status": "ignored", "reason": "No JSON payload"}), 400

    with data_lock:
        # Periodic Heartbeat Update (Traffic & Device Table)
        if payload.get("type") == "heartbeat":
            telemetry_data["traffic"] = payload.get("traffic", telemetry_data["traffic"])
            telemetry_data["devices"] = payload.get("devices", telemetry_data["devices"])
            telemetry_data["stats"]["total_arp"] = payload.get("stats", {}).get("total_arp", telemetry_data["stats"]["total_arp"])
            telemetry_data["stats"]["active_hosts"] = payload.get("stats", {}).get("active_hosts", telemetry_data["stats"]["active_hosts"])

        # Threat Alert Update (Triggered by Local ML Model)
        elif payload.get("type") == "alert":
            telemetry_data["stats"]["total_alerts"] += 1
            new_alert = payload.get("alert_data", {})
            new_alert["id"] = telemetry_data["stats"]["total_alerts"]
            telemetry_data["alerts"].insert(0, new_alert)
            telemetry_data["ml_status"] = payload.get("ml_status", telemetry_data["ml_status"])

            # Keep only the latest 40 alerts in cloud memory
            if len(telemetry_data["alerts"]) > 40:
                telemetry_data["alerts"].pop()

    return jsonify({"status": "success"}), 200

@app.route('/api/simulate', methods=['POST'])
def simulate_attack():
    """Cloud simulation trigger so the dashboard button works perfectly for demos."""
    global sim_counter
    now_str = datetime.now().strftime("%H:%M:%S")

    with data_lock:
        sim_counter += 1
        telemetry_data["stats"]["total_alerts"] += 1
        alert_id = telemetry_data["stats"]["total_alerts"]

        if sim_counter % 3 == 2:
            color, verdict, conf, spoofed = "blue", "SUSPICIOUS_ALERT", 86.4, "02:11:22:33:44:55"
            reason = "Irregular burst rate and frame timing anomaly detected. Potential scan."
            features = {"packet_rate": 4.5, "time_delta": 9.2, "burst_count": 7, "is_gratuitous": 0}
        elif sim_counter % 3 == 0:
            color, verdict, conf, spoofed = "green", "BENIGN_CHANGE", 92.1, "36:16:9b:bf:d5:9f"
            reason = "Low ingestion rate with standard delta. Normal NIC/DHCP transition."
            features = {"packet_rate": 0.8, "time_delta": 420.0, "burst_count": 2, "is_gratuitous": 0}
        else:
            color, verdict, conf, spoofed = "red", "MALICIOUS_ATTACK", 99.8, "de:ad:be:ef:13:37"
            reason = "High ingestion rate with duplicate IP advertisement. Confirmed ARP Poisoning."
            features = {"packet_rate": 26.0, "time_delta": 0.12, "burst_count": 31, "is_gratuitous": 1}

        ml_status = {
            "verdict": verdict,
            "color": color,
            "confidence": conf,
            "reason": reason,
            "features": features
        }

        new_alert = {
            "id": alert_id,
            "time": now_str,
            "ip": "192.168.1.1",
            "original_mac": "64:fb:92:74:4e:2b",
            "spoofed_mac": spoofed,
            "status": verdict,
            "color": color,
            "confidence": conf
        }

        telemetry_data["ml_status"] = ml_status
        telemetry_data["alerts"].insert(0, new_alert)

    return jsonify({"status": "simulated", "verdict": ml_status})

@app.route('/api/clear', methods=['POST'])
def clear_alerts():
    with data_lock:
        telemetry_data["alerts"].clear()
        telemetry_data["stats"]["total_alerts"] = 0
        telemetry_data["ml_status"] = {
            "verdict": "NOMINAL",
            "color": "green",
            "confidence": 99.4,
            "reason": "Alert logs cleared. Subnet monitor in nominal state.",
            "features": {"packet_rate": 0.0, "time_delta": 0.0, "burst_count": 0, "is_gratuitous": 0}
        }
    return jsonify({"status": "cleared"})

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=False)
import os
import time
import threading
from datetime import datetime
from collections import deque
from flask import Flask, jsonify, render_template, request
from scapy.all import sniff, ARP
import joblib
import numpy as np

app = Flask(__name__)

# State and Data Storage
data_lock = threading.Lock()
state_devices = {}
alerts_history = []
recent_packets = deque()
traffic_history = [0] * 15
total_arp_count = 0
alert_counter = 0

# ML Classification State
latest_ml_verdict = {
    "verdict": "NOMINAL",
    "color": "green",
    "confidence": 99.4,
    "reason": "Normal subnet baseline operation. No anomalies detected.",
    "features": {"packet_rate": 0.0, "time_delta": 0.0, "burst_count": 0, "is_gratuitous": 0}
}

# Load the Trained ML Model
MODEL_PATH = os.path.join(os.path.dirname(__file__), 'arp_classifier.pkl')
ml_model = None
if os.path.exists(MODEL_PATH):
    try:
        ml_model = joblib.load(MODEL_PATH)
        print("[+] ML Classifier (arp_classifier.pkl) loaded successfully.")
    except Exception as e:
        print(f"[!] Warning: Could not load ML model: {e}")
else:
    print("[!] Warning: 'arp_classifier.pkl' not found. Run 'python train_model.py' first.")

def classify_traffic(packet_rate, time_delta, is_gratuitous, burst_count):
    """Passes live extracted features to the Random Forest model."""
    if ml_model is None:
        return ("MALICIOUS_ATTACK", "red", 85.0, "Model unavailable - fallback heuristic")

    features = np.array([[packet_rate, time_delta, is_gratuitous, burst_count]])
    pred = ml_model.predict(features)[0]
    probs = ml_model.predict_proba(features)[0]
    confidence = float(np.max(probs) * 100)

    if pred == 2:
        return (
            "MALICIOUS_ATTACK",
            "red",
            round(confidence, 1),
            "High ingestion rate with duplicate IP advertisement. Confirmed ARP Cache Poisoning."
        )
    elif pred == 1:
        return (
            "SUSPICIOUS_ALERT",
            "blue",
            round(confidence, 1),
            "Unusual packet timing or burst anomaly observed. Flagged as potential scan/probe."
        )
    else:
        return (
            "BENIGN_CHANGE",
            "green",
            round(confidence, 1),
            "Low-frequency hardware transition or DHCP IP lease renewal. Non-malicious update."
        )

def process_arp_packet(pkt):
    """Callback for Scapy sniffing loop."""
    global total_arp_count, alert_counter, latest_ml_verdict
    if not pkt.haslayer(ARP):
        return

    now = time.time()
    now_str = datetime.now().strftime("%H:%M:%S")
    ip_src = pkt[ARP].psrc
    mac_src = pkt[ARP].hwsrc.lower()
    op_code = pkt[ARP].op

    with data_lock:
        total_arp_count += 1
        recent_packets.append(now)

        # Remove packets older than 2 seconds
        while recent_packets and recent_packets[0] < now - 2.0:
            recent_packets.popleft()

        burst_count = len(recent_packets)
        packet_rate = burst_count / 2.0
        is_gratuitous = 1 if (op_code == 2 and ip_src == pkt[ARP].pdst) else 0

        # Check existing host baseline
        if ip_src in state_devices:
            original_mac = state_devices[ip_src]["mac"]
            last_seen_epoch = state_devices[ip_src]["last_seen_epoch"]
            time_delta = max(0.01, now - last_seen_epoch)

            # MAC Mismatch Detected -> Trigger ML Evaluation
            if original_mac != mac_src:
                verdict, color, conf, reason = classify_traffic(packet_rate, time_delta, is_gratuitous, burst_count)

                latest_ml_verdict = {
                    "verdict": verdict,
                    "color": color,
                    "confidence": conf,
                    "reason": reason,
                    "features": {
                        "packet_rate": round(packet_rate, 2),
                        "time_delta": round(time_delta, 2),
                        "burst_count": burst_count,
                        "is_gratuitous": is_gratuitous
                    }
                }

                alert_counter += 1
                alerts_history.insert(0, {
                    "id": alert_counter,
                    "time": now_str,
                    "ip": ip_src,
                    "original_mac": original_mac,
                    "spoofed_mac": mac_src,
                    "status": verdict,
                    "color": color,
                    "confidence": conf
                })
            else:
                state_devices[ip_src]["last_seen"] = now_str
                state_devices[ip_src]["last_seen_epoch"] = now
        else:
            # First time seeing this host
            state_devices[ip_src] = {
                "mac": mac_src,
                "first_seen": now_str,
                "last_seen": now_str,
                "last_seen_epoch": now,
                "status": "Verified"
            }

def run_sniffer():
    """Background thread to capture live ARP packets."""
    try:
        sniff(filter="arp", prn=process_arp_packet, store=0)
    except Exception as e:
        print(f"[!] Sniffer encountered an exception: {e}")

# Start sniffer thread
sniffer_thread = threading.Thread(target=run_sniffer, daemon=True)
sniffer_thread.start()

def update_traffic_velocity():
    """Timer thread calculating rolling traffic velocity every 2 seconds."""
    while True:
        time.sleep(2.0)
        with data_lock:
            now = time.time()
            count = sum(1 for t in recent_packets if t >= now - 2.0)
            traffic_history.pop(0)
            traffic_history.append(count)

traffic_thread = threading.Thread(target=update_traffic_velocity, daemon=True)
traffic_thread.start()

# --- HTTP Endpoints ---

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/api/telemetry', methods=['GET'])
def get_telemetry():
    with data_lock:
        return jsonify({
            "stats": {
                "total_arp": total_arp_count,
                "active_hosts": len(state_devices),
                "total_alerts": alert_counter
            },
            "ml_status": latest_ml_verdict,
            "traffic": traffic_history,
            "alerts": alerts_history[:30],
            "devices": state_devices
        })

@app.route('/api/simulate', methods=['POST'])
def simulate_attack():
    """Simulates scenarios, alternating between Attack (Red), Alert (Blue), and Benign (Green)."""
    global alert_counter, latest_ml_verdict
    now_str = datetime.now().strftime("%H:%M:%S")

    # Mode rotation: Attack -> Suspicious Alert -> Benign NIC Swap
    sim_mode = request.args.get('mode', None)
    with data_lock:
        alert_counter += 1

        if sim_mode == "blue" or (sim_mode is None and alert_counter % 3 == 2):
            verdict, color, conf, reason = classify_traffic(4.2, 8.5, 0, 6)
            spoofed_mac = "02:11:22:33:44:55"
        elif sim_mode == "green" or (sim_mode is None and alert_counter % 3 == 0):
            verdict, color, conf, reason = classify_traffic(0.8, 480.0, 0, 2)
            spoofed_mac = "36:16:9b:bf:d5:9f"
        else:
            verdict, color, conf, reason = classify_traffic(24.5, 0.15, 1, 28)
            spoofed_mac = "de:ad:be:ef:13:37"

        latest_ml_verdict = {
            "verdict": verdict,
            "color": color,
            "confidence": conf,
            "reason": reason,
            "features": {
                "packet_rate": 24.5 if color == "red" else (4.2 if color == "blue" else 0.8),
                "time_delta": 0.15 if color == "red" else (8.5 if color == "blue" else 480.0),
                "burst_count": 28 if color == "red" else (6 if color == "blue" else 2),
                "is_gratuitous": 1 if color == "red" else 0
            }
        }

        alerts_history.insert(0, {
            "id": alert_counter,
            "time": now_str,
            "ip": "192.168.1.1",
            "original_mac": "64:fb:92:74:4e:2b",
            "spoofed_mac": spoofed_mac,
            "status": verdict,
            "color": color,
            "confidence": conf
        })

    return jsonify({"status": "ok", "verdict": latest_ml_verdict})

@app.route('/api/clear', methods=['POST'])
def clear_alerts():
    global alerts_history, alert_counter, latest_ml_verdict
    with data_lock:
        alerts_history.clear()
        alert_counter = 0
        latest_ml_verdict = {
            "verdict": "NOMINAL",
            "color": "green",
            "confidence": 99.4,
            "reason": "Alert logs cleared. Subnet monitor in nominal state.",
            "features": {"packet_rate": 0.0, "time_delta": 0.0, "burst_count": 0, "is_gratuitous": 0}
        }
    return jsonify({"status": "cleared"})

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=False)
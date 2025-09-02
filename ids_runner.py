# ids_runner.py
import asyncio
import threading
import pyshark
import joblib
import numpy as np
import datetime
import time
import statistics
from collections import defaultdict
from queue import Queue
import os
import csv

# === Global Alert Queue ===
alert_queue = Queue()

# === Load preprocessing + model ===
scaler = joblib.load(r"C:\Users\User\Desktop\FYP\scaler.pkl")
pca = joblib.load(r"C:\Users\User\Desktop\FYP\pca.pkl")
features = joblib.load(r"C:\Users\User\Desktop\FYP\features.pkl")
ocsvm = joblib.load(r"C:\Users\User\Desktop\FYP\ocsvm_model.pkl")

# === Flow Aggregation globals ===
packet_count = 0

# === Alert CSV Folder ===
ALERTS_FOLDER = "alerts"
os.makedirs(ALERTS_FOLDER, exist_ok=True)

# === Helper functions ===
def pkt_lengths(pkts):
    return [int(p.length) for p in pkts if hasattr(p, "length")]

def iats(pkts):
    arr = []
    for i in range(len(pkts) - 1):
        try:
            arr.append(float(pkts[i+1].sniff_timestamp) - float(pkts[i].sniff_timestamp))
        except Exception:
            continue
    return arr

def count_flag(pkts, flag):
    count = 0
    for p in pkts:
        try:
            val = getattr(p.tcp, flag, None)
            count += int(val) if val is not None else 0
        except Exception:
            continue
    return count

def compute_flow_features(pkts):
    feat = {}
    if not pkts:
        return {k: 0 for k in features}

    first = pkts[0]
    last = pkts[-1]
    duration = max(float(last.sniff_timestamp) - float(first.sniff_timestamp), 1e-6)
    feat["Flow Duration"] = duration
    feat["Timestamp"] = float(getattr(first, "sniff_timestamp", 0))

    # Protocol
    proto = getattr(first, "transport_layer", None)
    proto_val = 6 if proto and proto.upper() == "TCP" else 17
    feat["Protocol"] = proto_val
    try:
        feat["Dst Port"] = int(getattr(first[proto], "dstport", 0) if proto else 0)
    except Exception:
        feat["Dst Port"] = 0

    # Forward/backward split
    src_ip = getattr(getattr(first, "ip", None), "src", None) or getattr(getattr(first, "ipv6", None), "src", None)
    fwd_pkts, bwd_pkts = [], []
    for p in pkts:
        try:
            if hasattr(p, "ip") and p.ip.src == src_ip:
                fwd_pkts.append(p)
            elif hasattr(p, "ipv6") and p.ipv6.src == src_ip:
                fwd_pkts.append(p)
            else:
                bwd_pkts.append(p)
        except Exception:
            continue

    feat["Tot Fwd Pkts"] = len(fwd_pkts)
    feat["Tot Bwd Pkts"] = len(bwd_pkts)
    feat["TotLen Fwd Pkts"] = sum(pkt_lengths(fwd_pkts))
    feat["TotLen Bwd Pkts"] = sum(pkt_lengths(bwd_pkts))

    def stats(pkts_list):
        lengths = pkt_lengths(pkts_list)
        if not lengths:
            return 0, 0, 0, 0
        return max(lengths), min(lengths), statistics.mean(lengths), statistics.stdev(lengths) if len(lengths) > 1 else 0

    feat["Fwd Pkt Len Max"], feat["Fwd Pkt Len Min"], feat["Fwd Pkt Len Mean"], feat["Fwd Pkt Len Std"] = stats(fwd_pkts)
    feat["Bwd Pkt Len Max"], feat["Bwd Pkt Len Min"], feat["Bwd Pkt Len Mean"], feat["Bwd Pkt Len Std"] = stats(bwd_pkts)
    feat["Pkt Len Max"], feat["Pkt Len Min"], feat["Pkt Len Mean"], feat["Pkt Len Std"] = stats(pkts)

    # Throughput
    feat["Flow Byts/s"] = sum(pkt_lengths(pkts)) / duration
    feat["Flow Pkts/s"] = len(pkts) / duration

    # IATs
    ia = iats(pkts)
    feat["Flow IAT Mean"] = float(np.mean(ia)) if ia else 0
    feat["Flow IAT Std"] = float(np.std(ia)) if ia else 0
    feat["Flow IAT Max"] = max(ia) if ia else 0
    feat["Flow IAT Min"] = min(ia) if ia else 0

    def dir_iat(pkts_list):
        arr = iats(pkts_list)
        return sum(arr) if arr else 0, float(np.mean(arr)) if arr else 0, float(np.std(arr)) if arr else 0, max(arr) if arr else 0, min(arr) if arr else 0

    feat["Fwd IAT Tot"], feat["Fwd IAT Mean"], feat["Fwd IAT Std"], feat["Fwd IAT Max"], feat["Fwd IAT Min"] = dir_iat(fwd_pkts)
    feat["Bwd IAT Tot"], feat["Bwd IAT Mean"], feat["Bwd IAT Std"], feat["Bwd IAT Max"], feat["Bwd IAT Min"] = dir_iat(bwd_pkts)

    # TCP flags
    for flag in ["fin_flag", "syn_flag", "rst_flag", "psh_flag", "ack_flag", "urg_flag", "cwe_flag", "ece_flag"]:
        feat[f"Fwd {flag.replace('_',' ').title()} Cnt"] = count_flag(fwd_pkts, flag)
        feat[f"Bwd {flag.replace('_',' ').title()} Cnt"] = count_flag(bwd_pkts, flag)

    feat["Down/Up Ratio"] = (feat["TotLen Bwd Pkts"] / max(feat["TotLen Fwd Pkts"], 1))

    # Ensure all expected feature keys exist
    for key in features:
        if key not in feat:
            feat[key] = 0

    return feat

# === Alert saving (hourly CSV) ===
current_hour_file = None
current_hour = None
csv_lock = threading.Lock()

def save_alert(alert):
    global current_hour_file, current_hour
    now = datetime.datetime.now()
    hour_str = now.strftime("%Y%m%d_%H")
    
    if current_hour != hour_str:
        current_hour = hour_str
        current_hour_file = os.path.join(ALERTS_FOLDER, f"alerts_{hour_str}.csv")
        if not os.path.exists(current_hour_file):
            with open(current_hour_file, "w", newline="") as f:
                writer = csv.DictWriter(f, fieldnames=["time", "src", "dst", "severity", "message"])
                writer.writeheader()
    
    with csv_lock:
        with open(current_hour_file, "a", newline="") as f:
            writer = csv.DictWriter(f, fieldnames=["time", "src", "dst", "severity", "message"])
            writer.writerow(alert)

def save_alerts_thread(interval=5):
    while True:
        alerts_to_write = []
        while not alert_queue.empty():
            alerts_to_write.append(alert_queue.get())
        for alert in alerts_to_write:
            save_alert(alert)
        time.sleep(interval)

# Start alert saving thread
threading.Thread(target=save_alerts_thread, daemon=True).start()

# === IDS Runner ===
def run_ids(interfaces):
    global packet_count
    if isinstance(interfaces, str):
        interfaces = [interfaces]
    if not interfaces:
        print("[ids_runner] No interfaces provided to run_ids()")
        return

    try:
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
    except Exception as e:
        print(f"[ids_runner] Failed to create event loop: {e}")
    print(f"[*] IDS thread event loop set for interfaces: {interfaces}")

    try:
        capture = pyshark.LiveCapture(interface=interfaces)
    except Exception as e:
        print(f"[ids_runner] Failed to create LiveCapture on {interfaces}: {e}")
        return

    print(f"[*] LiveCapture created on interfaces: {interfaces} — starting sniff loop")
    flows = defaultdict(list)
    packet_count = 0

    for packet in capture.sniff_continuously():
        packet_count += 1
        try:
            ip_layer = getattr(packet, "ip", None) or getattr(packet, "ipv6", None)
            if ip_layer is None: continue

            proto = getattr(packet, "transport_layer", None)
            if proto is None: continue

            src = getattr(ip_layer, "src", None)
            dst = getattr(ip_layer, "dst", None)
            if src is None or dst is None: 
                continue

            allowed_ips = {"10.10.3.2", "10.10.4.2"}
            if src not in allowed_ips or dst not in allowed_ips:
                continue  # skip this packet            

            sport = int(getattr(getattr(packet, proto.lower(), None), "srcport", 0) or 0)
            dport = int(getattr(getattr(packet, proto.lower(), None), "dstport", 0) or 0)
            flow_id = (src, dst, sport, dport, proto)
            flows[flow_id].append(packet)

            feat_dict = compute_flow_features(flows[flow_id])
            x_new = np.array([feat_dict.get(f, 0) for f in features], dtype=float).reshape(1, -1)
            x_scaled = scaler.transform(x_new)
            x_pca = pca.transform(x_scaled)
            pred = ocsvm.predict(x_pca)[0]

            if pred == -1:
                score = float(ocsvm.decision_function(x_pca)[0])
                if score < -38:
                    severity = "High"
                elif score < 4:
                    severity = "Medium"
                else:
                    severity = "Low/Normal"

                push_alert(flow_id, score, severity)

            flows.pop(flow_id, None)

        except Exception:
            continue

        if packet_count % 50 == 0:
            current_time = time.time()
            for fid in list(flows.keys()):
                try:
                    first_pkt_time = float(flows[fid][0].sniff_timestamp)
                    if current_time - first_pkt_time > 300:
                        flows.pop(fid, None)
                except Exception:
                    flows.pop(fid, None)

def push_alert(flow, score, severity="High"):
    try:
        src_ip, dst_ip, src_port, dst_port, proto = flow
    except Exception:
        src_ip, dst_ip, src_port, dst_port, proto = ("?", "?", "?", "?", "?")
    alert = {
        "time": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "src": f"{src_ip}:{src_port}",
        "dst": f"{dst_ip}:{dst_port}",
        "severity": severity,
        "message": f"Anomalous {proto} flow detected (score={score:.3f})"
    }
    alert_queue.put(alert)
    print(f"[{severity}] {alert['message']} from {alert['src']} → {alert['dst']}")

def start_ids(interfaces):
    """Start IDS runner in a background thread monitoring the provided interfaces."""
    if isinstance(interfaces, str):
        interfaces = [interfaces]
    t = threading.Thread(target=run_ids, args=(interfaces,), daemon=True)
    t.start()
    print(f"[*] IDS thread started for interfaces: {interfaces}")

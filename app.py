import csv
from flask import Flask, jsonify, send_from_directory, request, Response, render_template, stream_with_context
import asyncio
import subprocess, time, requests, os
import psutil
import threading
import queue
import pyshark
import datetime
import json
import glob
from ids_runner import start_ids, alert_queue
import re
import subprocess
from dotenv import load_dotenv

app = Flask(__name__, static_folder="frontend")

# ---------------- Home Page ----------------
@app.route('/')
def home():
    return render_template(
        "home.html",
        ids_interfaces=ids_interfaces,
        capture_interfaces=capture_interfaces
    )

# ---------------- Configuration ----------------
load_dotenv()
TELEGRAM_BOT_TOKEN = os.getenv("TELEGRAM_BOT_TOKEN")
TELEGRAM_API_URL = f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}"
PHONE_FILE = "phone_chat.txt"
alert_cache = {}  # prevent alert fatigue
ALERT_COOLDOWN = 60  # seconds
GNS3_EXE = r"C:\Program Files\GNS3\gns3.exe"
GNS3_PROJECT = r"C:\Users\User\GNS3\projects\Final Year Project\Final Year Project.gns3"
GNS3_API_URL = "http://127.0.0.1:3080/v2/projects"
PROJECT_NAME = "Final Year Project"

# ---------------- Global State ----------------
gns3_process = None
chat_id_var = {"chat_id": None}
ids_interfaces = []
capture_interfaces = []
capture_threads = []
packet_queue = queue.Queue()
capture_running = False
active_captures = {}
alert_history = []
RAW_PCAP_DIR = "raw_pcap"
ALERTS_FOLDER = "alerts"
os.makedirs(RAW_PCAP_DIR, exist_ok=True)

# Load phone-chat mappings
phone_chat_map = {}
if os.path.exists(PHONE_FILE):
    with open(PHONE_FILE, "r") as f:
        for line in f:
            line = line.strip()
            if line:
                phone, chat_id = line.split(",")
                phone_chat_map[phone] = int(chat_id)

# ---------------- Helper Functions ----------------
def wait_for_gns3_server(timeout=120):
    for _ in range(timeout):
        try:
            requests.get(GNS3_API_URL)
            return True
        except requests.exceptions.ConnectionError:
            time.sleep(1)
    return False

def is_simulation_running():
    try:
        projects = requests.get(GNS3_API_URL).json()
        project = next((p for p in projects if p['name'] == PROJECT_NAME), None)
        if not project:
            return False
        nodes_url = f"{GNS3_API_URL}/{project['project_id']}/nodes"
        nodes = requests.get(nodes_url).json()
        return all(n['status'] == "started" for n in nodes)
    except:
        return False

def get_phone_chat_id(phone_number):
    try:
        with open(PHONE_FILE, "r") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                phone, chat_id = line.split(",")
                if phone == phone_number:
                    return chat_id
        return None
    except FileNotFoundError:
        return None

def terminate_process_tree(pid):
    try:
        parent = psutil.Process(pid)
        children = parent.children(recursive=True)
        for child in children:
            child.terminate()
        parent.terminate()
        psutil.wait_procs([parent] + children, timeout=10)
    except Exception as e:
        print(f"Error terminating process tree: {e}")

def kill_gns3_processes():
    for proc in psutil.process_iter(['pid', 'name', 'cmdline']):
        try:
            if proc.info['name'] and 'gns3' in proc.info['name'].lower():
                proc.terminate()
            elif proc.info['cmdline'] and any('gns3' in s.lower() for s in proc.info['cmdline']):
                proc.terminate()
        except Exception as e:
            print(f"Failed to terminate {proc.info}: {e}")
    time.sleep(5)

def safe_is_simulation_running():
    try:
        return is_simulation_running()
    except requests.RequestException:
        return False
    except Exception as e:
        print(f"Unexpected error checking simulation: {e}")
        return False

# ---------------- Packet Capture ----------------
def capture_packets(iface):
    global capture_running, active_captures
    capture_running = True
    timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    pcap_filename = f"capture_{timestamp}_{iface}.pcap"
    pcap_path = os.path.join(RAW_PCAP_DIR, pcap_filename)

    try:
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        capture = pyshark.LiveCapture(interface=iface, output_file=pcap_path)
        active_captures[iface] = capture

        for packet in capture.sniff_continuously():
            if not capture_running:
                break
            packet_info = {}
            packet_info["time"] = getattr(packet, "sniff_time", None)
            packet_info["time"] = packet_info["time"].strftime("%H:%M:%S") if packet_info["time"] else ""
            ip_layer = next((l for l in packet.layers if l.layer_name.lower() == "ip"), None)
            packet_info["src"] = getattr(ip_layer, "src", "") if ip_layer else ""
            packet_info["dst"] = getattr(ip_layer, "dst", "") if ip_layer else ""
            packet_info["protocol"] = packet.highest_layer
            packet_info["length"] = getattr(packet, "length", "")
            packet_info["info"] = str(packet.highest_layer)
            packet_queue.put(packet_info)

    except Exception as e:
        print(f"Error capturing on {iface}: {e}")

# ---------------- Telegram Bot ----------------
def save_phone_to_file(phone, chat_id):
    with open(PHONE_FILE, "a") as f:
        f.write(f"{phone},{chat_id}\n")

import os, subprocess, time, re, shutil

def start_localtunnel(port):
    env = os.environ.copy()
    # Ensure nodejs + npm global bin are in PATH
    env["PATH"] = (
        r"C:\Program Files\nodejs;"  # node.exe
        r"C:\Users\User\AppData\Roaming\npm;"  # lt.cmd
        + env["PATH"]
    )

    # Auto-detect lt path
    lt_path = shutil.which("lt", path=env["PATH"])
    if not lt_path:
        raise FileNotFoundError("LocalTunnel (lt) not found. Is it installed via npm?")

    process = subprocess.Popen(
        [lt_path, "--port", str(port)],
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        env=env
    )

    public_url = None
    start_time = time.time()

    for line in iter(process.stdout.readline, ""):
        print("LT:", line.strip())
        match = re.search(r"(https://[^\s]+)", line)
        if match:
            public_url = match.group(1)
            break
        if time.time() - start_time > 20:
            break

    return public_url

def set_webhook(public_url):
    resp = requests.get(
        f"{TELEGRAM_API_URL}/setWebhook",
        params={"url": f"{public_url}/telegram_webhook"}
    )
    print(resp.json())       

def send_message(chat_id, text):
    payload = {"chat_id": chat_id, "text": text}
    try:
        resp = requests.post(f"{TELEGRAM_API_URL}/sendMessage", json=payload, timeout=5)
        print(f"[Telegram] Response: {resp.json()}")
    except Exception as e:
        print(f"[Telegram] Failed to send message: {e}")

def make_alert_key(alert):
    src_ip = alert['src'].split(":")[0]
    dst_ip = alert['dst'].split(":")[0]
    signature = alert['message'].split("(")[0].strip()
    return f"{src_ip}->{dst_ip}-{alert['severity']}-{signature}"

def alert_sender():
    while True:
        try:
            alert = alert_queue.get(timeout=1)
            print(f"[DEBUG] Got alert from queue: {alert}")
        except Exception:
            time.sleep(0.5)
            continue
        chat_id = chat_id_var["chat_id"]
        if chat_id is None:
            continue
        key = make_alert_key(alert)
        now = time.time()
        cache_entry = alert_cache.get(key)
        if cache_entry and (now - cache_entry['last_time'] < ALERT_COOLDOWN):
            cache_entry['count'] += 1
            cache_entry['last_time'] = now
            continue
        else:
            alert_cache[key] = {'count': 1, 'last_time': now}
        msg = f"[{alert['severity']}] {alert['message']}\n{alert['src']} → {alert['dst']}\nTime: {alert['time']}"
        send_message(chat_id, msg)

@app.route("/telegram_webhook", methods=["POST"])
def telegram_webhook():
    update = request.get_json()
    if not update:
        return "No update", 400

    msg = update.get("message")
    if not msg or "text" not in msg:
        return "No message", 200

    chat_id = msg["chat"]["id"]
    text = msg["text"].strip()
    phone_pattern = re.compile(r"^01\d{8,9}$")  # Malaysian numbers

    if text.lower() == "/start":
        send_message(chat_id, "Welcome!\nPlease type your phone number:")
    else:
        if phone_pattern.match(text):
            phone_chat_map[text] = chat_id
            save_phone_to_file(text, chat_id)
            send_message(chat_id, f"Thanks! Phone {text} registered.")
        else:
            send_message(chat_id, "Invalid phone number format. Please try again.")

    return "OK", 200

def start_bot():
    threading.Thread(target=alert_sender, daemon=True).start()

# ---------------- Flask Error Handling ----------------
@app.errorhandler(Exception)
def handle_exception(e):
    response = jsonify({"status":"Error","message":str(e)})
    response.status_code = 500
    return response

# ---------------- Serve Frontend ----------------
@app.route('/<path:path>')
def serve_file(path):
    return send_from_directory('frontend', path)

# ---------------- Interfaces ----------------
@app.route('/interfaces', methods=['GET'])
def get_interfaces():
    interfaces = list(psutil.net_if_addrs().keys())
    return jsonify({"interfaces": interfaces}), 200

@app.route('/save_interfaces', methods=['POST'])
def save_interfaces():
    global ids_interfaces, capture_interfaces
    data = request.json
    chosen_type = data.get("type", "capture")
    interfaces = data.get("interfaces", [])
    if chosen_type == "ids":
        ids_interfaces = interfaces
        return jsonify({"status": "ok", "ids_interfaces": ids_interfaces}), 200
    else:
        capture_interfaces = interfaces
        return jsonify({"status": "ok", "capture_interfaces": capture_interfaces}), 200

# ---------------- GNS3 Start/Stop ----------------
@app.route('/start_gns3', methods=['POST'])
def start_gns3():
    global gns3_process
    try:
        if not ids_interfaces:
            return jsonify({"status":"Error","message":"No interfaces selected"}),400
        if gns3_process and gns3_process.poll() is None:
            return jsonify({"status":"Error", "message":"Simulation process already running"}),400
        if is_simulation_running():
            return jsonify({"status":"Error", "message":"Simulation already running"}),400
        gns3_process = subprocess.Popen([GNS3_EXE, GNS3_PROJECT], shell=True)
        if not wait_for_gns3_server(120):
            return jsonify({"status":"Error","message":"GNS3 server did not start"}),500
        project_id = None
        for _ in range(60):
            projects = requests.get(GNS3_API_URL).json()
            project = next((p for p in projects if p['name']==PROJECT_NAME), None)
            if project:
                project_id = project['project_id']
                break
            time.sleep(1)
        if not project_id:
            return jsonify({"status":"Error","message":"Project not found"}),500
        nodes_url = f"{GNS3_API_URL}/{project_id}/nodes"
        nodes = requests.get(nodes_url).json()
        for node in nodes:
            requests.post(f"{nodes_url}/{node['node_id']}/start")
        for _ in range(60):
            nodes_status = requests.get(nodes_url).json()
            if all(n['status']=="started" for n in nodes_status):
                return jsonify({"status":"Simulation started"}),200
            time.sleep(1)
        return jsonify({"status":"Error","message":"Simulation did not start"}),500
    except Exception as e:
        return jsonify({"status":"Error","message":str(e)}),500

@app.route('/stop_gns3', methods=['POST'])
def stop_gns3():
    global gns3_process
    try:
        try:
            projects = requests.get(GNS3_API_URL).json()
            project = next((p for p in projects if p['name'] == PROJECT_NAME), None)
        except requests.RequestException:
            project = None
        if project:
            project_id = project['project_id']
            try:
                nodes = requests.get(f"{GNS3_API_URL}/{project_id}/nodes").json()
                for node in nodes:
                    try:
                        requests.post(f"{GNS3_API_URL}/{project_id}/nodes/{node['node_id']}/stop")
                    except Exception as e:
                        print(f"Error stopping node {node['name']}: {e}")
            except Exception as e:
                print(f"Error fetching nodes: {e}")
            for _ in range(60):
                try:
                    nodes_status = requests.get(f"{GNS3_API_URL}/{project_id}/nodes").json()
                    if all(n['status'] == "stopped" for n in nodes_status):
                        break
                except Exception:
                    break
            try:
                requests.post(f"{GNS3_API_URL}/{project_id}/close")
            except Exception as e:
                print(f"Error closing project: {e}")
        if gns3_process and gns3_process.poll() is None:
            terminate_process_tree(gns3_process.pid)
            gns3_process = None
        kill_gns3_processes()
        if safe_is_simulation_running():
            return jsonify({"status": "Error", "message": "Failed to stop simulation"}), 500
        return jsonify({"status": "Simulation stopped"}), 200
    except Exception as e:
        return jsonify({"status": "Error", "message": str(e)}), 500

# ---------------- Capture Start/Stop ----------------
@app.route('/start_capture', methods=['POST'])
def start_capture():
    global capture_threads, capture_running
    if capture_running:
        return jsonify({"status": "Error", "message": "Capture already running"}), 400
    if not capture_interfaces:
        return jsonify({"status":"Error","message":"No interfaces selected"}),400
    capture_threads = []
    for iface in capture_interfaces:
        t = threading.Thread(target=capture_packets, args=(iface,), daemon=True)
        capture_threads.append(t)
        t.start()
    return jsonify({"status": "Capture started"}), 200

@app.route('/stop_capture', methods=['POST'])
def stop_capture():
    global capture_running, active_captures
    capture_running = False
    for iface, cap in active_captures.items():
        try:
            cap.close()
        except Exception as e:
            print(f"Error closing capture on {iface}: {e}")
    active_captures.clear()
    return jsonify({"status": "Capture stopped and saved to raw_pcap/"}), 200

@app.route('/packets')
def stream_packets():
    def event_stream():
        while True:
            try:
                packet = packet_queue.get(timeout=1)
                yield f"data: {json.dumps(packet)}\n\n" 
            except queue.Empty:
                continue
    return Response(event_stream(), mimetype="text/event-stream")

@app.route("/save_phone", methods=["POST"])
def save_phone():
    global chat_id_var
    data = request.get_json()
    phone = data.get("phone")
    if not phone:
        return jsonify({"status": "error", "message": "No phone number provided"}), 400
    chat_id = get_phone_chat_id(phone)
    if chat_id:
        chat_id_var["chat_id"] = chat_id
        return jsonify({"status": "ok", "message": "Phone number verified"}), 200
    else:
        return jsonify({"status": "error", "message": "Phone number not recognized"}), 404

# ---------------- IDS ----------------
@app.route('/start_ids', methods=['POST'])
def start_ids_route():
    global ids_interfaces
    try:
        if not ids_interfaces:
            return jsonify({"status": "Error", "message": "No IDS interfaces selected"}), 400
        start_ids(ids_interfaces)
        return jsonify({"status": "IDS started", "interfaces": ids_interfaces}), 200
    except Exception as e:
        return jsonify({"status": "Error", "message": str(e)}), 500

# ---------------- Alerts ----------------
@app.route('/get_alerts')
def get_alerts():
    date = request.args.get("date")
    if not date:
        return jsonify([])
    files = glob.glob(os.path.join(ALERTS_FOLDER, f"alerts_{date}_*.csv"))
    alerts = []
    for file in files:
        with open(file, newline='') as f:
            reader = csv.DictReader(f)
            for row in reader:
                alerts.append({
                    "time": row["time"],
                    "src": row["src"],
                    "dst": row["dst"],
                    "severity": row["severity"],
                    "message": row["message"]
                })
    return jsonify(alerts)

@app.route("/alerts_stream")
def alerts_stream():
    def generate():
        while True:
            if not alert_queue.empty():
                alert = alert_queue.get()
                alert_history.append(alert)
                yield f"data: {json.dumps(alert)}\n\n"
            else:
                time.sleep(1)
    return Response(
        stream_with_context(generate()),
        mimetype="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"}
    )

# ---------------- PCAP ----------------
@app.route("/list_pcaps")
def list_pcaps():
    files = sorted(os.listdir(RAW_PCAP_DIR))
    return jsonify(files)

@app.route("/get_pcap")
def get_pcap():
    filename = request.args.get("file")
    packets = []
    if not filename:
        return jsonify(packets)
    filepath = os.path.join(RAW_PCAP_DIR, filename)
    if not os.path.exists(filepath):
        return jsonify(packets)
    try:
        if filename.endswith(".csv"):
            with open(filepath, newline='') as f:
                reader = csv.DictReader(f)
                for row in reader:
                    packets.append({
                        "time": row.get("time",""),
                        "src": row.get("src",""),
                        "dst": row.get("dst",""),
                        "protocol": row.get("protocol",""),
                        "length": row.get("length",""),
                        "info": row.get("info","")
                    })
        else:
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            cap = pyshark.FileCapture(filepath, only_summaries=False)
            for pkt in cap:
                time_ = str(pkt.sniff_time)
                protocol = pkt.highest_layer
                length = getattr(pkt, "length", "")
                src = dst = ""
                if "IP" in pkt:
                    src = pkt.ip.src
                    dst = pkt.ip.dst
                elif "IPv6" in pkt:
                    src = pkt.ipv6.src
                    dst = pkt.ipv6.dst
                info = str(pkt)
                packets.append({
                    "time": time_,
                    "src": src,
                    "dst": dst,
                    "protocol": protocol,
                    "length": length,
                    "info": info
                })
            cap.close()
            loop.close()
    except Exception as e:
        print("Error reading PCAP:", e)
        packets = []
    return jsonify(packets)

# ---------------- Run App ----------------
if __name__ == "__main__":
    public_url = start_localtunnel(5000)  
    print("Tunnel started at:", public_url)    
    time.sleep(5)
    set_webhook(public_url)
    start_bot()
    app.run(port=5000, debug=True, use_reloader=False)


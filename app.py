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

app = Flask(__name__, static_folder="frontend")
@app.route('/')
def home():
    return render_template(
        "home.html",
        ids_interfaces=ids_interfaces,
        capture_interfaces=capture_interfaces
    )

GNS3_EXE = r"C:\Program Files\GNS3\gns3.exe"
GNS3_PROJECT = r"C:\Users\User\GNS3\projects\Final Year Project\Final Year Project.gns3"
GNS3_API_URL = "http://127.0.0.1:3080/v2/projects"
PROJECT_NAME = "Final Year Project"

gns3_process = None
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

def wait_for_gns3_server(timeout=120):
    """Wait until GNS3 server responds."""
    for _ in range(timeout):
        try:
            requests.get(GNS3_API_URL)
            return True
        except requests.exceptions.ConnectionError:
            time.sleep(1)
    return False

def is_simulation_running():
    """Check if the GNS3 project nodes are running."""
    try:
        projects = requests.get(GNS3_API_URL).json()
        project = next((p for p in projects if p['name']==PROJECT_NAME), None)
        if not project:
            return False

        nodes_url = f"{GNS3_API_URL}/{project['project_id']}/nodes"
        nodes = requests.get(nodes_url).json()
        return all(n['status']=="started" for n in nodes)
    except:
        return False
    

def terminate_process_tree(pid):
    """Terminate a process and all its children."""
    try:
        parent = psutil.Process(pid)
        children = parent.children(recursive=True)
        for child in children:
            child.terminate()
        parent.terminate()
        gone, alive = psutil.wait_procs([parent] + children, timeout=10)
    except Exception as e:
        print(f"Error terminating process tree: {e}")

def kill_gns3_processes():
    """Kill any lingering GNS3 GUI/server/QEMU processes."""
    for proc in psutil.process_iter(['pid', 'name', 'cmdline']):
        try:
            if proc.info['name'] and 'gns3' in proc.info['name'].lower():
                proc.terminate()
            elif proc.info['cmdline'] and any('gns3' in s.lower() for s in proc.info['cmdline']):
                proc.terminate()
        except Exception as e:
            print(f"Failed to terminate {proc.info}: {e}")
    # Wait a few seconds to ensure termination
    time.sleep(5)

def safe_is_simulation_running():
    """Check if simulation is running, safely handling connection errors."""
    try:
        return is_simulation_running()
    except requests.RequestException:
        # Cannot connect → server is not running → simulation is stopped
        return False
    except Exception as e:
        print(f"Unexpected error checking simulation: {e}")
        return False
    
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

            # Time
            packet_info["time"] = getattr(packet, "sniff_time", None)
            if packet_info["time"]:
                packet_info["time"] = packet_info["time"].strftime("%H:%M:%S")
            else:
                packet_info["time"] = ""

            # IP layer
            ip_layer = None
            for layer in packet.layers:
                if layer.layer_name.lower() == "ip":
                    ip_layer = layer
                    break
            if ip_layer:
                packet_info["src"] = getattr(ip_layer, "src", "")
                packet_info["dst"] = getattr(ip_layer, "dst", "")
            else:
                packet_info["src"] = ""
                packet_info["dst"] = ""

            packet_info["protocol"] = packet.highest_layer
            packet_info["length"] = getattr(packet, "length", "")
            packet_info["info"] = str(packet.highest_layer)

            packet_queue.put(packet_info)

    except Exception as e:
        print(f"Error capturing on {iface}: {e}")

@app.errorhandler(Exception)
def handle_exception(e):
    response = jsonify({"status":"Error","message":str(e)})
    response.status_code = 500
    return response

# Serve frontend files
@app.route('/')
def index():
    return send_from_directory('frontend', 'home.html')

@app.route('/<path:path>')
def serve_file(path):
    return send_from_directory('frontend', path)

# Return list of available interfaces
@app.route('/interfaces', methods=['GET'])
def get_interfaces():
    interfaces = list(psutil.net_if_addrs().keys())
    return jsonify({"interfaces": interfaces}), 200

# Save selected interfaces
@app.route('/save_interfaces', methods=['POST'])
def save_interfaces():
    global ids_interfaces, capture_interfaces
    data = request.json
    chosen_type = data.get("type", "capture")  # default to capture if not given
    interfaces = data.get("interfaces", [])

    if chosen_type == "ids":
        ids_interfaces = interfaces
        print(f"IDS interfaces saved: {ids_interfaces}")
        return jsonify({"status": "ok", "ids_interfaces": ids_interfaces}), 200
    else:
        capture_interfaces = interfaces
        print(f"Capture interfaces saved: {capture_interfaces}")
        return jsonify({"status": "ok", "capture_interfaces": capture_interfaces}), 200

# Start GNS3 simulation
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

        # Start the project
        gns3_process = subprocess.Popen([GNS3_EXE, GNS3_PROJECT], shell=True)

        if not wait_for_gns3_server(120):
            return jsonify({"status":"Error","message":"GNS3 server did not start"}),500

        # Wait for project to appear
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

        # Start nodes
        nodes_url = f"{GNS3_API_URL}/{project_id}/nodes"
        nodes = requests.get(nodes_url).json()
        for node in nodes:
            requests.post(f"{nodes_url}/{node['node_id']}/start")

        # Wait for all nodes to start
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
        # Stop nodes via API
        try:
            projects = requests.get(GNS3_API_URL).json()
            project = next((p for p in projects if p['name'] == PROJECT_NAME), None)
        except requests.RequestException:
            project = None  # Server is not running

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

            # Wait for all nodes to fully stop (max 60 seconds)
            for _ in range(60):
                try:
                    nodes_status = requests.get(f"{GNS3_API_URL}/{project_id}/nodes").json()
                    if all(n['status'] == "stopped" for n in nodes_status):
                        break
                except Exception:
                    break  # Server might be gone
                time.sleep(1)

            # 2️⃣ Close the project gracefully
            try:
                requests.post(f"{GNS3_API_URL}/{project_id}/close")
            except Exception as e:
                print(f"Error closing project: {e}")

        # 3️⃣ Terminate the GNS3 process tree if still running
        if gns3_process and gns3_process.poll() is None:
            terminate_process_tree(gns3_process.pid)
            gns3_process = None

        # 4️⃣ Kill any lingering GUI/server/QEMU processes
        kill_gns3_processes()

        # 5️⃣ Final check
        if safe_is_simulation_running():
            return jsonify({"status": "Error", "message": "Failed to stop simulation"}), 500

        return jsonify({"status": "Simulation stopped"}), 200

    except Exception as e:
        return jsonify({"status": "Error", "message": str(e)}), 500

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

    # Stop all active captures
    for iface, cap in active_captures.items():
        try:
            cap.close()  # ensure file is finalized
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

@app.route('/start_ids', methods=['POST'])
def start_ids_route():
    global ids_interfaces
    try:
        if not ids_interfaces:
            return jsonify({"status": "Error", "message": "No IDS interfaces selected"}), 400

        # Start IDS on all user-selected interfaces
        start_ids(ids_interfaces)

        return jsonify({"status": "IDS started", "interfaces": ids_interfaces}), 200
    except Exception as e:
        return jsonify({"status": "Error", "message": str(e)}), 500
    
@app.route('/get_alerts')
def get_alerts():
    date = request.args.get("date")  # e.g., "20250901"
    if not date:
        return jsonify([])

    # Find all hourly files for that date
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
                time.sleep(1)  # prevent busy loop
    return Response(
        stream_with_context(generate()),
        mimetype="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "X-Accel-Buffering": "no"
        }
    )

@app.route("/list_pcaps")
def list_pcaps():
    files = sorted(os.listdir(RAW_PCAP_DIR))
    return jsonify(files)

import asyncio
import pyshark

import asyncio
import pyshark

@app.route("/get_pcap")
def get_pcap():
    import os
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

            print(f"Logging PCAP: {filename}")
            for i, pkt in enumerate(cap):
                print(f"Packet {i}: {pkt}")

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
                else:
                    src = getattr(pkt, "source", "")
                    dst = getattr(pkt, "destination", "")

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

    print(f"Total packets parsed: {len(packets)}")
    return jsonify(packets)

if __name__=="__main__":
    app.run(port=5000, debug=True)

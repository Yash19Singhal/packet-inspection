"""
DPI Engine Web Server
Flask backend that wraps the C++ dpi_engine.exe, parses its stdout,
and serves structured JSON to the frontend dashboard.
"""

import os
import re
import subprocess
import tempfile
import uuid
from flask import Flask, request, jsonify, send_from_directory
from flask_cors import CORS

app = Flask(__name__, static_folder="static", static_url_path="")
CORS(app)

# Path to the DPI engine executable (supports Windows and Linux)
_base_dir = os.path.dirname(os.path.abspath(__file__))
engine_name = "dpi_engine.exe" if os.name == 'nt' else "dpi_engine"
DPI_ENGINE = os.path.join(_base_dir, engine_name)

# Uploads directory
UPLOAD_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "uploads")
os.makedirs(UPLOAD_DIR, exist_ok=True)


@app.route("/")
def index():
    """Serve the frontend dashboard."""
    return send_from_directory("static", "index.html")


@app.route("/api/analyze", methods=["POST"])
def analyze():
    """
    Accept a .pcap file upload + optional blocking rules,
    run dpi_engine.exe, parse stdout, and return structured JSON.
    """
    # --- Validate upload ---
    if "pcap_file" not in request.files:
        return jsonify({"error": "No pcap file uploaded"}), 400

    pcap_file = request.files["pcap_file"]
    if pcap_file.filename == "":
        return jsonify({"error": "Empty filename"}), 400

    if not pcap_file.filename.lower().endswith(".pcap"):
        return jsonify({"error": "File must be a .pcap file"}), 400

    # Save uploaded file
    file_id = str(uuid.uuid4())[:8]
    input_path = os.path.join(UPLOAD_DIR, f"{file_id}_input.pcap")
    output_path = os.path.join(UPLOAD_DIR, f"{file_id}_output.pcap")
    pcap_file.save(input_path)

    # --- Build command ---
    cmd = [DPI_ENGINE, input_path, output_path]

    # Parse blocking rules from form data
    block_ips = request.form.getlist("block_ips")
    block_apps = request.form.getlist("block_apps")
    block_domains = request.form.getlist("block_domains")

    for ip in block_ips:
        ip = ip.strip()
        if ip:
            cmd.extend(["--block-ip", ip])
    for app_name in block_apps:
        app_name = app_name.strip()
        if app_name:
            cmd.extend(["--block-app", app_name])
    for domain in block_domains:
        domain = domain.strip()
        if domain:
            cmd.extend(["--block-domain", domain])

    # Parse thread config
    lbs = request.form.get("lbs", "").strip()
    fps = request.form.get("fps", "").strip()
    if lbs and lbs.isdigit():
        cmd.extend(["--lbs", lbs])
    if fps and fps.isdigit():
        cmd.extend(["--fps", fps])

    # --- Run the DPI engine ---
    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            encoding="utf-8",
            errors="replace",
            timeout=60,
            cwd=os.path.dirname(os.path.abspath(__file__)),
        )
        stdout = result.stdout or ""
        stderr = result.stderr or ""
    except subprocess.TimeoutExpired:
        return jsonify({"error": "DPI engine timed out (>60s)"}), 500
    except FileNotFoundError:
        return jsonify({"error": f"DPI engine not found at {DPI_ENGINE}. Did you build it?"}), 500
    except Exception as e:
        return jsonify({"error": f"Failed to run DPI engine: {str(e)}"}), 500
    finally:
        # Cleanup input file
        if os.path.exists(input_path):
            os.remove(input_path)
        if os.path.exists(output_path):
            os.remove(output_path)

    if result.returncode != 0:
        return jsonify({"error": f"DPI engine failed: {stderr or stdout}"}), 500

    # --- Parse the stdout ---
    parsed = parse_dpi_output(stdout)
    return jsonify(parsed)


def parse_dpi_output(output: str) -> dict:
    """
    Parse the formatted terminal output from dpi_engine.exe into structured data.
    """
    data = {
        "engine_config": {
            "num_lbs": 0,
            "fps_per_lb": 0,
            "total_fps": 0,
        },
        "summary": {
            "total_packets": 0,
            "total_bytes": 0,
            "tcp_packets": 0,
            "udp_packets": 0,
            "forwarded": 0,
            "dropped": 0,
        },
        "thread_stats": {
            "load_balancers": [],
            "fast_paths": [],
        },
        "app_breakdown": [],
        "detected_domains": [],
        "blocked_rules": [],
    }

    lines = output.split("\n")

    for line in lines:
        # --- Engine Config ---
        # ║ Load Balancers:  2    FPs per LB:  2    Total FPs:  4     ║
        cfg_match = re.search(
            r"Load Balancers:\s*(\d+)\s+FPs per LB:\s*(\d+)\s+Total FPs:\s*(\d+)", line
        )
        if cfg_match:
            data["engine_config"]["num_lbs"] = int(cfg_match.group(1))
            data["engine_config"]["fps_per_lb"] = int(cfg_match.group(2))
            data["engine_config"]["total_fps"] = int(cfg_match.group(3))
            continue

        # --- Summary Stats ---
        for key, label in [
            ("total_packets", "Total Packets"),
            ("total_bytes", "Total Bytes"),
            ("tcp_packets", "TCP Packets"),
            ("udp_packets", "UDP Packets"),
            ("forwarded", "Forwarded"),
            ("dropped", "Dropped"),
        ]:
            match = re.search(rf"{label}:\s+(\d+)", line)
            if match:
                data["summary"][key] = int(match.group(1))
                break

        # --- Thread Stats ---
        # ║   LB0 dispatched:             53
        lb_match = re.search(r"LB(\d+)\s+dispatched:\s+(\d+)", line)
        if lb_match:
            data["thread_stats"]["load_balancers"].append({
                "id": int(lb_match.group(1)),
                "dispatched": int(lb_match.group(2)),
            })
            continue

        # ║   FP0 processed:              53
        fp_match = re.search(r"FP(\d+)\s+processed:\s+(\d+)", line)
        if fp_match:
            data["thread_stats"]["fast_paths"].append({
                "id": int(fp_match.group(1)),
                "processed": int(fp_match.group(2)),
            })
            continue

        # --- App Breakdown ---
        # ║ HTTPS                39  50.6% ##########
        app_match = re.search(
            r"║\s+(\S+(?:\s*/\s*\S+)?)\s+(\d+)\s+([\d.]+)%", line
        )
        if app_match:
            app_name = app_match.group(1).strip()
            # Skip section headers
            if app_name in ("THREAD", "APPLICATION", "PROCESSING"):
                continue
            data["app_breakdown"].append({
                "app": app_name,
                "count": int(app_match.group(2)),
                "percentage": float(app_match.group(3)),
            })
            continue

        # --- Detected Domains ---
        #   - example.com -> HTTPS
        domain_match = re.search(r"^\s+-\s+(.+?)\s+->\s+(.+)$", line)
        if domain_match:
            data["detected_domains"].append({
                "domain": domain_match.group(1).strip(),
                "app": domain_match.group(2).strip(),
            })
            continue

        # --- Blocked rules ---
        rule_match = re.search(r"\[Rules\]\s+Blocked\s+(\w+):\s+(.+)", line)
        if rule_match:
            data["blocked_rules"].append({
                "type": rule_match.group(1).strip(),
                "value": rule_match.group(2).strip(),
            })

    return data


if __name__ == "__main__":
    print("\n  DPI Engine Dashboard")
    print("  ========================")
    port = int(os.environ.get("PORT", 5000))
    print(f"  Starting server on port {port}...\n")
    app.run(host="0.0.0.0", port=port, debug=True)

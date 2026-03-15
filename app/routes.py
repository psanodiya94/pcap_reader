"""Flask routes for the PCAP Reader application."""

import os
import traceback

from flask import Blueprint, current_app, jsonify, render_template, request
from werkzeug.utils import secure_filename

from utils import parse_pcap, SSHHandler, PCAP_BACKEND, SSH_BACKEND

main_bp = Blueprint("main", __name__)


def _allowed_file(filename):
    return "." in filename and filename.rsplit(".", 1)[1].lower() in current_app.config["ALLOWED_EXTENSIONS"]


@main_bp.route("/")
def index():
    return render_template("index.html")


@main_bp.route("/api/status", methods=["GET"])
def status():
    """Return which backends are active."""
    return jsonify({
        "pcap_backend": PCAP_BACKEND,
        "ssh_backend": SSH_BACKEND,
    })


@main_bp.route("/api/upload", methods=["POST"])
def upload_pcap():
    """Handle local pcap file upload and parse it."""
    if "file" not in request.files:
        return jsonify({"error": "No file provided"}), 400

    file = request.files["file"]
    if file.filename == "":
        return jsonify({"error": "No file selected"}), 400

    if not _allowed_file(file.filename):
        return jsonify({"error": "Invalid file type. Allowed: pcap, pcapng, cap"}), 400

    filename = secure_filename(file.filename)
    filepath = os.path.join(current_app.config["UPLOAD_FOLDER"], filename)

    try:
        file.save(filepath)
        result = parse_pcap(filepath)
        return jsonify(result)
    except Exception as e:
        return jsonify({"error": f"Failed to parse pcap: {str(e)}"}), 500
    finally:
        if os.path.exists(filepath):
            os.remove(filepath)


@main_bp.route("/api/ssh/read", methods=["POST"])
def ssh_read_pcap():
    """Read and parse a pcap file from a remote server via SSH."""
    data = request.get_json()
    if not data:
        return jsonify({"error": "No JSON data provided"}), 400

    required = ["hostname", "username", "remote_path"]
    missing = [f for f in required if not data.get(f)]
    if missing:
        return jsonify({"error": f"Missing required fields: {', '.join(missing)}"}), 400

    try:
        with SSHHandler(
            hostname=data["hostname"],
            username=data["username"],
            password=data.get("password"),
            key_path=data.get("key_path"),
            port=int(data.get("port", 22)),
        ) as ssh:
            local_path = ssh.download_pcap(
                data["remote_path"],
                current_app.config["UPLOAD_FOLDER"],
            )
            try:
                result = parse_pcap(local_path)
                return jsonify(result)
            finally:
                if os.path.exists(local_path):
                    os.remove(local_path)

    except FileNotFoundError as e:
        return jsonify({"error": f"Remote file not found: {str(e)}"}), 404
    except Exception as e:
        return jsonify({"error": f"SSH operation failed: {str(e)}"}), 500


@main_bp.route("/api/ssh/tshark", methods=["POST"])
def ssh_tshark():
    """Run tshark on a remote server and return output."""
    data = request.get_json()
    if not data:
        return jsonify({"error": "No JSON data provided"}), 400

    required = ["hostname", "username", "remote_path"]
    missing = [f for f in required if not data.get(f)]
    if missing:
        return jsonify({"error": f"Missing required fields: {', '.join(missing)}"}), 400

    try:
        with SSHHandler(
            hostname=data["hostname"],
            username=data["username"],
            password=data.get("password"),
            key_path=data.get("key_path"),
            port=int(data.get("port", 22)),
        ) as ssh:
            result = ssh.run_tshark(
                remote_pcap_path=data["remote_path"],
                display_filter=data.get("display_filter"),
                max_packets=int(data.get("max_packets", 1000)),
            )
            return jsonify(result)

    except FileNotFoundError as e:
        return jsonify({"error": str(e)}), 404
    except Exception as e:
        return jsonify({"error": f"SSH tshark failed: {str(e)}"}), 500


@main_bp.route("/api/ssh/check-tshark", methods=["POST"])
def check_tshark():
    """Check if tshark is available on a remote server."""
    data = request.get_json()
    if not data:
        return jsonify({"error": "No JSON data provided"}), 400

    try:
        with SSHHandler(
            hostname=data["hostname"],
            username=data["username"],
            password=data.get("password"),
            key_path=data.get("key_path"),
            port=int(data.get("port", 22)),
        ) as ssh:
            available = ssh.check_tshark_available()
            return jsonify({"tshark_available": available})

    except Exception as e:
        return jsonify({"error": str(e)}), 500

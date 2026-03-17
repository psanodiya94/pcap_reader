"""Flask routes for the PCAP Reader application."""

import os
import uuid

from flask import Blueprint, current_app, jsonify, render_template, request, session
from werkzeug.utils import secure_filename

from utils import parse_pcap, SSHHandler, PCAP_BACKEND, SSH_BACKEND
from utils.hex_dump import get_packet_hexdump

main_bp = Blueprint("main", __name__)

# Simple in-memory store: session_id -> file_path
# In production you'd use proper session/cache management.
_active_files = {}


def _allowed_file(filename):
    return "." in filename and filename.rsplit(".", 1)[1].lower() in current_app.config["ALLOWED_EXTENSIONS"]


def _store_active_file(filepath):
    """Store the current pcap file and clean up any previous one."""
    sid = session.get("sid")
    if not sid:
        sid = uuid.uuid4().hex
        session["sid"] = sid

    # Remove previous file
    old_path = _active_files.get(sid)
    if old_path and os.path.exists(old_path) and old_path != filepath:
        os.remove(old_path)

    _active_files[sid] = filepath
    return sid


def _get_active_file():
    """Get the current active pcap file path for this session."""
    sid = session.get("sid")
    if not sid:
        return None
    path = _active_files.get(sid)
    if path and os.path.exists(path):
        return path
    return None


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
    # Add unique prefix to avoid collisions
    unique_name = f"{uuid.uuid4().hex}_{filename}"
    filepath = os.path.join(current_app.config["UPLOAD_FOLDER"], unique_name)

    try:
        file.save(filepath)
        result = parse_pcap(filepath)
        # Keep the file for hex dump requests
        _store_active_file(filepath)
        return jsonify(result)
    except Exception as e:
        if os.path.exists(filepath):
            os.remove(filepath)
        return jsonify({"error": f"Failed to parse pcap: {str(e)}"}), 500


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
                _store_active_file(local_path)
                return jsonify(result)
            except Exception:
                if os.path.exists(local_path):
                    os.remove(local_path)
                raise

    except FileNotFoundError as e:
        return jsonify({"error": f"Remote file not found: {str(e)}"}), 404
    except Exception as e:
        return jsonify({"error": f"SSH operation failed: {str(e)}"}), 500


@main_bp.route("/api/hexdump/<int:packet_no>", methods=["GET"])
def hexdump(packet_no):
    """Return hex dump for a specific packet from the last parsed pcap."""
    filepath = _get_active_file()
    if not filepath:
        return jsonify({"error": "No pcap file loaded. Upload or read a file first."}), 404

    try:
        result = get_packet_hexdump(filepath, packet_no)
        return jsonify(result)
    except ValueError as e:
        return jsonify({"error": str(e)}), 404
    except Exception as e:
        return jsonify({"error": f"Hex dump failed: {str(e)}"}), 500


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

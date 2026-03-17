"""Standalone web server using only Python standard library (http.server).

Used when Flask is not installed. Provides the same API endpoints and
serves the same static files and HTML template.
"""

import cgi
import json
import mimetypes
import os
import re
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse

from utils import parse_pcap, SSHHandler, PCAP_BACKEND, SSH_BACKEND
from utils.hex_dump import get_packet_hexdump

# Paths
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
STATIC_DIR = os.path.join(BASE_DIR, "static")
TEMPLATE_DIR = os.path.join(BASE_DIR, "templates")
UPLOAD_DIR = os.path.join(os.path.dirname(BASE_DIR), "uploads")
ALLOWED_EXTENSIONS = {"pcap", "pcapng", "cap"}
MAX_CONTENT_LENGTH = 50 * 1024 * 1024  # 50 MB

os.makedirs(UPLOAD_DIR, exist_ok=True)

# Store the last uploaded/downloaded pcap file path (single-user stdlib server)
_active_pcap_file = None


def _allowed_file(filename):
    return "." in filename and filename.rsplit(".", 1)[1].lower() in ALLOWED_EXTENSIONS


def _secure_filename(filename):
    """Basic filename sanitization."""
    filename = os.path.basename(filename)
    safe = "".join(c if (c.isalnum() or c in "._-") else "_" for c in filename)
    return safe or "upload"


def _set_active_file(filepath):
    """Store the active pcap file, cleaning up the previous one."""
    global _active_pcap_file
    if _active_pcap_file and os.path.exists(_active_pcap_file) and _active_pcap_file != filepath:
        os.remove(_active_pcap_file)
    _active_pcap_file = filepath


class PCAPRequestHandler(BaseHTTPRequestHandler):
    """HTTP request handler for the PCAP Reader application."""

    def log_message(self, format, *args):
        print(f"[{self.log_date_time_string()}] {format % args}")

    # --- GET routes ---

    def do_GET(self):
        parsed = urlparse(self.path)
        path = parsed.path

        if path == "/" or path == "":
            self._serve_index()
        elif path.startswith("/static/"):
            self._serve_static(path)
        elif path == "/api/status":
            self._send_json({"pcap_backend": PCAP_BACKEND, "ssh_backend": SSH_BACKEND})
        elif re.match(r"^/api/hexdump/(\d+)$", path):
            pkt_no = int(re.match(r"^/api/hexdump/(\d+)$", path).group(1))
            self._handle_hexdump(pkt_no)
        else:
            self._send_error(404, "Not found")

    # --- POST routes ---

    def do_POST(self):
        parsed = urlparse(self.path)
        path = parsed.path

        if path == "/api/upload":
            self._handle_upload()
        elif path == "/api/ssh/read":
            self._handle_ssh_read()
        elif path == "/api/ssh/tshark":
            self._handle_ssh_tshark()
        elif path == "/api/ssh/check-tshark":
            self._handle_ssh_check_tshark()
        else:
            self._send_error(404, "Not found")

    # --- File serving ---

    def _serve_index(self):
        index_path = os.path.join(TEMPLATE_DIR, "index.html")
        if not os.path.isfile(index_path):
            self._send_error(500, "index.html not found")
            return

        with open(index_path, "r") as f:
            html = f.read()

        html = html.replace(
            "{{ url_for('static', filename='css/style.css') }}", "/static/css/style.css"
        )
        html = html.replace(
            "{{ url_for('static', filename='js/app.js') }}", "/static/js/app.js"
        )

        self._send_response(200, html.encode(), "text/html")

    def _serve_static(self, path):
        safe_path = os.path.normpath(path.lstrip("/"))
        if ".." in safe_path:
            self._send_error(403, "Forbidden")
            return

        file_path = os.path.join(BASE_DIR, safe_path)
        if not os.path.isfile(file_path):
            self._send_error(404, "File not found")
            return

        mime_type, _ = mimetypes.guess_type(file_path)
        with open(file_path, "rb") as f:
            data = f.read()
        self._send_response(200, data, mime_type or "application/octet-stream")

    # --- API handlers ---

    def _handle_upload(self):
        content_type = self.headers.get("Content-Type", "")
        if "multipart/form-data" not in content_type:
            self._send_json({"error": "Expected multipart/form-data"}, 400)
            return

        try:
            content_length = int(self.headers.get("Content-Length", 0))
            if content_length > MAX_CONTENT_LENGTH:
                self._send_json({"error": "File too large (max 50 MB)"}, 400)
                return

            form = cgi.FieldStorage(
                fp=self.rfile,
                headers=self.headers,
                environ={
                    "REQUEST_METHOD": "POST",
                    "CONTENT_TYPE": content_type,
                    "CONTENT_LENGTH": str(content_length),
                },
            )
        except Exception as e:
            self._send_json({"error": f"Failed to parse form data: {e}"}, 400)
            return

        if "file" not in form:
            self._send_json({"error": "No file provided"}, 400)
            return

        file_item = form["file"]
        if not file_item.filename:
            self._send_json({"error": "No file selected"}, 400)
            return

        if not _allowed_file(file_item.filename):
            self._send_json({"error": "Invalid file type. Allowed: pcap, pcapng, cap"}, 400)
            return

        filename = _secure_filename(file_item.filename)
        filepath = os.path.join(UPLOAD_DIR, filename)

        try:
            with open(filepath, "wb") as f:
                f.write(file_item.file.read())
            result = parse_pcap(filepath)
            _set_active_file(filepath)
            self._send_json(result)
        except Exception as e:
            if os.path.exists(filepath):
                os.remove(filepath)
            self._send_json({"error": f"Failed to parse pcap: {e}"}, 500)

    def _handle_ssh_read(self):
        data = self._read_json_body()
        if data is None:
            return

        required = ["hostname", "username", "remote_path"]
        missing = [f for f in required if not data.get(f)]
        if missing:
            self._send_json({"error": f"Missing required fields: {', '.join(missing)}"}, 400)
            return

        try:
            with SSHHandler(
                hostname=data["hostname"],
                username=data["username"],
                password=data.get("password"),
                key_path=data.get("key_path"),
                port=int(data.get("port", 22)),
            ) as ssh:
                local_path = ssh.download_pcap(data["remote_path"], UPLOAD_DIR)
                try:
                    result = parse_pcap(local_path)
                    _set_active_file(local_path)
                    self._send_json(result)
                except Exception:
                    if os.path.exists(local_path):
                        os.remove(local_path)
                    raise
        except FileNotFoundError as e:
            self._send_json({"error": f"Remote file not found: {e}"}, 404)
        except Exception as e:
            self._send_json({"error": f"SSH operation failed: {e}"}, 500)

    def _handle_hexdump(self, packet_no):
        """Return hex dump for a specific packet."""
        global _active_pcap_file
        if not _active_pcap_file or not os.path.exists(_active_pcap_file):
            self._send_json({"error": "No pcap file loaded. Upload or read a file first."}, 404)
            return

        try:
            result = get_packet_hexdump(_active_pcap_file, packet_no)
            self._send_json(result)
        except ValueError as e:
            self._send_json({"error": str(e)}, 404)
        except Exception as e:
            self._send_json({"error": f"Hex dump failed: {e}"}, 500)

    def _handle_ssh_tshark(self):
        data = self._read_json_body()
        if data is None:
            return

        required = ["hostname", "username", "remote_path"]
        missing = [f for f in required if not data.get(f)]
        if missing:
            self._send_json({"error": f"Missing required fields: {', '.join(missing)}"}, 400)
            return

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
                self._send_json(result)
        except FileNotFoundError as e:
            self._send_json({"error": str(e)}, 404)
        except Exception as e:
            self._send_json({"error": f"SSH tshark failed: {e}"}, 500)

    def _handle_ssh_check_tshark(self):
        data = self._read_json_body()
        if data is None:
            return

        try:
            with SSHHandler(
                hostname=data["hostname"],
                username=data["username"],
                password=data.get("password"),
                key_path=data.get("key_path"),
                port=int(data.get("port", 22)),
            ) as ssh:
                available = ssh.check_tshark_available()
                self._send_json({"tshark_available": available})
        except Exception as e:
            self._send_json({"error": str(e)}, 500)

    # --- Helpers ---

    def _read_json_body(self):
        try:
            content_length = int(self.headers.get("Content-Length", 0))
            body = self.rfile.read(content_length)
            return json.loads(body)
        except (json.JSONDecodeError, ValueError) as e:
            self._send_json({"error": f"Invalid JSON: {e}"}, 400)
            return None

    def _send_json(self, data, status=200):
        body = json.dumps(data).encode()
        self._send_response(status, body, "application/json")

    def _send_error(self, status, message):
        body = json.dumps({"error": message}).encode()
        self._send_response(status, body, "application/json")

    def _send_response(self, status, body, content_type):
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


def run_stdlib_server(host="0.0.0.0", port=5000):
    """Start the stdlib HTTP server."""
    server = HTTPServer((host, port), PCAPRequestHandler)
    print(f"PCAP Reader (stdlib server) running on http://{host}:{port}")
    print(f"  PCAP backend : {PCAP_BACKEND}")
    print(f"  SSH backend  : {SSH_BACKEND}")
    print("Press Ctrl+C to stop.\n")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nShutting down.")
        server.server_close()

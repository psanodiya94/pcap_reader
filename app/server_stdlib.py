"""Standalone web server using only Python standard library (http.server).

Used when Flask is not installed. Provides the same API endpoints and
serves the same static files and HTML template.

NOTE: The deprecated ``cgi`` module has been replaced with a manual
multipart/form-data parser using only ``email.parser`` and ``io``, which
works on Python 3.13+ where ``cgi`` was removed.
"""

from __future__ import annotations

import io
import json
import logging
import mimetypes
import os
import re
import uuid
from email.parser import BytesParser
from http.server import HTTPServer, BaseHTTPRequestHandler
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from utils import parse_pcap, SSHHandler, PCAP_BACKEND, SSH_BACKEND
from utils.hex_dump import get_packet_hexdump

logger = logging.getLogger(__name__)

# Paths
BASE_DIR = Path(__file__).resolve().parent
STATIC_DIR = BASE_DIR / "static"
TEMPLATE_DIR = BASE_DIR / "templates"
UPLOAD_DIR = BASE_DIR.parent / "uploads"
ALLOWED_EXTENSIONS = {"pcap", "pcapng", "cap"}
MAX_CONTENT_LENGTH = 50 * 1024 * 1024  # 50 MB

UPLOAD_DIR.mkdir(exist_ok=True)

# Store the last uploaded/downloaded pcap file path (single-user stdlib server)
_active_pcap_file: str | None = None


def _allowed_file(filename: str) -> bool:
    return "." in filename and filename.rsplit(".", 1)[1].lower() in ALLOWED_EXTENSIONS


def _secure_filename(filename: str) -> str:
    """Basic filename sanitization."""
    filename = os.path.basename(filename)
    safe = "".join(c if (c.isalnum() or c in "._-") else "_" for c in filename)
    return safe or "upload"


def _set_active_file(filepath: str) -> None:
    """Store the active pcap file, cleaning up the previous one."""
    global _active_pcap_file
    if _active_pcap_file and os.path.exists(_active_pcap_file) and _active_pcap_file != filepath:
        os.remove(_active_pcap_file)
    _active_pcap_file = filepath


def _parse_multipart(content_type: str, body: bytes) -> dict[str, Any]:
    """Parse multipart/form-data without the deprecated cgi module.

    Returns a dict mapping field names to either ``bytes`` (for file
    uploads) or ``str`` (for text fields).  File fields additionally
    get ``<name>_filename`` entries.
    """
    # Extract boundary from content-type
    boundary: str | None = None
    for part in content_type.split(";"):
        part = part.strip()
        if part.lower().startswith("boundary="):
            boundary = part.split("=", 1)[1].strip().strip('"')
            break

    if not boundary:
        raise ValueError("Missing boundary in Content-Type header")

    boundary_bytes = boundary.encode("ascii")
    delimiter = b"--" + boundary_bytes
    end_delimiter = delimiter + b"--"

    # Split the body on the boundary
    parts = body.split(delimiter)

    fields: dict[str, Any] = {}
    parser = BytesParser()

    for part in parts:
        # Skip preamble and epilogue
        part = part.strip(b"\r\n")
        if not part or part == b"--" or part.startswith(end_delimiter):
            continue
        if part.endswith(b"--"):
            part = part[:-2]

        # Separate headers from body using the blank line
        header_end = part.find(b"\r\n\r\n")
        if header_end == -1:
            continue

        raw_headers = part[:header_end]
        field_body = part[header_end + 4:]
        # Strip trailing \r\n from field body
        if field_body.endswith(b"\r\n"):
            field_body = field_body[:-2]

        # Parse headers via email.parser
        msg = parser.parsebytes(raw_headers)
        disposition = msg.get("Content-Disposition", "")

        # Extract name and optional filename
        name: str | None = None
        filename: str | None = None
        for token in disposition.split(";"):
            token = token.strip()
            if token.lower().startswith("name="):
                name = token.split("=", 1)[1].strip().strip('"')
            elif token.lower().startswith("filename="):
                filename = token.split("=", 1)[1].strip().strip('"')

        if name is None:
            continue

        if filename is not None:
            fields[name] = field_body
            fields[f"{name}_filename"] = filename
        else:
            fields[name] = field_body.decode("utf-8", errors="replace")

    return fields


class PCAPRequestHandler(BaseHTTPRequestHandler):
    """HTTP request handler for the PCAP Reader application."""

    def log_message(self, format: str, *args: Any) -> None:
        logger.info(format, *args)

    # --- GET routes ---

    def do_GET(self) -> None:
        parsed = urlparse(self.path)
        path = parsed.path

        if path in ("/", ""):
            self._serve_index()
        elif path.startswith("/static/"):
            self._serve_static(path)
        elif path == "/api/status":
            self._send_json({"pcap_backend": PCAP_BACKEND, "ssh_backend": SSH_BACKEND})
        elif m := re.match(r"^/api/hexdump/(\d+)$", path):
            pkt_no = int(m.group(1))
            self._handle_hexdump(pkt_no)
        else:
            self._send_error(404, "Not found")

    # --- POST routes ---

    def do_POST(self) -> None:
        parsed = urlparse(self.path)
        path = parsed.path

        match path:
            case "/api/upload":
                self._handle_upload()
            case "/api/ssh/read":
                self._handle_ssh_read()
            case "/api/ssh/tshark":
                self._handle_ssh_tshark()
            case "/api/ssh/check-tshark":
                self._handle_ssh_check_tshark()
            case _:
                self._send_error(404, "Not found")

    # --- File serving ---

    def _serve_index(self) -> None:
        index_path = TEMPLATE_DIR / "index.html"
        if not index_path.is_file():
            self._send_error(500, "index.html not found")
            return

        html = index_path.read_text()

        html = html.replace(
            "{{ url_for('static', filename='css/style.css') }}", "/static/css/style.css"
        )
        html = html.replace(
            "{{ url_for('static', filename='js/app.js') }}", "/static/js/app.js"
        )

        self._send_response(200, html.encode(), "text/html")

    def _serve_static(self, path: str) -> None:
        safe_path = Path(path.lstrip("/"))
        if ".." in safe_path.parts:
            self._send_error(403, "Forbidden")
            return

        file_path = BASE_DIR / safe_path
        if not file_path.is_file():
            self._send_error(404, "File not found")
            return

        mime_type, _ = mimetypes.guess_type(str(file_path))
        data = file_path.read_bytes()
        self._send_response(200, data, mime_type or "application/octet-stream")

    # --- API handlers ---

    def _handle_upload(self) -> None:
        content_type = self.headers.get("Content-Type", "")
        if "multipart/form-data" not in content_type:
            self._send_json({"error": "Expected multipart/form-data"}, 400)
            return

        try:
            content_length = int(self.headers.get("Content-Length", 0))
            if content_length > MAX_CONTENT_LENGTH:
                self._send_json({"error": "File too large (max 50 MB)"}, 400)
                return

            body = self.rfile.read(content_length)
            fields = _parse_multipart(content_type, body)
        except Exception as e:
            self._send_json({"error": f"Failed to parse form data: {e}"}, 400)
            return

        if "file" not in fields:
            self._send_json({"error": "No file provided"}, 400)
            return

        filename = fields.get("file_filename", "")
        if not filename:
            self._send_json({"error": "No file selected"}, 400)
            return

        if not _allowed_file(filename):
            self._send_json({"error": "Invalid file type. Allowed: pcap, pcapng, cap"}, 400)
            return

        safe_name = _secure_filename(filename)
        unique_name = f"{uuid.uuid4().hex}_{safe_name}"
        filepath = str(UPLOAD_DIR / unique_name)

        try:
            with open(filepath, "wb") as f:
                f.write(fields["file"])
            result = parse_pcap(filepath)
            _set_active_file(filepath)
            self._send_json(result)
        except Exception as e:
            if os.path.exists(filepath):
                os.remove(filepath)
            self._send_json({"error": f"Failed to parse pcap: {e}"}, 500)

    def _handle_ssh_read(self) -> None:
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
                local_path = ssh.download_pcap(data["remote_path"], str(UPLOAD_DIR))
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

    def _handle_hexdump(self, packet_no: int) -> None:
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

    def _handle_ssh_tshark(self) -> None:
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

    def _handle_ssh_check_tshark(self) -> None:
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

    def _read_json_body(self) -> dict[str, Any] | None:
        try:
            content_length = int(self.headers.get("Content-Length", 0))
            body = self.rfile.read(content_length)
            return json.loads(body)
        except (json.JSONDecodeError, ValueError) as e:
            self._send_json({"error": f"Invalid JSON: {e}"}, 400)
            return None

    def _send_json(self, data: Any, status: int = 200) -> None:
        body = json.dumps(data).encode()
        self._send_response(status, body, "application/json")

    def _send_error(self, status: int, message: str) -> None:
        body = json.dumps({"error": message}).encode()
        self._send_response(status, body, "application/json")

    def _send_response(self, status: int, body: bytes, content_type: str) -> None:
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


def run_stdlib_server(host: str = "0.0.0.0", port: int = 5000) -> None:
    """Start the stdlib HTTP server."""
    server = HTTPServer((host, port), PCAPRequestHandler)
    logger.info("PCAP Reader (stdlib server) running on http://%s:%d", host, port)
    logger.info("  PCAP backend : %s", PCAP_BACKEND)
    logger.info("  SSH backend  : %s", SSH_BACKEND)
    logger.info("Press Ctrl+C to stop.")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        logger.info("Shutting down.")
        server.server_close()

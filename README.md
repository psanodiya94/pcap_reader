# PCAP Reader

A web-based tool for reading and analyzing standard PCAP files. Supports local file uploads and remote file access via SSH, with optional Wireshark/tshark integration.

**Zero dependencies required** — runs entirely on the Python standard library. Third-party packages (Flask, scapy, paramiko) can optionally be installed in a virtual environment for enhanced features.

## Features

- **Local PCAP Upload** — Upload `.pcap`, `.pcapng`, or `.cap` files and view parsed packet data in a table
- **SSH Remote Read** — Connect to a remote server via SSH and download + parse a pcap file
- **SSH Tshark** — Run `tshark` (Wireshark CLI) on a remote server and view the output directly
- **Packet Summary** — Total packets, unique sources/destinations, and protocol breakdown chart
- **Live Filtering** — Filter displayed packets by protocol, IP address, or info text
- **Dark UI** — Clean, responsive dark-themed interface

## How It Works — Two Modes

| Component    | Standard Library (default)         | With Third-Party Packages          |
|--------------|------------------------------------|------------------------------------|
| Web server   | `http.server` (built-in)           | Flask                              |
| PCAP parsing | `struct`-based binary parser       | scapy (supports pcapng)            |
| SSH / SCP    | `subprocess` + system `ssh`/`scp`  | paramiko                           |

The app auto-detects which libraries are available and uses the best backend.

## Project Structure

```
pcap_reader/
├── run.py                       # Entry point (auto-detects backends)
├── config.py                    # Configuration (used by Flask mode)
├── setup.sh                     # Setup script
├── requirements.txt             # Third-party dependencies (optional)
├── app/
│   ├── __init__.py              # Flask app factory
│   ├── routes.py                # Flask API routes
│   ├── server_stdlib.py         # Stdlib HTTP server (no Flask needed)
│   ├── static/
│   │   ├── css/style.css
│   │   └── js/app.js
│   └── templates/
│       └── index.html
└── utils/
    ├── __init__.py              # Auto-detection: picks best backend
    ├── pcap_parser.py           # PCAP parser (scapy)
    ├── pcap_parser_stdlib.py    # PCAP parser (stdlib only)
    ├── ssh_handler.py           # SSH handler (paramiko)
    └── ssh_handler_stdlib.py    # SSH handler (stdlib subprocess)
```

## Installation & Usage

### Option 1: Run with standard library only (no install needed)

```bash
git clone https://github.com/<your-username>/pcap_reader.git
cd pcap_reader

# Just run it — no pip install, no venv required
python3 run.py
```

This uses Python's built-in `http.server`, `struct`-based pcap parsing, and system `ssh`/`scp` for remote access.

### Option 2: Install third-party packages (in a virtual environment)

```bash
git clone https://github.com/<your-username>/pcap_reader.git
cd pcap_reader

# Creates venv and installs Flask, scapy, paramiko inside it
./setup.sh --install-deps

# Activate and run
source venv/bin/activate
python run.py
```

> **All third-party packages are installed inside `venv/` only, never system-wide.**

### Manual venv setup

```bash
python3 -m venv venv
source venv/bin/activate    # Linux/macOS
# venv\Scripts\activate     # Windows

pip install -r requirements.txt
python run.py
```

Open your browser at `http://localhost:5000`.

## Usage Guide

### Local File Upload

1. Click the **Local File Upload** tab
2. Select a `.pcap`, `.pcapng`, or `.cap` file
3. Click **Parse PCAP** to view the results

> Note: `.pcapng` files require scapy. The stdlib parser supports classic `.pcap` format.

### SSH - Read PCAP

1. Click the **SSH - Read PCAP** tab
2. Enter the remote server's IP/hostname, port, username, and password (or SSH key path)
3. Provide the full path to the pcap file on the remote server
4. Click **Read Remote PCAP** — the file is downloaded and parsed locally

> Without paramiko, the app uses system `ssh`/`scp` commands (must be on PATH).

### SSH - Tshark Output

1. Click the **SSH - Tshark Output** tab
2. Enter SSH connection details and the remote pcap file path
3. Optionally add a Wireshark display filter (e.g., `tcp.port == 80`)
4. Click **Run Tshark** — requires `tshark` to be installed on the remote server

## API Endpoints

| Method | Endpoint                | Description                          |
|--------|-------------------------|--------------------------------------|
| GET    | `/api/status`           | Show active backends (scapy/stdlib)  |
| POST   | `/api/upload`           | Upload and parse a local pcap file   |
| POST   | `/api/ssh/read`         | Download and parse a remote pcap     |
| POST   | `/api/ssh/tshark`       | Run tshark on a remote server        |
| POST   | `/api/ssh/check-tshark` | Check if tshark is available remotely |

## Requirements

- Python 3.8+
- For SSH features (without paramiko): OpenSSH client (`ssh`, `scp`) on PATH
- For tshark features: `tshark` (Wireshark CLI) installed on the remote server

## License

MIT

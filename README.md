# PCAP Reader

A web-based tool for reading and analyzing standard PCAP files. Supports local file uploads and remote file access via SSH, with optional Wireshark/tshark integration.

## Features

- **Local PCAP Upload** — Upload `.pcap`, `.pcapng`, or `.cap` files and view parsed packet data in a table
- **SSH Remote Read** — Connect to a remote server via SSH and download + parse a pcap file
- **SSH Tshark** — Run `tshark` (Wireshark CLI) on a remote server and view the output directly
- **Packet Summary** — Total packets, unique sources/destinations, and protocol breakdown chart
- **Live Filtering** — Filter displayed packets by protocol, IP address, or info text
- **Dark UI** — Clean, responsive dark-themed interface

## Project Structure

```
pcap_reader/
├── run.py                  # Application entry point
├── config.py               # Configuration settings
├── requirements.txt        # Python dependencies
├── app/
│   ├── __init__.py         # Flask app factory
│   ├── routes.py           # API routes and endpoints
│   ├── static/
│   │   ├── css/style.css   # Stylesheet
│   │   └── js/app.js       # Frontend JavaScript
│   └── templates/
│       └── index.html      # Main HTML template
└── utils/
    ├── __init__.py
    ├── pcap_parser.py      # PCAP file parsing with scapy
    └── ssh_handler.py      # SSH connection and tshark handling
```

## Installation

```bash
# Clone the repository
git clone https://github.com/<your-username>/pcap_reader.git
cd pcap_reader

# Create a virtual environment
python3 -m venv venv
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt
```

## Usage

```bash
python run.py
```

Open your browser at `http://localhost:5000`.

### Local File Upload

1. Click the **Local File Upload** tab
2. Select a `.pcap`, `.pcapng`, or `.cap` file
3. Click **Parse PCAP** to view the results

### SSH - Read PCAP

1. Click the **SSH - Read PCAP** tab
2. Enter the remote server's IP/hostname, port, username, and password (or SSH key path)
3. Provide the full path to the pcap file on the remote server
4. Click **Read Remote PCAP** — the file is downloaded and parsed locally

### SSH - Tshark Output

1. Click the **SSH - Tshark Output** tab
2. Enter SSH connection details and the remote pcap file path
3. Optionally add a Wireshark display filter (e.g., `tcp.port == 80`)
4. Click **Run Tshark** — requires `tshark` to be installed on the remote server

## API Endpoints

| Method | Endpoint              | Description                          |
|--------|-----------------------|--------------------------------------|
| POST   | `/api/upload`         | Upload and parse a local pcap file   |
| POST   | `/api/ssh/read`       | Download and parse a remote pcap     |
| POST   | `/api/ssh/tshark`     | Run tshark on a remote server        |
| POST   | `/api/ssh/check-tshark` | Check if tshark is available remotely |

## Requirements

- Python 3.8+
- For tshark features: `tshark` (Wireshark CLI) installed on the remote server

## License

MIT

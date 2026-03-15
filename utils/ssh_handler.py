"""SSH handler for remote pcap file operations."""

import os
import tempfile

import paramiko


class SSHHandler:
    """Manage SSH connections to remote servers for pcap operations."""

    def __init__(self, hostname, username, password=None, key_path=None, port=22):
        self.hostname = hostname
        self.username = username
        self.password = password
        self.key_path = key_path
        self.port = port
        self.client = None

    def connect(self):
        """Establish SSH connection."""
        self.client = paramiko.SSHClient()
        self.client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

        connect_kwargs = {
            "hostname": self.hostname,
            "port": self.port,
            "username": self.username,
        }

        if self.key_path and os.path.isfile(self.key_path):
            connect_kwargs["key_filename"] = self.key_path
        elif self.password:
            connect_kwargs["password"] = self.password
        else:
            raise ValueError("Either password or SSH key path is required")

        self.client.connect(**connect_kwargs)

    def download_pcap(self, remote_path, local_dir):
        """Download a pcap file from the remote server."""
        if not self.client:
            raise RuntimeError("Not connected. Call connect() first.")

        filename = os.path.basename(remote_path)
        local_path = os.path.join(local_dir, f"remote_{filename}")

        sftp = self.client.open_sftp()
        try:
            sftp.stat(remote_path)
            sftp.get(remote_path, local_path)
        finally:
            sftp.close()

        return local_path

    def run_tshark(self, remote_pcap_path, display_filter=None, decode_as=None, max_packets=1000):
        """Run tshark on the remote server and return output."""
        if not self.client:
            raise RuntimeError("Not connected. Call connect() first.")

        # Check if tshark is available
        _, stdout, stderr = self.client.exec_command("which tshark")
        tshark_path = stdout.read().decode().strip()
        if not tshark_path:
            raise FileNotFoundError(
                "tshark is not installed on the remote server. "
                "Install wireshark-cli/tshark to use this feature."
            )

        # Build tshark command
        cmd = f"{tshark_path} -r {remote_pcap_path} -c {max_packets}"

        if display_filter:
            # Sanitize display filter to prevent injection
            safe_filter = display_filter.replace("'", "'\\''")
            cmd += f" -Y '{safe_filter}'"

        if decode_as:
            safe_decode = decode_as.replace("'", "'\\''")
            cmd += f" -d '{safe_decode}'"

        _, stdout, stderr = self.client.exec_command(cmd, timeout=30)
        output = stdout.read().decode()
        errors = stderr.read().decode()

        return {
            "output": output,
            "errors": errors,
            "command": cmd,
        }

    def check_tshark_available(self):
        """Check if tshark is installed on the remote server."""
        if not self.client:
            raise RuntimeError("Not connected. Call connect() first.")

        _, stdout, _ = self.client.exec_command("which tshark")
        return bool(stdout.read().decode().strip())

    def close(self):
        """Close SSH connection."""
        if self.client:
            self.client.close()
            self.client = None

    def __enter__(self):
        self.connect()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()

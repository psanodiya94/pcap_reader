"""SSH handler for remote pcap file operations."""

from __future__ import annotations

import os
from typing import Any, Self

import paramiko


class SSHHandler:
    """Manage SSH connections to remote servers for pcap operations."""

    def __init__(
        self,
        hostname: str,
        username: str,
        password: str | None = None,
        key_path: str | None = None,
        port: int = 22,
    ) -> None:
        self.hostname = hostname
        self.username = username
        self.password = password
        self.key_path = key_path
        self.port = port
        self.client: paramiko.SSHClient | None = None

    def connect(self) -> None:
        """Establish SSH connection."""
        self.client = paramiko.SSHClient()
        self.client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

        connect_kwargs: dict[str, Any] = {
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

    def download_pcap(self, remote_path: str, local_dir: str) -> str:
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

    def run_tshark(
        self,
        remote_pcap_path: str,
        display_filter: str | None = None,
        decode_as: str | None = None,
        max_packets: int = 1000,
    ) -> dict[str, str]:
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

    def check_tshark_available(self) -> bool:
        """Check if tshark is installed on the remote server."""
        if not self.client:
            raise RuntimeError("Not connected. Call connect() first.")

        _, stdout, _ = self.client.exec_command("which tshark")
        return bool(stdout.read().decode().strip())

    def close(self) -> None:
        """Close SSH connection."""
        if self.client:
            self.client.close()
            self.client = None

    def __enter__(self) -> Self:
        self.connect()
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc_val: BaseException | None,
        exc_tb: Any,
    ) -> None:
        self.close()

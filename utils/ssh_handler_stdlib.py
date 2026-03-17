"""SSH handler using only Python standard library (subprocess + system ssh/scp)."""

from __future__ import annotations

import os
import shutil
import subprocess
from typing import Any, Self


class SSHHandlerStdlib:
    """Manage SSH operations using the system ssh/scp commands."""

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

        # Verify ssh is available on the system
        if not shutil.which("ssh"):
            raise FileNotFoundError(
                "ssh command not found on this system. "
                "Install OpenSSH or install paramiko: pip install paramiko"
            )

    def _build_ssh_opts(self) -> list[str]:
        """Build common SSH options."""
        opts = [
            "-o", "StrictHostKeyChecking=no",
            "-o", "BatchMode=yes",
            "-p", str(self.port),
        ]
        if self.key_path and os.path.isfile(self.key_path):
            opts += ["-i", self.key_path]
        return opts

    def _build_scp_opts(self) -> list[str]:
        """Build common SCP options."""
        opts = [
            "-o", "StrictHostKeyChecking=no",
            "-o", "BatchMode=yes",
            "-P", str(self.port),
        ]
        if self.key_path and os.path.isfile(self.key_path):
            opts += ["-i", self.key_path]
        return opts

    def _remote_target(self) -> str:
        return f"{self.username}@{self.hostname}"

    def connect(self) -> None:
        """Test SSH connectivity."""
        cmd = ["ssh", *self._build_ssh_opts(), self._remote_target(), "echo", "ok"]
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=15)
        if result.returncode != 0:
            raise ConnectionError(
                f"SSH connection failed: {result.stderr.strip()}"
            )

    def download_pcap(self, remote_path: str, local_dir: str) -> str:
        """Download a pcap file from the remote server using scp."""
        if not shutil.which("scp"):
            raise FileNotFoundError(
                "scp command not found. Install OpenSSH or install paramiko."
            )

        filename = os.path.basename(remote_path)
        local_path = os.path.join(local_dir, f"remote_{filename}")

        cmd = [
            "scp", *self._build_scp_opts(),
            f"{self._remote_target()}:{remote_path}",
            local_path,
        ]
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)

        if result.returncode != 0:
            error = result.stderr.strip()
            if "No such file" in error or "not found" in error.lower():
                raise FileNotFoundError(f"Remote file not found: {remote_path}")
            raise RuntimeError(f"SCP download failed: {error}")

        return local_path

    def run_tshark(
        self,
        remote_pcap_path: str,
        display_filter: str | None = None,
        decode_as: str | None = None,
        max_packets: int = 1000,
    ) -> dict[str, str]:
        """Run tshark on the remote server via SSH."""
        # Build the remote tshark command
        remote_cmd = f"tshark -r {remote_pcap_path} -c {max_packets}"

        if display_filter:
            safe_filter = display_filter.replace("'", "'\\''")
            remote_cmd += f" -Y '{safe_filter}'"

        if decode_as:
            safe_decode = decode_as.replace("'", "'\\''")
            remote_cmd += f" -d '{safe_decode}'"

        cmd = ["ssh", *self._build_ssh_opts(), self._remote_target(), remote_cmd]
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)

        return {
            "output": result.stdout,
            "errors": result.stderr,
            "command": remote_cmd,
        }

    def check_tshark_available(self) -> bool:
        """Check if tshark is installed on the remote server."""
        cmd = ["ssh", *self._build_ssh_opts(), self._remote_target(), "which", "tshark"]
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=15)
        return result.returncode == 0 and bool(result.stdout.strip())

    def close(self) -> None:
        """No-op for subprocess-based handler."""

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

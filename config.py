from __future__ import annotations

import os
from pathlib import Path


class Config:
    SECRET_KEY: str = os.environ.get("SECRET_KEY", os.urandom(24).hex())
    UPLOAD_FOLDER: str = str(Path(__file__).resolve().parent / "uploads")
    MAX_CONTENT_LENGTH: int = 50 * 1024 * 1024  # 50 MB max upload
    ALLOWED_EXTENSIONS: set[str] = {"pcap", "pcapng", "cap"}

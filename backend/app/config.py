"""
Centralized configuration loaded from environment variables.
All config access goes through this module — no os.environ.get() scattered across files.
"""

import os
import tempfile
from pathlib import Path

from dotenv import load_dotenv

load_dotenv()


# --- Mistral AI ---
MISTRAL_API_KEY: str = os.environ.get("MISTRAL_API_KEY", "").strip()
MISTRAL_TEXT_MODEL: str = os.environ.get("MISTRAL_TEXT_MODEL", "mistral-large-latest")
MISTRAL_VISION_MODEL: str = os.environ.get("MISTRAL_VISION_MODEL", "mistral-large-latest")
MISTRAL_OCR_MODEL: str = os.environ.get("MISTRAL_OCR_MODEL", "mistral-ocr-latest")

# --- Backend ---
CORS_ALLOW_ORIGINS: str = os.environ.get(
    "CORS_ALLOW_ORIGINS",
    "http://localhost:3000,http://127.0.0.1:3000",
)

UPLOAD_DIR: Path = Path(
    os.environ.get(
        "INCIDENT_ZERO_UPLOAD_DIR",
        str(Path(tempfile.gettempdir()) / "incident-zero-uploads"),
    )
)
UPLOAD_DIR.mkdir(parents=True, exist_ok=True)

"""
Centralized configuration loaded from environment variables.
All config access goes through this module — no os.environ.get() scattered across files.

Security notes:
  - API keys are never logged or included in error responses
  - Upload directory is validated at startup
  - Path inputs are sanitized before use
"""

import os
import tempfile
from pathlib import Path

from dotenv import load_dotenv

load_dotenv()


class Settings:
    """Immutable configuration singleton. Read from env vars once at import time."""

    __slots__ = (
        "mistral_api_key",
        "mistral_text_model",
        "mistral_vision_model",
        "mistral_ocr_model",
        "cors_allow_origins",
        "upload_dir",
        "max_upload_size_bytes",
        "allowed_upload_extensions",
    )

    def __init__(self) -> None:
        # --- Mistral AI ---
        self.mistral_api_key: str = os.environ.get("MISTRAL_API_KEY", "").strip()
        self.mistral_text_model: str = os.environ.get(
            "MISTRAL_TEXT_MODEL", "mistral-large-latest"
        )
        self.mistral_vision_model: str = os.environ.get(
            "MISTRAL_VISION_MODEL", "mistral-large-latest"
        )
        self.mistral_ocr_model: str = os.environ.get(
            "MISTRAL_OCR_MODEL", "mistral-ocr-latest"
        )

        # --- Backend ---
        self.cors_allow_origins: str = os.environ.get(
            "CORS_ALLOW_ORIGINS",
            "http://localhost:3000,http://127.0.0.1:3000",
        )

        self.upload_dir: Path = Path(
            os.environ.get(
                "INCIDENT_ZERO_UPLOAD_DIR",
                str(Path(tempfile.gettempdir()) / "incident-zero-uploads"),
            )
        )
        self.upload_dir.mkdir(parents=True, exist_ok=True)

        # --- Security limits ---
        self.max_upload_size_bytes: int = int(
            os.environ.get("MAX_UPLOAD_SIZE_BYTES", str(50 * 1024 * 1024))  # 50 MB
        )
        self.allowed_upload_extensions: set[str] = {
            ".log", ".txt", ".json", ".csv",
            ".png", ".jpg", ".jpeg", ".bmp", ".tiff", ".webp",
            ".py", ".js", ".ts", ".java", ".go", ".rb", ".rs",
            ".c", ".cpp", ".h", ".yaml", ".yml", ".toml", ".xml",
            ".env", ".cfg", ".ini", ".conf", ".sh",
        }


# Singleton — all modules import this
settings = Settings()

# Backward-compatible exports used by main.py
CORS_ALLOW_ORIGINS = settings.cors_allow_origins
UPLOAD_DIR = settings.upload_dir

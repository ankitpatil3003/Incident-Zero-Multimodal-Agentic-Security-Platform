# Clean Python file — should produce zero findings.

import os


def get_config():
    """Read config from environment variables (the safe way)."""
    return {
        "api_key": os.environ.get("API_KEY", ""),
        "db_host": os.environ.get("DB_HOST", "localhost"),
    }


def compute(x: int, y: int) -> int:
    return x + y

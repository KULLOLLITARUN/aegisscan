"""
Safe configuration loader module using standard library JSON parsing and env vars.
"""

import json
import os
from pathlib import Path
from typing import Any, Dict


class ConfigLoader:
    """Safe application configuration loader."""

    def __init__(self, config_path: str) -> None:
        self.config_path = Path(config_path)

    def load_json(self) -> Dict[str, Any]:
        """Load and parse JSON config file safely."""
        if not self.config_path.is_file():
            return {}
        try:
            with open(self.config_path, "r", encoding="utf-8") as f:
                data = json.load(f)
                return data if isinstance(data, dict) else {}
        except (json.JSONDecodeError, OSError):
            return {}

    @staticmethod
    def get_env_var(key: str, default: str = "") -> str:
        """Safely fetch environment variable."""
        return os.environ.get(key, default)

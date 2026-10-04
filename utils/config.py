"""Configuration loader.

Reads settings from a local config.json (optional) and environment variables.
The VirusTotal API key is read from the VT_API_KEY environment variable or
from an optional config.json file which is NOT committed to the repo.
"""

import json
import os
from pathlib import Path

DEFAULT_VT_URL = "https://www.virustotal.com/api/v3/"
DEFAULT_TIMEOUT = 20  # seconds
PLACEHOLDER_KEYS = {"YOUR_VIRUSTOTAL_API_KEY", "REPLACE_ME", "changeme"}


class Settings:
    def __init__(self):
        self.config_path = Path(__file__).parent.parent / "config.json"
        self._data = {}
        self._load_file()
        self.vt_api_key = os.environ.get("VT_API_KEY", "") or self._data.get("vt_api_key", "")
        if self.vt_api_key.strip().lower() in PLACEHOLDER_KEYS or "your_" in self.vt_api_key.lower():
            self.vt_api_key = ""
        self.vt_api_url = os.environ.get(
            "VT_API_URL", self._data.get("vt_api_url", DEFAULT_VT_URL)
        )
        self.vt_timeout = int(os.environ.get(
            "VT_TIMEOUT", self._data.get("vt_timeout", DEFAULT_TIMEOUT)
        ))

    def _load_file(self):
        if self.config_path.exists():
            try:
                self._data = json.loads(self.config_path.read_text(encoding="utf-8"))
            except (json.JSONDecodeError, OSError):
                self._data = {}

    @property
    def vt_enabled(self) -> bool:
        return bool(self.vt_api_key.strip())

    def save_config_hint(self) -> str:
        """Return a hint for the user on how to configure the API key."""
        if self.vt_enabled:
            return ""

        template_path = Path(__file__).parent.parent / "config.json"
        message = (
            "VirusTotal integration is disabled. Set the environment variable "
            "VT_API_KEY or create config.json "
        )
        if not template_path.exists():
            try:
                template_path.write_text(
                    json.dumps({"vt_api_key": "YOUR_VIRUSTOTAL_API_KEY"}, indent=2)
                    + "\n",
                    encoding="utf-8",
                )
                message += f"(sample created at {template_path.name})"
            except OSError:
                pass
        else:
            message += f"({template_path.name} already exists)"
        return message


settings = Settings()
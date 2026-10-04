import hashlib
import os
import re
from pathlib import Path


class StaticAnalyzer:
    """Phase 1: Static analysis - file info, strings, and hashes."""

    def __init__(self, file_path):
        self.file_path = Path(file_path)
        self.file_size = self.file_path.stat().st_size if self.file_path.exists() else 0
        self.data = self._read_file()

    def _read_file(self):
        """Read file bytes (limit to first 1MB for large files)."""
        with open(self.file_path, "rb") as f:
            return f.read()

    def get_basic_info(self):
        """Return basic file information."""
        return {
            "filename": self.file_path.name,
            "size_bytes": self.file_size,
            "size_human": self._format_bytes(self.file_size),
            "extension": self.file_path.suffix or "No extension",
            "last_modified": self._format_timestamp(self.file_path.stat().st_mtime),
        }

    def get_hashes(self):
        """Calculate MD5, SHA1, SHA256 hashes."""
        md5 = hashlib.md5(self.data).hexdigest()
        sha1 = hashlib.sha1(self.data).hexdigest()
        sha256 = hashlib.sha256(self.data).hexdigest()

        return {
            "md5": md5,
            "sha1": sha1,
            "sha256": sha256,
        }

    def extract_strings(self, min_length=4, max_results=200):
        """Extract readable strings from binary data."""
        strings = []
        pattern = re.compile(rb"[\x20-\x7e]{%d,}" % min_length)

        for match in pattern.finditer(self.data):
            string = match.group().decode("ascii", errors="ignore")
            if len(string.strip()) > 0:
                strings.append(string)
            if len(strings) >= max_results:
                break

        return strings

    def extract_urls(self):
        """Extract URLs from strings."""
        strings = self.extract_strings(min_length=4, max_results=500)
        pattern = re.compile(
            r"https?://[^\s<>\"']+|(?:ftp|ftps)://[^\s<>\"']+", re.IGNORECASE
        )
        urls = set()
        for s in strings:
            for match in pattern.findall(s):
                urls.add(match)
        return sorted(urls)

    def extract_ips(self):
        """Extract IP addresses from strings."""
        strings = self.extract_strings(min_length=7, max_results=500)
        pattern = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
        ips = set()
        for s in strings:
            for match in pattern.findall(s):
                if self._is_valid_ip(match):
                    ips.add(match)
        return sorted(ips)

    def extract_commands(self):
        """Extract suspicious shell commands indicators."""
        strings = self.extract_strings(min_length=4, max_results=500)
        cmd_indicators = [
            "powershell",
            "cmd",
            "wscript",
            "cscript",
            "rundll32",
            "reg add",
            "schtasks",
            "whoami",
            "net user",
            "net localgroup",
            "vssadmin",
            "wmic",
            "certutil",
            "bitsadmin",
            "curl",
            "wget",
            "taskkill",
        ]
        commands = set()
        for s in strings:
            lower = s.lower()
            for indicator in cmd_indicators:
                if indicator in lower:
                    commands.add(indicator)
        return sorted(commands)

    def get_entropy(self):
        """Calculate Shannon entropy of the file content."""
        if not self.data:
            return 0.0
        import math

        entropy = 0.0
        for x in range(256):
            p_x = self.data.count(x) / len(self.data)
            if p_x > 0:
                entropy += -p_x * math.log2(p_x)
        return round(entropy, 4)

    @staticmethod
    def _format_bytes(num):
        """Format bytes to human-readable size."""
        for unit in ["B", "KB", "MB", "GB"]:
            if num < 1024.0:
                return f"{num:.2f} {unit}"
            num /= 1024.0
        return f"{num:.2f} TB"

    @staticmethod
    def _format_timestamp(ts):
        import datetime

        return datetime.datetime.fromtimestamp(ts).strftime("%Y-%m-%d %H:%M:%S")

    @staticmethod
    def _is_valid_ip(ip):
        """Validate IP address format."""
        try:
            parts = ip.split(".")
            if len(parts) != 4:
                return False
            for p in parts:
                if not p.isdigit() or not 0 <= int(p) <= 255:
                    return False
            return True
        except ValueError:
            return False

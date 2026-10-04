"""VirusTotal API v3 client for hash lookups and file scanning.

The real API call is only made when an API key is configured; otherwise the
module degrades gracefully so MalwareLens still works fully offline.
"""

import base64
import json
import time
import urllib.error
import urllib.parse
import urllib.request

from utils.config import settings


class VirusTotalError(Exception):
    """Raised for VirusTotal API failures."""


class VirusTotal:
    def __init__(self, api_key=None):
        self.api_key = (api_key or settings.vt_api_key).strip()
        self.api_url = settings.vt_api_url.rstrip("/") + "/"
        self.timeout = settings.vt_timeout
        self.enabled = bool(self.api_key)

    def _headers(self, extra=None):
        headers = {"x-apikey": self.api_key, "Accept": "application/json"}
        if extra:
            headers.update(extra)
        return headers

    def _request(self, path, method="GET", data=None):
        if not self.enabled:
            raise VirusTotalError("No VirusTotal API key configured")

        url = self.api_url + path
        req = urllib.request.Request(url, headers=self._headers(), method=method)
        if data is not None:
            body = json.dumps(data).encode("utf-8")
            req.add_header("Content-Type", "application/json")
            req.data = body

        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                return json.loads(resp.read().decode("utf-8"))
        except urllib.error.HTTPError as e:
            detail = ""
            try:
                detail = e.read().decode("utf-8")[:300]
            except Exception:
                pass
            if e.code == 404:
                raise VirusTotalError("File not found in VirusTotal database") from e
            if e.code == 401:
                raise VirusTotalError("Invalid VirusTotal API key") from e
            if e.code == 409:
                raise VirusTotalError("Daily quota exceeded") from e
            raise VirusTotalError(f"HTTP {e.code}: {detail}") from e
        except urllib.error.URLError as e:
            raise VirusTotalError(f"Network error: {e.reason}") from e

    def file_report(self, file_hash):
        """Look up a file hash (sha256/sha1/md5) in VirusTotal."""
        return self._request(f"files/{file_hash}")

    def analyze_file_hash(self, file_hash):
        """Fetch and normalize a file intelligence report."""
        if not self.enabled:
            return None
        try:
            raw = self.file_report(file_hash)
        except VirusTotalError as e:
            return {"error": str(e), "found": False}

        data = raw.get("data", {})
        attributes = data.get("attributes", {})

        stats = attributes.get("last_analysis_stats", {})
        results_map = attributes.get("last_analysis_results", {})

        vendors = []
        for engine, result in results_map.items():
            category = result.get("category")
            if category in ("malicious", "suspicious"):
                vendors.append({
                    "engine": engine,
                    "category": category,
                    "result": result.get("result") or result.get("detail") or "",
                })

        tags = attributes.get("tags", [])

        return {
            "found": True,
            "detections": int(stats.get("malicious", 0)),
            "suspicious": int(stats.get("suspicious", 0)),
            "harmless": int(stats.get("harmless", 0)),
            "undetected": int(stats.get("undetected", 0)),
            "total_engines": (
                int(stats.get("malicious", 0))
                + int(stats.get("suspicious", 0))
                + int(stats.get("harmless", 0))
                + int(stats.get("undetected", 0))
                + int(stats.get("type-unsupported", 0))
            ),
            "malicious_vendors": vendors[:30],
            "tags": tags,
            "meaningful_name": attributes.get("meaningful_name"),
            "reputation": attributes.get("reputation"),
            "last_submission": attributes.get("last_submission_date"),
            "first_submission": attributes.get("first_submission_date"),
        }

    def upload_file(self, file_path, filename=None):
        """Upload a file for async scanning."""
        if not self.enabled:
            raise VirusTotalError("No VirusTotal API key configured")

        boundary = "----MLBoundary" + str(int(time.time() * 1000))
        with open(file_path, "rb") as f:
            data = f.read()
        file_name = urllib.parse.quote(filename or file_path.name)
        body_parts = [
            f"--{boundary}\r\n".encode(),
            b'Content-Disposition: form-data; name="file"; filename="',
            file_name.encode(),
            b'"\r\nContent-Type: application/octet-stream\r\n\r\n',
            data,
            b"\r\n",
            f"--{boundary}--\r\n".encode(),
        ]
        body = b"".join(body_parts)

        req = urllib.request.Request(
            self.api_url + "files",
            data=body,
            headers=self._headers({"Content-Type": f"multipart/form-data; boundary={boundary}"}),
            method="POST",
        )
        try:
            with urllib.request.urlopen(req, timeout=max(self.timeout, 120)) as resp:
                return json.loads(resp.read().decode("utf-8"))
        except urllib.error.HTTPError as e:
            raise VirusTotalError(f"Upload failed (HTTP {e.code})") from e

    @staticmethod
    def public_analysis_url(file_hash):
        """Return the public VirusTotal analysis page URL for a hash."""
        return f"https://www.virustotal.com/gui/file/{file_hash}"

    def analyze_url(self, url):
        """Check a URL against VirusTotal."""
        try:
            url_id = base64.urlsafe_b64encode(url.encode("utf-8")).decode("utf-8").rstrip("=")
            raw = self._request(f"urls/{url_id}")
        except VirusTotalError as e:
            return {"error": str(e), "found": False}

        attributes = raw.get("data", {}).get("attributes", {})
        stats = attributes.get("last_analysis_stats", {})
        return {
            "found": True,
            "detections": int(stats.get("malicious", 0)),
            "total_engines": int(stats.get("harmless", 0)) + int(stats.get("malicious", 0)),
        }


def enrich_with_virustotal(hashes):
    """Enrich analysis results with VirusTotal lookups for the file hashes."""
    vt = VirusTotal()
    if not vt.enabled:
        return {
            "enabled": False,
            "message": settings.save_config_hint(),
            "file": None,
            "urls": [],
        }

    file_result = None
    if hashes and hashes.get("sha256"):
        file_result = vt.analyze_file_hash(hashes["sha256"])

    return {
        "enabled": True,
        "message": "",
        "file": file_result,
        "urls": [],
    }
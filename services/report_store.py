"""Persistence of analysis reports and the history listing.

Each analysis is snapshotted to a JSON file so reports can be re-rendered and
re-downloaded independently of the original upload (which is temporary).
"""

import json
import uuid
from datetime import datetime
from pathlib import Path


class ReportStoreError(Exception):
    """Raised when a report cannot be stored or read."""


class ReportStore:
    def __init__(self, folder, max_reports=20):
        self.folder = Path(folder)
        self.folder.mkdir(exist_ok=True)
        self.max_reports = max_reports

    # ----- private helpers -----

    def _path(self, report_id):
        return self.folder / f"report_{report_id}.json"

    @staticmethod
    def _safe_unlink(path):
        try:
            if path.exists():
                path.unlink()
        except (PermissionError, OSError):
            pass

    # ----- public API -----

    def save(self, result, user_id=None):
        """Persist an analysis result; returns a short alphanumeric id.

        A small ``_meta`` block (owner id + timestamp) is stored alongside the
        report so history and reports can be scoped to the owning account.
        """
        report_id = uuid.uuid4().hex[:16]
        stored = dict(result)
        stored["_meta"] = {
            "user_id": user_id,
            "created_at": datetime.utcnow().isoformat(),
        }
        path = self._path(report_id)
        try:
            path.write_text(json.dumps(stored, indent=2, default=str), encoding="utf-8")
        except OSError as e:
            raise ReportStoreError(f"Could not store report: {e}") from e
        self.prune()
        return report_id

    def load(self, report_id):
        """Load a stored analysis result dict, or None if missing/invalid."""
        if not report_id or not report_id.isalnum():
            return None
        path = self._path(report_id)
        if not path.exists():
            return None
        try:
            return json.loads(path.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError):
            return None

    def list_summaries(self, user_id=None):
        """Return summaries of stored reports, newest first.

        When ``user_id`` is given only reports owned by that account are
        returned.
        """
        entries = []
        for report_file in self.folder.glob("report_*.json"):
            report_id = report_file.stem.replace("report_", "")
            try:
                result = json.loads(report_file.read_text(encoding="utf-8"))
            except (json.JSONDecodeError, OSError):
                continue

            owner = (result.get("_meta") or {}).get("user_id")
            if user_id is not None and owner != user_id:
                continue

            info = result.get("info", {})
            hashes = result.get("hashes", {})
            risk = result.get("risk", {})
            vt = result.get("virustotal") or {}

            vt_line = None
            vt_file = vt.get("file")
            if vt.get("enabled") and vt_file and vt_file.get("found"):
                vt_line = {
                    "detections": vt_file.get("detections", 0),
                    "total_engines": vt_file.get("total_engines", 0),
                }
            elif not vt.get("enabled"):
                vt_line = {"disabled": True}

            mtime = datetime.fromtimestamp(report_file.stat().st_mtime)

            entries.append({
                "report_id": report_id,
                "owner_id": owner,
                "filename": info.get("filename", "Unknown"),
                "size_human": info.get("size_human", "?"),
                "md5": hashes.get("md5", ""),
                "sha256": hashes.get("sha256", ""),
                "risk_score": risk.get("score", 0),
                "risk_level": risk.get("level", "UNKNOWN"),
                "risk_color": risk.get("color", "green"),
                "analyzed_at": mtime,
                "analyzed_at_iso": mtime.strftime("%Y-%m-%d %H:%M:%S"),
                "vt": vt_line,
            })

        entries.sort(key=lambda e: e["analyzed_at"], reverse=True)
        return entries

    def prune(self):
        """Delete the oldest reports when the store exceeds max_reports."""
        reports = sorted(
            self.folder.glob("report_*.json"),
            key=lambda p: p.stat().st_mtime,
        )
        for old in reports[: max(0, len(reports) - self.max_reports)]:
            self._safe_unlink(old)

    def delete_user_reports(self, user_id):
        """Delete every stored report owned by the given account; returns count."""
        removed = 0
        for report_file in self.folder.glob("report_*.json"):
            try:
                result = json.loads(report_file.read_text(encoding="utf-8"))
            except (json.JSONDecodeError, OSError):
                continue
            if (result.get("_meta") or {}).get("user_id") == user_id:
                self._safe_unlink(report_file)
                removed += 1
        return removed

    def delete_report(self, report_id):
        """Delete a single stored report by id; returns True when removed."""
        if not report_id or not report_id.isalnum():
            return False
        path = self._path(report_id)
        if not path.exists():
            return False
        self._safe_unlink(path)
        return True
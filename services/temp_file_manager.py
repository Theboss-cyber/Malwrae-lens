"""Lifecycle management for temporary files created during uploads."""

from pathlib import Path


class TempFileManager:
    """Tracks temporary files and purges them on a first-in-first-out basis.

    Submissions and crypto operations produce plaintext/ciphertext copies and
    report snapshots in the workspace. This manager caps how many may exist at
    once and removes the oldest when the cap is exceeded, or on explicit
    cleanup.
    """

    def __init__(self):
        self._files = []

    def add(self, path):
        self._files.append(Path(path))

    def trim(self, max_entries):
        """Remove the oldest tracked files until at most `max_entries` remain."""
        while len(self._files) > max_entries:
            old = self._files.pop(0)
            self._safe_unlink(old)

    def cleanup_all(self):
        """Delete every tracked temp file and clear the registry."""
        for path in self._files:
            self._safe_unlink(path)
        self._files.clear()

    @staticmethod
    def _safe_unlink(path):
        try:
            if path.exists():
                path.unlink()
        except (PermissionError, OSError):
            pass
"""Orchestration of the AES-256-GCM encryption/decryption tool.

Encapsulates the file-ops around :mod:`utils.crypto_tool`: staging uploads,
choosing non-colliding output names, deleting plaintext/ciphertext copies once
an operation finishes, and cleaning up both artifacts when a run fails.
"""

from pathlib import Path

from utils.crypto_tool import CryptoError, decrypt_file, encrypt_file

from services.files import unique_path

ENCRYPTED_SUFFIX = ".mlenc"
DECRYPTED_PREFIX = "decrypted_"
DECRYPTED_SUFFIX = ".restored"


class CryptoServiceError(Exception):
    """Raised for crypto workflow failures (input validation or operation)."""


class CryptoService:
    def __init__(self, workspace):
        self.workspace = Path(workspace)
        self.workspace.mkdir(exist_ok=True)

    # ----- staging -----

    def stage_upload(self, filename):
        """Copy an uploaded file into the workspace under a unique name."""
        return unique_path(self.workspace, f"crypto_{filename}")

    # ----- operations -----

    def encrypt(self, input_path, password):
        """Encrypt a staged file in place; returns the display result dict."""
        input_path = Path(input_path)
        output_path = input_path.with_suffix(ENCRYPTED_SUFFIX)
        try:
            info = encrypt_file(str(input_path), str(output_path), password)
        except CryptoError as e:
            self._cleanup_on_error(input_path, output_path)
            raise CryptoServiceError(str(e)) from e

        self._safe_unlink(input_path)  # plaintext copy no longer needed
        return {
            "action": "encrypt",
            "title": "File Encrypted Successfully",
            "input_name": input_path.name,
            "output_name": output_path.name,
            "original_size": info["original_size"],
            "output_size": info["output_size"],
            "salt": info["salt"],
            "nonce": info["nonce"],
            "tag": info["tag"],
            "iterations": info["iterations"],
            "message": (
                "Your file was encrypted with AES-256-GCM. "
                "The original file stays on the server temporarily and will be cleaned up."
            ),
        }

    def decrypt(self, input_path, password):
        """Decrypt a staged .mlenc file; returns the display result dict."""
        input_path = Path(input_path)
        if input_path.suffix.lower() != ENCRYPTED_SUFFIX:
            raise CryptoServiceError(
                "File must have .mlenc extension (encrypted by MalwareLens). "
                "The file header was checked - see warning below if it isn't valid."
            )

        output_path = unique_path(
            self.workspace,
            f"{DECRYPTED_PREFIX}{input_path.stem}{DECRYPTED_SUFFIX}",
        )
        try:
            info = decrypt_file(str(input_path), str(output_path), password)
        except CryptoError as e:
            self._cleanup_on_error(input_path, output_path)
            raise CryptoServiceError(str(e)) from e

        self._safe_unlink(input_path)  # ciphertext copy no longer needed
        return {
            "action": "decrypt",
            "title": "File Decrypted Successfully",
            "input_name": input_path.name,
            "output_name": output_path.name,
            "original_size": info["original_size"],
            "output_size": info["output_size"],
            "iterations": info["iterations"],
            "message": (
                "The file was decrypted and authenticated successfully (GCM tag verified). "
                "The encrypted copy stays on the server temporarily."
            ),
        }

    # ----- helpers -----

    @staticmethod
    def _cleanup_on_error(*paths):
        for path in paths:
            try:
                if Path(path).exists():
                    Path(path).unlink()
            except (PermissionError, OSError):
                pass

    @staticmethod
    def _safe_unlink(path):
        try:
            if Path(path).exists():
                Path(path).unlink()
        except (PermissionError, OSError):
            pass
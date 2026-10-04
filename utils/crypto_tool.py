"""File encryption/decryption utilities using AES-256-GCM.

File format:
    "MLENC1"          6 bytes   magic
    version           1 byte    format version (1)
    iterations        4 bytes   PBKDF2 iteration count (big-endian uint32)
    salt             16 bytes   PBKDF2 salt
    nonce            12 bytes   AES-GCM nonce
    tag              16 bytes   authentication tag (stored after ciphertext)
    ciphertext       N bytes    encrypted data

Decryption verifies the GCM tag, so entering the wrong password fails
cleanly with no partial output written.
"""

import hashlib
import os
import struct

from Crypto.Cipher import AES
from Crypto.Hash import SHA256
from Crypto.Protocol.KDF import PBKDF2

MAGIC = b"MLENC1"
FORMAT_VERSION = 1
KDF_ITERATIONS = 300_000
SALT_SIZE = 16
NONCE_SIZE = 12
TAG_SIZE = 16
CHUNK_SIZE = 1_048_576  # 1 MB

# Constant-time header layout size
HEADER_SIZE = len(MAGIC) + 1 + 4 + SALT_SIZE + NONCE_SIZE
TOTAL_HEADER = HEADER_SIZE + TAG_SIZE  # header + tag bytes


class CryptoError(Exception):
    """Raised for encryption/decryption failures."""


def _password_bytes(password) -> bytes:
    """Normalize password input to bytes and validate it's non-empty."""
    password_bytes = password.encode("utf-8") if isinstance(password, str) else bytes(password)
    if not password_bytes:
        raise CryptoError("Password cannot be empty")
    return password_bytes


def _derive_key(password: bytes, salt: bytes, iterations: int = KDF_ITERATIONS) -> bytes:
    """Derive a 32-byte AES-256 key from the password via PBKDF2-HMAC-SHA256."""
    password_bytes = _password_bytes(password)
    return PBKDF2(password_bytes, salt, dkLen=32, count=iterations, hmac_hash_module=SHA256)


def encrypt_file(input_path: str, output_path: str, password: str) -> dict:
    """Encrypt a file with AES-256-GCM. Returns metadata about the operation."""
    _password_bytes(password)

    salt = os.urandom(SALT_SIZE)
    nonce = os.urandom(NONCE_SIZE)
    song_for_key = _derive_key(password, salt)

    try:
        cipher = AES.new(song_for_key, AES.MODE_GCM, nonce=nonce)
    except Exception as e:
        raise CryptoError(f"Failed to initialize cipher: {e}") from e

    original_size = 0
    bytes_written = 0
    with open(input_path, "rb") as src, open(output_path, "wb") as dst:
        dst.write(MAGIC)
        dst.write(bytes([FORMAT_VERSION]))
        dst.write(struct.pack(">I", KDF_ITERATIONS))
        dst.write(salt)
        dst.write(nonce)

        while True:
            chunk = src.read(CHUNK_SIZE)
            if not chunk:
                break
            original_size += len(chunk)
            encrypted = cipher.encrypt(chunk)
            dst.write(encrypted)
            bytes_written += len(encrypted)

        tag = cipher.digest()
        dst.write(tag)

    return {
        "action": "encrypt",
        "input": input_path,
        "output": output_path,
        "original_size": original_size,
        "output_size": bytes_written + TOTAL_HEADER,
        "salt": salt.hex(),
        "nonce": nonce.hex(),
        "tag": tag.hex(),
        "iterations": KDF_ITERATIONS,
    }


def decrypt_file(input_path: str, output_path: str, password: str) -> dict:
    """Decrypt an MLENC1 file. Raises CryptoError on wrong password or corrupt data."""
    _password_bytes(password)

    with open(input_path, "rb") as f:
        header = f.read(HEADER_SIZE)

    if len(header) < HEADER_SIZE:
        raise CryptoError("Invalid file: too small to be an encrypted file")
    if header[:6] != MAGIC:
        raise CryptoError("Invalid file: not a MalwareLens encrypted file (missing MLENC1 magic)")
    if header[6] != FORMAT_VERSION:
        raise CryptoError(f"Unsupported format version: {header[6]}")

    iterations = struct.unpack(">I", header[7:11])[0]
    salt = header[11:27]
    nonce = header[27:39]

    key = _derive_key(password, salt, iterations)

    total = os.path.getsize(input_path)
    data_size = total - HEADER_SIZE - TAG_SIZE
    if data_size < 0:
        raise CryptoError("Invalid file: truncated ciphertext")

    try:
        cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    except Exception as e:
        raise CryptoError(f"Failed to initialize cipher: {e}") from e

    total = os.path.getsize(input_path)
    data_size = total - HEADER_SIZE - TAG_SIZE
    if data_size < 0:
        raise CryptoError("Invalid file: truncated ciphertext")

    original_size = data_size
    try:
        with open(input_path, "rb") as src, open(output_path, "wb") as dst:
            src.seek(HEADER_SIZE)
            remaining = data_size
            while remaining > 0:
                chunk = src.read(min(CHUNK_SIZE, remaining))
                if not chunk:
                    break
                dst.write(cipher.decrypt(chunk))
                remaining -= len(chunk)
            tag = src.read(TAG_SIZE)
            if len(tag) != TAG_SIZE:
                raise CryptoError("Invalid file: missing authentication tag")
            try:
                cipher.verify(tag)
            except ValueError as e:
                raise CryptoError(
                    "WRONG PASSWORD or file was tampered/corrupted - authentication failed"
                ) from e
    except CryptoError:
        try:
            os.remove(output_path)
        except OSError:
            pass
        raise

    return {
        "action": "decrypt",
        "input": input_path,
        "output": output_path,
        "original_size": original_size,
        "output_size": original_size,
        "iterations": iterations,
    }


def verify_encrypted_file(path: str) -> dict:
    """Inspect an encrypted file header without decrypting it."""
    with open(path, "rb") as f:
        header = f.read(HEADER_SIZE)

    valid = len(header) == HEADER_SIZE and header[:6] == MAGIC
    info = {
        "is_encrypted": valid,
        "version": header[6] if valid else None,
        "iterations": struct.unpack(">I", header[7:11])[0] if valid else None,
        "salt": header[11:27].hex() if valid else None,
        "nonce": header[27:39].hex() if valid else None,
    }
    if valid:
        info["file_size"] = os.path.getsize(path)
        info["ciphertext_size"] = info["file_size"] - TOTAL_HEADER
    return info


def hash_file(path: str, algorithm: str = "sha256") -> dict:
    """Compute a file hash (sha256 / sha1 / md5)."""
    hashers = {
        "sha256": hashlib.sha256,
        "sha1": hashlib.sha1,
        "md5": hashlib.md5,
    }
    hasher = hashers.get(algorithm, hashers["sha256"])()
    size = 0
    with open(path, "rb") as f:
        while True:
            chunk = f.read(CHUNK_SIZE)
            if not chunk:
                break
            hasher.update(chunk)
            size += len(chunk)
    return {"algorithm": algorithm, "hash": hasher.hexdigest(), "size": size}
"""Filesystem helpers shared by the service layer."""

from pathlib import Path


def unique_path(directory, filename):
    """Return a path inside `directory` that does not collide with existing files.

    If the requested filename already exists, a numeric counter is appended to
    the stem (e.g. ``sample.exe`` -> ``sample_1.exe``).
    """
    directory = Path(directory)
    candidate = directory / filename
    counter = 1
    while candidate.exists():
        stem = Path(candidate).stem
        ext = Path(candidate).suffix
        candidate = directory / f"{stem}_{counter}{ext}"
        counter += 1
    return candidate
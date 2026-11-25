"""Guarded archive inspection/extraction helpers (never execute extracted content)."""
from __future__ import annotations

from pathlib import Path, PurePosixPath
import zipfile


class ArchiveLimitError(ValueError):
    pass


def _safe_member_path(root: Path, name: str) -> Path:
    normalized = name.replace("\\", "/")
    member = PurePosixPath(normalized)
    if member.is_absolute() or any(part in {"..", ""} for part in member.parts):
        raise ArchiveLimitError(f"Unsafe archive path: {name!r}")
    destination = (root / Path(*member.parts)).resolve()
    base = root.resolve()
    if destination != base and base not in destination.parents:
        raise ArchiveLimitError(f"Archive path escapes destination: {name!r}")
    return destination


def inspect_zip(path: Path, *, max_entries: int = 10000,
                max_total_uncompressed: int = 1 << 30,
                max_single_file: int = 256 << 20) -> dict:
    path = Path(path)
    with zipfile.ZipFile(path) as archive:
        entries = archive.infolist()
        if len(entries) > max_entries:
            raise ArchiveLimitError("Archive contains too many entries")
        total = 0
        files = []
        for item in entries:
            if item.is_dir():
                continue
            _safe_member_path(Path("/safe-root"), item.filename)
            if item.file_size > max_single_file:
                raise ArchiveLimitError(f"Archive member exceeds size limit: {item.filename}")
            total += item.file_size
            if total > max_total_uncompressed:
                raise ArchiveLimitError("Archive exceeds total uncompressed size limit")
            files.append({"name": item.filename, "compressed_size": item.compress_size,
                          "size": item.file_size, "crc": item.CRC})
        return {"entries": len(entries), "files": len(files),
                "uncompressed_bytes": total, "members": files}


def extract_zip_guarded(path: Path, destination: Path, **limits) -> dict:
    destination = Path(destination)
    destination.mkdir(parents=True, exist_ok=True)
    summary = inspect_zip(path, **limits)
    written = 0
    with zipfile.ZipFile(path) as archive:
        for item in archive.infolist():
            if item.is_dir():
                continue
            target = _safe_member_path(destination, item.filename)
            target.parent.mkdir(parents=True, exist_ok=True)
            with archive.open(item, "r") as src, target.open("wb") as dst:
                copied = 0
                while True:
                    chunk = src.read(1024 * 1024)
                    if not chunk:
                        break
                    copied += len(chunk)
                    if copied > item.file_size:
                        raise ArchiveLimitError("Archive member expanded beyond declared size")
                    dst.write(chunk)
            written += 1
    summary["extracted_files"] = written
    return summary

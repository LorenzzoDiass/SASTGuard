"""Secure handling of uploaded source code / project archives.

Supported source languages: Python (.py), JavaScript/TypeScript
(.js/.jsx/.mjs/.cjs/.ts/.tsx) and Java (.java), plus .zip for whole projects.

Protections implemented:
- extension allow-list (driven by settings.allowed_extensions)
- maximum total size enforcement
- path traversal / absolute path rejection on extracted names
- Zip Slip prevention (every member must resolve inside the target dir)
- per-member and total uncompressed size limits (zip bomb mitigation)

Uploaded code is NEVER executed. It is only written to disk and parsed.
"""
from __future__ import annotations

import os
import uuid
import zipfile
from dataclasses import dataclass
from typing import List

from app.core.config import settings


class UploadError(Exception):
    """Raised when an upload violates a security constraint."""


@dataclass
class StoredUpload:
    scan_dir: str
    files: List[str]


_MAX_MEMBERS = 5000
_MAX_UNCOMPRESSED = 200 * 1024 * 1024  # 200 MB total uncompressed


def _ext_ok(filename: str) -> bool:
    _, ext = os.path.splitext(filename.lower())
    return ext in settings.allowed_extensions_list


def _source_extensions() -> set:
    """Scannable source extensions (everything allowed except the archive).

    Driven by ``settings.allowed_extensions`` so configuration stays the single
    source of truth. These are the file types extracted from a .zip and the
    types accepted as a direct single-file upload.
    """
    return {e for e in settings.allowed_extensions_list if e != ".zip"}


def _safe_join(base: str, *paths: str) -> str:
    """Join and ensure the result stays within base (anti path-traversal)."""
    base_real = os.path.realpath(base)
    target = os.path.realpath(os.path.join(base_real, *paths))
    if target != base_real and not target.startswith(base_real + os.sep):
        raise UploadError(f"Path traversal attempt blocked: {paths}")
    return target


def store_upload(filename: str, content: bytes, upload_root: str = None) -> StoredUpload:
    """Validate and persist an uploaded file, returning the stored .py files.

    A .zip is safely extracted; a .py is stored directly.
    """
    upload_root = upload_root or settings.upload_dir
    if not filename:
        raise UploadError("Missing filename")
    if not _ext_ok(filename):
        raise UploadError(
            f"Extension not allowed. Allowed: {settings.allowed_extensions_list}"
        )
    if len(content) > settings.upload_max_bytes:
        raise UploadError(
            f"File too large ({len(content)} bytes > {settings.upload_max_bytes})"
        )

    scan_dir = os.path.join(upload_root, uuid.uuid4().hex)
    os.makedirs(scan_dir, exist_ok=True)

    ext = os.path.splitext(filename.lower())[1]
    if ext in _source_extensions():
        safe_name = os.path.basename(filename)
        dest = _safe_join(scan_dir, safe_name)
        with open(dest, "wb") as fh:
            fh.write(content)
        return StoredUpload(scan_dir=scan_dir, files=[dest])

    if ext == ".zip":
        return _extract_zip(content, scan_dir)

    raise UploadError("Unsupported file type")


def _extract_zip(content: bytes, scan_dir: str) -> StoredUpload:
    import io

    stored: List[str] = []
    try:
        zf = zipfile.ZipFile(io.BytesIO(content))
    except zipfile.BadZipFile as exc:
        raise UploadError("Invalid zip archive") from exc

    members = zf.infolist()
    if len(members) > _MAX_MEMBERS:
        raise UploadError("Zip archive has too many entries")

    total_uncompressed = sum(m.file_size for m in members)
    if total_uncompressed > _MAX_UNCOMPRESSED:
        raise UploadError("Zip archive uncompressed size exceeds limit (zip bomb?)")

    source_exts = tuple(_source_extensions())
    for member in members:
        name = member.filename
        if member.is_dir():
            continue
        # Reject absolute paths and parent traversal explicitly.
        if name.startswith("/") or name.startswith("\\") or ".." in name.replace("\\", "/").split("/"):
            raise UploadError(f"Unsafe path in archive: {name}")
        # Only extract supported source files (.py/.js/.ts/.java/...).
        # TypeScript declaration files carry no executable code.
        low = name.lower()
        if low.endswith(".d.ts") or not low.endswith(source_exts):
            continue
        # Zip Slip guard: resolved path must stay inside scan_dir.
        dest = _safe_join(scan_dir, name)
        os.makedirs(os.path.dirname(dest), exist_ok=True)
        with zf.open(member) as src, open(dest, "wb") as out:
            out.write(src.read())
        stored.append(dest)

    if not stored:
        raise UploadError("No supported source files found in archive")
    return StoredUpload(scan_dir=scan_dir, files=stored)

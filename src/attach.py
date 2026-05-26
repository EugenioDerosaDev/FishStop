"""
analysis/attach.py — Attachment analysis.

Responsibilities:
  - MAGIC_BYTES / CONTENT_TYPE_TO_EXT databases.
  - _identify_magic_bytes(): format detection from raw bytes.
  - analyze_attachment(): decodes base64 payload, computes hashes,
    detects extension/content-type mismatches.
"""

import base64
import hashlib
import re
from typing import Optional


# ---------------------------------------------------------------------------
# Magic bytes database (Gary Kessler / File Signatures)
# ---------------------------------------------------------------------------

MAGIC_BYTES: dict[str, list[bytes]] = {
    "pdf":  [b"%PDF"],
    "zip":  [b"PK\x03\x04", b"PK\x05\x06", b"PK\x07\x08"],
    "docx": [b"PK\x03\x04"],
    "xlsx": [b"PK\x03\x04"],
    "pptx": [b"PK\x03\x04"],
    "exe":  [b"MZ"],
    "elf":  [b"\x7fELF"],
    "png":  [b"\x89PNG\r\n\x1a\n"],
    "jpg":  [b"\xff\xd8\xff"],
    "gif":  [b"GIF87a", b"GIF89a"],
    "bmp":  [b"BM"],
    "tiff": [b"II*\x00", b"MM\x00*"],
    "rar":  [b"Rar!\x1a\x07"],
    "7z":   [b"7z\xbc\xaf\x27\x1c"],
    "gz":   [b"\x1f\x8b"],
    "bz2":  [b"BZh"],
    "doc":  [b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"],
    "xls":  [b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"],
    "ppt":  [b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"],
    "rtf":  [b"{\\rtf"],
    "html": [b"<!DOCTYPE", b"<html"],
    "xml":  [b"<?xml"],
    "js":   [],
    "bat":  [],
    "ps1":  [],
    "sh":   [b"#!/"],
}

CONTENT_TYPE_TO_EXT: dict[str, list[str]] = {
    "application/pdf":       ["pdf"],
    "application/zip":       ["zip", "docx", "xlsx", "pptx"],
    "application/msword":    ["doc"],
    "application/vnd.openxmlformats-officedocument.wordprocessingml.document": ["docx"],
    "application/vnd.ms-excel": ["xls"],
    "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet": ["xlsx"],
    "application/vnd.ms-powerpoint": ["ppt"],
    "application/vnd.openxmlformats-officedocument.presentationml.presentation": ["pptx"],
    "application/x-rar-compressed": ["rar"],
    "application/x-7z-compressed":  ["7z"],
    "application/gzip":      ["gz"],
    "application/x-bzip2":  ["bz2"],
    "application/octet-stream": [],
    "image/png":  ["png"],
    "image/jpeg": ["jpg"],
    "image/gif":  ["gif"],
    "image/bmp":  ["bmp"],
    "image/tiff": ["tiff"],
    "text/html":  ["html"],
    "text/xml":   ["xml"],
    "application/rtf": ["rtf"],
}


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _identify_magic_bytes(raw: bytes) -> Optional[str]:
    """Returns the format name identified by magic bytes, or None."""
    for fmt, signatures in MAGIC_BYTES.items():
        for sig in signatures:
            if raw.startswith(sig):
                return fmt
    return None


def _ext_from_filename(filename: str) -> Optional[str]:
    """Extract lowercase extension from filename."""
    if "." in filename:
        return filename.rsplit(".", 1)[-1].lower()
    return None


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def analyze_attachment(
    filename: str,
    content_type: str,
    encoding: str,
    raw_payload,
) -> dict:
    """
    Decodes a base64 email attachment, computes cryptographic hashes,
    identifies the true format via magic bytes, and detects
    extension / content-type mismatches.

    Returns:
      {
        "filename"               : str
        "content_type"           : str
        "encoding"               : str
        "magic_bytes_hex"        : str | None
        "magic_detected_format"  : str | None
        "extension_from_filename": str | None
        "extension_match"        : bool | None
        "anomaly"                : str | None
        "hash_md5"               : str | None
        "hash_sha1"              : str | None
        "hash_sha256"            : str | None
        "size_bytes"             : int | None
      }
    """
    entry: dict = {
        "filename":                filename,
        "content_type":            content_type,
        "encoding":                encoding,
        "magic_bytes_hex":         None,
        "magic_detected_format":   None,
        "extension_from_filename": _ext_from_filename(filename),
        "extension_match":         None,
        "anomaly":                 None,
        "hash_md5":                None,
        "hash_sha1":               None,
        "hash_sha256":             None,
        "size_bytes":              None,
    }

    if encoding == "base64" and raw_payload:
        try:
            if isinstance(raw_payload, str):
                raw_bytes = base64.b64decode(raw_payload.replace("\n", "").replace("\r", ""))
            else:
                raw_bytes = base64.b64decode(raw_payload)
            first16 = raw_bytes[:16]
            entry["magic_bytes_hex"]      = first16.hex().upper()
            entry["magic_detected_format"] = _identify_magic_bytes(raw_bytes)
            entry["size_bytes"]           = len(raw_bytes)
            entry["hash_md5"]             = hashlib.md5(raw_bytes).hexdigest()
            entry["hash_sha1"]            = hashlib.sha1(raw_bytes).hexdigest()
            entry["hash_sha256"]          = hashlib.sha256(raw_bytes).hexdigest()
        except Exception as exc:
            entry["anomaly"] = f"Base64 decode error: {exc}"
            return entry
    else:
        entry["anomaly"] = "Non-base64 attachment — raw bytes not decoded"
        return entry

    ct_base       = content_type.split(";")[0].strip().lower()
    expected_exts = CONTENT_TYPE_TO_EXT.get(ct_base, [])
    file_ext      = entry["extension_from_filename"]
    magic_fmt     = entry["magic_detected_format"]

    mismatches = []
    if file_ext and expected_exts and file_ext not in expected_exts:
        mismatches.append(
            f"Content-Type '{ct_base}' expects {expected_exts} but filename has '.{file_ext}'"
        )
    if magic_fmt and file_ext and magic_fmt != file_ext:
        zip_like = {"docx", "xlsx", "pptx", "zip"}
        if not (magic_fmt == "zip" and file_ext in zip_like):
            mismatches.append(
                f"Magic bytes identify format as '{magic_fmt}' but filename extension is '.{file_ext}'"
            )
    if magic_fmt and expected_exts and magic_fmt not in expected_exts:
        zip_like = {"docx", "xlsx", "pptx", "zip"}
        if not (magic_fmt == "zip" and bool(set(expected_exts) & zip_like)):
            mismatches.append(
                f"Magic bytes identify '{magic_fmt}' but Content-Type expects {expected_exts}"
            )

    entry["extension_match"] = len(mismatches) == 0
    entry["anomaly"] = "; ".join(mismatches) if mismatches else None
    return entry


def collect_attachments(msg) -> list[dict]:
    """
    Walks a parsed email.message object and returns analyzed attachment dicts.
    """
    results = []
    for part in msg.walk():
        ct       = part.get_content_type()
        disp     = str(part.get("Content-Disposition") or "")
        encoding = str(part.get("Content-Transfer-Encoding") or "").lower().strip()
        filename = part.get_filename() or ""
        is_attach = "attachment" in disp.lower()

        if is_attach or filename:
            raw_payload = part.get_payload(decode=False)
            results.append(analyze_attachment(
                filename=filename,
                content_type=ct,
                encoding=encoding,
                raw_payload=raw_payload,
            ))
    return results

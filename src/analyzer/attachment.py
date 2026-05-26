"""
analyzer/attachment.py — Analisi degli allegati email.

Espone:
  - analyze_attachment(...) : decodifica base64, calcola hash, verifica
                              integrità tramite magic bytes e rileva
                              discrepanze tra Content-Type ed estensione.
  - identify_magic_bytes(raw) : identifica il formato reale da firme binarie
  - ext_from_filename(name)   : estrae l'estensione da un filename
"""

import base64
import hashlib
from typing import Optional

from .constants import MAGIC_BYTES, CONTENT_TYPE_TO_EXT


def identify_magic_bytes(raw: bytes) -> Optional[str]:
    """Restituisce il nome del formato identificato dai magic bytes, o None."""
    for fmt, signatures in MAGIC_BYTES.items():
        for sig in signatures:
            if raw.startswith(sig):
                return fmt
    return None


def ext_from_filename(filename: str) -> Optional[str]:
    """Estrae l'estensione lowercase dal filename."""
    if "." in filename:
        return filename.rsplit(".", 1)[-1].lower()
    return None


def analyze_attachment(
    filename: str,
    content_type: str,
    encoding: str,
    raw_payload,
) -> dict:
    """
    Analizza un allegato email decodificandolo dal base64, calcolandone
    gli hash crittografici e verificando la coerenza tra magic bytes,
    estensione del filename e Content-Type dichiarato.

    Returns
    -------
    {
      "filename"                 : str
      "content_type"             : str
      "encoding"                 : str
      "magic_bytes_hex"          : str | None
      "magic_detected_format"    : str | None
      "extension_from_filename"  : str | None
      "extension_match"          : bool | None
      "anomaly"                  : str | None
      "hash_md5"                 : str | None
      "hash_sha1"                : str | None
      "hash_sha256"              : str | None
      "size_bytes"               : int | None
    }
    """
    entry: dict = {
        "filename":                filename,
        "content_type":            content_type,
        "encoding":                encoding,
        "magic_bytes_hex":         None,
        "magic_detected_format":   None,
        "extension_from_filename": ext_from_filename(filename),
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
            entry["magic_bytes_hex"]       = first16.hex().upper()
            entry["magic_detected_format"] = identify_magic_bytes(raw_bytes)
            entry["size_bytes"]            = len(raw_bytes)
            entry["hash_md5"]              = hashlib.md5(raw_bytes).hexdigest()
            entry["hash_sha1"]             = hashlib.sha1(raw_bytes).hexdigest()
            entry["hash_sha256"]           = hashlib.sha256(raw_bytes).hexdigest()
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

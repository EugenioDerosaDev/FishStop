import re
import base64
import email
from email import policy
from typing import Optional


# ---------------------------------------------------------------------------
# Magic Bytes database (Gary Kessler / File Signatures)
# ---------------------------------------------------------------------------
MAGIC_BYTES: dict[str, list[bytes]] = {
    "pdf":  [b"%PDF"],
    "zip":  [b"PK\x03\x04", b"PK\x05\x06", b"PK\x07\x08"],
    "docx": [b"PK\x03\x04"],   # docx/xlsx/pptx are zip-based
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
    "doc":  [b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"],  # OLE2
    "xls":  [b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"],
    "ppt":  [b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"],
    "rtf":  [b"{\\rtf"],
    "html": [b"<!DOCTYPE", b"<html"],
    "xml":  [b"<?xml"],
    "js":   [],   # no reliable magic bytes
    "bat":  [],
    "ps1":  [],
    "sh":   [b"#!/"],
}

# Map content-type → expected extension(s)
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
    "application/octet-stream": [],  # unknown — check magic bytes only
    "image/png":  ["png"],
    "image/jpeg": ["jpg"],
    "image/gif":  ["gif"],
    "image/bmp":  ["bmp"],
    "image/tiff": ["tiff"],
    "text/html":  ["html"],
    "text/xml":   ["xml"],
    "application/rtf": ["rtf"],
}


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
# Received chain parser
# ---------------------------------------------------------------------------
_IP_RE = re.compile(r"\[(\d{1,3}(?:\.\d{1,3}){3})\]")
_BY_RE = re.compile(r"by\s+([\w.\-]+)", re.IGNORECASE)
_FROM_RE = re.compile(r"from\s+([\w.\-]+)\s*(?:\(([^)]*)\))?", re.IGNORECASE)
_FOR_RE = re.compile(r"for\s+<([^>]+)>", re.IGNORECASE)
_TLS_RE = re.compile(r"version=(TLS[\w.]+)\s+cipher=([\w\-]+)", re.IGNORECASE)


def _parse_received_hop(raw: str) -> dict:
    hop: dict = {"raw": raw.strip()}

    m = _FROM_RE.search(raw)
    if m:
        hop["from_host"] = m.group(1)
        parenthetical = m.group(2) or ""
        ip_m = _IP_RE.search(parenthetical) or _IP_RE.search(raw)
        hop["sender_ip"] = ip_m.group(1) if ip_m else None
        # Try to grab a service name inside parenthetical (e.g. "emkei.cz")
        parts = [p.strip() for p in parenthetical.replace("[", "").replace("]", "").split()]
        hop["sender_domain"] = parts[0] if parts and not parts[0][0].isdigit() else None

    m2 = _BY_RE.search(raw)
    hop["by_host"] = m2.group(1) if m2 else None

    m3 = _FOR_RE.search(raw)
    hop["for_address"] = m3.group(1) if m3 else None

    m4 = _TLS_RE.search(raw)
    if m4:
        hop["tls_version"] = m4.group(1)
        hop["tls_cipher"]  = m4.group(2)

    return hop


# ---------------------------------------------------------------------------
# Authentication-Results parser
# ---------------------------------------------------------------------------
_AUTH_FIELD_RE = re.compile(
    r"(spf|dkim|dmarc)\s*=\s*([\w]+)"
    r"(?:[^;]*?smtp\.\w+=([^\s;]+))?",
    re.IGNORECASE,
)


def _parse_auth_results(raw: str) -> dict:
    results: dict = {}
    for m in _AUTH_FIELD_RE.finditer(raw):
        proto  = m.group(1).upper()
        status = m.group(2).lower()
        identity = m.group(3) or ""
        results[proto] = {"status": status, "identity": identity, "raw": m.group(0).strip()}
    return results


# ---------------------------------------------------------------------------
# Main analyzer
# ---------------------------------------------------------------------------

class EmlSOCAnalyzer:
    """
    Parses a raw .eml file and returns a structured SOC-style report dict.
    Everything is extracted dynamically from the actual email — no hardcoded
    logic tied to a specific message.
    """

    def analyze(self, eml_path: str) -> dict:
        with open(eml_path, "rb") as f:
            msg = email.message_from_binary_file(f, policy=policy.compat32)

        report: dict = {}

        # ------------------------------------------------------------------ #
        # 1. Basic envelope fields
        # ------------------------------------------------------------------ #
        report["delivered_to"] = self._header(msg, "Delivered-To")
        report["to"]           = self._header(msg, "To")
        report["from_"]        = self._header(msg, "From")
        report["subject"]      = self._header(msg, "Subject")
        report["date"]         = self._header(msg, "Date")
        report["message_id"]   = self._header(msg, "Message-Id")
        report["importance"]   = self._header(msg, "Importance") or self._header(msg, "X-Priority")
        report["mime_version"] = self._header(msg, "MIME-Version")
        report["content_type"] = self._header(msg, "Content-Type")

        # ------------------------------------------------------------------ #
        # 2. Return-Path / Errors-To / Reply-To
        # ------------------------------------------------------------------ #
        report["return_path"] = self._header(msg, "Return-Path")
        report["errors_to"]   = self._header(msg, "Errors-To")
        reply_to              = self._header(msg, "Reply-To")
        report["reply_to"]    = reply_to

        # Anomaly: Reply-To ≠ From
        from_addr  = self._extract_address(report["from_"])
        reply_addr = self._extract_address(reply_to)
        report["reply_to_mismatch"] = bool(
            reply_addr and from_addr and reply_addr.lower() != from_addr.lower()
        )

        # ------------------------------------------------------------------ #
        # 3. Google / routing metadata
        # ------------------------------------------------------------------ #
        report["x_google_smtp_source"] = self._header(msg, "X-Google-Smtp-Source")
        report["x_received"]           = self._header(msg, "X-Received")

        # ------------------------------------------------------------------ #
        # 4. ARC headers
        # ------------------------------------------------------------------ #
        report["arc_seal"]                   = self._header(msg, "ARC-Seal")
        report["arc_message_signature"]      = self._header(msg, "ARC-Message-Signature")
        report["arc_authentication_results"] = self._header(msg, "ARC-Authentication-Results")

        # ------------------------------------------------------------------ #
        # 5. Received chain  (chronological: last = closest to sender)
        # ------------------------------------------------------------------ #
        raw_received = msg.get_all("Received") or []
        hops = [_parse_received_hop(r) for r in raw_received]
        report["received_hops"] = hops
        # Convenience aliases
        report["closest_to_recipient"] = hops[0]  if hops else {}
        report["injection_server"]     = hops[1]  if len(hops) > 1 else {}
        report["closest_to_sender"]    = hops[-1] if hops else {}

        # ------------------------------------------------------------------ #
        # 6. Received-SPF raw line
        # ------------------------------------------------------------------ #
        report["received_spf_raw"] = self._header(msg, "Received-SPF")

        # ------------------------------------------------------------------ #
        # 7. Authentication-Results (parsed)
        # ------------------------------------------------------------------ #
        auth_raw = self._header(msg, "Authentication-Results") or ""
        arc_auth_raw = report["arc_authentication_results"] or ""
        report["auth_results"]     = _parse_auth_results(auth_raw)
        report["arc_auth_results"] = _parse_auth_results(arc_auth_raw)

        # ------------------------------------------------------------------ #
        # 8. DKIM header presence check
        # ------------------------------------------------------------------ #
        report["dkim_signature_present"] = bool(msg.get("DKIM-Signature"))
        report["dkim_signature_raw"]     = self._header(msg, "DKIM-Signature")

        # ------------------------------------------------------------------ #
        # 9. Body parts & attachments (with magic byte check)
        # ------------------------------------------------------------------ #
        body_parts       = []
        attachments_info = []

        for part in msg.walk():
            ct          = part.get_content_type()
            disp        = str(part.get("Content-Disposition") or "")
            encoding    = str(part.get("Content-Transfer-Encoding") or "").lower().strip()
            filename    = part.get_filename() or ""
            is_attach   = "attachment" in disp.lower()

            if is_attach or filename:
                raw_payload = part.get_payload(decode=False)
                attachment_entry = self._analyze_attachment(
                    filename=filename,
                    content_type=ct,
                    encoding=encoding,
                    raw_payload=raw_payload,
                )
                attachments_info.append(attachment_entry)
            elif ct == "text/plain":
                payload = part.get_payload(decode=True)
                if payload:
                    charset = part.get_content_charset() or "utf-8"
                    body_parts.append(payload.decode(charset, errors="ignore"))
            elif ct == "text/html" and not body_parts:
                payload = part.get_payload(decode=True)
                if payload:
                    charset = part.get_content_charset() or "utf-8"
                    body_parts.append(payload.decode(charset, errors="ignore"))

        report["body"]        = "\n".join(body_parts).strip()
        report["attachments"] = attachments_info

        # ------------------------------------------------------------------ #
        # 10. Summary flags (for quick SOC triage)
        # ------------------------------------------------------------------ #
        report["flags"] = self._build_flags(report)

        return report

    # ------------------------------------------------------------------ #
    # Helpers
    # ------------------------------------------------------------------ #

    @staticmethod
    def _header(msg, name: str) -> Optional[str]:
        val = msg.get(name)
        if val is None:
            return None
        # Collapse folded whitespace
        return re.sub(r"\s+", " ", str(val)).strip()

    @staticmethod
    def _extract_address(raw: Optional[str]) -> Optional[str]:
        if not raw:
            return None
        m = re.search(r"<([^>]+)>", raw)
        if m:
            return m.group(1).strip()
        m2 = re.search(r"[\w.+\-]+@[\w.\-]+", raw)
        return m2.group(0).strip() if m2 else None

    def _analyze_attachment(
        self,
        filename: str,
        content_type: str,
        encoding: str,
        raw_payload,
    ) -> dict:
        entry: dict = {
            "filename": filename,
            "content_type": content_type,
            "encoding": encoding,
            "magic_bytes_hex": None,
            "magic_detected_format": None,
            "extension_from_filename": _ext_from_filename(filename),
            "extension_match": None,
            "anomaly": None,
        }

        # Decode base64 to get actual bytes
        if encoding == "base64" and raw_payload:
            try:
                if isinstance(raw_payload, str):
                    raw_bytes = base64.b64decode(raw_payload.replace("\n", "").replace("\r", ""))
                else:
                    raw_bytes = base64.b64decode(raw_payload)
                first16 = raw_bytes[:16]
                entry["magic_bytes_hex"] = first16.hex().upper()
                entry["magic_detected_format"] = _identify_magic_bytes(raw_bytes)
            except Exception as exc:
                entry["anomaly"] = f"Base64 decode error: {exc}"
                return entry
        else:
            entry["anomaly"] = "Non-base64 attachment — raw bytes not decoded"
            return entry

        # Compare content-type expected extensions vs filename extension vs magic bytes
        ct_base = content_type.split(";")[0].strip().lower()
        expected_exts = CONTENT_TYPE_TO_EXT.get(ct_base, [])
        file_ext      = entry["extension_from_filename"]
        magic_fmt     = entry["magic_detected_format"]

        mismatches = []
        if file_ext and expected_exts and file_ext not in expected_exts:
            mismatches.append(
                f"Content-Type '{ct_base}' expects {expected_exts} but filename has '.{file_ext}'"
            )
        if magic_fmt and file_ext and magic_fmt != file_ext:
            # Special case: zip-based Office formats share the same magic bytes
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

    @staticmethod
    def _build_flags(report: dict) -> list[dict]:
        flags = []

        def flag(level: str, field: str, message: str):
            flags.append({"level": level, "field": field, "message": message})

        # SPF
        spf = report["auth_results"].get("SPF") or report["arc_auth_results"].get("SPF")
        if spf:
            if spf["status"] != "pass":
                flag("HIGH", "SPF", f"SPF {spf['status'].upper()} — dominio non autorizza il server mittente")
        else:
            flag("MEDIUM", "SPF", "Nessun risultato SPF trovato negli header")

        # DKIM
        if not report["dkim_signature_present"]:
            flag("MEDIUM", "DKIM", "Firma DKIM assente negli header")
        dkim = report["auth_results"].get("DKIM") or report["arc_auth_results"].get("DKIM")
        if dkim and dkim["status"] != "pass":
            flag("HIGH", "DKIM", f"DKIM {dkim['status'].upper()}")

        # DMARC
        dmarc = report["auth_results"].get("DMARC") or report["arc_auth_results"].get("DMARC")
        if dmarc and dmarc["status"] not in ("pass", "bestguesspass"):
            flag("HIGH", "DMARC", f"DMARC {dmarc['status'].upper()}")
        elif not dmarc:
            flag("LOW", "DMARC", "Nessuna policy DMARC rilevata negli header")

        # Reply-To mismatch
        if report["reply_to_mismatch"]:
            flag("HIGH", "Reply-To",
                 f"Reply-To ({report['reply_to']}) differs da From ({report['from_']}) — possibile harvesting")

        # Injection server anomaly
        inj = report.get("injection_server", {})
        if inj.get("sender_ip"):
            flag("INFO", "Received",
                 f"Server di iniezione: {inj.get('sender_domain') or inj.get('from_host', '?')} "
                 f"[{inj['sender_ip']}] — verificare reputazione IP/dominio")

        # Attachment anomalies
        for att in report.get("attachments", []):
            if att.get("anomaly"):
                flag("HIGH", "Attachment",
                     f"'{att['filename']}': {att['anomaly']}")
            if att.get("magic_bytes_hex"):
                flag("INFO", "Attachment",
                     f"'{att['filename']}': magic bytes {att['magic_bytes_hex'][:8]}… "
                     f"→ formato rilevato: {att['magic_detected_format'] or 'sconosciuto'}")

        return flags
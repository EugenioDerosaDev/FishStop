"""
analysis/header.py — Email header parsing.

Responsibilities:
  - Envelope field extraction (From, To, Subject, Date, etc.)
  - Received hop chain parsing (_parse_received_hop)
  - Authentication-Results parsing (_parse_auth_results)
  - Anomaly detection: Reply-To mismatch, Return-Path domain mismatch,
    Display Name spoofing
  - SPF sender IP extraction (_extract_spf_sender_ip)
"""

import re
from typing import Optional


# ---------------------------------------------------------------------------
# Regex patterns for Received header parsing
# ---------------------------------------------------------------------------

_IP_RE = re.compile(
    r"(?:\[|(?<=\s\())"
    r"([0-9a-fA-F]{1,4}(?::[0-9a-fA-F]{1,4}){1,7}|(?:::[0-9a-fA-F]{1,4}){1,7}|[0-9a-fA-F]{1,4}::|"
    r"\d{1,3}(?:\.\d{1,3}){3})"
    r"(?=\s*\)|\])"
)
_BY_RE   = re.compile(r"by\s+([\w.\-]+)", re.IGNORECASE)
_FROM_RE = re.compile(r"from\s+([\w.\-]+)\s*(?:\(([^)]*)\))?", re.IGNORECASE)
_FOR_RE  = re.compile(r"for\s+<([^>]+)>", re.IGNORECASE)
_TLS_RE  = re.compile(r"version=(TLS[\w.]+)\s+cipher=([\w\-]+)", re.IGNORECASE)

_AUTH_FIELD_RE = re.compile(
    r"(spf|dkim|dmarc)\s*=\s*([\w]+)"
    r"(?:[^;]*?smtp\.\w+=([^\s;]+))?",
    re.IGNORECASE,
)

_PRIVATE_IP_RE = re.compile(
    r'^(10\.|172\.(1[6-9]|2\d|3[01])\.|192\.168\.|127\.)'
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def get_header(msg, name: str) -> Optional[str]:
    """Extracts and normalizes a single header value."""
    val = msg.get(name)
    if val is None:
        return None
    return re.sub(r"\s+", " ", str(val)).strip()


def extract_address(raw: Optional[str]) -> Optional[str]:
    """Pulls a bare email address from 'Display Name <addr>' or plain 'addr'."""
    if not raw:
        return None
    m = re.search(r"<([^>]+)>", raw)
    if m:
        return m.group(1).strip()
    m2 = re.search(r"[\w.+\-]+@[\w.\-]+", raw)
    return m2.group(0).strip() if m2 else None


def extract_domain(email_or_addr: str) -> str:
    """Returns the domain part of an address string, lower-cased."""
    m = re.search(r"@([\w.\-]+)", email_or_addr or "")
    return m.group(1).lower() if m else ""


# ---------------------------------------------------------------------------
# Received chain parser
# ---------------------------------------------------------------------------

def parse_received_hop(raw: str) -> dict:
    """Parses a single Received header into a structured dict."""
    hop: dict = {"raw": raw.strip()}
    clean_raw = " ".join(raw.split())

    m = _FROM_RE.search(clean_raw)
    if m:
        hop["from_host"] = m.group(1)
        parenthetical    = m.group(2) or ""

        ip_m = _IP_RE.search(parenthetical)
        if not ip_m:
            host_end = m.end(1)
            ip_m = _IP_RE.search(clean_raw, host_end)

        hop["sender_ip"] = ip_m.group(1) if ip_m else None

        parts = [p.strip() for p in
                 parenthetical.replace("[", "").replace("]", "")
                               .replace("(", "").replace(")", "").split()]
        hop["sender_domain"] = (
            parts[0] if parts and not parts[0][0].isdigit() and ":" not in parts[0]
            else None
        )

    if not hop.get("sender_ip"):
        fallback_ip = _IP_RE.search(clean_raw)
        hop["sender_ip"] = fallback_ip.group(1) if fallback_ip else None

    m2 = _BY_RE.search(clean_raw)
    hop["by_host"] = m2.group(1) if m2 else None

    m3 = _FOR_RE.search(clean_raw)
    hop["for_address"] = m3.group(1) if m3 else None

    m4 = _TLS_RE.search(clean_raw)
    if m4:
        hop["tls_version"] = m4.group(1)
        hop["tls_cipher"]  = m4.group(2)

    hop["all_ips"] = list(dict.fromkeys(_IP_RE.findall(clean_raw)))
    return hop


# ---------------------------------------------------------------------------
# Authentication-Results parser
# ---------------------------------------------------------------------------

def parse_auth_results(raw: str) -> dict:
    """Parses an Authentication-Results header into a protocol → result dict."""
    results: dict = {}
    for m in _AUTH_FIELD_RE.finditer(raw):
        proto    = m.group(1).upper()
        status   = m.group(2).lower()
        identity = m.group(3) or ""
        results[proto] = {"status": status, "identity": identity, "raw": m.group(0).strip()}
    return results


# ---------------------------------------------------------------------------
# SPF sender IP extraction
# ---------------------------------------------------------------------------

def extract_spf_sender_ip(msg, hops: list) -> Optional[str]:
    """
    Extracts the correct IP to use for live SPF verification.

    Priority:
      1. client-ip= in the LAST Received-SPF header (closest to sender)
      2. smtp.remote-ip= in Authentication-Results
      3. First public IP in the last Received hop
      4. Fallback: sender_ip from hop[1]
    """
    all_rcvd_spf = msg.get_all('Received-SPF') or []
    for rcvd_spf in reversed(all_rcvd_spf):
        m = re.search(r'client-ip=([\d.a-fA-F:]+)', str(rcvd_spf), re.IGNORECASE)
        if m and not _PRIVATE_IP_RE.match(m.group(1)):
            return m.group(1)

    auth = str(msg.get('Authentication-Results') or '')
    m = re.search(r'smtp\.remote-ip=([\d.]+)', auth, re.IGNORECASE)
    if m and not _PRIVATE_IP_RE.match(m.group(1)):
        return m.group(1)

    if hops:
        last_hop = hops[-1]
        for ip in (last_hop.get('all_ips') or []):
            if ip and not _PRIVATE_IP_RE.match(ip):
                return ip

    return hops[1].get('sender_ip') if len(hops) > 1 else None


# ---------------------------------------------------------------------------
# Envelope extraction
# ---------------------------------------------------------------------------

def extract_envelope(msg) -> dict:
    """
    Extracts all envelope-level fields from a parsed email.message object
    and detects header-based anomalies.

    Returns a flat dict ready to be merged into the SOC report.
    """
    report: dict = {}

    report["delivered_to"] = get_header(msg, "Delivered-To")
    report["to"]           = get_header(msg, "To")
    report["from_"]        = get_header(msg, "From")
    report["subject"]      = get_header(msg, "Subject")
    report["date"]         = get_header(msg, "Date")
    report["message_id"]   = get_header(msg, "Message-Id")
    report["importance"]   = get_header(msg, "Importance") or get_header(msg, "X-Priority")
    report["mime_version"] = get_header(msg, "MIME-Version")
    report["content_type"] = get_header(msg, "Content-Type")

    report["return_path"] = get_header(msg, "Return-Path")
    report["errors_to"]   = get_header(msg, "Errors-To")
    reply_to              = get_header(msg, "Reply-To")
    report["reply_to"]    = reply_to

    # Google / routing metadata
    report["x_google_smtp_source"] = get_header(msg, "X-Google-Smtp-Source")
    report["x_received"]           = get_header(msg, "X-Received")

    # ARC headers
    report["arc_seal"]                   = get_header(msg, "ARC-Seal")
    report["arc_message_signature"]      = get_header(msg, "ARC-Message-Signature")
    report["arc_authentication_results"] = get_header(msg, "ARC-Authentication-Results")

    # ── Anomaly: Reply-To ≠ From ──────────────────────────────────────────
    from_addr  = extract_address(report["from_"])
    reply_addr = extract_address(reply_to)
    report["reply_to_mismatch"] = bool(
        reply_addr and from_addr and reply_addr.lower() != from_addr.lower()
    )

    # ── Anomaly: Return-Path domain ≠ From domain ─────────────────────────
    return_path_addr   = extract_address(report["return_path"] or "")
    return_path_domain = extract_domain(return_path_addr or "") if return_path_addr else ""
    from_domain        = extract_domain(from_addr or "") if from_addr else ""
    report["return_path_domain_mismatch"] = bool(
        return_path_domain and from_domain
        and return_path_domain.lower() != from_domain.lower()
    )
    report["return_path_domain"] = return_path_domain

    # ── Anomaly: Display Name Spoofing ────────────────────────────────────
    display_name_email_match = None
    if report["from_"]:
        dn_match = re.match(r'^"?([^"<]+)"?\s*<', report["from_"])
        if dn_match:
            dn = dn_match.group(1).strip()
            embedded = re.search(r"[\w.+\-]+@[\w.\-]+", dn)
            if embedded:
                embedded_addr = embedded.group(0).lower()
                if from_addr and embedded_addr != from_addr.lower():
                    display_name_email_match = embedded_addr
    report["display_name_spoofing"] = display_name_email_match

    # ── Received chain ────────────────────────────────────────────────────
    raw_received = msg.get_all("Received") or []
    hops = [parse_received_hop(r) for r in raw_received]
    report["received_hops"]        = hops
    report["closest_to_recipient"] = hops[0]  if hops else {}
    report["injection_server"]     = hops[1]  if len(hops) > 1 else {}
    report["closest_to_sender"]    = hops[-1] if hops else {}
    report["injection_sender_ip"]  = extract_spf_sender_ip(msg, hops)

    # ── Received-SPF raw ─────────────────────────────────────────────────
    report["received_spf_raw"] = get_header(msg, "Received-SPF")

    # ── Authentication-Results ────────────────────────────────────────────
    auth_raw     = get_header(msg, "Authentication-Results") or ""
    arc_auth_raw = report["arc_authentication_results"] or ""
    report["auth_results"]     = parse_auth_results(auth_raw)
    report["arc_auth_results"] = parse_auth_results(arc_auth_raw)

    # ── DKIM header presence ──────────────────────────────────────────────
    report["dkim_signature_present"] = bool(msg.get("DKIM-Signature"))
    report["dkim_signature_raw"]     = get_header(msg, "DKIM-Signature")

    return report

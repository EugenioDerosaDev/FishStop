"""
analyzer/received_parser.py — Parsing degli header di routing email (Enterprise Level).

Espone:
  - parse_received_hop(raw)    : dizionario strutturato per un singolo hop Received
  - parse_auth_results(raw)    : dizionario SPF/DKIM/DMARC da Authentication-Results
"""

import ipaddress
import re
from typing import Any, Dict, List, Optional

# ── Regex Enterprise-Grade ──────────────────────────────────────────────────

# Estrae potenziali candidati IP (stringhe di caratteri esadecimali, due punti e punti)
# La validazione formale ed enterprise viene delegata al modulo 'ipaddress'
_IP_CANDIDATE_RE = re.compile(r"\[?([0-9a-fA-F:.]+)\]?")

_BY_RE = re.compile(r"\bby\s+([\w.\-]+)", re.IGNORECASE)
_FROM_RE = re.compile(r"\bfrom\s+([\w.\-]+)\s*(?:\(([^)]*)\))?", re.IGNORECASE)
_FOR_RE = re.compile(r"\bfor\s+<([^>]+)>", re.IGNORECASE)

# TLS regex più tollerante per gli standard moderni (inclusi TLSv1.3 e formati estesi)
_TLS_RE = re.compile(
    r"(?:version=)?(TLSv?[\d.]+)\s+(?:cipher|version)=([\w\-]+)", re.IGNORECASE
)

# Authentication-Results standard RFC 8601
_AUTH_FIELD_RE = re.compile(
    r"\b(spf|dkim|dmarc)\s*=\s*([a-zA-Z0-9_-]+)(?:\s+(?:header\.[a-zA-Z0-9_-]+|smtp\.[a-zA-Z0-9_-]+)\s*=\s*([^\s;]+))?",
    re.IGNORECASE,
)


# ── Funzioni di Utility Internizzate ─────────────────────────────────────────


def _extract_valid_ips(text: str) -> List[str]:
    """
    Trova tutti i candidati IP nel testo e restituisce solo quelli che superano
    la validazione rigorosa del modulo ipaddress di Python, rimuovendo i duplicati.
    """
    valid_ips: Dict[str, bool] = {}
    # Pulizia preliminare per evitare falsi positivi con caratteri di punteggiatura attigui
    cleaned_text = text.replace("(", " ").replace(")", " ").replace(";", " ")

    for match in _IP_CANDIDATE_RE.finditer(cleaned_text):
        candidate = match.group(1).strip(".")
        # Rimuove eventuali prefissi comuni negli header email (es. "IPv6:")
        if candidate.lower().startswith("ipv6:"):
            candidate = candidate[5:]

        try:
            # Sfrutta il parsing nativo C-level di Python (valida sia IPv4 che IPv6)
            ip_obj = ipaddress.ip_address(candidate)
            valid_ips[str(ip_obj)] = True
        except ValueError:
            continue

    return list(valid_ips.keys())


# ── Funzioni Principali Esposte ──────────────────────────────────────────────


def parse_received_hop(raw: str) -> Dict[str, Any]:
    """
    Parsa un singolo header Received in modo sicuro ed enterprise.
    Garantisce l'assenza di crash anche su stringhe RFC-non-compliant.
    """
    if not raw:
        return {
            "raw": "",
            "from_host": None,
            "sender_ip": None,
            "sender_domain": None,
            "by_host": None,
            "for_address": None,
            "tls_version": None,
            "tls_cipher": None,
            "all_ips": [],
        }

    hop: Dict[str, Any] = {"raw": raw.strip()}
    clean_raw = " ".join(raw.split())

    # Estrazione di tutti gli IP validi presenti nell'header
    all_ips = _extract_valid_ips(clean_raw)
    hop["all_ips"] = all_ips

    # Parsing della sezione 'FROM'
    m_from = _FROM_RE.search(clean_raw)
    if m_from:
        hop["from_host"] = m_from.group(1)
        parenthetical = m_from.group(2) or ""

        # Cerca prima l'IP dentro la parentesi (comportamento standard MTA)
        parenthesis_ips = _extract_valid_ips(parenthetical)
        if parenthesis_ips:
            hop["sender_ip"] = parenthesis_ips[0]
        else:
            hop["sender_ip"] = all_ips[0] if all_ips else None

        # Identificazione del sender_domain dichiarato (eshewing IP/helo-name)
        parts = [p.strip("()[]:,") for p in parenthetical.split() if p.strip("()[]:,")]
        if parts:
            first_part = parts[0]
            # Se la prima parte non è un IP valido, la consideriamo il dominio dichiarato
            try:
                ipaddress.ip_address(first_part.lower().replace("ipv6:", ""))
                hop["sender_domain"] = None
            except ValueError:
                hop["sender_domain"] = first_part
        else:
            hop["sender_domain"] = None
    else:
        hop["from_host"] = None
        hop["sender_ip"] = all_ips[0] if all_ips else None
        hop["sender_domain"] = None

    # Parsing della sezione 'BY'
    m_by = _BY_RE.search(clean_raw)
    hop["by_host"] = m_by.group(1) if m_by else None

    # Parsing della sezione 'FOR'
    m_for = _FOR_RE.search(clean_raw)
    hop["for_address"] = m_for.group(1) if m_for else None

    # Parsing dei dati TLS
    m_tls = _TLS_RE.search(clean_raw)
    if m_tls:
        hop["tls_version"] = m_tls.group(1)
        hop["tls_cipher"] = m_tls.group(2)
    else:
        hop["tls_version"] = None
        hop["tls_cipher"] = None

    return hop


def parse_auth_results(raw: str) -> Dict[str, Dict[str, str]]:
    """
    Parsa l'header Authentication-Results normalizzando i risultati
    secondo lo standard RFC 8601.
    """
    results: Dict[str, Dict[str, str]] = {}
    if not raw:
        return results

    for m in _AUTH_FIELD_RE.finditer(raw):
        proto = m.group(1).upper()
        status = m.group(2).lower()
        identity = m.group(3) or ""

        results[proto] = {
            "status": status,
            "identity": identity.strip("<>\"'"),
            "raw": m.group(0).strip(),
        }
    return results
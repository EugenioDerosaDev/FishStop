"""
validators/spf.py — Verifica SPF per email in ingresso.

Usa pyspf per una valutazione completa del record SPF.
Se pyspf non è installato, esegue un controllo di presenza via DNS.

Funzione pubblica:
  check_spf(resolver, sender_ip, mail_from, helo_domain) → dict
"""

import re
import dns.resolver
from typing import Optional

try:
    import spf as pyspf
    _SPF_AVAILABLE = True
except ImportError:
    _SPF_AVAILABLE = False


def _extract_address(raw: Optional[str]) -> Optional[str]:
    if not raw:
        return None
    m = re.search(r"<([^>]+)>", raw)
    if m:
        return m.group(1).strip()
    m2 = re.search(r"[\w.+\-]+@[\w.\-]+", raw)
    return m2.group(0).strip() if m2 else None


def _extract_domain(email_or_raw: str) -> str:
    addr = _extract_address(email_or_raw) or email_or_raw
    m = re.search(r"@([\w.\-]+)", addr)
    return m.group(1).lower() if m else ""


def _fetch_spf_record(resolver: dns.resolver.Resolver, domain: str) -> str:
    try:
        for rdata in resolver.resolve(domain, "TXT"):
            txt = rdata.to_text().strip('"')
            if txt.startswith("v=spf1"):
                return txt
    except Exception:
        pass
    return ""


def _spf_presence_only(resolver: dns.resolver.Resolver, domain: str) -> dict:
    """Fallback quando pyspf non è installato: verifica solo l'esistenza del record."""
    record = _fetch_spf_record(resolver, domain)
    if record:
        return {
            "status":  "record-found",
            "record":  record,
            "message": "Record SPF trovato (installare pyspf per la valutazione completa)",
        }
    return {
        "status":  "none",
        "record":  "",
        "message": "Nessun record SPF trovato (installare pyspf per la valutazione completa)",
    }


def check_spf(
    resolver: dns.resolver.Resolver,
    sender_ip: str,
    mail_from: str,
    helo_domain: str = "",
) -> dict:
    """
    Valutazione SPF completa via pyspf.

    Parameters
    ----------
    resolver    : istanza dns.resolver.Resolver condivisa
    sender_ip   : IP del server di iniezione (dalla catena Received)
    mail_from   : indirizzo envelope sender (header Return-Path)
    helo_domain : dominio HELO — fallback quando mail_from è '<>'

    Returns
    -------
    {
      "status"    : "pass" | "fail" | "softfail" | "neutral" |
                    "none" | "permerror" | "temperror" | "error",
      "record"    : str,
      "domain"    : str,
      "sender_ip" : str,
      "mail_from" : str,
      "message"   : str,
      "library"   : "pyspf" | "dns-presence-only"
    }
    """
    addr   = _extract_address(mail_from) or mail_from
    domain = _extract_domain(addr)

    base = {
        "sender_ip": sender_ip,
        "mail_from": addr,
        "domain":    domain,
        "record":    "",
        "library":   "pyspf",
    }

    if not _SPF_AVAILABLE:
        base["library"] = "dns-presence-only"
        return {**base, **_spf_presence_only(resolver, domain)}

    if not sender_ip or not domain:
        return {**base, "status": "error",
                "message": "sender_ip o mail_from mancanti — impossibile valutare SPF"}

    try:
        result, explanation = pyspf.check2(
            i=sender_ip,
            s=addr,
            h=helo_domain or domain,
        )
        result     = (result or "none").lower()
        record_str = _fetch_spf_record(resolver, domain)
        return {
            **base,
            "status":  result,
            "record":  record_str,
            "message": explanation or f"SPF {result.upper()}",
        }
    except Exception as exc:
        return {**base, "status": "error", "message": f"Errore pyspf: {exc}"}

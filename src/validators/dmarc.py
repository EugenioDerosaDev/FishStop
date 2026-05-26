"""
validators/dmarc.py — Valutazione DMARC completa.

Recupera il record DMARC via DNS, parsa i tag, verifica l'allineamento
tra i domini SPF/DKIM e il dominio From (strict vs relaxed).

Funzione pubblica:
  check_dmarc(resolver, from_address, spf_result, spf_domain, dkim_results) → dict
"""

import re
import dns.resolver
from typing import Optional


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


def _parse_dmarc_record(record: str) -> dict:
    """Parsa un record DMARC TXT in un dizionario tag→valore."""
    tags: dict = {}
    for part in record.split(";"):
        part = part.strip()
        if "=" in part:
            k, _, v = part.partition("=")
            tags[k.strip().lower()] = v.strip().lower()
    return tags


def _fetch_dmarc_record(
    resolver: dns.resolver.Resolver, domain: str
) -> tuple[str, str]:
    """
    Recupera il record DMARC TXT, risalendo al dominio organizzativo se necessario.
    Restituisce (record_text, lookup_domain) oppure ("", "").
    """
    labels = domain.split(".")
    for i in range(len(labels) - 1):
        candidate  = ".".join(labels[i:])
        dmarc_host = f"_dmarc.{candidate}"
        try:
            for rdata in resolver.resolve(dmarc_host, "TXT"):
                txt = rdata.to_text().strip('"')
                if txt.startswith("v=DMARC1"):
                    return txt, candidate
        except Exception:
            continue
    return "", ""


def _domains_aligned(check_domain: str, from_domain: str, mode: str) -> bool:
    """
    True se check_domain è allineato con from_domain nel modo specificato.
      strict  (s): match esatto richiesto
      relaxed (r): il dominio organizzativo (ultimi due label) deve coincidere
    """
    check_domain = check_domain.lower().lstrip(".")
    from_domain  = from_domain.lower().lstrip(".")

    if mode == "s":
        return check_domain == from_domain

    def org(d: str) -> str:
        parts = d.split(".")
        return ".".join(parts[-2:]) if len(parts) >= 2 else d

    return org(check_domain) == org(from_domain)


def check_dmarc(
    resolver: dns.resolver.Resolver,
    from_address: str,
    spf_result: str,
    spf_domain: str,
    dkim_results: list,
) -> dict:
    """
    Valutazione DMARC completa: lookup record, parsing policy,
    verifica allineamento SPF/DKIM e disposizione finale.

    Returns
    -------
    {
      "status"           : "pass" | "fail" | "none" | "error",
      "policy"           : "none" | "quarantine" | "reject",
      "subdomain_policy" : str,
      "pct"              : int,
      "adkim"            : "r" | "s",
      "aspf"             : "r" | "s",
      "record"           : str,
      "domain"           : str,
      "spf_aligned"      : bool,
      "dkim_aligned"     : bool,
      "message"          : str,
      "rua"              : str,
      "ruf"              : str,
    }
    """
    from_addr   = _extract_address(from_address) or from_address
    from_domain = _extract_domain(from_addr)

    base: dict = {
        "domain":           from_domain,
        "record":           "",
        "policy":           "none",
        "subdomain_policy": "none",
        "pct":              100,
        "adkim":            "r",
        "aspf":             "r",
        "spf_aligned":      False,
        "dkim_aligned":     False,
        "rua":              "",
        "ruf":              "",
    }

    if not from_domain:
        return {**base, "status": "error",
                "message": "Impossibile estrarre il dominio dall'header From"}

    record, lookup_domain = _fetch_dmarc_record(resolver, from_domain)
    if not record:
        return {**base, "status": "none",
                "message": f"Nessun record DMARC trovato per {from_domain} né per il dominio organizzativo"}

    base["domain"] = lookup_domain
    base["record"] = record

    tags             = _parse_dmarc_record(record)
    policy           = tags.get("p",   "none")
    subdomain_policy = tags.get("sp",  policy)
    pct              = int(tags.get("pct", "100"))
    adkim            = tags.get("adkim", "r")
    aspf             = tags.get("aspf",  "r")

    base.update({
        "policy":           policy,
        "subdomain_policy": subdomain_policy,
        "pct":              pct,
        "adkim":            adkim,
        "aspf":             aspf,
        "rua":              tags.get("rua", ""),
        "ruf":              tags.get("ruf", ""),
    })

    spf_aligned = False
    if spf_result == "pass" and spf_domain:
        spf_aligned = _domains_aligned(spf_domain, from_domain, aspf)
    base["spf_aligned"] = spf_aligned

    dkim_aligned = False
    for sig in (dkim_results or []):
        if sig.get("result") == "pass":
            d_domain = sig.get("d_domain", "")
            if d_domain and _domains_aligned(d_domain, from_domain, adkim):
                dkim_aligned = True
                break
    base["dkim_aligned"] = dkim_aligned

    if spf_aligned or dkim_aligned:
        aligned_via = []
        if spf_aligned:  aligned_via.append("SPF")
        if dkim_aligned: aligned_via.append("DKIM")
        return {
            **base,
            "status":  "pass",
            "message": (
                f"DMARC PASS — allineamento verificato tramite {' + '.join(aligned_via)} "
                f"(policy: {policy}, pct: {pct}%)"
            ),
        }
    else:
        return {
            **base,
            "status":  "fail",
            "message": (
                f"DMARC FAIL — né SPF né DKIM risultano allineati con il dominio From ({from_domain}). "
                f"Policy applicata: {policy} ({pct}%)"
            ),
        }

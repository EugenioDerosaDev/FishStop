"""
validators/dkim.py — Verifica crittografica della firma DKIM.

Usa dkimpy per la verifica reale della firma. Se non installato,
verifica solo la presenza dell'header DKIM-Signature.

Funzione pubblica:
  check_dkim(raw_eml_bytes) → dict
"""

import re

try:
    import dkim
    _DKIM_AVAILABLE = True
except ImportError:
    _DKIM_AVAILABLE = False


def _dkim_presence_only(raw_eml_bytes: bytes) -> dict:
    """Fallback quando dkimpy non è installato."""
    import email as _email
    msg     = _email.message_from_bytes(raw_eml_bytes)
    present = bool(msg.get("DKIM-Signature"))
    return {
        "status":     "present" if present else "none",
        "signatures": [],
        "message":    (
            "Firma DKIM rilevata (installare dkimpy per la verifica crittografica)"
            if present else
            "Firma DKIM assente (installare dkimpy per la verifica crittografica)"
        ),
        "library": "presence-only",
    }


def check_dkim(raw_eml_bytes: bytes) -> dict:
    """
    Verifica crittografica DKIM via dkimpy.

    Parameters
    ----------
    raw_eml_bytes : byte grezzi del file .eml completo

    Returns
    -------
    {
      "status"     : "pass" | "fail" | "none" | "error",
      "signatures" : list[dict],   — risultato per-firma
      "message"    : str,
      "library"    : "dkimpy" | "presence-only"
    }
    """
    if not _DKIM_AVAILABLE:
        return _dkim_presence_only(raw_eml_bytes)

    signatures = []
    overall    = "none"

    try:
        sig_headers = [
            v for k, v in (
                __import__("email").message_from_bytes(raw_eml_bytes).items()
            )
            if k.lower() == "dkim-signature"
        ]

        if not sig_headers:
            return {
                "status":     "none",
                "signatures": [],
                "message":    "Nessuna firma DKIM presente nell'email",
                "library":    "dkimpy",
            }

        for idx, sig_raw in enumerate(sig_headers):
            sig_info: dict = {"index": idx, "raw_header": sig_raw[:120] + "…"}

            d_match = re.search(r"\bd=([^\s;]+)", sig_raw)
            s_match = re.search(r"\bs=([^\s;]+)", sig_raw)
            sig_info["d_domain"]       = d_match.group(1).rstrip(";") if d_match else "?"
            sig_info["selector"]       = s_match.group(1).rstrip(";") if s_match else "?"
            sig_info["dns_key_record"] = (
                f"{sig_info['selector']}._domainkey.{sig_info['d_domain']}"
            )

            try:
                verifier = dkim.DKIM(raw_eml_bytes)
                ok = verifier.verify(idx=idx)
                sig_info["result"]  = "pass" if ok else "fail"
                sig_info["message"] = "Firma verificata ✅" if ok else "Verifica fallita ❌ — possibile manomissione"
            except dkim.DKIMException as dke:
                sig_info["result"]  = "fail"
                sig_info["message"] = f"Errore DKIM: {dke}"
            except Exception as exc:
                sig_info["result"]  = "error"
                sig_info["message"] = f"Errore inatteso: {exc}"

            signatures.append(sig_info)

        results = {s["result"] for s in signatures}
        if results == {"pass"}:
            overall = "pass"
        elif "fail" in results:
            overall = "fail"
        else:
            overall = "error"

        return {
            "status":     overall,
            "signatures": signatures,
            "message":    f"{len(signatures)} firma/e verificata/e — risultato complessivo: {overall.upper()}",
            "library":    "dkimpy",
        }

    except Exception as exc:
        return {
            "status":     "error",
            "signatures": signatures,
            "message":    f"Errore critico dkimpy: {exc}",
            "library":    "dkimpy",
        }

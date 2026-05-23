"""
validators.py — Real SPF / DKIM / DMARC validation

Dependencies (add to requirements.txt):
    dnspython>=2.4.0
    pyspf>=2.0.14
    dkimpy>=1.1.4

Install:
    pip install dnspython pyspf dkimpy
"""

import re
import json
import urllib.request
import urllib.parse
import urllib.error
import dns.resolver
from typing import Optional

# ── AbuseIPDB ──────────────────────────────────────────────────────────────
import streamlit as st
ABUSEIPDB_API_KEY = st.secrets.get("ABUSEIPDB_API_KEY", "")
ABUSEIPDB_ENDPOINT = "https://api.abuseipdb.com/api/v2/check"

# ── optional imports with graceful fallback ────────────────────────────────
try:
    import spf as pyspf          # pyspf
    _SPF_AVAILABLE = True
except ImportError:
    _SPF_AVAILABLE = False

try:
    import dkim                  # dkimpy
    _DKIM_AVAILABLE = True
except ImportError:
    _DKIM_AVAILABLE = False


# ── helpers ────────────────────────────────────────────────────────────────

def _extract_address(raw: Optional[str]) -> Optional[str]:
    """Pull a bare address out of  'Display Name <user@domain>' or plain 'user@domain'."""
    if not raw:
        return None
    m = re.search(r"<([^>]+)>", raw)
    if m:
        return m.group(1).strip()
    m2 = re.search(r"[\w.+\-]+@[\w.\-]+", raw)
    return m2.group(0).strip() if m2 else None


def _extract_domain(email_or_raw: str) -> str:
    """Return the domain part of an address string, lower-cased."""
    addr = _extract_address(email_or_raw) or email_or_raw
    m = re.search(r"@([\w.\-]+)", addr)
    return m.group(1).lower() if m else ""


def _parse_dmarc_record(record: str) -> dict:
    """
    Parse a DMARC TXT record into a tag→value dict.
    e.g. 'v=DMARC1; p=reject; rua=mailto:dmarc@example.com; adkim=s; aspf=r'
    """
    tags: dict = {}
    for part in record.split(";"):
        part = part.strip()
        if "=" in part:
            k, _, v = part.partition("=")
            tags[k.strip().lower()] = v.strip().lower()
    return tags


# ── main validator class ───────────────────────────────────────────────────

class EmailSecurityValidator:
    """
    Validates SPF, DKIM, and DMARC for a received .eml.

    Key design decisions vs the old version
    ────────────────────────────────────────
    • SPF  – evaluated against the *sender IP* and the *Return-Path / MAIL FROM*
              domain (not the From header), using pyspf's full mechanism engine.
    • DKIM – cryptographic signature verification via dkimpy, which fetches the
              public key from DNS and validates the hash.
    • DMARC– the record is fetched and parsed; alignment between the RFC5321
              MAIL FROM / DKIM d= domain and the RFC5322 From domain is checked
              per the DMARC spec (strict vs relaxed).
    """

    def __init__(self):
        self.resolver = dns.resolver.Resolver()
        self.resolver.timeout = 5.0
        self.resolver.lifetime = 5.0

    # ── SPF ───────────────────────────────────────────────────────────────

    def check_spf(
        self,
        sender_ip: str,
        mail_from: str,           # Return-Path / MAIL FROM address (not From header)
        helo_domain: str = "",    # optional HELO/EHLO hostname from Received header
    ) -> dict:
        """
        Full SPF evaluation via pyspf.

        Parameters
        ----------
        sender_ip   : IP address of the injection server (from the Received chain).
        mail_from   : The envelope sender address (Return-Path header).
                      SPF MUST be checked against this, not the From header.
        helo_domain : HELO domain string — used as fallback when mail_from is '<>'.

        Returns
        -------
        {
          "status"     : "pass" | "fail" | "softfail" | "neutral" |
                         "none" | "permerror" | "temperror" | "error",
          "record"     : str,   # the raw SPF TXT record found (if any)
          "domain"     : str,   # the domain that was evaluated
          "sender_ip"  : str,
          "mail_from"  : str,
          "message"    : str,
          "library"    : "pyspf" | "dns-presence-only"
        }
        """
        addr = _extract_address(mail_from) or mail_from
        domain = _extract_domain(addr)

        base = {
            "sender_ip":  sender_ip,
            "mail_from":  addr,
            "domain":     domain,
            "record":     "",
            "library":    "pyspf",
        }

        if not _SPF_AVAILABLE:
            # Graceful degradation: presence-only check (old behaviour)
            base["library"] = "dns-presence-only"
            return {**base, **self._spf_presence_only(domain)}

        if not sender_ip or not domain:
            return {**base, "status": "error",
                    "message": "sender_ip o mail_from mancanti — impossibile valutare SPF"}

        try:
            # pyspf.check2 returns (result, explanation)
            result, explanation = pyspf.check2(
                i=sender_ip,
                s=addr,
                h=helo_domain or domain,
            )
            result = (result or "none").lower()

            # Try to retrieve the actual record for display purposes
            record_str = self._fetch_spf_record(domain)

            return {
                **base,
                "status":  result,
                "record":  record_str,
                "message": explanation or f"SPF {result.upper()}",
            }
        except Exception as exc:
            return {**base, "status": "error", "message": f"Errore pyspf: {exc}"}

    def _spf_presence_only(self, domain: str) -> dict:
        """Fallback when pyspf is not installed: just check record existence."""
        record = self._fetch_spf_record(domain)
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

    def _fetch_spf_record(self, domain: str) -> str:
        try:
            for rdata in self.resolver.resolve(domain, "TXT"):
                txt = rdata.to_text().strip('"')
                if txt.startswith("v=spf1"):
                    return txt
        except Exception:
            pass
        return ""

    # ── DKIM ──────────────────────────────────────────────────────────────

    def check_dkim(self, raw_eml_bytes: bytes) -> dict:
        """
        Cryptographic DKIM verification via dkimpy.

        dkimpy fetches the public key from DNS at  <selector>._domainkey.<d=>
        and verifies the hash of the canonicalized headers + body.

        Parameters
        ----------
        raw_eml_bytes : the complete raw bytes of the .eml file.

        Returns
        -------
        {
          "status"     : "pass" | "fail" | "none" | "error",
          "signatures" : list of per-signature result dicts,
          "message"    : str,
          "library"    : "dkimpy" | "presence-only"
        }
        """
        if not _DKIM_AVAILABLE:
            return self._dkim_presence_only(raw_eml_bytes)

        # dkimpy can verify multiple signatures in one email
        signatures = []
        overall = "none"

        try:
            d = dkim.DKIM(raw_eml_bytes)
            # d.verify() verifies the *first* signature; iterate all headers for completeness
            sig_headers = [
                v for k, v in (
                    # email.message_from_bytes is lightweight here
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

                # Extract d= and s= for display
                d_match = re.search(r"\bd=([^\s;]+)", sig_raw)
                s_match = re.search(r"\bs=([^\s;]+)", sig_raw)
                sig_info["d_domain"]  = d_match.group(1).rstrip(";") if d_match else "?"
                sig_info["selector"]  = s_match.group(1).rstrip(";") if s_match else "?"
                sig_info["dns_key_record"] = (
                    f"{sig_info['selector']}._domainkey.{sig_info['d_domain']}"
                )

                try:
                    # Re-instantiate per signature so we always check the first one
                    # dkimpy verifies from the raw bytes; for multi-sig we rebuild
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

            # Overall result: pass only if ALL signatures pass
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

    def _dkim_presence_only(self, raw_eml_bytes: bytes) -> dict:
        """Fallback when dkimpy is not installed."""
        import email as _email
        msg = _email.message_from_bytes(raw_eml_bytes)
        present = bool(msg.get("DKIM-Signature"))
        return {
            "status":     "present" if present else "none",
            "signatures": [],
            "message":    (
                "Firma DKIM rilevata (installare dkimpy per la verifica crittografica)"
                if present else
                "Firma DKIM assente (installare dkimpy per la verifica crittografica)"
            ),
            "library":    "presence-only",
        }

    # ── DMARC ─────────────────────────────────────────────────────────────

    def check_dmarc(
        self,
        from_address: str,        # RFC5322 From header
        spf_result: str,          # "pass" | "fail" | … from check_spf()
        spf_domain: str,          # domain that SPF was evaluated against (Return-Path domain)
        dkim_results: list,       # list of per-signature dicts from check_dkim()
    ) -> dict:
        """
        Full DMARC evaluation including:
          • record lookup (with organizational-domain tree walk)
          • policy parsing  (p=, sp=, pct=, adkim=, aspf=)
          • SPF alignment check  (relaxed or strict)
          • DKIM alignment check (relaxed or strict)
          • final pass/fail disposition

        Returns
        -------
        {
          "status"          : "pass" | "fail" | "none" | "error",
          "policy"          : "none" | "quarantine" | "reject",
          "subdomain_policy": str,
          "pct"             : int,       # percentage of mail subject to policy
          "adkim"           : "r" | "s", # relaxed / strict DKIM alignment
          "aspf"            : "r" | "s", # relaxed / strict SPF alignment
          "record"          : str,
          "domain"          : str,       # organizational domain found
          "spf_aligned"     : bool,
          "dkim_aligned"    : bool,
          "message"         : str,
          "rua"             : str,       # aggregate report URI
          "ruf"             : str,       # forensic report URI
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

        # ── 1. Fetch DMARC record (with org-domain tree walk) ─────────────
        record, lookup_domain = self._fetch_dmarc_record(from_domain)
        if not record:
            return {**base, "status": "none",
                    "message": f"Nessun record DMARC trovato per {from_domain} né per il dominio organizzativo"}

        base["domain"] = lookup_domain
        base["record"] = record

        # ── 2. Parse tags ──────────────────────────────────────────────────
        tags = _parse_dmarc_record(record)
        policy          = tags.get("p",   "none")
        subdomain_policy= tags.get("sp",  policy)    # sp= defaults to p=
        pct             = int(tags.get("pct", "100"))
        adkim           = tags.get("adkim", "r")      # r = relaxed, s = strict
        aspf            = tags.get("aspf",  "r")
        rua             = tags.get("rua",   "")
        ruf             = tags.get("ruf",   "")

        base.update({
            "policy":           policy,
            "subdomain_policy": subdomain_policy,
            "pct":              pct,
            "adkim":            adkim,
            "aspf":             aspf,
            "rua":              rua,
            "ruf":              ruf,
        })

        # ── 3. SPF alignment ──────────────────────────────────────────────
        spf_aligned = False
        if spf_result == "pass" and spf_domain:
            spf_aligned = self._domains_aligned(spf_domain, from_domain, aspf)
        base["spf_aligned"] = spf_aligned

        # ── 4. DKIM alignment ─────────────────────────────────────────────
        dkim_aligned = False
        for sig in (dkim_results or []):
            if sig.get("result") == "pass":
                d_domain = sig.get("d_domain", "")
                if d_domain and self._domains_aligned(d_domain, from_domain, adkim):
                    dkim_aligned = True
                    break
        base["dkim_aligned"] = dkim_aligned

        # ── 5. Final disposition ──────────────────────────────────────────
        # DMARC passes if at least one aligned mechanism passes
        if spf_aligned or dkim_aligned:
            status = "pass"
            aligned_via = []
            if spf_aligned:  aligned_via.append("SPF")
            if dkim_aligned: aligned_via.append("DKIM")
            message = (
                f"DMARC PASS — allineamento verificato tramite {' + '.join(aligned_via)} "
                f"(policy: {policy}, pct: {pct}%)"
            )
        else:
            status = "fail"
            message = (
                f"DMARC FAIL — né SPF né DKIM risultano allineati con il dominio From ({from_domain}). "
                f"Policy applicata: {policy} ({pct}%)"
            )

        return {**base, "status": status, "message": message}

    def _fetch_dmarc_record(self, domain: str) -> tuple[str, str]:
        """
        Fetch DMARC TXT record, walking up to the organizational domain if needed.
        Returns (record_text, lookup_domain) or ("", "").
        """
        # Try exact domain first, then remove one label at a time (org-domain walk)
        labels = domain.split(".")
        for i in range(len(labels) - 1):
            candidate = ".".join(labels[i:])
            dmarc_host = f"_dmarc.{candidate}"
            try:
                for rdata in self.resolver.resolve(dmarc_host, "TXT"):
                    txt = rdata.to_text().strip('"')
                    if txt.startswith("v=DMARC1"):
                        return txt, candidate
            except Exception:
                continue
        return "", ""

    @staticmethod
    def _domains_aligned(check_domain: str, from_domain: str, mode: str) -> bool:
        """
        True if check_domain aligns with from_domain under the given mode.
          strict  (s): exact match required
          relaxed (r): organizational domain (last two labels) must match
        """
        check_domain = check_domain.lower().lstrip(".")
        from_domain  = from_domain.lower().lstrip(".")

        if mode == "s":
            return check_domain == from_domain

        # Relaxed: extract org domain (last two labels, ignoring ccTLD quirks)
        def org(d: str) -> str:
            parts = d.split(".")
            return ".".join(parts[-2:]) if len(parts) >= 2 else d

        return org(check_domain) == org(from_domain)

    # ── AbuseIPDB ─────────────────────────────────────────────────────────

    def check_ip_reputation(self, ip: str) -> dict:
        """
        Interroga l'API AbuseIPDB v2 per ottenere la reputazione di un IP.

        Returns
        -------
        {
          "status"               : "ok" | "skipped" | "error",
          "ip"                   : str,
          "abuseConfidenceScore" : int,        # 0–100
          "totalReports"         : int,
          "numDistinctUsers"     : int,
          "countryCode"          : str,
          "isp"                  : str,
          "domain"               : str,
          "isWhitelisted"        : bool,
          "usageType"            : str,
          "lastReportedAt"       : str | None,
          "url"                  : str,        # link diretto alla pagina AbuseIPDB
          "message"              : str,
        }
        """
        base = {
            "ip":                   ip,
            "abuseConfidenceScore": 0,
            "totalReports":         0,
            "numDistinctUsers":     0,
            "countryCode":          "",
            "isp":                  "",
            "domain":               "",
            "isWhitelisted":        False,
            "usageType":            "",
            "lastReportedAt":       None,
            "url":                  f"https://www.abuseipdb.com/check/{ip}",
        }

        if not ip:
            return {**base, "status": "skipped", "message": "Nessun IP fornito"}

        if not ABUSEIPDB_API_KEY:
            return {**base, "status": "skipped",
                    "message": "API key AbuseIPDB non configurata — lookup saltato"}

        params = urllib.parse.urlencode({"ipAddress": ip, "maxAgeInDays": "90"})
        url    = f"{ABUSEIPDB_ENDPOINT}?{params}"
        req    = urllib.request.Request(
            url,
            headers={
                "Key":    ABUSEIPDB_API_KEY,
                "Accept": "application/json",
            },
        )

        try:
            with urllib.request.urlopen(req, timeout=6) as resp:
                payload = json.loads(resp.read().decode("utf-8"))
        except urllib.error.HTTPError as exc:
            return {**base, "status": "error",
                    "message": f"AbuseIPDB HTTP {exc.code}: {exc.reason}"}
        except Exception as exc:
            return {**base, "status": "error",
                    "message": f"Errore AbuseIPDB: {exc}"}

        data = payload.get("data", {})
        score = int(data.get("abuseConfidenceScore") or 0)

        return {
            **base,
            "status":               "ok",
            "abuseConfidenceScore": score,
            "totalReports":         int(data.get("totalReports") or 0),
            "numDistinctUsers":     int(data.get("numDistinctUsers") or 0),
            "countryCode":          data.get("countryCode") or "",
            "isp":                  data.get("isp") or "",
            "domain":               data.get("domain") or "",
            "isWhitelisted":        bool(data.get("isWhitelisted")),
            "usageType":            data.get("usageType") or "",
            "lastReportedAt":       data.get("lastReportedAt"),
            "message": (
                f"Score: {score}/100 — {int(data.get('totalReports') or 0)} segnalazioni "
                f"da {int(data.get('numDistinctUsers') or 0)} utenti distinti"
            ),
        }


# ── smoke test ─────────────────────────────────────────────────────────────

if __name__ == "__main__":
    validator = EmailSecurityValidator()

    # SPF — requires a real sender IP and Return-Path address
    print("=== SPF ===")
    spf = validator.check_spf(
        sender_ip="209.85.220.41",       # a Gmail sending IP
        mail_from="test@gmail.com",
    )
    print(spf)

    # DMARC — requires spf/dkim results
    print("\n=== DMARC ===")
    dmarc = validator.check_dmarc(
        from_address="test@gmail.com",
        spf_result=spf["status"],
        spf_domain=spf["domain"],
        dkim_results=[],                 # no DKIM sigs for this quick test
    )
    print(dmarc)
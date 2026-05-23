import re
import json
import socket
import urllib.request
import urllib.parse
import urllib.error
import dns.resolver
from typing import Optional

# Config centralizzata: risolve .env in locale, st.secrets su Streamlit Cloud.
# Nessun import di streamlit qui — validators.py rimane usabile in script standalone.
from src.config import ABUSEIPDB_API_KEY, VIRUSTOTAL_API_KEY

# ── Endpoint ───────────────────────────────────────────────────────────────
ABUSEIPDB_ENDPOINT  = "https://api.abuseipdb.com/api/v2/check"
VIRUSTOTAL_ENDPOINT = "https://www.virustotal.com/api/v3/files"

# ── optional imports with graceful fallback ────────────────────────────────
try:
    import spf as pyspf
    _SPF_AVAILABLE = True
except ImportError:
    _SPF_AVAILABLE = False

try:
    import dkim
    _DKIM_AVAILABLE = True
except ImportError:
    _DKIM_AVAILABLE = False


# ── helpers ────────────────────────────────────────────────────────────────

def _extract_address(raw: Optional[str]) -> Optional[str]:
    """Pull a bare address out of 'Display Name <user@domain>' or plain 'user@domain'."""
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
        mail_from: str,
        helo_domain: str = "",
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
          "record"     : str,
          "domain"     : str,
          "sender_ip"  : str,
          "mail_from"  : str,
          "message"    : str,
          "library"    : "pyspf" | "dns-presence-only"
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
            return {**base, **self._spf_presence_only(domain)}

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

        signatures = []
        overall    = "none"

        try:
            d = dkim.DKIM(raw_eml_bytes)
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
                sig_info["d_domain"]  = d_match.group(1).rstrip(";") if d_match else "?"
                sig_info["selector"]  = s_match.group(1).rstrip(";") if s_match else "?"
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

    def _dkim_presence_only(self, raw_eml_bytes: bytes) -> dict:
        """Fallback when dkimpy is not installed."""
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

    # ── DMARC ─────────────────────────────────────────────────────────────

    def check_dmarc(
        self,
        from_address: str,
        spf_result: str,
        spf_domain: str,
        dkim_results: list,
    ) -> dict:
        """
        Full DMARC evaluation including record lookup, policy parsing,
        SPF/DKIM alignment check and final pass/fail disposition.

        Returns
        -------
        {
          "status"          : "pass" | "fail" | "none" | "error",
          "policy"          : "none" | "quarantine" | "reject",
          "subdomain_policy": str,
          "pct"             : int,
          "adkim"           : "r" | "s",
          "aspf"            : "r" | "s",
          "record"          : str,
          "domain"          : str,
          "spf_aligned"     : bool,
          "dkim_aligned"    : bool,
          "message"         : str,
          "rua"             : str,
          "ruf"             : str,
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

        record, lookup_domain = self._fetch_dmarc_record(from_domain)
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
        rua              = tags.get("rua",   "")
        ruf              = tags.get("ruf",   "")

        base.update({
            "policy":           policy,
            "subdomain_policy": subdomain_policy,
            "pct":              pct,
            "adkim":            adkim,
            "aspf":             aspf,
            "rua":              rua,
            "ruf":              ruf,
        })

        spf_aligned = False
        if spf_result == "pass" and spf_domain:
            spf_aligned = self._domains_aligned(spf_domain, from_domain, aspf)
        base["spf_aligned"] = spf_aligned

        dkim_aligned = False
        for sig in (dkim_results or []):
            if sig.get("result") == "pass":
                d_domain = sig.get("d_domain", "")
                if d_domain and self._domains_aligned(d_domain, from_domain, adkim):
                    dkim_aligned = True
                    break
        base["dkim_aligned"] = dkim_aligned

        if spf_aligned or dkim_aligned:
            status      = "pass"
            aligned_via = []
            if spf_aligned:  aligned_via.append("SPF")
            if dkim_aligned: aligned_via.append("DKIM")
            message = (
                f"DMARC PASS — allineamento verificato tramite {' + '.join(aligned_via)} "
                f"(policy: {policy}, pct: {pct}%)"
            )
        else:
            status  = "fail"
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
        labels = domain.split(".")
        for i in range(len(labels) - 1):
            candidate  = ".".join(labels[i:])
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

        def org(d: str) -> str:
            parts = d.split(".")
            return ".".join(parts[-2:]) if len(parts) >= 2 else d

        return org(check_domain) == org(from_domain)

    # ── AbuseIPDB — metodo privato HTTP ───────────────────────────────────

    def _abuseipdb_call(self, ip: str) -> dict:
        """
        Chiamata raw all'API AbuseIPDB v2 per un singolo IP.
        Restituisce il dict "data" della risposta, o lancia eccezione.
        """
        params = urllib.parse.urlencode({"ipAddress": ip, "maxAgeInDays": "90"})
        url    = f"{ABUSEIPDB_ENDPOINT}?{params}"
        req    = urllib.request.Request(
            url,
            headers={"Key": ABUSEIPDB_API_KEY, "Accept": "application/json"},
        )
        with urllib.request.urlopen(req, timeout=6) as resp:
            return json.loads(resp.read().decode("utf-8")).get("data", {})

    @staticmethod
    def _format_abuseipdb(data: dict, lookup_key: str) -> dict:
        """Normalizza il dict 'data' di AbuseIPDB in un risultato uniforme."""
        score = int(data.get("abuseConfidenceScore") or 0)
        ip    = data.get("ipAddress", lookup_key)
        return {
            "status":               "ok",
            "ip":                   ip,
            "abuseConfidenceScore": score,
            "totalReports":         int(data.get("totalReports") or 0),
            "numDistinctUsers":     int(data.get("numDistinctUsers") or 0),
            "countryCode":          data.get("countryCode") or "",
            "isp":                  data.get("isp") or "",
            "domain":               data.get("domain") or "",
            "isWhitelisted":        bool(data.get("isWhitelisted")),
            "usageType":            data.get("usageType") or "",
            "lastReportedAt":       data.get("lastReportedAt"),
            "url":                  f"https://www.abuseipdb.com/check/{ip}",
            "message": (
                f"Score: {score}/100 — {int(data.get('totalReports') or 0)} segnalazioni "
                f"da {int(data.get('numDistinctUsers') or 0)} utenti distinti"
            ),
        }

    # ── AbuseIPDB — IP ────────────────────────────────────────────────────

    def check_ip_reputation(self, ip: str) -> dict:
        """
        Interroga AbuseIPDB v2 per la reputazione di un indirizzo IP.

        Returns
        -------
        {
          "status"               : "ok" | "skipped" | "error",
          "ip"                   : str,
          "abuseConfidenceScore" : int,
          "totalReports"         : int,
          "numDistinctUsers"     : int,
          "countryCode"          : str,
          "isp"                  : str,
          "domain"               : str,
          "isWhitelisted"        : bool,
          "usageType"            : str,
          "lastReportedAt"       : str | None,
          "url"                  : str,
          "message"              : str,
        }
        """
        base = {
            "ip": ip, "abuseConfidenceScore": 0, "totalReports": 0,
            "numDistinctUsers": 0, "countryCode": "", "isp": "", "domain": "",
            "isWhitelisted": False, "usageType": "", "lastReportedAt": None,
            "url": f"https://www.abuseipdb.com/check/{ip}",
        }
        if not ip:
            return {**base, "status": "skipped", "message": "Nessun IP fornito"}
        if not ABUSEIPDB_API_KEY:
            return {**base, "status": "skipped",
                    "message": "API key AbuseIPDB non configurata — lookup saltato"}
        try:
            data = self._abuseipdb_call(ip)
            return self._format_abuseipdb(data, ip)
        except urllib.error.HTTPError as exc:
            return {**base, "status": "error",
                    "message": f"AbuseIPDB HTTP {exc.code}: {exc.reason}"}
        except Exception as exc:
            return {**base, "status": "error",
                    "message": f"Errore AbuseIPDB: {exc}"}

    # ── AbuseIPDB — Dominio ───────────────────────────────────────────────

    def check_domain_reputation(self, domain: str) -> dict:
        """
        Controlla la reputazione di un dominio su AbuseIPDB.

        Strategia a due livelli:
          1. Prova il dominio direttamente tramite l'endpoint /check.
          2. Se fallisce, risolve il dominio in IP via DNS e ripete il lookup.

        Returns
        -------
        Stessa struttura di check_ip_reputation, più:
          "domain_queried" : str
          "resolved_ip"    : str
          "lookup_method"  : "direct" | "dns-fallback" | "skipped" | "error"
        """
        base = {
            "domain_queried":       domain,
            "resolved_ip":          "",
            "lookup_method":        "error",
            "ip":                   "",
            "abuseConfidenceScore": 0,
            "totalReports":         0,
            "numDistinctUsers":     0,
            "countryCode":          "",
            "isp":                  "",
            "domain":               "",
            "isWhitelisted":        False,
            "usageType":            "",
            "lastReportedAt":       None,
            "url":                  f"https://www.abuseipdb.com/check/{domain}",
            "message":              "",
        }

        if not domain:
            return {**base, "status": "skipped",
                    "lookup_method": "skipped",
                    "message": "Nessun dominio fornito"}
        if not ABUSEIPDB_API_KEY:
            return {**base, "status": "skipped",
                    "lookup_method": "skipped",
                    "message": "API key AbuseIPDB non configurata — lookup saltato"}

        try:
            data = self._abuseipdb_call(domain)
            if data:
                result = self._format_abuseipdb(data, domain)
                result["domain_queried"] = domain
                result["resolved_ip"]    = data.get("ipAddress", "")
                result["lookup_method"]  = "direct"
                return result
        except urllib.error.HTTPError as exc:
            if exc.code not in (422, 400):
                return {**base, "status": "error",
                        "message": f"AbuseIPDB HTTP {exc.code}: {exc.reason}"}
        except Exception:
            pass

        resolved_ip = ""
        try:
            resolved_ip = socket.gethostbyname(domain)
        except Exception as exc:
            return {**base, "status": "error",
                    "lookup_method": "dns-fallback",
                    "message": f"Impossibile risolvere il dominio `{domain}` in IP: {exc}"}

        try:
            data   = self._abuseipdb_call(resolved_ip)
            result = self._format_abuseipdb(data, resolved_ip)
            result["domain_queried"] = domain
            result["resolved_ip"]    = resolved_ip
            result["lookup_method"]  = "dns-fallback"
            return result
        except urllib.error.HTTPError as exc:
            return {**base, "status": "error",
                    "lookup_method": "dns-fallback",
                    "resolved_ip":   resolved_ip,
                    "message": f"AbuseIPDB HTTP {exc.code} (IP {resolved_ip}): {exc.reason}"}
        except Exception as exc:
            return {**base, "status": "error",
                    "lookup_method": "dns-fallback",
                    "resolved_ip":   resolved_ip,
                    "message": f"Errore AbuseIPDB (IP {resolved_ip}): {exc}"}

    # ── VirusTotal — File Hash ─────────────────────────────────────────────

    def check_file_hash(self, sha256: str) -> dict:
        """
        Interroga VirusTotal v3 per la reputazione di un hash SHA-256.

        Flusso:
          GET /files/{sha256}
            200 → file noto a VT, restituisce analisi completa
            404 → file mai sottomesso a VT (non significa che sia pulito)
            401 → API key non valida
            429 → rate limit superato (free tier: 4 req/min)

        Returns
        -------
        {
          "status"           : "malicious" | "suspicious" | "clean" |
                               "unknown"   | "not_found"  |
                               "skipped"   | "error",
          "sha256"           : str,
          "malicious"        : int,
          "suspicious"       : int,
          "undetected"       : int,
          "total_engines"    : int,
          "detection_ratio"  : str,
          "threat_label"     : str,
          "file_type"        : str,
          "file_name"        : str,
          "first_submission" : str,
          "last_analysis"    : str,
          "permalink"        : str,
          "message"          : str,
        }
        """
        base = {
            "sha256":           sha256,
            "malicious":        0,
            "suspicious":       0,
            "undetected":       0,
            "total_engines":    0,
            "detection_ratio":  "—",
            "threat_label":     "",
            "file_type":        "",
            "file_name":        "",
            "first_submission": "",
            "last_analysis":    "",
            "permalink":        f"https://www.virustotal.com/gui/file/{sha256}",
        }

        if not sha256:
            return {**base, "status": "skipped",
                    "message": "Nessun hash fornito"}
        if not VIRUSTOTAL_API_KEY:
            return {**base, "status": "skipped",
                    "message": "API key VirusTotal non configurata — lookup saltato"}

        url = f"{VIRUSTOTAL_ENDPOINT}/{sha256}"
        req = urllib.request.Request(
            url,
            headers={
                "x-apikey": VIRUSTOTAL_API_KEY,
                "Accept":   "application/json",
            },
        )

        try:
            with urllib.request.urlopen(req, timeout=10) as resp:
                data = json.loads(resp.read().decode("utf-8"))
            return self._format_vt_file(data, base)

        except urllib.error.HTTPError as exc:
            if exc.code == 404:
                return {**base, "status": "not_found",
                        "message": "Hash non trovato su VirusTotal — file mai sottomesso o molto recente"}
            if exc.code == 401:
                return {**base, "status": "error",
                        "message": "API key VirusTotal non valida (HTTP 401)"}
            if exc.code == 429:
                return {**base, "status": "error",
                        "message": "Rate limit VirusTotal superato (free tier: 4 req/min) — riprova tra poco"}
            return {**base, "status": "error",
                    "message": f"VirusTotal HTTP {exc.code}: {exc.reason}"}
        except Exception as exc:
            return {**base, "status": "error",
                    "message": f"Errore VirusTotal: {exc}"}

    @staticmethod
    def _format_vt_file(data: dict, base: dict) -> dict:
        """
        Normalizza la risposta JSON di VT /files/{hash} in un dict uniforme.

        Struttura risposta VT:
          data.attributes.last_analysis_stats
          data.attributes.popular_threat_classification.suggested_threat_label
          data.attributes.type_description
          data.attributes.names[0]
          data.attributes.first_submission_date  (epoch int)
          data.attributes.last_analysis_date     (epoch int)
        """
        import datetime

        attrs = data.get("data", {}).get("attributes", {})
        stats = attrs.get("last_analysis_stats", {})

        malicious  = int(stats.get("malicious",  0))
        suspicious = int(stats.get("suspicious", 0))
        undetected = int(stats.get("undetected", 0))
        harmless   = int(stats.get("harmless",   0))
        total      = malicious + suspicious + undetected + harmless

        ptc          = attrs.get("popular_threat_classification") or {}
        threat_label = ptc.get("suggested_threat_label", "")

        file_type = attrs.get("type_description", "")
        names     = attrs.get("names") or []
        file_name = names[0] if names else ""

        def _epoch_to_iso(val) -> str:
            if not val:
                return ""
            try:
                return datetime.datetime.fromtimestamp(
                    int(val), tz=datetime.timezone.utc
                ).strftime("%Y-%m-%d %H:%M UTC")
            except Exception:
                return str(val)

        first_sub = _epoch_to_iso(attrs.get("first_submission_date"))
        last_anal = _epoch_to_iso(attrs.get("last_analysis_date"))

        if malicious > 0:
            status = "malicious"
        elif suspicious > 0:
            status = "suspicious"
        elif total > 0:
            status = "clean"
        else:
            status = "unknown"

        detection_ratio = f"{malicious + suspicious} / {total}" if total else "0 / 0"

        message_parts = [f"{malicious} engine su {total} lo segnalano come malevolo"]
        if suspicious:
            message_parts.append(f"{suspicious} come sospetto")
        if threat_label:
            message_parts.append(f"minaccia rilevata: {threat_label}")

        return {
            **base,
            "status":           status,
            "malicious":        malicious,
            "suspicious":       suspicious,
            "undetected":       undetected,
            "total_engines":    total,
            "detection_ratio":  detection_ratio,
            "threat_label":     threat_label,
            "file_type":        file_type,
            "file_name":        file_name,
            "first_submission": first_sub,
            "last_analysis":    last_anal,
            "message":          " — ".join(message_parts),
        }


# ── smoke test ─────────────────────────────────────────────────────────────

if __name__ == "__main__":
    validator = EmailSecurityValidator()

    print("=== SPF ===")
    spf = validator.check_spf(
        sender_ip="209.85.220.41",
        mail_from="test@gmail.com",
    )
    print(spf)

    print("\n=== DMARC ===")
    dmarc = validator.check_dmarc(
        from_address="test@gmail.com",
        spf_result=spf["status"],
        spf_domain=spf["domain"],
        dkim_results=[],
    )
    print(dmarc)

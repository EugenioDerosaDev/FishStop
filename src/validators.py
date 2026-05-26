import re
import json
import socket
import urllib.request
import urllib.parse
import urllib.error
import dns.resolver
import requests
from typing import Optional

# Config centralizzata
from src.config import ABUSEIPDB_API_KEY, VIRUSTOTAL_API_KEY

ABUSEIPDB_ENDPOINT  = "https://api.abuseipdb.com/api/v2/check"
VIRUSTOTAL_ENDPOINT = "https://www.virustotal.com/api/v3/files"

_IPAPI_FIELDS = (
    "status,message,country,countryCode,regionName,city,"
    "zip,lat,lon,timezone,isp,org,as,proxy,hosting,query"
)
IPAPI_ENDPOINT = "http://ip-api.com/json/{ip}?fields=" + _IPAPI_FIELDS

# Inizializziamo una sessione riutilizzabile Keep-Alive a livello di modulo
_session = requests.Session()
_session.headers.update({"Accept": "application/json"})

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
    tags: dict = {}
    for part in record.split(";"):
        part = part.strip()
        if "=" in part:
            k, _, v = part.partition("=")
            tags[k.strip().lower()] = v.strip().lower()
    return tags


class EmailSecurityValidator:
    """
    Validates SPF, DKIM, and DMARC for a received .eml with Enterprise SOC capabilities.
    """

    def __init__(self):
        self.resolver = dns.resolver.Resolver()
        self.resolver.timeout = 2.0
        self.resolver.lifetime = 4.0

    # ── SPF ENTERPRISE-LEVEL ───────────────────────────────────────────────

    def check_spf(
        self,
        sender_ip: str,
        mail_from: str,
        helo_domain: str = "",
    ) -> dict:
        """
        Valutazione SPF Enterprise-Grade conforme a RFC 7208.
        Rileva attivamente anomalie di configurazione, errori di sintassi,
        record multipli conflittuali e attacchi basati su DNS amplification (10+ lookups).
        """
        addr   = _extract_address(mail_from) or mail_from
        domain = _extract_domain(addr)

        # Gestione indirizzo nullo (es. Bounce/NDR) -> usa HELO come da specifica RFC
        if (not addr or addr == "<>") and helo_domain:
            domain = _extract_domain(helo_domain) or helo_domain

        base = {
            "sender_ip":  sender_ip,
            "mail_from":  addr,
            "domain":     domain,
            "record":     "",
            "library":    "pyspf",
            "warnings":   [],  # Indicatori di rischio/anomalie per il SOC
            "dns_lookups": None
        }

        if not sender_ip or not domain:
            return {**base, "status": "error", "message": "sender_ip o domain mancanti"}

        # 1. Ispezione statica e preventiva del Record DNS (Analisi di conformità SOC)
        spf_records = self._fetch_all_spf_records(domain)
        
        if len(spf_records) > 1:
            base["warnings"].append("MULTIPLE_SPF_RECORDS_DETECTED")
            return {
                **base,
                "status": "permerror",
                "record": " | ".join(spf_records),
                "message": f"PermError: Trovati {len(spf_records)} record v=spf1. Il dominio viola l'RFC 7208."
            }
        
        record_str = spf_records[0] if spf_records else ""
        base["record"] = record_str

        if record_str:
            # Rilevamento configurazioni permissive insicure
            if "+all" in record_str or " ?all" in record_str:
                base["warnings"].append("INSECURE_ALL_MECHANISM")
            # Conteggio statico approssimativo dei DNS lookups (include, a, mx, ptr, exists, redirect)
            lookups_count = len(re.findall(r'\b(include|a|mx|ptr|exists|redirect)\b', record_str))
            base["dns_lookups"] = lookups_count
            if lookups_count > 10:
                base["warnings"].append("EXCEEDS_10_DNS_LOOKUPS_LIMIT")

        if not _SPF_AVAILABLE:
            base["library"] = "dns-presence-only"
            return {**base, **self._spf_presence_only(record_str)}

        # 2. Esecuzione del motore di valutazione crittografico/sintattico
        try:
            # Validazione preventiva della sintassi IP
            socket.inet_pton(socket.AF_INET, sender_ip) if ":" not in sender_ip else socket.inet_pton(socket.AF_INET6, sender_ip)
        except socket.error:
            return {**base, "status": "error", "message": f"IP sorgente malformato: {sender_ip}"}

        try:
            # Esecuzione nativa pyspf
            result, explanation = pyspf.check2(
                i=sender_ip,
                s=addr if addr and addr != "<>" else f"postmaster@{domain}",
                h=helo_domain or domain,
            )
            result = (result or "none").lower()
            
            # Arricchimento dei messaggi di errore per l'analista SOC
            if result == "permerror" and not base["warnings"]:
                base["warnings"].append("SINTAX_OR_LOOKUP_ERROR")

            return {
                **base,
                "status":  result,
                "message": explanation or f"SPF {result.upper()}",
            }
        except Exception as exc:
            # Cattura crash imprevisti del motore di parsing (es. stringhe binarie o malformazioni estreme)
            base["warnings"].append("PARSER_CRASH")
            return {**base, "status": "permerror", "message": f"Frenata d'emergenza del parser SPF: {exc}"}

    def _fetch_all_spf_records(self, domain: str) -> list:
        """Recupera tutti i record TXT che iniziano con v=spf1 senza fermarsi al primo."""
        records = []
        try:
            answers = self.resolver.resolve(domain, "TXT")
            for rdata in answers:
                # Gestione dei record TXT frammentati in più stringhe
                txt = "".join([part.decode('utf-8', errors='ignore') if isinstance(part, bytes) else part for part in rdata.strings]).strip()
                if txt.lower().startswith("v=spf1"):
                    records.append(txt)
        except Exception:
            pass
        return records

    def _spf_presence_only(self, record: str) -> dict:
        if record:
            return {
                "status":  "record-found",
                "message": "Record SPF presente. Installare la libreria 'pyspf' per la validazione dinamica IP.",
            }
        return {
            "status":  "none",
            "message": "Nessun record SPF registrato nel DNS per questo dominio.",
        }

    # ── DKIM ──────────────────────────────────────────────────────────────

    def check_dkim(self, raw_eml_bytes: bytes) -> dict:
        if not _DKIM_AVAILABLE:
            return self._dkim_presence_only(raw_eml_bytes)

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
        import email as _email
        msg     = _email.message_from_bytes(raw_eml_bytes)
        present = bool(msg.get("DKIM-Signature"))
        return {
            "status":     "present" if present else "none",
            "signatures": [],
            "message":    "Firma DKIM rilevata (installare dkimpy per la verifica crittografica)",
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
            return {**base, "status": "error", "message": "Impossibile estrarre il dominio dall'header From"}

        record, lookup_domain = self._fetch_dmarc_record(from_domain)
        if not record:
            return {**base, "status": "none", "message": f"Nessun record DMARC trovato per {from_domain}"}

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
        # Un SPF pass è allineato solo se il dominio valutato (Return-Path) è allineato con il From
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
            message = f"DMARC PASS — allineamento verificato tramite {' + '.join(aligned_via)} (policy: {policy})"
        else:
            status  = "fail"
            message = f"DMARC FAIL — né SPF né DKIM risultano allineati con il dominio From ({from_domain})."

        return {**base, "status": status, "message": message}

    def _fetch_dmarc_record(self, domain: str) -> tuple[str, str]:
        labels = domain.split(".")
        for i in range(len(labels) - 1):
            candidate  = ".".join(labels[i:])
            dmarc_host = f"_dmarc.{candidate}"
            try:
                for rdata in self.resolver.resolve(dmarc_host, "TXT"):
                    txt = "".join([part.decode('utf-8', errors='ignore') if isinstance(part, bytes) else part for part in rdata.strings]).strip()
                    if txt.startswith("v=DMARC1"):
                        return txt, candidate
            except Exception:
                continue
        return "", ""

    @staticmethod
    def _domains_aligned(check_domain: str, from_domain: str, mode: str) -> bool:
        check_domain = check_domain.lower().lstrip(".")
        from_domain  = from_domain.lower().lstrip(".")
        if mode == "s":
            return check_domain == from_domain
        def org(d: str) -> str:
            parts = d.split(".")
            return ".".join(parts[-2:]) if len(parts) >= 2 else d
        return org(check_domain) == org(from_domain)

    # ── API ALLINEATE AD ALTA VELOCITÀ (requests.Session) ────────────────

    def _abuseipdb_call(self, ip: str) -> dict:
        """Sostituito urllib con requests + Keep-Alive session per massimizzare le performance."""
        params = {"ipAddress": ip, "maxAgeInDays": "90"}
        headers = {"Key": ABUSEIPDB_API_KEY}
        response = _session.get(ABUSEIPDB_ENDPOINT, params=params, headers=headers, timeout=4)
        response.raise_for_status()
        return response.json().get("data", {})

    @staticmethod
    def _format_abuseipdb(data: dict, lookup_key: str) -> dict:
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
            "message": f"Score: {score}/100 — {int(data.get('totalReports') or 0)} segnalazioni.",
        }

    def check_ip_reputation(self, ip: str) -> dict:
        base = {"ip": ip, "abuseConfidenceScore": 0, "totalReports": 0, "numDistinctUsers": 0, "isWhitelisted": False}
        if not ip: return {**base, "status": "skipped", "message": "Nessun IP"}
        if not ABUSEIPDB_API_KEY: return {**base, "status": "skipped", "message": "API key assente"}
        try:
            data = self._abuseipdb_call(ip)
            return self._format_abuseipdb(data, ip)
        except Exception as exc:
            return {**base, "status": "error", "message": f"Errore AbuseIPDB: {exc}"}

    def check_domain_reputation(self, domain: str) -> dict:
        base = {"domain_queried": domain, "resolved_ip": "", "lookup_method": "error", "abuseConfidenceScore": 0}
        if not domain: return {**base, "status": "skipped", "message": "Nessun dominio"}
        if not ABUSEIPDB_API_KEY: return {**base, "status": "skipped", "message": "API key assente"}
        try:
            answers = self.resolver.resolve(domain, "A")
            resolved_ip = str(answers[0])
        except Exception as exc:
            return {**base, "status": "skipped", "message": f"Dominio non risolvibile: {exc}"}
        try:
            data = self._abuseipdb_call(resolved_ip)
            result = self._format_abuseipdb(data, resolved_ip)
            result.update({"domain_queried": domain, "resolved_ip": resolved_ip, "lookup_method": "dns-resolved"})
            return result
        except Exception as exc:
            return {**base, "status": "error", "message": f"Errore su IP {resolved_ip}: {exc}"}

    def check_file_hash(self, sha256: str) -> dict:
        base = {"sha256": sha256, "malicious": 0, "suspicious": 0, "total_engines": 0}
        if not sha256: return {**base, "status": "skipped", "message": "No hash"}
        if not VIRUSTOTAL_API_KEY: return {**base, "status": "skipped", "message": "VT key assente"}
        
        url = f"{VIRUSTOTAL_ENDPOINT}/{sha256}"
        headers = {"x-apikey": VIRUSTOTAL_API_KEY}
        try:
            response = _session.get(url, headers=headers, timeout=5)
            if response.status_code == 404:
                return {**base, "status": "not_found", "message": "Hash non trovato su VT"}
            response.raise_for_status()
            return self._format_vt_file(response.json(), base)
        except Exception as exc:
            return {**base, "status": "error", "message": f"Errore VT: {exc}"}

    @staticmethod
    def _format_vt_file(data: dict, base: dict) -> dict:
        attrs = data.get("data", {}).get("attributes", {})
        stats = attrs.get("last_analysis_stats", {})
        malicious = int(stats.get("malicious", 0))
        suspicious = int(stats.get("suspicious", 0))
        total = sum(int(v) for v in stats.values())
        return {
            **base,
            "status": "malicious" if malicious > 0 else "clean",
            "malicious": malicious,
            "suspicious": suspicious,
            "total_engines": total,
            "message": f"{malicious} engine rilevano minacce su {total}.",
        }

    def geolocate_ip(self, ip: str) -> dict:
        base = {"ip": ip, "country": "", "is_proxy": False, "is_hosting": False}
        if not ip or ip.startswith("10.") or ip.startswith("192.168.") or ip.startswith("127."):
            return {**base, "status": "skipped", "message": "IP privato o assente"}
        try:
            response = _session.get(IPAPI_ENDPOINT.format(ip=ip), timeout=4)
            response.raise_for_status()
            data = response.json()
            if data.get("status") != "success":
                return {**base, "status": "skipped", "message": data.get("message", "fail")}
            return {
                "status": "ok", "ip": data.get("query", ip), "country": data.get("country", ""),
                "is_proxy": bool(data.get("proxy")), "is_hosting": bool(data.get("hosting")),
                "message": f"{data.get('city')}, {data.get('country')}",
            }
        except Exception as exc:
            return {**base, "status": "error", "message": f"Errore geo: {exc}"}


if __name__ == "__main__":
    validator = EmailSecurityValidator()
    print("=== SPF ENTERPRISE TEST ===")
    # Test con IP legittimo di Google Cloud / Gmail
    spf = validator.check_spf(sender_ip="209.85.220.41", mail_from="test@gmail.com")
    print(json.dumps(spf, indent=2))
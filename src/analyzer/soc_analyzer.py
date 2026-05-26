"""
analyzer/soc_analyzer.py — Motore di analisi statica ed euristica per il SOC.

Classe principale:
  EmlSOCAnalyzer.analyze(eml_path) → dict

Coordina tutti i sotto-moduli dell'analyzer:
  - received_parser  : parsing catena Received e Authentication-Results
  - link_extractor   : estrazione URL dal corpo
  - lookalike        : rilevamento domini lookalike
  - attachment       : analisi allegati via magic bytes e hash
  - html_utils       : stripping HTML per body_clean
"""

import re
import email
from email import policy
from typing import Optional

from .attachment      import analyze_attachment
from .html_utils      import strip_html
from .link_extractor  import extract_links
from .lookalike       import check_lookalike_domains, is_ip_url
from .received_parser import parse_received_hop, parse_auth_results


def _extract_domain(email_or_addr: str) -> str:
    """Restituisce la porzione dominio di un indirizzo email, in minuscolo."""
    m = re.search(r"@([\w.\-]+)", email_or_addr or "")
    return m.group(1).lower() if m else ""


class EmlSOCAnalyzer:
    """
    Parsa un file .eml grezzo e restituisce un report strutturato per il triage SOC.
    Tutta la logica è estratta dinamicamente dall'email — nessun hardcoding
    legato a messaggi specifici.
    """

    def analyze(self, eml_path: str) -> dict:
        with open(eml_path, "rb") as f:
            raw_bytes = f.read()

        msg = email.message_from_bytes(raw_bytes, policy=policy.default)
        report: dict = {}
        report["raw_eml_bytes"] = raw_bytes

        # ── 1. Campi envelope ──────────────────────────────────────────────
        report["delivered_to"] = self._header(msg, "Delivered-To")
        report["to"]           = self._header(msg, "To")
        report["from_"]        = self._header(msg, "From")
        report["subject"]      = self._header(msg, "Subject")
        report["date"]         = self._header(msg, "Date")
        report["message_id"]   = self._header(msg, "Message-Id")
        report["importance"]   = self._header(msg, "Importance") or self._header(msg, "X-Priority")
        report["mime_version"] = self._header(msg, "MIME-Version")
        report["content_type"] = self._header(msg, "Content-Type")

        # ── 2. Return-Path / Errors-To / Reply-To ─────────────────────────
        report["return_path"] = self._header(msg, "Return-Path")
        report["errors_to"]   = self._header(msg, "Errors-To")
        reply_to              = self._header(msg, "Reply-To")
        report["reply_to"]    = reply_to

        from_addr  = self._extract_address(report["from_"])
        reply_addr = self._extract_address(reply_to)
        report["reply_to_mismatch"] = bool(
            reply_addr and from_addr and reply_addr.lower() != from_addr.lower()
        )

        return_path_addr   = self._extract_address(report["return_path"])
        return_path_domain = _extract_domain(return_path_addr or "") if return_path_addr else ""
        from_domain        = _extract_domain(from_addr or "") if from_addr else ""
        report["return_path_domain_mismatch"] = bool(
            return_path_domain and from_domain
            and return_path_domain.lower() != from_domain.lower()
        )
        report["return_path_domain"] = return_path_domain

        # Display Name Spoofing: il display name contiene un indirizzo diverso dal mittente reale
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

        # ── 3. Metadata Google / routing ──────────────────────────────────
        report["x_google_smtp_source"] = self._header(msg, "X-Google-Smtp-Source")
        report["x_received"]           = self._header(msg, "X-Received")

        # ── 4. Header ARC ─────────────────────────────────────────────────
        report["arc_seal"]                   = self._header(msg, "ARC-Seal")
        report["arc_message_signature"]      = self._header(msg, "ARC-Message-Signature")
        report["arc_authentication_results"] = self._header(msg, "ARC-Authentication-Results")

        # ── 5. Catena Received ────────────────────────────────────────────
        raw_received = msg.get_all("Received") or []
        hops = [parse_received_hop(r) for r in raw_received]
        report["received_hops"]         = hops
        report["closest_to_recipient"]  = hops[0]  if hops else {}
        report["injection_server"]      = hops[1]  if len(hops) > 1 else {}
        report["closest_to_sender"]     = hops[-1] if hops else {}
        report["injection_sender_ip"]   = self._extract_spf_sender_ip(msg, hops)

        # ── 6. Received-SPF raw ───────────────────────────────────────────
        report["received_spf_raw"] = self._header(msg, "Received-SPF")

        # ── 7. Authentication-Results ─────────────────────────────────────
        auth_raw     = self._header(msg, "Authentication-Results") or ""
        arc_auth_raw = report["arc_authentication_results"] or ""
        report["auth_results"]     = parse_auth_results(auth_raw)
        report["arc_auth_results"] = parse_auth_results(arc_auth_raw)

        # ── 8. Firma DKIM ─────────────────────────────────────────────────
        report["dkim_signature_present"] = bool(msg.get("DKIM-Signature"))
        report["dkim_signature_raw"]     = self._header(msg, "DKIM-Signature")

        # ── 9. Body e allegati ────────────────────────────────────────────
        body_parts       = []
        html_parts       = []
        attachments_info = []

        for part in msg.walk():
            ct       = part.get_content_type()
            disp     = str(part.get("Content-Disposition") or "")
            encoding = str(part.get("Content-Transfer-Encoding") or "").lower().strip()
            filename = part.get_filename() or ""
            is_attach = "attachment" in disp.lower()

            if is_attach or filename:
                raw_payload = part.get_payload(decode=False)
                attachments_info.append(analyze_attachment(
                    filename=filename,
                    content_type=ct,
                    encoding=encoding,
                    raw_payload=raw_payload,
                ))
            elif ct == "text/plain":
                payload = part.get_payload(decode=True)
                if payload:
                    charset = part.get_content_charset() or "utf-8"
                    body_parts.append(payload.decode(charset, errors="ignore"))
            elif ct == "text/html":
                payload = part.get_payload(decode=True)
                if payload:
                    charset = part.get_content_charset() or "utf-8"
                    html_parts.append(payload.decode(charset, errors="ignore"))

        raw_body = "\n".join(body_parts) if body_parts else "\n".join(html_parts)
        report["body"]      = raw_body.strip()
        report["body_html"] = "\n".join(html_parts).strip() if html_parts else None

        if body_parts:
            report["body_clean"] = re.sub(r"\n{3,}", "\n\n", report["body"]).strip()
        else:
            combined_html = "\n".join(html_parts)
            report["body_clean"] = strip_html(combined_html)

        report["body_source"]        = "text/plain" if body_parts else ("text/html" if html_parts else "empty")
        report["html_strip_applied"] = (not bool(body_parts)) and bool(html_parts)
        report["attachments"]        = attachments_info

        # ── 10. Link e lookalike ──────────────────────────────────────────
        report["links"] = extract_links(
            body_plain=report["body"],
            body_html=report.get("body_html") or "",
        )
        report["lookalike_alerts"] = check_lookalike_domains(report["links"])

        # ── 11. Flag SOC ──────────────────────────────────────────────────
        report["flags"] = self._build_flags(report)

        return report

    # ── Helpers ────────────────────────────────────────────────────────────

    @staticmethod
    def _header(msg, name: str) -> Optional[str]:
        val = msg.get(name)
        if val is None:
            return None
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

    @staticmethod
    def _extract_spf_sender_ip(msg, hops: list) -> str | None:
        """
        Estrae l'IP corretto per la verifica SPF live.

        Priorità:
          1. client-ip= nell'ULTIMO Received-SPF (più vicino al mittente)
          2. smtp.remote-ip= in Authentication-Results
          3. Primo IP pubblico nell'ultimo hop Received
          4. Fallback: sender_ip dall'hop [1]
        """
        _private = re.compile(
            r'^(10\.|172\.(1[6-9]|2\d|3[01])\.|192\.168\.|127\.)'
        )

        all_rcvd_spf = msg.get_all("Received-SPF") or []
        for rcvd_spf in reversed(all_rcvd_spf):
            m = re.search(r"client-ip=([\d.a-fA-F:]+)", str(rcvd_spf), re.IGNORECASE)
            if m and not _private.match(m.group(1)):
                return m.group(1)

        auth = str(msg.get("Authentication-Results") or "")
        m = re.search(r"smtp\.remote-ip=([\d.]+)", auth, re.IGNORECASE)
        if m and not _private.match(m.group(1)):
            return m.group(1)

        if hops:
            last_hop = hops[-1]
            for ip in (last_hop.get("all_ips") or []):
                if ip and not _private.match(ip):
                    return ip

        return (hops[1].get("sender_ip") if len(hops) > 1 else None)

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

        # Return-Path domain mismatch
        if report.get("return_path_domain_mismatch"):
            _from_domain = _extract_domain(
                EmlSOCAnalyzer._extract_address(report.get("from_") or "") or ""
            )
            flag(
                "HIGH", "Return-Path",
                f"Il dominio Return-Path (`{report['return_path_domain']}`) differisce dal "
                f"dominio From (`{_from_domain}`) — il server che riceverà i bounce "
                "non è controllato dal mittente dichiarato. Tipico di phishing o BEC."
            )
        elif report.get("return_path") and not report.get("return_path_domain"):
            flag("LOW", "Return-Path", "Return-Path presente ma dominio non estraibile")

        # HTML stripping applicato
        if report.get("html_strip_applied"):
            flag("INFO", "Body",
                 "Corpo email in formato HTML puro: tag rimossi prima dell'analisi AI. "
                 "Possibile offuscamento testuale nascosto nei tag.")

        # Display Name Spoofing
        dns_val = report.get("display_name_spoofing")
        if dns_val:
            flag(
                "HIGH", "Display Name",
                f"Il Display Name del campo From contiene un indirizzo email (`{dns_val}`). "
                "Tecnica classica di Display Name Spoofing: i client di posta mostrano "
                "l'indirizzo embedded invece del mittente reale."
            )

        # Injection server
        inj = report.get("injection_server", {})
        if inj.get("sender_ip"):
            flag("INFO", "Received",
                 f"Server di iniezione: {inj.get('sender_domain') or inj.get('from_host', '?')} "
                 f"[{inj['sender_ip']}] — verificare reputazione IP/dominio")

        # Anomalie allegati
        for att in report.get("attachments", []):
            if att.get("anomaly"):
                flag("HIGH", "Attachment",
                     f"'{att['filename']}': {att['anomaly']}")
            if att.get("magic_bytes_hex"):
                flag("INFO", "Attachment",
                     f"'{att['filename']}': magic bytes {att['magic_bytes_hex'][:8]}… "
                     f"→ formato rilevato: {att['magic_detected_format'] or 'sconosciuto'}")

        # Link anomalie: IP-direct e lookalike
        for lnk in report.get("links", []):
            if lnk.get("is_ip"):
                flag(
                    "HIGH", "Link",
                    "URL con IP nudo rilevato: `" + lnk["url"] + "` — evita DNS lookup, "
                    "tipico di phishing o C2",
                )

        for alert in report.get("lookalike_alerts", []):
            technique_label = {
                "edit_distance": "Edit-distance",
                "homoglyph":     "Omoglifi Unicode",
                "typosquatting": "Typosquatting",
            }.get(alert["technique"], alert["technique"])
            flag(
                "HIGH", "Lookalike Domain",
                technique_label + ": `" + alert["host"] + "` assomiglia a `"
                + alert["matched_brand"] + "` — " + alert["detail"],
            )

        return flags

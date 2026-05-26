"""
analysis/flags.py — SOC flag list builder.

Responsibility:
  - build_flags(): inspects the fully assembled SOC report dict and returns
    a list of {level, field, message} flag dicts for display in the triage UI.

All detection logic that produces user-visible alerts lives here.
Input is the completed report dict; output is purely presentational.
"""

from analysis.header import extract_domain, extract_address


def build_flags(report: dict) -> list[dict]:
    """
    Inspects the assembled SOC report and returns a prioritized flag list.

    Levels: HIGH | MEDIUM | LOW | INFO
    """
    flags: list[dict] = []

    def flag(level: str, field: str, message: str) -> None:
        flags.append({"level": level, "field": field, "message": message})

    # ── SPF ───────────────────────────────────────────────────────────────
    spf = report["auth_results"].get("SPF") or report["arc_auth_results"].get("SPF")
    if spf:
        if spf["status"] != "pass":
            flag("HIGH", "SPF",
                 f"SPF {spf['status'].upper()} — domain does not authorise the sending server")
    else:
        flag("MEDIUM", "SPF", "No SPF result found in headers")

    # ── DKIM ──────────────────────────────────────────────────────────────
    if not report["dkim_signature_present"]:
        flag("MEDIUM", "DKIM", "DKIM signature absent from headers")
    dkim = report["auth_results"].get("DKIM") or report["arc_auth_results"].get("DKIM")
    if dkim and dkim["status"] != "pass":
        flag("HIGH", "DKIM", f"DKIM {dkim['status'].upper()}")

    # ── DMARC ─────────────────────────────────────────────────────────────
    dmarc = report["auth_results"].get("DMARC") or report["arc_auth_results"].get("DMARC")
    if dmarc and dmarc["status"] not in ("pass", "bestguesspass"):
        flag("HIGH", "DMARC", f"DMARC {dmarc['status'].upper()}")
    elif not dmarc:
        flag("LOW", "DMARC", "No DMARC policy detected in headers")

    # ── Reply-To mismatch ─────────────────────────────────────────────────
    if report["reply_to_mismatch"]:
        flag("HIGH", "Reply-To",
             f"Reply-To ({report['reply_to']}) differs from From ({report['from_']}) "
             "— possible harvesting")

    # ── Return-Path domain mismatch ───────────────────────────────────────
    if report.get("return_path_domain_mismatch"):
        _from_domain = extract_domain(
            extract_address(report.get("from_") or "") or ""
        )
        flag(
            "HIGH", "Return-Path",
            f"Return-Path domain (`{report['return_path_domain']}`) differs from "
            f"From domain (`{_from_domain}`) — bounce server is not controlled by "
            "the declared sender. Typical of phishing or BEC."
        )
    elif report.get("return_path") and not report.get("return_path_domain"):
        flag("LOW", "Return-Path", "Return-Path present but domain not extractable")

    # ── HTML strip applied ────────────────────────────────────────────────
    if report.get("html_strip_applied"):
        flag("INFO", "Body",
             "Email body is pure HTML: tags removed before AI analysis. "
             "Possible textual obfuscation hidden in tags.")

    # ── Display Name Spoofing ─────────────────────────────────────────────
    dns_val = report.get("display_name_spoofing")
    if dns_val:
        flag(
            "HIGH", "Display Name",
            f"Display Name in From field contains an email address (`{dns_val}`). "
            "Classic Display Name Spoofing: mail clients show the embedded address "
            "instead of the real sender."
        )

    # ── Injection server info ─────────────────────────────────────────────
    inj = report.get("injection_server", {})
    if inj.get("sender_ip"):
        flag("INFO", "Received",
             f"Injection server: {inj.get('sender_domain') or inj.get('from_host', '?')} "
             f"[{inj['sender_ip']}] — verify IP/domain reputation")

    # ── Attachment anomalies ──────────────────────────────────────────────
    for att in report.get("attachments", []):
        if att.get("anomaly"):
            flag("HIGH", "Attachment",
                 f"'{att['filename']}': {att['anomaly']}")
        if att.get("magic_bytes_hex"):
            flag("INFO", "Attachment",
                 f"'{att['filename']}': magic bytes {att['magic_bytes_hex'][:8]}… "
                 f"→ detected format: {att['magic_detected_format'] or 'unknown'}")

    # ── IP-direct links ───────────────────────────────────────────────────
    for lnk in report.get("links", []):
        if lnk.get("is_ip"):
            flag(
                "HIGH", "Link",
                "Bare-IP URL detected: `" + lnk["url"] + "` — bypasses DNS lookup, "
                "typical of phishing or C2",
            )

    # ── Lookalike domain alerts ───────────────────────────────────────────
    for alert in report.get("lookalike_alerts", []):
        technique_label = {
            "edit_distance": "Edit-distance",
            "homoglyph":     "Unicode homoglyphs",
            "typosquatting": "Typosquatting",
        }.get(alert["technique"], alert["technique"])
        flag(
            "HIGH", "Lookalike Domain",
            technique_label + ": `" + alert["host"] + "` resembles `"
            + alert["matched_brand"] + "` — " + alert["detail"],
        )

    return flags

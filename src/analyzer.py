"""
analysis/analyzer.py — EmlSOCAnalyzer: thin orchestrator.

This file's only job is to open an .eml, call the focused sub-modules in order,
and return the assembled SOC report dict. No analysis logic lives here.
"""

import email
from email import policy

from analysis.header  import extract_envelope
from analysis.body    import extract_body_parts
from analysis.attach  import collect_attachments
from analysis.links   import extract_links, check_lookalike_domains
from analysis.flags   import build_flags


class EmlSOCAnalyzer:
    """
    Parses a raw .eml file and returns a structured SOC-style report dict.
    All extraction is dynamic — no logic is hardcoded to a specific message.
    """

    def analyze(self, eml_path: str) -> dict:
        with open(eml_path, "rb") as f:
            raw_bytes = f.read()

        msg = email.message_from_bytes(raw_bytes, policy=policy.default)

        # Preserve raw bytes for cryptographic DKIM verification
        report: dict = {"raw_eml_bytes": raw_bytes}

        # 1. Envelope fields, received chain, auth results, anomalies
        report.update(extract_envelope(msg))

        # 2. Body parts (plain text, HTML, cleaned text for BERT)
        report.update(extract_body_parts(msg))

        # 3. Attachments (magic bytes, hashes, mismatch detection)
        report["attachments"] = collect_attachments(msg)

        # 4. Link extraction + lookalike domain detection
        report["links"] = extract_links(
            body_plain=report["body"],
            body_html=report.get("body_html") or "",
        )
        report["lookalike_alerts"] = check_lookalike_domains(report["links"])

        # 5. SOC flags summary
        report["flags"] = build_flags(report)

        return report

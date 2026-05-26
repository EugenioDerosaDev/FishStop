"""
analysis/body.py — HTML stripping and email body extraction.

Responsibilities:
  - _strip_html(): converts raw HTML to clean text for BERT and text analysis.
  - extract_body_parts(): walks a parsed email message and returns
    (body_plain, body_html, body_clean, body_source, html_strip_applied).
"""

import re
from typing import Optional

try:
    from bs4 import BeautifulSoup
    _BS4_AVAILABLE = True
except ImportError:
    _BS4_AVAILABLE = False


def _strip_html(html: str) -> str:
    """
    Converts raw HTML to clean text suitable for AI analysis and text checks.

    Strategy:
      1. BeautifulSoup (lxml > html.parser) for robust parsing of malformed HTML,
         encoding errors and nested tags.
      2. Removes <script> and <style> before text extraction to avoid passing
         JS or CSS to the model.
      3. Uses '\\n' separator between tags to preserve paragraph structure.
      4. Regex fallback if BeautifulSoup is not installed.

    Why this matters:
      Attackers insert invisible HTML tags or comments in the middle of words
      (e.g. Pa<!-- x -->ypal) to bypass string-based filters. Without stripping,
      BERT receives dirty tokens and URL regexes miss the real links.
    """
    if not html or not html.strip():
        return ""

    if _BS4_AVAILABLE:
        try:
            soup = BeautifulSoup(html, "lxml")
        except Exception:
            soup = BeautifulSoup(html, "html.parser")

        for tag in soup(["script", "style", "head"]):
            tag.decompose()

        text = soup.get_text(separator="\n")
    else:
        text = re.sub(r"<[^>]+>", " ", html)
        text = (text
                .replace("&amp;",  "&")
                .replace("&lt;",   "<")
                .replace("&gt;",   ">")
                .replace("&nbsp;", " ")
                .replace("&quot;", '"')
                .replace("&#39;",  "'"))

    lines = [line.strip() for line in text.splitlines()]
    lines = [l for l in lines if l]
    cleaned = "\n".join(lines)
    cleaned = re.sub(r" {2,}", " ", cleaned)

    return cleaned.strip()


def extract_body_parts(msg) -> dict:
    """
    Walks a parsed email.message object and extracts all body parts.

    Returns a dict with keys:
      body             : str  — raw body text (plain preferred, HTML fallback)
      body_html        : str | None — raw HTML if present
      body_clean       : str  — text after HTML stripping (BERT input)
      body_source      : "text/plain" | "text/html" | "empty"
      html_strip_applied : bool
    """
    body_parts: list[str] = []
    html_parts: list[str] = []

    for part in msg.walk():
        ct   = part.get_content_type()
        disp = str(part.get("Content-Disposition") or "")
        if "attachment" in disp.lower():
            continue
        if ct == "text/plain":
            payload = part.get_payload(decode=True)
            if payload:
                charset = part.get_content_charset() or "utf-8"
                body_parts.append(payload.decode(charset, errors="ignore"))
        elif ct == "text/html":
            payload = part.get_payload(decode=True)
            if payload:
                charset = part.get_content_charset() or "utf-8"
                html_parts.append(payload.decode(charset, errors="ignore"))

    raw_body  = "\n".join(body_parts) if body_parts else "\n".join(html_parts)
    body_html = "\n".join(html_parts).strip() if html_parts else None

    if body_parts:
        body_clean = re.sub(r"\n{3,}", "\n\n", raw_body).strip()
    else:
        body_clean = _strip_html("\n".join(html_parts))

    if body_parts:
        source = "text/plain"
    elif html_parts:
        source = "text/html"
    else:
        source = "empty"

    return {
        "body":               raw_body.strip(),
        "body_html":          body_html,
        "body_clean":         body_clean,
        "body_source":        source,
        "html_strip_applied": (not bool(body_parts)) and bool(html_parts),
    }

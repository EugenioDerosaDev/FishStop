"""
analyzer/link_extractor.py — Estrazione di URL dal corpo delle email.

Espone:
  - extract_links(body_plain, body_html) : lista di link strutturati

Gestisce sia testo plain che HTML, deduplicando i risultati per (url, source).
"""

import re
from urllib.parse import urlparse

from .html_utils import strip_html
from .lookalike import is_ip_url


# Regex per URL assoluti — cattura http/https/ftp e URL senza schema (www.)
_URL_RE = re.compile(
    r"""(?i)\b(?:https?://|ftp://|www\.)"""
    r"""(?:[a-z0-9\-]+\.)+[a-z]{2,}"""
    r"""(?::\d{1,5})?"""
    r"""(?:/[^\s"'<>\]\)]*)?""",
    re.VERBOSE,
)

# Estrae l'href da tag <a> (anche in HTML malformato)
_HREF_RE = re.compile(r"""href\s*=\s*["']?(https?://[^\s"'<>]+)""", re.IGNORECASE)


def extract_links(body_plain: str, body_html: str) -> list[dict]:
    """
    Estrae tutti i link dal corpo email (sia da testo plain che da HTML).

    Per ogni link restituisce:
      {
        "url"          : str   — URL assoluto normalizzato
        "display_text" : str   — testo visibile nel tag <a> (se HTML)
        "host"         : str   — hostname estratto
        "scheme"       : str   — http / https / ftp / (blank per www.)
        "source"       : "html_href" | "html_text" | "plain_text"
        "is_ip"        : bool  — True se l'host è un IP nudo
      }
    Deduplicati per url.
    """
    seen: set[str] = set()
    links: list[dict] = []

    def _add(url: str, display: str, source: str) -> None:
        url = url.strip().rstrip(".,;)")
        if not url or url in seen:
            return
        seen.add(url)
        if url.lower().startswith("www."):
            url = "http://" + url
        try:
            parsed = urlparse(url)
            host   = parsed.netloc.lower().split(":")[0]
            scheme = parsed.scheme.lower()
        except Exception:
            return
        links.append({
            "url":          url,
            "display_text": display.strip()[:120],
            "host":         host,
            "scheme":       scheme,
            "source":       source,
            "is_ip":        is_ip_url(host),
        })

    # 1. href nei tag <a> — fonte più affidabile per gli URL reali
    if body_html:
        for m in _HREF_RE.finditer(body_html):
            _add(m.group(1), "", "html_href")

        # 2. URL testuali nell'HTML (link non cliccabili o nel testo visibile)
        html_stripped = strip_html(body_html)
        for m in _URL_RE.finditer(html_stripped):
            _add(m.group(0), "", "html_text")

    # 3. URL nel corpo plain
    if body_plain:
        for m in _URL_RE.finditer(body_plain):
            _add(m.group(0), "", "plain_text")

    return links

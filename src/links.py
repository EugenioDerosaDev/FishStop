"""
analysis/links.py — Link extraction and lookalike domain detection.

Responsibilities:
  - extract_links(): pulls all URLs from plain-text and HTML email bodies.
  - check_lookalike_domains(): detects typosquatting / homoglyph / edit-distance
    domain spoofing against a list of known brands.
"""

import re
import unicodedata
from urllib.parse import urlparse

from analysis.body import _strip_html


# ---------------------------------------------------------------------------
# Regexes
# ---------------------------------------------------------------------------

_URL_RE = re.compile(
    r"""(?i)\b(?:https?://|ftp://|www\.)"""
    r"""(?:[a-z0-9\-]+\.)+[a-z]{2,}"""
    r"""(?::\d{1,5})?"""
    r"""(?:/[^\s"'<>\]\)]*)?""",
    re.VERBOSE,
)

_HREF_RE = re.compile(r"""href\s*=\s*["']?(https?://[^\s"'<>]+)""", re.IGNORECASE)


# ---------------------------------------------------------------------------
# Known brands
# ---------------------------------------------------------------------------

KNOWN_BRANDS: list[str] = [
    "paypal.com", "amazon.com", "amazon.it", "apple.com", "microsoft.com",
    "google.com", "gmail.com", "outlook.com", "live.com", "hotmail.com",
    "facebook.com", "instagram.com", "linkedin.com", "twitter.com", "x.com",
    "dropbox.com", "icloud.com", "chase.com", "wellsfargo.com", "bankofamerica.com",
    "intesasanpaolo.com", "unicredit.it", "poste.it", "postepay.it",
    "netflix.com", "spotify.com", "ebay.com", "dhl.com", "fedex.com",
    "ups.com", "brt.it", "gls-italy.com",
]

# Unicode homoglyph → ASCII mapping (subset relevant for phishing)
_HOMOGLYPH_MAP: dict[str, str] = {
    "а": "a", "е": "e", "о": "o", "р": "p", "с": "c", "х": "x",
    "ı": "i", "ĺ": "l", "ḷ": "l", "ó": "o", "ô": "o", "ö": "o",
    "ú": "u", "ü": "u", "ñ": "n", "ç": "c",
    "ԁ": "d", "ɡ": "g", "ʏ": "y", "ʋ": "v",
}


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _levenshtein(a: str, b: str) -> int:
    """Edit (Levenshtein) distance between two strings, O(n·m) space O(n)."""
    if a == b:
        return 0
    if len(a) < len(b):
        a, b = b, a
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        curr = [i]
        for j, cb in enumerate(b, 1):
            curr.append(min(
                prev[j] + 1,
                curr[j - 1] + 1,
                prev[j - 1] + (ca != cb),
            ))
        prev = curr
    return prev[-1]


def _normalize_homoglyphs(domain: str) -> str:
    """Normalizes a domain by replacing Unicode homoglyph characters with
    their ASCII equivalents. Also handles NFC/NFKC normalization."""
    domain = unicodedata.normalize("NFKC", domain.lower())
    return "".join(_HOMOGLYPH_MAP.get(ch, ch) for ch in domain)


def _strip_public_suffix(domain: str) -> str:
    """Returns the second-level domain (SLD) for edit-distance comparisons.
    Example: mail.paypa1.com → paypa1"""
    parts = domain.rstrip(".").split(".")
    if len(parts) >= 2:
        return parts[-2]
    return domain


def _is_ip_url(host: str) -> bool:
    """True if the host is an IPv4 or IPv6 address."""
    ipv4 = re.fullmatch(r"\d{1,3}(?:\.\d{1,3}){3}", host)
    ipv6 = host.startswith("[") and host.endswith("]")
    return bool(ipv4 or ipv6)


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def extract_links(body_plain: str, body_html: str) -> list[dict]:
    """
    Extracts all links from email body (plain text and HTML).

    Returns a list of dicts:
      {
        "url"          : str   — absolute normalized URL
        "display_text" : str   — visible text in <a> tag (if HTML)
        "host"         : str   — extracted hostname
        "scheme"       : str   — http / https / ftp
        "source"       : "html_href" | "html_text" | "plain_text"
        "is_ip"        : bool  — True if host is a bare IP
      }
    Deduplicated by (url, source).
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
            "is_ip":        _is_ip_url(host),
        })

    if body_html:
        for m in _HREF_RE.finditer(body_html):
            _add(m.group(1), "", "html_href")
        html_stripped = _strip_html(body_html)
        for m in _URL_RE.finditer(html_stripped):
            _add(m.group(0), "", "html_text")

    if body_plain:
        for m in _URL_RE.finditer(body_plain):
            _add(m.group(0), "", "plain_text")

    return links


def check_lookalike_domains(
    links: list[dict],
    known_brands: list[str] | None = None,
    edit_distance_threshold: int = 2,
) -> list[dict]:
    """
    For each link, checks whether the domain resembles a known brand using
    three combined techniques:

      1. Levenshtein distance on SLD ≤ threshold
      2. Unicode homoglyphs — visually identical characters to ASCII
      3. Typosquatting patterns — consonant insertion/duplication,
         0↔o / 1↔l / rn↔m substitution, deceptive prefixes

    Returns only alerts (empty list = no suspects found).

    Each alert:
      {
        "url"              : str
        "host"             : str
        "matched_brand"    : str
        "technique"        : "edit_distance" | "homoglyph" | "typosquatting"
        "detail"           : str
        "edit_distance"    : int | None
      }
    """
    brands = known_brands if known_brands is not None else KNOWN_BRANDS
    alerts: list[dict] = []
    seen_pairs: set[tuple[str, str]] = set()

    def _alert(url: str, host: str, brand: str, technique: str,
                detail: str, dist: int | None = None) -> None:
        key = (host, brand)
        if key in seen_pairs:
            return
        seen_pairs.add(key)
        alerts.append({
            "url":           url,
            "host":          host,
            "matched_brand": brand,
            "technique":     technique,
            "detail":        detail,
            "edit_distance": dist,
        })

    for link in links:
        host = link["host"]
        url  = link["url"]

        if not host or _is_ip_url(host):
            continue

        host_norm = _normalize_homoglyphs(host)
        host_sld  = _strip_public_suffix(host_norm)

        for brand in brands:
            brand_norm = _normalize_homoglyphs(brand)
            brand_sld  = _strip_public_suffix(brand_norm)

            if host_norm == brand_norm or host_norm.endswith("." + brand_norm):
                break

            # Technique 1: Levenshtein on SLD
            dist = _levenshtein(host_sld, brand_sld)
            if 0 < dist <= edit_distance_threshold:
                _alert(url, host, brand, "edit_distance",
                       f"SLD `{host_sld}` is {dist} edit(s) from `{brand_sld}` "
                       f"(brand: {brand})", dist)
                continue

            # Technique 2: Unicode homoglyphs
            if host_norm != host.lower() and _levenshtein(host_norm, brand_norm) <= edit_distance_threshold:
                _alert(url, host, brand, "homoglyph",
                       f"Domain `{host}` contains Unicode homoglyph characters "
                       f"making it visually similar to `{brand}`")
                continue

            # Technique 3: Typosquatting patterns — deceptive prefixes
            for prefix in ("secure-", "login-", "verify-", "account-",
                           "update-", "signin-", "support-", "my-", "auth-"):
                candidate = host_norm.lstrip("www.")
                if candidate.startswith(prefix):
                    inner = candidate[len(prefix):]
                    if _levenshtein(_strip_public_suffix(inner), brand_sld) <= 1:
                        _alert(url, host, brand, "typosquatting",
                               f"Deceptive prefix `{prefix}` in front of a domain "
                               f"similar to `{brand}`")
                        break

            # Technique 3b: Character substitution 0↔o, 1↔i/l, rn↔m
            subst = (host_sld
                     .replace("0", "o").replace("1", "i").replace("1", "l")
                     .replace("rn", "m").replace("vv", "w"))
            if subst != host_sld and _levenshtein(subst, brand_sld) == 0:
                _alert(url, host, brand, "typosquatting",
                       f"Character substitution (`{host_sld}` → `{subst}`) "
                       f"replicates `{brand_sld}` (brand: {brand})")

    return alerts

"""
analyzer/__init__.py — Public API del package analyzer.

Importa le classi e funzioni principali così gli altri moduli
possono fare:
    from src.analyzer import EmlSOCAnalyzer
    from src.analyzer import extract_links, check_lookalike_domains
"""

from .soc_analyzer   import EmlSOCAnalyzer
from .link_extractor import extract_links
from .lookalike      import check_lookalike_domains, levenshtein, normalize_homoglyphs, is_ip_url
from .attachment     import analyze_attachment, identify_magic_bytes, ext_from_filename
from .received_parser import parse_received_hop, parse_auth_results
from .html_utils     import strip_html
from .constants      import KNOWN_BRANDS, HOMOGLYPH_MAP, MAGIC_BYTES, CONTENT_TYPE_TO_EXT

__all__ = [
    "EmlSOCAnalyzer",
    "extract_links",
    "check_lookalike_domains",
    "levenshtein",
    "normalize_homoglyphs",
    "is_ip_url",
    "analyze_attachment",
    "identify_magic_bytes",
    "ext_from_filename",
    "parse_received_hop",
    "parse_auth_results",
    "strip_html",
    "KNOWN_BRANDS",
    "HOMOGLYPH_MAP",
    "MAGIC_BYTES",
    "CONTENT_TYPE_TO_EXT",
]

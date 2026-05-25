import re
import base64
import hashlib
import email
import unicodedata
from email import policy
from typing import Optional
from urllib.parse import urlparse

try:
    from bs4 import BeautifulSoup
    _BS4_AVAILABLE = True
except ImportError:
    _BS4_AVAILABLE = False


# ---------------------------------------------------------------------------
# Link Extraction + Lookalike Domain Detection
# ---------------------------------------------------------------------------

# Regex per URL assoluti — cattura http/https/ftp e URL senza schema (www.)
_URL_RE = re.compile(
    r"""(?i)\b(?:https?://|ftp://|www\.)"""          # schema o www.
    r"""(?:[a-z0-9\-]+\.)+[a-z]{2,}"""               # host
    r"""(?::\d{1,5})?"""                              # porta opzionale
    r"""(?:/[^\s"'<>\]\)]*)?""",                      # path opzionale
    re.VERBOSE,
)

# Estrae l'href da tag <a> (anche in HTML malformato)
_HREF_RE = re.compile(r"""href\s*=\s*["']?(https?://[^\s"'<>]+)""", re.IGNORECASE)

# Domini di brand noti — usati come riferimento per il lookalike check.
# Ampliabile con i brand rilevanti per il contesto aziendale.
KNOWN_BRANDS: list[str] = [
    "paypal.com", "amazon.com", "amazon.it", "apple.com", "microsoft.com",
    "google.com", "gmail.com", "outlook.com", "live.com", "hotmail.com",
    "facebook.com", "instagram.com", "linkedin.com", "twitter.com", "x.com",
    "dropbox.com", "icloud.com", "chase.com", "wellsfargo.com", "bankofamerica.com",
    "intesasanpaolo.com", "unicredit.it", "poste.it", "postepay.it",
    "netflix.com", "spotify.com", "ebay.com", "dhl.com", "fedex.com",
    "ups.com", "brt.it", "gls-italy.com",
]

# Caratteri Unicode omoglifi → ASCII equivalente
# (sottoinsieme rilevante per phishing; non serve un mapping completo)
_HOMOGLYPH_MAP: dict[str, str] = {
    "а": "a", "е": "e", "о": "o", "р": "p", "с": "c", "х": "x",
    "ı": "i", "ĺ": "l", "ḷ": "l", "ó": "o", "ô": "o", "ö": "o",
    "ú": "u", "ü": "u", "ñ": "n", "ç": "c",
    # Caratteri cirillici frequenti negli IDN attack
    "ԁ": "d", "ɡ": "g", "ʏ": "y", "ʋ": "v",
}


def _levenshtein(a: str, b: str) -> int:
    """Distanza di edit (Levenshtein) tra due stringhe, O(n·m) spazio O(n)."""
    if a == b:
        return 0
    if len(a) < len(b):
        a, b = b, a
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        curr = [i]
        for j, cb in enumerate(b, 1):
            curr.append(min(
                prev[j] + 1,       # delete
                curr[j - 1] + 1,   # insert
                prev[j - 1] + (ca != cb),  # replace
            ))
        prev = curr
    return prev[-1]


def _normalize_homoglyphs(domain: str) -> str:
    """
    Normalizza un dominio sostituendo i caratteri omoglifi Unicode con
    il loro equivalente ASCII. Gestisce anche la forma NFC/NFKC.
    """
    domain = unicodedata.normalize("NFKC", domain.lower())
    return "".join(_HOMOGLYPH_MAP.get(ch, ch) for ch in domain)


def _strip_public_suffix(domain: str) -> str:
    """
    Ritorna il 'registered domain' (etichette - TLD) in forma semplificata.
    Non usa una libreria PSL completa: rimuove solo l'ultimo label (TLD)
    per confronti di distanza più significativi.

    Esempio: mail.paypa1.com → paypa1
    """
    parts = domain.rstrip(".").split(".")
    if len(parts) >= 2:
        return parts[-2]   # secondo-livello (SLD)
    return domain


def _is_ip_url(host: str) -> bool:
    """True se l'host è un indirizzo IPv4 o IPv6."""
    ipv4 = re.fullmatch(r"\d{1,3}(?:\.\d{1,3}){3}", host)
    ipv6 = host.startswith("[") and host.endswith("]")
    return bool(ipv4 or ipv6)


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
    Deduplicati per (url, source).
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
            host   = parsed.netloc.lower().split(":")[0]   # rimuove porta
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

    # 1. href nei tag <a> — fonte più affidabile per gli URL reali
    if body_html:
        for m in _HREF_RE.finditer(body_html):
            _add(m.group(1), "", "html_href")

        # 2. URL testuali nell'HTML (link non cliccabili o nel testo visibile)
        html_stripped = _strip_html(body_html)
        for m in _URL_RE.finditer(html_stripped):
            _add(m.group(0), "", "html_text")

    # 3. URL nel corpo plain
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
    Per ogni link controlla se il dominio assomiglia a un brand noto
    usando tre tecniche combinate:

      1. Levenshtein distance sull'SLD (Second-Level Domain) ≤ threshold
      2. Omografia Unicode — caratteri visivamente identici ad ASCII
      3. Typosquatting patterns — inserimento/duplicazione consonanti,
         sostituzione 0↔o / 1↔l / rn↔m, aggiunta prefissi "secure-",
         "login-", "verify-", "account-", "update-"

    Restituisce solo gli alert (lista vuota = nessun sospetto trovato).

    Ogni alert:
      {
        "url"              : str
        "host"             : str
        "matched_brand"    : str
        "technique"        : "edit_distance" | "homoglyph" | "typosquatting"
        "detail"           : str   — spiegazione umana
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

            # Salta i match esatti (il dominio IS il brand)
            if host_norm == brand_norm or host_norm.endswith("." + brand_norm):
                break  # stesso dominio organizzativo → non è lookalike

            # ── Tecnica 1: Levenshtein sull'SLD ─────────────────────────
            dist = _levenshtein(host_sld, brand_sld)
            if 0 < dist <= edit_distance_threshold:
                _alert(url, host, brand, "edit_distance",
                       f"SLD `{host_sld}` dista {dist} edit da `{brand_sld}` "
                       f"(brand: {brand})", dist)
                continue

            # ── Tecnica 2: Omografia Unicode ────────────────────────────
            if host_norm != host.lower() and _levenshtein(host_norm, brand_norm) <= edit_distance_threshold:
                _alert(url, host, brand, "homoglyph",
                       f"Il dominio `{host}` contiene caratteri Unicode omoglifi "
                       f"che lo rendono visivamente simile a `{brand}`")
                continue

            # ── Tecnica 3: Typosquatting patterns ───────────────────────
            # Prefissi ingannatori
            for prefix in ("secure-", "login-", "verify-", "account-",
                           "update-", "signin-", "support-", "my-", "auth-"):
                candidate = host_norm.lstrip("www.")
                if candidate.startswith(prefix):
                    inner = candidate[len(prefix):]
                    if _levenshtein(_strip_public_suffix(inner), brand_sld) <= 1:
                        _alert(url, host, brand, "typosquatting",
                               f"Prefisso ingannatorio `{prefix}` davanti a un dominio "
                               f"simile a `{brand}`")
                        break

            # Sostituzione 0↔o, 1↔i/l, rn↔m
            subst = (host_sld
                     .replace("0", "o").replace("1", "i").replace("1", "l")
                     .replace("rn", "m").replace("vv", "w"))
            if subst != host_sld and _levenshtein(subst, brand_sld) == 0:
                _alert(url, host, brand, "typosquatting",
                       f"Sostituzione caratteri (`{host_sld}` → `{subst}`) "
                       f"replica `{brand_sld}` (brand: {brand})")

    return alerts


# ---------------------------------------------------------------------------
# Magic Bytes database (Gary Kessler / File Signatures)
# ---------------------------------------------------------------------------
MAGIC_BYTES: dict[str, list[bytes]] = {
    "pdf":  [b"%PDF"],
    "zip":  [b"PK\x03\x04", b"PK\x05\x06", b"PK\x07\x08"],
    "docx": [b"PK\x03\x04"],
    "xlsx": [b"PK\x03\x04"],
    "pptx": [b"PK\x03\x04"],
    "exe":  [b"MZ"],
    "elf":  [b"\x7fELF"],
    "png":  [b"\x89PNG\r\n\x1a\n"],
    "jpg":  [b"\xff\xd8\xff"],
    "gif":  [b"GIF87a", b"GIF89a"],
    "bmp":  [b"BM"],
    "tiff": [b"II*\x00", b"MM\x00*"],
    "rar":  [b"Rar!\x1a\x07"],
    "7z":   [b"7z\xbc\xaf\x27\x1c"],
    "gz":   [b"\x1f\x8b"],
    "bz2":  [b"BZh"],
    "doc":  [b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"],
    "xls":  [b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"],
    "ppt":  [b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"],
    "rtf":  [b"{\\rtf"],
    "html": [b"<!DOCTYPE", b"<html"],
    "xml":  [b"<?xml"],
    "js":   [],
    "bat":  [],
    "ps1":  [],
    "sh":   [b"#!/"],
}

CONTENT_TYPE_TO_EXT: dict[str, list[str]] = {
    "application/pdf":       ["pdf"],
    "application/zip":       ["zip", "docx", "xlsx", "pptx"],
    "application/msword":    ["doc"],
    "application/vnd.openxmlformats-officedocument.wordprocessingml.document": ["docx"],
    "application/vnd.ms-excel": ["xls"],
    "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet": ["xlsx"],
    "application/vnd.ms-powerpoint": ["ppt"],
    "application/vnd.openxmlformats-officedocument.presentationml.presentation": ["pptx"],
    "application/x-rar-compressed": ["rar"],
    "application/x-7z-compressed":  ["7z"],
    "application/gzip":      ["gz"],
    "application/x-bzip2":  ["bz2"],
    "application/octet-stream": [],
    "image/png":  ["png"],
    "image/jpeg": ["jpg"],
    "image/gif":  ["gif"],
    "image/bmp":  ["bmp"],
    "image/tiff": ["tiff"],
    "text/html":  ["html"],
    "text/xml":   ["xml"],
    "application/rtf": ["rtf"],
}


def _identify_magic_bytes(raw: bytes) -> Optional[str]:
    """Returns the format name identified by magic bytes, or None."""
    for fmt, signatures in MAGIC_BYTES.items():
        for sig in signatures:
            if raw.startswith(sig):
                return fmt
    return None


def _ext_from_filename(filename: str) -> Optional[str]:
    """Extract lowercase extension from filename."""
    if "." in filename:
        return filename.rsplit(".", 1)[-1].lower()
    return None


def _extract_domain(email_or_addr: str) -> str:
    """Return the domain part of an address string, lower-cased."""
    m = re.search(r"@([\w.\-]+)", email_or_addr or "")
    return m.group(1).lower() if m else ""


# ---------------------------------------------------------------------------
# HTML stripping
# ---------------------------------------------------------------------------

def _strip_html(html: str) -> str:
    """
    Converte HTML grezzo in testo pulito adatto all'analisi AI e ai controlli
    testuali.

    Strategia (in ordine):
      1. BeautifulSoup (lxml > html.parser come backend) per un parsing robusto
         che gestisce HTML malformato, encoding errors e tag annidati.
      2. Rimozione di <script> e <style> prima dell'estrazione del testo, per
         evitare che codice JS o CSS venga passato al modello.
      3. Separatore '\n' tra i tag per preservare la struttura dei paragrafi.
      4. Fallback regex se BeautifulSoup non è installato: rimuove tutti i tag
         con un pattern greedy-safe e decodifica le entity HTML principali.
         Meno preciso ma sempre meglio del testo grezzo.

    Perché è importante:
      Gli attaccanti inseriscono tag o commenti HTML invisibili in mezzo alle
      parole (es. Pa<!-- x -->ypal, P<span style='display:none'>x</span>aypal)
      per aggirare i filtri basati su stringhe. Senza stripping, BERT riceve
      token sporchi e le regex sui link non trovano le URL reali.
    """
    if not html or not html.strip():
        return ""

    if _BS4_AVAILABLE:
        try:
            soup = BeautifulSoup(html, "lxml")
        except Exception:
            soup = BeautifulSoup(html, "html.parser")

        # Rimuovi blocchi script e style — il loro contenuto non è testo leggibile
        for tag in soup(["script", "style", "head"]):
            tag.decompose()

        # get_text con separatore newline per preservare la struttura dei paragrafi
        text = soup.get_text(separator="\n")
    else:
        # Fallback regex: rimuovi tutti i tag HTML
        text = re.sub(r"<[^>]+>", " ", html)
        # Decodifica le entity HTML più comuni
        text = (text
                .replace("&amp;",  "&")
                .replace("&lt;",   "<")
                .replace("&gt;",   ">")
                .replace("&nbsp;", " ")
                .replace("&quot;", '"')
                .replace("&#39;",  "'"))

    # Normalizza whitespace: collassa spazi multipli e righe vuote consecutive
    lines = [line.strip() for line in text.splitlines()]
    lines = [l for l in lines if l]                      # rimuovi righe vuote
    cleaned = "\n".join(lines)
    cleaned = re.sub(r" {2,}", " ", cleaned)             # spazi multipli → singolo

    return cleaned.strip()


# ---------------------------------------------------------------------------
# Received chain parser
# ---------------------------------------------------------------------------
# Riconosce sia IPv4 sia IPv6, rimuovendo eventuali parentesi quadre o tonde di contorno
_IP_RE = re.compile(
    r"(?:\[|(?<=\s\())"                         # Parentesi quadra o tonda aperta con spazio prima
    r"([0-9a-fA-F]{1,4}(?::[0-9a-fA-F]{1,4}){1,7}|(?:::[0-9a-fA-F]{1,4}){1,7}|[0-9a-fA-F]{1,4}::|" # IPv6 standard/compresso
    r"\d{1,3}(?:\.\d{1,3}){3})"                 # IPv4 classico
    r"(?=\s*\)|\])"                             # Chiusura parentesi tonda o quadra
)
_BY_RE = re.compile(r"by\s+([\w.\-]+)", re.IGNORECASE)
_FROM_RE = re.compile(r"from\s+([\w.\-]+)\s*(?:\(([^)]*)\))?", re.IGNORECASE)
_FOR_RE = re.compile(r"for\s+<([^>]+)>", re.IGNORECASE)
_TLS_RE = re.compile(r"version=(TLS[\w.]+)\s+cipher=([\w\-]+)", re.IGNORECASE)


def _parse_received_hop(raw: str) -> dict:
    hop: dict = {"raw": raw.strip()}

    # Applica una pulizia iniziale per normalizzare i ritorni a capo e gli spazi multipli
    clean_raw = " ".join(raw.split())

    m = _FROM_RE.search(clean_raw)
    if m:
        hop["from_host"] = m.group(1)
        parenthetical = m.group(2) or ""
        
        # Primo tentativo: cerca l'IP all'interno delle parentesi del campo FROM
        ip_m = _IP_RE.search(parenthetical)
        if not ip_m:
            # Secondo tentativo: se non è nelle parentesi, cercalo subito dopo il nome host
            # Molto comune nei log Exchange: from host.com (IP) by...
            host_end = m.end(1)
            ip_m = _IP_RE.search(clean_raw, host_end)
        
        hop["sender_ip"] = ip_m.group(1) if ip_m else None
        
        parts = [p.strip() for p in parenthetical.replace("[", "").replace("]", "").replace("(", "").replace(")", "").split()]
        hop["sender_domain"] = parts[0] if parts and not parts[0][0].isdigit() and ":" not in parts[0] else None

    # Se non è stato trovato un From strutturato ma è presente un IP, lo estraiamo comunque come paracadute
    if not hop.get("sender_ip"):
        fallback_ip = _IP_RE.search(clean_raw)
        hop["sender_ip"] = fallback_ip.group(1) if fallback_ip else None

    m2 = _BY_RE.search(clean_raw)
    hop["by_host"] = m2.group(1) if m2 else None

    m3 = _FOR_RE.search(clean_raw)
    hop["for_address"] = m3.group(1) if m3 else None

    m4 = _TLS_RE.search(clean_raw)
    if m4:
        hop["tls_version"] = m4.group(1)
        hop["tls_cipher"]  = m4.group(2)

    # Raccoglie tutti gli IP univoci presenti nell'header usando la nuova regex
    hop["all_ips"] = list(dict.fromkeys(_IP_RE.findall(clean_raw)))

    return hop


# ---------------------------------------------------------------------------
# Authentication-Results parser
# ---------------------------------------------------------------------------
_AUTH_FIELD_RE = re.compile(
    r"(spf|dkim|dmarc)\s*=\s*([\w]+)"
    r"(?:[^;]*?smtp\.\w+=([^\s;]+))?",
    re.IGNORECASE,
)


def _parse_auth_results(raw: str) -> dict:
    results: dict = {}
    for m in _AUTH_FIELD_RE.finditer(raw):
        proto    = m.group(1).upper()
        status   = m.group(2).lower()
        identity = m.group(3) or ""
        results[proto] = {"status": status, "identity": identity, "raw": m.group(0).strip()}
    return results


# ---------------------------------------------------------------------------
# Main analyzer
# ---------------------------------------------------------------------------

class EmlSOCAnalyzer:
    """
    Parses a raw .eml file and returns a structured SOC-style report dict.
    Everything is extracted dynamically from the actual email — no hardcoded
    logic tied to a specific message.
    """

    def analyze(self, eml_path: str) -> dict:
        with open(eml_path, "rb") as f:
            raw_bytes = f.read()

        msg = email.message_from_bytes(raw_bytes, policy=policy.default)

        report: dict = {}

        # Conserva i byte grezzi per la verifica crittografica DKIM
        report["raw_eml_bytes"] = raw_bytes

        # ------------------------------------------------------------------ #
        # 1. Basic envelope fields
        # ------------------------------------------------------------------ #
        report["delivered_to"] = self._header(msg, "Delivered-To")
        report["to"]           = self._header(msg, "To")
        report["from_"]        = self._header(msg, "From")
        report["subject"]      = self._header(msg, "Subject")
        report["date"]         = self._header(msg, "Date")
        report["message_id"]   = self._header(msg, "Message-Id")
        report["importance"]   = self._header(msg, "Importance") or self._header(msg, "X-Priority")
        report["mime_version"] = self._header(msg, "MIME-Version")
        report["content_type"] = self._header(msg, "Content-Type")

        # ------------------------------------------------------------------ #
        # 2. Return-Path / Errors-To / Reply-To
        # ------------------------------------------------------------------ #
        report["return_path"] = self._header(msg, "Return-Path")
        report["errors_to"]   = self._header(msg, "Errors-To")
        reply_to              = self._header(msg, "Reply-To")
        report["reply_to"]    = reply_to

        # Anomaly: Reply-To ≠ From
        from_addr  = self._extract_address(report["from_"])
        reply_addr = self._extract_address(reply_to)
        report["reply_to_mismatch"] = bool(
            reply_addr and from_addr and reply_addr.lower() != from_addr.lower()
        )
        # Anomaly: Return-Path domain ≠ From domain (server spoofing signal)
        return_path_addr   = self._extract_address(report["return_path"])
        return_path_domain = _extract_domain(return_path_addr or "") if return_path_addr else ""
        from_domain        = _extract_domain(from_addr or "") if from_addr else ""
        report["return_path_domain_mismatch"] = bool(
            return_path_domain and from_domain
            and return_path_domain.lower() != from_domain.lower()
        )
        report["return_path_domain"] = return_path_domain

        # Anomaly: Display Name contains an email address DIFFERENT from the actual sender
        # e.g. From: "support@paypal.com" <attacker@evil.com>  ← spoofing reale
        #      From: "Mario Rossi mario@example.com" <mario@example.com>  ← stesso indirizzo, non segnalare
        display_name_email_match = None
        if report["from_"]:
            dn_match = re.match(r'^"?([^"<]+)"?\s*<', report["from_"])
            if dn_match:
                dn = dn_match.group(1).strip()
                embedded = re.search(r"[\w.+\-]+@[\w.\-]+", dn)
                if embedded:
                    embedded_addr = embedded.group(0).lower()
                    # Segnala solo se l'indirizzo embedded è DIVERSO dal mittente reale
                    if from_addr and embedded_addr != from_addr.lower():
                        display_name_email_match = embedded_addr
        report["display_name_spoofing"] = display_name_email_match  # None oppure l'indirizzo spoofato
        
 

        # ------------------------------------------------------------------ #
        # 3. Google / routing metadata
        # ------------------------------------------------------------------ #
        report["x_google_smtp_source"] = self._header(msg, "X-Google-Smtp-Source")
        report["x_received"]           = self._header(msg, "X-Received")

        # ------------------------------------------------------------------ #
        # 4. ARC headers
        # ------------------------------------------------------------------ #
        report["arc_seal"]                   = self._header(msg, "ARC-Seal")
        report["arc_message_signature"]      = self._header(msg, "ARC-Message-Signature")
        report["arc_authentication_results"] = self._header(msg, "ARC-Authentication-Results")

        # ------------------------------------------------------------------ #
        # 5. Received chain  (chronological: last = closest to sender)
        # ------------------------------------------------------------------ #
        raw_received = msg.get_all("Received") or []
        hops = [_parse_received_hop(r) for r in raw_received]
        report["received_hops"] = hops
        report["closest_to_recipient"] = hops[0]  if hops else {}
        report["injection_server"]     = hops[1]  if len(hops) > 1 else {}
        report["closest_to_sender"]    = hops[-1] if hops else {}

        # Convenience: IP del server di iniezione (usato dai validator SPF)
        report["injection_sender_ip"] = self._extract_spf_sender_ip(msg, hops)

        # ------------------------------------------------------------------ #
        # 6. Received-SPF raw line
        # ------------------------------------------------------------------ #
        report["received_spf_raw"] = self._header(msg, "Received-SPF")

        # ------------------------------------------------------------------ #
        # 7. Authentication-Results (parsed)
        # ------------------------------------------------------------------ #
        auth_raw     = self._header(msg, "Authentication-Results") or ""
        arc_auth_raw = report["arc_authentication_results"] or ""
        report["auth_results"]     = _parse_auth_results(auth_raw)
        report["arc_auth_results"] = _parse_auth_results(arc_auth_raw)

        # ------------------------------------------------------------------ #
        # 8. DKIM header presence check
        # ------------------------------------------------------------------ #
        report["dkim_signature_present"] = bool(msg.get("DKIM-Signature"))
        report["dkim_signature_raw"]     = self._header(msg, "DKIM-Signature")

        # ------------------------------------------------------------------ #
        # 9. Body parts & attachments (with magic byte check)
        # ------------------------------------------------------------------ #
        body_parts       = []   # text/plain parti (priorità)
        html_parts       = []   # text/html parti (fallback)
        attachments_info = []

        for part in msg.walk():
            ct       = part.get_content_type()
            disp     = str(part.get("Content-Disposition") or "")
            encoding = str(part.get("Content-Transfer-Encoding") or "").lower().strip()
            filename = part.get_filename() or ""
            is_attach = "attachment" in disp.lower()

            if is_attach or filename:
                raw_payload = part.get_payload(decode=False)
                attachments_info.append(self._analyze_attachment(
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

        # body grezzo: text/plain se disponibile, altrimenti HTML grezzo come fallback
        raw_body = "\n".join(body_parts) if body_parts else "\n".join(html_parts)
        report["body"] = raw_body.strip()

        # body_html: l'HTML grezzo originale (per rendering e analisi link futura)
        report["body_html"] = "\n".join(html_parts).strip() if html_parts else None

        # body_clean: testo pulito dai tag HTML — input canonico per BERT e analisi testuali.
        # Se il body grezzo è già text/plain, non serve stripping; lo applichiamo
        # solo se l'unica fonte disponibile era HTML.
        if body_parts:
            # Testo già pulito — normalizza solo whitespace
            report["body_clean"] = re.sub(r"\n{3,}", "\n\n", report["body"]).strip()
        else:
            # Corpo era HTML: esegui stripping completo
            combined_html = "\n".join(html_parts)
            report["body_clean"] = _strip_html(combined_html)

        # Segnala nel report quale metodo è stato usato (utile per debug nella UI)
        report["body_source"]       = "text/plain" if body_parts else ("text/html" if html_parts else "empty")
        report["html_strip_applied"] = (not bool(body_parts)) and bool(html_parts)

        report["attachments"] = attachments_info

        # ------------------------------------------------------------------ #
        # 10. Link extraction + lookalike domain detection
        # ------------------------------------------------------------------ #
        report["links"] = extract_links(
            body_plain=report["body"],
            body_html=report.get("body_html") or "",
        )
        report["lookalike_alerts"] = check_lookalike_domains(report["links"])

        # ------------------------------------------------------------------ #
        # 11. Summary flags (for quick SOC triage)
        # ------------------------------------------------------------------ #
        report["flags"] = self._build_flags(report)

        return report

    # ------------------------------------------------------------------ #
    # Helpers
    # ------------------------------------------------------------------ #

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

    def _analyze_attachment(
        self,
        filename: str,
        content_type: str,
        encoding: str,
        raw_payload,
    ) -> dict:
        entry: dict = {
            "filename": filename,
            "content_type": content_type,
            "encoding": encoding,
            "magic_bytes_hex": None,
            "magic_detected_format": None,
            "extension_from_filename": _ext_from_filename(filename),
            "extension_match": None,
            "anomaly": None,
            "hash_md5":    None,
            "hash_sha1":   None,
            "hash_sha256": None,
            "size_bytes":  None,
        }

        if encoding == "base64" and raw_payload:
            try:
                if isinstance(raw_payload, str):
                    raw_bytes = base64.b64decode(raw_payload.replace("\n", "").replace("\r", ""))
                else:
                    raw_bytes = base64.b64decode(raw_payload)
                first16 = raw_bytes[:16]
                entry["magic_bytes_hex"]       = first16.hex().upper()
                entry["magic_detected_format"] = _identify_magic_bytes(raw_bytes)
                entry["size_bytes"]            = len(raw_bytes)
                entry["hash_md5"]              = hashlib.md5(raw_bytes).hexdigest()
                entry["hash_sha1"]             = hashlib.sha1(raw_bytes).hexdigest()
                entry["hash_sha256"]           = hashlib.sha256(raw_bytes).hexdigest()
            except Exception as exc:
                entry["anomaly"] = f"Base64 decode error: {exc}"
                return entry
        else:
            entry["anomaly"] = "Non-base64 attachment — raw bytes not decoded"
            return entry

        ct_base       = content_type.split(";")[0].strip().lower()
        expected_exts = CONTENT_TYPE_TO_EXT.get(ct_base, [])
        file_ext      = entry["extension_from_filename"]
        magic_fmt     = entry["magic_detected_format"]

        mismatches = []
        if file_ext and expected_exts and file_ext not in expected_exts:
            mismatches.append(
                f"Content-Type '{ct_base}' expects {expected_exts} but filename has '.{file_ext}'"
            )
        if magic_fmt and file_ext and magic_fmt != file_ext:
            zip_like = {"docx", "xlsx", "pptx", "zip"}
            if not (magic_fmt == "zip" and file_ext in zip_like):
                mismatches.append(
                    f"Magic bytes identify format as '{magic_fmt}' but filename extension is '.{file_ext}'"
                )
        if magic_fmt and expected_exts and magic_fmt not in expected_exts:
            zip_like = {"docx", "xlsx", "pptx", "zip"}
            if not (magic_fmt == "zip" and bool(set(expected_exts) & zip_like)):
                mismatches.append(
                    f"Magic bytes identify '{magic_fmt}' but Content-Type expects {expected_exts}"
                )

        entry["extension_match"] = len(mismatches) == 0
        entry["anomaly"] = "; ".join(mismatches) if mismatches else None
        return entry

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
                # Return-Path domain mismatch (server spoofing / bounce harvesting)
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
        # HTML stripping applicato — segnala che il corpo era HTML puro
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
    
    
        # Injection server anomaly
        inj = report.get("injection_server", {})
        if inj.get("sender_ip"):
            flag("INFO", "Received",
                 f"Server di iniezione: {inj.get('sender_domain') or inj.get('from_host', '?')} "
                 f"[{inj['sender_ip']}] — verificare reputazione IP/dominio")

        # Attachment anomalies
        for att in report.get("attachments", []):
            if att.get("anomaly"):
                flag("HIGH", "Attachment",
                     f"'{att['filename']}': {att['anomaly']}")
            if att.get("magic_bytes_hex"):
                flag("INFO", "Attachment",
                     f"'{att['filename']}': magic bytes {att['magic_bytes_hex'][:8]}… "
                     f"→ formato rilevato: {att['magic_detected_format'] or 'sconosciuto'}")

        # Link anomalies: IP-direct e lookalike
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
    
    @staticmethod
    def _extract_spf_sender_ip(msg, hops: list) -> str | None:
        """
        Estrae l'IP corretto da usare per la verifica SPF live.

        L'IP giusto è quello che il MX del destinatario ha visto arrivare
        la connessione SMTP — non un relay interno successivo.
        Priorità di estrazione:

        1. client-ip= nel Received-SPF header  ← più affidabile, scritto dal MX
        2. smtp.remote-ip= in Authentication-Results
        3. IP pubblico nell'ultimo hop Received (più vicino al mittente)
        4. Fallback: sender_ip dall'hop [1] (vecchio comportamento)
        """
        import re
        ip_re = re.compile(r'(\d{1,3}(?:\.\d{1,3}){3})')
        _private = re.compile(
            r'^(10\.|172\.(1[6-9]|2\d|3[01])\.|192\.168\.|127\.)'
        )

        # 1. Received-SPF: client-ip=
        rcvd_spf = str(msg.get('Received-SPF') or '')
        m = re.search(r'client-ip=([\d.a-fA-F:]+)', rcvd_spf, re.IGNORECASE)
        if m and not _private.match(m.group(1)):
            return m.group(1)

        # 2. Authentication-Results: smtp.remote-ip=
        auth = str(msg.get('Authentication-Results') or '')
        m = re.search(r'smtp\.remote-ip=([\d.]+)', auth, re.IGNORECASE)
        if m and not _private.match(m.group(1)):
            return m.group(1)

        # 3. Ultimo hop Received — primo IP pubblico
        if hops:
            last_hop = hops[-1]
            for ip in (last_hop.get('all_ips') or []):
                if ip and not _private.match(ip):
                    return ip

        # 4. Fallback legacy: hop [1]
        return (hops[1].get('sender_ip') if len(hops) > 1 else None)
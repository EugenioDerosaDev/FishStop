"""
analyzer/constants.py — Costanti condivise per l'analisi statica delle email.

Contiene:
  - KNOWN_BRANDS       : database di domini brand noti per il lookalike check
  - _HOMOGLYPH_MAP     : mappa omoglifi Unicode → ASCII
  - MAGIC_BYTES        : firme binarie per l'identificazione reale degli allegati
  - CONTENT_TYPE_TO_EXT: mapping Content-Type MIME → estensioni attese
"""

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
HOMOGLYPH_MAP: dict[str, str] = {
    "а": "a", "е": "e", "о": "o", "р": "p", "с": "c", "х": "x",
    "ı": "i", "ĺ": "l", "ḷ": "l", "ó": "o", "ô": "o", "ö": "o",
    "ú": "u", "ü": "u", "ñ": "n", "ç": "c",
    # Caratteri cirillici frequenti negli IDN attack
    "ԁ": "d", "ɡ": "g", "ʏ": "y", "ʋ": "v",
}

# Magic Bytes database (Gary Kessler / File Signatures)
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

"""
analyzer/html_utils.py — Pulizia e normalizzazione HTML per l'analisi email.

Espone:
  - strip_html(html)  : converte HTML grezzo in testo pulito

Gli attaccanti inseriscono tag o commenti HTML invisibili in mezzo alle parole
(es. Pa<!-- x -->ypal) per aggirare i filtri basati su stringhe. Senza
stripping, BERT riceve token sporchi e le regex sui link non trovano le URL reali.
"""

import re

try:
    from bs4 import BeautifulSoup
    _BS4_AVAILABLE = True
except ImportError:
    _BS4_AVAILABLE = False


def strip_html(html: str) -> str:
    """
    Converte HTML grezzo in testo pulito adatto all'analisi AI e ai controlli
    testuali.

    Strategia (in ordine):
      1. BeautifulSoup (lxml > html.parser come backend) per un parsing robusto
         che gestisce HTML malformato, encoding errors e tag annidati.
      2. Rimozione di <script> e <style> prima dell'estrazione del testo, per
         evitare che codice JS o CSS venga passato al modello.
      3. Separatore '\\n' tra i tag per preservare la struttura dei paragrafi.
      4. Fallback regex se BeautifulSoup non è installato: rimuove tutti i tag
         con un pattern greedy-safe e decodifica le entity HTML principali.
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
        # Fallback regex
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

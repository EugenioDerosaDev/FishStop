import os
import re
import email
from email import policy
import pandas as pd


def _sanitize_eml_bytes(raw_bytes: bytes) -> bytes:
    """
    Pre-processes raw .eml bytes exported by non-standard MUAs or webmail clients
    that violate RFC 2822 in predictable ways. Applies three fixes in order:

    1. **Spurious leading lines** — Some clients (e.g. Rackspace webmail) prepend
       lines like ``Created at: Wed, 13 May 2026 09:36:48 AM (CEST)`` whose field
       name contains spaces, making them invalid RFC 2822 headers. Python's email
       parser stops at the first invalid line and treats everything after it as the
       body, so From/Subject/Received all come back as None. Fix: skip lines until
       the first syntactically valid header field (printable ASCII, no spaces, ends
       with colon).

    2. **Unicode whitespace used as header folding** — The same clients use Unicode
       characters (U+2003 EM SPACE ``\\xe2\\x80\\x83``, U+00A0 NO-BREAK SPACE
       ``\\xc2\\xa0``) instead of the ASCII SP/HTAB required by RFC 5322 §2.2.3 for
       folded long headers. Python's parser does not recognise these as continuation
       lines and misparses multi-line headers (Received, ARC-*, etc.). Fix: lines
       that start with Unicode whitespace but not ASCII whitespace are prefixed with
       a regular space; inline NBSP is replaced with a regular space throughout.

    3. **Missing blank-line separator** — Header-only exports (no body, no trailing
       blank line) confuse Python's ``email`` parser boundary detection. Fix: append
       ``\\n\\n`` if no blank line is already present.
    """
    lines = raw_bytes.split(b'\n')

    # ── Fix 1: skip leading non-RFC-2822 header lines ────────────────────────
    # RFC 5322 field-name: one or more printable US-ASCII characters except ':'
    # Regex: [!-9] covers '!' to '9' (includes '-'); [;-~] covers ';' to '~'
    valid_field_re = re.compile(rb'^[!-9;-~]+:')
    start = 0
    for i, line in enumerate(lines):
        if valid_field_re.match(line):
            start = i
            break
    lines = lines[start:]

    # ── Fix 2: normalise Unicode folding whitespace ───────────────────────────
    # EM SPACE family: U+2000–U+200B all encode to \xe2\x80\x{80-8b} in UTF-8
    # NO-BREAK SPACE: U+00A0 → \xc2\xa0 in UTF-8
    unicode_indent_re = re.compile(rb'^(?:(?:\xe2\x80[\x80-\x8b])|\xc2\xa0)+')
    fixed_lines = []
    for line in lines:
        # If line starts with Unicode WS but NOT ASCII space/tab, it's a folded
        # continuation that Python won't recognise — prefix with ASCII space.
        if line and line[0:1] not in (b' ', b'\t') and unicode_indent_re.match(line):
            line = b' ' + unicode_indent_re.sub(b'', line)
        # Replace any remaining NBSP inline (e.g. inside Received header values)
        line = line.replace(b'\xc2\xa0', b' ')
        fixed_lines.append(line)

    result = b'\n'.join(fixed_lines)

    # ── Fix 3: ensure blank-line header/body separator ───────────────────────
    if b'\n\n' not in result:
        result = result + b'\n\n'

    return result


class EmailParserPipeline:
    def __init__(self):
        pass

    def parse_single_eml(self, eml_path: str) -> dict:
        """
        Legge un singolo file .eml ed estrae Mittente, Destinatario, Oggetto,
        Data, Header grezzi e il Corpo del testo pulito in modo ricorsivo.

        Applica automaticamente _sanitize_eml_bytes() prima del parsing per
        gestire i file esportati da MUA non conformi a RFC 2822 (es. webmail
        Rackspace, alcuni client Exchange) che:
          - inseriscono righe non-header all'inizio del file
          - usano Unicode whitespace per il folding degli header
          - omettono la riga vuota di separazione header/body
        """
        if not os.path.exists(eml_path):
            raise FileNotFoundError(f"File .eml non trovato in: {eml_path}")

        with open(eml_path, 'rb') as f:
            raw_bytes = f.read()

        # Pre-processing per file non-conformi a RFC 2822
        sanitized = _sanitize_eml_bytes(raw_bytes)

        # Usiamo policy.default che converte automaticamente gli header complessi in stringhe pulite
        msg = email.message_from_bytes(sanitized, policy=policy.default)

        # Estrazione e pulizia dei metadati principali
        sender = str(msg.get('From', '')).strip()
        to = str(msg.get('To', '')).strip()
        subject = str(msg.get('Subject', '')).strip()
        date = str(msg.get('Date', '')).strip()

        # Normalizzazione degli Header (risolve i problemi di righe multiple / folding)
        raw_headers = {}
        for k, v in msg.items():
            raw_headers[k] = str(v).replace('\n', ' ').replace('\t', ' ').strip()

        # Estrazione ricorsiva del corpo del testo (Corretto per gestire strutture multipart annidate)
        body_parts = []
        html_parts = []

        if msg.is_multipart():
            for part in msg.walk():
                content_type = part.get_content_type()
                content_disposition = str(part.get_content_disposition())

                # Saltiamo i veri e propri file allegati per non inquinare il testo del modello
                if 'attachment' in content_disposition:
                    continue

                if content_type == 'text/plain':
                    payload = part.get_payload(decode=True)
                    if payload:
                        charset = part.get_content_charset() or 'utf-8'
                        body_parts.append(payload.decode(charset, errors='ignore'))
                elif content_type == 'text/html':
                    payload = part.get_payload(decode=True)
                    if payload:
                        charset = part.get_content_charset() or 'utf-8'
                        html_parts.append(payload.decode(charset, errors='ignore'))
            
            # Se abbiamo trovato del testo semplice uniamo tutto, altrimenti usiamo l'HTML come fallback
            body = "\n".join(body_parts) if body_parts else "\n".join(html_parts)
        else:
            payload = msg.get_payload(decode=True)
            body = payload.decode(msg.get_content_charset() or 'utf-8', errors='ignore') if payload else ""

        return {
            "sender": sender,
            "to": to,
            "subject": subject,
            "date": date,
            "raw_headers": raw_headers,
            "body": body.strip()
        }

    def load_batch_emls(self, folder_path: str) -> pd.DataFrame:
        """
        Scansiona una cartella, analizza tutti i file .eml presenti e
        restituisce un DataFrame di Pandas pronto per l'addestramento.
        """
        parsed_emails = []
        
        if not os.path.exists(folder_path):
            return pd.DataFrame()

        for filename in os.listdir(folder_path):
            if filename.endswith('.eml'):
                full_path = os.path.join(folder_path, filename)
                try:
                    data = self.parse_single_eml(full_path)
                    parsed_emails.append(data)
                except Exception as e:
                    print(f"[-] Errore nel parsing del file {filename}: {e}")

        return pd.DataFrame(parsed_emails)

if __name__ == "__main__":
    print("[*] Test isolato del modulo parser.py con i file caricati...")
    parser = EmailParserPipeline()
    
    for test_file in ['test.eml', 'test2.eml', 'test3_good.eml']:
        if os.path.exists(test_file):
            res = parser.parse_single_eml(test_file)
            print(f"[+] Parsing di {test_file} completato con successo! Oggetto: {res['subject']}")
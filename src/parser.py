import os
import email
from email import policy
import pandas as pd

class EmailParserPipeline:
    def __init__(self):
        pass

    def parse_single_eml(self, eml_path: str) -> dict:
        """
        Legge un singolo file .eml ed estrae Mittente, Destinatario, Oggetto,
        Data, Header grezzi e il Corpo del testo pulito in modo ricorsivo.
        """
        if not os.path.exists(eml_path):
            raise FileNotFoundError(f"File .eml non trovato in: {eml_path}")

        with open(eml_path, 'rb') as f:
            # Usiamo policy.default che converte automaticamente gli header complessi in stringhe pulite
            msg = email.message_from_binary_file(f, policy=policy.default)

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
    
    # Eseguiamo un check volante se i file sono nella directory corrente
    for test_file in ['test.eml', 'test2.eml', 'test3_good.eml']:
        if os.path.exists(test_file):
            res = parser.parse_single_eml(test_file)
            print(f"[+] Parsing di {test_file} completato con successo! Oggetto: {res['subject']}")
import dns.resolver
import re

class EmailSecurityValidator:
    def __init__(self):
        # Resolver DNS standard
        self.resolver = dns.resolver.Resolver()
        self.resolver.timeout = 5.0
        self.resolver.lifetime = 5.0

    def _extract_domain(self, email_address: str) -> str:
        """Estrae il dominio da un indirizzo email (es. utente@esempio.com -> esempio.com)"""
        match = re.search(r"@([\w.-]+)", email_address)
        return match.group(1).lower() if match else ""

    def check_spf(self, email_address: str) -> dict:
        """Verifica la presenza e la validità del record SPF sul dominio mittente."""
        domain = self._extract_domain(email_address)
        if not domain:
            return {"status": "Error", "record": "", "message": "Dominio non valido"}
        
        try:
            txt_records = self.resolver.resolve(domain, 'TXT')
            for record in txt_records:
                record_text = record.to_text().strip('"')
                if record_text.startswith("v=spf1"):
                    return {"status": "Pass", "record": record_text, "message": "Record SPF trovato"}
            return {"status": "Fail", "record": "", "message": "Nessun record SPF configurato"}
        except Exception as e:
            return {"status": "Error", "record": "", "message": f"Errore DNS: {str(e)}"}

    def check_dmarc(self, email_address: str) -> dict:
        """Verifica la presenza del record DMARC sul dominio mittente (_dmarc.dominio.com)."""
        domain = self._extract_domain(email_address)
        if not domain:
            return {"status": "Error", "record": "", "message": "Dominio non valido"}
        
        dmarc_domain = f"_dmarc.{domain}"
        try:
            txt_records = self.resolver.resolve(dmarc_domain, 'TXT')
            for record in txt_records:
                record_text = record.to_text().strip('"')
                if record_text.startswith("v=DMARC1"):
                    return {"status": "Pass", "record": record_text, "message": "Record DMARC trovato"}
            return {"status": "Fail", "record": "", "message": "Nessun record DMARC configurato"}
        except Exception as e:
            return {"status": "Fail", "record": "", "message": f"Nessun record DMARC o errore DNS: {str(e)}"}

    def check_dkim_presence(self, raw_headers: dict) -> dict:
        """
        In un triage rapido, verifica se l'email dichiara una firma DKIM negli header.
        (La validazione crittografica richiede la chiave pubblica DNS, per ora facciamo un check di presenza)
        """
        # Normalizziamo le chiavi degli header in minuscolo
        headers_lower = {k.lower(): v for k, v in raw_headers.items()}
        if 'dkim-signature' in headers_lower:
            return {"status": "Present", "message": "Firma DKIM rilevata negli header dell'email"}
        return {"status": "Missing", "message": "Firma DKIM assente negli header"}

if __name__ == "__main__":
    # Test rapido di validazione
    validator = EmailSecurityValidator()
    test_email = "security@paypal.com"
    
    print(f"[*] Analisi DNS per: {test_email}")
    print("SPF Check:", validator.check_spf(test_email))
    print("DMARC Check:", validator.check_dmarc(test_email))
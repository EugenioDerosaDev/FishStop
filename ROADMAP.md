# 🗺️ FishStop — Roadmap & Feature Backlog

Questo file traccia le funzionalità da implementare e i miglioramenti da apportare ai moduli esistenti.

---

## ✅ Già implementato

- Parsing header `.eml` (From, To, Subject, Date, Return-Path, Reply-To, Message-Id)
- Catena `Received` hop-by-hop con estrazione IP e TLS
- Validazione SPF / DKIM / DMARC live (con fallback graceful senza librerie)
- Rilevamento mismatch Reply-To ≠ From
- Analisi allegati: magic bytes, Content-Type, estensione (coerenza triplice)
- Classificazione AI con BERT fine-tuned (testo email → legittima / phishing)
- Flag SOC con livelli HIGH / MEDIUM / LOW / INFO
- Interfaccia Streamlit con pannelli espandibili

---

## 🚧 Da implementare

### 1. Ispezione del corpo — MIME e offuscamento HTML

**Modulo coinvolto:** `analyzer.py`

- [ ] **HTML stripping prima dell'analisi testuale**
  Pulire il body HTML dai tag prima di passarlo al modello BERT e ai controlli testuali. Gli attaccanti inseriscono tag o commenti invisibili in mezzo alle parole (es. `Pa<!-- x -->ypal`) per aggirare filtri basati su stringhe. Usare `BeautifulSoup` o `lxml` per lo stripping.

- [ ] **Estrazione e analisi dei link (`<a href>`)** 
  Estrarre tutti i tag `<a href="...">` dal corpo HTML e confrontare il testo cliccabile visibile con la URL reale di destinazione. Una discrepanza (es. testo `"paypal.com"` che punta a `evil.ru`) è un forte segnale di phishing.

- [ ] **Lookalike domain detection (typosquatting + IDN homograph)**
  Controllare i domini estratti dai link contro il dominio del mittente (`From:`). Implementare:
  - Distanza di Levenshtein per il typosquatting (es. `paypa1.com` vs `paypal.com`)
  - Decodifica Punycode per attacchi omografi IDN (es. `pаypal.com` con `а` cirillico → `xn--pypal-4ve.com`)

- [ ] **Rilevamento QR Code (Quishing)**
  Le email di phishing moderne evitano link testuali e usano immagini con QR code per nascondere la URL malevola. Implementare:
  - Isolamento delle immagini incluse nel corpo HTML (tag `<img>` + parti MIME `image/*`)
  - Scansione OCR/QR con `pyzbar` + `Pillow` per estrarre la URL codificata
  - Aggiungere la URL estratta al pool dei link da analizzare

---

### 2. Hashing allegati + Threat Intelligence

**Modulo coinvolto:** `analyzer.py` + nuovo modulo `threat_intel.py`

- [ ] **Calcolo hash SHA-256 di ogni allegato**
  Per ogni allegato estratto dall'`.eml`, calcolare l'hash SHA-256 dei byte grezzi decodificati (già disponibili nella pipeline magic bytes). Esporre l'hash nel report SOC.

- [ ] **Lookup hash su VirusTotal**
  Interrogare l'API VirusTotal v3 (`/files/{hash}`) per ogni hash SHA-256 calcolato. Mostrare nel pannello allegati: numero di engine che lo segnalano, permalink al report VT.

- [ ] **Lookup IP su AbuseIPDB**
  Per ogni IP estratto dalla catena `Received` (injection server e closest-to-sender), interrogare l'API AbuseIPDB (`/check`) e mostrare: abuse confidence score, paese, ISP, numero di segnalazioni.

- [ ] **Lookup IP su VirusTotal**
  Complementare ad AbuseIPDB, usare il endpoint VT `/ip_addresses/{ip}` per reputazione aggiuntiva.

---

## 🔧 Da controllare / migliorare

### 3. Mismatch tra campi envelope

**Modulo coinvolto:** `analyzer.py`, `app.py`

- [ ] **Confronto esteso From / Return-Path / Reply-To**
  Attualmente il codice confronta solo `Reply-To` vs `From`. Aggiungere:
  - Confronto dominio `From:` vs dominio `Return-Path:` — un disallineamento qui è quasi sempre spoofing
  - Confronto dominio `From:` vs dominio nell'ultimo hop `Received:` (closest-to-sender)
  - Tutti i mismatch devono generare un flag `HIGH` con spiegazione esplicita nel pannello SOC

- [ ] **Fix label Reply-To assente**
  Quando `Reply-To` è assente, mostrare `⚪ Assente` invece di `✅ Coerente` — il verde implica un controllo positivo che non è stato eseguito.
  *(Fix già disponibile — da mergiare)*

---

### 4. Analisi catena `Received` + reputazione IP

**Modulo coinvolto:** `analyzer.py`, nuovo `threat_intel.py`

- [ ] **Lettura della catena in ordine corretto (bottom-up)**
  Gli header `Received` vanno letti dal basso verso l'alto: l'ultimo in lista è il server di origine reale (closest-to-sender). Verificare che la UI li presenti con etichette corrette e che il server di iniezione (hop 1 dal basso) sia quello usato per i lookup SPF e Threat Intel.

- [ ] **Reputazione IP automatica per ogni hop**
  Per ogni IP estratto dalla catena `Received`, effettuare un lookup AbuseIPDB / VirusTotal e mostrare inline nel pannello "Catena Received" un badge di reputazione (es. 🟢 Clean / 🟠 Sospetto / 🔴 Malevolo) con il punteggio.

- [ ] **Geolocalizzazione IP**
  Aggiungere paese e ASN per ogni IP della catena usando un'API di geolocalizzazione (es. `ip-api.com` free tier o MaxMind GeoLite2 locale). Utile per rilevare routing anomalo (es. email da banca italiana con hop in Russia).

---

## 📦 Dipendenze da aggiungere a `requirements.txt`

| Libreria | Funzionalità |
|---|---|
| `beautifulsoup4` | HTML stripping e estrazione link |
| `lxml` | Parser HTML veloce (backend per BS4) |
| `pyzbar` | Decodifica QR code da immagini |
| `Pillow` | Lettura immagini per QR scan |
| `python-Levenshtein` | Distanza edit per typosquatting |
| `requests` | Chiamate API VirusTotal / AbuseIPDB |

---

## 🔑 API key necessarie

Da aggiungere come variabili d'ambiente (`.env`):

```
VIRUSTOTAL_API_KEY=...
ABUSEIPDB_API_KEY=...
```




#aggiungere 
aggiungere modo per integrare altre email nel dataset di addestramento. 
aggiungere selezione per far si di essere comply con tesseract 



Link extraction + lookalike domain — altissimo valore, copre una delle tecniche di phishing più comuni
VirusTotal hash lookup automatico — completa qualcosa già visibile nell'UI
Geolocalizzazione IP — aggiunge contesto immediato alla catena Received senza dipendenze pesanti (ip-api.com è free)
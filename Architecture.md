# FishStop — Mappa dell'Architettura del Progetto

Documento di riferimento per capire **cosa fa ogni file** e **come si relaziona agli altri**. Pensato per orientarsi rapidamente nel codice senza dover rileggere tutto da capo.

---

## Vista d'insieme

FishStop è una piattaforma di **triage e detection del phishing** su file `.eml`. Si compone di tre macro-aree:

1. **Parsing & analisi statica** — estrae header, hop di routing, link, allegati da un `.eml` e li arricchisce con euristiche anti-phishing (lookalike domain, display name spoofing, ecc.)
2. **Validazione di sicurezza** — verifica SPF/DKIM/DMARC, reputazione IP/dominio (AbuseIPDB), reputazione file (VirusTotal), geolocalizzazione.
3. **Classificazione AI** — un modello BERT fine-tuned classifica il testo dell'email come phishing/legittima, con possibilità di costruire un dataset custom e riaddestrare il modello aziendale.

Tutto converge in **due interfacce**: una app Streamlit (`app.py`, uso interattivo) e una API REST (`api.py`, uso programmatico).

```
.eml in ingresso
      │
      ├─► src/parser.py  o  src/analyzer/soc_analyzer.py  → estrazione strutturata
      │
      ├─► src/validators/*  → SPF / DKIM / DMARC / reputazione IP & file / geo
      │
      ├─► src/train.py (modello BERT)  → classificazione phishing/legittima
      │
      └─► src/app.py (UI)  o  src/api.py (REST)  → presentazione risultati
```

---

## 1. Ingresso, configurazione e parsing

### `src/config.py`
**Responsabilità:** gestione centralizzata di variabili d'ambiente e segreti (API key di AbuseIPDB e VirusTotal).
Risolve le chiavi con priorità: variabili d'ambiente/`.env` (sviluppo locale) → `st.secrets` di Streamlit (deploy cloud) → stringa vuota come fallback sicuro. Espone `get_secret()` e le costanti `ABUSEIPDB_API_KEY`, `VIRUSTOTAL_API_KEY`, usate da tutto il package `validators`. Eseguibile standalone (`python -m src.config`) per diagnosticare quali chiavi sono configurate.

### `src/parser.py`
**Responsabilità:** parsing "tollerante" di file `.eml` non sempre conformi a RFC 2822 (es. esportazioni da webmail Rackspace o client Exchange non standard).
Contiene `_sanitize_eml_bytes()`, che applica tre fix prima del parsing vero e proprio: rimuove righe iniziali non valide come header, normalizza spazi Unicode usati per il folding degli header, e garantisce la riga vuota di separazione header/body. La classe `EmailParserPipeline` espone `parse_single_eml()` (estrae mittente, destinatario, oggetto, data, header grezzi, corpo) e `load_batch_emls()` (scansiona una cartella e produce un `DataFrame` pronto per il training). È usata principalmente da `train.py` per caricare email locali (`personal_emails`), mentre l'analisi "ricca" per la UI passa invece da `analyzer/soc_analyzer.py`.

### `src/analyzer.py` (file monolitico, legacy)
**Responsabilità:** versione "tutto in uno" — non più importata direttamente da `app.py` — che contiene la stessa logica oggi suddivisa nel package `src/analyzer/` (estrazione link, lookalike domain, magic bytes allegati, parsing Received/Authentication-Results, classe `EmlSOCAnalyzer`). È mantenuto per compatibilità/riferimento storico; la logica "viva" usata dall'app è quella del package `src/analyzer/` (vedi sotto). Da notare: `src/app.py` importa `from src.analyzer import EmlSOCAnalyzer`, che Python risolve sul **package** `src/analyzer/__init__.py`, non su questo file — quindi in pratica questo modulo `analyzer.py` oggi è dead code rispetto al flusso applicativo.

---

## 2. Package `src/analyzer/` — motore di analisi statica/euristica (quello realmente usato)

### `src/analyzer/__init__.py`
**Responsabilità:** API pubblica del package. Riesporta `EmlSOCAnalyzer`, le funzioni di estrazione link/lookalike/allegati/received-parsing/html-stripping e le costanti condivise, così gli altri moduli possono fare `from src.analyzer import EmlSOCAnalyzer`.

### `src/analyzer/soc_analyzer.py`
**Responsabilità:** il vero **motore di analisi SOC**. La classe `EmlSOCAnalyzer.analyze(eml_path)` orchestra tutti i sotto-moduli e produce un report dict completo:
- campi envelope (From, To, Subject, Date, Message-Id…)
- anomalie identità: Reply-To mismatch, Return-Path domain mismatch, Display Name Spoofing
- header ARC
- catena `Received` parsata hop-by-hop (`received_parser`) + IP del server di iniezione per la verifica SPF live
- `Authentication-Results` parsati
- corpo email (plain o HTML-stripped) e allegati analizzati (`attachment.py`)
- link estratti (`link_extractor.py`) e domini lookalike (`lookalike.py`)
- **`flags`**: lista di alert SOC con livello (`HIGH/MEDIUM/LOW/INFO`), generata da `_build_flags()` combinando tutti i segnali sopra.

Questo è l'oggetto (`soc`) che `app.py` consuma per popolare tutta la UI di triage.

### `src/analyzer/received_parser.py`
**Responsabilità:** parsing "enterprise-grade" degli header `Received` e `Authentication-Results`. `parse_received_hop()` estrae IP validi (validati con il modulo `ipaddress`, non solo regex), host `from`/`by`, indirizzo `for`, versione/cipher TLS. `parse_auth_results()` normalizza SPF/DKIM/DMARC secondo RFC 8601.

### `src/analyzer/link_extractor.py`
**Responsabilità:** estrae tutti gli URL dal corpo email (sia da `href` HTML che da testo plain/HTML), deduplicandoli e classificandoli per fonte (`html_href`, `html_text`, `plain_text`) e flaggando URL con IP nudo (`is_ip`).

### `src/analyzer/lookalike.py`
**Responsabilità:** rilevamento di domini lookalike/typosquatting contro una lista di brand noti (`constants.KNOWN_BRANDS`), con tre tecniche: distanza di Levenshtein sul second-level domain, normalizzazione omoglifi Unicode, pattern di typosquatting (prefissi ingannevoli, sostituzioni di caratteri tipo `0↔o`, `rn↔m`).

### `src/analyzer/attachment.py`
**Responsabilità:** analisi forense degli allegati. Decodifica il base64, calcola hash MD5/SHA1/SHA256, identifica il formato reale via magic bytes (`identify_magic_bytes`) e verifica coerenza tra estensione del filename, Content-Type dichiarato e magic bytes — segnalando eventuali mismatch come possibile mascheramento di file malevoli.

### `src/analyzer/html_utils.py`
**Responsabilità:** pulizia HTML → testo. Usa BeautifulSoup (fallback regex) per rimuovere `script/style/head` e ottenere testo pulito, necessario sia per dare un input "pulito" al modello BERT sia per evitare che tag invisibili (es. `Pa<!-- x -->ypal`) aggirino i controlli testuali.

### `src/analyzer/constants.py`
**Responsabilità:** dati statici condivisi: `KNOWN_BRANDS` (domini di brand noti per il lookalike check), `HOMOGLYPH_MAP` (caratteri Unicode che imitano lettere ASCII), `MAGIC_BYTES` (firme binarie per riconoscimento formati file), `CONTENT_TYPE_TO_EXT` (mapping MIME type → estensioni attese).

---

## 3. Package `src/validators/` — controlli di sicurezza esterni (quello realmente usato)

### `src/validators/__init__.py`
**Responsabilità:** facciata `EmailSecurityValidator`, punto di accesso unico usato da `app.py`/`api.py`. Inizializza un `dns.resolver.Resolver` condiviso (timeout ottimizzati per l'interattività) e delega ai singoli moduli SPF/DKIM/DMARC/reputazione/geo. Espone anche `pipeline_analisi_veloce()`, che esegue reputazione IP, reputazione dominio, geolocalizzazione e (opzionalmente) reputazione file **in parallelo** con un `ThreadPoolExecutor`, per non bloccare l'app durante le chiamate HTTP esterne.

### `src/validators/spf.py`
**Responsabilità:** verifica SPF tramite `pyspf` (se installato) sul `sender_ip`/`mail_from`/`helo_domain`; se la libreria manca, fa solo un controllo di presenza del record TXT via DNS (`record-found`/`none`). Restituisce stato (`pass/fail/softfail/...`), record SPF grezzo e messaggio esplicativo.

### `src/validators/dkim.py`
**Responsabilità:** verifica crittografica della firma DKIM tramite `dkimpy`, per ogni firma presente nell'email: estrae dominio (`d=`) e selettore (`s=`), prova la verifica reale e riporta `pass/fail/error` per firma più uno stato complessivo. Senza `dkimpy` installato, fa solo presence-check dell'header.

### `src/validators/dmarc.py`
**Responsabilità:** valutazione DMARC completa: recupera il record TXT `_dmarc.<dominio>` (risalendo al dominio organizzativo se serve), parsa i tag (`p`, `sp`, `pct`, `adkim`, `aspf`, `rua`, `ruf`) e verifica l'**allineamento** SPF/DKIM col dominio `From` in modalità strict o relaxed, determinando `pass`/`fail`.

### `src/validators/ip_reputation.py`
**Responsabilità:** interrogazione di **AbuseIPDB** (`check_ip_reputation`) per il punteggio di abuso di un IP, e `check_domain_reputation` che prima risolve il dominio via DNS in IP e poi interroga AbuseIPDB su quell'IP, gestendo in modo distinto i casi di dominio non risolvibile, nameserver irraggiungibili o timeout.

### `src/validators/geolocation.py`
**Responsabilità:** geolocalizzazione IP tramite `ip-api.com`: ritorna paese/città/ISP/ASN/timezone e due flag rilevanti per il SOC, `is_proxy` e `is_hosting` (indicano IP dietro VPN/proxy o datacenter, segnali tipici di infrastrutture malevole).

### `src/validators/file_reputation.py`
**Responsabilità:** interrogazione di **VirusTotal** (endpoint `/files/{sha256}`) per la reputazione di un allegato via hash. Calcola stato (`malicious/suspicious/clean/not_found`), conteggio engine che lo segnalano, threat label, tipo file e date di prima/ultima sottomissione.

### `src/validators.py` (file monolitico, legacy)
**Responsabilità:** stessa logica del package `src/validators/` ma raccolta in un unico file/classe (`EmailSecurityValidator` "tutto in uno"). Non è importato da `app.py`/`api.py` (che usano il package), quindi è da considerarsi **codice di riferimento/non più in uso attivo** — utile solo come storico o se in futuro si vuole tornare a un'unica classe monolitica.

---

## 4. Componenti UI

### `src/components/__init__.py`
File vuoto, marca `src/components` come package Python.

### `src/components/email_globe.py`
**Responsabilità:** visualizzazione **3D interattiva** (globo terrestre via D3.js + Canvas, iniettato come HTML in `components.html`) del percorso di routing dell'email. `render_email_globe(soc, validator)`:
1. assegna un ruolo a ogni hop (`recipient`, `injection`, `relay`, `sender`)
2. geolocalizza e controlla la reputazione di ogni IP **in parallelo** (`ThreadPoolExecutor`)
3. costruisce l'HTML/JS del globo (`_build_globe_html`) con archi animati tra gli hop, colorati per livello di rischio, tooltip con dettagli al passaggio del mouse
4. mostra anche delle card riassuntive sopra il globo (origine → destinatario)

Usato dentro l'expander "🌍 Percorso geografico email" in `app.py`.

---

## 5. Costruzione dataset e training del modello

### `src/eml_dataset_builder.py`
**Responsabilità:** gestisce il **dataset custom aziendale** costruito a partire da file `.eml` caricati dall'utente nel tab "Dataset Builder" della UI. Classe `EmlDatasetBuilder`:
- preprocessa il testo in modo identico al dataset Kaggle (`subject + body`, HTML stripping, lowercase, rimozione punteggiatura, collasso spazi) per garantire coerenza col formato `xt_combined` usato in training
- `add_eml()` / `add_batch()`: aggiungono email al CSV (`data/custom_dataset.csv`) deduplicando via hash SHA-256 del testo; `add_batch()` è ottimizzato per batch grandi (centinaia di file): carica gli hash esistenti una sola volta, scrive il CSV in un unico flush, e salva i file `.eml` su disco in parallelo
- `remove_by_hash()`, `load_df()`, `stats()`: gestione/consultazione del dataset
- `load_for_training()`: restituisce le colonne pronte per essere concatenate al pool Kaggle in `train.py`

Eseguibile anche da CLI: `python eml_dataset_builder.py <cartella_eml> <label>`.

### `src/train.py`
**Responsabilità:** training e fine-tuning del modello **BERT** per la classificazione phishing/legittima. Classe `BERTPhishingTrainer`:
- rileva automaticamente l'hardware disponibile (Apple Silicon/MPS, CUDA, CPU) e configura batch size/precisione di conseguenza
- `download_and_combine_data()`: scarica il dataset Kaggle (`phishing_email.csv`), lo unisce alle email personali locali (via `EmailParserPipeline`) e al dataset custom (via `EmlDatasetBuilder`), applicando lo stesso preprocessing ovunque
- `prepare_datasets()`: split stratificato 70/10/20 (train/val/test)
- `train()`: fine-tuning completo del modello base (5 epoche, iperparametri allineati al notebook originale), con tokenizzazione lazy-padding e `compute_metrics` (accuracy, f1, precision, recall)
- `finetune_on_custom()`: percorso usato dalla UI ("🚀 Avvia Training" nel Dataset Builder) — fine-tuning **solo sul dataset aziendale custom**, con soglie minime di campioni per classe, avviso di sbilanciamento, learning rate più bassa per non distruggere la conoscenza pregressa del modello, e salvataggio di metadati di training (`training_meta.json`) insieme al modello in `models/company_model/`
- `evaluate_test_set()`: stampa report di classificazione e confusion matrix sul test set isolato

---

## 6. Interfacce applicative

### `src/app.py`
**Responsabilità:** **applicazione Streamlit**, punto di ingresso principale per l'uso interattivo. Due sezioni (radio nella sidebar):

1. **🔍 Triage & Analisi** — upload di un `.eml`, esecuzione di `EmlSOCAnalyzer.analyze()`, poi rendering di:
   - envelope/identità (mismatch Reply-To, Return-Path, Display Name Spoofing)
   - reputazione domini mittente (AbuseIPDB, in parallelo con fallback sul dominio "parent" se il sottodominio non è risolvibile)
   - catena Received hop-by-hop con geolocalizzazione e reputazione IP per ogni hop
   - globo 3D del percorso (`render_email_globe`)
   - SPF/DKIM/DMARC con verifica live e confronto con gli header `Authentication-Results` dichiarati
   - allegati (magic bytes, hash, VirusTotal)
   - link e domini lookalike
   - corpo email pulito/raw
   - riepilogo flag SOC
   - **classificazione BERT** del testo (modello aziendale se presente, altrimenti modello base da Hugging Face `eugenioderodev/fishstop-bert`)

2. **🗃️ Dataset Builder** — upload batch di `.eml` con assegnazione label (singola o di massa), statistiche del dataset custom, tabella consultabile con filtro e rimozione per hash, reset completo, e pannello per avviare il training del modello aziendale (`BERTPhishingTrainer.finetune_on_custom`) con relative metriche.

Contiene anche `_strip_encoded_content()`, helper che ripulisce blocchi base64/quoted-printable dal testo grezzo mostrato nel debugger laterale (sidebar), per leggibilità.

`init_backend()` è cachata con `@st.cache_resource`: istanzia parser, validator, analyzer e carica tokenizer/modello una sola volta per sessione, scegliendo tra modello aziendale locale, modello base locale, o fallback su Hugging Face.

### `src/api.py`
**Responsabilità:** **API REST FastAPI**, alternativa programmatica alla UI Streamlit (stesso motore di analisi, nessuna classificazione BERT esposta qui — solo analisi statica/euristica + reputazione). Endpoint:
- `GET /health` — healthcheck
- `POST /analyze` — upload `.eml` → report completo (header, flags, link, lookalike, allegati, corpo pulito) tramite `EmlSOCAnalyzer`
- `GET /analyze/flags-only` — versione leggera, solo flag SOC (utile per integrazioni che vogliono solo il verdetto, non tutto il dettaglio)
- `POST /check-ip` — reputazione IP via `EmailSecurityValidator.check_ip_reputation`
- `POST /check-domain` — reputazione dominio via `EmailSecurityValidator.check_domain_reputation`

Istanzia `analyzer` e `validator` come singleton a livello di modulo (thread-safe per operazioni di sola lettura).

---

## 7. File di base

### `src/__init__.py`
File vuoto, marca `src` come package Python root del progetto.

---

## Note architetturali importanti

- **Duplicazione intenzionale (legacy vs attivo):** esistono due implementazioni parallele per analyzer (`src/analyzer.py` vs package `src/analyzer/`) e validators (`src/validators.py` vs package `src/validators/`). In Python, quando un modulo e un package hanno lo stesso nome nello stesso livello, l'import `from src.analyzer import ...` risolve sul **package** (cartella con `__init__.py`), quindi i file singoli `analyzer.py`/`validators.py` sono effettivamente **non usati** dal flusso applicativo corrente (`app.py`, `api.py`). Vale la pena valutare se rimuoverli per evitare confusione futura, dato che la logica è già duplicata identica nei package.
- **Flusso dei dati di training:** `train.py` combina tre fonti — Kaggle, cartelle locali `personal_emails`/`custom_legitimate`/`custom_phishing` (via `parser.py`), e il dataset costruito interattivamente (`eml_dataset_builder.py` + tab Dataset Builder in `app.py`) — applicando sempre lo stesso preprocessing testuale per garantire coerenza del modello.
- **Parallelizzazione:** ricorrente in tutto il progetto l'uso di `ThreadPoolExecutor` per le chiamate I/O-bound (reputazione IP/dominio, geolocalizzazione), per mantenere la UI reattiva nonostante le tante chiamate HTTP esterne (AbuseIPDB, VirusTotal, ip-api.com, DNS).

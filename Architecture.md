Questo archivio contiene i componenti core per l'analisi forense e il rilevamento automatico del phishing all'interno di file `.eml`. Il sistema combina controlli di sicurezza tradizionali (DNS/Reputazione) con un modello predittivo basato su Intelligenza Artificiale (BERT).

---

## Struttura dei Moduli e Responsabilità

### 1. `src/analyzer.py`
**Responsabilità del file:** Estrazione dinamica e analisi forense in stile SOC del contenuto strutturato di un file `.eml`.
* **Classe `EmlSOCAnalyzer`**
  * `analyze(eml_path)`: Coordina l'estrazione dell'envelope, degli header, del testo, dei link e degli allegati.
  * `_extract_spf_sender_ip(msg, hops)`: Identifica l'IP pubblico originario del mittente analizzando la catena di server.
  * `_check_dkim_signature_present(msg)`: Verifica se l'header della firma DKIM è fisicamente presente.
  * `_parse_attachments(msg)`: Estrae metadati e calcola l'hash SHA-256 degli allegati.
  * `_build_flags(report)`: Genera indicatori di allerta rapidi (flag di sicurezza) basandosi sui dati estratti.
  * *Interazioni:* Utilizza le librerie native `email` e `re`, e collabora con le funzioni globali di pulizia del testo e controllo dei domini sosia (`KNOWN_BRANDS`).

### 2. `src/validators.py`
**Responsabilità del file:** Validazione tecnica dei protocolli di autenticazione e interrogazione dei servizi di reputazione esterni.
* **Classe `EmailSecurityValidator`**
  * `check_spf(sender_ip, mail_from, ...)`: Controlla se l'IP del mittente è autorizzato nel record DNS SPF del dominio.
  * `check_dkim(raw_eml_bytes)`: Valida crittograficamente la firma DKIM leggendo la chiave pubblica dal DNS.
  * `check_dmarc(from_header, ...)`: Verifica l'allineamento DMARC tra l'header From e i risultati SPF/DKIM.
  * `check_ip_reputation(ip)`: Interroga le API esterne di **AbuseIPDB** per verificare la reputazione dell'IP.
  * `check_domain_reputation(domain)`: Risolve il dominio e ne controlla l'IP tramite `check_ip_reputation`.
  * `check_file_hash_vt(sha256)`: Verifica la firma/hash degli allegati sul database malware di **VirusTotal**.
  * `geolocate_ip(ip)`: Ottiene la posizione geografica e l'ISP dell'IP tramite l'endpoint di **ip-api.com**.
  * *Interazioni:* Dialoga direttamente con i server DNS, con i servizi API di terze parti e con `src/config.py` per le chiavi segrete.

### 3. `src/parser.py`
**Responsabilità del file:** Parsing e sanificazione a basso livello dei file `.eml` grezzi sul disco.
* **Classe `EmailParserPipeline`**
  * `parse_single_eml(eml_path)`: Esegue il parsing di base di un singolo file `.eml` estraendo mittente, destinatario, oggetto, data e corpo.
  * `load_batch_emls(folder_path)`: Scansiona una cartella locale e unisce il parsing di tutte le email in un DataFrame.
  * *Interazioni:* Utilizza una funzione globale di sanificazione (`_sanitize_eml_bytes`) per correggere i file `.eml` non standard prima del parsing e restituisce strutture dati compatibili con `pandas`.

### 4. `src/eml_dataset_builder.py`
**Responsabilità del file:** Costruzione, deduplicazione e gestione di un dataset personalizzato (CSV) partendo da file `.eml` locali.
* **Classe `EmlDatasetBuilder`**
  * `_load_hashes()`: Carica gli hash dei testi già censiti nel CSV per evitare inserimenti duplicati.
  * `add_eml(eml_bytes, ...)`: Preprocessa il testo di una singola email e lo accoda al dataset se non duplicato.
  * `add_batch(items, ...)`: Gestisce l'elaborazione parallela multithreading di un blocco di email.
  * `remove_by_hash(text_hash)`: Rimuove un record specifico dal file CSV tramite il suo hash identitativo.
  * *Interazioni:* Scrive sul file di database `data/custom_dataset.csv` e interagisce con le routine globali di normalizzazione del testo.

### 5. `src/train.py`
**Responsabilità del file:** Orchestrazione del ciclo di addestramento, bilanciamento dati e valutazione del modello di Deep Learning (BERT).
* **Classe `BERTPhishingTrainer`**
  * `download_and_combine_data(...)`: Unisce e bilancia i dati provenienti da Kaggle, dalle email personali e dal dataset custom.
  * `prepare_datasets(df)`: Concatena i campi di testo, esegue la tokenizzazione per BERT e suddivide in Train/Val/Test.
  * `train(train_data, val_data)`: Configura e avvia il processo di fine-tuning sul modello Transformers selezionato.
  * `evaluate_test_set(trainer, test_data)`: Calcola e stampa metriche di classificazione (F1-score, Precision, Recall, Matrice di Confusione).
  * *Interazioni:* Interagisce con l'hardware locale (`torch`), scarica i dati tramite `kagglehub`, importa `EmailParserPipeline` ed effettua il fine-tuning tramite la libreria `transformers` (Hugging Face).

### 6. File di Configurazione e Interfaccia (Procedurali)
* **`src/config.py`**: Gestisce centralmente il caricamento sicuro delle chiavi API (`get_secret()`) dando priorità al file locale `.env` o a `st.secrets` di Streamlit Cloud. Interagisce con `validators.py`.
* **`app.py`**: Interfaccia grafica utente realizzata in **Streamlit**. Non contiene classi; istanzia `EmlSOCAnalyzer`, `EmailSecurityValidator` e il modello BERT per fornire all'analista una dashboard web in cui caricare le email e visualizzare i verdetti di sicurezza.
"""

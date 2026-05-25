# 🛡️ FishStop — Phishing Email Detection

FishStop è un tool SOC per l'analisi e il triage di email sospette in formato `.eml`. Combina analisi degli header (SPF / DKIM / DMARC), ispezione degli allegati tramite magic bytes e classificazione AI con BERT fine-tuned su dataset di phishing.

---

## Struttura del progetto

```
fishstop/
├── src/
│   ├── app.py          # Interfaccia Streamlit
│   ├── analyzer.py     # Parsing SOC degli header .eml
│   ├── validators.py   # Validazione SPF / DKIM / DMARC live
│   ├── parser.py       # Pipeline parsing batch di file .eml
│   └── train.py        # Fine-tuning BERT per classificazione phishing
├── models/
│   └── saved_models/   # Modello BERT addestrato (generato da train.py)
├── data/
│   └── raw/
│       └── personal_emails/  # Email .eml personali per arricchire il training
├── logs/               # Log di training HuggingFace
├── requirements.txt
└── README.md
```

---

## Setup ambiente (Mac)

```bash
# Crea l'ambiente virtuale
python3 -m venv .venv

# Attivalo
source .venv/bin/activate

# Aggiorna pip e installa le dipendenze
pip install --upgrade pip
pip install -r requirements.txt
```

---

## Avvio dell'app

```bash
./.venv/bin/streamlit run src/app.py
```

Apri il browser su `http://localhost:8501`, trascina un file `.eml` e ottieni il triage completo.

---

## Training del modello BERT

Il modello viene addestrato su 15.000 email dal dataset Kaggle `naserabdullahalam/phishing-email-dataset`, con supporto opzionale per email `.eml` locali nella cartella `data/raw/personal_emails/`.

```bash
./.venv/bin/python src/train.py
```

Il modello fine-tuned viene salvato in `models/saved_models/` e caricato automaticamente dall'app.

**Parametri di training:**

| Parametro | Valore |
|---|---|
| Modello base | `bert-base-uncased` |
| Epoche | 5 |
| Learning rate | 2e-5 |
| Weight decay | 0.01 |
| Optimizer | AdamW |
| Batch size (GPU/Mac) | 16 |
| Batch size (CPU) | 4 × grad_accum 4 = 16 effettivo |
| Split | 70% train / 10% val / 20% test |
| Best model metric | F1 |

---

## Troubleshooting

Se il training si interrompe con errori legati ad `accelerate` o `transformers`:

```bash
./.venv/bin/pip install --upgrade "accelerate>=1.1.0" "transformers[torch]"
```

Se `dkimpy` o `pyspf` non sono disponibili, i controlli DKIM e SPF degradano automaticamente a una verifica di presenza (nessun crash).

---

## Aggiornare il repository

```bash
git add .
git commit -m "descrizione delle modifiche"
git push origin main
```

---

## Dipendenze principali

- `streamlit` — interfaccia web
- `transformers` + `torch` — modello BERT
- `datasets` — gestione dataset HuggingFace
- `scikit-learn` — metriche di valutazione
- `dnspython` — lookup DNS per SPF / DMARC
- `dkimpy` — verifica crittografica DKIM *(opzionale)*
- `pyspf` — valutazione record SPF *(opzionale)*
- `kagglehub` — download automatico del dataset

Installa tutto con:

```bash
pip install -r requirements.txt
```



#todo
1. abbassare il rischio dei domini lookalike 
2. sample_1043 spf error (softfail, da modellare, cosi come permerror ecc. )
3. sample_1043 lookalike Falsi positivi, sito corto come t.co sembra altri
4. usare cursor?

import os
import sys

# Forza Python a riconoscere la cartella radice per trovare 'src.parser'
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# Carica variabili d'ambiente da .env (Kaggle, API keys, ecc.)
try:
    from dotenv import load_dotenv
    load_dotenv(override=False)
except ImportError:
    pass  # python-dotenv opzionale — le variabili devono essere già in env


import pandas as pd
import numpy as np
import torch
import kagglehub
from sklearn.model_selection import train_test_split
from sklearn.metrics import (
    accuracy_score, precision_recall_fscore_support,
    classification_report, confusion_matrix,
    precision_score, recall_score, f1_score
)
from transformers import BertTokenizer, BertForSequenceClassification
from transformers import Trainer, TrainingArguments
from transformers import DataCollatorWithPadding
from datasets import Dataset

# Importazione del parser ottimizzato per gli EML locali
from src.parser import EmailParserPipeline
from src.eml_dataset_builder import EmlDatasetBuilder


class BERTPhishingTrainer:
    def __init__(self, model_name="bert-base-uncased", num_labels=2):
        print("[*] Inizializzazione di BERT Tokenizer e Modello...")
        self.tokenizer = BertTokenizer.from_pretrained(model_name)
        self.model = BertForSequenceClassification.from_pretrained(model_name, num_labels=num_labels)

        # RILEVAMENTO AUTOMATICO DELL'AMBIENTE E CONFIGURAZIONE HARDWARE
        if torch.backends.mps.is_available():
            self.device = "mps"
            self.is_mac = True
            os.environ["PYTORCH_MPS_HIGH_WATERMARK_RATIO"] = "0.0"
            print("[🍏 AMBIENTE: MACBOOK DETECTED] Rilevato chip Apple Silicon. Attivazione ottimizzazioni GPU (MPS).")
        elif torch.cuda.is_available():
            self.device = "cuda"
            self.is_mac = False
            print("[⚡ AMBIENTE: CUDA DETECTED] Rilevata GPU Nvidia.")
        else:
            self.device = "cpu"
            self.is_mac = False
            print("[☁️ AMBIENTE: CLOUD/CPU DETECTED] Esecuzione su CPU standard (perfetto per Codespaces).")

        self.model.to(self.device)
        print(f"[+] Modello configurato sul dispositivo di calcolo: {self.device}")

    # ------------------------------------------------------------------
    # DATA
    # ------------------------------------------------------------------

    def download_and_combine_data(self, personal_eml_folder="data/raw/personal_emails", sample_size=15000):
        """
        Scarica il dataset da Kaggle, normalizza le colonne, esegue il
        parsing delle email locali e applica il preprocessing del notebook:
        - dropna
        - label → int
        - lowercase only (URL, simboli, punteggiatura preservati come da notebook)
        """
        print("[*] Interrogazione e recupero del dataset principale da KaggleHub...")
        kaggle_dir = kagglehub.dataset_download("naserabdullahalam/phishing-email-dataset")

        csv_path = os.path.join(kaggle_dir, "phishing_email.csv")
        if not os.path.exists(csv_path):
            files = [f for f in os.listdir(kaggle_dir) if f.endswith('.csv')]
            if files:
                csv_path = os.path.join(kaggle_dir, files[0])
            else:
                raise FileNotFoundError(f"Impossibile trovare file CSV in: {kaggle_dir}")

        print(f"[+] Dataset Kaggle caricato da: {csv_path}")
        df_kaggle = pd.read_csv(csv_path)

        # Normalizzazione nomi colonne
        df_kaggle.columns = [col.lower().strip() for col in df_kaggle.columns]
        rename_dict = {}
        for col in df_kaggle.columns:
            if 'text' in col or 'body' in col or 'email' in col:
                rename_dict[col] = 'text'
            elif 'label' in col or 'class' in col or 'target' in col:
                rename_dict[col] = 'label'
        if rename_dict:
            df_kaggle.rename(columns=rename_dict, inplace=True)

        # Campionamento — 15.000 righe come da notebook
        print(f"[*] Campionamento di {sample_size} righe...")
        if len(df_kaggle) > sample_size:
            df_kaggle = df_kaggle.sample(n=sample_size, random_state=42).reset_index(drop=True)

        # Preprocessing identico al notebook
        df_kaggle.dropna(subset=['text', 'label'], inplace=True)
        df_kaggle['label'] = df_kaggle['label'].astype(int)
        df_kaggle['text'] = df_kaggle['text'].apply(lambda x: str(x).lower())

        # Integrazione email personali
        parser = EmailParserPipeline()
        
        # LOGICA CORRETTA: puntiamo alle sottocartelle dentro data/raw
        base_raw_folder = "data/raw"
        personal_legit_folder = os.path.join(base_raw_folder, "custom_legitimate")
        personal_phish_folder = os.path.join(base_raw_folder, "custom_phishing")
        
        df_list = []
        
        # 1. Carica le email legittime custom (Label 0)
        if os.path.exists(personal_legit_folder):
            df_legit = parser.load_batch_emls(personal_legit_folder)
            if not df_legit.empty:
                df_list.append(pd.DataFrame({
                    'text': df_legit['body'].apply(lambda x: str(x).lower()),
                    'label': 0
                }))
                print(f"[*] Caricate {len(df_legit)} email custom LEGITTIME (Label 0).")

        # 2. Carica le email di phishing custom (Label 1)
        if os.path.exists(personal_phish_folder):
            df_phish = parser.load_batch_emls(personal_phish_folder)
            if not df_phish.empty:
                df_list.append(pd.DataFrame({
                    'text': df_phish['body'].apply(lambda x: str(x).lower()),
                    'label': 1
                }))
                print(f"[*] Caricate {len(df_phish)} email custom di PHISHING (Label 1).")

        # Unione dei dati custom locali al pool di Kaggle, se presenti
        if df_list:
            df_personal_aligned = pd.concat(df_list, ignore_index=True)
            df_personal_aligned.dropna(subset=['text'], inplace=True)
            df_combined = pd.concat([df_kaggle, df_personal_aligned], ignore_index=True)
            print(f"[*] Integrazione attiva: unione di {len(df_personal_aligned)} email locali totali.")
        else:
            print("[!] Nessuna email trovata in custom_legitimate o custom_phishing. Si procede solo con Kaggle.")
            df_combined = df_kaggle

        # ── Integrazione dataset custom (EmlDatasetBuilder) ───────────────
        # Legge data/custom_dataset.csv se esiste — prodotto dal tab
        # "Dataset Builder" dell'app. Il testo è già preprocessato nel
        # formato xt_combined, compatibile con il pool Kaggle.
        try:
            custom_builder = EmlDatasetBuilder()
            df_custom = custom_builder.load_for_training()
            if not df_custom.empty:
                df_custom['text'] = df_custom['text'].apply(lambda x: str(x).lower())
                df_custom.dropna(subset=['text'], inplace=True)
                df_combined = pd.concat([df_combined, df_custom], ignore_index=True)
                s = custom_builder.stats()
                print(
                    f"[*] Dataset custom caricato: {len(df_custom)} righe "
                    f"({s['legitimate']} legittime, {s['phishing']} phishing)"
                )
            else:
                print("[!] Nessun dato custom trovato in data/custom_dataset.csv — ignorato.")
        except Exception as e:
            print(f"[!] Impossibile caricare il dataset custom: {e} — ignorato.")

        print(f"[+] Pool dei dati pronto. Dimensione totale campioni: {len(df_combined)}")
        return df_combined

    # ------------------------------------------------------------------
    # SPLIT  —  70 / 10 / 20  identico al notebook
    # ------------------------------------------------------------------

    def prepare_datasets(self, df):
        """
        Split 70% train / 10% val / 20% test con stratify su label,
        esattamente come nel notebook (due chiamate a train_test_split).
        """
        # 1. Isola il 20% di test
        train_val_df, test_df = train_test_split(
            df, test_size=0.20, random_state=42, stratify=df['label']
        )
        # 2. Dal rimanente 80% prendi 12.5% come val → 10% del totale
        train_df, val_df = train_test_split(
            train_val_df, test_size=0.125, random_state=42, stratify=train_val_df['label']
        )

        print(f"[*] Suddivisione -> Train: {len(train_df)} | Val: {len(val_df)} | Test: {len(test_df)}")
        return (
            Dataset.from_pandas(train_df.reset_index(drop=True)),
            Dataset.from_pandas(val_df.reset_index(drop=True)),
            Dataset.from_pandas(test_df.reset_index(drop=True)),
        )

    # ------------------------------------------------------------------
    # TOKENIZZAZIONE  —  DataCollatorWithPadding (lazy padding) come notebook
    # ------------------------------------------------------------------

    def _tokenize_function(self, examples):
        """
        Tokenizzazione per-sample con truncation a 512 token.
        Il padding viene gestito in modo lazy dal DataCollatorWithPadding
        al momento del batching, esattamente come nel notebook.
        """
        return self.tokenizer(examples['text'], truncation=True, max_length=512)

    # ------------------------------------------------------------------
    # METRICHE  —  accuracy, f1, precision, recall come da notebook
    # ------------------------------------------------------------------

    @staticmethod
    def compute_metrics(eval_pred):
        logits, labels = eval_pred
        preds = np.argmax(logits, axis=1)
        precision, recall, f1, _ = precision_recall_fscore_support(labels, preds, average='binary')
        acc = accuracy_score(labels, preds)
        return {'accuracy': acc, 'f1': f1, 'precision': precision, 'recall': recall}

    # ------------------------------------------------------------------
    # TRAINING
    # ------------------------------------------------------------------

    def train(self, train_dataset, val_dataset, output_dir="./models/saved_models"):
        """
        Tokenizza i dataset e avvia il fine-tuning di BERT con i parametri
        allineati al notebook:
          - 5 epoche
          - metric_for_best_model = "f1"  (più robusta di accuracy su classi sbilanciate)
          - optimizer adamw_torch esplicito
          - batch size adattivo all'hardware con gradient accumulation
        """
        print("[*] Tokenizzazione dei dataset (batched=True per efficienza)...")
        train_tokenized = train_dataset.map(self._tokenize_function, batched=True)
        val_tokenized   = val_dataset.map(self._tokenize_function, batched=True)

        data_collator = DataCollatorWithPadding(tokenizer=self.tokenizer)

        # Configurazione hardware-aware del batch size
        if self.is_mac:
            # Mac Apple Silicon (MPS): batch più grande, bf16 nativo
            train_batch = 16
            grad_accum  = 1
            use_bf16    = True
            log_strategy = "epoch"
        elif self.device == "cuda":
            # GPU Nvidia: batch pieno come il notebook
            train_batch = 16
            grad_accum  = 1
            use_bf16    = False
            log_strategy = "epoch"
        else:
            # CPU (Codespaces / macchine senza GPU): batch ridotto + accumulation
            # per simulare batch_size=16 effettivo (4 × 4 = 16)
            train_batch = 4
            grad_accum  = 4
            use_bf16    = False
            log_strategy = "epoch"

        print(f"[*] Configurazione Trainer -> Batch: {train_batch} | GradAccum: {grad_accum} | BF16: {use_bf16}")

        training_args = TrainingArguments(
            output_dir=output_dir,

            # ── iperparametri identici al notebook ──────────────────────
            learning_rate=2e-5,
            num_train_epochs=5,                  # era 3, notebook usa 5
            weight_decay=0.01,
            optim="adamw_torch",                 # esplicito come nel notebook

            # ── batch / hardware ────────────────────────────────────────
            per_device_train_batch_size=train_batch,
            per_device_eval_batch_size=train_batch,
            gradient_accumulation_steps=grad_accum,
            bf16=use_bf16,
            dataloader_pin_memory=False,
            dataloader_num_workers=0,

            # ── checkpointing ────────────────────────────────────────────
            eval_strategy="epoch",
            save_strategy="epoch",
            save_total_limit=2,                  # mantieni solo i 2 migliori checkpoint
            load_best_model_at_end=True,
            metric_for_best_model="f1",          # era "accuracy", notebook usa "f1"
            greater_is_better=True,

            # ── logging ──────────────────────────────────────────────────
            logging_dir='./logs',
            logging_strategy=log_strategy,
            report_to="none",
        )

        trainer = Trainer(
            model=self.model,
            args=training_args,
            train_dataset=train_tokenized,
            eval_dataset=val_tokenized,
            processing_class=self.tokenizer,
            data_collator=data_collator,
            compute_metrics=self.compute_metrics,
        )

        print("[*] Inizio fine-tuning BERT (5 epoche)...")
        trainer.train()

        os.makedirs(output_dir, exist_ok=True)
        self.model.save_pretrained(output_dir)
        self.tokenizer.save_pretrained(output_dir)
        print(f"[+] Modello e tokenizer salvati in: {output_dir}")
        return trainer

    # ------------------------------------------------------------------
    # FINE-TUNING SU DATASET AZIENDALE
    # ------------------------------------------------------------------

    # Soglie minime per garantire un training significativo
    MIN_SAMPLES_PER_CLASS = 20   # sotto questa soglia il training è inaffidabile
    IMBALANCE_RATIO_WARN  = 5    # avvisa se la classe maggioritaria è >5x la minoritaria

    def finetune_on_custom(
        self,
        base_model_path: str = "./models/saved_models",
        output_dir:       str = "./models/company_model",
        num_epochs:       int = 5,
        progress_callback=None,   # callable(step: str, pct: int) per aggiornare la UI
    ) -> dict:
        """
        Fine-tuning del modello base su SOLO il dataset aziendale custom
        (data/custom_dataset.csv). Nessuna dipendenza da Kaggle o API esterne.

        Flusso:
          1. Carica il dataset custom da EmlDatasetBuilder
          2. Valida soglie minime (campioni per classe, bilanciamento)
          3. Carica il modello base (saved_models o bert-base-uncased come fallback)
          4. Split 70/10/20 con stratify
          5. Fine-tuning con iperparametri conservativi (lr bassa per preservare
             la conoscenza generale di BERT sul phishing)
          6. Salva in models/company_model/
          7. Restituisce un dict con metriche e path

        Returns
        -------
        {
          "status"   : "ok" | "error" | "insufficient_data",
          "message"  : str,
          "metrics"  : dict | None,   # accuracy, f1, precision, recall sul test set
          "model_path": str,
        }
        """
        def _progress(step: str, pct: int):
            print(f"[{pct:3d}%] {step}")
            if progress_callback:
                progress_callback(step, pct)

        _progress("Caricamento dataset custom…", 0)

        # ── 1. Carica e valida il dataset ──────────────────────────────────
        try:
            custom_builder = EmlDatasetBuilder()
            df = custom_builder.load_for_training()
        except Exception as exc:
            return {"status": "error", "message": f"Errore lettura dataset: {exc}",
                    "metrics": None, "model_path": ""}

        if df.empty:
            return {
                "status":  "insufficient_data",
                "message": "Il dataset custom è vuoto. Aggiungi email prima di addestrare.",
                "metrics": None, "model_path": "",
            }

        # Conta per classe
        counts = df["label"].value_counts().to_dict()
        n_legit    = counts.get(0, 0)
        n_phishing = counts.get(1, 0)
        n_total    = len(df)

        # Blocco: soglia minima per classe
        if n_legit < self.MIN_SAMPLES_PER_CLASS or n_phishing < self.MIN_SAMPLES_PER_CLASS:
            return {
                "status":  "insufficient_data",
                "message": (
                    f"Dataset troppo piccolo: {n_legit} email legittime, {n_phishing} phishing. "
                    f"Servono almeno {self.MIN_SAMPLES_PER_CLASS} campioni per classe. "
                    "Aggiungi altre email e riprova."
                ),
                "metrics": None, "model_path": "",
            }

        # Avviso sbilanciamento (non blocca, ma viene riportato)
        imbalance_warning = None
        if n_legit > 0 and n_phishing > 0:
            ratio = max(n_legit, n_phishing) / min(n_legit, n_phishing)
            if ratio > self.IMBALANCE_RATIO_WARN:
                minority = "legittime" if n_legit < n_phishing else "phishing"
                imbalance_warning = (
                    f"⚠️ Dataset sbilanciato ({ratio:.1f}x): poche email {minority}. "
                    "Il modello potrebbe essere meno preciso su quella classe."
                )
                print(f"[!] {imbalance_warning}")

        _progress(f"Dataset: {n_total} campioni ({n_legit} legittime, {n_phishing} phishing)", 5)

        # ── 2. Carica modello base ─────────────────────────────────────────
        _progress("Caricamento modello base…", 10)
        try:
            from transformers import AutoTokenizer, AutoModelForSequenceClassification
            if os.path.isdir(base_model_path):
                self.tokenizer = AutoTokenizer.from_pretrained(base_model_path)
                self.model     = AutoModelForSequenceClassification.from_pretrained(
                    base_model_path, num_labels=2
                )
                print(f"[+] Modello base caricato da: {base_model_path}")
            else:
                # Fallback a bert-base-uncased se il modello base non esiste
                self.tokenizer = AutoTokenizer.from_pretrained("bert-base-uncased")
                self.model     = AutoModelForSequenceClassification.from_pretrained(
                    "bert-base-uncased", num_labels=2
                )
                print("[!] Modello base non trovato — uso bert-base-uncased come fallback")
            self.model.to(self.device)
        except Exception as exc:
            return {"status": "error", "message": f"Errore caricamento modello: {exc}",
                    "metrics": None, "model_path": ""}

        # ── 3. Split 70/10/20 con stratify ────────────────────────────────
        _progress("Preparazione split train/val/test…", 15)
        try:
            train_val_df, test_df = train_test_split(
                df, test_size=0.20, random_state=42, stratify=df["label"]
            )
            # Se il dataset è piccolo adattiamo la val (min 1 campione per classe)
            val_size = max(0.125, 2 / len(train_val_df)) if len(train_val_df) >= 4 else 0.25
            train_df, val_df = train_test_split(
                train_val_df, test_size=val_size, random_state=42,
                stratify=train_val_df["label"]
            )
        except ValueError as exc:
            return {"status": "error",
                    "message": f"Errore nello split — probabilmente dataset ancora troppo piccolo: {exc}",
                    "metrics": None, "model_path": ""}

        print(f"[*] Split -> Train: {len(train_df)} | Val: {len(val_df)} | Test: {len(test_df)}")

        train_ds = Dataset.from_pandas(train_df.reset_index(drop=True))
        val_ds   = Dataset.from_pandas(val_df.reset_index(drop=True))
        test_ds  = Dataset.from_pandas(test_df.reset_index(drop=True))

        # ── 4. Tokenizzazione ─────────────────────────────────────────────
        _progress("Tokenizzazione…", 20)
        train_tok = train_ds.map(self._tokenize_function, batched=True)
        val_tok   = val_ds.map(self._tokenize_function,   batched=True)
        test_tok  = test_ds.map(self._tokenize_function,  batched=True)

        data_collator = DataCollatorWithPadding(tokenizer=self.tokenizer)

        # ── 5. Iperparametri ──────────────────────────────────────────────
        # Learning rate più bassa (1e-5) rispetto al training Kaggle (2e-5):
        # preserva la conoscenza generale e riduce l'overfitting su dataset piccoli.
        # Epoche più basse sul dataset piccolo per lo stesso motivo.
        if self.is_mac:
            train_batch, grad_accum, use_bf16 = 8, 1, True
        elif self.device == "cuda":
            train_batch, grad_accum, use_bf16 = 8, 1, False
        else:
            train_batch, grad_accum, use_bf16 = 2, 4, False

        os.makedirs(output_dir, exist_ok=True)

        _progress("Avvio training…", 25)

        training_args = TrainingArguments(
            output_dir=output_dir,
            learning_rate=1e-5,
            num_train_epochs=num_epochs,
            weight_decay=0.01,
            optim="adamw_torch",
            per_device_train_batch_size=train_batch,
            per_device_eval_batch_size=train_batch,
            gradient_accumulation_steps=grad_accum,
            bf16=use_bf16,
            dataloader_pin_memory=False,
            dataloader_num_workers=0,
            eval_strategy="epoch",
            save_strategy="epoch",
            save_total_limit=1,
            load_best_model_at_end=True,
            metric_for_best_model="f1",
            greater_is_better=True,
            logging_dir=os.path.join(output_dir, "logs"),
            logging_strategy="epoch",
            report_to="none",
        )

        trainer = Trainer(
            model=self.model,
            args=training_args,
            train_dataset=train_tok,
            eval_dataset=val_tok,
            processing_class=self.tokenizer,
            data_collator=data_collator,
            compute_metrics=self.compute_metrics,
        )

        try:
            trainer.train()
        except Exception as exc:
            return {"status": "error", "message": f"Errore durante il training: {exc}",
                    "metrics": None, "model_path": ""}

        # ── 6. Salva il modello aziendale ─────────────────────────────────
        _progress("Salvataggio modello…", 85)
        self.model.save_pretrained(output_dir)
        self.tokenizer.save_pretrained(output_dir)

        # Salva metadati del training (data, campioni usati, metriche)
        import json
        from datetime import datetime, timezone
        meta = {
            "trained_at":   datetime.now(timezone.utc).isoformat(),
            "base_model":   base_model_path,
            "n_train":      len(train_df),
            "n_val":        len(val_df),
            "n_test":       len(test_df),
            "n_legitimate": n_legit,
            "n_phishing":   n_phishing,
            "epochs":       num_epochs,
            "imbalance_warning": imbalance_warning,
        }

        # ── 7. Valutazione test set ────────────────────────────────────────
        _progress("Valutazione sul test set…", 90)
        try:
            preds_out = trainer.predict(test_tok)
            y_true = test_tok["label"]
            y_pred = np.argmax(preds_out.predictions, axis=1)
            metrics = {
                "accuracy":  round(float(accuracy_score(y_true, y_pred)),  4),
                "precision": round(float(precision_score(y_true, y_pred, zero_division=0)), 4),
                "recall":    round(float(recall_score(y_true, y_pred, zero_division=0)),    4),
                "f1":        round(float(f1_score(y_true, y_pred, zero_division=0)),        4),
            }
            meta["metrics"] = metrics
            print(f"\n[+] Test set — Accuracy: {metrics['accuracy']} | F1: {metrics['f1']} | "
                  f"Precision: {metrics['precision']} | Recall: {metrics['recall']}")
        except Exception as exc:
            metrics = None
            meta["metrics"] = {}
            print(f"[!] Valutazione test set fallita: {exc}")

        with open(os.path.join(output_dir, "training_meta.json"), "w") as f:
            json.dump(meta, f, indent=2)

        _progress("Completato ✅", 100)

        msg = f"Modello aziendale addestrato su {n_total} email e salvato in `{output_dir}`."
        if imbalance_warning:
            msg += f"\n{imbalance_warning}"

        return {
            "status":     "ok",
            "message":    msg,
            "metrics":    metrics,
            "model_path": output_dir,
            "meta":       meta,
        }

    # ------------------------------------------------------------------
    # VALUTAZIONE TEST SET  —  allineata al notebook (+ confusion matrix)
    # ------------------------------------------------------------------

    def evaluate_test_set(self, trainer, test_dataset):
        """
        Valuta il modello sul test set isolato con le stesse metriche del notebook:
        accuracy, precision, recall, f1, classification report e confusion matrix.
        """
        print("[*] Tokenizzazione del test set...")
        test_tokenized = test_dataset.map(self._tokenize_function, batched=True)

        print("[*] Generazione predizioni sul Test Set...")
        predictions = trainer.predict(test_tokenized)

        y_true = test_tokenized['label']
        y_pred = np.argmax(predictions.predictions, axis=1)

        sep = "=" * 50
        print(f"\n{sep}")
        print("  RISULTATI FINALI SUL TEST SET")
        print(sep)
        print(f"Accuracy  : {accuracy_score(y_true, y_pred):.4f}")
        print(f"Precision : {precision_score(y_true, y_pred):.4f}")
        print(f"Recall    : {recall_score(y_true, y_pred):.4f}")
        print(f"F1 Score  : {f1_score(y_true, y_pred):.4f}")
        print(f"\n{sep}")
        print("  CLASSIFICATION REPORT")
        print(sep)
        print(classification_report(y_true, y_pred, target_names=["Legittima", "Phishing"]))
        print(f"\n{sep}")
        print("  CONFUSION MATRIX")
        print(sep)
        cm = confusion_matrix(y_true, y_pred)
        print(f"                  Pred Legittima  Pred Phishing")
        print(f"  Reale Legittima       {cm[0][0]:>6}         {cm[0][1]:>6}")
        print(f"  Reale Phishing        {cm[1][0]:>6}         {cm[1][1]:>6}")
        print(sep)


# ----------------------------------------------------------------------
# ENTRY POINT
# ----------------------------------------------------------------------

if __name__ == "__main__":
    trainer_pipeline = BERTPhishingTrainer()

    # Sample size allineato al notebook (15.000).
    # Su CPU si usa un subset ridotto per rendere il training praticabile.
    if trainer_pipeline.is_mac or trainer_pipeline.device == "cuda":
        target_samples = 15000
    else:
        target_samples = 6000   # CPU: subset ridotto ma più grande del precedente

    try:
        # Manteniamo il parametro personal_eml_folder intatto come a monte per evitare disallineamenti
        df = trainer_pipeline.download_and_combine_data(
            personal_eml_folder="data/raw/personal_emails",
            sample_size=target_samples
        )

        train_data, val_data, test_data = trainer_pipeline.prepare_datasets(df)
        trainer_obj = trainer_pipeline.train(train_data, val_data)
        trainer_pipeline.evaluate_test_set(trainer_obj, test_data)

    except Exception as e:
        import traceback
        print(f"\n[!] Errore bloccante nell'esecuzione: {e}")
        traceback.print_exc()
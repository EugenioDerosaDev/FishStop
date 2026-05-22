import os
import sys

# Forza Python a riconoscere la cartella radice per trovare 'src.parser'
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# Hardcoding temporaneo delle credenziali per bypassare i problemi del .env
os.environ["KAGGLE_USERNAME"] = "eugenioderosa"
os.environ["KAGGLE_KEY"] = "KGAT_8f8c51550b799cda8ed82117f2e37ca2"

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
        df_personal = parser.load_batch_emls(personal_eml_folder)

        if not df_personal.empty:
            print(f"[*] Integrazione attiva: unione di {len(df_personal)} email personali nel pool...")
            df_personal_aligned = pd.DataFrame({
                'text': df_personal['body'].apply(lambda x: str(x).lower()),
                'label': 1
            })
            df_personal_aligned.dropna(subset=['text'], inplace=True)
            df_combined = pd.concat([df_kaggle, df_personal_aligned], ignore_index=True)
        else:
            print("[!] Nessuna email personale rilevata. Si procede solo con Kaggle.")
            df_combined = df_kaggle

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
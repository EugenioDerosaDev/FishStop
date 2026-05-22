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
from sklearn.metrics import accuracy_score, precision_recall_fscore_support, classification_report
from transformers import BertTokenizer, BertForSequenceClassification
from transformers import Trainer, TrainingArguments
from transformers import DataCollatorWithPadding
from datasets import Dataset

# Importazione del tuo parser ottimizzato per gli EML locali
from src.parser import EmailParserPipeline

class BERTPhishingTrainer:
    def __init__(self, model_name="bert-base-uncased", num_labels=2):
        print("[*] Inizializzazione di BERT Tokenizer e Modello...")
        self.tokenizer = BertTokenizer.from_pretrained(model_name)
        self.model = BertForSequenceClassification.from_pretrained(model_name, num_labels=num_labels)
        
        # 🕵️‍♂️ RILEVAMENTO AUTOMATICO DELL'AMBIENTE E CONFIGURAZIONE HARDWARE
        if torch.backends.mps.is_available():
            self.device = "mps"
            self.is_mac = True
            # Rimuove il limite artificiale di allocazione della memoria grafica su Apple Silicon
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

    def download_and_combine_data(self, personal_eml_folder="data/raw/personal_emails", sample_size=3000):
        """
        Scarica il dataset in automatico da Kaggle, normalizza le colonne,
        esegue il parsing delle email locali e applica il preprocessing corretto.
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

        df_kaggle.columns = [col.lower().strip() for col in df_kaggle.columns]
        rename_dict = {}
        for col in df_kaggle.columns:
            if 'text' in col or 'body' in col or 'email' in col:
                rename_dict[col] = 'text'
            elif 'label' in col or 'class' in col or 'target' in col:
                rename_dict[col] = 'label'
        if rename_dict:
            df_kaggle.rename(columns=rename_dict, inplace=True)

        print(f"[*] Campionamento strategico di {sample_size} righe...")
        if len(df_kaggle) > sample_size:
            df_kaggle = df_kaggle.sample(n=sample_size, random_state=42).reset_index(drop=True)
        
        df_kaggle.dropna(subset=['text', 'label'], inplace=True)
        df_kaggle['label'] = df_kaggle['label'].astype(int)
        df_kaggle['text'] = df_kaggle['text'].apply(lambda x: str(x).lower())

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
            print("[!] Nessuna email personale rilevata nella cartella data/raw/personal_emails. Si procede solo con Kaggle.")
            df_combined = df_kaggle
        
        print(f"[+] Pool dei dati pronto. Dimensione totale campioni: {len(df_combined)}")
        return df_combined

    def prepare_datasets(self, df):
        """Split di validazione: 70% Train, 10% Validation, 20% Test"""
        train_df, rest_df = train_test_split(df, test_size=0.30, random_state=42, stratify=df['label'])
        val_df, test_df = train_test_split(rest_df, test_size=0.6667, random_state=42, stratify=rest_df['label'])

        print(f"[*] Suddivisione completata -> Train: {len(train_df)} | Val: {len(val_df)} | Test: {len(test_df)}")
        return Dataset.from_pandas(train_df), Dataset.from_pandas(val_df), Dataset.from_pandas(test_df)

    def _tokenize_function(self, examples):
        return self.tokenizer(examples['text'], truncation=True, max_length=512)

    @staticmethod
    def compute_metrics(eval_pred):
        logits, labels = eval_pred
        preds = np.argmax(logits, axis=1)
        precision, recall, f1, _ = precision_recall_fscore_support(labels, preds, average='binary')
        acc = accuracy_score(labels, preds)
        return {'accuracy': acc, 'f1': f1, 'precision': precision, 'recall': recall}

    def train(self, train_dataset, val_dataset, output_dir="./models/saved_models"):
        """Esegue la mappatura dei token e addestra il livello classificatore di BERT"""
        print("[*] Esecuzione del mapping di tokenizzazione sui segmenti di testo...")
        train_tokenized = train_dataset.map(self._tokenize_function, batched=False)
        val_tokenized = val_dataset.map(self._tokenize_function, batched=False)

        data_collator = DataCollatorWithPadding(tokenizer=self.tokenizer)

        # 🎛️ CONFIGURAZIONE DINAMICA DEI TRAINING ARGUMENTS IN BASE ALL'HARDWARE
        if self.is_mac:
            # Parametri ottimizzati per stabilità ed accelerazione hardware su Mac M2
            train_batch = 4
            grad_accum = 2
            use_bf16 = True
            log_steps = 20
        else:
            # Parametri leggeri anti-crash (OOM) pensati per la sola CPU del Codespace
            train_batch = 2
            grad_accum = 4
            use_bf16 = False
            log_steps = 10

        print(f"[*] Configurazione Trainer -> Batch size: {train_batch} | Accumulation steps: {grad_accum} | BF16: {use_bf16}")

        training_args = TrainingArguments(
            output_dir=output_dir,
            learning_rate=2e-5,
            per_device_train_batch_size=train_batch,
            per_device_eval_batch_size=train_batch,
            gradient_accumulation_steps=grad_accum,
            num_train_epochs=3,
            weight_decay=0.01,
            eval_strategy="epoch",
            save_strategy="epoch",
            load_best_model_at_end=True,
            metric_for_best_model="accuracy",
            logging_dir='./logs',
            logging_steps=log_steps,
            report_to="none",
            dataloader_pin_memory=False,
            dataloader_num_workers=0,  # Fondamentale sia su Mac che su cloud per evitare leak di memoria dei semafori
            bf16=use_bf16
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

        print("[*] Inizio dei cicli di fine-tuning su BERT...")
        trainer.train()
        
        os.makedirs(output_dir, exist_ok=True)
        self.model.save_pretrained(output_dir)
        self.tokenizer.save_pretrained(output_dir)
        print(f"[+] Modello e pesi salvati con successo in: {output_dir}")
        return trainer

    def evaluate_test_set(self, trainer, test_dataset):
        test_tokenized = test_dataset.map(self._tokenize_function, batched=False)
        print("[*] Generazione report metriche sul Test Set isolato...")
        predictions = trainer.predict(test_tokenized)
        
        y_true = test_tokenized['label']
        y_pred = np.argmax(predictions.predictions, axis=1)
        
        print("\n" + "="*40 + "\n     MATRICE E CLASSIFICATION REPORT\n" + "="*40)
        print(classification_report(y_true, y_pred, target_names=["Legittima", "Phishing"]))

if __name__ == "__main__":
    trainer_pipeline = BERTPhishingTrainer()
    
    # 📏 Scegliamo dinamicamente la dimensione del dataset
    # 6000 righe per uno sprint sicuro su Mac M2, 3000 righe ultra-leggero per la CPU del Codespace
    target_samples = 6000 if trainer_pipeline.is_mac else 3000
    
    try:
        df = trainer_pipeline.download_and_combine_data(
            personal_eml_folder="data/raw/personal_emails", 
            sample_size=target_samples
        )
        
        train_data, val_data, test_data = trainer_pipeline.prepare_datasets(df)
        trainer_obj = trainer_pipeline.train(train_data, val_data)
        trainer_pipeline.evaluate_test_set(trainer_obj, test_data)
        
    except Exception as e:
        print(f"\n[!] Errore bloccante nell'esecuzione: {str(e)}")
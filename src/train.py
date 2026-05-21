import os
import pandas as pd
import numpy as np
import torch
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score, precision_recall_fscore_support, classification_report
from transformers import BertTokenizer, BertForSequenceClassification
from transformers import Trainer, TrainingArguments
from transformers import DataCollatorWithPadding
from datasets import Dataset

class BERTPhishingTrainer:
    def __init__(self, model_name="bert-base-uncased", num_labels=2):
        self.tokenizer = BertTokenizer.from_pretrained(model_name)
        self.model = BertForSequenceClassification.from_pretrained(model_name, num_labels=num_labels)
        self.device = "cuda" if torch.cuda.is_available() else "cpu"
        self.model.to(self.device)

    def load_and_preprocess_data(self, csv_path, sample_size=15000):
        """Carica il dataset, effettua il campionamento e pulisce i nulli (Logica del notebook)"""
        if not os.path.exists(csv_path):
            raise FileNotFoundError(f"Dataset non trovato in: {csv_path}")
            
        df = pd.read_csv(csv_path)
        
        # Campionamento se il dataset è troppo grande
        if len(df) > sample_size:
            df = df.sample(n=sample_size, random_state=42).reset_index(drop=True)
            
        df.dropna(inplace=True)
        df['label'] = df['label'].astype(int)
        df['text'] = df['text'].apply(lambda x: str(x).lower())
        return df

    def prepare_datasets(self, df):
        """Split 70/10/20 e conversione nel formato HuggingFace Dataset"""
        # Split Train (70%) e Rest (30%)
        train_df, rest_df = train_test_split(df, test_size=0.30, random_state=42, stratify=df['label'])
        # Split Rest in Validation (10% del totale) e Test (20% del totale)
        val_df, test_df = train_test_split(rest_df, test_size=0.6667, random_state=42, stratify=rest_df['label'])

        # Conversione in oggetti Dataset di HuggingFace
        train_dataset = Dataset.from_pandas(train_df)
        val_dataset = Dataset.from_pandas(val_df)
        test_dataset = Dataset.from_pandas(test_df)
        
        return train_dataset, val_dataset, test_dataset

    def _tokenize_function(self, examples):
        """Tokenizzazione tramite BERT Tokenizer"""
        return self.tokenizer(examples['text'], truncation=True, max_length=512)

    @staticmethod
    def compute_metrics(eval_pred):
        """Calcolo delle metriche di valutazione durante l'addestramento"""
        logits, labels = eval_pred
        preds = np.argmax(logits, axis=1)
        precision, recall, f1, _ = precision_recall_fscore_support(labels, preds, average='binary')
        acc = accuracy_score(labels, preds)
        return {
            'accuracy': acc,
            'f1': f1,
            'precision': precision,
            'recall': recall
        }

    def train(self, train_dataset, val_dataset, output_dir="./models/saved_models"):
        """Configurazione dei TrainingArguments ed esecuzione del Trainer"""
        # Tokenizzazione dei dataset
        train_tokenized = train_dataset.map(self._tokenize_function, batched=True)
        val_tokenized = val_dataset.map(self._tokenize_function, batched=True)

        # Data Collator per il padding dinamico dei batch
        data_collator = DataCollatorWithPadding(tokenizer=self.tokenizer)

        # Argomenti di addestramento presi dal workflow standard BERT
        training_args = TrainingArguments(
            output_dir=output_dir,
            learning_rate=2e-5,
            per_device_train_batch_size=16,
            per_device_eval_batch_size=16,
            num_train_epochs=3,
            weight_decay=00.1,
            evaluation_strategy="epoch",
            save_strategy="epoch",
            load_best_model_at_end=True,
            metric_for_best_model="accuracy",
            logging_dir='./logs',
            logging_steps=100,
            report_to="none" # Evita chiamate esterne (es. wandb) nel Codespace
        )

        trainer = Trainer(
            model=self.model,
            args=training_args,
            train_dataset=train_tokenized,
            eval_dataset=val_tokenized,
            tokenizer=self.tokenizer,
            data_collator=data_collator,
            compute_metrics=self.compute_metrics,
        )

        print("[*] Inizio addestramento del modello BERT...")
        trainer.train()
        
        # Salvataggio finale del modello e del tokenizer pronti per l'Inference
        self.model.save_pretrained(output_dir)
        self.tokenizer.save_pretrained(output_dir)
        print(f"[+] Modello salvato con successo in: {output_dir}")
        return trainer

    def evaluate_test_set(self, trainer, test_dataset):
        """Valutazione finale sul Test Set e stampa del Classification Report"""
        test_tokenized = test_dataset.map(self._tokenize_function, batched=True)
        print("[*] Valutazione sul Test Set...")
        predictions = trainer.predict(test_tokenized)
        
        y_true = test_tokenized['label']
        y_pred = np.argmax(predictions.predictions, axis=1)
        
        print("\n=== CLASSIFICATION REPORT ===")
        print(classification_report(y_true, y_pred, target_names=["Legitimate", "Phishing"]))

if __name__ == "__main__":
    # Script di esecuzione locale/test dell'intera pipeline
    trainer_pipeline = BERTPhishingTrainer()
    
    # Assicurati di posizionare il file csv in data/raw/phishing_email.csv o di cambiare il percorso qui sotto
    csv_path = "data/raw/phishing_email.csv" 
    
    try:
        df = trainer_pipeline.load_and_preprocess_data(csv_path, sample_size=15000)
        train_data, val_data, test_data = trainer_pipeline.prepare_datasets(df)
        
        # Avvia l'addestramento (Nota: richiede risorse computazionali/tempo a seconda della macchina)
        trainer_obj = trainer_pipeline.train(train_data, val_data)
        
        # Valuta i risultati sul test set finale
        trainer_pipeline.evaluate_test_set(trainer_obj, test_data)
    except FileNotFoundError as e:
        print(f"[!] Errore: {e}. Carica il dataset prima di eseguire lo script.")
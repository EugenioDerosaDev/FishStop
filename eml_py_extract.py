import os
import random
from email import message_from_bytes

# --- CONFIGURAZIONE PERCORSI CORRETTI ---
BASE_DIR = r"/Users/eugenio/Downloads/archive-2"

# Il percorso esatto basato sulla tua struttura
PATH_HAM = os.path.join(BASE_DIR, "ham_zipped", "main_ham")

# La nuova cartella di destinazione dentro archive-2
OUTPUT_DIR = os.path.join(BASE_DIR, "email_selezionate_eml")

# Numero di email da estrarre
TARGET_COUNT = 600

def estrai_e_converti_ham():
    print(f"Controllo il percorso: {PATH_HAM}")
    
    if not os.path.exists(PATH_HAM):
        print(f"\n[ERRORE] Non trovo ancora la cartella.")
        print(f"Per favore, verifica se il percorso scritto qui sopra corrisponde millimetricamente a dove vedi i file.")
        return

    # 1. Raccogli i file escludendo quelli nascosti del Mac (tipo .DS_Store o ._file)
    all_files = []
    for f in os.listdir(PATH_HAM):
        full_path = os.path.join(PATH_HAM, f)
        if os.path.isfile(full_path) and not f.startswith('.'):
            all_files.append(full_path)

    total_disponibili = len(all_files)
    print(f"File email trovati: {total_disponibili}")
    
    if total_disponibili == 0:
        print("[AVVISO] La cartella esiste ma non contiene file visibili.")
        return

    # 2. Selezione casuale di 600 elementi
    sample_size = min(TARGET_COUNT, total_disponibili)
    selected_samples = random.sample(all_files, sample_size)
    print(f"Estrazione e conversione di {sample_size} email in corso...")

    # Crea la cartella di output
    os.makedirs(OUTPUT_DIR, exist_ok=True)

    # 3. Conversione e scrittura dei file .eml
    convertiti = 0
    for index, file_path in enumerate(selected_samples, start=1):
        nome_file_originale = os.path.basename(file_path)
        
        # Genera il nome pulito del file .eml
        nuovo_nome_eml = f"ham_{index}_{nome_file_originale}.eml"
        percorso_destinazione = os.path.join(OUTPUT_DIR, nuovo_nome_eml)
        
        try:
            # Lettura binaria per evitare eccezioni sui caratteri non-standard
            with open(file_path, 'rb') as f_in:
                raw_bytes = f_in.read()
                
            # Ricostruzione della struttura email corretta
            msg = message_from_bytes(raw_bytes)
            
            # Scrittura del file .eml finale
            with open(percorso_destinazione, 'wb') as f_out:
                f_out.write(msg.as_bytes())
                
            convertiti += 1
        except Exception as e:
            print(f"Errore sul file {nome_file_originale}: {e}")

    print(f"\n[OK] Fatto! {convertiti} email convertite con successo.")
    print(f"Trovi tutto nella cartella:\n--> {OUTPUT_DIR}")

if __name__ == "__main__":
    estrai_e_converti_ham()
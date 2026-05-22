# FishStop
.eml classifier


pip install -r requirements.txt


streamlit run src/app.py



da mac all'inizio : 
# Crea l'ambiente virtuale
python3 -m venv .venv

# Attivalo
source .venv/bin/activate

# Aggiorna pip e installa i pacchetti
pip install --upgrade pip
pip install -r requirements.txt


tbshoot: 
./.venv/bin/pip install --upgrade "accelerate>=1.1.0" "transformers[torch]"

./.venv/bin/python src/train.py

#github agg repo 
git add . 
git commit -m "msg" 
git push origin main
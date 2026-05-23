"""
config.py — Gestione centralizzata delle variabili d'ambiente e dei segreti.

Logica di risoluzione (priorità decrescente):
  1. Variabili d'ambiente del sistema / file .env  (sviluppo locale con VSCode)
  2. st.secrets di Streamlit                        (deploy su Streamlit Cloud)
  3. Stringa vuota come fallback sicuro              (chiave non configurata)

Come usarlo negli altri moduli:
    from src.config import get_secret, ABUSEIPDB_API_KEY, VIRUSTOTAL_API_KEY

Aggiungere nuove chiavi:
  - Aggiungere la coppia KEY = get_secret("KEY") in fondo al file.
  - In locale: aggiungere KEY=valore nel file .env (non committare mai .env!)
  - Su Streamlit Cloud: aggiungere la chiave in Settings → Secrets.
"""

import os

# ── 1. Carica .env se presente (solo in sviluppo locale) ──────────────────
# python-dotenv è opzionale: se non installato si usa solo l'ambiente di sistema.
# override=False → le variabili già presenti nell'env di sistema hanno precedenza.
try:
    from dotenv import load_dotenv
    # Cerca .env nella root del progetto (due livelli sopra questo file: src/config.py → /)
    _env_path = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), ".env")
    load_dotenv(dotenv_path=_env_path, override=False)
    _DOTENV_LOADED = os.path.exists(_env_path)
except ImportError:
    _DOTENV_LOADED = False


# ── 2. Rilevamento ambiente ────────────────────────────────────────────────
def _is_streamlit_cloud() -> bool:
    """
    True se il codice gira dentro un contesto Streamlit attivo con st.secrets
    configurati (tipicamente Streamlit Cloud o un server con secrets.toml).

    Non solleva eccezioni: se Streamlit non è importato o i secrets non sono
    disponibili restituisce semplicemente False.
    """
    try:
        import streamlit as st
        # st.secrets lancia AttributeError o FileNotFoundError se non configurati
        _ = st.secrets
        return True
    except Exception:
        return False


def _read_streamlit_secret(key: str, default: str = "") -> str:
    """Legge un segreto da st.secrets senza crashare se non disponibile."""
    try:
        import streamlit as st
        return st.secrets.get(key, default)
    except Exception:
        return default


# ── 3. Funzione pubblica ───────────────────────────────────────────────────
def get_secret(key: str, default: str = "") -> str:
    """
    Risolve una chiave di configurazione nell'ordine:
      1. Variabile d'ambiente (os.environ) — popolata da .env in locale
         o dalle env var del sistema in produzione.
      2. st.secrets di Streamlit — usato su Streamlit Cloud.
      3. `default` (stringa vuota se non specificato).

    Questo ordine garantisce che:
      - In locale con VSCode il .env basta, Streamlit non viene nemmeno toccato.
      - Su Streamlit Cloud, se la env var non è impostata a livello di sistema,
        si usa il secrets manager integrato.
      - In script standalone (train.py, test) non crasha mai.
    """
    # Priorità 1: variabile d'ambiente (include valori caricati da .env)
    value = os.environ.get(key)
    if value:
        return value

    # Priorità 2: st.secrets (solo se Streamlit è attivo)
    if _is_streamlit_cloud():
        value = _read_streamlit_secret(key, default)
        if value:
            return value

    return default


# ── 4. Diagnostica (visibile solo in debug / script standalone) ───────────
def print_config_status():
    """Stampa lo stato della configurazione — utile per debug in locale."""
    print("=" * 55)
    print("  CONFIG STATUS")
    print("=" * 55)
    print(f"  .env caricato          : {_DOTENV_LOADED}")
    print(f"  Streamlit secrets OK   : {_is_streamlit_cloud()}")
    print(f"  ABUSEIPDB_API_KEY      : {'✅ presente' if ABUSEIPDB_API_KEY  else '❌ mancante'}")
    print(f"  VIRUSTOTAL_API_KEY     : {'✅ presente' if VIRUSTOTAL_API_KEY else '❌ mancante'}")
    print("=" * 55)


# ── 5. Chiavi applicative ─────────────────────────────────────────────────
# Aggiungi qui tutte le chiavi usate nel progetto.
# Gli altri moduli importano direttamente queste costanti invece di chiamare
# get_secret() ogni volta, così la risoluzione avviene una sola volta all'avvio.

ABUSEIPDB_API_KEY  = get_secret("ABUSEIPDB_API_KEY")
VIRUSTOTAL_API_KEY = get_secret("VIRUSTOTAL_API_KEY")
# KAGGLE_USERNAME  = get_secret("KAGGLE_USERNAME")   # decommentare se serve
# KAGGLE_KEY       = get_secret("KAGGLE_KEY")


# ── 6. Smoke test (python -m src.config) ─────────────────────────────────
if __name__ == "__main__":
    print_config_status()
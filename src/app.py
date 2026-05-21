import streamlit as st
import os
import sys

# Aggiungiamo la cartella radice al path per evitare problemi di importazione nei moduli src
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.parser import EmailParserPipeline
from src.validators import EmailSecurityValidator

# Inizializzazione dei moduli di backend
@st.cache_resource
def init_backend():
    return EmailParserPipeline(), EmailSecurityValidator()

parser, validator = init_backend()

# Configurazione della pagina Streamlit
st.set_page_config(
    page_title="FishStop - Triage & Phishing Detection",
    page_icon="🛡️",
    layout="wide"
)

# Header dell'applicazione
st.title("🛡️ FishStop - Analisi & Triage Email")
st.markdown("Carica un file `.eml` sospetto per analizzare istantaneamente l'architettura DNS del mittente e i vettori di contenuto tramite IA.")
st.hr()

# Layout a due colonne: Caricamento a sinistra, Risultati a destra
col_upload, col_results = st.columns([1, 2])

with col_upload:
    st.subheader("📥 Input Email")
    uploaded_file = st.file_uploader("Trascina qui il file .eml da analizzare", type=["eml"])
    
    if uploaded_file is not None:
        st.success("File caricato correttamente! Elaborazione in corso...")
        
        # Salvataggio temporaneo del file per permettere al parser di leggerlo
        temp_path = os.path.join("data", "raw", "temp_triage.eml")
        os.makedirs(os.path.dirname(temp_path), exist_ok=True)
        with open(temp_path, "wb") as f:
            f.write(uploaded_file.getbuffer())

with col_results:
    st.subheader("📊 Pannello di Analisi e Triage")
    
    if uploaded_file is None:
        st.info("In attesa di un file `.eml` per avviare il triage.")
    else:
        try:
            # 1. PARSING DELL'EMAIL
            email_data = parser.parse_single_eml(temp_path)
            
            # Mostra i Metadati estratti
            with st.expander("📝 Dettagli e Contenuto dell'Email", expanded=True):
                st.write(f"**Da:** {email_data['sender']}")
                st.write(f"**A:** {email_data['to']}")
                st.write(f"**Oggetto:** {email_data['subject']}")
                st.write(f"**Data:** {email_data['date']}")
                st.text_area("Corpo del Testo Estratto (per BERT):", email_data['body'], height=150)
            
            # 2. CONTROLLI DI SICUREZZA (MxToolbox Style)
            st.subheader("🔑 Autenticazione e Record Intrinseci (DNS)")
            
            # Esecuzione dei controlli reali
            spf_res = validator.check_spf(email_data['sender'])
            dmarc_res = validator.check_dmarc(email_data['sender'])
            dkim_res = validator.check_dkim_presence(email_data['raw_headers'])
            
            col_spf, col_dkim, col_dmarc = st.columns(3)
            
            with col_spf:
                if spf_res["status"] == "Pass":
                    st.metric(label="SPF Check", value="PASS ✅", delta="Valido")
                elif spf_res["status"] == "Fail":
                    st.metric(label="SPF Check", value="FAIL ❌", delta="- Record Mancante", delta_color="inverse")
                else:
                    st.metric(label="SPF Check", value="ERROR ⚠️", delta="Errore DNS", delta_color="off")
                st.caption(f"_{spf_res['message']}_")
                if spf_res["record"]:
                    st.code(spf_res["record"], language="text")
                    
            with col_dkim:
                if dkim_res["status"] == "Present":
                    st.metric(label="DKIM Signature", value="RILEVATA 🔑", delta="Firma presente")
                else:
                    st.metric(label="DKIM Signature", value="ASSENTE 🚫", delta="- Nessuna firma", delta_color="inverse")
                st.caption(f"_{dkim_res['message']}_")
                
            with col_dmarc:
                if dmarc_res["status"] == "Pass":
                    st.metric(label="DMARC Policy", value="COMPLIANT 🛡️", delta="Allineato")
                elif dmarc_res["status"] == "Fail":
                    st.metric(label="DMARC Policy", value="NONE/MISSING ⚠️", delta="- Rischio Spoofing", delta_color="inverse")
                else:
                    st.metric(label="DMARC Policy", value="ERROR ❌", delta="Errore DNS", delta_color="off")
                st.caption(f"_{dmarc_res['message']}_")
                if dmarc_res["record"]:
                    st.code(dmarc_res["record"], language="text")

            # 3. ANALISI PREDIZIONE IA (BERT)
            st.hr()
            st.subheader("🤖 Analisi Contenuto con Intelligenza Artificiale")
            
            # TODO: Quando il modello in src/train.py sarà addestrato, 
            # collegheremo qui la classe PhishingPredictor creata in precedenza.
            # Per ora simuliamo il comportamento dell'interfaccia grafica.
            
            st.warning("⚠️ Il modello BERT locale è in modalità simulazione (In attesa dell'addestramento definitivo).")
            
            # Eseguiamo un controllo mockup veloce basato su parole chiave nel corpo del testo
            text_lower = email_data['body'].lower() or email_data['subject'].lower()
            trigger_words = ["urgent", "click here", "verify", "suspend", "account", "login", "bank", "password"]
            found_triggers = [word for word in trigger_words if word in text_lower]
            
            if len(found_triggers) > 1:
                st.error(f"🚨 **Risultato IA: RILEVATO POSSIBIBILE PHISHING**")
                st.progress(85)
                st.write(f"**Confidenza del Modello:** 85.4% Probability Phishing")
                st.markdown(f"**Indicatori di testo rilevati (Mockup):** `{', '.join(found_triggers)}`")
            else:
                st.success(f"🟢 **Risultato IA: EMAIL LEGITTIMA**")
                st.progress(15)
                st.write(f"**Confidenza del Modello:** 91.2% Probability Legitimate")
                
            # Pulizia file temporaneo
            if os.path.exists(temp_path):
                os.remove(temp_path)
                
        except Exception as e:
            st.error(f"Si è verificato un errore durante l'analisi dell'email: {str(e)}")
import streamlit as st
import os
import sys
import torch
from transformers import AutoTokenizer, AutoModelForSequenceClassification

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.parser import EmailParserPipeline
from src.validators import EmailSecurityValidator
from src.analyzer import EmlSOCAnalyzer

# ── backend ────────────────────────────────────────────────────────────────
@st.cache_resource
def init_backend():
    # Inizializza i tuoi componenti custom
    parser = EmailParserPipeline()
    validator = EmailSecurityValidator()
    analyzer = EmlSOCAnalyzer()
    
    # Definisci il percorso locale dove hai salvato i file estratti dallo ZIP
    model_path = os.path.join("models", "saved_models")
    
    # Carica il Tokenizer e il Modello BERT reali
    tokenizer = AutoTokenizer.from_pretrained(model_path)
    model = AutoModelForSequenceClassification.from_pretrained(model_path)
    
    return parser, validator, analyzer, tokenizer, model

parser, validator, analyzer, tokenizer, model = init_backend()

# ── page config ────────────────────────────────────────────────────────────
st.set_page_config(
    page_title="FishStop - Triage & Phishing Detection",
    page_icon="🛡️",
    layout="wide",
)

st.title("🛡️ FishStop — Analisi & Triage Email")
st.markdown(
    "Carica un file `.eml` sospetto per analizzare istantaneamente l'architettura "
    "DNS del mittente e i vettori di contenuto tramite IA."
)
st.divider()

# ── layout ─────────────────────────────────────────────────────────────────
col_upload, col_results = st.columns([1, 2])

with col_upload:
    st.subheader("📥 Input Email")
    uploaded_file = st.file_uploader(
        "Trascina qui il file .eml da analizzare", type=["eml"]
    )

    if uploaded_file is not None:
        st.success("File caricato correttamente! Elaborazione in corso…")
        temp_path = os.path.join("data", "raw", "temp_triage.eml")
        os.makedirs(os.path.dirname(temp_path), exist_ok=True)
        with open(temp_path, "wb") as f:
            f.write(uploaded_file.getbuffer())


# ── helpers ────────────────────────────────────────────────────────────────

def _badge(level: str) -> str:
    colors = {"HIGH": "🔴", "MEDIUM": "🟠", "LOW": "🟡", "INFO": "🔵"}
    return colors.get(level, "⚪")


def _status_icon(ok: bool) -> str:
    return "✅" if ok else "❌"


# ── results panel ──────────────────────────────────────────────────────────

with col_results:
    st.subheader("📊 Pannello di Analisi e Triage")

    if uploaded_file is None:
        st.info("In attesa di un file `.eml` per avviare il triage.")
    else:
        try:
            # ── 1. DEEP HEADER ANALYSIS (new SOC analyzer) ─────────────────
            soc = analyzer.analyze(temp_path)

            # ── 1a. Envelope / identità ────────────────────────────────────
            with st.expander("📬 Envelope & Identità", expanded=True):
                cols = st.columns(2)
                with cols[0]:
                    st.markdown(f"**Delivered-To:** `{soc['delivered_to'] or '—'}`")
                    st.markdown(f"**To:** `{soc['to'] or '—'}`")
                    st.markdown(f"**From:** `{soc['from_'] or '—'}`")
                    st.markdown(f"**Subject:** `{soc['subject'] or '—'}`")
                with cols[1]:
                    st.markdown(f"**Date:** `{soc['date'] or '—'}`")
                    st.markdown(f"**Message-Id:** `{soc['message_id'] or '—'}`")
                    st.markdown(f"**Importance:** `{soc['importance'] or '—'}`")
                    st.markdown(f"**MIME-Version:** `{soc['mime_version'] or '—'}`")

                st.markdown("---")
                rp_ok = soc["return_path"] and soc["from_"]
                st.markdown(f"**Return-Path:** `{soc['return_path'] or '—'}`")
                st.markdown(f"**Errors-To:** `{soc['errors_to'] or '—'}`")

                reply_icon = "🔴 MISMATCH" if soc["reply_to_mismatch"] else "✅ Coerente"
                st.markdown(
                    f"**Reply-To:** `{soc['reply_to'] or '—'}` — {reply_icon}"
                )
                if soc["reply_to_mismatch"]:
                    st.warning(
                        "⚠️ Reply-To differisce dal From: un eventuale reply verrebbe "
                        "recapitato a un indirizzo diverso dal mittente dichiarato. "
                        "Indicatore tipico di phishing/harvesting."
                    )

                st.markdown(f"**Content-Type:** `{soc['content_type'] or '—'}`")

            # ── 1b. Catena Received ────────────────────────────────────────
            with st.expander("📡 Catena Received (routing hop-by-hop)"):
                hops = soc["received_hops"]
                if not hops:
                    st.info("Nessun header Received trovato.")
                else:
                    labels = []
                    for i, _ in enumerate(hops):
                        if i == 0:
                            labels.append("Hop 1 — Closest to Recipient (server ricevente)")
                        elif i == len(hops) - 1:
                            labels.append(f"Hop {i+1} — Closest to Sender (server di origine)")
                        elif i == 1:
                            labels.append(f"Hop {i+1} — Injection Server (server usato dal mittente)")
                        else:
                            labels.append(f"Hop {i+1} — Relay intermedio")

                    for label, hop in zip(labels, hops):
                        st.markdown(f"**{label}**")
                        c1, c2, c3 = st.columns(3)
                        c1.markdown(f"From host: `{hop.get('from_host') or '—'}`")
                        c2.markdown(f"Sender IP: `{hop.get('sender_ip') or '—'}`")
                        c3.markdown(f"By host: `{hop.get('by_host') or '—'}`")
                        if hop.get("sender_domain"):
                            st.markdown(f"Sender domain (parenthetical): `{hop['sender_domain']}`")
                        if hop.get("tls_version"):
                            st.markdown(
                                f"TLS: `{hop['tls_version']}` — Cipher: `{hop['tls_cipher']}`"
                            )
                        if hop.get("for_address"):
                            st.markdown(f"For: `{hop['for_address']}`")
                        with st.expander("Raw Received header"):
                            st.code(hop["raw"], language="text")
                        st.markdown("---")

            # ── 1c. Autenticazione ─────────────────────────────────────────
            with st.expander("🔑 Autenticazione (SPF / DKIM / DMARC)", expanded=True):

                # ── Run live validation ────────────────────────────────────
                # SPF: evaluated against the injection-server IP + Return-Path
                # (NOT the From header — that would be trivially spoofable).
                spf_live = validator.check_spf(
                    sender_ip  = soc.get("injection_sender_ip") or "",
                    mail_from  = soc.get("return_path") or soc.get("from_") or "",
                    helo_domain= (soc.get("injection_server") or {}).get("from_host") or "",
                )

                # DKIM: cryptographic verification from the raw .eml bytes
                dkim_live = validator.check_dkim(soc.get("raw_eml_bytes") or b"")

                # DMARC: policy + alignment, fed the live SPF/DKIM results
                dmarc_live = validator.check_dmarc(
                    from_address = soc.get("from_") or "",
                    spf_result   = spf_live["status"],
                    spf_domain   = spf_live.get("domain") or "",
                    dkim_results = dkim_live.get("signatures") or [],
                )

                # ── Header-based results (from receiving MTA) ──────────────
                # Keep these for cross-reference — they reflect what the
                # receiving server recorded at delivery time.
                auth_header = soc["auth_results"] or soc["arc_auth_results"]

                col_spf, col_dkim, col_dmarc = st.columns(3)

                # ── SPF column ─────────────────────────────────────────────
                with col_spf:
                    st.markdown("#### SPF")
                    status = spf_live["status"]
                    if status == "pass":
                        st.success(f"PASS ✅")
                    elif status in ("fail", "softfail"):
                        st.error(f"{status.upper()} ❌")
                    elif status in ("none", "neutral"):
                        st.warning(f"{status.upper()} ⚠️")
                    elif status == "record-found":
                        st.warning("Record trovato (pyspf non installato)")
                    else:
                        st.warning(f"{status.upper()}")

                    st.caption(f"Sender IP: `{spf_live.get('sender_ip') or '—'}`")
                    st.caption(f"MAIL FROM domain: `{spf_live.get('domain') or '—'}`")
                    st.caption(f"Libreria: `{spf_live.get('library')}`")

                    if spf_live.get("record"):
                        with st.expander("Record SPF"):
                            st.code(spf_live["record"], language="text")
                    if soc.get("received_spf_raw"):
                        with st.expander("Received-SPF (header MTA)"):
                            st.code(soc["received_spf_raw"], language="text")

                    # Cross-reference with Authentication-Results header
                    spf_header = auth_header.get("SPF")
                    if spf_header:
                        match = spf_header["status"] == status
                        icon = "✅" if match else "⚠️ diverge"
                        st.caption(f"Authentication-Results header: `{spf_header['status']}` {icon}")

                # ── DKIM column ────────────────────────────────────────────
                with col_dkim:
                    st.markdown("#### DKIM")
                    dkim_status = dkim_live["status"]
                    if dkim_status == "pass":
                        st.success("PASS ✅")
                    elif dkim_status == "fail":
                        st.error("FAIL ❌")
                    elif dkim_status in ("none", "present"):
                        st.warning(f"{'ASSENTE 🚫' if dkim_status == 'none' else 'PRESENTE (non verificato) ⚠️'}")
                    else:
                        st.warning(f"{dkim_status.upper()}")

                    st.caption(f"Libreria: `{dkim_live.get('library')}`")
                    st.caption(dkim_live.get("message", ""))

                    # Per-signature breakdown
                    for sig in dkim_live.get("signatures") or []:
                        sig_ok = sig["result"] == "pass"
                        label  = f"Firma #{sig['index']+1} — `{sig.get('d_domain','?')}` s=`{sig.get('selector','?')}`"
                        if sig_ok:
                            st.success(label + " ✅")
                        else:
                            st.error(label + " ❌")
                        st.caption(f"DNS key record: `{sig.get('dns_key_record','')}`")
                        st.caption(sig.get("message",""))

                    # Cross-reference
                    dkim_header = auth_header.get("DKIM")
                    if dkim_header:
                        match = dkim_header["status"] == dkim_status
                        icon  = "✅" if match else "⚠️ diverge"
                        st.caption(f"Authentication-Results header: `{dkim_header['status']}` {icon}")

                # ── DMARC column ───────────────────────────────────────────
                with col_dmarc:
                    st.markdown("#### DMARC")
                    dmarc_status = dmarc_live["status"]
                    if dmarc_status == "pass":
                        st.success("PASS ✅")
                    elif dmarc_status == "fail":
                        st.error("FAIL ❌")
                    elif dmarc_status == "none":
                        st.warning("NESSUN RECORD ⚠️")
                    else:
                        st.warning(f"{dmarc_status.upper()}")

                    st.caption(f"Policy: `{dmarc_live.get('policy','—')}` ({dmarc_live.get('pct',100)}%)")
                    st.caption(f"adkim: `{dmarc_live.get('adkim','r')}` · aspf: `{dmarc_live.get('aspf','r')}`")
                    spf_align_icon  = "✅" if dmarc_live.get("spf_aligned")  else "❌"
                    dkim_align_icon = "✅" if dmarc_live.get("dkim_aligned") else "❌"
                    st.caption(f"SPF allineato: {spf_align_icon} · DKIM allineato: {dkim_align_icon}")

                    if dmarc_live.get("record"):
                        with st.expander("Record DMARC"):
                            st.code(dmarc_live["record"], language="text")
                    if dmarc_live.get("rua"):
                        st.caption(f"RUA: `{dmarc_live['rua']}`")

                    # Cross-reference
                    dmarc_header = auth_header.get("DMARC")
                    if dmarc_header:
                        match = dmarc_header["status"] in ("pass","bestguesspass") and dmarc_status == "pass"
                        icon  = "✅" if match else "⚠️ diverge"
                        st.caption(f"Authentication-Results header: `{dmarc_header['status']}` {icon}")

                # ── Alignment summary ──────────────────────────────────────
                st.markdown("---")
                st.markdown("**Riepilogo allineamento DMARC**")
                c1, c2 = st.columns(2)
                c1.markdown(
                    f"SPF domain (`{spf_live.get('domain','—')}`) vs "
                    f"From domain (`{dmarc_live.get('domain','—')}`) — "
                    f"modalità `{dmarc_live.get('aspf','r')}`: "
                    + ("✅ allineato" if dmarc_live.get("spf_aligned") else "❌ non allineato")
                )
                dkim_sigs = dkim_live.get("signatures") or []
                if dkim_sigs:
                    passing_sigs = [s for s in dkim_sigs if s["result"] == "pass"]
                    for s in passing_sigs:
                        c2.markdown(
                            f"DKIM d=`{s.get('d_domain','?')}` vs "
                            f"From domain (`{dmarc_live.get('domain','—')}`) — "
                            f"modalità `{dmarc_live.get('adkim','r')}`: "
                            + ("✅ allineato" if dmarc_live.get("dkim_aligned") else "❌ non allineato")
                        )
                else:
                    c2.markdown("Nessuna firma DKIM da verificare per l'allineamento")

                # ── ARC ────────────────────────────────────────────────────
                if soc["arc_seal"]:
                    st.markdown("---")
                    st.markdown("**ARC Headers (intermediary signing)**")
                    with st.expander("ARC-Seal"):
                        st.code(soc["arc_seal"], language="text")
                    if soc["arc_message_signature"]:
                        with st.expander("ARC-Message-Signature"):
                            st.code(soc["arc_message_signature"], language="text")
                    if soc["arc_authentication_results"]:
                        with st.expander("ARC-Authentication-Results"):
                            st.code(soc["arc_authentication_results"], language="text")

            # ── 1d. Allegati ───────────────────────────────────────────────
            attachments = soc.get("attachments", [])
            with st.expander(f"📎 Allegati ({len(attachments)} trovati)"):
                if not attachments:
                    st.info("Nessun allegato rilevato.")
                for att in attachments:
                    st.markdown(f"### `{att['filename']}`")
                    c1, c2, c3 = st.columns(3)
                    c1.markdown(f"**Content-Type:** `{att['content_type']}`")
                    c2.markdown(f"**Encoding:** `{att['encoding']}`")
                    c3.markdown(f"**Ext. da filename:** `{att['extension_from_filename'] or '—'}`")

                    c4, c5 = st.columns(2)
                    c4.markdown(
                        f"**Magic Bytes (hex, primi 8B):** "
                        f"`{att['magic_bytes_hex'][:16] + '…' if att['magic_bytes_hex'] else '—'}`"
                    )
                    c5.markdown(
                        f"**Formato rilevato (magic):** `{att['magic_detected_format'] or '—'}`"
                    )

                    match_ok = att.get("extension_match")
                    if match_ok is True:
                        st.success("✅ Estensione, Content-Type e magic bytes coerenti")
                    elif att.get("anomaly"):
                        st.error(f"🔴 Anomalia: {att['anomaly']}")
                    else:
                        st.warning("⚠️ Impossibile verificare la coerenza (dati insufficienti)")
                    st.markdown("---")

            # ── 1e. Corpo testo ────────────────────────────────────────────
            with st.expander("📄 Corpo Email (testo estratto)"):
                st.text_area("Body:", soc["body"] or "(vuoto)", height=200)

            # ── 1f. Flags SOC summary ──────────────────────────────────────
            st.subheader("🚨 Riepilogo Flags SOC")
            flags = soc.get("flags", [])
            if not flags:
                st.success("Nessun flag critico rilevato.")
            else:
                for f in flags:
                    icon = _badge(f["level"])
                    lvl  = f["level"]
                    if lvl == "HIGH":
                        st.error(f"{icon} **[{lvl}] {f['field']}** — {f['message']}")
                    elif lvl == "MEDIUM":
                        st.warning(f"{icon} **[{lvl}] {f['field']}** — {f['message']}")
                    elif lvl == "LOW":
                        st.warning(f"{icon} **[{lvl}] {f['field']}** — {f['message']}")
                    else:
                        st.info(f"{icon} **[{lvl}] {f['field']}** — {f['message']}")

            st.divider()

            # ── 2. REAL AI CONTENT ANALYSIS (BERT integration) ────────────
            st.subheader("🤖 Analisi Contenuto con Intelligenza Artificiale (BERT)")
            
            # Unisci Oggetto e Corpo dell'email per l'analisi testuale completa
            email_text = f"Subject: {soc['subject'] or ''}\n\n{soc['body'] or ''}".strip()
            
            if not email_text or email_text.lower() == "subject:":
                st.warning("⚠️ Impossibile eseguire la classificazione: l'email non contiene testo significativo nel corpo o nell'oggetto.")
            else:
                with st.spinner("Messa a punto dei token... BERT sta analizzando il testo..."):
                    # Tokenizzazione (Tronca se supera i 512 token standard di BERT)
                    inputs = tokenizer(
                        email_text, 
                        return_tensors="pt", 
                        truncation=True, 
                        max_length=512
                    )
                    
                    # Esegui l'inferenza senza calcolare i gradienti (più veloce)
                    with torch.no_grad():
                        outputs = model(**inputs)
                        logits = outputs.logits
                        # Calcola le probabilità con Softmax
                        probabilities = torch.softmax(logits, dim=1).flatten().tolist()
                    
                    # Assumiamo la mappatura classica del tuo dataset: Index 0 = Safe, Index 1 = Phishing
                    # (Se nel tuo addestramento l'ordine è invertito, basta invertire gli indici qui sotto!)
                    prob_safe = probabilities[0] * 100
                    prob_phishing = probabilities[1] * 100

                    # Renderizza i risultati grafici a seconda della classificazione
                    if prob_phishing > prob_safe:
                        st.error(f"🚨 **Risultato IA: RILEVATO POSSIBILE PHISHING**")
                        st.progress(int(prob_phishing))
                        st.write(f"**Confidenza del Modello:** {prob_phishing:.2f}% Probability Phishing")
                    else:
                        st.success(f"🟢 **Risultato IA: EMAIL LEGITTIMA**")
                        st.progress(int(prob_phishing)) # La barra si riempie in base alla pericolosità
                        st.write(f"**Confidenza del Modello:** {prob_safe:.2f}% Probability Legitimate")
                    
                    with st.expander("Vedi metriche grezze dei logit"):
                        st.json({
                            "Logits (Safe, Phishing)": logits.flatten().tolist(),
                            "Probabilità Safe": f"{prob_safe:.4f}%",
                            "Probabilità Phishing": f"{prob_phishing:.4f}%"
                        })

            # ── cleanup ────────────────────────────────────────────────────
            if os.path.exists(temp_path):
                os.remove(temp_path)

        except Exception as e:
            st.error(f"Si è verificato un errore durante l'analisi: {str(e)}")
            import traceback
            st.code(traceback.format_exc())
import streamlit as st
import os
import sys
import torch
from transformers import AutoTokenizer, AutoModelForSequenceClassification

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.parser import EmailParserPipeline
from src.validators import EmailSecurityValidator
from src.analyzer import EmlSOCAnalyzer
from src.eml_dataset_builder import EmlDatasetBuilder
from src.train import BERTPhishingTrainer

HF_MODEL_ID = "eugenioderodev/fishstop-bert"


# ── backend ────────────────────────────────────────────────────────────────
@st.cache_resource
@st.cache_resource
def init_backend():
    parser    = EmailParserPipeline()
    validator = EmailSecurityValidator()
    analyzer  = EmlSOCAnalyzer()

    company_path = os.path.join("models", "company_model")
    base_path    = os.path.join("models", "saved_models")

    if os.path.isdir(company_path) and os.path.exists(os.path.join(company_path, "config.json")):
        model_path   = company_path
        model_source = "company"
    elif os.path.isdir(base_path) and os.path.exists(os.path.join(base_path, "config.json")):
        model_path   = base_path    # locale durante sviluppo
        model_source = "base"
    else:
        model_path   = HF_MODEL_ID  # Streamlit Cloud: scarica da HF
        model_source = "base"

    tokenizer = AutoTokenizer.from_pretrained(model_path)
    model     = AutoModelForSequenceClassification.from_pretrained(model_path)

    return parser, validator, analyzer, tokenizer, model, model_source

parser, validator, analyzer, tokenizer, model, model_source = init_backend()

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


# ── navigazione sidebar ────────────────────────────────────────────────────
with st.sidebar:
    st.markdown("## 🛡️ FishStop")
    page = st.radio(
        "Sezione",
        ["🔍 Triage & Analisi", "🗃️ Dataset Builder"],
        label_visibility="collapsed",
    )
    st.divider()
    st.caption("FishStop — Email Security Platform")

if page == "🗃️ Dataset Builder":
    # ═══════════════════════════════════════════════════════════════════════
    # DATASET BUILDER
    # ═══════════════════════════════════════════════════════════════════════
    st.header("🗃️ Dataset Builder — Aggiungi Email al Pool di Addestramento")
    st.markdown(
        "Carica file `.eml` in batch, assegna la label corretta e arricchisci il "
        "dataset custom che verrà usato al prossimo ciclo di training."
    )

    builder = EmlDatasetBuilder()
    stats   = builder.stats()

    st.subheader("📊 Stato Dataset Custom")
    m1, m2, m3 = st.columns(3)
    m1.metric("Totale campioni", stats["total"])
    m2.metric("✅ Legittime",    stats["legitimate"])
    m3.metric("🚨 Phishing",     stats["phishing"])
    if stats["last_added"]:
        st.caption(f"Ultimo aggiornamento: {stats['last_added']}")
    st.divider()

    st.subheader("📥 Carica nuovi file .eml")
    up_col, reset_col = st.columns([5, 1])
    with up_col:
        uploaded_emls = st.file_uploader(
            "Trascina qui uno o più file .eml",
            type=["eml"],
            accept_multiple_files=True,
            key=f"builder_uploader_{st.session_state.get('builder_uploader_gen', 0)}",
        )
    with reset_col:
        st.markdown("&nbsp;", unsafe_allow_html=True)  # spacer verticale
        if st.button("🗑️ Reset", use_container_width=True, type="secondary", help="Svuota l'uploader e azzera tutte le label assegnate"):
            # Pulisce cache bytes e label, poi ruota la key dell'uploader
            raw_cache_now = st.session_state.get("builder_raw_cache", {})
            for fname in list(raw_cache_now.keys()):
                st.session_state.pop(f"label_{fname}", None)
            st.session_state.pop("builder_raw_cache", None)
            st.session_state["builder_uploader_gen"] = (
                st.session_state.get("builder_uploader_gen", 0) + 1
            )
            st.rerun()

    if uploaded_emls:
        n_uploaded = len(uploaded_emls)
        st.markdown(f"**{n_uploaded} file caricati.** Assegna la label prima di procedere.")

        # ── Leggi i bytes UNA VOLTA SOLA e metti in cache nella sessione ──
        # Questo risolve il bug del puntatore consumato: upl.read() la
        # seconda volta (dentro il loop di salvataggio) restituiva b"".
        cache_key = "builder_raw_cache"
        if cache_key not in st.session_state:
            st.session_state[cache_key] = {}
        raw_cache: dict[str, bytes] = st.session_state[cache_key]

        for upl in uploaded_emls:
            if upl.name not in raw_cache:
                raw_cache[upl.name] = upl.read()

        # ── Assegnazione bulk ──────────────────────────────────────────────
        with st.container(border=True):
            bc1, bc2, bc3 = st.columns([2, 1, 1])
            with bc1:
                st.markdown("**🏷️ Assegna la stessa label a tutti i file**")
                st.caption("Sovrascrive le selezioni individuali sotto.")
            with bc2:
                if st.button("✅ Tutti Legittimi", use_container_width=True):
                    for u in uploaded_emls:
                        st.session_state[f"label_{u.name}"] = 0
                    st.rerun()
            with bc3:
                if st.button("🚨 Tutti Phishing", use_container_width=True):
                    for u in uploaded_emls:
                        st.session_state[f"label_{u.name}"] = 1
                    st.rerun()

        st.divider()

        # ── Preview + selezione label per ogni file ────────────────────────
        # Il preview usa i bytes già cachati — nessun seek/re-read.
        # Con 500+ file mostriamo un expander collassato di default per
        # non appesantire il rendering della pagina.
        import email as _email_mod

        PREVIEW_THRESHOLD = 50  # sopra questa soglia si usa expander collassato

        assignments: dict[str, int] = {}

        def _quick_preview(raw: bytes) -> tuple[str, str, str]:
            """Estrae From / Subject / inizio body senza fare il parse completo."""
            try:
                msg = _email_mod.message_from_bytes(raw)
                subject = str(msg.get("Subject") or "—").strip()
                sender  = str(msg.get("From")    or "—").strip()
                body_pv = ""
                for part in msg.walk():
                    if part.get_content_type() == "text/plain":
                        pl = part.get_payload(decode=True)
                        if pl:
                            lines    = [l.strip() for l in pl.decode("utf-8", errors="ignore").splitlines() if l.strip()]
                            body_pv  = " ".join(lines[:2])[:160]
                            break
                return sender, subject, body_pv
            except Exception:
                return "—", "—", ""

        def _render_file_row(upl_name: str, raw: bytes) -> int:
            """Disegna la riga di preview + radio label. Restituisce il label scelto (0 o 1)."""
            sender, subject, body_pv = _quick_preview(raw)

            # Priorità: 1) valore già in session_state per questo file —
            #               può essere un int (0/1 scritto dal bottone bulk)
            #               oppure una tupla ("✅ Legittima", 0) salvata dal widget radio
            #            2) default 0 (Legittima) — mai phishing di default
            session_key = f"label_{upl_name}"
            existing = st.session_state.get(session_key)
            if existing is None:
                default_idx = 0
            elif isinstance(existing, tuple):
                default_idx = existing[1]    # ("✅ Legittima", 0) → 0
            else:
                default_idx = int(existing)  # int da bottone bulk (0 o 1)

            with st.container(border=True):
                c1, c2 = st.columns([3, 1])
                with c1:
                    st.markdown(f"**📧 {upl_name}**")
                    st.caption(f"From: {sender}")
                    st.caption(f"Subject: {subject}")
                    if body_pv:
                        st.caption(f"Body: {body_pv}…")
                with c2:
                    label_choice = st.radio(
                        "Label",
                        options=[("✅ Legittima", 0), ("🚨 Phishing", 1)],
                        format_func=lambda x: x[0],
                        key=session_key,
                        index=default_idx,
                    )
            return label_choice[1]

        if n_uploaded <= PREVIEW_THRESHOLD:
            # Mostra tutti i file direttamente
            for upl in uploaded_emls:
                assignments[upl.name] = _render_file_row(upl.name, raw_cache[upl.name])
        else:
            # Con molti file usiamo un expander per non bloccare il browser
            st.info(
                f"ℹ️ {n_uploaded} file caricati. "
                "L'anteprima dettagliata è collassata per migliorare le prestazioni. "
                "Usa i bottoni **Tutti Legittimi / Tutti Phishing** per assegnare la label in blocco."
            )
            with st.expander(f"📋 Mostra anteprima di tutti i {n_uploaded} file", expanded=False):
                for upl in uploaded_emls:
                    assignments[upl.name] = _render_file_row(upl.name, raw_cache[upl.name])
            # Assegna label di default per i file non ancora visualizzati nell'expander
            for upl in uploaded_emls:
                if upl.name not in assignments:
                    val = st.session_state.get(f"label_{upl.name}", 0)
                    # session_state può contenere un int (da bulk) o una tupla (da radio widget)
                    assignments[upl.name] = val[1] if isinstance(val, tuple) else int(val)

        st.divider()

        if st.button("💾 Aggiungi al Dataset", type="primary", use_container_width=True):
            # ── Costruisce il batch con i bytes già cachati ─────────────────
            batch_items = [
                (raw_cache[upl.name], upl.name, assignments.get(upl.name, 0))
                for upl in uploaded_emls
                if upl.name in raw_cache
            ]

            progress_bar = st.progress(0, text="Avvio processing…")
            status_placeholder = st.empty()

            def _ui_progress(done: int, total: int) -> None:
                pct  = int(done / total * 100)
                progress_bar.progress(pct, text=f"Processing… {done}/{total}")

            # add_batch: hash caricati 1 volta, CSV scritto 1 volta, .eml salvati in parallelo
            results = builder.add_batch(batch_items, progress_callback=_ui_progress)

            progress_bar.progress(100, text="Completato ✅")

            added = skipped = errors = 0
            error_lines: list[str] = []

            for res in results:
                lbl       = assignments.get(res.get("message", "").split("'")[1] if "'" in res.get("message","") else "", 1)
                label_str = "Phishing 🚨" if lbl == 1 else "Legittima ✅"
                if res["status"] == "added":
                    added += 1
                elif res["status"] == "duplicate":
                    skipped += 1
                else:
                    errors += 1
                    error_lines.append(res["message"])

            # Riepilogo compatto — non mostriamo un st.success per riga
            # (con 500 file riempirebbe lo schermo)
            st.success(f"✅ **{added} aggiunte** | ⚠️ {skipped} duplicate | ❌ {errors} errori")
            if error_lines:
                with st.expander(f"❌ Dettaglio {errors} errori"):
                    for line in error_lines:
                        st.caption(line)

            new_stats = builder.stats()
            st.info(
                f"📊 Dataset: **{new_stats['total']} campioni totali** "
                f"({new_stats['legitimate']} legittime, {new_stats['phishing']} phishing)"
            )

            # Svuota la cache dei bytes e le label per liberare memoria e resettare la UI
            st.session_state.pop(cache_key, None)
            for upl in uploaded_emls:
                st.session_state.pop(f"label_{upl.name}", None)

            # Forza il rerun così i counter in cima (m1/m2/m3) leggono il CSV aggiornato
            st.rerun()

    st.divider()
    st.subheader("📋 Campioni nel Dataset Custom")
    df_view = builder.load_df()

    if df_view.empty:
        st.info("Il dataset è vuoto. Carica dei file .eml per iniziare.")
    else:
        filter_label = st.selectbox(
            "Filtra per label",
            options=["Tutti", "✅ Legittime (0)", "🚨 Phishing (1)"],
        )
        if filter_label == "✅ Legittime (0)":
            df_view = df_view[df_view["label"] == 0]
        elif filter_label == "🚨 Phishing (1)":
            df_view = df_view[df_view["label"] == 1]

        display_df = df_view[["source_file", "label", "added_at", "text_hash", "xt_combined"]].copy()
        display_df["xt_combined"] = display_df["xt_combined"].str[:80] + "…"
        display_df["text_hash"]   = display_df["text_hash"].str[:12] + "…"
        display_df["label"]       = display_df["label"].map({0: "✅ Legittima", 1: "🚨 Phishing"})
        st.dataframe(display_df, width="stretch", hide_index=True)

        st.markdown("**🗑️ Rimuovi un campione**")
        hash_to_remove = st.text_input("Incolla il text_hash (12+ caratteri)", placeholder="es. 3a7f2c1b9e04…")
        if st.button("Rimuovi", type="secondary"):
            if not hash_to_remove or len(hash_to_remove) < 8:
                st.warning("Hash troppo corto.")
            else:
                full_hashes = df_view["text_hash"].tolist()
                matches = [h for h in full_hashes if h.startswith(hash_to_remove)]
                if not matches:
                    st.error("Nessun campione trovato.")
                elif len(matches) > 1:
                    st.error(f"Prefisso ambiguo — {len(matches)} match. Inserisci più caratteri.")
                else:
                    if builder.remove_by_hash(matches[0]):
                        st.success(f"✅ Rimosso (`{matches[0][:12]}…`)")
                        st.rerun()
                    else:
                        st.error("Rimozione fallita.")

        st.markdown("---")
        st.markdown("**🔴 Reset completo dataset**")

        if not st.session_state.get("confirm_reset_dataset"):
            if st.button("🔴 Cancella tutto il dataset", type="secondary", use_container_width=True):
                st.session_state["confirm_reset_dataset"] = True
                st.rerun()
        else:
            st.warning(
                f"⚠️ Stai per cancellare **{len(df_view)} campioni** e tutti i file .eml nelle cartelle "
                f"`custom_legitimate` e `custom_phishing`. L'operazione è **irreversibile**."
            )
            col_yes, col_no = st.columns(2)
            with col_yes:
                if st.button("✅ Sì, cancella tutto", type="primary", use_container_width=True):
                    import shutil
                    # Svuota il CSV (ricrea solo header)
                    with open(builder.csv_path, "w", newline="", encoding="utf-8") as f:
                        import csv as _csv
                        _csv.DictWriter(f, fieldnames=["xt_combined", "label", "source_file", "text_hash", "added_at"]).writeheader()
                    # Cancella e ricrea le cartelle .eml
                    for folder in [builder.legit_folder, builder.phishing_folder]:
                        if os.path.isdir(folder):
                            shutil.rmtree(folder)
                        os.makedirs(folder, exist_ok=True)
                    st.session_state.pop("confirm_reset_dataset", None)
                    st.success("✅ Dataset resettato.")
                    st.rerun()
            with col_no:
                if st.button("❌ Annulla", use_container_width=True):
                    st.session_state.pop("confirm_reset_dataset", None)
                    st.rerun()

    st.divider()

    # ── Addestra il modello aziendale ──────────────────────────────────
    st.subheader("🧠 Addestra il Tuo Modello")

    # Leggi metadati dell'ultimo training se esiste
    company_path = os.path.join("models", "company_model")
    meta_path    = os.path.join(company_path, "training_meta.json")
    last_meta    = None
    if os.path.exists(meta_path):
        import json as _json
        try:
            with open(meta_path) as _f:
                last_meta = _json.load(_f)
        except Exception:
            pass

    # Stato modello attivo
    if model_source == "company":
        st.success("✅ **Modello aziendale attivo** — l'app sta usando il tuo modello personalizzato.")
    else:
        st.info("ℹ️ **Modello base attivo** (Kaggle-BERT). Addestra il tuo modello per personalizzarlo.")

    if last_meta:
        st.caption(f"Ultimo training: {last_meta.get('trained_at','—')[:19].replace('T',' ')} UTC — "
                   f"{last_meta.get('n_train',0)+last_meta.get('n_val',0)+last_meta.get('n_test',0)} campioni totali")
        m = last_meta.get("metrics") or {}
        if m:
            mc1, mc2, mc3, mc4 = st.columns(4)
            mc1.metric("Accuracy",  f"{m.get('accuracy',0):.2%}")
            mc2.metric("F1",        f"{m.get('f1',0):.2%}")
            mc3.metric("Precision", f"{m.get('precision',0):.2%}")
            mc4.metric("Recall",    f"{m.get('recall',0):.2%}")

    st.markdown("---")

    # Parametri training
    cur_stats = builder.stats()
    n_legit    = cur_stats["legitimate"]
    n_phishing = cur_stats["phishing"]
    n_total    = cur_stats["total"]

    tc1, tc2 = st.columns(2)
    with tc1:
        num_epochs = st.slider("Numero di epoche", min_value=1, max_value=10, value=5)
    with tc2:
        st.markdown("**Dataset disponibile**")
        st.caption(f"✅ Legittime: **{n_legit}** &nbsp;|&nbsp; 🚨 Phishing: **{n_phishing}** &nbsp;|&nbsp; Totale: **{n_total}**")
        MIN = 20
        if n_legit < MIN or n_phishing < MIN:
            st.warning(f"⚠️ Servono almeno **{MIN} campioni per classe**. "
                       f"Mancano: {max(0, MIN-n_legit)} legittime, {max(0, MIN-n_phishing)} phishing.")
        elif max(n_legit, n_phishing) / max(min(n_legit, n_phishing), 1) > 5:
            st.warning("⚠️ Dataset sbilanciato — considera di aggiungere più email della classe minoritaria.")
        else:
            st.success("✅ Dataset pronto per il training.")

    can_train = n_legit >= 20 and n_phishing >= 20

    if st.button("🚀 Avvia Training", type="primary",
                 disabled=not can_train,
                 width="stretch"):
        progress_bar = st.progress(0)
        status_text  = st.empty()

        def _ui_progress(step: str, pct: int):
            progress_bar.progress(pct)
            status_text.caption(f"⏳ {step}")

        with st.spinner("Training in corso… non chiudere questa pagina."):
            try:
                trainer_obj = BERTPhishingTrainer()
                result = trainer_obj.finetune_on_custom(
                    base_model_path="./models/saved_models",
                    output_dir="./models/company_model",
                    num_epochs=num_epochs,
                    progress_callback=_ui_progress,
                )
            except Exception as _exc:
                result = {"status": "error", "message": str(_exc), "metrics": None}

        progress_bar.progress(100)
        status_text.empty()

        if result["status"] == "ok":
            st.success(f"✅ **Training completato!** {result['message']}")
            m = result.get("metrics") or {}
            if m:
                rc1, rc2, rc3, rc4 = st.columns(4)
                rc1.metric("Accuracy",  f"{m.get('accuracy',0):.2%}")
                rc2.metric("F1",        f"{m.get('f1',0):.2%}")
                rc3.metric("Precision", f"{m.get('precision',0):.2%}")
                rc4.metric("Recall",    f"{m.get('recall',0):.2%}")
            st.info("🔄 Riavvia l'app (`streamlit run`) per caricare il nuovo modello aziendale.")
        elif result["status"] == "insufficient_data":
            st.warning(f"⚠️ {result['message']}")
        else:
            st.error(f"❌ Errore durante il training: {result['message']}")

else:
    pass  # continua sotto con il triage

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

                    #Nuovo codice (Fix con controllo Reply-To assente):
                    if not soc.get("reply_to"):
                                        reply_icon = "⚪ Assente"
                    else:
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

                    # ── Return-Path domain mismatch ───────────────────────────────────────
                    if soc.get("return_path_domain_mismatch"):
                        st.error(
                            f"🔴 **Return-Path Mismatch** — dominio `{soc['return_path_domain']}` "
                            f"≠ dominio From `{soc['from_']}`. "
                            "I bounce vengono recapitati a un dominio diverso dal mittente dichiarato."
                        )
                    elif soc.get("return_path"):
                        st.success("✅ Return-Path coerente con il dominio From")

                    # ── Display Name Spoofing ─────────────────────────────────────────────
                    dns_embedded = soc.get("display_name_spoofing")
                    if dns_embedded:
                        st.error(
                            f"🔴 **Display Name Spoofing rilevato** — il Display Name contiene "
                            f"`{dns_embedded}` ma il mittente reale è `{soc['from_']}`. "
                            "I client di posta mostrano l'indirizzo nel nome, non quello reale."
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

                            # ── AbuseIPDB reputation lookup ────────────────────
                            sender_ip = hop.get("sender_ip")
                            if sender_ip:
                                with st.expander(f"🔍 Reputazione IP: `{sender_ip}`"):
                                    with st.spinner(f"Interrogazione AbuseIPDB per {sender_ip}…"):
                                        ip_rep = validator.check_ip_reputation(sender_ip)

                                    if ip_rep["status"] == "ok":
                                        score = ip_rep["abuseConfidenceScore"]
                                        # Colore badge in base allo score
                                        if ip_rep["isWhitelisted"]:
                                            st.success(f"✅ **IP Whitelisted** — provider noto e affidabile")
                                        elif score == 0:
                                            st.success(f"✅ **Score: {score}/100** — nessuna segnalazione")
                                        elif score < 25:
                                            st.info(f"🟡 **Score: {score}/100** — basso rischio")
                                        elif score < 75:
                                            st.warning(f"🟠 **Score: {score}/100** — rischio moderato")
                                        else:
                                            st.error(f"🔴 **Score: {score}/100** — IP ad alto rischio!")

                                        rep_c1, rep_c2, rep_c3 = st.columns(3)
                                        rep_c1.metric("Segnalazioni totali", ip_rep["totalReports"])
                                        rep_c2.metric("Utenti distinti",     ip_rep["numDistinctUsers"])
                                        rep_c3.metric("Paese",               ip_rep["countryCode"] or "—")

                                        if ip_rep["isp"]:
                                            st.caption(f"**ISP:** {ip_rep['isp']}")
                                        if ip_rep["domain"]:
                                            st.caption(f"**Dominio ISP:** {ip_rep['domain']}")
                                        if ip_rep["usageType"]:
                                            st.caption(f"**Tipo utilizzo:** {ip_rep['usageType']}")
                                        if ip_rep["lastReportedAt"]:
                                            st.caption(f"**Ultima segnalazione:** {ip_rep['lastReportedAt'][:10]}")
                                        st.markdown(
                                            f"[🔗 Apri su AbuseIPDB]({ip_rep['url']})",
                                        )
                                    elif ip_rep["status"] == "skipped":
                                        st.info(f"ℹ️ {ip_rep['message']}")
                                    else:
                                        st.warning(f"⚠️ {ip_rep['message']}")

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
                        if att.get("size_bytes") is not None:
                            sz = att["size_bytes"]
                            sz_str = f"{sz:,} B" if sz < 1024 else f"{sz/1024:.1f} KB" if sz < 1_048_576 else f"{sz/1_048_576:.2f} MB"
                            st.caption(f"📦 Dimensione: **{sz_str}**")

                        match_ok = att.get("extension_match")
                        if match_ok is True:
                            st.success("✅ Estensione, Content-Type e magic bytes coerenti")
                        elif att.get("anomaly"):
                            st.error(f"🔴 Anomalia: {att['anomaly']}")
                        else:
                            st.warning("⚠️ Impossibile verificare la coerenza (dati insufficienti)")

                        # ── Hash & threat intel links ──────────────────────────
                        sha256 = att.get("hash_sha256")
                        if sha256:
                            st.markdown("**🔐 Hash crittografici**")
                            hc1, hc2, hc3 = st.columns(3)
                            hc1.caption("MD5")
                            hc1.code(att['hash_md5'], language="text")
                            hc2.caption("SHA-1")
                            hc2.code(att['hash_sha1'], language="text")
                            hc3.caption("SHA-256")
                            hc3.code(sha256, language="text")

                            st.markdown("**🔍 Analisi VirusTotal**")
                            with st.spinner(f"Interrogazione VirusTotal per `{sha256[:12]}…`"):
                                vt = validator.check_virustotal_hash(sha256)

                            if vt["status"] == "ok":
                                mal  = vt["malicious"]
                                susp = vt["suspicious"]
                                tot  = vt["total"]

                                if mal == 0 and susp == 0:
                                    st.success(f"✅ **Nessuna rilevazione** — 0 / {tot} engine")
                                elif mal <= 3:
                                    st.warning(f"🟠 **{mal} rilevazioni** ({susp} sospetti) su {tot} engine")
                                else:
                                    st.error(f"🔴 **{mal} rilevazioni** ({susp} sospetti) su {tot} engine")

                                vt_c1, vt_c2, vt_c3, vt_c4 = st.columns(4)
                                vt_c1.metric("🔴 Malevolo",  mal)
                                vt_c2.metric("🟠 Sospetto",  susp)
                                vt_c3.metric("✅ Pulito",    vt["harmless"])
                                vt_c4.metric("⬜ Non scansionato", vt["undetected"])

                                if vt["threat_label"]:
                                    st.caption(f"**Threat label:** `{vt['threat_label']}`")
                                if vt["threat_category"]:
                                    st.caption(f"**Categoria:** `{vt['threat_category']}`")
                                if vt["popular_threat"]:
                                    st.caption(f"**Nome comune:** `{vt['popular_threat']}`")
                                if vt["first_submission"]:
                                    st.caption(f"**Prima sottomissione:** {vt['first_submission']}")
                                if vt["last_analysis"]:
                                    st.caption(f"**Ultima analisi:** {vt['last_analysis']}")

                                st.markdown(f"[🔗 Apri su VirusTotal]({vt['url']})")

                            elif vt["status"] == "not_found":
                                st.info(f"ℹ️ {vt['message']}")
                                st.markdown(f"[🔗 Invia per analisi su VirusTotal]({vt['url']})")
                            elif vt["status"] == "skipped":
                                st.info(f"ℹ️ {vt['message']}")
                            else:
                                st.warning(f"⚠️ {vt['message']}")

                            st.caption(
                                "⚠️ Prima di caricare un allegato su servizi online, "
                                "verifica che non contenga dati riservati o PII."
                            )
                        st.markdown("---")

                # ── 1e. Corpo testo ────────────────────────────────────────────
                with st.expander("📄 Corpo Email (testo estratto)"):
                    body_source = soc.get("body_source", "unknown")
                    strip_applied = soc.get("html_strip_applied", False)

                    # Badge sorgente
                    if body_source == "text/plain":
                        st.caption("📝 Sorgente: `text/plain` — nessuno stripping necessario")
                    elif body_source == "text/html":
                        st.caption("🌐 Sorgente: `text/html` — stripping HTML applicato prima dell'analisi AI")
                    else:
                        st.caption("⚠️ Corpo email non rilevato")

                    if strip_applied:
                        # Mostra entrambe le versioni per permettere confronto
                        tab_clean, tab_raw = st.tabs(["✅ Testo pulito (input BERT)", "🔍 HTML grezzo originale"])
                        with tab_clean:
                            st.text_area(
                                "Testo dopo HTML stripping:",
                                soc.get("body_clean") or "(vuoto dopo stripping)",
                                height=220,
                            )
                        with tab_raw:
                            st.code(soc.get("body_html") or "(nessun HTML)", language="html")
                    else:
                        st.text_area("Body:", soc.get("body_clean") or soc["body"] or "(vuoto)", height=220)

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
                if model_source == "company":
                    st.success("🏢 Modello **aziendale** attivo — addestrato sulle email della tua organizzazione.")
                else:
                    st.info("🌐 Modello **base** attivo (Kaggle-BERT). Popola il dataset e addestra il tuo modello personalizzato nel Dataset Builder.")

                # Usa body_clean (testo senza tag HTML) come input per BERT.
                # Se il corpo era HTML grezzo, body_clean contiene il testo dopo
                # stripping; se era già text/plain, body_clean è identico al body.
                clean_body = soc.get("body_clean") or soc.get("body") or ""
                email_text = f"Subject: {soc['subject'] or ''}\n\n{clean_body}".strip()

                if soc.get("html_strip_applied"):
                    st.caption("ℹ️ Input BERT: testo estratto dopo HTML stripping — tag e commenti offuscanti rimossi.")

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
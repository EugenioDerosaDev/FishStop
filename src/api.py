import os
import sys
import tempfile
from typing import Optional

from fastapi import FastAPI, File, UploadFile, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.analyzer import EmlSOCAnalyzer
from src.validators import EmailSecurityValidator

app = FastAPI(
    title="FishStop API",
    description="SOC Email Triage & Phishing Detection API",
    version="1.0.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# Istanze singleton (thread-safe per lettura)
analyzer  = EmlSOCAnalyzer()
validator = EmailSecurityValidator()


# ── Modelli risposta ────────────────────────────────────────────────────────

class HealthResponse(BaseModel):
    status: str
    version: str


class AnalyzeResponse(BaseModel):
    from_: Optional[str]
    to: Optional[str]
    subject: Optional[str]
    date: Optional[str]
    message_id: Optional[str]
    reply_to_mismatch: bool
    return_path_domain_mismatch: bool
    display_name_spoofing: Optional[str]
    dkim_signature_present: bool
    auth_results: dict
    flags: list
    links: list
    lookalike_alerts: list
    attachments: list
    body_clean: Optional[str]


# ── Endpoints ───────────────────────────────────────────────────────────────

@app.get("/health", response_model=HealthResponse)
def health():
    return {"status": "ok", "version": "1.0.0"}


@app.post("/analyze", response_model=AnalyzeResponse)
async def analyze_eml(file: UploadFile = File(...)):
    """
    Carica un file .eml e ricevi l'analisi SOC completa.
    Restituisce header parsing, flags, link, lookalike domains e allegati.
    """
    if not file.filename.endswith(".eml"):
        raise HTTPException(status_code=400, detail="Il file deve avere estensione .eml")

    contents = await file.read()

    # Scrivi su file temp (EmlSOCAnalyzer lavora su path)
    with tempfile.NamedTemporaryFile(suffix=".eml", delete=False) as tmp:
        tmp.write(contents)
        tmp_path = tmp.name

    try:
        report = analyzer.analyze(tmp_path)
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Errore analisi: {exc}")
    finally:
        os.unlink(tmp_path)

    # Rimuovi i raw bytes dalla risposta (non serializzabili in JSON)
    report.pop("raw_eml_bytes", None)

    return AnalyzeResponse(
        from_=report.get("from_"),
        to=report.get("to"),
        subject=report.get("subject"),
        date=report.get("date"),
        message_id=report.get("message_id"),
        reply_to_mismatch=report.get("reply_to_mismatch", False),
        return_path_domain_mismatch=report.get("return_path_domain_mismatch", False),
        display_name_spoofing=report.get("display_name_spoofing"),
        dkim_signature_present=report.get("dkim_signature_present", False),
        auth_results=report.get("auth_results", {}),
        flags=report.get("flags", []),
        links=report.get("links", []),
        lookalike_alerts=report.get("lookalike_alerts", []),
        attachments=[
            {k: v for k, v in att.items()}
            for att in report.get("attachments", [])
        ],
        body_clean=report.get("body_clean"),
    )


@app.get("/analyze/flags-only")
async def analyze_flags(file: UploadFile = File(...)):
    """Versione leggera: restituisce solo i flags SOC senza il body."""
    if not file.filename.endswith(".eml"):
        raise HTTPException(status_code=400, detail="Richiesto file .eml")

    contents = await file.read()
    with tempfile.NamedTemporaryFile(suffix=".eml", delete=False) as tmp:
        tmp.write(contents)
        tmp_path = tmp.name

    try:
        report = analyzer.analyze(tmp_path)
    finally:
        os.unlink(tmp_path)

    high_flags = [f for f in report.get("flags", []) if f["level"] == "HIGH"]
    return {
        "subject":       report.get("subject"),
        "from_":         report.get("from_"),
        "total_flags":   len(report.get("flags", [])),
        "high_flags":    len(high_flags),
        "flags":         report.get("flags", []),
        "lookalike_alerts": report.get("lookalike_alerts", []),
    }


@app.post("/check-ip")
def check_ip(ip: str):
    """Controlla la reputazione di un IP su AbuseIPDB."""
    result = validator.check_ip_reputation(ip)
    return result


@app.post("/check-domain")
def check_domain(domain: str):
    """Controlla la reputazione di un dominio via AbuseIPDB (con risoluzione DNS)."""
    result = validator.check_domain_reputation(domain)
    return result
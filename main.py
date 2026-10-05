from pathlib import Path
import json

from fastapi import FastAPI, UploadFile, File, HTTPException, Depends
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from sqlalchemy.orm import Session

from database import Base, engine, get_db
from model import Analysis
from parser import parse_log
from detector import detect_threats
from ioc import extract_iocs
from analyzer import generate_analysis


# Create database tables
Base.metadata.create_all(bind=engine)


# Create FastAPI application
app = FastAPI(
    title="AI Security Log Analyzer",
    description=(
        "Analyze security logs, detect threats, "
        "extract IOCs, and generate AI-powered security insights."
    ),
    version="1.0.0"
)


# Directories
LOG_DIR = Path("logs")
FRONTEND_DIR = Path("frontend")

LOG_DIR.mkdir(exist_ok=True)


# Serve frontend files
app.mount(
    "/static",
    StaticFiles(directory=FRONTEND_DIR),
    name="static"
)


# --------------------------------------------------
# HOME / DASHBOARD
# --------------------------------------------------

@app.get("/")
def home():
    return FileResponse(
        FRONTEND_DIR / "index.html"
    )


# --------------------------------------------------
# ANALYZE SECURITY LOG
# --------------------------------------------------

@app.post("/analyze-log")
async def analyze_log(
    file: UploadFile = File(...),
    db: Session = Depends(get_db)
):

    # Check filename
    if not file.filename:
        raise HTTPException(
            status_code=400,
            detail="File name is required."
        )

    # Allowed file types
    allowed_extensions = {
        ".log",
        ".txt"
    }

    extension = Path(file.filename).suffix.lower()

    if extension not in allowed_extensions:
        raise HTTPException(
            status_code=400,
            detail="Only .log and .txt files are allowed."
        )

    # Read uploaded file
    content = await file.read()

    # Maximum file size: 5 MB
    if len(content) > 5 * 1024 * 1024:
        raise HTTPException(
            status_code=413,
            detail="File is too large. Maximum size is 5 MB."
        )

    # Convert file to text
    text = content.decode(
        "utf-8",
        errors="ignore"
    )

    # Secure filename
    safe_filename = Path(file.filename).name

    # Save uploaded log
    file_path = LOG_DIR / safe_filename
    file_path.write_bytes(content)

    # --------------------------------------------------
    # 1. Parse log
    # --------------------------------------------------

    events = parse_log(text)

    # --------------------------------------------------
    # 2. Detect threats
    # --------------------------------------------------

    threats = detect_threats(events)

    # --------------------------------------------------
    # 3. Extract IOCs
    # --------------------------------------------------

    iocs = extract_iocs(text)

    # --------------------------------------------------
    # 4. Generate AI security analysis
    # --------------------------------------------------

    analysis = generate_analysis(
        threats,
        iocs
    )

    # --------------------------------------------------
    # 5. Determine overall severity
    # --------------------------------------------------

    if any(
        threat["severity"] == "High"
        for threat in threats
    ):
        severity = "High"

    elif any(
        threat["severity"] == "Medium"
        for threat in threats
    ):
        severity = "Medium"

    else:
        severity = "Low"

    # --------------------------------------------------
    # 6. Save analysis to database
    # --------------------------------------------------

    record = Analysis(
        filename=safe_filename,
        total_events=len(events),
        threats_detected=len(threats),
        severity=severity,
        threats=json.dumps(threats),
        iocs=json.dumps(iocs)
    )

    db.add(record)
    db.commit()
    db.refresh(record)

    # --------------------------------------------------
    # 7. Return complete analysis
    # --------------------------------------------------

    return {
        "analysis_id": record.id,
        "filename": safe_filename,
        "total_events": len(events),
        "threats_detected": len(threats),
        "severity": severity,
        "threats": threats,
        "iocs": iocs,
        "ai_analysis": analysis
    }


# --------------------------------------------------
# GET ALL ANALYSES
# --------------------------------------------------

@app.get("/analyses")
def get_analyses(
    db: Session = Depends(get_db)
):

    analyses = db.query(Analysis).order_by(
        Analysis.id.desc()
    ).all()

    results = []

    for analysis in analyses:

        results.append({
            "id": analysis.id,
            "filename": analysis.filename,
            "total_events": analysis.total_events,
            "threats_detected": analysis.threats_detected,
            "severity": analysis.severity
        })

    return results


# --------------------------------------------------
# GET ONE ANALYSIS
# --------------------------------------------------

@app.get("/analyses/{analysis_id}")
def get_analysis(
    analysis_id: int,
    db: Session = Depends(get_db)
):

    analysis = db.query(Analysis).filter(
        Analysis.id == analysis_id
    ).first()

    if analysis is None:
        raise HTTPException(
            status_code=404,
            detail="Analysis not found."
        )

    return {
        "id": analysis.id,
        "filename": analysis.filename,
        "total_events": analysis.total_events,
        "threats_detected": analysis.threats_detected,
        "severity": analysis.severity,
        "threats": json.loads(analysis.threats),
        "iocs": json.loads(analysis.iocs)
    }
"""
SecureLens Web Dashboard — FastAPI backend

Run:
    uvicorn securelens.api:app --reload --port 8000

Endpoints:
    POST /scan         — scan submitted code snippet
    GET  /health       — health check
    GET  /rules        — list all static rules
"""

from __future__ import annotations

import time
from typing import Optional

try:
    from fastapi import FastAPI, HTTPException
    from fastapi.middleware.cors import CORSMiddleware
    from pydantic import BaseModel
except ImportError:
    raise ImportError(
        "Web dashboard requires FastAPI. Install with:\n"
        "  pip install securelens[web]"
    )

from .scanner import Scanner, PYTHON_RULES


app = FastAPI(
    title="SecureLens API",
    description="AI-powered code vulnerability reviewer",
    version="0.1.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

_scanner = Scanner()


# ─────────────────────────────────────────────
# Request / Response schemas
# ─────────────────────────────────────────────

class ScanRequest(BaseModel):
    code:     str
    filename: Optional[str] = "snippet.py"
    language: Optional[str] = "python"
    use_llm:  Optional[bool] = True


class HealthResponse(BaseModel):
    status:    str
    version:   str
    timestamp: float


# ─────────────────────────────────────────────
# Routes
# ─────────────────────────────────────────────

@app.get("/health", response_model=HealthResponse)
def health():
    return HealthResponse(
        status="ok",
        version="0.1.0",
        timestamp=time.time(),
    )


@app.post("/scan")
def scan(request: ScanRequest):
    if not request.code.strip():
        raise HTTPException(status_code=400, detail="Code cannot be empty.")

    result = _scanner.scan_code(
        code=request.code,
        filename=request.filename or "snippet.py",
        language=request.language or "python",
        use_llm=request.use_llm if request.use_llm is not None else True,
    )
    return result.to_dict()


@app.get("/rules")
def list_rules():
    return [
        {
            "rule_id":    r.rule_id,
            "title":      r.title,
            "severity":   r.severity.value,
            "cwe":        r.cwe,
            "description": r.description,
            "suggestion": r.suggestion,
        }
        for r in PYTHON_RULES
    ]
@app.get("/")
def root():
    return {
        "app": "SecureLens API",
        "status": "running",
        "docs": "/docs",
        "health": "/health"
    }
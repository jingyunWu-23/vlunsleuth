from __future__ import annotations

from dataclasses import asdict

from backend.run_audit import run_audit
from backend.schemas import AuditRequest

try:
    from fastapi import FastAPI
except Exception:  # pragma: no cover - FastAPI is optional during backend scaffolding.
    FastAPI = None


if FastAPI is not None:
    app = FastAPI(title="SCG Multi-Model Audit Backend")

    @app.post("/api/v1/audits")
    def create_audit(request: AuditRequest) -> dict:
        report = run_audit(request)
        return asdict(report)
else:
    app = None


from __future__ import annotations

import json
import traceback
import uuid
from concurrent.futures import ThreadPoolExecutor
from dataclasses import asdict
from datetime import datetime, timezone
from pathlib import Path
from threading import Lock
from typing import Any, Dict, List, Optional

from backend.reporting.markdown_report import write_markdown
from backend.run_audit import run_audit
from backend.schemas import AuditRequest

try:
    from fastapi import BackgroundTasks, FastAPI, File, Form, HTTPException, UploadFile
    from fastapi.middleware.cors import CORSMiddleware
    from fastapi.responses import FileResponse
except Exception:  # pragma: no cover - FastAPI is optional during backend scaffolding.
    BackgroundTasks = FastAPI = File = Form = HTTPException = UploadFile = None
    CORSMiddleware = None
    FileResponse = None


API_OUTPUT_ROOT = Path("backend_outputs") / "api_tasks"
UPLOAD_ROOT = Path("backend_outputs") / "uploads"
MAX_WORKERS = 2

_executor = ThreadPoolExecutor(max_workers=MAX_WORKERS)
_lock = Lock()
_tasks: Dict[str, Dict[str, Any]] = {}


if FastAPI is not None:
    app = FastAPI(
        title="SCG Multi-Model Audit Backend",
        version="0.2.0",
        description="Async backend API for Solidity upload, multi-model audit, task status, and report download.",
    )
    app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    @app.get("/api/v1/health")
    def health() -> dict:
        return {
            "status": "ok",
            "time": utc_now(),
            "max_workers": MAX_WORKERS,
            "output_root": str(API_OUTPUT_ROOT.resolve()),
        }

    @app.post("/api/v1/audits")
    def create_audit(request: AuditRequest, async_run: bool = True) -> dict:
        task_id = request.task_id or new_task_id()
        normalized = AuditRequest(
            task_id=task_id,
            source_path=request.source_path,
            mode=request.mode,
            target_vulnerabilities=request.target_vulnerabilities,
            need_verification=request.need_verification,
            need_repair=request.need_repair,
            background_risk_screening=request.background_risk_screening,
            background_screening_action=request.background_screening_action,
            output_dir=str(task_output_dir(task_id)),
        )
        create_task_record(task_id, normalized, source_kind="path")
        if async_run:
            submit_audit(normalized)
            return task_response(task_id)
        run_task(normalized)
        return task_response(task_id)

    @app.post("/api/v1/audits/upload")
    async def upload_and_create_audit(
        file: UploadFile = File(...),
        mode: str = Form("full_audit"),
        target_vulnerabilities: Optional[List[str]] = Form(None),
        need_verification: bool = Form(False),
        need_repair: bool = Form(True),
        background_risk_screening: bool = Form(True),
        background_screening_action: str = Form("warn_only"),
        async_run: bool = Form(True),
    ) -> dict:
        task_id = new_task_id()
        upload_dir = upload_task_dir(task_id)
        upload_dir.mkdir(parents=True, exist_ok=True)
        filename = safe_filename(file.filename or "source.sol")
        upload_path = upload_dir / filename
        data = await file.read()
        if not data:
            raise HTTPException(status_code=400, detail="Uploaded file is empty.")
        if not (filename.lower().endswith(".sol") or filename.lower().endswith(".zip")):
            raise HTTPException(status_code=400, detail="Only .sol and .zip uploads are supported.")
        upload_path.write_bytes(data)

        targets = normalize_form_list(target_vulnerabilities)
        request = AuditRequest(
            task_id=task_id,
            source_path=str(upload_path),
            mode=mode,
            target_vulnerabilities=targets,
            need_verification=need_verification,
            need_repair=need_repair,
            background_risk_screening=background_risk_screening,
            background_screening_action=background_screening_action,
            output_dir=str(task_output_dir(task_id)),
        )
        create_task_record(task_id, request, source_kind="upload", upload_path=str(upload_path))
        if async_run:
            submit_audit(request)
            return task_response(task_id)
        run_task(request)
        return task_response(task_id)

    @app.get("/api/v1/audits")
    def list_audits() -> dict:
        load_existing_tasks()
        with _lock:
            items = sorted(_tasks.values(), key=lambda item: item.get("created_at", ""), reverse=True)
        return {"tasks": items}

    @app.get("/api/v1/audits/{task_id}")
    def get_audit_status(task_id: str) -> dict:
        ensure_task_loaded(task_id)
        return task_response(task_id)

    @app.get("/api/v1/audits/{task_id}/report")
    def get_audit_report(task_id: str) -> dict:
        ensure_task_loaded(task_id)
        record = get_record_or_404(task_id)
        if record.get("status") != "succeeded":
            raise HTTPException(status_code=409, detail=f"Task is {record.get('status')}, report is not ready.")
        report_path = task_output_dir(task_id) / f"{task_id}.json"
        if not report_path.exists():
            raise HTTPException(status_code=404, detail="JSON report not found.")
        return json.loads(report_path.read_text(encoding="utf-8"))

    @app.get("/api/v1/audits/{task_id}/report.json")
    def download_json_report(task_id: str):
        return download_report_file(task_id, "json")

    @app.get("/api/v1/audits/{task_id}/report.md")
    def download_markdown_report(task_id: str):
        return download_report_file(task_id, "md")

    @app.get("/api/v1/audits/{task_id}/artifacts")
    def list_artifacts(task_id: str) -> dict:
        ensure_task_loaded(task_id)
        output_dir = task_output_dir(task_id)
        if not output_dir.exists():
            return {"task_id": task_id, "artifacts": []}
        artifacts = [
            {
                "name": path.name,
                "path": str(path),
                "size": path.stat().st_size,
                "download_url": artifact_download_url(task_id, path.name),
            }
            for path in sorted(output_dir.iterdir())
            if path.is_file()
        ]
        return {"task_id": task_id, "artifacts": artifacts}

else:
    app = None


def submit_audit(request: AuditRequest) -> None:
    mark_task(request.task_id, status="queued", updated_at=utc_now())
    _executor.submit(run_task, request)


def run_task(request: AuditRequest) -> None:
    mark_task(request.task_id, status="running", started_at=utc_now(), updated_at=utc_now())
    output_dir = task_output_dir(request.task_id)
    output_dir.mkdir(parents=True, exist_ok=True)
    try:
        report = run_audit(request)
        json_path = output_dir / f"{request.task_id}.json"
        markdown_path = output_dir / f"{request.task_id}.md"
        json_path.write_text(json.dumps(asdict(report), ensure_ascii=False, indent=2), encoding="utf-8")
        write_markdown(report, markdown_path)
        mark_task(
            request.task_id,
            status="succeeded",
            finished_at=utc_now(),
            updated_at=utc_now(),
            report_json=str(json_path),
            report_markdown=str(markdown_path),
            summary={
                "findings": len(report.findings),
                "warnings": len(report.warnings),
                "functions": len(report.risk_vectors),
                "evidence_count": report.metadata.get("evidence_count"),
                "model_counts": report.metadata.get("evidence_center", {}).get("model_counts", {}),
            },
        )
    except Exception as exc:
        mark_task(
            request.task_id,
            status="failed",
            finished_at=utc_now(),
            updated_at=utc_now(),
            error=f"{type(exc).__name__}: {exc}",
            traceback=traceback.format_exc(),
        )


def create_task_record(task_id: str, request: AuditRequest, source_kind: str, **extra: Any) -> None:
    record = {
        "task_id": task_id,
        "status": "created",
        "created_at": utc_now(),
        "updated_at": utc_now(),
        "source_kind": source_kind,
        "request": asdict(request),
        "output_dir": str(task_output_dir(task_id)),
        **extra,
    }
    with _lock:
        _tasks[task_id] = record
    write_status(record)


def mark_task(task_id: str, **updates: Any) -> None:
    with _lock:
        record = _tasks.setdefault(task_id, {"task_id": task_id, "created_at": utc_now()})
        record.update(updates)
        snapshot = dict(record)
    write_status(snapshot)


def task_response(task_id: str) -> dict:
    record = get_record_or_404(task_id)
    response = dict(record)
    status = response.get("status")
    response["status_url"] = f"/api/v1/audits/{task_id}"
    response["artifacts_url"] = f"/api/v1/audits/{task_id}/artifacts"
    if status == "succeeded":
        response["report_url"] = f"/api/v1/audits/{task_id}/report"
        response["report_json_url"] = f"/api/v1/audits/{task_id}/report.json"
        response["report_markdown_url"] = f"/api/v1/audits/{task_id}/report.md"
    return response


def get_record_or_404(task_id: str) -> dict:
    with _lock:
        record = _tasks.get(task_id)
    if record is None:
        raise HTTPException(status_code=404, detail=f"Task not found: {task_id}")
    return record


def ensure_task_loaded(task_id: str) -> None:
    with _lock:
        if task_id in _tasks:
            return
    status_path = task_output_dir(task_id) / "status.json"
    if status_path.exists():
        record = json.loads(status_path.read_text(encoding="utf-8"))
        with _lock:
            _tasks[task_id] = record


def load_existing_tasks() -> None:
    if not API_OUTPUT_ROOT.exists():
        return
    for status_path in API_OUTPUT_ROOT.glob("*/status.json"):
        try:
            record = json.loads(status_path.read_text(encoding="utf-8"))
        except Exception:
            continue
        with _lock:
            _tasks.setdefault(record.get("task_id", status_path.parent.name), record)


def write_status(record: dict) -> None:
    output_dir = task_output_dir(record["task_id"])
    output_dir.mkdir(parents=True, exist_ok=True)
    (output_dir / "status.json").write_text(json.dumps(record, ensure_ascii=False, indent=2), encoding="utf-8")


def download_report_file(task_id: str, suffix: str):
    ensure_task_loaded(task_id)
    record = get_record_or_404(task_id)
    if record.get("status") != "succeeded":
        raise HTTPException(status_code=409, detail=f"Task is {record.get('status')}, report is not ready.")
    path = task_output_dir(task_id) / f"{task_id}.{suffix}"
    if not path.exists():
        raise HTTPException(status_code=404, detail=f"{suffix.upper()} report not found.")
    media_type = "application/json" if suffix == "json" else "text/markdown"
    return FileResponse(path, media_type=media_type, filename=path.name)


def artifact_download_url(task_id: str, filename: str) -> str | None:
    if filename == f"{task_id}.json":
        return f"/api/v1/audits/{task_id}/report.json"
    if filename == f"{task_id}.md":
        return f"/api/v1/audits/{task_id}/report.md"
    return None


def task_output_dir(task_id: str) -> Path:
    return API_OUTPUT_ROOT / safe_task_id(task_id)


def upload_task_dir(task_id: str) -> Path:
    return UPLOAD_ROOT / safe_task_id(task_id)


def new_task_id() -> str:
    return f"TASK-{datetime.now(timezone.utc).strftime('%Y%m%d-%H%M%S')}-{uuid.uuid4().hex[:8]}"


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def safe_task_id(task_id: str) -> str:
    cleaned = "".join(ch for ch in task_id if ch.isalnum() or ch in {"-", "_"})
    if not cleaned:
        raise ValueError("Invalid task id.")
    return cleaned[:120]


def safe_filename(filename: str) -> str:
    name = Path(filename).name
    cleaned = "".join(ch if ch.isalnum() or ch in {"-", "_", ".", " "} else "_" for ch in name)
    return cleaned.strip() or "source.sol"


def normalize_form_list(values: Optional[List[str]]) -> List[str]:
    if not values:
        return []
    result: List[str] = []
    for value in values:
        for item in str(value).split(","):
            stripped = item.strip()
            if stripped:
                result.append(stripped)
    return result

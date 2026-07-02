from __future__ import annotations

import json
import hashlib
import shutil
import traceback
import uuid
from concurrent.futures import Future, ThreadPoolExecutor
from dataclasses import asdict
from datetime import datetime, timezone
from pathlib import Path
from threading import Lock
from typing import Any, Dict, List, Optional

from backend.api.security import hash_password, hash_token, new_access_token, session_expires_at, verify_password
from backend.persistence import get_store
from backend.reporting.markdown_report import write_markdown
from backend.run_audit import run_audit
from backend.schemas import AuditRequest

try:
    from fastapi import Depends, FastAPI, File, Form, Header, HTTPException, UploadFile
    from fastapi.middleware.cors import CORSMiddleware
    from fastapi.responses import FileResponse
    from pydantic import BaseModel
except Exception:  # pragma: no cover - FastAPI is optional during backend scaffolding.
    Depends = FastAPI = File = Form = Header = HTTPException = UploadFile = None
    CORSMiddleware = None
    FileResponse = None
    BaseModel = object


API_OUTPUT_ROOT = Path("backend_outputs") / "api_tasks"
UPLOAD_ROOT = Path("backend_outputs") / "uploads"
MAX_WORKERS = 2
TERMINAL_STATUSES = {"succeeded", "failed", "cancelled", "interrupted"}
ACTIVE_STATUSES = {"created", "queued", "running", "cancelling"}
STATUS_PROGRESS = {
    "created": 0,
    "queued": 5,
    "running": 20,
    "cancelling": 80,
    "succeeded": 100,
    "failed": 100,
    "cancelled": 100,
    "interrupted": 100,
}

_executor = ThreadPoolExecutor(max_workers=MAX_WORKERS)
_lock = Lock()
_tasks: Dict[str, Dict[str, Any]] = {}
_futures: Dict[str, Future] = {}
_store = get_store()


def bearer_token(authorization: Optional[str]) -> Optional[str]:
    if not authorization:
        return None
    prefix = "Bearer "
    if not authorization.startswith(prefix):
        return None
    token = authorization[len(prefix) :].strip()
    return token or None


def optional_current_user(authorization: Optional[str] = Header(None) if Header is not None else None) -> Optional[dict]:
    token = bearer_token(authorization)
    if not token or _store is None:
        return None
    try:
        return _store.get_user_by_token_hash(hash_token(token))
    except Exception:
        return None


def require_current_user(authorization: Optional[str] = Header(None) if Header is not None else None) -> dict:
    user = optional_current_user(authorization)
    if user is None:
        raise HTTPException(status_code=401, detail="Authentication required.")
    return user


if FastAPI is not None:
    class RegisterRequest(BaseModel):
        username: str
        password: str
        display_name: Optional[str] = None

    class LoginRequest(BaseModel):
        username: str
        password: str

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

    @app.on_event("startup")
    def startup() -> None:
        try:
            init_persistence()
        except Exception:
            return

    @app.get("/api/v1/health")
    def health() -> dict:
        load_existing_tasks()
        with _lock:
            counts = status_counts(_tasks.values())
        return {
            "status": "ok",
            "time": utc_now(),
            "max_workers": MAX_WORKERS,
            "output_root": str(API_OUTPUT_ROOT.resolve()),
            "task_counts": counts,
            "database": database_status(),
        }

    @app.post("/api/v1/auth/register")
    def register(request: RegisterRequest) -> dict:
        store = require_store()
        username = request.username.strip()
        if len(username) < 3:
            raise HTTPException(status_code=400, detail="Username must be at least 3 characters.")
        if len(request.password) < 8:
            raise HTTPException(status_code=400, detail="Password must be at least 8 characters.")
        password_hash, salt, iterations = hash_password(request.password)
        try:
            user = store.create_user(username, password_hash, salt, iterations, request.display_name)
        except Exception as exc:
            if "unique" in str(exc).lower() or "duplicate" in str(exc).lower():
                raise HTTPException(status_code=409, detail="Username already exists.") from exc
            raise
        token = new_access_token()
        store.create_session(str(user["id"]), hash_token(token), session_expires_at())
        return {"user": public_user(user), "access_token": token, "token_type": "bearer"}

    @app.post("/api/v1/auth/login")
    def login(request: LoginRequest) -> dict:
        store = require_store()
        user = store.get_user_by_username(request.username.strip())
        if user is None or not verify_password(
            request.password,
            user["password_hash"],
            user["password_salt"],
            int(user["password_iterations"]),
        ):
            raise HTTPException(status_code=401, detail="Invalid username or password.")
        token = new_access_token()
        store.create_session(str(user["id"]), hash_token(token), session_expires_at())
        return {"user": public_user(user), "access_token": token, "token_type": "bearer"}

    @app.get("/api/v1/auth/me")
    def me(current_user: dict = Depends(require_current_user)) -> dict:
        return {"user": public_user(current_user)}

    @app.post("/api/v1/auth/logout")
    def logout(authorization: Optional[str] = Header(None)) -> dict:
        token = bearer_token(authorization)
        if token and _store is not None:
            _store.delete_session(hash_token(token))
        return {"status": "ok"}

    @app.post("/api/v1/audits")
    def create_audit(
        request: AuditRequest,
        async_run: bool = True,
        current_user: Optional[dict] = Depends(optional_current_user),
    ) -> dict:
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
        create_task_record(task_id, normalized, source_kind="path", user_id=user_id(current_user))
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
        current_user: Optional[dict] = Depends(optional_current_user),
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
        create_task_record(
            task_id,
            request,
            source_kind="upload",
            upload_path=str(upload_path),
            user_id=user_id(current_user),
            source_size=len(data),
            source_sha256=sha256_bytes(data),
        )
        if async_run:
            submit_audit(request)
            return task_response(task_id)
        run_task(request)
        return task_response(task_id)

    @app.get("/api/v1/audits")
    def list_audits(
        status: Optional[str] = None,
        limit: int = 50,
        offset: int = 0,
        current_user: Optional[dict] = Depends(optional_current_user),
    ) -> dict:
        load_existing_tasks()
        limit = max(1, min(limit, 200))
        offset = max(0, offset)
        with _lock:
            all_items = list(_tasks.values())
        current_user_id = user_id(current_user)
        if current_user_id:
            all_items = [item for item in all_items if item.get("user_id") == current_user_id]
        else:
            all_items = [item for item in all_items if not item.get("user_id")]
        if status:
            wanted = {item.strip() for item in status.split(",") if item.strip()}
            all_items = [item for item in all_items if item.get("status") in wanted]
        items = sorted(all_items, key=lambda item: item.get("created_at", ""), reverse=True)
        return {
            "tasks": [decorate_task_record(item) for item in items[offset : offset + limit]],
            "total": len(items),
            "limit": limit,
            "offset": offset,
            "status_counts": status_counts(all_items),
        }

    @app.post("/api/v1/audits/{task_id}/cancel")
    def cancel_audit(task_id: str, current_user: Optional[dict] = Depends(optional_current_user)) -> dict:
        ensure_task_loaded(task_id)
        check_task_access(get_record_or_404(task_id), current_user)
        return cancel_task(task_id)

    @app.post("/api/v1/audits/{task_id}/retry")
    def retry_audit(
        task_id: str,
        async_run: bool = True,
        current_user: Optional[dict] = Depends(optional_current_user),
    ) -> dict:
        ensure_task_loaded(task_id)
        old_record = get_record_or_404(task_id)
        check_task_access(old_record, current_user)
        old_status = old_record.get("status")
        if old_status not in TERMINAL_STATUSES:
            raise HTTPException(status_code=409, detail=f"Task is {old_status}, only terminal tasks can be retried.")
        request_data = dict(old_record.get("request") or {})
        if not request_data:
            raise HTTPException(status_code=409, detail="Original task request is missing, retry is unavailable.")
        new_id = new_task_id()
        request_data["task_id"] = new_id
        request_data["output_dir"] = str(task_output_dir(new_id))
        request = AuditRequest(**request_data)
        create_task_record(
            new_id,
            request,
            source_kind=old_record.get("source_kind", "path"),
            retried_from=task_id,
            upload_path=old_record.get("upload_path"),
            user_id=old_record.get("user_id"),
            source_size=old_record.get("source_size"),
            source_sha256=old_record.get("source_sha256"),
        )
        if async_run:
            submit_audit(request)
            return task_response(new_id)
        run_task(request)
        return task_response(new_id)

    @app.delete("/api/v1/audits/{task_id}")
    def delete_audit(
        task_id: str,
        delete_upload: bool = False,
        current_user: Optional[dict] = Depends(optional_current_user),
    ) -> dict:
        ensure_task_loaded(task_id)
        record = get_record_or_404(task_id)
        check_task_access(record, current_user)
        status = record.get("status")
        if status in ACTIVE_STATUSES:
            raise HTTPException(status_code=409, detail=f"Task is {status}, cancel it before deleting.")
        output_dir = task_output_dir(task_id)
        upload_path = Path(record["upload_path"]) if record.get("upload_path") else None
        with _lock:
            _tasks.pop(task_id, None)
            _futures.pop(task_id, None)
        delete_persisted_task(task_id)
        if output_dir.exists():
            shutil.rmtree(output_dir)
        if delete_upload and upload_path is not None:
            upload_dir = upload_task_dir(task_id)
            if upload_dir.exists():
                shutil.rmtree(upload_dir)
        return {
            "task_id": task_id,
            "status": "deleted",
            "deleted_output": str(output_dir),
            "deleted_upload": bool(delete_upload and upload_path is not None),
        }

    @app.get("/api/v1/audits/{task_id}")
    def get_audit_status(task_id: str, current_user: Optional[dict] = Depends(optional_current_user)) -> dict:
        ensure_task_loaded(task_id)
        check_task_access(get_record_or_404(task_id), current_user)
        return task_response(task_id)

    @app.get("/api/v1/audits/{task_id}/events")
    def get_audit_events(task_id: str, current_user: Optional[dict] = Depends(optional_current_user)) -> dict:
        ensure_task_loaded(task_id)
        record = get_record_or_404(task_id)
        check_task_access(record, current_user)
        return {"task_id": task_id, "events": record.get("events", [])}

    @app.get("/api/v1/audits/{task_id}/report")
    def get_audit_report(task_id: str, current_user: Optional[dict] = Depends(optional_current_user)) -> dict:
        ensure_task_loaded(task_id)
        record = get_record_or_404(task_id)
        check_task_access(record, current_user)
        if record.get("status") != "succeeded":
            raise HTTPException(status_code=409, detail=f"Task is {record.get('status')}, report is not ready.")
        report_path = task_output_dir(task_id) / f"{task_id}.json"
        if not report_path.exists():
            raise HTTPException(status_code=404, detail="JSON report not found.")
        return json.loads(report_path.read_text(encoding="utf-8"))

    @app.get("/api/v1/audits/{task_id}/report.json")
    def download_json_report(task_id: str, current_user: Optional[dict] = Depends(optional_current_user)):
        return download_report_file(task_id, "json", current_user)

    @app.get("/api/v1/audits/{task_id}/report.md")
    def download_markdown_report(task_id: str, current_user: Optional[dict] = Depends(optional_current_user)):
        return download_report_file(task_id, "md", current_user)

    @app.get("/api/v1/audits/{task_id}/artifacts")
    def list_artifacts(task_id: str, current_user: Optional[dict] = Depends(optional_current_user)) -> dict:
        ensure_task_loaded(task_id)
        check_task_access(get_record_or_404(task_id), current_user)
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
    future = _executor.submit(run_task, request)
    with _lock:
        _futures[request.task_id] = future
    future.add_done_callback(lambda _: remove_future(request.task_id))


def run_task(request: AuditRequest) -> None:
    if is_cancel_requested(request.task_id):
        mark_task(request.task_id, status="cancelled", finished_at=utc_now(), updated_at=utc_now())
        remove_future(request.task_id)
        return
    mark_task(request.task_id, status="running", started_at=utc_now(), updated_at=utc_now())
    output_dir = task_output_dir(request.task_id)
    output_dir.mkdir(parents=True, exist_ok=True)
    try:
        report = run_audit(request)
        json_path = output_dir / f"{request.task_id}.json"
        markdown_path = output_dir / f"{request.task_id}.md"
        json_path.write_text(json.dumps(asdict(report), ensure_ascii=False, indent=2), encoding="utf-8")
        write_markdown(report, markdown_path)
        summary = {
            "findings": len(report.findings),
            "warnings": len(report.warnings),
            "functions": len(report.risk_vectors),
            "evidence_count": report.metadata.get("evidence_count"),
            "model_counts": report.metadata.get("evidence_center", {}).get("model_counts", {}),
        }
        if is_cancel_requested(request.task_id):
            mark_task(
                request.task_id,
                status="cancelled",
                finished_at=utc_now(),
                updated_at=utc_now(),
                report_json=str(json_path),
                report_markdown=str(markdown_path),
            )
            return
        mark_task(
            request.task_id,
            status="succeeded",
            finished_at=utc_now(),
            updated_at=utc_now(),
            report_json=str(json_path),
            report_markdown=str(markdown_path),
            summary=summary,
        )
        persist_report_artifacts(request.task_id, asdict(report), json_path, markdown_path)
    except Exception as exc:
        if is_cancel_requested(request.task_id):
            mark_task(
                request.task_id,
                status="cancelled",
                finished_at=utc_now(),
                updated_at=utc_now(),
                error=f"{type(exc).__name__}: {exc}",
            )
        else:
            mark_task(
                request.task_id,
                status="failed",
                finished_at=utc_now(),
                updated_at=utc_now(),
                error=f"{type(exc).__name__}: {exc}",
                traceback=traceback.format_exc(),
            )
    finally:
        remove_future(request.task_id)


def create_task_record(task_id: str, request: AuditRequest, source_kind: str, **extra: Any) -> None:
    ensure_unique_task_id(task_id)
    record = {
        "task_id": task_id,
        "status": "created",
        "progress": STATUS_PROGRESS["created"],
        "created_at": utc_now(),
        "updated_at": utc_now(),
        "source_kind": source_kind,
        "request": asdict(request),
        "output_dir": str(task_output_dir(task_id)),
        "events": [],
        **extra,
    }
    append_event_to_record(record, "created", "Task record created.")
    with _lock:
        _tasks[task_id] = record
    write_status(record)


def mark_task(task_id: str, **updates: Any) -> None:
    with _lock:
        record = _tasks.setdefault(task_id, {"task_id": task_id, "created_at": utc_now()})
        old_status = record.get("status")
        new_status = updates.get("status")
        if new_status is not None:
            updates.setdefault("progress", STATUS_PROGRESS.get(new_status, record.get("progress", 0)))
        record.update(updates)
        if new_status is not None and new_status != old_status:
            append_event_to_record(record, new_status, f"Task status changed to {new_status}.")
        snapshot = dict(record)
    write_status(snapshot)


def task_response(task_id: str) -> dict:
    record = get_record_or_404(task_id)
    response = decorate_task_record(record)
    status = response.get("status")
    response["status_url"] = f"/api/v1/audits/{task_id}"
    response["artifacts_url"] = f"/api/v1/audits/{task_id}/artifacts"
    response["events_url"] = f"/api/v1/audits/{task_id}/events"
    response["cancel_url"] = f"/api/v1/audits/{task_id}/cancel"
    response["retry_url"] = f"/api/v1/audits/{task_id}/retry"
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
        record = normalize_loaded_record(record, task_id)
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
        task_id = record.get("task_id", status_path.parent.name)
        with _lock:
            if task_id in _tasks:
                continue
        record = normalize_loaded_record(record, task_id)
        with _lock:
            _tasks.setdefault(task_id, record)


def normalize_loaded_record(record: dict, task_id: str) -> dict:
    record.setdefault("task_id", task_id)
    record.setdefault("events", [])
    if record.get("status") in ACTIVE_STATUSES:
        record["status"] = "interrupted"
        record["finished_at"] = record.get("finished_at") or utc_now()
        record["updated_at"] = utc_now()
        record["progress"] = STATUS_PROGRESS["interrupted"]
        append_event_to_record(record, "interrupted", "Task was active when the API process stopped.")
        write_status(record)
    return record


def write_status(record: dict) -> None:
    output_dir = task_output_dir(record["task_id"])
    output_dir.mkdir(parents=True, exist_ok=True)
    (output_dir / "status.json").write_text(json.dumps(record, ensure_ascii=False, indent=2), encoding="utf-8")
    persist_task_record(record)


def cancel_task(task_id: str) -> dict:
    with _lock:
        record = _tasks.get(task_id)
        if record is None:
            raise HTTPException(status_code=404, detail=f"Task not found: {task_id}")
        status = record.get("status")
        future = _futures.get(task_id)
    if status in TERMINAL_STATUSES:
        return task_response(task_id)
    if future is not None and future.cancel():
        mark_task(task_id, status="cancelled", cancel_requested=True, finished_at=utc_now(), updated_at=utc_now())
        remove_future(task_id)
        return task_response(task_id)
    if status in {"created", "queued"} and future is None:
        mark_task(task_id, status="cancelled", cancel_requested=True, finished_at=utc_now(), updated_at=utc_now())
        return task_response(task_id)
    mark_task(task_id, status="cancelling", cancel_requested=True, updated_at=utc_now())
    return task_response(task_id)


def remove_future(task_id: str) -> None:
    with _lock:
        _futures.pop(task_id, None)


def is_cancel_requested(task_id: str) -> bool:
    with _lock:
        record = _tasks.get(task_id) or {}
        return bool(record.get("cancel_requested"))


def ensure_unique_task_id(task_id: str) -> None:
    ensure_task_loaded(task_id)
    with _lock:
        existing = _tasks.get(task_id)
    if existing is not None:
        raise HTTPException(status_code=409, detail=f"Task already exists: {task_id}")


def append_event_to_record(record: dict, event_type: str, message: str) -> None:
    events = record.setdefault("events", [])
    events.append(
        {
            "time": utc_now(),
            "type": event_type,
            "message": message,
        }
    )
    if len(events) > 200:
        del events[:-200]


def decorate_task_record(record: dict) -> dict:
    response = dict(record)
    status = response.get("status")
    response.setdefault("progress", STATUS_PROGRESS.get(status, 0))
    response["can_cancel"] = status in {"created", "queued", "running", "cancelling"}
    response["can_retry"] = status in TERMINAL_STATUSES
    response["can_delete"] = status in TERMINAL_STATUSES
    return response


def status_counts(records) -> dict:
    counts: Dict[str, int] = {}
    for record in records:
        status = record.get("status", "unknown")
        counts[status] = counts.get(status, 0) + 1
    return counts


def init_persistence() -> None:
    if _store is None:
        return
    _store.init_schema()


def database_status() -> dict:
    if _store is None:
        return {"configured": False, "ready": False}
    try:
        init_persistence()
    except Exception as exc:
        return {"configured": True, "ready": False, "error": f"{type(exc).__name__}: {exc}"}
    return {"configured": True, "ready": True}


def require_store():
    if _store is None:
        raise HTTPException(status_code=503, detail="Database is not configured. Set SCG_DATABASE_URL.")
    try:
        init_persistence()
    except Exception as exc:
        raise HTTPException(status_code=503, detail=f"Database is not ready: {type(exc).__name__}: {exc}") from exc
    return _store


def public_user(user: dict) -> dict:
    return {
        "id": str(user.get("id")),
        "username": user.get("username"),
        "display_name": user.get("display_name"),
        "created_at": str(user.get("created_at")) if user.get("created_at") is not None else None,
        "updated_at": str(user.get("updated_at")) if user.get("updated_at") is not None else None,
    }


def user_id(user: Optional[dict]) -> Optional[str]:
    return str(user["id"]) if user and user.get("id") else None


def check_task_access(record: dict, current_user: Optional[dict]) -> None:
    owner_id = record.get("user_id")
    if not owner_id:
        return
    current_user_id = user_id(current_user)
    if current_user_id is None:
        raise HTTPException(status_code=401, detail="Authentication required for this task.")
    if current_user_id != owner_id:
        raise HTTPException(status_code=403, detail="You do not have access to this task.")


def persist_task_record(record: dict) -> None:
    if _store is None:
        return
    try:
        _store.upsert_task(dict(record))
    except Exception as exc:
        record["persistence_error"] = f"{type(exc).__name__}: {exc}"


def persist_report_artifacts(task_id: str, report_json: dict, json_path: Path, markdown_path: Path) -> None:
    if _store is None:
        return
    with _lock:
        record = dict(_tasks.get(task_id) or {})
    try:
        markdown_text = markdown_path.read_text(encoding="utf-8") if markdown_path.exists() else None
        _store.upsert_report(
            task_id=task_id,
            user_id=record.get("user_id"),
            report_json=report_json,
            report_markdown=markdown_text,
            report_json_path=str(json_path),
            report_markdown_path=str(markdown_path),
            summary=record.get("summary"),
        )
        for path in [json_path, markdown_path]:
            if path.exists():
                _store.upsert_artifact(
                    task_id=task_id,
                    name=path.name,
                    path=str(path),
                    size=path.stat().st_size,
                    artifact_type=path.suffix.lstrip(".") or "file",
                    download_url=artifact_download_url(task_id, path.name) or "",
                )
    except Exception as exc:
        mark_task(task_id, persistence_error=f"{type(exc).__name__}: {exc}", updated_at=utc_now())


def delete_persisted_task(task_id: str) -> None:
    if _store is None:
        return
    try:
        _store.delete_task(task_id)
    except Exception:
        return


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def download_report_file(task_id: str, suffix: str, current_user: Optional[dict] = None):
    ensure_task_loaded(task_id)
    record = get_record_or_404(task_id)
    check_task_access(record, current_user)
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

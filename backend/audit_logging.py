from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from time import perf_counter
from typing import Any


class AuditLogger:
    def __init__(self, task_id: str, output_dir: str | Path | None = None) -> None:
        self.task_id = task_id
        base_dir = Path(output_dir) if output_dir else Path("backend_outputs") / "api_tasks" / task_id
        self.path = base_dir / "audit.log"
        self.path.parent.mkdir(parents=True, exist_ok=True)

    def event(self, event: str, message: str, **fields: Any) -> None:
        payload = {
            "time": datetime.now(timezone.utc).isoformat(),
            "task_id": self.task_id,
            "event": event,
            "message": message,
            **sanitize_log_fields(fields),
        }
        with self.path.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(payload, ensure_ascii=False, default=str) + "\n")

    def phase_start(self, phase: str, label: str) -> float:
        started = perf_counter()
        self.event("phase_start", f"Start phase: {label}", phase=phase, label=label)
        return started

    def phase_end(self, phase: str, label: str, started: float) -> None:
        self.event(
            "phase_end",
            f"Finish phase: {label}",
            phase=phase,
            label=label,
            seconds=round(perf_counter() - started, 4),
        )

    def exception(self, event: str, exc: BaseException, **fields: Any) -> None:
        self.event(
            event,
            f"{type(exc).__name__}: {exc}",
            error_type=type(exc).__name__,
            error=str(exc),
            **fields,
        )


class NullAuditLogger:
    def event(self, event: str, message: str, **fields: Any) -> None:
        return

    def phase_start(self, phase: str, label: str) -> float:
        return perf_counter()

    def phase_end(self, phase: str, label: str, started: float) -> None:
        return

    def exception(self, event: str, exc: BaseException, **fields: Any) -> None:
        return


def build_audit_logger(task_id: str, output_dir: str | Path | None = None) -> AuditLogger:
    return AuditLogger(task_id, output_dir)


def sanitize_log_fields(fields: dict[str, Any]) -> dict[str, Any]:
    sensitive_tokens = ("api_key", "apikey", "secret", "token", "password", "authorization")
    sanitized: dict[str, Any] = {}
    for key, value in fields.items():
        if any(token in key.lower() for token in sensitive_tokens):
            sanitized[key] = "***"
        elif isinstance(value, dict):
            sanitized[key] = sanitize_log_fields(value)
        elif isinstance(value, list):
            sanitized[key] = [sanitize_log_value(item, sensitive_tokens) for item in value]
        else:
            sanitized[key] = value
    return sanitized


def sanitize_log_value(value: Any, sensitive_tokens: tuple[str, ...]) -> Any:
    if isinstance(value, dict):
        return sanitize_log_fields(value)
    if isinstance(value, list):
        return [sanitize_log_value(item, sensitive_tokens) for item in value]
    return value

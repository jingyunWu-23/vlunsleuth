from __future__ import annotations

import os
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, Optional

try:
    import psycopg
    from psycopg.rows import dict_row
    from psycopg.types.json import Jsonb
except Exception:  # pragma: no cover - optional until PostgreSQL/Supabase is configured.
    psycopg = None
    dict_row = None
    Jsonb = None


class SupabaseStore:
    """PostgreSQL storage layer compatible with Supabase connection strings."""

    def __init__(self, database_url: str) -> None:
        self.database_url = database_url

    def available(self) -> bool:
        return bool(self.database_url and psycopg is not None)

    def init_schema(self) -> None:
        self._require_driver()
        statements = [
            """
            create table if not exists scg_users (
                id uuid primary key,
                username text not null unique,
                display_name text,
                password_hash text not null,
                password_salt text not null,
                password_iterations integer not null,
                created_at timestamptz not null,
                updated_at timestamptz not null
            )
            """,
            """
            create table if not exists scg_sessions (
                id uuid primary key,
                user_id uuid not null references scg_users(id) on delete cascade,
                token_hash text not null unique,
                expires_at timestamptz not null,
                created_at timestamptz not null
            )
            """,
            """
            create table if not exists scg_contracts (
                id uuid primary key,
                task_id text unique,
                user_id uuid references scg_users(id) on delete set null,
                source_kind text,
                filename text,
                source_path text,
                sha256 text,
                size_bytes bigint,
                created_at timestamptz not null
            )
            """,
            """
            create table if not exists scg_audit_tasks (
                task_id text primary key,
                user_id uuid references scg_users(id) on delete set null,
                contract_id uuid references scg_contracts(id) on delete set null,
                status text not null,
                progress integer,
                source_kind text,
                request jsonb,
                summary jsonb,
                error text,
                traceback text,
                output_dir text,
                upload_path text,
                report_json_path text,
                report_markdown_path text,
                retried_from text,
                cancel_requested boolean,
                created_at timestamptz,
                started_at timestamptz,
                updated_at timestamptz,
                finished_at timestamptz,
                record jsonb not null
            )
            """,
            """
            create table if not exists scg_audit_events (
                id bigserial primary key,
                task_id text not null references scg_audit_tasks(task_id) on delete cascade,
                event_time timestamptz not null,
                event_type text not null,
                message text not null,
                payload jsonb,
                unique(task_id, event_time, event_type)
            )
            """,
            """
            create table if not exists scg_audit_reports (
                id uuid primary key,
                task_id text not null unique references scg_audit_tasks(task_id) on delete cascade,
                user_id uuid references scg_users(id) on delete set null,
                report_json jsonb not null,
                report_markdown text,
                report_json_path text,
                report_markdown_path text,
                summary jsonb,
                created_at timestamptz not null
            )
            """,
            """
            create table if not exists scg_audit_artifacts (
                id uuid primary key,
                task_id text not null references scg_audit_tasks(task_id) on delete cascade,
                name text not null,
                path text not null,
                size_bytes bigint,
                artifact_type text,
                download_url text,
                created_at timestamptz not null,
                unique(task_id, path)
            )
            """,
            "create index if not exists idx_scg_tasks_user_created on scg_audit_tasks(user_id, created_at desc)",
            "create index if not exists idx_scg_tasks_status_created on scg_audit_tasks(status, created_at desc)",
            "create index if not exists idx_scg_reports_task on scg_audit_reports(task_id)",
        ]
        with self._connect() as conn:
            with conn.cursor() as cur:
                for statement in statements:
                    cur.execute(statement)

    def create_user(
        self,
        username: str,
        password_hash: str,
        password_salt: str,
        password_iterations: int,
        display_name: Optional[str] = None,
    ) -> Dict[str, Any]:
        now = utc_now()
        user_id = str(uuid.uuid4())
        with self._connect() as conn:
            with conn.cursor(row_factory=dict_row) as cur:
                cur.execute(
                    """
                    insert into scg_users (
                        id, username, display_name, password_hash, password_salt,
                        password_iterations, created_at, updated_at
                    )
                    values (%s, %s, %s, %s, %s, %s, %s, %s)
                    returning id, username, display_name, created_at, updated_at
                    """,
                    (
                        user_id,
                        username,
                        display_name,
                        password_hash,
                        password_salt,
                        password_iterations,
                        now,
                        now,
                    ),
                )
                return dict(cur.fetchone())

    def get_user_by_username(self, username: str) -> Optional[Dict[str, Any]]:
        with self._connect() as conn:
            with conn.cursor(row_factory=dict_row) as cur:
                cur.execute("select * from scg_users where username = %s", (username,))
                row = cur.fetchone()
                return dict(row) if row else None

    def get_user_by_id(self, user_id: str) -> Optional[Dict[str, Any]]:
        with self._connect() as conn:
            with conn.cursor(row_factory=dict_row) as cur:
                cur.execute(
                    "select id, username, display_name, created_at, updated_at from scg_users where id = %s",
                    (user_id,),
                )
                row = cur.fetchone()
                return dict(row) if row else None

    def create_session(self, user_id: str, token_hash: str, expires_at: str) -> Dict[str, Any]:
        session_id = str(uuid.uuid4())
        now = utc_now()
        with self._connect() as conn:
            with conn.cursor(row_factory=dict_row) as cur:
                cur.execute(
                    """
                    insert into scg_sessions (id, user_id, token_hash, expires_at, created_at)
                    values (%s, %s, %s, %s, %s)
                    returning id, user_id, expires_at, created_at
                    """,
                    (session_id, user_id, token_hash, expires_at, now),
                )
                return dict(cur.fetchone())

    def get_user_by_token_hash(self, token_hash: str) -> Optional[Dict[str, Any]]:
        with self._connect() as conn:
            with conn.cursor(row_factory=dict_row) as cur:
                cur.execute(
                    """
                    select u.id, u.username, u.display_name, u.created_at, u.updated_at
                    from scg_sessions s
                    join scg_users u on u.id = s.user_id
                    where s.token_hash = %s and s.expires_at > %s
                    """,
                    (token_hash, utc_now()),
                )
                row = cur.fetchone()
                return dict(row) if row else None

    def delete_session(self, token_hash: str) -> None:
        with self._connect() as conn:
            with conn.cursor() as cur:
                cur.execute("delete from scg_sessions where token_hash = %s", (token_hash,))

    def upsert_contract_from_task(self, record: Dict[str, Any]) -> Optional[str]:
        source_path = record.get("upload_path") or (record.get("request") or {}).get("source_path")
        if not source_path:
            return None
        path = Path(source_path)
        contract_id = record.get("contract_id") or str(uuid.uuid4())
        with self._connect() as conn:
            with conn.cursor(row_factory=dict_row) as cur:
                cur.execute(
                    """
                    insert into scg_contracts (
                        id, task_id, user_id, source_kind, filename, source_path,
                        sha256, size_bytes, created_at
                    )
                    values (%s, %s, %s, %s, %s, %s, %s, %s, %s)
                    on conflict (task_id) do update set
                        user_id = excluded.user_id,
                        source_kind = excluded.source_kind,
                        filename = excluded.filename,
                        source_path = excluded.source_path,
                        sha256 = excluded.sha256,
                        size_bytes = excluded.size_bytes
                    returning id
                    """,
                    (
                        contract_id,
                        record.get("task_id"),
                        record.get("user_id"),
                        record.get("source_kind"),
                        path.name,
                        source_path,
                        record.get("source_sha256"),
                        record.get("source_size"),
                        record.get("created_at") or utc_now(),
                    ),
                )
                row = cur.fetchone()
                return str(row["id"]) if row else None

    def upsert_task(self, record: Dict[str, Any]) -> None:
        contract_id = record.get("contract_id") or self.upsert_contract_from_task(record)
        if contract_id:
            record["contract_id"] = contract_id
        with self._connect() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    insert into scg_audit_tasks (
                        task_id, user_id, contract_id, status, progress, source_kind,
                        request, summary, error, traceback, output_dir, upload_path,
                        report_json_path, report_markdown_path, retried_from,
                        cancel_requested, created_at, started_at, updated_at, finished_at,
                        record
                    )
                    values (
                        %s, %s, %s, %s, %s, %s,
                        %s, %s, %s, %s, %s, %s,
                        %s, %s, %s, %s, %s, %s, %s, %s,
                        %s
                    )
                    on conflict (task_id) do update set
                        user_id = excluded.user_id,
                        contract_id = excluded.contract_id,
                        status = excluded.status,
                        progress = excluded.progress,
                        source_kind = excluded.source_kind,
                        request = excluded.request,
                        summary = excluded.summary,
                        error = excluded.error,
                        traceback = excluded.traceback,
                        output_dir = excluded.output_dir,
                        upload_path = excluded.upload_path,
                        report_json_path = excluded.report_json_path,
                        report_markdown_path = excluded.report_markdown_path,
                        retried_from = excluded.retried_from,
                        cancel_requested = excluded.cancel_requested,
                        started_at = excluded.started_at,
                        updated_at = excluded.updated_at,
                        finished_at = excluded.finished_at,
                        record = excluded.record
                    """,
                    (
                        record["task_id"],
                        record.get("user_id"),
                        contract_id,
                        record.get("status"),
                        record.get("progress"),
                        record.get("source_kind"),
                        Jsonb(record.get("request")),
                        Jsonb(record.get("summary")),
                        record.get("error"),
                        record.get("traceback"),
                        record.get("output_dir"),
                        record.get("upload_path"),
                        record.get("report_json"),
                        record.get("report_markdown"),
                        record.get("retried_from"),
                        bool(record.get("cancel_requested")),
                        record.get("created_at"),
                        record.get("started_at"),
                        record.get("updated_at"),
                        record.get("finished_at"),
                        Jsonb(record),
                    ),
                )
        self.sync_task_events(record["task_id"], record.get("events", []))

    def sync_task_events(self, task_id: str, events: Iterable[Dict[str, Any]]) -> None:
        with self._connect() as conn:
            with conn.cursor() as cur:
                for event in events:
                    cur.execute(
                        """
                        insert into scg_audit_events (task_id, event_time, event_type, message, payload)
                        values (%s, %s, %s, %s, %s)
                        on conflict (task_id, event_time, event_type) do nothing
                        """,
                        (
                            task_id,
                            event.get("time") or utc_now(),
                            event.get("type") or "event",
                            event.get("message") or "",
                            Jsonb(event),
                        ),
                    )

    def upsert_report(
        self,
        task_id: str,
        user_id: Optional[str],
        report_json: Dict[str, Any],
        report_markdown: Optional[str],
        report_json_path: str,
        report_markdown_path: str,
        summary: Optional[Dict[str, Any]],
    ) -> None:
        report_id = str(uuid.uuid4())
        with self._connect() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    insert into scg_audit_reports (
                        id, task_id, user_id, report_json, report_markdown,
                        report_json_path, report_markdown_path, summary, created_at
                    )
                    values (%s, %s, %s, %s, %s, %s, %s, %s, %s)
                    on conflict (task_id) do update set
                        user_id = excluded.user_id,
                        report_json = excluded.report_json,
                        report_markdown = excluded.report_markdown,
                        report_json_path = excluded.report_json_path,
                        report_markdown_path = excluded.report_markdown_path,
                        summary = excluded.summary
                    """,
                    (
                        report_id,
                        task_id,
                        user_id,
                        Jsonb(report_json),
                        report_markdown,
                        report_json_path,
                        report_markdown_path,
                        Jsonb(summary),
                        utc_now(),
                    ),
                )

    def upsert_artifact(self, task_id: str, name: str, path: str, size: int, artifact_type: str, download_url: str) -> None:
        artifact_id = str(uuid.uuid4())
        with self._connect() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    insert into scg_audit_artifacts (
                        id, task_id, name, path, size_bytes, artifact_type, download_url, created_at
                    )
                    values (%s, %s, %s, %s, %s, %s, %s, %s)
                    on conflict (task_id, path) do update set
                        name = excluded.name,
                        size_bytes = excluded.size_bytes,
                        artifact_type = excluded.artifact_type,
                        download_url = excluded.download_url
                    """,
                    (artifact_id, task_id, name, path, size, artifact_type, download_url, utc_now()),
                )

    def delete_task(self, task_id: str) -> None:
        with self._connect() as conn:
            with conn.cursor() as cur:
                cur.execute("delete from scg_audit_tasks where task_id = %s", (task_id,))

    def _connect(self):
        self._require_driver()
        return psycopg.connect(self.database_url)

    def _require_driver(self) -> None:
        if not self.database_url:
            raise RuntimeError("SCG_DATABASE_URL is not configured.")
        if psycopg is None:
            raise RuntimeError("psycopg is not installed. Install requirements-backend.txt first.")


def get_store() -> Optional[SupabaseStore]:
    database_url = os.getenv("SCG_DATABASE_URL") or os.getenv("SUPABASE_DB_URL")
    if not database_url:
        return None
    return SupabaseStore(database_url)


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()

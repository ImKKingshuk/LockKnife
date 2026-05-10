from __future__ import annotations

import dataclasses
import datetime as dt
import hashlib
import json
import pathlib
import re
import sqlite3
from collections.abc import Iterator, Mapping
from contextlib import contextmanager
from typing import Any

from lockknife.core._case_models import (
    CaseArtifact,
    CaseJob,
    CaseJobStep,
    CaseManifest,
    CaseRuntimeScript,
    CaseRuntimeSession,
)
from lockknife.core.serialize import write_json

STORE_FILENAME = "case_store.sqlite3"
STORE_SCHEMA_VERSION = 1


@dataclasses.dataclass(frozen=True)
class EventRecord:
    event_id: int
    aggregate_type: str
    aggregate_id: str
    event_type: str
    timestamp_utc: str
    actor: str
    payload: dict[str, Any]
    previous_hash: str | None
    event_hash: str


def _utc_now() -> str:
    return dt.datetime.now(dt.UTC).isoformat()


def _json_dump(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), default=str)


def _json_load(value: str | None, default: Any) -> Any:
    if not value:
        return default
    return json.loads(value)


def _event_hash(payload: Mapping[str, Any]) -> str:
    return hashlib.sha256(_json_dump(payload).encode("utf-8")).hexdigest()


def _manifest_path(case_dir: pathlib.Path) -> pathlib.Path:
    return case_dir / "case_manifest.json"


def _store_path(case_dir: pathlib.Path) -> pathlib.Path:
    return case_dir / STORE_FILENAME


def _max_sequence(ids: list[str], prefix: str) -> int:
    pattern = re.compile(rf"^{re.escape(prefix)}-(\d+)$")
    max_value = 0
    for value in ids:
        match = pattern.match(value)
        if match is not None:
            max_value = max(max_value, int(match.group(1)))
    return max_value


def _manifest_from_json(path: pathlib.Path) -> CaseManifest:
    raw = json.loads(path.read_text(encoding="utf-8"))
    artifacts = [CaseArtifact(**item) for item in raw.pop("artifacts", [])]
    jobs = []
    for item in raw.pop("jobs", []):
        steps = [CaseJobStep(**step) for step in item.pop("steps", [])]
        jobs.append(CaseJob(steps=steps, **item))
    runtime_sessions = []
    for item in raw.pop("runtime_sessions", []):
        script_inventory = [
            CaseRuntimeScript(**script) for script in item.pop("script_inventory", [])
        ]
        runtime_sessions.append(CaseRuntimeSession(script_inventory=script_inventory, **item))
    raw.setdefault("schema_version", 2)
    return CaseManifest(artifacts=artifacts, jobs=jobs, runtime_sessions=runtime_sessions, **raw)


class CaseStore:
    def __init__(self, case_dir: pathlib.Path) -> None:
        self.case_dir = case_dir
        self.path = _store_path(case_dir)

    @classmethod
    def exists(cls, case_dir: pathlib.Path) -> bool:
        return _store_path(case_dir).exists()

    @classmethod
    def open(cls, case_dir: pathlib.Path) -> CaseStore:
        case_dir.mkdir(parents=True, exist_ok=True)
        store = cls(case_dir)
        is_new = not store.path.exists()
        store._initialize_schema()
        if is_new and _manifest_path(case_dir).exists():
            store.replace_from_manifest(
                _manifest_from_json(_manifest_path(case_dir)), event_type="case.migrated"
            )
        return store

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.path, timeout=5.0)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA foreign_keys=ON")
        conn.execute("PRAGMA busy_timeout=5000")
        return conn

    @contextmanager
    def transaction(self) -> Iterator[sqlite3.Connection]:
        conn = self._connect()
        try:
            conn.execute("BEGIN IMMEDIATE")
            yield conn
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        finally:
            conn.close()

    def _initialize_schema(self) -> None:
        with self._connect() as conn:
            conn.executescript(
                """
                CREATE TABLE IF NOT EXISTS store_meta (
                    key TEXT PRIMARY KEY,
                    value TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS cases (
                    case_id TEXT PRIMARY KEY,
                    title TEXT NOT NULL,
                    examiner TEXT NOT NULL,
                    notes TEXT,
                    created_at_utc TEXT NOT NULL,
                    updated_at_utc TEXT NOT NULL,
                    workspace_root TEXT NOT NULL,
                    target_serials_json TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS id_counters (
                    kind TEXT PRIMARY KEY,
                    next_value INTEGER NOT NULL
                );
                CREATE TABLE IF NOT EXISTS artifacts (
                    artifact_id TEXT PRIMARY KEY,
                    path TEXT NOT NULL,
                    category TEXT NOT NULL,
                    source_command TEXT NOT NULL,
                    sha256 TEXT NOT NULL,
                    size_bytes INTEGER NOT NULL,
                    created_at_utc TEXT NOT NULL,
                    device_serial TEXT,
                    input_paths_json TEXT NOT NULL,
                    parent_artifact_ids_json TEXT NOT NULL,
                    metadata_json TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS jobs (
                    job_id TEXT PRIMARY KEY,
                    action_id TEXT NOT NULL,
                    action_label TEXT NOT NULL,
                    workflow_kind TEXT NOT NULL,
                    status TEXT NOT NULL,
                    resumable INTEGER NOT NULL,
                    created_at_utc TEXT NOT NULL,
                    updated_at_utc TEXT NOT NULL,
                    started_at_utc TEXT NOT NULL,
                    ended_at_utc TEXT,
                    device_serial TEXT,
                    attempt_count INTEGER NOT NULL,
                    params_json TEXT NOT NULL,
                    latest_message TEXT,
                    error_message TEXT,
                    recovery_hint TEXT,
                    logs_path TEXT,
                    result_artifact_ids_json TEXT NOT NULL,
                    steps_json TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS runtime_sessions (
                    session_id TEXT PRIMARY KEY,
                    name TEXT NOT NULL,
                    app_id TEXT NOT NULL,
                    session_kind TEXT NOT NULL,
                    attach_mode TEXT NOT NULL,
                    status TEXT NOT NULL,
                    created_at_utc TEXT NOT NULL,
                    updated_at_utc TEXT NOT NULL,
                    started_at_utc TEXT NOT NULL,
                    last_connected_at_utc TEXT,
                    ended_at_utc TEXT,
                    device_id TEXT,
                    pid INTEGER,
                    connect_count INTEGER NOT NULL,
                    reload_count INTEGER NOT NULL,
                    event_count INTEGER NOT NULL,
                    last_event_at_utc TEXT,
                    active_script_id TEXT,
                    logs_path TEXT,
                    summary_path TEXT,
                    latest_message TEXT,
                    error_message TEXT,
                    recovery_hint TEXT,
                    result_artifact_ids_json TEXT NOT NULL,
                    script_inventory_json TEXT NOT NULL,
                    metadata_json TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS events (
                    event_id INTEGER PRIMARY KEY AUTOINCREMENT,
                    aggregate_type TEXT NOT NULL,
                    aggregate_id TEXT NOT NULL,
                    event_type TEXT NOT NULL,
                    timestamp_utc TEXT NOT NULL,
                    actor TEXT NOT NULL,
                    payload_json TEXT NOT NULL,
                    previous_hash TEXT,
                    event_hash TEXT NOT NULL
                );
                """
            )
            conn.execute(
                "INSERT OR REPLACE INTO store_meta(key, value) VALUES('schema_version', ?)",
                (str(STORE_SCHEMA_VERSION),),
            )

    def replace_from_manifest(
        self, manifest: CaseManifest, *, event_type: str = "case.snapshot"
    ) -> None:
        payload = dataclasses.asdict(manifest)
        with self.transaction() as conn:
            conn.execute("DELETE FROM cases")
            conn.execute("DELETE FROM artifacts")
            conn.execute("DELETE FROM jobs")
            conn.execute("DELETE FROM runtime_sessions")
            conn.execute(
                """
                INSERT INTO cases(
                    case_id, title, examiner, notes, created_at_utc, updated_at_utc,
                    workspace_root, target_serials_json
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    manifest.case_id,
                    manifest.title,
                    manifest.examiner,
                    manifest.notes,
                    manifest.created_at_utc,
                    manifest.updated_at_utc,
                    manifest.workspace_root,
                    _json_dump(manifest.target_serials),
                ),
            )
            for artifact in manifest.artifacts:
                conn.execute(
                    """
                    INSERT INTO artifacts VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        artifact.artifact_id,
                        artifact.path,
                        artifact.category,
                        artifact.source_command,
                        artifact.sha256,
                        artifact.size_bytes,
                        artifact.created_at_utc,
                        artifact.device_serial,
                        _json_dump(artifact.input_paths),
                        _json_dump(artifact.parent_artifact_ids),
                        _json_dump(artifact.metadata),
                    ),
                )
            for job in manifest.jobs:
                conn.execute(
                    """
                    INSERT INTO jobs VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        job.job_id,
                        job.action_id,
                        job.action_label,
                        job.workflow_kind,
                        job.status,
                        int(job.resumable),
                        job.created_at_utc,
                        job.updated_at_utc,
                        job.started_at_utc,
                        job.ended_at_utc,
                        job.device_serial,
                        job.attempt_count,
                        _json_dump(job.params),
                        job.latest_message,
                        job.error_message,
                        job.recovery_hint,
                        job.logs_path,
                        _json_dump(job.result_artifact_ids),
                        _json_dump([dataclasses.asdict(step) for step in job.steps]),
                    ),
                )
            for session in manifest.runtime_sessions:
                conn.execute(
                    """
                    INSERT INTO runtime_sessions VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        session.session_id,
                        session.name,
                        session.app_id,
                        session.session_kind,
                        session.attach_mode,
                        session.status,
                        session.created_at_utc,
                        session.updated_at_utc,
                        session.started_at_utc,
                        session.last_connected_at_utc,
                        session.ended_at_utc,
                        session.device_id,
                        session.pid,
                        session.connect_count,
                        session.reload_count,
                        session.event_count,
                        session.last_event_at_utc,
                        session.active_script_id,
                        session.logs_path,
                        session.summary_path,
                        session.latest_message,
                        session.error_message,
                        session.recovery_hint,
                        _json_dump(session.result_artifact_ids),
                        _json_dump(
                            [dataclasses.asdict(script) for script in session.script_inventory]
                        ),
                        _json_dump(session.metadata),
                    ),
                )
            self._sync_counters(conn, manifest)
            self._append_event_in_tx(
                conn,
                aggregate_type="case",
                aggregate_id=manifest.case_id,
                event_type=event_type,
                actor=manifest.examiner or "system",
                payload={"manifest": payload},
            )
        self.write_manifest_snapshot()

    def write_manifest_snapshot(self) -> pathlib.Path:
        manifest = self.load_manifest()
        path = _manifest_path(self.case_dir)
        write_json(path, dataclasses.asdict(manifest))
        return path

    def _touch_case_in_tx(
        self, conn: sqlite3.Connection, *, updated_at_utc: str
    ) -> tuple[str, str]:
        row = conn.execute("SELECT case_id, examiner FROM cases LIMIT 1").fetchone()
        if row is None:
            raise FileNotFoundError(f"No case metadata in {self.path}")
        conn.execute(
            "UPDATE cases SET updated_at_utc = ? WHERE case_id = ?",
            (updated_at_utc, row["case_id"]),
        )
        return str(row["case_id"]), str(row["examiner"] or "system")

    def _insert_artifact_in_tx(self, conn: sqlite3.Connection, artifact: CaseArtifact) -> None:
        conn.execute(
            """
            INSERT INTO artifacts VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(artifact_id) DO UPDATE SET
                path = excluded.path,
                category = excluded.category,
                source_command = excluded.source_command,
                sha256 = excluded.sha256,
                size_bytes = excluded.size_bytes,
                created_at_utc = excluded.created_at_utc,
                device_serial = excluded.device_serial,
                input_paths_json = excluded.input_paths_json,
                parent_artifact_ids_json = excluded.parent_artifact_ids_json,
                metadata_json = excluded.metadata_json
            """,
            (
                artifact.artifact_id,
                artifact.path,
                artifact.category,
                artifact.source_command,
                artifact.sha256,
                artifact.size_bytes,
                artifact.created_at_utc,
                artifact.device_serial,
                _json_dump(artifact.input_paths),
                _json_dump(artifact.parent_artifact_ids),
                _json_dump(artifact.metadata),
            ),
        )

    def persist_artifact(
        self,
        artifact: CaseArtifact,
        *,
        case_updated_at_utc: str,
        event_type: str,
        actor: str | None = None,
    ) -> CaseArtifact:
        with self.transaction() as conn:
            case_id, case_actor = self._touch_case_in_tx(conn, updated_at_utc=case_updated_at_utc)
            self._insert_artifact_in_tx(conn, artifact)
            self._append_event_in_tx(
                conn,
                aggregate_type="artifact",
                aggregate_id=artifact.artifact_id,
                event_type=event_type,
                actor=actor or case_actor,
                payload={"case_id": case_id, "artifact": dataclasses.asdict(artifact)},
            )
        self.write_manifest_snapshot()
        return artifact

    def _insert_job_in_tx(self, conn: sqlite3.Connection, job: CaseJob) -> None:
        conn.execute(
            """
            INSERT INTO jobs VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(job_id) DO UPDATE SET
                action_id = excluded.action_id,
                action_label = excluded.action_label,
                workflow_kind = excluded.workflow_kind,
                status = excluded.status,
                resumable = excluded.resumable,
                created_at_utc = excluded.created_at_utc,
                updated_at_utc = excluded.updated_at_utc,
                started_at_utc = excluded.started_at_utc,
                ended_at_utc = excluded.ended_at_utc,
                device_serial = excluded.device_serial,
                attempt_count = excluded.attempt_count,
                params_json = excluded.params_json,
                latest_message = excluded.latest_message,
                error_message = excluded.error_message,
                recovery_hint = excluded.recovery_hint,
                logs_path = excluded.logs_path,
                result_artifact_ids_json = excluded.result_artifact_ids_json,
                steps_json = excluded.steps_json
            """,
            (
                job.job_id,
                job.action_id,
                job.action_label,
                job.workflow_kind,
                job.status,
                int(job.resumable),
                job.created_at_utc,
                job.updated_at_utc,
                job.started_at_utc,
                job.ended_at_utc,
                job.device_serial,
                job.attempt_count,
                _json_dump(job.params),
                job.latest_message,
                job.error_message,
                job.recovery_hint,
                job.logs_path,
                _json_dump(job.result_artifact_ids),
                _json_dump([dataclasses.asdict(step) for step in job.steps]),
            ),
        )

    def persist_job(
        self,
        job: CaseJob,
        *,
        case_updated_at_utc: str,
        event_type: str,
        actor: str | None = None,
    ) -> CaseJob:
        with self.transaction() as conn:
            case_id, case_actor = self._touch_case_in_tx(conn, updated_at_utc=case_updated_at_utc)
            self._insert_job_in_tx(conn, job)
            self._append_event_in_tx(
                conn,
                aggregate_type="job",
                aggregate_id=job.job_id,
                event_type=event_type,
                actor=actor or case_actor,
                payload={"case_id": case_id, "job": dataclasses.asdict(job)},
            )
        self.write_manifest_snapshot()
        return job

    def get_job(self, job_id: str) -> CaseJob | None:
        return next((job for job in self.load_manifest().jobs if job.job_id == job_id), None)

    def _insert_runtime_session_in_tx(
        self, conn: sqlite3.Connection, session: CaseRuntimeSession
    ) -> None:
        conn.execute(
            """
            INSERT INTO runtime_sessions VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(session_id) DO UPDATE SET
                name = excluded.name,
                app_id = excluded.app_id,
                session_kind = excluded.session_kind,
                attach_mode = excluded.attach_mode,
                status = excluded.status,
                created_at_utc = excluded.created_at_utc,
                updated_at_utc = excluded.updated_at_utc,
                started_at_utc = excluded.started_at_utc,
                last_connected_at_utc = excluded.last_connected_at_utc,
                ended_at_utc = excluded.ended_at_utc,
                device_id = excluded.device_id,
                pid = excluded.pid,
                connect_count = excluded.connect_count,
                reload_count = excluded.reload_count,
                event_count = excluded.event_count,
                last_event_at_utc = excluded.last_event_at_utc,
                active_script_id = excluded.active_script_id,
                logs_path = excluded.logs_path,
                summary_path = excluded.summary_path,
                latest_message = excluded.latest_message,
                error_message = excluded.error_message,
                recovery_hint = excluded.recovery_hint,
                result_artifact_ids_json = excluded.result_artifact_ids_json,
                script_inventory_json = excluded.script_inventory_json,
                metadata_json = excluded.metadata_json
            """,
            (
                session.session_id,
                session.name,
                session.app_id,
                session.session_kind,
                session.attach_mode,
                session.status,
                session.created_at_utc,
                session.updated_at_utc,
                session.started_at_utc,
                session.last_connected_at_utc,
                session.ended_at_utc,
                session.device_id,
                session.pid,
                session.connect_count,
                session.reload_count,
                session.event_count,
                session.last_event_at_utc,
                session.active_script_id,
                session.logs_path,
                session.summary_path,
                session.latest_message,
                session.error_message,
                session.recovery_hint,
                _json_dump(session.result_artifact_ids),
                _json_dump([dataclasses.asdict(script) for script in session.script_inventory]),
                _json_dump(session.metadata),
            ),
        )

    def persist_runtime_session(
        self,
        session: CaseRuntimeSession,
        *,
        case_updated_at_utc: str,
        event_type: str,
        actor: str | None = None,
    ) -> CaseRuntimeSession:
        with self.transaction() as conn:
            case_id, case_actor = self._touch_case_in_tx(conn, updated_at_utc=case_updated_at_utc)
            self._insert_runtime_session_in_tx(conn, session)
            self._append_event_in_tx(
                conn,
                aggregate_type="runtime_session",
                aggregate_id=session.session_id,
                event_type=event_type,
                actor=actor or case_actor,
                payload={"case_id": case_id, "session": dataclasses.asdict(session)},
            )
        self.write_manifest_snapshot()
        return session

    def get_runtime_session(self, session_id: str) -> CaseRuntimeSession | None:
        return next(
            (
                session
                for session in self.load_manifest().runtime_sessions
                if session.session_id == session_id
            ),
            None,
        )

    def _sync_counters(self, conn: sqlite3.Connection, manifest: CaseManifest) -> None:
        counters = {
            "artifact": _max_sequence([item.artifact_id for item in manifest.artifacts], "artifact")
            + 1,
            "job": _max_sequence([item.job_id for item in manifest.jobs], "job") + 1,
            "rt": _max_sequence([item.session_id for item in manifest.runtime_sessions], "rt") + 1,
        }
        for kind, next_value in counters.items():
            conn.execute(
                """
                INSERT INTO id_counters(kind, next_value) VALUES(?, ?)
                ON CONFLICT(kind) DO UPDATE SET next_value = MAX(id_counters.next_value, excluded.next_value)
                """,
                (kind, next_value),
            )

    def load_manifest(self) -> CaseManifest:
        with self._connect() as conn:
            case_row = conn.execute("SELECT * FROM cases LIMIT 1").fetchone()
            if case_row is None:
                raise FileNotFoundError(f"No case metadata in {self.path}")
            artifacts = [
                CaseArtifact(
                    artifact_id=row["artifact_id"],
                    path=row["path"],
                    category=row["category"],
                    source_command=row["source_command"],
                    sha256=row["sha256"],
                    size_bytes=int(row["size_bytes"]),
                    created_at_utc=row["created_at_utc"],
                    device_serial=row["device_serial"],
                    input_paths=_json_load(row["input_paths_json"], []),
                    parent_artifact_ids=_json_load(row["parent_artifact_ids_json"], []),
                    metadata=_json_load(row["metadata_json"], {}),
                )
                for row in conn.execute("SELECT * FROM artifacts ORDER BY artifact_id")
            ]
            jobs = []
            for row in conn.execute("SELECT * FROM jobs ORDER BY job_id"):
                steps = [CaseJobStep(**step) for step in _json_load(row["steps_json"], [])]
                jobs.append(
                    CaseJob(
                        job_id=row["job_id"],
                        action_id=row["action_id"],
                        action_label=row["action_label"],
                        workflow_kind=row["workflow_kind"],
                        status=row["status"],
                        resumable=bool(row["resumable"]),
                        created_at_utc=row["created_at_utc"],
                        updated_at_utc=row["updated_at_utc"],
                        started_at_utc=row["started_at_utc"],
                        ended_at_utc=row["ended_at_utc"],
                        device_serial=row["device_serial"],
                        attempt_count=int(row["attempt_count"]),
                        params=_json_load(row["params_json"], {}),
                        latest_message=row["latest_message"],
                        error_message=row["error_message"],
                        recovery_hint=row["recovery_hint"],
                        logs_path=row["logs_path"],
                        result_artifact_ids=_json_load(row["result_artifact_ids_json"], []),
                        steps=steps,
                    )
                )
            runtime_sessions = []
            for row in conn.execute("SELECT * FROM runtime_sessions ORDER BY session_id"):
                scripts = [
                    CaseRuntimeScript(**script)
                    for script in _json_load(row["script_inventory_json"], [])
                ]
                runtime_sessions.append(
                    CaseRuntimeSession(
                        session_id=row["session_id"],
                        name=row["name"],
                        app_id=row["app_id"],
                        session_kind=row["session_kind"],
                        attach_mode=row["attach_mode"],
                        status=row["status"],
                        created_at_utc=row["created_at_utc"],
                        updated_at_utc=row["updated_at_utc"],
                        started_at_utc=row["started_at_utc"],
                        last_connected_at_utc=row["last_connected_at_utc"],
                        ended_at_utc=row["ended_at_utc"],
                        device_id=row["device_id"],
                        pid=row["pid"],
                        connect_count=int(row["connect_count"]),
                        reload_count=int(row["reload_count"]),
                        event_count=int(row["event_count"]),
                        last_event_at_utc=row["last_event_at_utc"],
                        active_script_id=row["active_script_id"],
                        logs_path=row["logs_path"],
                        summary_path=row["summary_path"],
                        latest_message=row["latest_message"],
                        error_message=row["error_message"],
                        recovery_hint=row["recovery_hint"],
                        result_artifact_ids=_json_load(row["result_artifact_ids_json"], []),
                        script_inventory=scripts,
                        metadata=_json_load(row["metadata_json"], {}),
                    )
                )
            return CaseManifest(
                schema_version=4,
                case_id=case_row["case_id"],
                title=case_row["title"],
                examiner=case_row["examiner"],
                notes=case_row["notes"],
                created_at_utc=case_row["created_at_utc"],
                updated_at_utc=case_row["updated_at_utc"],
                workspace_root=case_row["workspace_root"],
                target_serials=_json_load(case_row["target_serials_json"], []),
                artifacts=artifacts,
                jobs=jobs,
                runtime_sessions=runtime_sessions,
            )

    def allocate_id(self, kind: str, *, prefix: str, width: int = 4) -> str:
        with self.transaction() as conn:
            row = conn.execute(
                "SELECT next_value FROM id_counters WHERE kind = ?", (kind,)
            ).fetchone()
            next_value = int(row["next_value"]) if row else 1
            conn.execute(
                """
                INSERT INTO id_counters(kind, next_value) VALUES(?, ?)
                ON CONFLICT(kind) DO UPDATE SET next_value = excluded.next_value
                """,
                (kind, next_value + 1),
            )
        return f"{prefix}-{next_value:0{width}d}"

    def append_event(
        self,
        aggregate_type: str,
        aggregate_id: str,
        event_type: str,
        payload: Mapping[str, Any],
        *,
        actor: str = "system",
    ) -> EventRecord:
        with self.transaction() as conn:
            return self._append_event_in_tx(
                conn,
                aggregate_type=aggregate_type,
                aggregate_id=aggregate_id,
                event_type=event_type,
                actor=actor,
                payload=payload,
            )

    def _append_event_in_tx(
        self,
        conn: sqlite3.Connection,
        *,
        aggregate_type: str,
        aggregate_id: str,
        event_type: str,
        actor: str,
        payload: Mapping[str, Any],
    ) -> EventRecord:
        previous = conn.execute(
            "SELECT event_hash FROM events ORDER BY event_id DESC LIMIT 1"
        ).fetchone()
        previous_hash = previous["event_hash"] if previous else None
        timestamp = _utc_now()
        event_payload = {
            "aggregate_type": aggregate_type,
            "aggregate_id": aggregate_id,
            "event_type": event_type,
            "timestamp_utc": timestamp,
            "actor": actor,
            "payload": dict(payload),
            "previous_hash": previous_hash,
        }
        digest = _event_hash(event_payload)
        cursor = conn.execute(
            """
            INSERT INTO events(
                aggregate_type, aggregate_id, event_type, timestamp_utc, actor,
                payload_json, previous_hash, event_hash
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                aggregate_type,
                aggregate_id,
                event_type,
                timestamp,
                actor,
                _json_dump(payload),
                previous_hash,
                digest,
            ),
        )
        event_id = cursor.lastrowid
        if event_id is None:
            raise RuntimeError("SQLite did not return an event id")
        return EventRecord(
            event_id=int(event_id),
            aggregate_type=aggregate_type,
            aggregate_id=aggregate_id,
            event_type=event_type,
            timestamp_utc=timestamp,
            actor=actor,
            payload=dict(payload),
            previous_hash=previous_hash,
            event_hash=digest,
        )

    def event_chain(self) -> list[EventRecord]:
        with self._connect() as conn:
            rows = conn.execute("SELECT * FROM events ORDER BY event_id").fetchall()
        return [
            EventRecord(
                event_id=int(row["event_id"]),
                aggregate_type=row["aggregate_type"],
                aggregate_id=row["aggregate_id"],
                event_type=row["event_type"],
                timestamp_utc=row["timestamp_utc"],
                actor=row["actor"],
                payload=_json_load(row["payload_json"], {}),
                previous_hash=row["previous_hash"],
                event_hash=row["event_hash"],
            )
            for row in rows
        ]


def is_case_workspace(case_dir: pathlib.Path) -> bool:
    return _store_path(case_dir).exists() or _manifest_path(case_dir).exists()

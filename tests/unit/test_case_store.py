from __future__ import annotations

import dataclasses
import json
import pathlib
import sqlite3

from lockknife.core.case import (
    CaseStore,
    add_case_runtime_session_script,
    complete_case_job,
    create_case_workspace,
    load_case_manifest,
    record_case_runtime_session_event,
    register_case_artifact,
    register_case_artifact_with_status,
    start_case_job,
    start_case_runtime_session,
    update_case_runtime_session,
)


def test_case_workspace_creates_sqlite_store_and_manifest_snapshot(tmp_path: pathlib.Path) -> None:
    case_dir = tmp_path / "case"
    create_case_workspace(
        case_dir=case_dir,
        case_id="CASE-SQLITE",
        examiner="Examiner",
        title="SQLite Case",
    )

    assert (case_dir / "case_store.sqlite3").exists()
    assert (case_dir / "case_manifest.json").exists()
    assert load_case_manifest(case_dir).case_id == "CASE-SQLITE"


def test_case_store_migrates_json_manifest_and_preserves_artifacts(tmp_path: pathlib.Path) -> None:
    case_dir = tmp_path / "case"
    create_case_workspace(
        case_dir=case_dir,
        case_id="CASE-MIGRATE",
        examiner="Examiner",
        title="Migration Case",
    )
    artifact_file = case_dir / "evidence" / "sample.txt"
    artifact_file.parent.mkdir(parents=True, exist_ok=True)
    artifact_file.write_text("sample", encoding="utf-8")
    artifact = register_case_artifact(
        case_dir=case_dir,
        path=artifact_file,
        category="sample",
        source_command="test",
    )
    (case_dir / "case_store.sqlite3").unlink()

    migrated = load_case_manifest(case_dir)

    assert (case_dir / "case_store.sqlite3").exists()
    assert [item.artifact_id for item in migrated.artifacts] == [artifact.artifact_id]


def test_case_store_allocates_monotonic_ids_and_appends_hash_chain(tmp_path: pathlib.Path) -> None:
    case_dir = tmp_path / "case"
    create_case_workspace(
        case_dir=case_dir,
        case_id="CASE-AUDIT",
        examiner="Examiner",
        title="Audit Case",
    )
    store = CaseStore.open(case_dir)

    assert store.allocate_id("artifact", prefix="artifact") == "artifact-0001"
    assert store.allocate_id("artifact", prefix="artifact") == "artifact-0002"

    first = store.append_event("case", "CASE-AUDIT", "test.first", {"n": 1}, actor="Tester")
    second = store.append_event("case", "CASE-AUDIT", "test.second", {"n": 2}, actor="Tester")

    chain = store.event_chain()
    assert len(chain) >= 3
    assert second.previous_hash == first.event_hash
    assert dataclasses.asdict(chain[-1])["event_hash"] == second.event_hash


def test_case_mutations_persist_direct_sqlite_rows_and_manifest_snapshot(
    tmp_path: pathlib.Path,
) -> None:
    case_dir = tmp_path / "case"
    create_case_workspace(
        case_dir=case_dir,
        case_id="CASE-MUTATE",
        examiner="Examiner",
        title="Mutation Case",
    )

    artifact_file = case_dir / "derived" / "artifact.json"
    artifact_file.write_text("{}", encoding="utf-8")
    artifact = register_case_artifact(
        case_dir=case_dir,
        path=artifact_file,
        category="analysis-output",
        source_command="analysis run",
        metadata={"version": 1},
    )
    artifact_file.write_text('{"updated": true}', encoding="utf-8")
    updated_artifact = register_case_artifact_with_status(
        case_dir=case_dir,
        path=artifact_file,
        category="analysis-output",
        source_command="analysis run",
        metadata={"version": 2},
    ).artifact

    job = start_case_job(
        case_dir,
        action_id="analysis.run",
        action_label="Analysis Run",
        params={"case_dir": case_dir, "artifact_id": artifact.artifact_id},
    )
    completed_job = complete_case_job(
        case_dir,
        job_id=job.job_id,
        message="Analysis complete",
        payload={"artifact_id": artifact.artifact_id},
    )

    script_path = tmp_path / "hook.js"
    script_path.write_text("send('hook');", encoding="utf-8")
    session = start_case_runtime_session(
        case_dir,
        name="Hook",
        app_id="com.example.app",
        session_kind="hook",
        attach_mode="spawn",
        metadata={"preflight": {"status": "ok"}},
    )
    session = add_case_runtime_session_script(
        case_dir,
        session_id=session.session_id,
        label="Hook Script",
        path=str(script_path),
        source_command="runtime.hook",
    )
    session = update_case_runtime_session(
        case_dir,
        session_id=session.session_id,
        status="active",
        connect_increment=1,
        result_artifact_ids_append=[artifact.artifact_id],
    )
    session = record_case_runtime_session_event(
        case_dir,
        session_id=session.session_id,
        event={"timestamp_utc": "2026-05-10T00:00:00+00:00", "message": "loaded"},
    )

    manifest = load_case_manifest(case_dir)
    snapshot = json.loads((case_dir / "case_manifest.json").read_text(encoding="utf-8"))
    assert manifest.artifacts[0] == updated_artifact
    assert snapshot["artifacts"][0]["metadata"] == {"version": 2}
    assert snapshot["jobs"][0]["status"] == completed_job.status == "succeeded"
    assert snapshot["runtime_sessions"][0]["event_count"] == session.event_count == 1

    with sqlite3.connect(case_dir / "case_store.sqlite3") as conn:
        conn.row_factory = sqlite3.Row
        artifact_row = conn.execute(
            "SELECT metadata_json FROM artifacts WHERE artifact_id = ?",
            (updated_artifact.artifact_id,),
        ).fetchone()
        job_row = conn.execute(
            "SELECT status, result_artifact_ids_json FROM jobs WHERE job_id = ?",
            (completed_job.job_id,),
        ).fetchone()
        session_row = conn.execute(
            """
            SELECT status, connect_count, event_count, script_inventory_json
            FROM runtime_sessions
            WHERE session_id = ?
            """,
            (session.session_id,),
        ).fetchone()

    assert artifact_row is not None
    assert json.loads(artifact_row["metadata_json"]) == {"version": 2}
    assert job_row is not None
    assert job_row["status"] == "succeeded"
    assert json.loads(job_row["result_artifact_ids_json"]) == [artifact.artifact_id]
    assert session_row is not None
    assert session_row["status"] == "active"
    assert session_row["connect_count"] == 1
    assert session_row["event_count"] == 1
    assert len(json.loads(session_row["script_inventory_json"])) == 1

import json
import pathlib
import sqlite3

from lockknife.modules.forensics.artifacts import parse_forensics_directory
from lockknife.modules.forensics.parsers import decode_protobuf_file
from lockknife.modules.forensics.timeline import build_timeline_report


def test_parse_forensics_directory_imports_aleapp_lava_and_populates_timeline(
    tmp_path: pathlib.Path,
) -> None:
    metadata = {
        "artifacts": {
            "Messaging": [
                {
                    "name": "WhatsApp Messages",
                    "module": "whatsapp",
                    "tablename": "wa_messages",
                    "column_map": {"ts": "Timestamp", "body": "Body", "jid": "JID"},
                }
            ]
        }
    }
    (tmp_path / "_lava_data.json").write_text(json.dumps(metadata), encoding="utf-8")
    db_path = tmp_path / "_lava_artifacts.db"
    conn = sqlite3.connect(db_path)
    conn.execute("CREATE TABLE wa_messages (ts INTEGER, body TEXT, jid TEXT)")
    conn.execute(
        "INSERT INTO wa_messages VALUES (?, ?, ?)", (1710000000000, "hello", "alice@example.com")
    )
    conn.commit()
    conn.close()

    report = parse_forensics_directory(tmp_path)
    parsed_artifacts = tmp_path / "parsed_artifacts.json"
    parsed_artifacts.write_text(
        json.dumps([artifact.__dict__ for artifact in report.artifacts]), encoding="utf-8"
    )
    timeline = build_timeline_report(parsed_artifacts_path=parsed_artifacts)

    assert report.summary["aleapp_compatible"] is True
    assert report.summary["aleapp_imported_count"] == 1
    assert report.artifacts[0].artifact_family == "messaging"
    assert report.artifacts[0].records[0]["timestamp_ms"] == 1710000000000
    assert timeline["event_count"] == 1
    assert timeline["summary"]["source_counts"]["messaging"] == 1


def test_decode_protobuf_file_builds_nested_message_summary(tmp_path: pathlib.Path) -> None:
    blob = tmp_path / "sample.pb"
    payload = bytes(
        [
            0x08,
            0x96,
            0x01,
            0x12,
            0x05,
            *b"hello",
            0x1A,
            0x02,
            0x08,
            0x01,
        ]
    )
    blob.write_bytes(payload)

    decoded = decode_protobuf_file(blob)

    assert decoded is not None
    assert decoded["message_count"] >= 3
    assert decoded["nested_message_count"] >= 1
    assert decoded["string_field_count"] >= 1
    assert any(item.get("text") == "hello" for item in decoded["messages"])

import json
import pathlib
import sqlite3

from lockknife.modules.forensics.aleapp_compat import import_aleapp_artifacts, looks_like_aleapp_output


def test_import_aleapp_artifacts_reads_lava_database(tmp_path: pathlib.Path) -> None:
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
    conn.execute("INSERT INTO wa_messages VALUES (?, ?, ?)", (1710000000000, "hello", "alice@example.com"))
    conn.commit()
    conn.close()

    payload = import_aleapp_artifacts(tmp_path)

    assert looks_like_aleapp_output(tmp_path) is True
    assert payload["summary"]["artifact_count"] == 1
    assert payload["artifacts"][0]["artifact_family"] == "messaging"
    assert payload["artifacts"][0]["records"][0]["timestamp"] == 1710000000000


def test_import_aleapp_artifacts_falls_back_to_tsv_and_preserves_invalid_json_strings(tmp_path: pathlib.Path) -> None:
    (tmp_path / "_lava_data.json").write_text("{bad json}", encoding="utf-8")
    (tmp_path / "_lava_artifacts.db").write_bytes(b"not-a-db")
    tsv = tmp_path / "Messaging" / "messages.tsv"
    tsv.parent.mkdir(parents=True, exist_ok=True)
    tsv.write_text("Body\tMeta\nhello\t{oops}\n", encoding="utf-8")

    payload = import_aleapp_artifacts(tmp_path)

    assert payload["summary"]["source_format_counts"]["tsv"] == 1
    assert payload["warnings"]
    assert payload["artifacts"][0]["records"][0]["Meta"] == "{oops}"
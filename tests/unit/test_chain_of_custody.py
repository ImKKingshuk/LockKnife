import hashlib
import pathlib

from lockknife.modules.reporting.chain_of_custody import EvidenceItem, build_chain_of_custody_payload, generate_chain_of_custody, verify_chain_of_custody


def test_chain_of_custody_autohash(tmp_path: pathlib.Path) -> None:
    p = tmp_path / "evidence.bin"
    p.write_bytes(b"abc")
    expected = hashlib.sha256(b"abc").hexdigest()
    text = generate_chain_of_custody(case_id="C1", examiner="E", notes=None, evidence=[EvidenceItem(name="x", path=str(p))])
    assert expected in text


def test_chain_of_custody_renders_case_metadata_fields() -> None:
    text = generate_chain_of_custody(
        case_id="C2",
        examiner="Examiner",
        notes="Ready",
        evidence=[
            EvidenceItem(
                name="artifact-1",
                path="/tmp/evidence.json",
                sha256="abc123",
                category="extract-sms",
                source_command="extract sms",
                device_serial="SER-1",
                collected_at_utc="2026-03-09T00:00:00Z",
                size_bytes=42,
                integrity_status="verified",
            )
        ],
    )

    assert "Category: extract-sms" in text
    assert "Source command: extract sms" in text
    assert "Integrity status: verified" in text


def test_chain_of_custody_builds_hash_chain_payload() -> None:
    payload = build_chain_of_custody_payload(
        case_id="C3",
        examiner="Examiner",
        notes=None,
        evidence=[
            EvidenceItem(name="a", path="/tmp/a", sha256="1" * 64),
            EvidenceItem(name="b", path="/tmp/b", sha256="2" * 64),
        ],
    )

    assert payload["entry_count"] == 2
    assert payload["entries"][1]["previous_hash"] == payload["entries"][0]["entry_hash"]
    assert verify_chain_of_custody(payload["entries"])["status"] == "verified"

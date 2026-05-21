import pytest


def test_bruteforce_numeric_pin_sha256() -> None:
    lockknife_core = pytest.importorskip("lockknife.lockknife_core")
    pin = "0420"
    target = lockknife_core.sha256_hex(pin.encode("utf-8"))
    found = lockknife_core.bruteforce_numeric_pin(target, "sha256", 4)
    assert found == pin


def test_sha512_and_hmac() -> None:
    lockknife_core = pytest.importorskip("lockknife.lockknife_core")
    assert lockknife_core.sha512_hex(b"x")
    h = lockknife_core.hmac_sha256(b"k", b"data")
    assert isinstance(h, str)
    assert len(h) == 64


def test_aes256gcm_roundtrip() -> None:
    lockknife_core = pytest.importorskip("lockknife.lockknife_core")
    key = b"\x00" * 32
    nonce = b"\x01" * 12
    ct = lockknife_core.aes256gcm_encrypt(key, nonce, b"hello", b"")
    pt = lockknife_core.aes256gcm_decrypt(key, nonce, ct, b"")
    assert pt == b"hello"


def test_dictionary_attack(tmp_path) -> None:
    lockknife_core = pytest.importorskip("lockknife.lockknife_core")
    wl = tmp_path / "wordlist.txt"
    wl.write_text("foo\nbar\nsecret\n", encoding="utf-8")
    target = lockknife_core.sha256_hex(b"secret")
    found = lockknife_core.dictionary_attack(target, "sha256", str(wl))
    assert found == "secret"


def test_dictionary_attack_rules(tmp_path) -> None:
    lockknife_core = pytest.importorskip("lockknife.lockknife_core")
    if not hasattr(lockknife_core, "dictionary_attack_rules"):
        pytest.skip("dictionary_attack_rules not available")
    wl = tmp_path / "wordlist.txt"
    wl.write_text("secret\n", encoding="utf-8")
    target = lockknife_core.sha256_hex(b"secret7")
    found = lockknife_core.dictionary_attack_rules(target, "sha256", str(wl), 10)
    assert found == "secret7"


def test_android_pin_sha1_bruteforce() -> None:
    lockknife_core = pytest.importorskip("lockknife.lockknife_core")
    salt = 1234
    pin = "0420"
    target = lockknife_core.sha1_hex(f"{salt}{pin}".encode())
    found = lockknife_core.bruteforce_android_pin_sha1(target, salt, 4)
    assert found == pin


def test_scan_patterns_json() -> None:
    lockknife_core = pytest.importorskip("lockknife.lockknife_core")
    out = lockknife_core.scan_patterns_json(b"abc123abc", ["abc", "zzz"])
    assert "abc" in out


def test_sqlite_table_to_json(tmp_path) -> None:
    lockknife_core = pytest.importorskip("lockknife.lockknife_core")
    import json
    import sqlite3

    db = tmp_path / "x.db"
    con = sqlite3.connect(str(db))
    try:
        con.execute("CREATE TABLE t (id INTEGER, name TEXT)")
        con.execute("INSERT INTO t VALUES (1, 'a')")
        con.commit()
    finally:
        con.close()
    out = lockknife_core.sqlite_table_to_json(str(db), "t", 10)
    rows = json.loads(out)
    assert rows[0]["id"] == 1


def test_correlate_artifacts_json() -> None:
    lockknife_core = pytest.importorskip("lockknife.lockknife_core")
    out = lockknife_core.correlate_artifacts_json(['[{"number":"+1"}]', '[{"ssid":"Home"}]'])
    assert "+1" in out
    assert "edges" in out


def test_parse_ipv4_header_json() -> None:
    lockknife_core = pytest.importorskip("lockknife.lockknife_core")
    pkt = bytes.fromhex("450000140000000040060000c000020108080808")
    out = lockknife_core.parse_ipv4_header_json(pkt)
    assert "192.0.2.1" in out


def test_parse_elf_header_json_rejects_invalid() -> None:
    lockknife_core = pytest.importorskip("lockknife.lockknife_core")
    with pytest.raises(ValueError):
        lockknife_core.parse_elf_header_json(b"not-elf")


def test_parse_dex_header_json_valid() -> None:
    lockknife_core = pytest.importorskip("lockknife.lockknife_core")
    import json
    import struct

    buf = bytearray(0x70)
    buf[0:8] = b"dex\n035\0"
    struct.pack_into("<I", buf, 32, 1000)  # file_size
    struct.pack_into("<I", buf, 36, 0x70)  # header_size
    struct.pack_into("<I", buf, 40, 0x12345678)  # endian_tag
    struct.pack_into("<I", buf, 60, 0x200)  # string_ids_off

    out_str = lockknife_core.parse_dex_header_json(bytes(buf))
    res = json.loads(out_str)
    assert res["magic"] == "dex\n035\0"
    assert res["file_size"] == 1000
    assert res["header_size"] == 0x70
    assert res["endian_tag"] == 0x12345678
    assert res["string_ids_off"] == 0x200


def test_parse_elf_header_json_valid() -> None:
    lockknife_core = pytest.importorskip("lockknife.lockknife_core")
    import json

    elf = bytearray(64)
    elf[0:4] = b"\x7fELF"
    elf[4] = 2  # 64-bit
    elf[5] = 1  # Little endian
    elf[6] = 1  # Version
    elf[16] = 2  # e_type
    elf[18] = 0x3E  # e_machine (x86_64)
    elf[20] = 1  # e_version

    out_str = lockknife_core.parse_elf_header_json(bytes(elf))
    res = json.loads(out_str)
    assert res["class"] == 2
    assert res["endianness"] == 1
    assert res["machine"] == 0x3E
    assert isinstance(res["dynsyms"], list)
    assert isinstance(res["libraries"], list)


def test_detect_iocs_native() -> None:
    lockknife_core = pytest.importorskip("lockknife.lockknife_core")
    import json

    text = (
        "Sample hash: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855\n"
        "Sample URL: https://example.com/api?val=1\n"
        "Sample IP: 1.2.3.4 and invalid IP 999.999.999.999\n"
        "Sample domain: evil-domain.org"
    )
    out_str = lockknife_core.detect_iocs_native(text.encode("utf-8"))
    res = json.loads(out_str)

    matches = {item["ioc"]: item["kind"] for item in res}
    assert matches["e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"] == "sha256"
    assert matches["https://example.com/api?val=1"] == "url"
    assert matches["1.2.3.4"] == "ipv4"
    assert "999.999.999.999" not in matches
    assert matches["evil-domain.org"] == "domain"

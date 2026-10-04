from __future__ import annotations

import pathlib
import struct
import zipfile

import pytest
from click.testing import CliRunner

from lockknife.modules.apk._axml_parser import extract_manifest_xml_from_apk, parse_axml_to_xml
from lockknife.modules.apk._signing import _detect_signing_schemes
from lockknife.modules.apk.decompile import parse_apk_manifest
from lockknife_headless_cli.apk import apk


def _build_binary_axml() -> bytes:
    strings = [
        "http://schemas.android.com/apk/res/android",
        "android",
        "package",
        "com.lockknife.test",
        "versionCode",
        "versionName",
        "2.1.0",
        "manifest",
        "uses-permission",
        "name",
        "android.permission.INTERNET",
        "android.permission.READ_SMS",
        "application",
        "debuggable",
        "allowBackup",
        "usesCleartextTraffic",
        "activity",
        ".MainActivity",
        "exported",
        "intent-filter",
        "action",
        "android.intent.action.MAIN",
        "category",
        "android.intent.category.LAUNCHER",
        "uses-sdk",
        "minSdkVersion",
        "targetSdkVersion",
    ]

    str_offsets: list[int] = []
    str_data = bytearray()
    for s in strings:
        str_offsets.append(len(str_data))
        encoded = s.encode("utf-16le")
        str_data.extend(struct.pack("<H", len(s)))
        str_data.extend(encoded)
        str_data.extend(b"\x00\x00")

    sp_header_size = 28
    sp_size = sp_header_size + len(str_offsets) * 4 + len(str_data)
    pad = (4 - (sp_size % 4)) % 4
    sp_size += pad
    str_data.extend(b"\x00" * pad)

    strings_start = sp_header_size + len(str_offsets) * 4
    sp_chunk = bytearray()
    sp_chunk.extend(
        struct.pack(
            "<HHIIIIII",
            0x0001,
            sp_header_size,
            sp_size,
            len(strings),
            0,
            0,
            strings_start,
            0,
        )
    )
    for off in str_offsets:
        sp_chunk.extend(struct.pack("<I", off))
    sp_chunk.extend(str_data)

    xml_chunks = bytearray()
    # 1. Start namespace android -> http://schemas.android.com/apk/res/android
    xml_chunks.extend(struct.pack("<HHIIIII", 0x0100, 16, 24, 1, 0xFFFFFFFF, 1, 0))

    # 2. <manifest package="com.lockknife.test" android:versionCode="210" android:versionName="2.1.0">
    manifest_start = bytearray()
    manifest_start.extend(struct.pack("<HHII", 0x0102, 16, 16 + 20 + 60, 1))
    manifest_start.extend(struct.pack("<I", 0xFFFFFFFF))
    manifest_start.extend(struct.pack("<IIHHHHHH", 0xFFFFFFFF, 7, 20, 20, 3, 0, 0, 0))
    # attr package
    manifest_start.extend(struct.pack("<III", 0xFFFFFFFF, 2, 3))
    manifest_start.extend(struct.pack("<HBB", 8, 0, 3))
    manifest_start.extend(struct.pack("<I", 3))
    # attr android:versionCode = 210
    manifest_start.extend(struct.pack("<III", 0, 4, 0xFFFFFFFF))
    manifest_start.extend(struct.pack("<HBB", 8, 0, 16))
    manifest_start.extend(struct.pack("<I", 210))
    # attr android:versionName = "2.1.0"
    manifest_start.extend(struct.pack("<III", 0, 5, 6))
    manifest_start.extend(struct.pack("<HBB", 8, 0, 3))
    manifest_start.extend(struct.pack("<I", 6))
    xml_chunks.extend(manifest_start)

    # 3. <uses-sdk android:minSdkVersion="21" android:targetSdkVersion="34"/>
    uses_sdk = bytearray()
    uses_sdk.extend(struct.pack("<HHII", 0x0102, 16, 16 + 20 + 40, 2))
    uses_sdk.extend(struct.pack("<I", 0xFFFFFFFF))
    uses_sdk.extend(struct.pack("<IIHHHHHH", 0xFFFFFFFF, 24, 20, 20, 2, 0, 0, 0))
    # minSdkVersion = 21
    uses_sdk.extend(struct.pack("<III", 0, 25, 0xFFFFFFFF))
    uses_sdk.extend(struct.pack("<HBB", 8, 0, 16))
    uses_sdk.extend(struct.pack("<I", 21))
    # targetSdkVersion = 34
    uses_sdk.extend(struct.pack("<III", 0, 26, 0xFFFFFFFF))
    uses_sdk.extend(struct.pack("<HBB", 8, 0, 16))
    uses_sdk.extend(struct.pack("<I", 34))
    xml_chunks.extend(uses_sdk)
    xml_chunks.extend(struct.pack("<HHIIIII", 0x0103, 16, 24, 2, 0xFFFFFFFF, 0xFFFFFFFF, 24))

    # 4. <uses-permission android:name="android.permission.INTERNET"/>
    up_net = bytearray()
    up_net.extend(struct.pack("<HHII", 0x0102, 16, 56, 3))
    up_net.extend(struct.pack("<I", 0xFFFFFFFF))
    up_net.extend(struct.pack("<IIHHHHHH", 0xFFFFFFFF, 8, 20, 20, 1, 0, 0, 0))
    up_net.extend(struct.pack("<III", 0, 9, 10))
    up_net.extend(struct.pack("<HBB", 8, 0, 3))
    up_net.extend(struct.pack("<I", 10))
    xml_chunks.extend(up_net)
    xml_chunks.extend(struct.pack("<HHIIIII", 0x0103, 16, 24, 3, 0xFFFFFFFF, 0xFFFFFFFF, 8))

    # 5. <uses-permission android:name="android.permission.READ_SMS"/>
    up_sms = bytearray()
    up_sms.extend(struct.pack("<HHII", 0x0102, 16, 56, 4))
    up_sms.extend(struct.pack("<I", 0xFFFFFFFF))
    up_sms.extend(struct.pack("<IIHHHHHH", 0xFFFFFFFF, 8, 20, 20, 1, 0, 0, 0))
    up_sms.extend(struct.pack("<III", 0, 9, 11))
    up_sms.extend(struct.pack("<HBB", 8, 0, 3))
    up_sms.extend(struct.pack("<I", 11))
    xml_chunks.extend(up_sms)
    xml_chunks.extend(struct.pack("<HHIIIII", 0x0103, 16, 24, 4, 0xFFFFFFFF, 0xFFFFFFFF, 8))

    # 6. <application android:debuggable="true" android:allowBackup="true" android:usesCleartextTraffic="true">
    app_start = bytearray()
    app_start.extend(struct.pack("<HHII", 0x0102, 16, 16 + 20 + 60, 5))
    app_start.extend(struct.pack("<I", 0xFFFFFFFF))
    app_start.extend(struct.pack("<IIHHHHHH", 0xFFFFFFFF, 12, 20, 20, 3, 0, 0, 0))
    # debuggable = true
    app_start.extend(struct.pack("<III", 0, 13, 0xFFFFFFFF))
    app_start.extend(struct.pack("<HBB", 8, 0, 18))  # TYPE_INT_BOOLEAN
    app_start.extend(struct.pack("<I", 1))
    # allowBackup = true
    app_start.extend(struct.pack("<III", 0, 14, 0xFFFFFFFF))
    app_start.extend(struct.pack("<HBB", 8, 0, 18))
    app_start.extend(struct.pack("<I", 1))
    # usesCleartextTraffic = true
    app_start.extend(struct.pack("<III", 0, 15, 0xFFFFFFFF))
    app_start.extend(struct.pack("<HBB", 8, 0, 18))
    app_start.extend(struct.pack("<I", 1))
    xml_chunks.extend(app_start)

    # 7. <activity android:name=".MainActivity" android:exported="true">
    act_start = bytearray()
    act_start.extend(struct.pack("<HHII", 0x0102, 16, 16 + 20 + 40, 6))
    act_start.extend(struct.pack("<I", 0xFFFFFFFF))
    act_start.extend(struct.pack("<IIHHHHHH", 0xFFFFFFFF, 16, 20, 20, 2, 0, 0, 0))
    act_start.extend(struct.pack("<III", 0, 9, 17))  # android:name=".MainActivity"
    act_start.extend(struct.pack("<HBB", 8, 0, 3))
    act_start.extend(struct.pack("<I", 17))
    act_start.extend(struct.pack("<III", 0, 18, 0xFFFFFFFF))  # android:exported="true"
    act_start.extend(struct.pack("<HBB", 8, 0, 18))
    act_start.extend(struct.pack("<I", 1))
    xml_chunks.extend(act_start)

    # 8. <intent-filter>
    if_start = bytearray()
    if_start.extend(struct.pack("<HHII", 0x0102, 16, 36, 7))
    if_start.extend(struct.pack("<I", 0xFFFFFFFF))
    if_start.extend(struct.pack("<IIHHHHHH", 0xFFFFFFFF, 19, 20, 20, 0, 0, 0, 0))
    xml_chunks.extend(if_start)

    # <action android:name="android.intent.action.MAIN"/>
    act_action = bytearray()
    act_action.extend(struct.pack("<HHII", 0x0102, 16, 56, 8))
    act_action.extend(struct.pack("<I", 0xFFFFFFFF))
    act_action.extend(struct.pack("<IIHHHHHH", 0xFFFFFFFF, 20, 20, 20, 1, 0, 0, 0))
    act_action.extend(struct.pack("<III", 0, 9, 21))
    act_action.extend(struct.pack("<HBB", 8, 0, 3))
    act_action.extend(struct.pack("<I", 21))
    xml_chunks.extend(act_action)
    xml_chunks.extend(struct.pack("<HHIIIII", 0x0103, 16, 24, 8, 0xFFFFFFFF, 0xFFFFFFFF, 20))

    # <category android:name="android.intent.category.LAUNCHER"/>
    act_cat = bytearray()
    act_cat.extend(struct.pack("<HHII", 0x0102, 16, 56, 9))
    act_cat.extend(struct.pack("<I", 0xFFFFFFFF))
    act_cat.extend(struct.pack("<IIHHHHHH", 0xFFFFFFFF, 22, 20, 20, 1, 0, 0, 0))
    act_cat.extend(struct.pack("<III", 0, 9, 23))
    act_cat.extend(struct.pack("<HBB", 8, 0, 3))
    act_cat.extend(struct.pack("<I", 23))
    xml_chunks.extend(act_cat)
    xml_chunks.extend(struct.pack("<HHIIIII", 0x0103, 16, 24, 9, 0xFFFFFFFF, 0xFFFFFFFF, 22))

    # </intent-filter>
    xml_chunks.extend(struct.pack("<HHIIIII", 0x0103, 16, 24, 7, 0xFFFFFFFF, 0xFFFFFFFF, 19))

    # </activity>
    xml_chunks.extend(struct.pack("<HHIIIII", 0x0103, 16, 24, 6, 0xFFFFFFFF, 0xFFFFFFFF, 16))

    # </application>
    xml_chunks.extend(struct.pack("<HHIIIII", 0x0103, 16, 24, 5, 0xFFFFFFFF, 0xFFFFFFFF, 12))

    # </manifest>
    xml_chunks.extend(struct.pack("<HHIIIII", 0x0103, 16, 24, 10, 0xFFFFFFFF, 0xFFFFFFFF, 7))

    # End namespace
    xml_chunks.extend(struct.pack("<HHIIIII", 0x0101, 16, 24, 10, 0xFFFFFFFF, 1, 0))

    total_size = 8 + len(sp_chunk) + len(xml_chunks)
    file_header = struct.pack("<HHI", 0x0003, 8, total_size)
    return file_header + sp_chunk + xml_chunks


def _create_synthetic_apk(apk_file: pathlib.Path, *, binary: bool = True) -> pathlib.Path:
    with zipfile.ZipFile(apk_file, "w") as zf:
        if binary:
            zf.writestr("AndroidManifest.xml", _build_binary_axml())
        else:
            zf.writestr(
                "AndroidManifest.xml",
                """<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android" package="com.lockknife.plain">
    <uses-sdk android:minSdkVersion="23" android:targetSdkVersion="33"/>
    <uses-permission android:name="android.permission.READ_SMS"/>
    <application android:debuggable="false" android:allowBackup="true" android:usesCleartextTraffic="false">
        <activity android:name=".HomeActivity" android:exported="true">
            <intent-filter>
                <action android:name="android.intent.action.MAIN"/>
                <category android:name="android.intent.category.LAUNCHER"/>
            </intent-filter>
        </activity>
    </application>
</manifest>""",
            )
        # Add mock DEX and signature
        zf.writestr("classes.dex", b"dex\n035\x00" + b"\x00" * 100)
        zf.writestr("META-INF/MANIFEST.MF", "Manifest-Version: 1.0\n")
        zf.writestr("META-INF/CERT.RSA", b"mock-cert-bytes")
    return apk_file


def test_parse_axml_binary_manifest() -> None:
    data = _build_binary_axml()
    xml_str = parse_axml_to_xml(data)
    assert "<manifest" in xml_str
    assert 'package="com.lockknife.test"' in xml_str
    assert "android:versionCode=" in xml_str
    assert "uses-permission" in xml_str
    assert "android.permission.INTERNET" in xml_str
    assert "debuggable=" in xml_str
    assert "</manifest>" in xml_str


def test_parse_axml_plain_xml() -> None:
    plain = b'<manifest package="com.test"><application/></manifest>'
    xml_str = parse_axml_to_xml(plain)
    assert 'package="com.test"' in xml_str


def test_extract_manifest_and_parse_native_apk(tmp_path: pathlib.Path) -> None:
    apk_path = tmp_path / "test_app.apk"
    _create_synthetic_apk(apk_path, binary=True)

    extracted_xml = extract_manifest_xml_from_apk(apk_path)
    assert 'package="com.lockknife.test"' in extracted_xml

    info = parse_apk_manifest(apk_path)
    assert info["package"] == "com.lockknife.test"
    assert info["version_name"] == "2.1.0"
    assert info["version_code"] == "210"
    assert info["sdk"]["min"] == "21"
    assert info["sdk"]["target"] == "34"
    assert "android.permission.INTERNET" in info["permissions"]
    assert "android.permission.READ_SMS" in info["permissions"]
    assert info["debuggable"] is True
    assert info["allow_backup"] is True
    assert info["uses_cleartext_traffic"] is True
    assert "com.lockknife.test.MainActivity" in info["activities"]
    assert info["main_activity"] == "com.lockknife.test.MainActivity"
    assert info["signing"]["schemes"]["v1"] is True


def test_parse_plain_xml_apk_manifest(tmp_path: pathlib.Path) -> None:
    apk_path = tmp_path / "plain_app.apk"
    _create_synthetic_apk(apk_path, binary=False)

    info = parse_apk_manifest(apk_path)
    assert info["package"] == "com.lockknife.plain"
    assert info["sdk"]["min"] == "23"
    assert info["sdk"]["target"] == "33"
    assert "android.permission.READ_SMS" in info["permissions"]
    assert info["main_activity"] == "com.lockknife.plain.HomeActivity"


def test_signing_scheme_v1_detection(tmp_path: pathlib.Path) -> None:
    apk_path = tmp_path / "signed.apk"
    _create_synthetic_apk(apk_path, binary=True)
    schemes = _detect_signing_schemes(apk_path, {"meta_inf_signers": ["META-INF/CERT.RSA"]})
    assert schemes["v1"] is True
    assert schemes["v2"] is False


def test_cli_apk_permissions_no_external_dependency(tmp_path: pathlib.Path) -> None:
    apk_path = tmp_path / "cli_perm.apk"
    _create_synthetic_apk(apk_path, binary=True)

    runner = CliRunner()
    res = runner.invoke(apk, ["permissions", str(apk_path)])
    assert res.exit_code == 0
    assert "com.lockknife.test" in res.output
    assert "READ_SMS" in res.output


def test_cli_apk_analyze_no_external_dependency(tmp_path: pathlib.Path) -> None:
    apk_path = tmp_path / "cli_analyze.apk"
    _create_synthetic_apk(apk_path, binary=True)

    runner = CliRunner()
    res = runner.invoke(apk, ["analyze", str(apk_path)])
    assert res.exit_code == 0
    assert "com.lockknife.test" in res.output
    assert "findings" in res.output


def test_cli_apk_vulnerability_no_external_dependency(tmp_path: pathlib.Path) -> None:
    apk_path = tmp_path / "cli_vuln.apk"
    _create_synthetic_apk(apk_path, binary=True)

    runner = CliRunner()
    res = runner.invoke(apk, ["vulnerability", str(apk_path)])
    assert res.exit_code == 0
    assert "com.lockknife.test" in res.output
    assert "cve" in res.output


@pytest.mark.parametrize(
    "mutation", ["header", "chunk", "count", "offset", "attributes", "truncated"]
)
def test_axml_rejects_malformed_boundaries(mutation):
    data = bytearray(_build_binary_axml())
    if mutation == "header":
        struct.pack_into("<H", data, 2, 0)
    elif mutation == "chunk":
        struct.pack_into("<I", data, 12, len(data) + 1)
    elif mutation == "count":
        struct.pack_into("<I", data, 16, 0xFFFFFFFF)
    elif mutation == "offset":
        struct.pack_into("<I", data, 36, len(data))
    elif mutation == "attributes":
        pool_size = struct.unpack_from("<I", data, 12)[0]
        struct.pack_into("<H", data, 8 + pool_size + 24 + 26, 0)
    else:
        data = data[:-1]
    with pytest.raises(ValueError):
        parse_axml_to_xml(bytes(data))


def test_axml_duplicate_manifest_and_size_limit(tmp_path, monkeypatch):
    from lockknife.modules.apk import _axml_parser

    path = tmp_path / "duplicate.apk"
    with zipfile.ZipFile(path, "w") as archive:
        archive.writestr("AndroidManifest.xml", b"<manifest/>")
        archive.writestr("androidmanifest.xml", b"<manifest/>")
    with pytest.raises(ValueError, match="exactly one"):
        extract_manifest_xml_from_apk(path)
    monkeypatch.setattr(_axml_parser, "MAX_MANIFEST_BYTES", 8)
    with pytest.raises(ValueError, match="size limit"):
        parse_axml_to_xml(b"<manifest/>")


def test_signing_block_detects_real_pairs_and_rejects_malformed(tmp_path):
    path = tmp_path / "signing.apk"
    _create_synthetic_apk(path)
    raw = path.read_bytes()
    eocd = raw.rfind(b"PK\x05\x06")
    cd_offset = struct.unpack_from("<I", raw, eocd + 16)[0]
    pairs = struct.pack("<QI", 5, 0x7109871A) + b"x" + struct.pack("<QI", 5, 0xF05368C0) + b"y"
    size = len(pairs) + 24
    block = struct.pack("<Q", size) + pairs + struct.pack("<Q", size) + b"APK Sig Block 42"
    updated = bytearray(raw[:cd_offset] + block + raw[cd_offset:])
    struct.pack_into("<I", updated, eocd + len(block) + 16, cd_offset + len(block))
    path.write_bytes(updated)
    assert _detect_signing_schemes(path, {})["v2"] is True
    assert _detect_signing_schemes(path, {})["v3"] is True
    struct.pack_into("<Q", updated, cd_offset + 8, 0)
    path.write_bytes(updated)
    assert _detect_signing_schemes(path, {})["v2"] is False

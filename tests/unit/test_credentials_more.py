import pathlib

import pytest


class _FakeAdb:
    def __init__(self) -> None:
        self.pulled: list[tuple[str, str]] = []
        self.shell_calls: list[str] = []

    def pull(self, serial: str, remote_path: str, local_path: pathlib.Path, timeout_s: float = 0.0) -> None:
        self.pulled.append((serial, remote_path))
        local_path.parent.mkdir(parents=True, exist_ok=True)
        if remote_path.endswith("WifiConfigStore.xml"):
            local_path.write_text(
                "<WifiConfigStoreData><Network><WifiConfiguration><string name=\"SSID\">\"Home\"</string>"
                "<string name=\"PreSharedKey\">\"pw\"</string><string name=\"KeyMgmt\">WPA_PSK</string>"
                "</WifiConfiguration></Network></WifiConfigStoreData>",
                encoding="utf-8",
            )
        elif remote_path.endswith("wpa_supplicant.conf"):
            local_path.write_text('network={\nssid="Cafe"\npsk="1234"\n}\n', encoding="utf-8")
        elif remote_path.endswith("/data/system/gesture.key"):
            local_path.write_bytes(b"\x00" * 20)
        else:
            local_path.write_bytes(b"x")

    def shell(self, serial: str, command: str, timeout_s: float = 0.0) -> str:
        self.shell_calls.append(command)
        if "ls -1 /data/misc/keystore" in command:
            return "entry1\nentry2\n"
        return ""

    def has_su(self, serial: str) -> bool:
        return True

    def getprop(self, serial: str) -> dict[str, str]:
        return {}


class _FakeDevices:
    def __init__(self) -> None:
        self._adb = _FakeAdb()

    def pull(self, serial: str, remote_path: str, local_path: pathlib.Path, timeout_s: float = 0.0) -> None:
        return self._adb.pull(serial, remote_path, local_path, timeout_s=timeout_s)

    def shell(self, serial: str, command: str, timeout_s: float = 0.0) -> str:
        return self._adb.shell(serial, command, timeout_s=timeout_s)

    def has_root(self, serial: str) -> bool:
        return True


def test_extract_wifi_passwords_xml() -> None:
    from lockknife.modules.credentials.wifi import extract_wifi_passwords

    dev = _FakeDevices()
    creds = extract_wifi_passwords(dev, "SERIAL")  # type: ignore[arg-type]
    assert creds[0].ssid == "Home"
    assert creds[0].psk == "pw"


def test_extract_wifi_passwords_wpa_conf(monkeypatch) -> None:
    from lockknife.modules.credentials import wifi as wifi_mod

    dev = _FakeDevices()
    orig_pull = dev.pull

    def pull(serial: str, remote_path: str, local_path: pathlib.Path, timeout_s: float = 0.0) -> None:
        if remote_path.endswith("WifiConfigStore.xml"):
            raise RuntimeError("no")
        return orig_pull(serial, remote_path, local_path, timeout_s=timeout_s)

    monkeypatch.setattr(dev, "pull", pull)
    creds = wifi_mod.extract_wifi_passwords(dev, "SERIAL")  # type: ignore[arg-type]
    assert creds[0].ssid == "Cafe"
    assert creds[0].psk == "1234"


def test_gesture_key_pull_requires_nonempty(tmp_path) -> None:
    from lockknife.modules.credentials.gesture import GestureKeyNotFound, pull_gesture_key

    dev = _FakeDevices()
    p = pull_gesture_key(dev, "SERIAL", tmp_path)  # type: ignore[arg-type]
    assert p.exists()

    def pull_empty(serial: str, remote_path: str, local_path: pathlib.Path, timeout_s: float = 0.0) -> None:
        local_path.parent.mkdir(parents=True, exist_ok=True)
        local_path.write_bytes(b"")

    dev.pull = pull_empty  # type: ignore[method-assign]
    with pytest.raises(GestureKeyNotFound):
        pull_gesture_key(dev, "SERIAL", tmp_path)  # type: ignore[arg-type]


def test_list_keystore() -> None:
    from lockknife.modules.credentials.keystore import list_keystore

    dev = _FakeDevices()
    rows = list_keystore(dev, "SERIAL")  # type: ignore[arg-type]
    assert rows[0].entries == ["entry1", "entry2"]


def test_crack_password_with_rules_fallback(tmp_path) -> None:
    lockknife_core = pytest.importorskip("lockknife.lockknife_core")
    from lockknife.modules.credentials.password import crack_password_with_rules

    wl = tmp_path / "w.txt"
    wl.write_text("Secret\n", encoding="utf-8")
    target = lockknife_core.sha256_hex(b"Secret7")
    found = crack_password_with_rules(target, "sha256", wl, max_suffix=10)
    assert found == "Secret7"


def test_crack_password_with_rules_leetspeak(tmp_path, monkeypatch) -> None:
    lockknife_core = pytest.importorskip("lockknife.lockknife_core")
    from lockknife.modules.credentials.password import crack_password_with_rules

    wl = tmp_path / "w2.txt"
    wl.write_text("test\n", encoding="utf-8")
    target = lockknife_core.sha256_hex(b"73$7")
    monkeypatch.setattr(lockknife_core, "dictionary_attack_rules", lambda *args, **kwargs: (_ for _ in ()).throw(RuntimeError("x")))
    found = crack_password_with_rules(target, "sha256", wl, max_suffix=0)
    assert found == "73$7"


def test_crack_password_with_rules_suffix_loop(tmp_path, monkeypatch) -> None:
    lockknife_core = pytest.importorskip("lockknife.lockknife_core")
    from lockknife.modules.credentials.password import crack_password_with_rules

    wl = tmp_path / "w3.txt"
    wl.write_text("test\n", encoding="utf-8")
    target = lockknife_core.sha256_hex(b"test5")
    monkeypatch.setattr(lockknife_core, "dictionary_attack_rules", lambda *args, **kwargs: (_ for _ in ()).throw(RuntimeError("x")))
    found = crack_password_with_rules(target, "sha256", wl, max_suffix=6)
    assert found == "test5"


def test_recover_gesture_from_keyfile_and_device(tmp_path) -> None:
    lockknife_core = pytest.importorskip("lockknife.lockknife_core")
    from lockknife.modules.credentials.gesture import recover_gesture, recover_gesture_from_keyfile

    key_bytes = bytes.fromhex(lockknife_core.sha1_hex(bytes([0, 1, 2, 3])))
    p = tmp_path / "gesture.key"
    p.write_bytes(key_bytes)
    assert recover_gesture_from_keyfile(p) == "1-2-3-4"

    class _Adb:
        def pull(self, serial: str, remote_path: str, local_path: pathlib.Path, timeout_s: float = 0.0) -> None:
            local_path.parent.mkdir(parents=True, exist_ok=True)
            local_path.write_bytes(key_bytes)

    class _Dev:
        _adb = _Adb()

        def pull(self, serial: str, remote_path: str, local_path: pathlib.Path, timeout_s: float = 0.0) -> None:
            return self._adb.pull(serial, remote_path, local_path, timeout_s=timeout_s)

        def has_root(self, serial: str) -> bool:
            return True

    assert recover_gesture(_Dev(), "SER") == "1-2-3-4"  # type: ignore[arg-type]

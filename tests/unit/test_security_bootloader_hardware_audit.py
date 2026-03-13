import dataclasses

from lockknife.core.device import DeviceInfo
from lockknife.modules.security.bootloader import analyze_bootloader
from lockknife.modules.security.device_audit import run_device_audit
from lockknife.modules.security.hardware import analyze_hardware_security


class _FakeDevices:
    def __init__(self, props: dict[str, str], *, root: bool) -> None:
        self._props = props
        self._root = root
        self._adb = self._Adb()

    class _Adb:
        def shell(self, serial: str, command: str, timeout_s: float = 0.0) -> str:
            if "settings get global adb_enabled" in command:
                return "1\n"
            if "settings get global development_settings_enabled" in command:
                return "1\n"
            if "settings get secure install_non_market_apps" in command:
                return "0\n"
            if "settings get global package_verifier_enable" in command:
                return "1\n"
            return "\n"

    def shell(self, serial: str, command: str, timeout_s: float = 0.0) -> str:
        return self._adb.shell(serial, command, timeout_s=timeout_s)

    def info(self, serial: str) -> DeviceInfo:
        return DeviceInfo(serial=serial, props=dict(self._props))

    def has_root(self, serial: str) -> bool:
        return bool(self._root)


def test_analyze_bootloader_maps_properties() -> None:
    dev = _FakeDevices(
        {
            "ro.boot.flash.locked": "1",
            "ro.boot.verifiedbootstate": "green",
            "ro.boot.vbmeta.device_state": "locked",
            "ro.boot.bootloader": "u-boot",
            "ro.boot.slot_suffix": "_a",
        },
        root=False,
    )
    st = analyze_bootloader(dev, "SERIAL")  # type: ignore[arg-type]
    assert st.flash_locked == "1"
    assert st.verifiedbootstate == "green"
    assert st.vbmeta_device_state == "locked"
    assert st.bootloader == "u-boot"
    assert st.slot_suffix == "_a"


def test_analyze_hardware_security_detects_strongbox() -> None:
    dev = _FakeDevices(
        {
            "ro.hardware.keymaster": "km",
            "ro.hardware.gatekeeper": "gk",
            "vendor.strongbox.enabled": "true",
        },
        root=False,
    )
    st = analyze_hardware_security(dev, "SERIAL")  # type: ignore[arg-type]
    assert st.keymaster_hw == "km"
    assert st.gatekeeper_hw == "gk"
    assert st.strongbox is True


def test_run_device_audit_includes_root_and_test_keys() -> None:
    dev = _FakeDevices({"ro.build.tags": "release-keys,test-keys", "ro.build.version.sdk": "30"}, root=True)
    findings = [dataclasses.asdict(f) for f in run_device_audit(dev, "SERIAL")]  # type: ignore[arg-type]
    ids = {f["id"] for f in findings}
    assert "test_keys" in ids
    assert "root" in ids

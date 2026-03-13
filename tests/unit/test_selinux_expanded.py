import dataclasses


def test_selinux_status_collects_policy_domains_denials() -> None:
    from lockknife.modules.security.selinux import get_selinux_status

    class _Adb:
        def shell(self, serial: str, command: str, timeout_s: float = 0.0) -> str:
            if command.startswith("getenforce"):
                return "Enforcing\n"
            if "policyvers" in command:
                return "33\n"
            if "/sys/fs/selinux/policy" in command:
                return "allow untrusted_app system_server:file read\npermissive isolated_app\n"
            if "ps -AZ" in command or "ps -Z" in command:
                return "u:r:untrusted_app:s0 u0_a123 123 0 0 S com.example\n"
            if "grep 'avc:'" in command:
                return "avc: denied { read } for pid=1 comm=x scontext=u:r:isolated_app:s0 tcontext=u:object_r:system_data_file:s0 tclass=file permissive=1\n"
            return ""

    class _Dev:
        _adb = _Adb()

        def shell(self, serial: str, command: str, timeout_s: float = 0.0) -> str:
            return self._adb.shell(serial, command, timeout_s=timeout_s)

        def has_root(self, serial: str) -> bool:
            return True

    st = get_selinux_status(_Dev(), "SER")  # type: ignore[arg-type]
    d = dataclasses.asdict(st)
    assert d["mode"] == "Enforcing"
    assert d["status"] == "Enforcing"
    assert d["policy_version"] == "33"
    assert "untrusted_app" in d["domains"]
    assert d["denials"]
    assert d["policy_analysis"]["policy_readable"] is True
    assert "isolated_app" in d["permissive_domains"]
    assert d["posture"]["risk_level"] == "high"
    assert d["denial_summary"]["count"] == 1
    assert d["remediation_hints"]

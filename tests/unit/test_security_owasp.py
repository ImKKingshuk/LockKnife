from lockknife.modules.security.owasp import mastg_summary


def test_mastg_summary_from_findings_list() -> None:
    artifacts = [{"id": "debuggable", "severity": "high"}]
    out = mastg_summary(artifacts)
    assert "MSTG-RESILIENCE-2" in out["mastg_ids"]
    assert "M10: Extraneous Functionality" in out["owasp_categories"]
    assert out["masvs_scorecard"]["status"] == "fail"


def test_mastg_summary_includes_apk_phase5_findings() -> None:
    artifacts = {
        "findings": [{"id": "weak_exported_provider", "severity": "high", "evidence": ["content://com.example.provider/users"]}],
        "risk_summary": {"score": 80},
    }
    out = mastg_summary(artifacts)
    assert "MSTG-PLATFORM-8" in out["mastg_ids"]
    assert out["coverage"]["mapped_finding_total"] == 1
    assert out["evidence_links"][0]["evidence"] == ["content://com.example.provider/users"]


def test_mastg_summary_builds_area_scorecard() -> None:
    out = mastg_summary(
        {
            "findings": [
                {"id": "component_permission_gap", "severity": "high", "evidence": ["DeepLinkActivity"]},
                {"id": "crypto_ecb_mode", "severity": "high"},
            ]
        }
    )

    areas = {item["area"]: item for item in out["masvs_scorecard"]["areas"]}
    assert areas["PLATFORM"]["status"] == "fail"
    assert areas["CRYPTO"]["status"] == "fail"
    assert any(check["triggered_by"] for check in areas["PLATFORM"]["checks"])

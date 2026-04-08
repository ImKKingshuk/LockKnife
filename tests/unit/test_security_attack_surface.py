from __future__ import annotations

import json
import pathlib

from lockknife.modules.security.attack_surface import assess_attack_surface


class _Devices:
    def __init__(self, outputs: dict[str, str]) -> None:
        self.outputs = outputs
        self.commands: list[str] = []

    def shell(self, serial: str, command: str, timeout_s: float = 30.0) -> str:
        assert serial == "SERIAL"
        self.commands.append(command)
        return self.outputs[command]


def test_assess_attack_surface_from_artifacts_builds_static_surface(tmp_path: pathlib.Path) -> None:
    artifacts = tmp_path / "apk_analysis.json"
    artifacts.write_text(
        json.dumps(
            {
                "manifest": {
                    "package": "com.example.app",
                    "components": {
                        "activities": [
                            {"name": "DeepLinkActivity", "exported": True, "permission": None}
                        ],
                        "interaction_analysis": {
                            "overlaps": [
                                {
                                    "scheme": "myapp",
                                    "components": ["DeepLinkActivity", "DeepLinkSecondary"],
                                }
                            ],
                            "permission_gaps": [
                                {"component": "DeepLinkActivity", "bucket": "activities"}
                            ],
                            "custom_scheme_overlaps": [
                                {
                                    "scheme": "myapp",
                                    "components": ["DeepLinkActivity", "DeepLinkSecondary"],
                                }
                            ],
                        },
                        "providers": [
                            {
                                "name": "ExampleProvider",
                                "exported": True,
                                "permission": None,
                                "authorities": ["com.example.provider"],
                                "read_permission": None,
                                "write_permission": None,
                                "grant_uri_permissions": True,
                            }
                        ],
                        "deeplinks": [
                            {"component": "DeepLinkActivity", "uri": "myapp://example/path"}
                        ],
                        "summary": {
                            "exported_total": 2,
                            "browsable_deeplink_total": 1,
                            "provider_weak_permission_total": 1,
                            "intent_filter_overlap_total": 1,
                            "component_permission_gap_total": 1,
                        },
                    },
                }
            }
        ),
        encoding="utf-8",
    )

    report = assess_attack_surface(None, artifacts_path=artifacts)

    assert report["package"] == "com.example.app"
    assert report["surface"]["summary"]["exported_total"] == 2
    assert report["surface"]["summary"]["browsable_deeplink_total"] == 1
    assert report["surface"]["summary"]["provider_weak_permission_total"] == 1
    assert report["static_analysis"]["review_queue"]
    assert report["surface"]["summary"]["component_permission_gap_total"] == 1
    assert report["surface"]["component_clusters"]["provider"]
    finding_ids = {finding["id"] for finding in report["findings"]}
    assert "exported_components" in finding_ids
    assert "browsable_deeplinks" in finding_ids
    assert "weak_exported_provider" in finding_ids
    assert "intent_filter_overlap" in finding_ids
    assert "component_permission_gap" in finding_ids
    assert report["risk_summary"]["level"] in {"medium", "high"}
    assert report["risk_summary"]["score_breakdown"]
    assert set(report["mastg"]["mastg_ids"]) >= {"MSTG-PLATFORM-3", "MSTG-PLATFORM-8"}
    assert "M1: Improper Platform Usage" in report["mastg"]["owasp_categories"]


def test_assess_attack_surface_runs_safe_live_probes(tmp_path: pathlib.Path) -> None:
    artifacts = tmp_path / "apk_analysis.json"
    artifacts.write_text(
        json.dumps(
            {
                "manifest": {
                    "package": "com.example.app",
                    "components": {
                        "providers": [
                            {
                                "name": "ExampleProvider",
                                "exported": True,
                                "authorities": ["com.example.provider"],
                                "read_permission": None,
                                "write_permission": None,
                                "grant_uri_permissions": True,
                            }
                        ],
                        "activities": [
                            {
                                "name": "DeepLinkActivity",
                                "exported": True,
                                "permission": None,
                                "actions": ["android.intent.action.VIEW"],
                                "probe_uri": "myapp://example/path",
                            }
                        ],
                        "deeplinks": [
                            {"component": "DeepLinkActivity", "uri": "myapp://example/path"}
                        ],
                        "interaction_analysis": {
                            "permission_gaps": [
                                {"component": "DeepLinkActivity", "bucket": "activities"}
                            ]
                        },
                    },
                }
            }
        ),
        encoding="utf-8",
    )
    devices = _Devices(
        {
            "pm path com.example.app": "package:/data/app/com.example.app/base.apk\n",
            "cmd package query-intent-activities -a android.intent.action.VIEW -d myapp://example/path": "com.example.app/.DeepLinkActivity\n",
            "cmd package resolve-activity --brief -n DeepLinkActivity": "com.example.app/.DeepLinkActivity\n",
            "cmd package resolve-content-provider com.example.provider": "com.example.app/.ExampleProvider\n",
        }
    )

    report = assess_attack_surface(devices, serial="SERIAL", artifacts_path=artifacts)

    assert report["probe_results"]["attempted"] is True
    assert report["probe_results"]["package_present"] is True
    assert report["probe_results"]["summary"]["deeplink_resolved_total"] == 1
    assert report["probe_results"]["summary"]["provider_resolved_total"] == 1
    assert report["probe_results"]["summary"]["component_permission_gap_total"] == 1
    assert report["live_analysis"]["review_queue"]
    finding_ids = {finding["id"] for finding in report["findings"]}
    assert "live_deeplink_resolution" in finding_ids
    assert "live_provider_resolution" in finding_ids
    assert "live_component_permission_gap" in finding_ids
    assert report["risk_summary"]["exploitability"] == "high"
    assert report["risk_summary"]["evidence_strength"] == "strong"

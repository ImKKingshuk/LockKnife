from __future__ import annotations

import pathlib

import pytest

from lockknife.core.exceptions import LockKnifeError
from lockknife.core.pipeline.dag import build_dag
from lockknife.core.pipeline.playbooks import (
    BUILTIN_PLAYBOOKS,
    get_playbook,
    list_playbooks,
    load_custom_playbook,
)


def test_builtin_playbooks_exist_and_are_valid_dags() -> None:
    expected_playbooks = {"triage", "deep-forensics", "incident-response", "crypto-audit", "full-spectrum"}
    assert set(BUILTIN_PLAYBOOKS.keys()) == expected_playbooks

    for name in expected_playbooks:
        pb = get_playbook(name)
        assert pb.name == name
        assert len(pb.steps) > 0
        # Verify DAG validity (no cycles, no missing dependencies)
        dag = build_dag(pb.steps)
        assert dag.step_count == len(pb.steps)


def test_unknown_playbook_raises() -> None:
    with pytest.raises(LockKnifeError, match="Unknown playbook 'invalid-pb'"):
        get_playbook("invalid-pb")


def test_list_playbooks() -> None:
    pbs = list_playbooks()
    assert len(pbs) == len(BUILTIN_PLAYBOOKS)


def test_load_custom_playbook_json(tmp_path: pathlib.Path) -> None:
    json_file = tmp_path / "custom.json"
    json_file.write_text(
        """{
            "name": "json-test",
            "title": "JSON Playbook",
            "description": "Testing json",
            "category": "custom",
            "steps": [
                {
                    "step_id": "step.1",
                    "label": "First Step",
                    "action_id": "security.scan",
                    "category": "security"
                }
            ]
        }""",
        encoding="utf-8",
    )
    pb = load_custom_playbook(json_file)
    assert pb.name == "json-test"
    assert pb.title == "JSON Playbook"
    assert len(pb.steps) == 1
    assert pb.steps[0].action_id == "security.scan"


def test_load_custom_playbook_yaml(tmp_path: pathlib.Path) -> None:
    yaml_file = tmp_path / "custom.yaml"
    yaml_file.write_text(
        """name: yaml-test
title: YAML Playbook
description: Testing yaml
category: custom
steps:
  - step_id: step.1
    label: Root Step
    action_id: device.info
    category: device
  - step_id: step.2
    label: Scan Step
    action_id: security.scan
    category: security
    depends_on:
      - step.1
""",
        encoding="utf-8",
    )
    pb = load_custom_playbook(yaml_file)
    assert pb.name == "yaml-test"
    assert len(pb.steps) == 2
    dag = build_dag(pb.steps)
    assert dag.step_count == 2


def test_load_missing_file_raises(tmp_path: pathlib.Path) -> None:
    with pytest.raises(LockKnifeError, match="Playbook file not found"):
        load_custom_playbook(tmp_path / "missing.yaml")

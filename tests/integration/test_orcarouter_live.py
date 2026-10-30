"""Live OrcaRouter Cyber Inference checks, enabled only when a key is present.

These use the provider code path implemented in this change (no standalone
curl): configuration resolution, catalog discovery, and one real chat request.
The key is read from ORCAROUTER_API_KEY and never printed or stored.
"""

from __future__ import annotations

import os
import pathlib

import pytest
from click.testing import CliRunner

from lockknife.core.agent import orcarouter
from lockknife.core.agent.provider import OpenAICompatibleProvider, ProviderConfig
from lockknife_headless_cli.agent import agent_group
from lockknife_headless_cli.main import cli

pytestmark = pytest.mark.skipif(
    not os.getenv("ORCAROUTER_API_KEY"), reason="ORCAROUTER_API_KEY not configured"
)

# Our verification key is not business-verified, so the documented
# orcarouter/auto route, the dedicated cyber tier and orcarouter/fusion all
# answer 403 for it. Prove the wiring with a public text model the key can use.
LIVE_MODEL = os.getenv("ORCAROUTER_LIVE_MODEL", "deepseek/deepseek-v4.1-flash")


def test_live_catalog_through_cli(monkeypatch: pytest.MonkeyPatch) -> None:
    import lockknife_headless_cli.agent as agent_mod

    monkeypatch.setattr(agent_mod, "_ORCAROUTER_CATALOG", orcarouter.ModelCatalogCache())
    result = CliRunner().invoke(agent_group, ["models", "--format", "json"])
    assert result.exit_code == 0, result.output
    output = result.output
    start = output.index("{\n")
    import json

    payload = json.loads(output[start : output.rindex("}") + 1])
    assert payload["catalog_source"] == "live"
    assert payload["model_count"] > 0
    for model in payload["models"]:
        assert model["id"]
    assert os.environ["ORCAROUTER_API_KEY"] not in output


def test_live_chat_through_provider() -> None:
    cfg = ProviderConfig.for_orcarouter(api_key=os.getenv("ORCAROUTER_API_KEY"), model=LIVE_MODEL)
    assert cfg.api_base == "https://api.orcarouter.ai/v1"
    decision = OpenAICompatibleProvider(cfg).complete(
        [{"role": "user", "content": "Reply with the single word: ready"}]
    )
    assert decision.text
    assert os.environ["ORCAROUTER_API_KEY"] not in decision.text


def test_live_agent_goal_via_orcarouter(tmp_path: pathlib.Path) -> None:
    result = CliRunner().invoke(
        cli,
        [
            "--cli",
            "agent",
            "goal",
            "Summarize the current workspace status",
            "--provider",
            "orcarouter",
            "--model",
            LIVE_MODEL,
            "--case-dir",
            str(tmp_path / "orca_live_case"),
            "--budget",
            "1",
            "--format",
            "json",
        ],
    )
    assert result.exit_code in (0, 1), result.output
    assert os.environ["ORCAROUTER_API_KEY"] not in result.output
    # A rejected-key path must say so rather than hang or retry forever.
    assert "Provider connection failure: HTTPError" not in result.output

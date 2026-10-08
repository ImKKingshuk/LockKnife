from __future__ import annotations

import dataclasses
import json
import logging
import os
import pathlib
import time
from typing import Any

from lockknife.core.agent.models import AgentGoal, ToolObservation, TurnRecord

logger = logging.getLogger("lockknife.agent.memory")

_CHARS_PER_TOKEN = 4
_DEFAULT_MAX_CONTEXT_TOKENS = 12000
_MAX_OBSERVATION_CHARS = 4000


@dataclasses.dataclass
class WorkingMemory:
    """Active in-memory working state for the current run."""
    goal: AgentGoal
    scratchpad: list[str] = dataclasses.field(default_factory=list)
    recent_turns: list[TurnRecord] = dataclasses.field(default_factory=list)

    def add_scratchpad_note(self, note: str) -> None:
        self.scratchpad.append(note.strip())


class MemoryStore:
    """Three-tier memory manager: Working, Episodic (CaseStore), and Semantic Facts."""

    def __init__(
        self,
        case_dir: pathlib.Path,
        max_context_tokens: int = _DEFAULT_MAX_CONTEXT_TOKENS,
    ) -> None:
        self.case_dir = pathlib.Path(case_dir).resolve()
        self.max_context_tokens = max_context_tokens
        self.agent_dir = self.case_dir / ".agent"
        self.memory_dir = self.agent_dir / "memory"
        self.artifacts_dir = self.agent_dir / "artifacts"
        self.facts_path = self.agent_dir / "facts.json"

        self.agent_dir.mkdir(parents=True, exist_ok=True)
        self.memory_dir.mkdir(parents=True, exist_ok=True)
        self.artifacts_dir.mkdir(parents=True, exist_ok=True)

        self._facts: dict[str, Any] = self._load_facts()

    def _load_facts(self) -> dict[str, Any]:
        if self.facts_path.exists():
            try:
                return json.loads(self.facts_path.read_text(encoding="utf-8"))
            except Exception as exc:
                logger.warning("Failed to load facts from %s: %s", self.facts_path, exc)
        return {}

    def save_facts(self) -> None:
        try:
            self.facts_path.write_text(json.dumps(self._facts, indent=2), encoding="utf-8")
        except Exception as exc:
            logger.warning("Failed to save facts to %s: %s", self.facts_path, exc)

    def set_fact(self, key: str, value: Any) -> None:
        """Store or update a semantic fact about the device or investigation."""
        self._facts[key] = value
        self.save_facts()

    def get_facts(self) -> dict[str, Any]:
        return dict(self._facts)

    def persist_turn(self, turn: TurnRecord) -> None:
        """Save turn record into episodic memory."""
        turn_file = self.memory_dir / f"turn_{turn.turn_index:04d}.json"
        try:
            turn_file.write_text(json.dumps(turn.to_dict(), indent=2), encoding="utf-8")
        except Exception as exc:
            logger.warning("Failed to persist turn %d to %s: %s", turn.turn_index, turn_file, exc)

    def load_episodic_turns(self) -> list[dict[str, Any]]:
        """Load all persisted turns from the case memory."""
        turns: list[dict[str, Any]] = []
        for file in sorted(self.memory_dir.glob("turn_*.json")):
            try:
                turns.append(json.loads(file.read_text(encoding="utf-8")))
            except Exception:
                continue
        return turns

    def truncate_observation_payload(self, tool_id: str, payload: Any) -> tuple[Any, str | None]:
        """Truncate large tool outputs, writing full output to an artifact file."""
        text = json.dumps(payload, default=str) if not isinstance(payload, str) else payload
        if len(text) <= _MAX_OBSERVATION_CHARS:
            return payload, None

        # Content exceeds max chars - spill to disk
        timestamp = int(time.time() * 1000)
        safe_tool = tool_id.replace(".", "_")
        artifact_path = self.artifacts_dir / f"obs_{safe_tool}_{timestamp}.txt"
        try:
            artifact_path.write_text(text, encoding="utf-8")
        except Exception as exc:
            logger.warning("Failed to write artifact: %s", exc)

        preview = (
            text[:_MAX_OBSERVATION_CHARS]
            + f"\n\n[... Truncated {len(text) - _MAX_OBSERVATION_CHARS} chars. "
            + f"Full output saved to: {artifact_path}]"
        )
        return preview, str(artifact_path)

    def build_llm_messages(
        self,
        working_memory: WorkingMemory,
        consolidated_summary: str | None = None,
    ) -> list[dict[str, Any]]:
        """Construct the prompt messages array for the LLM with auto-compaction."""
        messages: list[dict[str, Any]] = []

        # 1. System/Goal message
        facts_summary = json.dumps(self._facts) if self._facts else "None recorded yet."
        scratchpad_text = "\n".join(f"- {note}" for note in working_memory.scratchpad) or "None."

        context_header = (
            f"=== MISSION OBJECTIVE ===\n{working_memory.goal.objective}\n\n"
            f"Target Device: {working_memory.goal.target_device or 'Auto-detect'}\n"
            f"Case Directory: {self.case_dir}\n\n"
            f"=== KNOWN SEMANTIC FACTS ===\n{facts_summary}\n\n"
            f"=== WORKING SCRATCHPAD ===\n{scratchpad_text}\n"
        )
        if consolidated_summary:
            context_header += (
                f"\n=== PRIOR CONSOLIDATED INVESTIGATION SUMMARY ===\n{consolidated_summary}\n"
            )

        messages.append({"role": "user", "content": context_header})

        # 2. Append turns
        for turn in working_memory.recent_turns:
            if turn.decision.tool_calls:
                messages.append({
                    "role": "assistant",
                    "content": turn.decision.reasoning or turn.decision.text or "",
                    "tool_calls": [
                        {
                            "id": tc.call_id,
                            "type": "function",
                            "function": {
                                "name": tc.tool_id,
                                "arguments": json.dumps(tc.arguments),
                            },
                        }
                        for tc in turn.decision.tool_calls
                    ],
                })
            elif turn.decision.text or turn.decision.reasoning:
                messages.append({
                    "role": "assistant",
                    "content": turn.decision.text or turn.decision.reasoning or "",
                })

            for obs in turn.observations:
                messages.append({
                    "role": "tool",
                    "tool_call_id": obs.call_id,
                    "content": json.dumps(obs.to_dict(), default=str),
                })

        return messages

    def check_and_compact(
        self,
        working_memory: WorkingMemory,
        consolidated_summary: str | None,
    ) -> tuple[WorkingMemory, str | None]:
        """Perform AutoCompact if estimated tokens exceed max_context_tokens."""
        messages = self.build_llm_messages(working_memory, consolidated_summary)
        total_chars = sum(len(str(m.get("content", ""))) for m in messages)
        estimated_tokens = total_chars // _CHARS_PER_TOKEN

        if estimated_tokens <= self.max_context_tokens or len(working_memory.recent_turns) <= 4:
            return working_memory, consolidated_summary

        # AutoCompact: Keep the last 3 turns, compress older turns into bulleted summary
        older_turns = working_memory.recent_turns[:-3]
        preserved_turns = working_memory.recent_turns[-3:]

        summary_bullets: list[str] = []
        if consolidated_summary:
            summary_bullets.append(consolidated_summary)

        for t in older_turns:
            t_summary = f"- Turn {t.turn_index}: "
            if t.decision.tool_calls:
                t_tools = ", ".join(tc.tool_id for tc in t.decision.tool_calls)
                obs_status = "succeeded" if all(o.success for o in t.observations) else "had errors"
                t_summary += f"Executed [{t_tools}] -> {obs_status}."
            elif t.decision.text:
                t_summary += f"Reasoned: {t.decision.text[:120]}..."
            summary_bullets.append(t_summary)

        new_summary = "\n".join(summary_bullets)
        working_memory.recent_turns = preserved_turns
        logger.info(
            "AutoCompact triggered: compacted %d turns into consolidated summary",
            len(older_turns),
        )
        return working_memory, new_summary

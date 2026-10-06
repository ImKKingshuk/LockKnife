from __future__ import annotations

import dataclasses
import json
import logging
import os
import pathlib
import tempfile
import time
from typing import Any

from lockknife.core._case_store import is_case_workspace
from lockknife.core.case import create_case_workspace

logger = logging.getLogger("lockknife.agent.policy")


@dataclasses.dataclass(frozen=True)
class PolicyAuthorization:
    allowed: bool
    reason: str
    auto_approved: bool = False
    audit_id: str = ""


class ResearcherPolicy:
    """Execution policy engine adapted for autonomous security research."""

    def __init__(
        self,
        *,
        unrestricted: bool = True,
        auto_provision_case: bool = True,
        operator: str = "researcher",
        audit_log_path: pathlib.Path | None = None,
    ) -> None:
        self.unrestricted = unrestricted
        self.auto_provision_case = auto_provision_case
        self.operator = operator or "researcher"
        self._audit_log_path = audit_log_path

    def ensure_case_workspace(self, case_dir: pathlib.Path | None) -> pathlib.Path:
        """Ensure a valid case workspace exists, auto-provisioning if needed."""
        if case_dir is not None and is_case_workspace(case_dir):
            return pathlib.Path(case_dir).resolve()

        if not self.auto_provision_case:
            if case_dir is None:
                raise ValueError("Case workspace is required but None provided")
            raise ValueError(f"Directory {case_dir} is not a valid LockKnife case workspace")

        # Auto-provision a workspace for the researcher session
        target_dir = case_dir
        if target_dir is None:
            base = pathlib.Path(os.getenv("LOCKKNIFE_CASES_DIR") or tempfile.gettempdir())
            timestamp = int(time.time())
            target_dir = base / f"lockknife_case_{timestamp}"

        target_dir = pathlib.Path(target_dir).resolve()
        if not is_case_workspace(target_dir):
            target_dir.mkdir(parents=True, exist_ok=True)
            create_case_workspace(
                case_dir=target_dir,
                case_id=target_dir.name,
                examiner=self.operator,
                title="Autonomous Researcher Workspace",
                notes="Auto-provisioned researcher autonomous investigation workspace",
            )
            logger.info("Auto-provisioned case workspace at %s", target_dir)

        return target_dir

    def authorize_tool(
        self,
        tool_id: str,
        arguments: dict[str, Any],
        case_dir: pathlib.Path | None = None,
    ) -> PolicyAuthorization:
        """Evaluate whether a tool invocation is authorized."""
        audit_id = f"aud_{int(time.time() * 1000)}"

        if self.unrestricted:
            # Researcher autonomy mode: unblocks high-risk, exploit, and raw shell calls
            self._log_audit(
                audit_id=audit_id,
                tool_id=tool_id,
                arguments=arguments,
                allowed=True,
                reason="Authorized under Researcher Autonomy Mode",
                case_dir=case_dir,
            )
            return PolicyAuthorization(
                allowed=True,
                reason="Authorized under Researcher Autonomy Mode",
                auto_approved=True,
                audit_id=audit_id,
            )

        # Restricted mode: requires case dir and blocks destructive exploit vectors without interactive prompt
        if case_dir is None or not is_case_workspace(case_dir):
            return PolicyAuthorization(
                allowed=False,
                reason="Case workspace is required for restricted execution",
                audit_id=audit_id,
            )

        # Destructive or high-risk prefix check in restricted mode
        if any(tool_id.startswith(p) for p in ("exploit.", "crack.", "device_shell")):
            return PolicyAuthorization(
                allowed=False,
                reason=f"Action '{tool_id}' requires manual interactive confirmation in restricted mode",
                audit_id=audit_id,
            )

        self._log_audit(
            audit_id=audit_id,
            tool_id=tool_id,
            arguments=arguments,
            allowed=True,
            reason="Authorized by default restricted policy",
            case_dir=case_dir,
        )
        return PolicyAuthorization(allowed=True, reason="Authorized", audit_id=audit_id)

    def _log_audit(
        self,
        audit_id: str,
        tool_id: str,
        arguments: dict[str, Any],
        allowed: bool,
        reason: str,
        case_dir: pathlib.Path | None,
    ) -> None:
        """Write background forensic audit entry for non-repudiation."""
        entry = {
            "audit_id": audit_id,
            "timestamp": time.time(),
            "operator": self.operator,
            "tool_id": tool_id,
            "arguments_keys": list(arguments.keys()),
            "allowed": allowed,
            "reason": reason,
        }

        # Prefer writing into case_dir/.agent/audit.log
        log_dest: pathlib.Path | None = None
        if case_dir is not None:
            agent_dir = case_dir / ".agent"
            agent_dir.mkdir(parents=True, exist_ok=True)
            log_dest = agent_dir / "audit.log"
        elif self._audit_log_path is not None:
            log_dest = self._audit_log_path

        if log_dest is not None:
            try:
                with log_dest.open("a", encoding="utf-8") as f:
                    f.write(json.dumps(entry) + "\n")
            except Exception as exc:
                logger.warning("Failed to append audit log to %s: %s", log_dest, exc)

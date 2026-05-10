from __future__ import annotations

import dataclasses
import pathlib
import subprocess  # nosec B404
import time
from collections.abc import Mapping, Sequence
from typing import Any, Literal

from lockknife.core._case_store import CaseStore, is_case_workspace

RiskLevel = Literal["low", "medium", "high", "critical"]
ExecutionMode = Literal["dry-run", "lab-live"]
CapabilityStatus = Literal[
    "implemented-live",
    "dependency-gated",
    "poc-only",
    "simulated",
    "not-implemented",
]


@dataclasses.dataclass(frozen=True)
class ExecutionIntent:
    operator: str
    case_dir: pathlib.Path
    target: str
    vector: str
    risk: RiskLevel
    mode: ExecutionMode
    capability_status: CapabilityStatus
    confirmed: bool = False


@dataclasses.dataclass(frozen=True)
class PolicyDecision:
    allowed: bool
    reason: str
    intent: ExecutionIntent


@dataclasses.dataclass(frozen=True)
class ExecutionPreview:
    intent: ExecutionIntent
    command: tuple[str, ...] = ()
    target: str = ""
    files_touched: tuple[str, ...] = ()
    network_endpoints: tuple[str, ...] = ()
    dry_run: bool = True

    def to_dict(self) -> dict[str, object]:
        return {
            "operator": self.intent.operator,
            "case_dir": str(self.intent.case_dir),
            "target": self.target or self.intent.target,
            "vector": self.intent.vector,
            "risk": self.intent.risk,
            "mode": self.intent.mode,
            "capability_status": self.intent.capability_status,
            "command": list(self.command),
            "files_touched": list(self.files_touched),
            "network_endpoints": list(self.network_endpoints),
            "dry_run": self.dry_run,
        }


@dataclasses.dataclass(frozen=True)
class ExecutionResult:
    intent: ExecutionIntent
    preview: ExecutionPreview
    stdout: str = ""
    stderr: str = ""
    return_code: int = 0
    duration_s: float = 0.0
    dry_run: bool = False

    def to_dict(self) -> dict[str, object]:
        return {
            **self.preview.to_dict(),
            "stdout": self.stdout,
            "stderr": self.stderr,
            "return_code": self.return_code,
            "duration_s": self.duration_s,
            "dry_run": self.dry_run,
        }


class ExecutionPolicy:
    def authorize(self, intent: ExecutionIntent) -> PolicyDecision:
        if not intent.operator.strip() or intent.operator == "unknown":
            return PolicyDecision(False, "Operator identity is required", intent)
        if not intent.target.strip():
            return PolicyDecision(False, "Target scope is required", intent)
        if not is_case_workspace(intent.case_dir):
            return PolicyDecision(False, "Case workspace is required", intent)
        if intent.mode == "dry-run":
            return PolicyDecision(True, "Dry-run authorized", intent)
        if intent.capability_status in {"simulated", "not-implemented", "poc-only"}:
            return PolicyDecision(
                False,
                f"Capability status '{intent.capability_status}' cannot run live",
                intent,
            )
        if intent.mode != "lab-live":
            return PolicyDecision(False, "Unsupported execution mode", intent)
        if intent.risk in {"high", "critical"} and not intent.confirmed:
            return PolicyDecision(False, "High-risk live execution requires confirmation", intent)
        if intent.capability_status != "implemented-live":
            return PolicyDecision(
                False, "Live execution requires implemented-live capability", intent
            )
        return PolicyDecision(True, "Lab live execution authorized", intent)


class ExecutionGateway:
    def __init__(self, policy: ExecutionPolicy | None = None) -> None:
        self.policy = policy or ExecutionPolicy()

    def authorize(self, intent: ExecutionIntent) -> PolicyDecision:
        decision = self.policy.authorize(intent)
        self._audit(
            intent, "execution.policy", {"allowed": decision.allowed, "reason": decision.reason}
        )
        return decision

    def preview(
        self,
        intent: ExecutionIntent,
        *,
        command: Sequence[str] = (),
        files_touched: Sequence[str] = (),
        network_endpoints: Sequence[str] = (),
    ) -> ExecutionPreview:
        return ExecutionPreview(
            intent=intent,
            command=tuple(command),
            target=intent.target,
            files_touched=tuple(files_touched),
            network_endpoints=tuple(network_endpoints),
            dry_run=intent.mode == "dry-run",
        )

    def require_authorized(self, intent: ExecutionIntent) -> PolicyDecision:
        decision = self.authorize(intent)
        if not decision.allowed:
            raise PermissionError(decision.reason)
        return decision

    def run_subprocess(
        self,
        intent: ExecutionIntent,
        command: Sequence[str],
        *,
        timeout_s: float = 30.0,
        metadata: Mapping[str, object] | None = None,
    ) -> ExecutionResult:
        preview = self.preview(intent, command=command)
        self.require_authorized(intent)
        if intent.mode == "dry-run":
            result = ExecutionResult(intent=intent, preview=preview, dry_run=True)
            self._audit(
                intent, "execution.dry_run", {"preview": preview.to_dict(), **dict(metadata or {})}
            )
            return result
        start = time.time()
        proc = subprocess.run(  # nosec B603
            list(command),
            capture_output=True,
            text=True,
            timeout=timeout_s,
            check=False,
        )
        result = ExecutionResult(
            intent=intent,
            preview=preview,
            stdout=proc.stdout,
            stderr=proc.stderr,
            return_code=proc.returncode,
            duration_s=time.time() - start,
            dry_run=False,
        )
        self._audit(intent, "execution.result", {**result.to_dict(), **dict(metadata or {})})
        return result

    def run_adb(
        self,
        intent: ExecutionIntent,
        argv: Sequence[str],
        *,
        adb_path: str = "adb",
        timeout_s: float = 30.0,
    ) -> ExecutionResult:
        return self.run_subprocess(intent, [adb_path, *argv], timeout_s=timeout_s)

    def run_adb_shell(
        self,
        intent: ExecutionIntent,
        serial: str,
        command: str,
        *,
        adb_path: str = "adb",
        timeout_s: float = 30.0,
    ) -> ExecutionResult:
        return self.run_adb(
            intent,
            ["-s", serial, "shell", command],
            adb_path=adb_path,
            timeout_s=timeout_s,
        )

    def authorize_external_http(
        self,
        intent: ExecutionIntent,
        *,
        method: str,
        url: str,
        metadata: Mapping[str, object] | None = None,
    ) -> ExecutionPreview:
        preview = self.preview(
            intent,
            command=(method.upper(), url),
            network_endpoints=(url,),
        )
        self.require_authorized(intent)
        event_type = "execution.dry_run" if intent.mode == "dry-run" else "execution.authorized"
        self._audit(
            intent,
            event_type,
            {"preview": preview.to_dict(), "http_method": method.upper(), **dict(metadata or {})},
        )
        return preview

    def authorize_plugin_load(
        self,
        intent: ExecutionIntent,
        *,
        source: str,
        metadata: Mapping[str, object] | None = None,
    ) -> ExecutionPreview:
        preview = self.preview(intent, command=("plugin.load", source))
        self.require_authorized(intent)
        event_type = "execution.dry_run" if intent.mode == "dry-run" else "execution.authorized"
        self._audit(
            intent,
            event_type,
            {"preview": preview.to_dict(), "plugin_source": source, **dict(metadata or {})},
        )
        return preview

    def _audit(
        self, intent: ExecutionIntent, event_type: str, payload: Mapping[str, object]
    ) -> None:
        if intent.case_dir:
            try:
                CaseStore.open(intent.case_dir).append_event(
                    "execution",
                    f"{intent.vector}:{intent.target}",
                    event_type,
                    {
                        "target": intent.target,
                        "vector": intent.vector,
                        "risk": intent.risk,
                        "mode": intent.mode,
                        "capability_status": intent.capability_status,
                        **dict(payload),
                    },
                    actor=intent.operator,
                )
            except Exception:
                if intent.mode != "dry-run":
                    raise


def _risk_level(value: object) -> RiskLevel:
    raw = str(getattr(value, "value", value) or "medium").strip().lower()
    if raw in {"safe", "low"}:
        return "low"
    if raw == "medium":
        return "medium"
    if raw == "high":
        return "high"
    if raw == "critical":
        return "critical"
    return "medium"


def execution_intent_from_scope(
    scope: Any,
    *,
    target: str,
    vector: str,
    risk: object = "medium",
    capability_status: CapabilityStatus = "implemented-live",
    confirmed: bool | None = None,
) -> ExecutionIntent:
    """Build an execution-policy intent from an exploitation authorization scope."""
    case_dir = getattr(scope, "case_dir", None)
    if case_dir is None:
        raise ValueError("case_dir is required for policy-gated execution")
    mode: ExecutionMode = "dry-run" if bool(getattr(scope, "dry_run", False)) else "lab-live"
    return ExecutionIntent(
        operator=str(getattr(scope, "operator", "") or "unknown"),
        case_dir=pathlib.Path(case_dir),
        target=target,
        vector=vector,
        risk=_risk_level(risk),
        mode=mode,
        capability_status=capability_status,
        confirmed=bool(getattr(scope, "lab_mode", False)) if confirmed is None else confirmed,
    )


def maybe_execution_intent_from_scope(
    scope: Any,
    *,
    target: str,
    vector: str,
    risk: object = "medium",
    capability_status: CapabilityStatus = "implemented-live",
    confirmed: bool | None = None,
) -> ExecutionIntent | None:
    """Return an intent when the scope has case context; otherwise leave legacy flow untouched."""
    if getattr(scope, "case_dir", None) is None:
        return None
    return execution_intent_from_scope(
        scope,
        target=target,
        vector=vector,
        risk=risk,
        capability_status=capability_status,
        confirmed=confirmed,
    )

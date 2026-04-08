from __future__ import annotations

from collections.abc import Callable
from typing import Any, cast


def handle(app: Any, action: str, params: dict[str, Any], *, cb: Any) -> dict[str, Any] | None:
    dataclasses = cb.dataclasses
    json = cb.json
    pathlib = cb.pathlib
    _ok = cast(Callable[[Any, str], dict[str, Any]], cb._ok)
    _err = cast(Callable[[str], dict[str, Any]], cb._err)
    _require = cb._require
    _opt = cb._opt
    _path_param = cb._path_param
    _csv_list = cb._csv_list
    _resolve_case_output = cb._resolve_case_output
    _register_case_output = cb._register_case_output
    _safe_name = cb._safe_name
    case_output_path = cb.case_output_path
    write_json = cb.write_json
    parse_directory_as_aleapp = cb.parse_directory_as_aleapp
    detect_iocs = cb.detect_iocs

    if action == "analyze.evidence":
        input_dir = pathlib.Path(_require(params, "input_dir"))
        patterns = _csv_list(params.get("patterns")) or []
        case_dir = _path_param(params.get("case_dir"))
        output, _derived = _resolve_case_output(
            _path_param(params.get("output")),
            case_dir,
            area="derived",
            filename=f"analyze_evidence_{_safe_name(input_dir.name)}.json",
        )
        artifacts = parse_directory_as_aleapp(input_dir)
        all_records = []
        for a in artifacts:
            all_records.extend(a.records)
        iocs = [dataclasses.asdict(m) for m in detect_iocs(all_records)]
        pat_hits = []
        for p in input_dir.glob("*.dex"):
            try:
                from lockknife.modules.security.malware import scan_with_patterns

                pat_hits.append({"file": str(p), "hits": scan_with_patterns(list(patterns), p)})
            except Exception:
                cb.log.debug("evidence_dex_scan_failed", exc_info=True, path=str(p))
                continue
        payload = {
            "artifacts": [dataclasses.asdict(a) for a in artifacts],
            "iocs": iocs,
            "pattern_hits": pat_hits,
        }
        if output is not None:
            write_json(output, payload)
            _register_case_output(
                case_dir,
                path=output,
                category="analyze-evidence",
                source_command="analyze evidence",
                input_paths=[str(input_dir)],
                metadata={
                    "patterns": list(patterns),
                    "artifact_count": len(artifacts),
                    "ioc_count": len(iocs),
                },
            )
            return _ok(
                payload,
                f"Analyzed evidence directory: {len(artifacts)} artifacts, {len(iocs)} IOCs saved to {output}",
            )
        return _ok(
            payload, f"Analyzed evidence directory: {len(artifacts)} artifacts, {len(iocs)} IOCs"
        )

    return None

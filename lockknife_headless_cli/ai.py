from __future__ import annotations

import json
import pathlib
import re

import click

from lockknife.core.case import case_output_path, register_case_artifact
from lockknife.core.cli_instrumentation import LockKnifeGroup
from lockknife.core.cli_types import READABLE_FILE
from lockknife.core.output import console
from lockknife.core.serialize import write_json
from lockknife.modules._case_enrichment_payloads import anomaly_payload, password_payload
from lockknife.modules.ai.anomaly import anomaly_scores
from lockknife.modules.ai.malware_classifier import predict_classifier, train_classifier
from lockknife.modules.ai.password_predictor import PasswordPredictor, load_personal_data


@click.group(help="AI/ML helpers for anomaly scoring and classification.", cls=LockKnifeGroup)
def ai() -> None:
    pass


def _safe_name(value: str) -> str:
    return re.sub(r"[^A-Za-z0-9._-]+", "_", value).strip("._") or "ai"


def _resolve_case_output(output: pathlib.Path | None, case_dir: pathlib.Path | None, *, filename: str) -> tuple[pathlib.Path | None, bool]:
    if output is not None:
        return output, False
    if case_dir is None:
        return None, False
    return case_output_path(case_dir, area="derived", filename=filename), True


def _register_ai_output(
    *,
    case_dir: pathlib.Path | None,
    output: pathlib.Path,
    category: str,
    source_command: str,
    input_paths: list[str] | None = None,
    metadata: dict[str, object] | None = None,
) -> None:
    if case_dir is None:
        return
    register_case_artifact(
        case_dir=case_dir,
        path=output,
        category=category,
        source_command=source_command,
        input_paths=input_paths,
        metadata=metadata,
    )


@ai.command("anomaly")
@click.option("--input", "input_path", type=READABLE_FILE, required=True)
@click.option("--feature", "features", multiple=True)
@click.option("--output", type=click.Path(dir_okay=False, path_type=pathlib.Path))
@click.option("--case-dir", type=click.Path(file_okay=False, exists=True, path_type=pathlib.Path))
def anomaly_cmd(input_path: pathlib.Path, features: tuple[str, ...], output: pathlib.Path | None, case_dir: pathlib.Path | None) -> None:
    rows = json.loads(input_path.read_text(encoding="utf-8"))
    output, derived = _resolve_case_output(output, case_dir, filename=f"ai_anomaly_{_safe_name(input_path.stem)}.json")
    out = anomaly_payload(rows, list(features), anomaly_scores(rows, list(features)), input_path=input_path, case_dir=case_dir, output=output)
    if output:
        write_json(output, out)
        _register_ai_output(
            case_dir=case_dir,
            output=output,
            category="ai-anomaly",
            source_command="ai anomaly",
            input_paths=[str(input_path)],
            metadata={"feature_keys": list(features), "row_count": len(rows), **(out.get("summary") or {})},
        )
        if derived:
            console.print(str(output))
        return
    console.print_json(json.dumps(out))


@ai.command("train-malware")
@click.option("--input", "input_path", type=READABLE_FILE, required=True)
@click.option("--feature", "features", multiple=True)
@click.option("--label", "label_key", required=True)
@click.option("--model", "model_path", type=click.Path(dir_okay=False, path_type=pathlib.Path))
@click.option("--case-dir", type=click.Path(file_okay=False, exists=True, path_type=pathlib.Path))
def train_cmd(
    input_path: pathlib.Path,
    features: tuple[str, ...],
    label_key: str,
    model_path: pathlib.Path | None,
    case_dir: pathlib.Path | None,
) -> None:
    if model_path is None:
        if case_dir is None:
            raise click.ClickException("Either --model or --case-dir is required")
        model_path = case_output_path(case_dir, area="derived", filename=f"ai_malware_model_{_safe_name(input_path.stem)}.joblib")
    rows = json.loads(input_path.read_text(encoding="utf-8"))
    out = train_classifier(rows, list(features), label_key, model_path)
    _register_ai_output(
        case_dir=case_dir,
        output=out,
        category="ai-malware-model",
        source_command="ai train-malware",
        input_paths=[str(input_path)],
        metadata={"feature_keys": list(features), "label_key": label_key, "row_count": len(rows)},
    )
    console.print(str(out))


@ai.command("classify-malware")
@click.option("--input", "input_path", type=READABLE_FILE, required=True)
@click.option("--model", "model_path", type=READABLE_FILE, required=True)
@click.option("--output", type=click.Path(dir_okay=False, path_type=pathlib.Path))
@click.option("--case-dir", type=click.Path(file_okay=False, exists=True, path_type=pathlib.Path))
def classify_cmd(
    input_path: pathlib.Path,
    model_path: pathlib.Path,
    output: pathlib.Path | None,
    case_dir: pathlib.Path | None,
) -> None:
    rows = json.loads(input_path.read_text(encoding="utf-8"))
    out = predict_classifier(rows, model_path)
    output, derived = _resolve_case_output(output, case_dir, filename=f"ai_classify_malware_{_safe_name(input_path.stem)}.json")
    if output:
        write_json(output, out)
        _register_ai_output(
            case_dir=case_dir,
            output=output,
            category="ai-malware-classification",
            source_command="ai classify-malware",
            input_paths=[str(input_path), str(model_path)],
            metadata={"row_count": len(rows), "model_path": str(model_path)},
        )
        if derived:
            console.print(str(output))
        return
    console.print_json(json.dumps(out))


@ai.command("predict-password")
@click.option("--corpus", type=READABLE_FILE, required=True)
@click.option("--personal-data", type=READABLE_FILE)
@click.option("--count", type=int, default=50)
@click.option("--min-len", type=int, default=6)
@click.option("--max-len", type=int, default=12)
@click.option("--seed", type=int)
@click.option("--markov-order", type=int, default=2)
@click.option("--output", type=click.Path(dir_okay=False, path_type=pathlib.Path))
@click.option("--case-dir", type=click.Path(file_okay=False, exists=True, path_type=pathlib.Path))
def predict_password_cmd(
    corpus: pathlib.Path,
    personal_data: pathlib.Path | None,
    count: int,
    min_len: int,
    max_len: int,
    seed: int | None,
    markov_order: int,
    output: pathlib.Path | None,
    case_dir: pathlib.Path | None,
) -> None:
    model = PasswordPredictor.train_from_wordlist(corpus, order=markov_order)
    source_words = [line.strip() for line in corpus.read_text(encoding="utf-8", errors="ignore").splitlines() if line.strip()]
    personal_payload = load_personal_data(personal_data) if personal_data is not None else None
    generated = model.generate(count=count, min_len=min_len, max_len=max_len, seed=seed, personal_data=personal_payload)
    output, derived = _resolve_case_output(output, case_dir, filename=f"ai_predict_password_{_safe_name(corpus.stem)}.json")
    out = password_payload(
        generated,
        wordlist_path=corpus,
        source_words=source_words,
        min_len=min_len,
        max_len=max_len,
        seed=seed,
        metadata={"markov_order": markov_order, "personal_data_path": str(personal_data) if personal_data else None},
        case_dir=case_dir,
        output=output,
    )
    if output:
        write_json(output, out)
        _register_ai_output(
            case_dir=case_dir,
            output=output,
            category="ai-password-predictions",
            source_command="ai predict-password",
            input_paths=[str(corpus)] + ([str(personal_data)] if personal_data is not None else []),
            metadata={"count": count, "min_len": min_len, "max_len": max_len, "seed": seed, "markov_order": markov_order, **(out.get("summary") or {})},
        )
        if derived:
            console.print(str(output))
        return
    console.print_json(json.dumps(out))

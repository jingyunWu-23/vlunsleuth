from __future__ import annotations

import argparse
import csv
import json
import re
from collections import defaultdict
from pathlib import Path
from typing import Any, Dict, Iterable, List, Sequence


VALID_STATUSES = {"suspected", "confirmed"}
VULNERABILITY_ALIASES = {
    "reentrancy": "VULN_REENTRANCY",
    "timestamp": "VULN_TIMESTAMP",
    "delegatecall": "VULN_DELEGATECALL",
    "sbunchecked_low_level_calls": "VULN_UNCHECKED_LOW_LEVEL_CALLS",
    "unchecked_low_level_calls": "VULN_UNCHECKED_LOW_LEVEL_CALLS",
    "unchecked_lowlevel": "VULN_UNCHECKED_LOW_LEVEL_CALLS",
    "access_control": "VULN_ACCESS_CONTROL",
    "arithmetic": "VULN_ARITHMETIC",
    "locked_ether": "VULN_LOCKED_ETHER",
    "bad_randomness": "VULN_BAD_RANDOMNESS",
}


def normalize_text(value: Any) -> str:
    return str(value or "").strip()


def normalize_function_name(function_name: Any, function_signature: Any = "") -> str:
    direct = normalize_text(function_name)
    if direct:
        return direct
    signature = normalize_text(function_signature)
    match = re.search(r"\bfunction\s+([A-Za-z_][A-Za-z0-9_]*)", signature)
    if match:
        return match.group(1)
    match = re.search(r"\b([A-Za-z_][A-Za-z0-9_]*)\s*\(", signature)
    return match.group(1) if match else signature


def normalize_vulnerability(value: Any) -> str:
    raw = normalize_text(value)
    if not raw:
        return ""
    upper = raw.upper()
    if upper.startswith("VULN_"):
        return upper
    key = raw.lower().replace("-", "_").replace(" ", "_")
    return VULNERABILITY_ALIASES.get(key, upper)


def parse_float(value: Any, default: float = 0.0) -> float:
    try:
        return float(value)
    except (TypeError, ValueError):
        return default


def row_key(row: Dict[str, Any]) -> tuple[str, str, str, str]:
    return (
        normalize_text(row.get("sample_id")),
        normalize_vulnerability(row.get("vulnerability_id") or row.get("expected_vulnerability_id")),
        normalize_text(row.get("contract_name")),
        normalize_function_name(row.get("function_name"), row.get("function_signature")),
    )


def load_csv(path: Path) -> List[Dict[str, Any]]:
    with path.open("r", newline="", encoding="utf-8-sig") as handle:
        return list(csv.DictReader(handle))


def load_labels(path: Path) -> List[Dict[str, Any]]:
    if path.suffix.lower() == ".json":
        data = json.loads(path.read_text(encoding="utf-8"))
        rows = data.get("labels", data if isinstance(data, list) else [])
    else:
        rows = load_csv(path)
    labels: List[Dict[str, Any]] = []
    for row in rows:
        labels.append({
            **row,
            "sample_id": normalize_text(row.get("sample_id") or row.get("task_id")),
            "vulnerability_id": normalize_vulnerability(row.get("vulnerability_id") or row.get("expected_vulnerability_id")),
            "function_name": normalize_function_name(row.get("function_name"), row.get("function_signature")),
            "contract_name": normalize_text(row.get("contract_name")),
        })
    return [row for row in labels if row["sample_id"] and row["vulnerability_id"] and row["function_name"]]


def iter_json_reports(path: Path) -> Iterable[Path]:
    if path.is_file():
        yield path
        return
    for item in sorted(path.rglob("*.json")):
        if item.name in {"status.json", "slither_results.json", "function_pseudo_labels.json"}:
            continue
        yield item


def load_predictions_from_report(path: Path, include_warnings: bool, sample_id_source: str) -> List[Dict[str, Any]]:
    data = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        return []
    task_id = normalize_text(data.get("task_id")) or path.stem
    sample_id = task_id if sample_id_source == "task_id" else path.stem

    rows: List[Dict[str, Any]] = []
    for item in data.get("findings", []) or []:
        rows.append({
            "sample_id": normalize_text(item.get("sample_id")) or sample_id,
            "source": str(path),
            "status": item.get("status"),
            "contract_name": item.get("contract_name"),
            "function_signature": item.get("function_signature"),
            "function_name": normalize_function_name(item.get("function_name"), item.get("function_signature")),
            "vulnerability_id": item.get("vulnerability_id"),
            "confidence": item.get("confidence"),
            "finding_id": item.get("finding_id"),
            "prediction_source": "finding",
        })
    if include_warnings:
        for item in data.get("warnings", []) or []:
            rows.append({
                "sample_id": normalize_text(item.get("sample_id")) or sample_id,
                "source": str(path),
                "status": item.get("status"),
                "contract_name": item.get("contract_name"),
                "function_signature": item.get("function_signature"),
                "function_name": normalize_function_name(item.get("function_name"), item.get("function_signature")),
                "vulnerability_id": item.get("target_vulnerability"),
                "confidence": item.get("score"),
                "finding_id": item.get("warning_id"),
                "prediction_source": "warning",
            })
    return rows


def load_predictions(path: Path, include_warnings: bool, sample_id_source: str) -> List[Dict[str, Any]]:
    if path.suffix.lower() == ".csv":
        rows = load_csv(path)
    else:
        rows = []
        for report_path in iter_json_reports(path):
            try:
                rows.extend(load_predictions_from_report(report_path, include_warnings, sample_id_source))
            except Exception:
                continue

    predictions: List[Dict[str, Any]] = []
    for row in rows:
        status = normalize_text(row.get("status")).lower()
        predictions.append({
            **row,
            "sample_id": normalize_text(row.get("sample_id") or row.get("task_id")),
            "status": status,
            "contract_name": normalize_text(row.get("contract_name")),
            "function_name": normalize_function_name(row.get("function_name"), row.get("function_signature")),
            "vulnerability_id": normalize_vulnerability(row.get("vulnerability_id") or row.get("target_vulnerability")),
            "confidence": parse_float(row.get("confidence") or row.get("score")),
        })
    return [
        row for row in predictions
        if row["sample_id"] and row["vulnerability_id"] and row["function_name"]
    ]


def write_csv(rows: Sequence[Dict[str, Any]], path: Path, fieldnames: Sequence[str]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", newline="", encoding="utf-8-sig") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(rows)


def precision_recall_f1(tp: int, pred_count: int, gold_count: int) -> dict[str, float]:
    precision = tp / pred_count if pred_count else 0.0
    recall = tp / gold_count if gold_count else 0.0
    f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0
    return {
        "precision": round(precision, 4),
        "recall": round(recall, 4),
        "f1": round(f1, 4),
    }


def evaluate(
    labels: List[Dict[str, Any]],
    predictions: List[Dict[str, Any]],
    allowed_statuses: set[str],
    restrict_predictions_to_label_vulnerabilities: bool = False,
) -> dict[str, Any]:
    gold_keys = {row_key(row) for row in labels}
    filtered_predictions = [row for row in predictions if not allowed_statuses or row["status"] in allowed_statuses]
    if restrict_predictions_to_label_vulnerabilities:
        label_vulnerabilities = {key[1] for key in gold_keys}
        filtered_predictions = [
            row for row in filtered_predictions
            if row["vulnerability_id"] in label_vulnerabilities
        ]

    best_by_key: Dict[tuple[str, str, str, str], Dict[str, Any]] = {}
    for prediction in filtered_predictions:
        key = row_key(prediction)
        current = best_by_key.get(key)
        if current is None or prediction["confidence"] > current["confidence"]:
            best_by_key[key] = prediction

    predicted_keys = set(best_by_key)
    true_positive_keys = gold_keys & predicted_keys

    by_sample_gold: Dict[tuple[str, str], set[tuple[str, str, str, str]]] = defaultdict(set)
    by_sample_predictions: Dict[tuple[str, str], List[Dict[str, Any]]] = defaultdict(list)
    for key in gold_keys:
        by_sample_gold[(key[0], key[1])].add(key)
    for prediction in filtered_predictions:
        by_sample_predictions[(prediction["sample_id"], prediction["vulnerability_id"])].append(prediction)

    hit_rows: List[Dict[str, Any]] = []
    hit1 = 0
    hit3 = 0
    sample_cases = sorted(by_sample_gold)
    for sample_key in sample_cases:
        gold_for_sample = by_sample_gold[sample_key]
        ranked = sorted(by_sample_predictions.get(sample_key, []), key=lambda item: item["confidence"], reverse=True)
        top1_keys = {row_key(item) for item in ranked[:1]}
        top3_keys = {row_key(item) for item in ranked[:3]}
        is_hit1 = bool(gold_for_sample & top1_keys)
        is_hit3 = bool(gold_for_sample & top3_keys)
        hit1 += int(is_hit1)
        hit3 += int(is_hit3)
        hit_rows.append({
            "sample_id": sample_key[0],
            "vulnerability_id": sample_key[1],
            "gold_function_count": len(gold_for_sample),
            "prediction_count": len(ranked),
            "hit_at_1": is_hit1,
            "hit_at_3": is_hit3,
            "top1_function": ranked[0]["function_name"] if ranked else "",
            "top1_contract": ranked[0]["contract_name"] if ranked else "",
            "top1_confidence": ranked[0]["confidence"] if ranked else "",
        })

    metrics = precision_recall_f1(len(true_positive_keys), len(predicted_keys), len(gold_keys))
    metrics.update({
        "gold_count": len(gold_keys),
        "prediction_count": len(predicted_keys),
        "true_positive_count": len(true_positive_keys),
        "sample_case_count": len(sample_cases),
        "hit_at_1": round(hit1 / len(sample_cases), 4) if sample_cases else 0.0,
        "hit_at_3": round(hit3 / len(sample_cases), 4) if sample_cases else 0.0,
    })

    per_vulnerability: List[Dict[str, Any]] = []
    vulnerabilities = sorted({key[1] for key in gold_keys} | {key[1] for key in predicted_keys})
    for vulnerability_id in vulnerabilities:
        vuln_gold = {key for key in gold_keys if key[1] == vulnerability_id}
        vuln_pred = {key for key in predicted_keys if key[1] == vulnerability_id}
        vuln_tp = vuln_gold & vuln_pred
        row = {"vulnerability_id": vulnerability_id}
        row.update(precision_recall_f1(len(vuln_tp), len(vuln_pred), len(vuln_gold)))
        row.update({
            "gold_count": len(vuln_gold),
            "prediction_count": len(vuln_pred),
            "true_positive_count": len(vuln_tp),
        })
        per_vulnerability.append(row)

    detail_rows = []
    for key in sorted(gold_keys | predicted_keys):
        prediction = best_by_key.get(key)
        detail_rows.append({
            "sample_id": key[0],
            "vulnerability_id": key[1],
            "contract_name": key[2],
            "function_name": key[3],
            "in_gold": key in gold_keys,
            "in_prediction": key in predicted_keys,
            "is_true_positive": key in true_positive_keys,
            "confidence": prediction.get("confidence") if prediction else "",
            "status": prediction.get("status") if prediction else "",
            "prediction_source": prediction.get("prediction_source") if prediction else "",
        })

    return {
        "overall": metrics,
        "per_vulnerability": per_vulnerability,
        "sample_hits": hit_rows,
        "details": detail_rows,
    }


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Evaluate function-level vulnerability localization against Slither pseudo labels.")
    parser.add_argument("--labels", required=True, help="Slither pseudo-label CSV/JSON.")
    parser.add_argument("--system", required=True, help="System findings CSV, one report JSON, or a directory containing report JSON files.")
    parser.add_argument("--output-dir", default="backend_outputs/experiments/localization_eval/evaluation")
    parser.add_argument("--include-warnings", action="store_true", help="Also evaluate warning entries from backend JSON reports.")
    parser.add_argument("--statuses", default="suspected,confirmed", help="Comma-separated prediction statuses to include. Empty means all.")
    parser.add_argument("--sample-id-source", choices=["task_id", "file_stem"], default="task_id", help="For JSON reports, derive sample_id from task_id or JSON file stem.")
    parser.add_argument("--restrict-predictions-to-label-vulnerabilities", action="store_true", help="Ignore prediction vulnerability types that do not appear in the label set.")
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    labels = load_labels(Path(args.labels))
    predictions = load_predictions(Path(args.system), args.include_warnings, args.sample_id_source)
    statuses = {item.strip().lower() for item in args.statuses.split(",") if item.strip()}

    result = evaluate(
        labels,
        predictions,
        statuses,
        restrict_predictions_to_label_vulnerabilities=args.restrict_predictions_to_label_vulnerabilities,
    )
    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    (output_dir / "function_localization_metrics.json").write_text(json.dumps(result, ensure_ascii=False, indent=2), encoding="utf-8")
    write_csv(result["per_vulnerability"], output_dir / "function_localization_by_vulnerability.csv", [
        "vulnerability_id",
        "precision",
        "recall",
        "f1",
        "gold_count",
        "prediction_count",
        "true_positive_count",
    ])
    write_csv(result["sample_hits"], output_dir / "function_localization_sample_hits.csv", [
        "sample_id",
        "vulnerability_id",
        "gold_function_count",
        "prediction_count",
        "hit_at_1",
        "hit_at_3",
        "top1_function",
        "top1_contract",
        "top1_confidence",
    ])
    write_csv(result["details"], output_dir / "function_localization_details.csv", [
        "sample_id",
        "vulnerability_id",
        "contract_name",
        "function_name",
        "in_gold",
        "in_prediction",
        "is_true_positive",
        "confidence",
        "status",
        "prediction_source",
    ])

    print(json.dumps({
        "labels": len(labels),
        "predictions": len(predictions),
        "output_dir": str(output_dir),
        **result["overall"],
    }, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()

# -*- coding: utf-8 -*-
from __future__ import annotations

import argparse
import csv
import json
import re
import sys
import traceback
from pathlib import Path
from typing import Any, Dict, Iterable, List

sys.path.insert(0, str(Path(__file__).resolve().parent))

from backend.preprocessing.source_loader import read_text
from generate_slither_function_pseudolabels import build_pseudo_labels, write_csv as write_label_csv


VULNERABILITY_DIRS: Dict[str, str] = {
    "reentrancy": "VULN_REENTRANCY",
    "timestamp": "VULN_TIMESTAMP",
    "delegatecall": "VULN_DELEGATECALL",
    "unchecked_low_level_calls": "VULN_UNCHECKED_LOW_LEVEL_CALLS",
    "sbunchecked_low_level_calls": "VULN_UNCHECKED_LOW_LEVEL_CALLS",
    "access_control": "VULN_ACCESS_CONTROL",
    "arithmetic": "VULN_ARITHMETIC",
    "locked_ether": "VULN_LOCKED_ETHER",
    "bad_randomness": "VULN_BAD_RANDOMNESS",
}


LABEL_FIELDNAMES = [
    "sample_id",
    "sample_path",
    "sample_vulnerability",
    "expected_vulnerability_id",
    "expected_match",
    "label_id",
    "source_path",
    "contract_name",
    "function_name",
    "function_signature",
    "function_start_line",
    "function_end_line",
    "slither_check",
    "vulnerability_id",
    "impact",
    "confidence",
    "confidence_score",
    "detector_index",
    "pseudo_label_source",
    "description",
    "locations",
]


def normalize_name(value: str) -> str:
    value = value.strip().lower().replace("-", "_").replace(" ", "_")
    value = re.sub(r"[^a-z0-9_]+", "_", value)
    return re.sub(r"_+", "_", value).strip("_")


def slug(value: str) -> str:
    value = re.sub(r"[^A-Za-z0-9_.-]+", "_", value)
    return re.sub(r"_+", "_", value).strip("_") or "sample"


def load_vulnerability_dirs(path: str | None) -> Dict[str, str]:
    mapping = dict(VULNERABILITY_DIRS)
    if not path:
        return mapping
    data = json.loads(read_text(Path(path)))
    for key, value in data.items():
        mapping[normalize_name(key)] = str(value)
    return mapping


def iter_samples(dataset_root: Path, mapping: Dict[str, str], single_vulnerability: str | None) -> Iterable[dict[str, str]]:
    if single_vulnerability:
        vulnerability_id = single_vulnerability
        for source_path in sorted(dataset_root.rglob("*.sol")):
            sample_id = slug(source_path.relative_to(dataset_root).with_suffix("").as_posix())
            yield {
                "sample_id": sample_id,
                "sample_path": str(source_path),
                "sample_vulnerability": normalize_name(single_vulnerability),
                "expected_vulnerability_id": vulnerability_id,
            }
        return

    for child in sorted(dataset_root.iterdir()):
        if not child.is_dir():
            continue
        folder_key = normalize_name(child.name)
        vulnerability_id = mapping.get(folder_key)
        if not vulnerability_id:
            continue
        for source_path in sorted(child.rglob("*.sol")):
            relative = source_path.relative_to(dataset_root).with_suffix("").as_posix()
            yield {
                "sample_id": slug(relative),
                "sample_path": str(source_path),
                "sample_vulnerability": folder_key,
                "expected_vulnerability_id": vulnerability_id,
            }


def enrich_label(label: Dict[str, Any], sample: Dict[str, str]) -> Dict[str, Any]:
    vulnerability_id = str(label.get("vulnerability_id") or "")
    row = {
        **sample,
        **label,
        "expected_match": vulnerability_id == sample["expected_vulnerability_id"],
    }
    row["locations"] = json.dumps(row.get("locations") or [], ensure_ascii=False)
    return row


def write_csv(rows: List[Dict[str, Any]], path: Path, fieldnames: List[str]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", newline="", encoding="utf-8-sig") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(rows)


def detect_encoding(path: Path) -> str:
    data = path.read_bytes()
    for encoding in ("utf-8", "utf-8-sig", "gb18030", "gbk", "cp936"):
        try:
            data.decode(encoding)
            return encoding
        except UnicodeError:
            continue
    return "latin-1-fallback"


def write_encoding_report(samples: List[dict[str, str]], output_dir: Path) -> None:
    rows = []
    for sample in samples:
        source_path = Path(sample["sample_path"])
        encoding = detect_encoding(source_path)
        if encoding not in {"utf-8", "utf-8-sig"}:
            rows.append({
                **sample,
                "detected_encoding": encoding,
            })
    if rows:
        write_csv(rows, output_dir / "non_utf8_sources.csv", [
            "sample_id",
            "sample_path",
            "sample_vulnerability",
            "expected_vulnerability_id",
            "detected_encoding",
        ])


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Batch-generate Slither function-level pseudo labels for localization experiments.")
    parser.add_argument("dataset_root", help="Root directory. Expected layout: root/<vulnerability_name>/*.sol")
    parser.add_argument("--output-dir", default="backend_outputs/experiments/localization_eval/slither")
    parser.add_argument("--vulnerability-map", help="Optional JSON mapping from folder names to vulnerability IDs.")
    parser.add_argument("--single-vulnerability", help="Treat every .sol under dataset_root as this vulnerability ID.")
    parser.add_argument("--keep-all-slither-labels", action="store_true", help="Keep Slither labels that do not match the folder vulnerability.")
    parser.add_argument("--limit", type=int, help="Only process the first N samples after --start-index filtering.")
    parser.add_argument("--start-index", type=int, default=1, help="1-based sample index to start from.")
    return parser.parse_args()


def run(args: argparse.Namespace) -> None:
    dataset_root = Path(args.dataset_root)
    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    mapping = load_vulnerability_dirs(args.vulnerability_map)

    labels: List[Dict[str, Any]] = []
    samples_summary: List[Dict[str, Any]] = []
    errors: List[Dict[str, str]] = []
    all_samples = list(iter_samples(dataset_root, mapping, args.single_vulnerability))
    start = max(1, args.start_index)
    samples = all_samples[start - 1:]
    if args.limit is not None:
        samples = samples[:max(0, args.limit)]
    write_encoding_report(samples, output_dir)

    for offset, sample in enumerate(samples, start):
        source_path = Path(sample["sample_path"])
        sample_output_dir = output_dir / "samples" / sample["sample_vulnerability"] / sample["sample_id"]
        progress = {
            "current_index": offset,
            "sample_id": sample["sample_id"],
            "sample_path": sample["sample_path"],
            "sample_vulnerability": sample["sample_vulnerability"],
        }
        (output_dir / "current_sample.json").write_text(json.dumps(progress, ensure_ascii=False, indent=2), encoding="utf-8")
        print(json.dumps({"processing": progress}, ensure_ascii=True), flush=True)
        try:
            result = build_pseudo_labels(str(source_path), sample_output_dir, sample["sample_id"])
        except Exception as exc:
            sample_output_dir.mkdir(parents=True, exist_ok=True)
            error_payload = {
                **sample,
                "error": f"{type(exc).__name__}: {exc}",
                "traceback": traceback.format_exc(),
            }
            (sample_output_dir / "error.json").write_text(
                json.dumps(error_payload, ensure_ascii=False, indent=2),
                encoding="utf-8",
            )
            errors.append({
                **error_payload,
                "sample_json": str(sample_output_dir / "error.json"),
            })
            continue

        sample_output_dir.mkdir(parents=True, exist_ok=True)
        (sample_output_dir / "function_pseudo_labels.json").write_text(
            json.dumps(result, ensure_ascii=False, indent=2),
            encoding="utf-8",
        )
        write_label_csv(result.get("labels", []), sample_output_dir / "function_pseudo_labels.csv")

        sample_labels = [enrich_label(item, sample) for item in result.get("labels", [])]
        if not args.keep_all_slither_labels:
            sample_labels = [item for item in sample_labels if item["expected_match"]]
        labels.extend(sample_labels)
        slither = result.get("slither", {})
        samples_summary.append({
            **sample,
            "slither_status": slither.get("status"),
            "slither_exit_code": slither.get("exit_code"),
            "slither_detector_count": slither.get("detector_count", 0),
            "slither_error": slither.get("error"),
            "function_count": result.get("function_count", 0),
            "pseudo_label_count": len(sample_labels),
            "all_slither_label_count": len(result.get("labels", [])),
            "unmatched_detector_count": result.get("unmatched_detector_count", 0),
            "sample_json": str(sample_output_dir / "function_pseudo_labels.json"),
        })

    output_dir.mkdir(parents=True, exist_ok=True)
    write_csv(labels, output_dir / "slither_function_labels.csv", LABEL_FIELDNAMES)
    write_csv(samples_summary, output_dir / "slither_samples_summary.csv", [
        "sample_id",
        "sample_path",
        "sample_vulnerability",
        "expected_vulnerability_id",
        "slither_status",
        "slither_exit_code",
        "slither_detector_count",
        "slither_error",
        "function_count",
        "pseudo_label_count",
        "all_slither_label_count",
        "unmatched_detector_count",
        "sample_json",
    ])
    if errors:
        write_csv(errors, output_dir / "slither_errors.csv", [
            "sample_id",
            "sample_path",
            "sample_vulnerability",
            "expected_vulnerability_id",
            "error",
            "sample_json",
            "traceback",
        ])

    summary = {
        "dataset_root": str(dataset_root),
        "output_dir": str(output_dir),
        "sample_count": len(samples_summary),
        "discovered_sample_count": len(samples),
        "total_discovered_sample_count": len(all_samples),
        "start_index": start,
        "limit": args.limit,
        "pseudo_label_count": len(labels),
        "error_count": len(errors),
        "labels_csv": str(output_dir / "slither_function_labels.csv"),
        "samples_csv": str(output_dir / "slither_samples_summary.csv"),
        "errors_csv": str(output_dir / "slither_errors.csv") if errors else None,
    }
    (output_dir / "slither_batch_summary.json").write_text(json.dumps(summary, ensure_ascii=False, indent=2), encoding="utf-8")
    print(json.dumps(summary, ensure_ascii=True, indent=2))


def main() -> None:
    args = parse_args()
    try:
        run(args)
    except Exception as exc:
        output_dir = Path(getattr(args, "output_dir", "backend_outputs/experiments/localization_eval/slither"))
        output_dir.mkdir(parents=True, exist_ok=True)
        payload = {
            "error": f"{type(exc).__name__}: {exc}",
            "traceback": traceback.format_exc(),
        }
        (output_dir / "fatal_error.json").write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
        raise


if __name__ == "__main__":
    main()

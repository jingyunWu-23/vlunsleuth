from __future__ import annotations

import argparse
import csv
import json
import os
from dataclasses import asdict
from pathlib import Path
from typing import Any, Dict, Iterable, List

from backend.agents.slither_verification_agent import run_slither, same_source_file
from backend.preprocessing.feature_extractor import build_analysis_input
from backend.preprocessing.source_loader import load_sources
from backend.schemas import FunctionUnit


def detector_overlaps_function(detector: Dict[str, Any], function: FunctionUnit) -> bool:
    for location in detector.get("locations", []):
        if not same_source_file(location.get("filename"), function.source_path):
            continue
        start_line = location.get("start_line")
        end_line = location.get("end_line")
        if start_line is None or end_line is None:
            continue
        if int(start_line) <= function.end_line and int(end_line) >= function.start_line:
            return True
    description = str(detector.get("description", ""))
    return bool(function.name and function.name in description and function.contract_name in description)


def map_detector_to_functions(detector: Dict[str, Any], functions: Iterable[FunctionUnit]) -> List[FunctionUnit]:
    return [function for function in functions if detector_overlaps_function(detector, function)]


def build_pseudo_labels(source_path: str, output_dir: Path, task_id: str) -> Dict[str, Any]:
    sources = load_sources(source_path)
    os.environ.setdefault("SCG_ENABLE_REAL_OPCODE", "0")
    analysis = build_analysis_input(task_id, sources)
    slither_result = run_slither(source_path, output_dir)

    labels: List[Dict[str, Any]] = []
    unmatched_detectors: List[Dict[str, Any]] = []
    detectors = slither_result.get("detectors", [])

    for detector_index, detector in enumerate(detectors, 1):
        matched_functions = map_detector_to_functions(detector, analysis.functions)
        if not matched_functions:
            unmatched_detectors.append({
                "detector_index": detector_index,
                "check": detector.get("check"),
                "vulnerability_id": detector.get("vulnerability_id"),
                "impact": detector.get("impact"),
                "confidence": detector.get("confidence"),
                "description": detector.get("description"),
                "locations": detector.get("locations", []),
            })
            continue

        for function in matched_functions:
            labels.append({
                "label_id": f"PL-{len(labels) + 1:04d}",
                "source_path": function.source_path,
                "contract_name": function.contract_name,
                "function_name": function.name,
                "function_signature": function.signature,
                "function_start_line": function.start_line,
                "function_end_line": function.end_line,
                "detector_index": detector_index,
                "slither_check": detector.get("check"),
                "vulnerability_id": detector.get("vulnerability_id") or "UNMAPPED_SLITHER_DETECTOR",
                "impact": detector.get("impact"),
                "confidence": detector.get("confidence"),
                "confidence_score": detector.get("confidence_score"),
                "description": detector.get("description"),
                "locations": detector.get("locations", []),
                "pseudo_label_source": "slither_function_overlap",
            })

    return {
        "task_id": task_id,
        "source_path": source_path,
        "slither": {
            "status": slither_result.get("status"),
            "artifact": slither_result.get("artifact"),
            "command": slither_result.get("command"),
            "solc_version": slither_result.get("solc_version"),
            "detector_count": slither_result.get("detector_count", len(detectors)),
            "exit_code": slither_result.get("exit_code"),
            "error": slither_result.get("error"),
            "stdout": slither_result.get("stdout"),
            "stderr": slither_result.get("stderr"),
        },
        "function_count": len(analysis.functions),
        "pseudo_label_count": len(labels),
        "unmatched_detector_count": len(unmatched_detectors),
        "labels": labels,
        "unmatched_detectors": unmatched_detectors,
        "functions": [asdict(function) for function in analysis.functions],
    }


def write_csv(labels: List[Dict[str, Any]], path: Path) -> None:
    fieldnames = [
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
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", newline="", encoding="utf-8-sig") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames)
        writer.writeheader()
        for item in labels:
            row = {field: item.get(field) for field in fieldnames}
            row["locations"] = json.dumps(row.get("locations") or [], ensure_ascii=False)
            writer.writerow(row)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Generate function-level pseudo labels from Slither findings.")
    parser.add_argument("source_path", help="Solidity file, project directory, or zip archive.")
    parser.add_argument("--task-id", default="SLITHER-PSEUDO-LABELS")
    parser.add_argument("--output-dir", default="backend_outputs/experiments/slither_pseudolabels")
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    result = build_pseudo_labels(args.source_path, output_dir, args.task_id)
    json_path = output_dir / "function_pseudo_labels.json"
    csv_path = output_dir / "function_pseudo_labels.csv"
    json_path.write_text(json.dumps(result, ensure_ascii=False, indent=2), encoding="utf-8")
    write_csv(result["labels"], csv_path)

    print(json.dumps({
        "source_path": args.source_path,
        "slither_status": result["slither"].get("status"),
        "function_count": result["function_count"],
        "pseudo_label_count": result["pseudo_label_count"],
        "unmatched_detector_count": result["unmatched_detector_count"],
        "json": str(json_path),
        "csv": str(csv_path),
        "slither_artifact": result["slither"].get("artifact"),
    }, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()

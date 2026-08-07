# -*- coding: utf-8 -*-
from __future__ import annotations

import argparse
import csv
import json
import subprocess
import sys
from pathlib import Path
from typing import Any, Dict, List

from backend.reporting.markdown_report import report_to_dict, write_markdown
from backend.run_audit import run_audit
from backend.schemas import AuditRequest


def read_csv(path: Path) -> List[Dict[str, Any]]:
    with path.open("r", newline="", encoding="utf-8-sig") as handle:
        return list(csv.DictReader(handle))


def write_csv(rows: List[Dict[str, Any]], path: Path, fieldnames: List[str]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", newline="", encoding="utf-8-sig") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(rows)


def collect_labeled_samples(labels_csv: Path) -> List[Dict[str, str]]:
    samples: Dict[str, Dict[str, str]] = {}
    for row in read_csv(labels_csv):
        sample_id = str(row.get("sample_id") or "").strip()
        sample_path = str(row.get("sample_path") or "").strip()
        vulnerability = str(row.get("expected_vulnerability_id") or row.get("vulnerability_id") or "").strip()
        if not sample_id or not sample_path or not vulnerability:
            continue
        key = f"{sample_id}|{vulnerability}"
        samples.setdefault(key, {
            "sample_id": sample_id,
            "sample_path": sample_path,
            "sample_vulnerability": str(row.get("sample_vulnerability") or "").strip(),
            "expected_vulnerability_id": vulnerability,
        })
    return sorted(samples.values(), key=lambda item: (item["sample_vulnerability"], item["sample_id"]))


def filter_labels_for_samples(labels_csv: Path, samples: List[Dict[str, str]], output_csv: Path) -> int:
    allowed = {
        (sample["sample_id"], sample["expected_vulnerability_id"])
        for sample in samples
    }
    rows = [
        row for row in read_csv(labels_csv)
        if (str(row.get("sample_id") or "").strip(), str(row.get("expected_vulnerability_id") or row.get("vulnerability_id") or "").strip()) in allowed
    ]
    if rows:
        fieldnames = list(rows[0].keys())
    else:
        fieldnames = [
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
    write_csv(rows, output_csv, fieldnames)
    return len(rows)


def project_path(path_text: str, project_root: Path) -> Path:
    path = Path(path_text)
    return path if path.is_absolute() else project_root / path


def run_localization_audits(
    samples: List[Dict[str, str]],
    output_dir: Path,
    project_root: Path,
    mode: str,
    need_verification: bool,
    write_md: bool,
) -> List[Dict[str, Any]]:
    reports_dir = output_dir / "system_reports"
    rows: List[Dict[str, Any]] = []
    for index, sample in enumerate(samples, 1):
        source_path = project_path(sample["sample_path"], project_root)
        task_id = sample["sample_id"]
        report_dir = reports_dir / task_id
        report_json = report_dir / f"{task_id}.json"
        report_dir.mkdir(parents=True, exist_ok=True)
        print(json.dumps({
            "running": index,
            "total": len(samples),
            "sample_id": task_id,
            "target": sample["expected_vulnerability_id"],
        }, ensure_ascii=True), flush=True)
        try:
            request = AuditRequest(
                task_id=task_id,
                source_path=str(source_path),
                mode=mode,
                target_vulnerabilities=[sample["expected_vulnerability_id"]],
                need_verification=need_verification,
                output_dir=str(report_dir),
            )
            report = run_audit(request)
            report_json.write_text(json.dumps(report_to_dict(report), ensure_ascii=False, indent=2), encoding="utf-8")
            if write_md:
                write_markdown(report, report_dir / f"{task_id}.md")
            rows.append({
                **sample,
                "status": "ok",
                "report_json": str(report_json),
                "finding_count": len(report.findings),
                "warning_count": len(report.warnings),
                "function_count": report.metadata.get("functions", 0),
                "error": "",
            })
        except Exception as exc:
            rows.append({
                **sample,
                "status": "failed",
                "report_json": "",
                "finding_count": 0,
                "warning_count": 0,
                "function_count": 0,
                "error": f"{type(exc).__name__}: {exc}",
            })
    return rows


def run_evaluator(labels_csv: Path, reports_dir: Path, output_dir: Path, include_warnings: bool) -> Dict[str, Any]:
    cmd = [
        sys.executable,
        str(Path(__file__).resolve().parent / "evaluate_function_localization.py"),
        "--labels",
        str(labels_csv),
        "--system",
        str(reports_dir),
        "--output-dir",
        str(output_dir / "evaluation"),
        "--sample-id-source",
        "task_id",
    ]
    if include_warnings:
        cmd.append("--include-warnings")
    completed = subprocess.run(
        cmd,
        cwd=str(Path(__file__).resolve().parents[1]),
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        check=False,
    )
    result = {
        "command": cmd,
        "exit_code": completed.returncode,
        "stdout": completed.stdout,
        "stderr": completed.stderr,
    }
    if completed.returncode != 0:
        raise RuntimeError(f"Evaluation failed: {completed.stderr or completed.stdout}")
    return result


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Run SCG localization accuracy evaluation using Slither pseudo labels.")
    parser.add_argument("--labels", default="backend_outputs/experiments/localization_eval/slither_full/slither_function_labels.csv")
    parser.add_argument("--output-dir", default="backend_outputs/experiments/localization_eval/system_localization_accuracy")
    parser.add_argument("--mode", default="full_audit")
    parser.add_argument("--limit", type=int, help="Limit labeled sample count for a quick run.")
    parser.add_argument("--include-warnings", action="store_true", help="Evaluate warnings as localization predictions too.")
    parser.add_argument("--need-verification", action="store_true", help="Run Slither verification during SCG audit.")
    parser.add_argument("--write-md", action="store_true", help="Also write Markdown reports.")
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    project_root = Path(__file__).resolve().parents[1]
    labels_csv = project_path(args.labels, project_root)
    output_dir = project_path(args.output_dir, project_root)
    output_dir.mkdir(parents=True, exist_ok=True)

    samples = collect_labeled_samples(labels_csv)
    if args.limit is not None:
        samples = samples[:max(0, args.limit)]
    skipped_count = len(read_csv(labels_csv)) - len(samples)
    sample_list_csv = output_dir / "labeled_samples_used.csv"
    write_csv(samples, sample_list_csv, [
        "sample_id",
        "sample_path",
        "sample_vulnerability",
        "expected_vulnerability_id",
    ])
    filtered_labels_csv = output_dir / "slither_function_labels_used.csv"
    filtered_label_count = filter_labels_for_samples(labels_csv, samples, filtered_labels_csv)

    run_rows = run_localization_audits(
        samples=samples,
        output_dir=output_dir,
        project_root=project_root,
        mode=args.mode,
        need_verification=args.need_verification,
        write_md=args.write_md,
    )
    write_csv(run_rows, output_dir / "system_localization_runs.csv", [
        "sample_id",
        "sample_path",
        "sample_vulnerability",
        "expected_vulnerability_id",
        "status",
        "report_json",
        "finding_count",
        "warning_count",
        "function_count",
        "error",
    ])

    evaluator = run_evaluator(filtered_labels_csv, output_dir / "system_reports", output_dir, args.include_warnings)
    summary_path = output_dir / "localization_accuracy_run_summary.json"
    summary = {
        "labels_csv": str(labels_csv),
        "output_dir": str(output_dir),
        "labeled_sample_count": len(samples),
        "filtered_label_count": filtered_label_count,
        "label_rows_minus_unique_samples": skipped_count,
        "successful_audits": sum(1 for row in run_rows if row["status"] == "ok"),
        "failed_audits": sum(1 for row in run_rows if row["status"] != "ok"),
        "sample_list_csv": str(sample_list_csv),
        "filtered_labels_csv": str(filtered_labels_csv),
        "runs_csv": str(output_dir / "system_localization_runs.csv"),
        "evaluation_dir": str(output_dir / "evaluation"),
        "evaluator": evaluator,
    }
    summary_path.write_text(json.dumps(summary, ensure_ascii=False, indent=2), encoding="utf-8")
    print(json.dumps(summary, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()

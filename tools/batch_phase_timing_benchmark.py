from __future__ import annotations

import argparse
import csv
import json
import statistics
from pathlib import Path
from typing import Any, Dict, Iterable, List

from backend.reporting.markdown_report import report_to_dict, write_markdown
from backend.run_audit import run_audit
from backend.schemas import AuditRequest


def iter_sources(source_root: Path, limit: int | None = None) -> Iterable[Path]:
    count = 0
    if source_root.is_file() and source_root.suffix.lower() == ".sol":
        yield source_root
        return
    for path in sorted(source_root.rglob("*.sol")):
        yield path
        count += 1
        if limit is not None and count >= limit:
            return


def safe_sample_id(source_root: Path, source_path: Path) -> str:
    try:
        relative = source_path.relative_to(source_root if source_root.is_dir() else source_root.parent)
    except ValueError:
        relative = source_path.name
    text = str(relative).replace("\\", "_").replace("/", "_")
    return Path(text).with_suffix("").as_posix().replace(":", "_").replace(" ", "_")


def flatten_phase_timings(timings: Dict[str, Any]) -> Dict[str, float]:
    row: Dict[str, float] = {
        "total_seconds": float(timings.get("total_seconds") or 0.0),
        "measured_phase_seconds": float(timings.get("measured_phase_seconds") or 0.0),
        "unmeasured_overhead_seconds": float(timings.get("unmeasured_overhead_seconds") or 0.0),
    }
    if "report_generation_seconds" in timings:
        row["report_generation_seconds"] = float(timings.get("report_generation_seconds") or 0.0)
    for phase in timings.get("phases", []) or []:
        name = str(phase.get("name") or "").strip()
        if name:
            row[name] = float(phase.get("seconds") or 0.0)
    return row


def mean(values: List[float]) -> float:
    return round(statistics.mean(values), 4) if values else 0.0


def stdev(values: List[float]) -> float:
    return round(statistics.stdev(values), 4) if len(values) > 1 else 0.0


def percentile(values: List[float], ratio: float) -> float:
    if not values:
        return 0.0
    ordered = sorted(values)
    index = min(len(ordered) - 1, max(0, round((len(ordered) - 1) * ratio)))
    return round(ordered[index], 4)


def write_csv(rows: List[Dict[str, Any]], path: Path, fieldnames: List[str]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", newline="", encoding="utf-8-sig") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(rows)


def build_summary(detail_rows: List[Dict[str, Any]], phase_names: List[str]) -> List[Dict[str, Any]]:
    summary_rows: List[Dict[str, Any]] = []
    total_values = [float(row.get("total_seconds") or 0.0) for row in detail_rows if not row.get("is_warmup")]
    avg_total = mean(total_values)
    for phase in ["total_seconds", *phase_names, "report_generation_seconds", "unmeasured_overhead_seconds"]:
        values = [float(row.get(phase) or 0.0) for row in detail_rows if not row.get("is_warmup")]
        if not values or all(value == 0.0 for value in values):
            continue
        avg = mean(values)
        summary_rows.append({
            "phase": phase,
            "run_count": len(values),
            "avg_seconds": avg,
            "min_seconds": round(min(values), 4),
            "max_seconds": round(max(values), 4),
            "stdev_seconds": stdev(values),
            "p50_seconds": percentile(values, 0.50),
            "p95_seconds": percentile(values, 0.95),
            "avg_percent_of_total": round(avg / avg_total * 100, 2) if avg_total else 0.0,
        })
    return summary_rows


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Batch benchmark SCG audit phase timings.")
    parser.add_argument("source_root", help="Solidity file or directory containing .sol files.")
    parser.add_argument("--output-dir", default="backend_outputs/experiments/phase_timing_benchmark")
    parser.add_argument("--mode", default="full_audit")
    parser.add_argument("--target", action="append", default=[], help="Optional target vulnerability. Can be used multiple times.")
    parser.add_argument("--repeat", type=int, default=3, help="Measured runs per sample.")
    parser.add_argument("--warmup", type=int, default=1, help="Warmup runs per sample, excluded from averages.")
    parser.add_argument("--limit", type=int, help="Limit number of .sol samples.")
    parser.add_argument("--need-verification", action="store_true", help="Include Slither verification phase.")
    parser.add_argument("--write-reports", action="store_true", help="Write every run JSON/MD report.")
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    source_root = Path(args.source_root)
    output_dir = Path(args.output_dir)
    runs_dir = output_dir / "runs"
    output_dir.mkdir(parents=True, exist_ok=True)

    detail_rows: List[Dict[str, Any]] = []
    errors: List[Dict[str, Any]] = []
    phase_names: set[str] = set()
    sources = list(iter_sources(source_root, args.limit))

    for sample_index, source_path in enumerate(sources, 1):
        sample_id = safe_sample_id(source_root, source_path)
        total_runs = max(0, args.warmup) + max(1, args.repeat)
        for run_index in range(1, total_runs + 1):
            is_warmup = run_index <= args.warmup
            task_id = f"BENCH-{sample_index:04d}-{run_index:02d}-{sample_id}"
            request = AuditRequest(
                task_id=task_id,
                source_path=str(source_path),
                mode=args.mode,
                target_vulnerabilities=args.target,
                need_verification=args.need_verification,
                output_dir=str(runs_dir / task_id),
            )
            try:
                report = run_audit(request)
                timings = report.metadata.get("phase_timings", {})
                flattened = flatten_phase_timings(timings)
                phase_names.update(
                    key for key in flattened
                    if key not in {"total_seconds", "measured_phase_seconds", "unmeasured_overhead_seconds", "report_generation_seconds"}
                )
                row = {
                    "sample_index": sample_index,
                    "sample_id": sample_id,
                    "source_path": str(source_path),
                    "run_index": run_index,
                    "is_warmup": is_warmup,
                    "task_id": task_id,
                    "status": "ok",
                    **flattened,
                }
                detail_rows.append(row)
                if args.write_reports:
                    run_dir = runs_dir / task_id
                    run_dir.mkdir(parents=True, exist_ok=True)
                    write_markdown(report, run_dir / f"{task_id}.md")
                    (run_dir / f"{task_id}.json").write_text(
                        json.dumps(report_to_dict(report), ensure_ascii=False, indent=2),
                        encoding="utf-8",
                    )
            except Exception as exc:
                errors.append({
                    "sample_index": sample_index,
                    "sample_id": sample_id,
                    "source_path": str(source_path),
                    "run_index": run_index,
                    "is_warmup": is_warmup,
                    "task_id": task_id,
                    "error": f"{type(exc).__name__}: {exc}",
                })

    ordered_phases = sorted(phase_names)
    detail_fieldnames = [
        "sample_index",
        "sample_id",
        "source_path",
        "run_index",
        "is_warmup",
        "task_id",
        "status",
        "total_seconds",
        *ordered_phases,
        "report_generation_seconds",
        "measured_phase_seconds",
        "unmeasured_overhead_seconds",
    ]
    write_csv(detail_rows, output_dir / "phase_timing_runs.csv", detail_fieldnames)
    summary_rows = build_summary(detail_rows, ordered_phases)
    write_csv(summary_rows, output_dir / "phase_timing_summary.csv", [
        "phase",
        "run_count",
        "avg_seconds",
        "min_seconds",
        "max_seconds",
        "stdev_seconds",
        "p50_seconds",
        "p95_seconds",
        "avg_percent_of_total",
    ])
    if errors:
        write_csv(errors, output_dir / "phase_timing_errors.csv", [
            "sample_index",
            "sample_id",
            "source_path",
            "run_index",
            "is_warmup",
            "task_id",
            "error",
        ])

    result = {
        "source_root": str(source_root),
        "output_dir": str(output_dir),
        "sample_count": len(sources),
        "measured_repeat": args.repeat,
        "warmup_repeat": args.warmup,
        "successful_runs": len(detail_rows),
        "error_runs": len(errors),
        "summary_csv": str(output_dir / "phase_timing_summary.csv"),
        "runs_csv": str(output_dir / "phase_timing_runs.csv"),
        "errors_csv": str(output_dir / "phase_timing_errors.csv") if errors else None,
    }
    (output_dir / "phase_timing_benchmark.json").write_text(json.dumps(result, ensure_ascii=False, indent=2), encoding="utf-8")
    print(json.dumps(result, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()

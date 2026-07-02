from __future__ import annotations

import argparse
import json
from dataclasses import asdict
from pathlib import Path
from typing import Any, Dict

from backend.preprocessing.feature_extractor import build_analysis_input
from backend.preprocessing.source_loader import load_sources


def preprocess_source(source_path: str, task_id: str = "PREPROCESS-LOCAL") -> Dict[str, Any]:
    sources = load_sources(source_path)
    analysis = build_analysis_input(task_id=task_id, sources=sources)
    payload = asdict(analysis)
    payload["summary"] = {
        "task_id": task_id,
        "source_files": len(analysis.sources),
        "contracts": len(analysis.contracts),
        "functions": len(analysis.functions),
        "call_graph_edges": sum(len(calls) for calls in analysis.call_graph.values()),
        "dangerous_functions": sum(1 for fn in analysis.functions if fn.features.get("dangerous_apis")),
    }
    return payload


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Preprocess Solidity source for the SCG audit backend.")
    parser.add_argument("source_path", help="A .sol file, a directory, or a zip archive.")
    parser.add_argument("--task-id", default="PREPROCESS-LOCAL")
    parser.add_argument("--output", default="backend_outputs/preprocess.json")
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    payload = preprocess_source(args.source_path, task_id=args.task_id)
    output_path = Path(args.output)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
    print(json.dumps(payload["summary"], ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()


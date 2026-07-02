from __future__ import annotations

import argparse
import json
from dataclasses import asdict
from pathlib import Path

from backend.agents.reasoning_localization_agent import build_findings_and_warnings
from backend.evidence.evidence_center import EvidenceCenter
from backend.function_risk.reasoning_gate import select_reasoning_targets
from backend.function_risk.risk_score import compute_risk_vectors
from backend.model_adapters import adapter_results_to_metadata, build_default_registry, execute_adapters
from backend.preprocessing.feature_extractor import build_analysis_input
from backend.preprocessing.source_loader import load_sources
from backend.rag.knowledge_context import build_knowledge_context
from backend.rag.jsonl_knowledge_store import JsonlKnowledgeStore
from backend.reporting.markdown_report import write_markdown
from backend.router.workflow_router import build_workflow
from backend.schemas import AuditReport, AuditRequest


def run_audit(request: AuditRequest) -> AuditReport:
    sources = load_sources(request.source_path)
    target = request.target_vulnerabilities[0] if request.target_vulnerabilities else None
    analysis = build_analysis_input(request.task_id, sources, target_vulnerability=target)
    workflow = build_workflow(request, analysis)

    center = EvidenceCenter()
    center.register_functions(analysis.functions)
    center.add_static_evidence(analysis.functions, task_id=request.task_id)
    registry = build_default_registry(target_vulnerabilities=request.target_vulnerabilities or None)
    selected_adapters = registry.select_for_workflow(workflow.formal_models)
    evidences, adapter_results = execute_adapters(selected_adapters, analysis)
    center.add_many(evidences)

    initial_risk_vectors = compute_risk_vectors(
        analysis.functions,
        center.grouped(),
        selected_vulnerabilities=request.target_vulnerabilities,
    )
    reasoning_selection = select_reasoning_targets(initial_risk_vectors)

    store = JsonlKnowledgeStore()
    fn_by_id = {fn.function_id: fn for fn in analysis.functions}
    preliminary_vector_by_id = {vector.function_id: vector for vector in initial_risk_vectors}
    knowledge_contexts = {}
    for function_id in reasoning_selection.selected_function_ids:
        fn = fn_by_id.get(function_id)
        if not fn:
            continue
        context = build_knowledge_context(store, fn, preliminary_vector_by_id.get(function_id), top_k=5)
        knowledge_contexts[function_id] = context
        center.add_knowledge_evidence(fn, context.items, task_id=request.task_id)

    risk_vectors = compute_risk_vectors(
        analysis.functions,
        center.grouped(),
        selected_vulnerabilities=request.target_vulnerabilities,
    )
    findings, warnings = build_findings_and_warnings(
        analysis.functions,
        risk_vectors,
        center.grouped(),
        store=store,
        selected_vulnerabilities=request.target_vulnerabilities,
        reasoning_selection=reasoning_selection,
        knowledge_contexts=knowledge_contexts,
    )
    return AuditReport(
        task_id=request.task_id,
        mode=request.mode,
        workflow=workflow.as_dict(),
        risk_vectors=risk_vectors,
        findings=findings,
        warnings=warnings,
        metadata={
            "source_files": len(analysis.sources),
            "contracts": len(analysis.contracts),
            "functions": len(analysis.functions),
            "evidence_count": len(center.all()),
            "evidence_center": center.summary(),
            "reasoning_gate": {
                "max_candidates": reasoning_selection.max_candidates,
                "selected_count": len(reasoning_selection.selected_function_ids),
                "selected_function_ids": sorted(reasoning_selection.selected_function_ids),
                "reasons": reasoning_selection.reasons,
            },
            "registered_adapters": registry.describe(),
            "adapter_results": adapter_results_to_metadata(adapter_results),
        },
    )


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Run the SCG backend audit pipeline.")
    parser.add_argument("source_path")
    parser.add_argument("--task-id", default="TASK-LOCAL-001")
    parser.add_argument("--mode", default="full_audit")
    parser.add_argument("--target", action="append", default=[])
    parser.add_argument("--output-dir", default="backend_outputs")
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    request = AuditRequest(
        task_id=args.task_id,
        source_path=args.source_path,
        mode=args.mode,
        target_vulnerabilities=args.target,
        output_dir=args.output_dir,
    )
    report = run_audit(request)
    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    (output_dir / f"{request.task_id}.json").write_text(json.dumps(asdict(report), ensure_ascii=False, indent=2), encoding="utf-8")
    write_markdown(report, output_dir / f"{request.task_id}.md")
    print(json.dumps(report.metadata, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()

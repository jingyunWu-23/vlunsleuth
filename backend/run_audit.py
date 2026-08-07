from __future__ import annotations

import argparse
import json
from contextlib import contextmanager
from time import perf_counter
from pathlib import Path

from backend.analysis import (
    analyze_project_components,
    contract_component_map,
    function_contract_map,
    summarize_contract_status,
)
from backend.agents.reasoning_localization_agent import build_findings_and_warnings
from backend.agents.slither_verification_agent import verify_report_with_slither
from backend.evidence.evidence_center import EvidenceCenter
from backend.function_risk.reasoning_gate import select_reasoning_targets_by_project
from backend.function_risk.risk_score import compute_risk_vectors
from backend.model_adapters import adapter_results_to_metadata, build_default_registry, execute_adapters
from backend.preprocessing.feature_extractor import build_analysis_input
from backend.preprocessing.source_loader import load_sources
from backend.rag.knowledge_context import build_knowledge_context
from backend.rag.jsonl_knowledge_store import JsonlKnowledgeStore
from backend.reporting.markdown_report import report_to_dict, write_markdown
from backend.router.workflow_router import build_workflow
from backend.schemas import AuditReport, AuditRequest


class PhaseTimer:
    def __init__(self) -> None:
        self._started_at = perf_counter()
        self._phases: list[dict[str, float | str]] = []

    @contextmanager
    def phase(self, name: str):
        started = perf_counter()
        try:
            yield
        finally:
            finished = perf_counter()
            self._phases.append({
                "name": name,
                "seconds": round(finished - started, 4),
            })

    def summary(self) -> dict:
        total = perf_counter() - self._started_at
        phases = list(self._phases)
        measured = sum(float(item["seconds"]) for item in phases)
        return {
            "total_seconds": round(total, 4),
            "measured_phase_seconds": round(measured, 4),
            "unmeasured_overhead_seconds": round(max(0.0, total - measured), 4),
            "phases": phases,
        }


def run_audit(request: AuditRequest) -> AuditReport:
    timer = PhaseTimer()
    with timer.phase("source_loading"):
        sources = load_sources(request.source_path)
    with timer.phase("preprocessing_and_feature_extraction"):
        target = request.target_vulnerabilities[0] if request.target_vulnerabilities else None
        analysis = build_analysis_input(request.task_id, sources, target_vulnerability=target)
    with timer.phase("project_grouping"):
        project_analysis = analyze_project_components(analysis.sources, analysis.contracts, analysis.call_graph)
        function_contracts = function_contract_map(analysis.contracts)
        contract_components = contract_component_map(project_analysis)
    with timer.phase("workflow_routing"):
        workflow = build_workflow(request, analysis)

    center = EvidenceCenter()
    with timer.phase("static_evidence_registration"):
        center.register_functions(analysis.functions)
        center.add_static_evidence(analysis.functions, task_id=request.task_id)
    with timer.phase("model_adapter_inference"):
        registry = build_default_registry(target_vulnerabilities=request.target_vulnerabilities or None)
        selected_adapters = registry.select_for_workflow(workflow.formal_models)
        evidences, adapter_results = execute_adapters(selected_adapters, analysis)
        center.add_many(evidences)

    with timer.phase("initial_risk_scoring_and_reasoning_gate"):
        initial_risk_vectors = compute_risk_vectors(
            analysis.functions,
            center.grouped(),
            selected_vulnerabilities=request.target_vulnerabilities,
        )
        reasoning_selection = select_reasoning_targets_by_project(
            initial_risk_vectors,
            function_contracts=function_contracts,
            contract_components=contract_components,
        )

    with timer.phase("knowledge_retrieval"):
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

    with timer.phase("final_risk_scoring"):
        risk_vectors = compute_risk_vectors(
            analysis.functions,
            center.grouped(),
            selected_vulnerabilities=request.target_vulnerabilities,
        )
    with timer.phase("reasoning_localization"):
        findings, warnings = build_findings_and_warnings(
            analysis.functions,
            risk_vectors,
            center.grouped(),
            store=store,
            selected_vulnerabilities=request.target_vulnerabilities,
            reasoning_selection=reasoning_selection,
            knowledge_contexts=knowledge_contexts,
        )
    with timer.phase("contract_statistics"):
        contract_statistics = summarize_contract_status(analysis.contracts, risk_vectors, findings, warnings)
    report = AuditReport(
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
            "project_analysis": project_analysis,
            "contract_statistics": contract_statistics,
            "evidence_count": len(center.all()),
            "evidence_center": center.summary(),
            "reasoning_gate": {
                "max_candidates": reasoning_selection.max_candidates,
                "selected_count": len(reasoning_selection.selected_function_ids),
                "strategy": reasoning_selection.strategy,
                "component_count": reasoning_selection.component_count,
                "contract_count": reasoning_selection.contract_count,
                "per_contract_top_k": reasoning_selection.per_contract_top_k,
                "selected_function_ids": sorted(reasoning_selection.selected_function_ids),
                "reasons": reasoning_selection.reasons,
            },
            "registered_adapters": registry.describe(),
            "adapter_results": adapter_results_to_metadata(adapter_results),
        },
    )
    if request.need_verification:
        with timer.phase("verification"):
            verification_output_dir = Path(request.output_dir) if request.output_dir else None
            report.metadata["verification"] = {
                "slither": verify_report_with_slither(
                    report,
                    analysis.functions,
                    request.source_path,
                    output_dir=verification_output_dir,
                )
            }
    report.metadata["phase_timings"] = timer.summary()
    return report


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
    started = perf_counter()
    write_markdown(report, output_dir / f"{request.task_id}.md")
    report.metadata["phase_timings"]["report_generation_seconds"] = round(perf_counter() - started, 4)
    (output_dir / f"{request.task_id}.json").write_text(json.dumps(report_to_dict(report), ensure_ascii=False, indent=2), encoding="utf-8")
    print(json.dumps(report.metadata, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()

from __future__ import annotations

import argparse
import json
from contextlib import contextmanager
from time import perf_counter
from pathlib import Path
from typing import Any, Callable

from backend.agents.reasoning_localization_agent import build_findings_and_warnings
from backend.agents.slither_verification_agent import verify_report_with_slither
from backend.evidence.evidence_center import EvidenceCenter
from backend.function_risk.reasoning_gate import select_reasoning_targets
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


ProgressCallback = Callable[[int, str], None]


PHASE_PROGRESS = {
    "source_loading": (10, 15, "读取上传文件"),
    "preprocessing_and_feature_extraction": (15, 25, "合约预处理与特征提取"),
    "workflow_routing": (25, 28, "检测流程路由"),
    "static_evidence_registration": (28, 35, "静态证据注册"),
    "model_adapter_inference": (35, 60, "多模型检测"),
    "initial_risk_scoring_and_reasoning_gate": (60, 66, "初始风险评分"),
    "knowledge_retrieval": (66, 75, "RAG 知识库检索"),
    "final_risk_scoring": (75, 80, "最终风险评分"),
    "reasoning_localization": (80, 90, "LLM 推理定位"),
    "verification": (90, 96, "Slither 验证"),
    "report_generation": (96, 99, "报告生成"),
}


def run_audit(request: AuditRequest, progress_callback: ProgressCallback | None = None) -> AuditReport:
    timer = PhaseTimer()
    with progress_phase(timer, "source_loading", progress_callback):
        sources = load_sources(request.source_path)
    with progress_phase(timer, "preprocessing_and_feature_extraction", progress_callback):
        target = request.target_vulnerabilities[0] if request.target_vulnerabilities else None
        analysis = build_analysis_input(request.task_id, sources, target_vulnerability=target)
    with progress_phase(timer, "workflow_routing", progress_callback):
        workflow = build_workflow(request, analysis)

    center = EvidenceCenter()
    with progress_phase(timer, "static_evidence_registration", progress_callback):
        center.register_functions(analysis.functions)
        center.add_static_evidence(analysis.functions, task_id=request.task_id)
    with progress_phase(timer, "model_adapter_inference", progress_callback):
        registry = build_default_registry(target_vulnerabilities=request.target_vulnerabilities or None)
        selected_adapters = registry.select_for_workflow(workflow.formal_models)
        evidences, adapter_results = execute_adapters(selected_adapters, analysis)
        center.add_many(evidences)

    with progress_phase(timer, "initial_risk_scoring_and_reasoning_gate", progress_callback):
        initial_risk_vectors = compute_risk_vectors(
            analysis.functions,
            center.grouped(),
            selected_vulnerabilities=request.target_vulnerabilities,
        )
        reasoning_selection = select_reasoning_targets(initial_risk_vectors)

    with progress_phase(timer, "knowledge_retrieval", progress_callback):
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

    with progress_phase(timer, "final_risk_scoring", progress_callback):
        risk_vectors = compute_risk_vectors(
            analysis.functions,
            center.grouped(),
            selected_vulnerabilities=request.target_vulnerabilities,
        )
    with progress_phase(timer, "reasoning_localization", progress_callback):
        findings, warnings = build_findings_and_warnings(
            analysis.functions,
            risk_vectors,
            center.grouped(),
            store=store,
            selected_vulnerabilities=request.target_vulnerabilities,
            reasoning_selection=reasoning_selection,
            knowledge_contexts=knowledge_contexts,
        )
    contract_summary = build_contract_summary(analysis.contracts, risk_vectors, findings, warnings)
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
            "contract_summary": contract_summary,
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
    if request.need_verification:
        with progress_phase(timer, "verification", progress_callback):
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


@contextmanager
def progress_phase(timer: PhaseTimer, name: str, callback: ProgressCallback | None):
    start, end, label = PHASE_PROGRESS.get(name, (20, 95, name))
    emit_progress(callback, start, label)
    with timer.phase(name):
        yield
    emit_progress(callback, end, label)


def emit_progress(callback: ProgressCallback | None, progress: int, phase: str) -> None:
    if callback is None:
        return
    callback(progress, phase)


def build_contract_summary(contracts, risk_vectors, findings, warnings) -> dict[str, Any]:
    vectors_by_contract: dict[str, list] = {}
    findings_by_contract: dict[str, list] = {}
    warnings_by_contract: dict[str, list] = {}
    for vector in risk_vectors:
        vectors_by_contract.setdefault(vector.contract_name, []).append(vector)
    for finding in findings:
        findings_by_contract.setdefault(finding.contract_name, []).append(finding)
    for warning in warnings:
        warnings_by_contract.setdefault(warning.contract_name, []).append(warning)

    projects = []
    abnormal_count = 0
    for contract in contracts:
        contract_vectors = vectors_by_contract.get(contract.name, [])
        contract_findings = findings_by_contract.get(contract.name, [])
        contract_warnings = warnings_by_contract.get(contract.name, [])
        max_risk = max((vector.r_func for vector in contract_vectors), default=0.0)
        status = contract_detection_status(contract_findings, contract_warnings, max_risk)
        if status == "abnormal":
            abnormal_count += 1
        vulnerabilities = sorted(
            {
                finding.vulnerability_id
                for finding in contract_findings
                if getattr(finding, "vulnerability_id", None)
            }
            | {
                warning.target_vulnerability
                for warning in contract_warnings
                if getattr(warning, "target_vulnerability", None)
            }
        )
        projects.append(
            {
                "project_id": f"{contract.source_path}::{contract.name}",
                "project_name": contract.name,
                "contract_name": contract.name,
                "source_path": contract.source_path,
                "function_count": len(contract.functions),
                "finding_count": len(contract_findings),
                "warning_count": len(contract_warnings),
                "max_risk": round(max_risk, 4),
                "severity": severity_from_score(max_risk),
                "status": status,
                "vulnerabilities": vulnerabilities,
                "finding_ids": [finding.finding_id for finding in contract_findings],
                "warning_ids": [warning.warning_id for warning in contract_warnings],
            }
        )

    projects.sort(key=lambda item: (item["status"] != "abnormal", -item["max_risk"], item["contract_name"]))
    total_contracts = len(contracts)
    return {
        "total_contracts": total_contracts,
        "input_contract_total": total_contracts,
        "normal_contracts": max(0, total_contracts - abnormal_count),
        "abnormal_contracts": abnormal_count,
        "projects": projects,
    }


def contract_detection_status(findings, warnings, max_risk: float) -> str:
    if findings or warnings:
        return "abnormal"
    if max_risk >= 0.45:
        return "abnormal"
    return "normal"


def severity_from_score(score: float) -> str:
    if score >= 0.70:
        return "high"
    if score >= 0.45:
        return "medium"
    if score > 0:
        return "low"
    return "none"


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

from __future__ import annotations

from typing import Dict, List, Tuple

from backend.agents.llm_reasoning_service import LLMReasoningService
from backend.function_risk.reasoning_gate import ReasoningSelection
from backend.rag.knowledge_context import KnowledgeContext
from backend.rag.jsonl_knowledge_store import JsonlKnowledgeStore
from backend.schemas import Finding, FunctionUnit, ModelEvidence, RiskVector, Warning


def build_findings_and_warnings(
    functions: List[FunctionUnit],
    risk_vectors: List[RiskVector],
    evidence_by_function: Dict[str, List[ModelEvidence]],
    store: JsonlKnowledgeStore | None = None,
    selected_vulnerabilities: List[str] | None = None,
    reasoning_selection: ReasoningSelection | None = None,
    knowledge_contexts: Dict[str, KnowledgeContext] | None = None,
    llm_service: LLMReasoningService | None = None,
) -> Tuple[List[Finding], List[Warning]]:
    selected = set(selected_vulnerabilities or [])
    fn_by_id = {fn.function_id: fn for fn in functions}
    findings: List[Finding] = []
    warnings: List[Warning] = []
    store = store or JsonlKnowledgeStore()
    knowledge_contexts = knowledge_contexts or {}
    llm_service = llm_service or LLMReasoningService()

    for vector in risk_vectors[:20]:
        if reasoning_selection and not reasoning_selection.contains(vector.function_id):
            continue
        fn = fn_by_id.get(vector.function_id)
        if not fn:
            continue
        evidences = evidence_by_function.get(vector.function_id, [])
        if not evidences and vector.r_func < 0.45:
            continue
        query = f"{fn.contract_name} {fn.name} {' '.join(fn.features.get('dangerous_apis', []))} {fn.code[:800]}"
        knowledge = store.search(query, top_k=3, agent="reasoning")
        knowledge_context = knowledge_contexts.get(vector.function_id)
        llm_result = None
        for evidence in evidences:
            if evidence.model_id in {"RAG_KNOWLEDGE", "STATIC_RULES"}:
                continue
            vulnerability_id = evidence.vulnerability_id or "VULN_UNKNOWN_ANOMALY"
            if selected and vulnerability_id not in selected and evidence.model_id.startswith("LSTM"):
                warnings.append(make_warning(vector, evidence))
                continue
            if evidence.calibrated_confidence >= 0.55 or vector.r_func >= 0.55:
                if llm_result is None and knowledge_context is not None:
                    llm_result = llm_service.reason(
                        fn,
                        vector,
                        evidences,
                        knowledge_context,
                        gate_reasons=(reasoning_selection.reasons.get(vector.function_id, []) if reasoning_selection else []),
                    )
                reasoning = llm_result or {}
                findings.append(Finding(
                    finding_id=f"F-{len(findings) + 1:04d}",
                    scope="in_scope",
                    status="suspected",
                    contract_name=fn.contract_name,
                    function_signature=fn.signature,
                    vulnerability_id=vulnerability_id,
                    severity=severity_from_score(max(evidence.calibrated_confidence, vector.r_func)),
                    confidence=max(evidence.calibrated_confidence, vector.r_func),
                    summary=reasoning.get("summary") or (
                        f"{fn.contract_name}.{fn.name} 存在来自 {evidence.model_id} 的 "
                        f"{vulnerability_id} 风险证据。"
                    ),
                    evidence=[evidence],
                    knowledge=knowledge,
                    location=reasoning.get("location") or evidence.location_candidates,
                    recommendation=(
                        reasoning.get("repair_suggestion", {}).get("strategy")
                        or recommendation_from_knowledge(knowledge)
                    ),
                    reasoning=reasoning,
                    verification_plan=reasoning.get("verification_plan", {}),
                    repair_suggestion=reasoning.get("repair_suggestion", {}),
                ))
        if vector.r_func >= 0.60 and not evidences:
            warnings.append(Warning(
                warning_id=f"W-{len(warnings) + 1:04d}",
                scope="out_of_scope",
                status="screening_warning",
                contract_name=fn.contract_name,
                function_signature=fn.signature,
                target_vulnerability="GENERAL_RISK",
                score=vector.r_func,
                summary=f"{fn.contract_name}.{fn.name} 在全局函数风险排序中处于较高风险位置。",
                recommended_action={"action": "review_high_risk_function", "target_vulnerability": "GENERAL_RISK"},
            ))
    return findings, warnings


def make_warning(vector: RiskVector, evidence: ModelEvidence) -> Warning:
    return Warning(
        warning_id=f"W-{abs(hash(evidence.evidence_id)) % 100000:05d}",
        scope="out_of_scope",
        status="screening_warning",
        contract_name=evidence.contract_name,
        function_signature=evidence.function_signature,
        target_vulnerability=evidence.vulnerability_id or "UNKNOWN",
        score=max(vector.r_func, evidence.calibrated_confidence),
        summary=f"{evidence.model_id} 检测到范围外风险候选项，建议发起对应专项检测。",
        recommended_action={
            "action": "start_new_scan",
            "target_vulnerability": evidence.vulnerability_id or "UNKNOWN",
        },
        evidence=[evidence],
    )


def severity_from_score(score: float) -> str:
    if score >= 0.80:
        return "high"
    if score >= 0.55:
        return "medium"
    return "low"


def recommendation_from_knowledge(knowledge: List[dict]) -> str | None:
    for item in knowledge:
        content = item.get("content", {})
        if isinstance(content, dict):
            if content.get("repair_strategy"):
                return content["repair_strategy"]
            if content.get("recommendation"):
                return content["recommendation"]
    return None

from __future__ import annotations

from collections import defaultdict
from typing import Dict, List, Set, Tuple

from backend.agents.llm_reasoning_service import LLMReasoningService
from backend.function_risk.reasoning_gate import ReasoningSelection
from backend.function_risk.risk_score import (
    DEFAULT_WARNING_CATEGORIES,
    normalize_vulnerability,
    semantic_category_allowed,
    static_category_score,
)
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
    selected = {normalize_vulnerability(item) for item in (selected_vulnerabilities or [])}
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

        grouped = group_primary_evidence(fn, vector, evidences, selected)
        warnings.extend(build_rejected_warnings(fn, vector, evidences, selected))
        warnings.extend(build_anomaly_warnings(fn, vector, evidences))

        for vulnerability_id, primary_evidences in grouped.items():
            if not semantic_category_allowed(fn, vulnerability_id):
                warnings.append(make_rejected_warning(fn, vector, vulnerability_id, primary_evidences, "静态语义不满足该漏洞类型。"))
                continue

            confidence = max(
                [vector.selected_scores.get(vulnerability_id, 0.0), static_category_score(fn, vulnerability_id)]
                + [item.calibrated_confidence for item in primary_evidences]
            )
            if confidence < 0.55 and vector.r_func < 0.55:
                continue

            finding_evidences = merge_evidences(primary_evidences + supporting_evidences(vulnerability_id, evidences))
            reasoning = {}
            if knowledge_context is not None:
                reasoning = llm_service.reason(
                    fn,
                    vector,
                    finding_evidences,
                    knowledge_context,
                    gate_reasons=(reasoning_selection.reasons.get(vector.function_id, []) if reasoning_selection else []),
                )

            reasoning_status = str(reasoning.get("status", "suspected"))
            if reasoning_status == "rejected":
                warnings.append(make_rejected_warning(
                    fn,
                    vector,
                    vulnerability_id,
                    finding_evidences,
                    reasoning.get("summary") or "大模型推理已排除该漏洞结论。",
                ))
                continue

            finding_status = reasoning_status if reasoning_status in {"suspected", "inconclusive"} else "suspected"
            findings.append(Finding(
                finding_id=f"F-{len(findings) + 1:04d}",
                scope="in_scope",
                status=finding_status,
                contract_name=fn.contract_name,
                function_signature=fn.signature,
                vulnerability_id=vulnerability_id,
                severity=severity_from_score(max(confidence, vector.r_func)),
                confidence=max(confidence, vector.r_func),
                summary=reasoning.get("summary") or default_finding_summary(fn, vulnerability_id, finding_evidences),
                evidence=finding_evidences,
                knowledge=knowledge,
                location=reasoning.get("location") or first_locations(finding_evidences),
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
    return findings, dedupe_warnings(warnings)


def group_primary_evidence(
    fn: FunctionUnit,
    vector: RiskVector,
    evidences: List[ModelEvidence],
    selected: Set[str],
) -> Dict[str, List[ModelEvidence]]:
    grouped: Dict[str, List[ModelEvidence]] = defaultdict(list)
    for evidence in evidences:
        if not is_primary_concrete_evidence(evidence):
            continue
        vulnerability_id = normalize_vulnerability(evidence.vulnerability_id or evidence.model_id)
        if selected and vulnerability_id not in selected and evidence.model_id.startswith("LSTM"):
            continue
        if semantic_category_allowed(fn, vulnerability_id):
            grouped[vulnerability_id].append(evidence)

    categories = selected or set(DEFAULT_WARNING_CATEGORIES)
    for category in categories:
        vulnerability_id = normalize_vulnerability(category)
        if vulnerability_id == "VULN_UNKNOWN_ANOMALY" or vulnerability_id in grouped:
            continue
        if static_category_score(fn, vulnerability_id) >= 0.55 or vector.selected_scores.get(vulnerability_id, 0.0) >= 0.55:
            static_evidences = [item for item in evidences if item.model_id == "STATIC_RULES"]
            if static_evidences:
                grouped[vulnerability_id].extend(static_evidences)
    return grouped


def is_primary_concrete_evidence(evidence: ModelEvidence) -> bool:
    if evidence.model_id in {"RAG_KNOWLEDGE", "STATIC_RULES"}:
        return False
    if evidence.model_id.startswith("DEEPSVDD"):
        return False
    vulnerability_id = normalize_vulnerability(evidence.vulnerability_id or evidence.model_id)
    return vulnerability_id not in {"UNKNOWN", "VULN_UNKNOWN_ANOMALY"}


def supporting_evidences(vulnerability_id: str, evidences: List[ModelEvidence]) -> List[ModelEvidence]:
    result: List[ModelEvidence] = []
    for evidence in evidences:
        if evidence.model_id in {"STATIC_RULES", "RAG_KNOWLEDGE"}:
            result.append(evidence)
        elif evidence.model_id.startswith("DEEPSVDD"):
            result.append(evidence)
        elif normalize_vulnerability(evidence.vulnerability_id or evidence.model_id) == vulnerability_id:
            result.append(evidence)
    return result


def build_rejected_warnings(
    fn: FunctionUnit,
    vector: RiskVector,
    evidences: List[ModelEvidence],
    selected: Set[str],
) -> List[Warning]:
    warnings: List[Warning] = []
    for evidence in evidences:
        if not is_primary_concrete_evidence(evidence):
            continue
        vulnerability_id = normalize_vulnerability(evidence.vulnerability_id or evidence.model_id)
        if selected and vulnerability_id not in selected and evidence.model_id.startswith("LSTM"):
            warnings.append(make_warning(vector, evidence))
            continue
        if evidence.calibrated_confidence >= 0.55 and not semantic_category_allowed(fn, vulnerability_id):
            warnings.append(make_rejected_warning(fn, vector, vulnerability_id, [evidence], "模型高分，但静态语义硬规则不支持该漏洞类型。"))
    return warnings


def build_anomaly_warnings(fn: FunctionUnit, vector: RiskVector, evidences: List[ModelEvidence]) -> List[Warning]:
    warnings: List[Warning] = []
    for evidence in evidences:
        if not evidence.model_id.startswith("DEEPSVDD"):
            continue
        if evidence.calibrated_confidence < 0.55:
            continue
        warnings.append(Warning(
            warning_id=f"W-{abs(hash(evidence.evidence_id)) % 100000:05d}",
            scope="out_of_scope",
            status="anomaly_warning",
            contract_name=fn.contract_name,
            function_signature=fn.signature,
            target_vulnerability="VULN_UNKNOWN_ANOMALY",
            score=max(vector.r_func, evidence.calibrated_confidence),
            summary="DeepSVDD 检测到行为异常信号，但该信号不直接等价于具体漏洞类型。",
            recommended_action={"action": "review_anomaly", "target_vulnerability": "VULN_UNKNOWN_ANOMALY"},
            evidence=[evidence],
        ))
    return warnings


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


def make_rejected_warning(
    fn: FunctionUnit,
    vector: RiskVector,
    vulnerability_id: str,
    evidences: List[ModelEvidence],
    reason: str,
) -> Warning:
    return Warning(
        warning_id=f"W-{abs(hash(fn.function_id + vulnerability_id + reason)) % 100000:05d}",
        scope="out_of_scope",
        status="rejected_false_positive",
        contract_name=fn.contract_name,
        function_signature=fn.signature,
        target_vulnerability=vulnerability_id,
        score=max([vector.r_func] + [item.calibrated_confidence for item in evidences]),
        summary=f"{vulnerability_id} 结论已被降级为误报/不成立：{reason}",
        recommended_action={"action": "review_rejected_result", "target_vulnerability": vulnerability_id},
        evidence=merge_evidences(evidences),
    )


def merge_evidences(evidences: List[ModelEvidence]) -> List[ModelEvidence]:
    merged: Dict[str, ModelEvidence] = {}
    for evidence in evidences:
        merged.setdefault(evidence.evidence_id, evidence)
    return list(merged.values())


def dedupe_warnings(warnings: List[Warning]) -> List[Warning]:
    merged: Dict[Tuple[str, str, str], Warning] = {}
    for warning in warnings:
        key = (warning.contract_name, warning.function_signature, warning.target_vulnerability)
        if key not in merged or warning.score > merged[key].score:
            merged[key] = warning
    return list(merged.values())


def first_locations(evidences: List[ModelEvidence]) -> List[dict]:
    for evidence in evidences:
        if evidence.location_candidates:
            return evidence.location_candidates
    return []


def default_finding_summary(fn: FunctionUnit, vulnerability_id: str, evidences: List[ModelEvidence]) -> str:
    models = ", ".join(sorted({item.model_id for item in evidences}))
    return f"{fn.contract_name}.{fn.name} 存在 {vulnerability_id} 风险证据，来源包括：{models}。"


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

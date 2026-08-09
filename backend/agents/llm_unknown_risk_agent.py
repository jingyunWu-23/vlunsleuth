from __future__ import annotations

from dataclasses import asdict
from typing import Any, Dict, List

from backend.agents.llm_client import LLMClient, PlaceholderLLMClient, build_llm_client
from backend.schemas import FunctionUnit, ModelEvidence, RiskVector


UNKNOWN_RISK_PROMPT = """You are an LLM Unknown Risk Agent for smart contract security.
Return strict JSON only. Do not use Markdown.
Your task is not to classify known vulnerability labels. Reason about whether an anomalous
function may contain a new semantic, business-logic, cross-function, asset-flow, permission,
or state-consistency risk.

Rules:
- Do not output known labels such as VULN_REENTRANCY, VULN_TIMESTAMP, VULN_DELEGATECALL,
  VULN_UNCHECKED_LOW_LEVEL_CALLS, VULN_ACCESS_CONTROL, VULN_ARITHMETIC,
  VULN_LOCKED_ETHER, or VULN_BAD_RANDOMNESS as the final target_vulnerability.
- If evidence is weak, return status "inconclusive".
- If you propose a risk, mark it as tentative and requiring human review.
- Natural-language fields should be Simplified Chinese.
"""


class LLMUnknownRiskAgent:
    def __init__(self, client: LLMClient | None = None) -> None:
        self.client = client or build_llm_client()

    def reason_unknown_risk(
        self,
        function: FunctionUnit,
        vector: RiskVector,
        anomaly_evidences: List[ModelEvidence],
        known_evidences: List[ModelEvidence],
    ) -> Dict[str, Any]:
        if isinstance(self.client, PlaceholderLLMClient):
            return build_inconclusive_result(
                function,
                vector,
                "LLM API is not configured; no generated unknown risk hypothesis was produced.",
            )
        payload = build_unknown_risk_payload(function, vector, anomaly_evidences, known_evidences)
        try:
            result = self.client.complete_json(UNKNOWN_RISK_PROMPT, payload)
        except Exception as exc:
            result = build_inconclusive_result(function, vector, f"{type(exc).__name__}: {exc}")
        if not isinstance(result, dict):
            result = build_inconclusive_result(function, vector, str(result))
        return normalize_unknown_result(result, function, vector)


def build_unknown_risk_payload(
    function: FunctionUnit,
    vector: RiskVector,
    anomaly_evidences: List[ModelEvidence],
    known_evidences: List[ModelEvidence],
) -> Dict[str, Any]:
    return {
        "task": "unknown_semantic_risk_reasoning",
        "target": {
            "source_path": function.source_path,
            "contract_name": function.contract_name,
            "function_name": function.name,
            "signature": function.signature,
            "start_line": function.start_line,
            "end_line": function.end_line,
            "visibility": function.visibility,
            "mutability": function.mutability,
            "modifiers": function.modifiers,
            "critical_statements": function.features.get("critical_statements", [])[:12],
            "dangerous_apis": function.features.get("dangerous_apis", []),
            "code": function.code[:5000],
        },
        "risk": {
            "r_func": vector.r_func,
            "lstm_score": vector.lstm_score,
            "anomaly_score": vector.anomaly_score,
            "static_score": vector.static_score,
            "business_score": vector.business_score,
            "protection_score": vector.protection_score,
            "component_reasons": vector.component_reasons,
        },
        "anomaly_evidence": [compact_evidence(item) for item in anomaly_evidences],
        "known_vulnerability_evidence": [compact_evidence(item) for item in known_evidences],
        "output_schema": {
            "status": "suspected | inconclusive | rejected",
            "target_vulnerability": "VULN_LLM_SEMANTIC_WARNING",
            "risk_title": "简体中文短标题",
            "risk_type_freeform": "snake_case_freeform_risk_type",
            "source": "LLM_GENERATED",
            "trust_level": "tentative",
            "requires_human_review": True,
            "confidence": "number between 0 and 1",
            "summary": "简体中文",
            "reasoning": ["简体中文"],
            "location": [{"line": "number", "code": "string", "reason": "简体中文"}],
            "verification_plan": {
                "goal": "简体中文",
                "static_checks": ["简体中文"],
                "dynamic_checks": ["简体中文"],
                "manual_review_points": ["简体中文"],
            },
            "repair_suggestion": {
                "strategy": "简体中文",
                "side_effects": ["简体中文"],
                "post_fix_checks": ["简体中文"],
            },
        },
    }


def compact_evidence(evidence: ModelEvidence) -> Dict[str, Any]:
    data = asdict(evidence)
    data["feature_evidence"] = data.get("feature_evidence", [])[:3]
    return data


def normalize_unknown_result(result: Dict[str, Any], function: FunctionUnit, vector: RiskVector) -> Dict[str, Any]:
    status = str(result.get("status") or "inconclusive")
    if status not in {"suspected", "inconclusive", "rejected"}:
        status = "inconclusive"
    confidence = safe_float(result.get("confidence"), default=max(vector.anomaly_score, vector.r_func))
    if status != "suspected":
        confidence = min(confidence, 0.54)
    result["status"] = status
    result["target_vulnerability"] = "VULN_LLM_SEMANTIC_WARNING" if status == "suspected" else "VULN_UNKNOWN_ANOMALY"
    result["source"] = "LLM_GENERATED" if status == "suspected" else "ANOMALY_SIGNAL"
    result["trust_level"] = "tentative"
    result["requires_human_review"] = True
    result["confidence"] = round(max(0.0, min(1.0, confidence)), 4)
    result.setdefault("risk_title", "大模型生成型未知语义风险" if status == "suspected" else "未知行为异常")
    result.setdefault("risk_type_freeform", "llm_semantic_unknown_risk" if status == "suspected" else "unknown_anomaly")
    result.setdefault(
        "summary",
        f"{function.contract_name}.{function.name} 出现未知异常信号，当前结论需要人工复核。",
    )
    result.setdefault("reasoning", [])
    result.setdefault("location", function.features.get("critical_statements", [])[:5])
    result.setdefault("verification_plan", {})
    result.setdefault("repair_suggestion", {})
    return result


def build_inconclusive_result(function: FunctionUnit, vector: RiskVector, reason: str) -> Dict[str, Any]:
    return {
        "status": "inconclusive",
        "target_vulnerability": "VULN_UNKNOWN_ANOMALY",
        "risk_title": "未知行为异常",
        "risk_type_freeform": "unknown_anomaly",
        "source": "ANOMALY_SIGNAL",
        "trust_level": "tentative",
        "requires_human_review": True,
        "confidence": max(vector.anomaly_score, min(vector.r_func, 0.54)),
        "summary": f"{function.contract_name}.{function.name} 存在异常信号，但尚未形成可解释的新漏洞假设。",
        "reasoning": [reason],
        "location": function.features.get("critical_statements", [])[:5],
        "verification_plan": {
            "goal": "人工复核异常路径，确认是否存在业务逻辑、权限、资产流或状态一致性风险。",
            "manual_review_points": ["检查异常路径是否可达。", "检查是否存在资产或权限影响。"],
        },
        "repair_suggestion": {},
    }


def safe_float(value: Any, default: float = 0.0) -> float:
    try:
        return float(value)
    except (TypeError, ValueError):
        return float(default)

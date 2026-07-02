from __future__ import annotations

from dataclasses import asdict
from typing import Any, Dict, List

from backend.agents.llm_client import LLMClient, build_llm_client
from backend.rag.knowledge_context import KnowledgeContext
from backend.schemas import FunctionUnit, ModelEvidence, RiskVector


SYSTEM_PROMPT = """You are a smart-contract security reasoning agent.
Return strict JSON only. Do not change upstream model scores.
You may output suspected risks, localization, verification plans, and repair suggestions.
Do not mark a vulnerability as verified without external tool evidence."""


class LLMReasoningService:
    def __init__(self, client: LLMClient | None = None) -> None:
        self.client = client or build_llm_client()

    def reason(
        self,
        function: FunctionUnit,
        vector: RiskVector,
        evidences: List[ModelEvidence],
        knowledge_context: KnowledgeContext,
        gate_reasons: List[str] | None = None,
    ) -> Dict[str, Any]:
        payload = build_reasoning_payload(function, vector, evidences, knowledge_context, gate_reasons or [])
        try:
            result = self.client.complete_json(SYSTEM_PROMPT, payload)
        except NotImplementedError:
            result = build_not_configured_result(function, vector)
        except Exception as exc:
            result = build_llm_error_result(function, vector, exc)
        if not isinstance(result, dict):
            result = {"status": "inconclusive", "summary": str(result)}
        result.setdefault("status", "suspected")
        result.setdefault("summary", f"{function.contract_name}.{function.name} selected for reasoning.")
        result.setdefault("verification_plan", {})
        result.setdefault("repair_suggestion", {})
        return result


def build_reasoning_payload(
    function: FunctionUnit,
    vector: RiskVector,
    evidences: List[ModelEvidence],
    knowledge_context: KnowledgeContext,
    gate_reasons: List[str],
) -> Dict[str, Any]:
    return {
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
            "critical_statements": function.features.get("critical_statements", [])[:10],
            "code": function.code[:4000],
        },
        "risk": {
            "r_func": vector.r_func,
            "selected_scores": vector.selected_scores,
            "warning_scores": vector.warning_scores,
            "components": {
                "anomaly_score": vector.anomaly_score,
                "gcn_score": vector.gcn_score,
                "static_score": vector.static_score,
                "business_score": vector.business_score,
                "knowledge_score": vector.knowledge_score,
                "consistency_score": vector.consistency_score,
                "protection_score": vector.protection_score,
            },
            "component_reasons": vector.component_reasons,
            "gate_reasons": gate_reasons,
        },
        "evidence": [compact_evidence(item) for item in evidences],
        "knowledge_context": knowledge_context.compact(max_items=10),
        "output_schema": {
            "status": "suspected | rejected | inconclusive",
            "candidate_vulnerability": "string",
            "summary": "string",
            "reasoning": ["string"],
            "location": [{"line": "number", "code": "string", "reason": "string"}],
            "verification_plan": {"goal": "string", "static_checks": ["string"], "dynamic_checks": ["string"]},
            "repair_suggestion": {"strategy": "string", "patch_pattern": "string", "post_fix_checks": ["string"]},
            "confidence_adjustment": "number between -0.2 and 0.2",
        },
    }


def compact_evidence(evidence: ModelEvidence) -> Dict[str, Any]:
    data = asdict(evidence)
    feature_evidence = data.get("feature_evidence", [])
    compact_features = []
    for item in feature_evidence[:3]:
        compact = dict(item)
        if "features" in compact and isinstance(compact["features"], dict):
            features = compact["features"]
            compact["features"] = {
                "dangerous_apis": features.get("dangerous_apis", []),
                "critical_statements": features.get("critical_statements", [])[:8],
                "static_score": features.get("static_score"),
                "business_score": features.get("business_score"),
                "protection_score": features.get("protection_score"),
            }
        compact_features.append(compact)
    data["feature_evidence"] = compact_features
    return data


def build_not_configured_result(function: FunctionUnit, vector: RiskVector) -> Dict[str, Any]:
    return {
        "status": "inconclusive",
        "candidate_vulnerability": "MODEL_API_NOT_CONFIGURED",
        "summary": (
            f"{function.contract_name}.{function.name} passed the reasoning gate "
            f"(R_func={vector.r_func}), but the large-model API hook is not configured."
        ),
        "reasoning": ["Fill OpenAICompatibleLLMClient.complete_json() to enable real model reasoning."],
        "verification_plan": {
            "goal": "Configure LLM API, then generate a vulnerability-specific verification plan.",
            "static_checks": [],
            "dynamic_checks": [],
        },
        "repair_suggestion": {
            "strategy": "No model-generated repair suggestion because LLM API is not configured.",
            "post_fix_checks": [],
        },
        "confidence_adjustment": 0.0,
    }


def build_llm_error_result(function: FunctionUnit, vector: RiskVector, exc: Exception) -> Dict[str, Any]:
    return {
        "status": "inconclusive",
        "candidate_vulnerability": "LLM_API_ERROR",
        "summary": (
            f"{function.contract_name}.{function.name} passed the reasoning gate "
            f"(R_func={vector.r_func}), but the large-model API call failed."
        ),
        "reasoning": [f"{type(exc).__name__}: {exc}"],
        "verification_plan": {
            "goal": "Retry large-model reasoning after fixing API connectivity or response format.",
            "static_checks": [],
            "dynamic_checks": [],
        },
        "repair_suggestion": {
            "strategy": "No model-generated repair suggestion because the LLM API call failed.",
            "post_fix_checks": [],
        },
        "confidence_adjustment": 0.0,
    }

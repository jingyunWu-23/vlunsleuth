from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List

from backend.rag.jsonl_knowledge_store import JsonlKnowledgeStore
from backend.schemas import FunctionUnit, RiskVector


AGENT_TARGETS = ["reasoning", "localization", "verification", "repair", "report"]


@dataclass
class KnowledgeContext:
    function_id: str
    query: str
    items: List[Dict[str, Any]] = field(default_factory=list)
    by_agent: Dict[str, List[Dict[str, Any]]] = field(default_factory=dict)

    def compact(self, max_items: int = 8) -> Dict[str, Any]:
        compact_items = []
        for item in self.items[:max_items]:
            compact_items.append({
                "knowledge_id": item.get("knowledge_id"),
                "knowledge_type": item.get("knowledge_type"),
                "swc_id": item.get("swc_id"),
                "vulnerability_name": item.get("vulnerability_name"),
                "risk_level": item.get("risk_level"),
                "contract_name": item.get("contract_name"),
                "function_name": item.get("function_name"),
                "source_file": item.get("source_file"),
                "start_line": item.get("start_line"),
                "end_line": item.get("end_line"),
                "content": summarize_content(item.get("content")),
            })
        return {
            "function_id": self.function_id,
            "query": self.query[:1200],
            "items": compact_items,
            "agent_counts": {key: len(value) for key, value in self.by_agent.items()},
        }


def build_knowledge_context(
    store: JsonlKnowledgeStore,
    function: FunctionUnit,
    vector: RiskVector | None = None,
    top_k: int = 5,
) -> KnowledgeContext:
    query = build_knowledge_query(function, vector)
    merged: Dict[str, Dict[str, Any]] = {}
    by_agent: Dict[str, List[Dict[str, Any]]] = {}

    general = store.search(query, top_k=top_k)
    for item in general:
        merged[item.get("knowledge_id", str(id(item)))] = item

    for agent in AGENT_TARGETS:
        items = store.search(query, top_k=top_k, agent=agent)
        by_agent[agent] = items
        for item in items:
            merged[item.get("knowledge_id", str(id(item)))] = item

    return KnowledgeContext(
        function_id=function.function_id,
        query=query,
        items=list(merged.values()),
        by_agent=by_agent,
    )


def build_knowledge_query(function: FunctionUnit, vector: RiskVector | None = None) -> str:
    features = function.features
    score_text = ""
    if vector:
        score_text = (
            f"R_func={vector.r_func} static={vector.static_score} anomaly={vector.anomaly_score} "
            f"knowledge={vector.knowledge_score} consistency={vector.consistency_score}"
        )
    parts = [
        function.contract_name,
        function.name,
        function.signature,
        score_text,
        " ".join(features.get("dangerous_apis", [])),
        " ".join(str(item.get("code", "")) for item in features.get("critical_statements", [])[:5]),
        function.code[:1200],
    ]
    return "\n".join(part for part in parts if part)


def summarize_content(content: Any) -> Any:
    if isinstance(content, dict):
        summary: Dict[str, Any] = {}
        for key in (
            "cause",
            "trigger_conditions",
            "dangerous_patterns",
            "verification_goal",
            "static_checks",
            "repair_strategy",
            "patch_pattern",
            "recommendation",
            "summary",
            "impact",
        ):
            if key in content:
                summary[key] = content[key]
        return summary or {key: str(value)[:300] for key, value in list(content.items())[:5]}
    if isinstance(content, str):
        return content[:800]
    return content

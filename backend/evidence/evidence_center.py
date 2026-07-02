from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass, field
from typing import Any, Dict, Iterable, List, Optional

from backend.schemas import FunctionUnit, ModelEvidence


@dataclass
class FunctionEvidenceBundle:
    function: Optional[FunctionUnit] = None
    evidences: List[ModelEvidence] = field(default_factory=list)

    def by_prefix(self, prefix: str) -> List[ModelEvidence]:
        return [item for item in self.evidences if item.model_id.startswith(prefix)]


class EvidenceCenter:
    def __init__(self) -> None:
        self._bundles: Dict[str, FunctionEvidenceBundle] = defaultdict(FunctionEvidenceBundle)

    def register_functions(self, functions: Iterable[FunctionUnit]) -> None:
        for fn in functions:
            self._bundles[fn.function_id].function = fn

    def add_many(self, evidences: Iterable[ModelEvidence]) -> None:
        for evidence in evidences:
            self.add(evidence)

    def add(self, evidence: ModelEvidence) -> None:
        self._bundles[evidence.function_id].evidences.append(evidence)

    def add_static_evidence(self, functions: Iterable[FunctionUnit], task_id: str) -> None:
        for fn in functions:
            features = fn.features
            score = float(features.get("static_score", 0.0))
            if score <= 0.0 and not features.get("critical_statements"):
                continue
            concise_features = {
                "dangerous_apis": features.get("dangerous_apis", []),
                "critical_statements": features.get("critical_statements", [])[:20],
                "unchecked_low_level_call": features.get("unchecked_low_level_call", False),
                "external_before_state_update": features.get("external_before_state_update", False),
                "loop_external_call": features.get("loop_external_call", False),
                "protection_terms": features.get("protection_terms", []),
                "business_score": features.get("business_score", 0.0),
                "protection_score": features.get("protection_score", 0.0),
            }
            self.add(ModelEvidence(
                evidence_id=f"{task_id}-static-{abs(hash(fn.function_id))}",
                model_id="STATIC_RULES",
                scope="function",
                contract_name=fn.contract_name,
                function_signature=fn.signature,
                function_id=fn.function_id,
                vulnerability_id=None,
                raw_score=score,
                calibrated_confidence=score,
                label="static_risk" if score >= 0.4 else "static_signal",
                location_candidates=[
                    {"start_line": item.get("line"), "end_line": item.get("line"), "roles": item.get("roles", [])}
                    for item in features.get("critical_statements", [])[:20]
                ],
                feature_evidence=[{"type": "static_features", "features": concise_features}],
                metadata={"source": "backend.preprocessing.feature_extractor"},
            ))

    def add_knowledge_evidence(
        self,
        function: FunctionUnit,
        knowledge_items: List[Dict[str, Any]],
        task_id: str,
    ) -> None:
        if not knowledge_items:
            return
        score = knowledge_similarity_score(knowledge_items)
        swc_ids = sorted({item.get("swc_id", "unknown") for item in knowledge_items if item.get("swc_id")})
        self.add(ModelEvidence(
            evidence_id=f"{task_id}-rag-{abs(hash(function.function_id))}",
            model_id="RAG_KNOWLEDGE",
            scope="function",
            contract_name=function.contract_name,
            function_signature=function.signature,
            function_id=function.function_id,
            vulnerability_id=swc_ids[0] if len(swc_ids) == 1 else None,
            raw_score=score,
            calibrated_confidence=score,
            label="knowledge_match" if score >= 0.5 else "weak_knowledge_match",
            location_candidates=[
                {
                    "source_file": item.get("source_file"),
                    "start_line": item.get("start_line"),
                    "end_line": item.get("end_line"),
                    "swc_id": item.get("swc_id"),
                }
                for item in knowledge_items[:5]
            ],
            feature_evidence=[{
                "type": "rag_matches",
                "matches": [
                    {
                        "knowledge_id": item.get("knowledge_id"),
                        "knowledge_type": item.get("knowledge_type"),
                        "swc_id": item.get("swc_id"),
                        "vulnerability_name": item.get("vulnerability_name"),
                        "risk_level": item.get("risk_level"),
                    }
                    for item in knowledge_items[:5]
                ],
            }],
            metadata={"source": "dataset/knowledge/unified_multi_agent_knowledge.jsonl"},
        ))

    def by_function(self, function_id: str) -> List[ModelEvidence]:
        return list(self._bundles.get(function_id, FunctionEvidenceBundle()).evidences)

    def bundle(self, function_id: str) -> FunctionEvidenceBundle:
        return self._bundles.get(function_id, FunctionEvidenceBundle())

    def all(self) -> List[ModelEvidence]:
        items: List[ModelEvidence] = []
        for bundle in self._bundles.values():
            items.extend(bundle.evidences)
        return items

    def grouped(self) -> Dict[str, List[ModelEvidence]]:
        return {key: list(value.evidences) for key, value in self._bundles.items()}

    def summary(self) -> Dict[str, Any]:
        model_counts: Dict[str, int] = defaultdict(int)
        for evidence in self.all():
            model_counts[evidence.model_id] += 1
        return {
            "function_count": len(self._bundles),
            "evidence_count": len(self.all()),
            "model_counts": dict(sorted(model_counts.items())),
        }


def knowledge_similarity_score(items: List[Dict[str, Any]]) -> float:
    if not items:
        return 0.0
    type_bonus = len({item.get("knowledge_type") for item in items}) * 0.08
    risk_bonus = 0.10 if any(item.get("risk_level") == "high" for item in items) else 0.0
    ground_truth_bonus = 0.10 if any(item.get("quality", {}).get("is_ground_truth") for item in items) else 0.0
    base = min(0.55, 0.18 + 0.07 * len(items))
    return round(min(1.0, base + type_bonus + risk_bonus + ground_truth_bonus), 4)

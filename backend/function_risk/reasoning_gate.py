from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List, Set

from backend.schemas import RiskVector


@dataclass
class ReasoningGateConfig:
    min_r_func: float = 0.35
    min_selected_score: float = 0.45
    high_confidence_model_score: float = 0.55
    small_project_top_k: int = 10
    medium_project_top_k: int = 20
    large_project_ratio: float = 0.10
    large_project_max_k: int = 50


@dataclass
class ReasoningSelection:
    selected_function_ids: Set[str]
    max_candidates: int
    reasons: Dict[str, List[str]] = field(default_factory=dict)

    def contains(self, function_id: str) -> bool:
        return function_id in self.selected_function_ids


def select_reasoning_targets(
    risk_vectors: List[RiskVector],
    config: ReasoningGateConfig | None = None,
) -> ReasoningSelection:
    config = config or ReasoningGateConfig()
    max_candidates = candidate_budget(len(risk_vectors), config)
    selected: Set[str] = set()
    reasons: Dict[str, List[str]] = {}

    for vector in risk_vectors[:max_candidates]:
        vector_reasons: List[str] = []
        if vector.r_func >= config.min_r_func:
            vector_reasons.append(f"R_func >= {config.min_r_func}")
        if max(vector.selected_scores.values(), default=0.0) >= config.min_selected_score:
            vector_reasons.append(f"R_selected >= {config.min_selected_score}")
        model_max = max(
            vector.anomaly_score,
            vector.gcn_score,
            max(vector.selected_scores.values(), default=0.0),
        )
        if model_max >= config.high_confidence_model_score:
            vector_reasons.append(f"high confidence model score >= {config.high_confidence_model_score}")
        if vector_reasons:
            selected.add(vector.function_id)
            reasons[vector.function_id] = vector_reasons

    return ReasoningSelection(selected_function_ids=selected, max_candidates=max_candidates, reasons=reasons)


def candidate_budget(function_count: int, config: ReasoningGateConfig) -> int:
    if function_count <= config.small_project_top_k:
        return min(function_count, config.small_project_top_k)
    if function_count <= 100:
        return min(function_count, config.medium_project_top_k)
    return min(function_count, max(1, int(function_count * config.large_project_ratio)), config.large_project_max_k)

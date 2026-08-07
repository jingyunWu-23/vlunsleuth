from __future__ import annotations

from collections import defaultdict
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
    per_contract_top_k: int = 5


@dataclass
class ReasoningSelection:
    selected_function_ids: Set[str]
    max_candidates: int
    reasons: Dict[str, List[str]] = field(default_factory=dict)
    strategy: str = "global_risk_top_k"
    component_count: int = 0
    contract_count: int = 0
    per_contract_top_k: int = 0

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
        vector_reasons = gate_reasons(vector, config)
        if vector_reasons:
            selected.add(vector.function_id)
            reasons[vector.function_id] = vector_reasons

    return ReasoningSelection(selected_function_ids=selected, max_candidates=max_candidates, reasons=reasons)


def select_reasoning_targets_by_project(
    risk_vectors: List[RiskVector],
    function_contracts: Dict[str, str],
    contract_components: Dict[str, str],
    config: ReasoningGateConfig | None = None,
) -> ReasoningSelection:
    config = config or ReasoningGateConfig()
    grouped: Dict[str, Dict[str, List[RiskVector]]] = defaultdict(lambda: defaultdict(list))
    for vector in risk_vectors:
        contract_key = function_contracts.get(vector.function_id) or f"unknown:{vector.contract_name}"
        component_id = contract_components.get(contract_key, "component_unknown")
        grouped[component_id][contract_key].append(vector)

    selected: Set[str] = set()
    reasons: Dict[str, List[str]] = {}
    for component_id in sorted(grouped):
        for contract_key in sorted(grouped[component_id]):
            vectors = sorted(grouped[component_id][contract_key], key=lambda item: item.r_func, reverse=True)
            for rank, vector in enumerate(vectors[:config.per_contract_top_k], 1):
                vector_reasons = gate_reasons(vector, config)
                if not vector_reasons:
                    continue
                vector_reasons.append(f"project component={component_id}")
                vector_reasons.append(f"contract top-{config.per_contract_top_k} rank={rank}")
                selected.add(vector.function_id)
                reasons[vector.function_id] = vector_reasons

    return ReasoningSelection(
        selected_function_ids=selected,
        max_candidates=len(selected),
        reasons=reasons,
        strategy="project_component_contract_top_k",
        component_count=len(grouped),
        contract_count=sum(len(contracts) for contracts in grouped.values()),
        per_contract_top_k=config.per_contract_top_k,
    )


def gate_reasons(vector: RiskVector, config: ReasoningGateConfig) -> List[str]:
    reasons: List[str] = []
    if vector.r_func >= config.min_r_func:
        reasons.append(f"R_func >= {config.min_r_func}")
    if max(vector.selected_scores.values(), default=0.0) >= config.min_selected_score:
        reasons.append(f"R_selected >= {config.min_selected_score}")
    model_max = max(
        vector.anomaly_score,
        vector.gcn_score,
        max(vector.selected_scores.values(), default=0.0),
    )
    if model_max >= config.high_confidence_model_score:
        reasons.append(f"high confidence model score >= {config.high_confidence_model_score}")
    return reasons


def candidate_budget(function_count: int, config: ReasoningGateConfig) -> int:
    if function_count <= config.small_project_top_k:
        return min(function_count, config.small_project_top_k)
    if function_count <= 100:
        return min(function_count, config.medium_project_top_k)
    return min(function_count, max(1, int(function_count * config.large_project_ratio)), config.large_project_max_k)

from __future__ import annotations

from typing import Dict, Iterable, List, Tuple

from backend.model_adapters.base import AdapterExecutionResult, DetectionModel
from backend.schemas import AnalysisInput, ModelEvidence


def execute_adapters(
    adapters: Iterable[DetectionModel],
    analysis: AnalysisInput,
) -> Tuple[List[ModelEvidence], List[AdapterExecutionResult]]:
    evidences: List[ModelEvidence] = []
    results: List[AdapterExecutionResult] = []
    for adapter in adapters:
        result = adapter.run(analysis)
        results.append(result)
        evidences.extend(result.evidences)
    return evidences, results


def adapter_results_to_metadata(results: Iterable[AdapterExecutionResult]) -> Dict[str, dict]:
    return {
        result.adapter_id: {
            "adapter_id": result.adapter_id,
            "status": result.status,
            "evidence_count": len(result.evidences),
            "warnings": result.warnings,
            "metadata": result.metadata,
        }
        for result in results
    }

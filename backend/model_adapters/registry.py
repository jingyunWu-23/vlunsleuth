from __future__ import annotations

from typing import Dict, Iterable, List, Optional, Set

from backend.model_adapters.base import DetectionModel
from backend.model_adapters.deepsvdd_adapter import DeepSVDDAdapter
from backend.model_adapters.gcn_adapter import GCNAdapter
from backend.model_adapters.lstm_adapter import LSTMAdapter


class ModelAdapterRegistry:
    def __init__(self) -> None:
        self._adapters: Dict[str, DetectionModel] = {}

    def register(self, adapter: DetectionModel) -> None:
        self._adapters[adapter.adapter_id] = adapter

    def all(self) -> List[DetectionModel]:
        return list(self._adapters.values())

    def select_for_workflow(self, formal_models: Iterable[str]) -> List[DetectionModel]:
        requested: Set[str] = set(formal_models)
        selected: List[DetectionModel] = []
        for adapter in self.all():
            if requested.intersection(adapter.workflow_model_ids):
                selected.append(adapter)
        return selected

    def describe(self) -> List[dict]:
        return [adapter.metadata() for adapter in self.all()]


def build_default_registry(
    target_vulnerabilities: Optional[Iterable[str]] = None,
    lstm_model_dir: Optional[str] = None,
) -> ModelAdapterRegistry:
    registry = ModelAdapterRegistry()
    registry.register(LSTMAdapter(
        model_dir=lstm_model_dir or "LG-DeepSVDD/pretrain/semantic features/LSTM/outputs",
        target_vulnerabilities=target_vulnerabilities,
    ))
    registry.register(DeepSVDDAdapter())
    registry.register(GCNAdapter())
    return registry


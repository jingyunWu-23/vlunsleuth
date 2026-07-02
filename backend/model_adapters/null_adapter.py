from __future__ import annotations

from typing import List

from backend.model_adapters.base import DetectionModel
from backend.schemas import AnalysisInput, ModelEvidence


class NullAdapter(DetectionModel):
    def __init__(self, adapter_id: str, model_family: str, workflow_model_ids: List[str]) -> None:
        self.adapter_id = adapter_id
        self.model_family = model_family
        self.workflow_model_ids = workflow_model_ids

    def analyze(self, analysis: AnalysisInput) -> List[ModelEvidence]:
        raise NotImplementedError(
            f"{self.adapter_id} is registered as a placeholder; real model inference is not connected yet."
        )


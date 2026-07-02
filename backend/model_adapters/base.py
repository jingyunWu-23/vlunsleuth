from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any, Dict, List

from backend.schemas import AnalysisInput, ModelEvidence


@dataclass
class AdapterExecutionResult:
    adapter_id: str
    status: str
    evidences: List[ModelEvidence] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)


class DetectionModel(ABC):
    adapter_id: str
    model_family: str
    workflow_model_ids: List[str]

    def is_available(self) -> bool:
        return True

    def run(self, analysis: AnalysisInput) -> AdapterExecutionResult:
        if not self.is_available():
            return AdapterExecutionResult(
                adapter_id=self.adapter_id,
                status="skipped",
                warnings=["Adapter is not available in the current environment."],
                metadata=self.metadata(),
            )
        try:
            evidences = self.analyze(analysis)
        except NotImplementedError as exc:
            return AdapterExecutionResult(
                adapter_id=self.adapter_id,
                status="not_implemented",
                warnings=[str(exc) or "Adapter inference is not implemented yet."],
                metadata=self.metadata(),
            )
        except Exception as exc:
            return AdapterExecutionResult(
                adapter_id=self.adapter_id,
                status="error",
                warnings=[f"{type(exc).__name__}: {exc}"],
                metadata=self.metadata(),
            )
        return AdapterExecutionResult(
            adapter_id=self.adapter_id,
            status="ok",
            evidences=evidences,
            metadata=self.metadata(),
        )

    def metadata(self) -> Dict[str, Any]:
        return {
            "adapter_id": self.adapter_id,
            "model_family": self.model_family,
            "workflow_model_ids": self.workflow_model_ids,
        }

    @abstractmethod
    def analyze(self, analysis: AnalysisInput) -> List[ModelEvidence]:
        raise NotImplementedError

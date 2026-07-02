from __future__ import annotations

from typing import List

from backend.model_adapters.base import DetectionModel
from backend.schemas import AnalysisInput, ModelEvidence


class DeepSVDDAdapter(DetectionModel):
    adapter_id = "deepsvdd_adapter"
    model_family = "DeepSVDD"
    workflow_model_ids = ["DEEPSVDD"]

    def metadata(self) -> dict:
        data = super().metadata()
        data.update({
            "real_inference_hook": "Call LG-DeepSVDD/DeepSVDD scoring here after the function-level feature pipeline is finalized.",
        })
        return data

    def analyze(self, analysis: AnalysisInput) -> List[ModelEvidence]:
        evidences: List[ModelEvidence] = []
        for fn in analysis.functions:
            score = self._anomaly_score(fn.features)
            if score < 0.35:
                continue
            evidences.append(ModelEvidence(
                evidence_id=f"{analysis.task_id}-deepsvdd-{abs(hash(fn.function_id))}",
                model_id="DEEPSVDD_UNKNOWN_ANOMALY",
                scope="function",
                contract_name=fn.contract_name,
                function_signature=fn.signature,
                function_id=fn.function_id,
                vulnerability_id=None,
                raw_score=score,
                calibrated_confidence=score,
                label="anomaly" if score >= 0.60 else "weak_anomaly",
                location_candidates=[{"start_line": fn.start_line, "end_line": fn.end_line}],
                feature_evidence=[{"type": "anomaly_feature_proxy", "features": fn.features}],
                metadata={"adapter_mode": "static_proxy_until_deepsvdd_feature_pipeline_is_connected"},
            ))
        return evidences

    def _anomaly_score(self, features: dict) -> float:
        static_score = float(features.get("static_score", 0.0))
        business_score = float(features.get("business_score", 0.0))
        dangerous_count = len(features.get("dangerous_apis", []))
        score = 0.45 * static_score + 0.30 * business_score + 0.08 * dangerous_count
        return round(max(0.0, min(1.0, score)), 4)

from __future__ import annotations

import json
import math
import os
from hashlib import sha1
from pathlib import Path
from typing import Any, Dict, List, Tuple

import numpy as np

from backend.model_adapters.base import DetectionModel
from backend.schemas import AnalysisInput, FunctionUnit, ModelEvidence


DEFAULT_MODEL_STEM = "svdd_scg_reentrancy_gen0_LSTM"


class DeepSVDDAdapter(DetectionModel):
    adapter_id = "deepsvdd_adapter"
    model_family = "DeepSVDD"
    workflow_model_ids = ["DEEPSVDD"]

    def __init__(
        self,
        model_dir: str | None = None,
        model_stem: str | None = None,
        evidence_floor: float = 0.35,
    ) -> None:
        self.model_dir = Path(
            model_dir
            or os.getenv("SCG_DEEPSVDD_MODEL_DIR")
            or "LG-DeepSVDD/DeepSVDD/outputs/models"
        ).resolve()
        self.model_stem = model_stem or os.getenv("SCG_DEEPSVDD_MODEL_STEM") or DEFAULT_MODEL_STEM
        self.encoder_path = Path(os.getenv("SCG_DEEPSVDD_ENCODER") or self.model_dir / f"{self.model_stem}_encoder.h5").resolve()
        self.meta_npz_path = Path(os.getenv("SCG_DEEPSVDD_META_NPZ") or self.model_dir / f"{self.model_stem}_meta.npz").resolve()
        self.meta_json_path = Path(os.getenv("SCG_DEEPSVDD_META_JSON") or self.model_dir / f"{self.model_stem}_meta.json").resolve()
        self.evidence_floor = float(os.getenv("SCG_DEEPSVDD_EVIDENCE_FLOOR", str(evidence_floor)))
        self._encoder = None
        self._meta: Dict[str, Any] | None = None
        self._runtime_error: str | None = None

    def is_available(self) -> bool:
        return self.encoder_path.exists() and self.meta_npz_path.exists()

    def metadata(self) -> dict:
        data = super().metadata()
        meta = self._load_meta_only()
        data.update({
            "model_stem": self.model_stem,
            "encoder_path": str(self.encoder_path),
            "meta_npz_path": str(self.meta_npz_path),
            "meta_json_path": str(self.meta_json_path),
            "input_shape": meta.get("shape"),
            "latent_dim": meta.get("latent_dim"),
            "threshold": meta.get("threshold"),
            "threshold_percentile": meta.get("threshold_percentile"),
            "vul_type": meta.get("vul_type"),
            "runtime_status": self._runtime_status(),
            "real_inference": "Enabled when TensorFlow can load the DeepSVDD encoder.",
        })
        return data

    def analyze(self, analysis: AnalysisInput) -> List[ModelEvidence]:
        try:
            encoder, meta = self._load_runtime()
        except Exception as exc:
            self._runtime_error = f"{type(exc).__name__}: {exc}"
            return self._static_proxy(analysis, adapter_mode="static_proxy_after_deepsvdd_load_error")

        evidences: List[ModelEvidence] = []
        for fn in analysis.functions:
            vector, vector_meta = self._vectorize_function(fn, int(meta["shape"]))
            latent = encoder.predict(vector.reshape(1, -1), verbose=0)
            raw_score = float(np.sum((latent[0] - meta["c"]) ** 2))
            threshold = float(meta["threshold"])
            calibrated = self._calibrate(raw_score, threshold)
            prediction = 1 if raw_score > threshold else 0
            if prediction == 0 and calibrated < self.evidence_floor:
                continue
            label = "anomaly" if prediction == 1 else "weak_anomaly"
            evidences.append(ModelEvidence(
                evidence_id=f"{analysis.task_id}-deepsvdd-{_stable_hash(fn.function_id)}",
                model_id="DEEPSVDD_REENTRANCY_ANOMALY",
                scope="function",
                contract_name=fn.contract_name,
                function_signature=fn.signature,
                function_id=fn.function_id,
                vulnerability_id="VULN_UNKNOWN_ANOMALY",
                raw_score=round(raw_score, 6),
                calibrated_confidence=round(calibrated, 4),
                label=label,
                location_candidates=[{"start_line": fn.start_line, "end_line": fn.end_line}],
                feature_evidence=[{
                    "type": "deepsvdd_lstm_encoder_distance",
                    "score": round(raw_score, 6),
                    "threshold": round(threshold, 6),
                    "distance_ratio": round(raw_score / threshold, 6) if threshold > 0 else None,
                    "prediction": prediction,
                    "vectorization": vector_meta,
                }],
                metadata={
                    "adapter_mode": "deepsvdd_h5_inference",
                    "model_stem": self.model_stem,
                    "model_vulnerability": meta.get("vul_type", "reentrancy"),
                    "encoder_path": str(self.encoder_path),
                    "meta_npz_path": str(self.meta_npz_path),
                    "threshold_percentile": meta.get("threshold_percentile"),
                    "nu": meta.get("nu"),
                    "regul": meta.get("regul"),
                    "latent_dim": int(meta["c"].shape[0]),
                },
            ))
        return evidences

    def _load_runtime(self) -> Tuple[Any, Dict[str, Any]]:
        if self._encoder is not None and self._meta is not None:
            return self._encoder, self._meta
        if not self.encoder_path.exists():
            raise FileNotFoundError(f"DeepSVDD encoder not found: {self.encoder_path}")
        if not self.meta_npz_path.exists():
            raise FileNotFoundError(f"DeepSVDD meta npz not found: {self.meta_npz_path}")

        try:
            from tensorflow.keras.models import load_model
        except ImportError:
            from keras.models import load_model  # type: ignore

        npz = np.load(self.meta_npz_path, allow_pickle=True)
        meta_json = self._load_meta_json()
        center = np.asarray(npz["c"], dtype="float32")
        shape = int(npz["shape"])
        self._meta = {
            **meta_json,
            "c": center,
            "shape": shape,
            "threshold": float(npz["threshold"]),
            "threshold_percentile": float(npz["threshold_percentile"]),
            "nu": float(npz["nu"]),
            "regul": float(npz["regul"]),
        }
        self._encoder = load_model(self.encoder_path, compile=False)
        self._runtime_error = None
        return self._encoder, self._meta

    def _load_meta_only(self) -> Dict[str, Any]:
        meta = self._load_meta_json()
        if self.meta_npz_path.exists():
            try:
                npz = np.load(self.meta_npz_path, allow_pickle=True)
                meta.update({
                    "shape": int(npz["shape"]),
                    "threshold": float(npz["threshold"]),
                    "threshold_percentile": float(npz["threshold_percentile"]),
                    "nu": float(npz["nu"]),
                    "regul": float(npz["regul"]),
                    "latent_dim": int(np.asarray(npz["c"]).shape[0]),
                })
            except Exception as exc:
                meta["meta_npz_error"] = f"{type(exc).__name__}: {exc}"
        return meta

    def _load_meta_json(self) -> Dict[str, Any]:
        if not self.meta_json_path.exists():
            return {}
        try:
            return json.loads(self.meta_json_path.read_text(encoding="utf-8"))
        except Exception as exc:
            return {"meta_json_error": f"{type(exc).__name__}: {exc}"}

    def _runtime_status(self) -> Dict[str, str]:
        if self._runtime_error:
            return {"tensorflow": self._runtime_error}
        try:
            import tensorflow  # noqa: F401
            return {"tensorflow": "available"}
        except Exception as exc:
            return {"tensorflow": f"unavailable: {type(exc).__name__}: {exc}"}

    def _vectorize_function(self, fn: FunctionUnit, shape: int) -> Tuple[np.ndarray, Dict[str, Any]]:
        sequence = list(fn.features.get("opcode_proxy_sequence") or fn.features.get("token_sequence") or [])
        if not sequence:
            sequence = fn.code.split()
        values = np.zeros(shape, dtype="float32")
        for index, token in enumerate(sequence[:shape]):
            values[index] = _token_to_unit_float(str(token))

        numeric_tail = [
            float(fn.features.get("static_score", 0.0)),
            float(fn.features.get("business_score", 0.0)),
            float(fn.features.get("protection_score", 0.0)),
            min(1.0, len(fn.features.get("dangerous_apis", [])) / 6.0),
            min(1.0, float(fn.features.get("token_count", 0.0)) / 1000.0),
            min(1.0, float(fn.features.get("line_span", 1.0)) / 200.0),
        ]
        for offset, value in enumerate(reversed(numeric_tail), 1):
            if offset <= shape:
                values[-offset] = float(max(0.0, min(1.0, value)))

        return values, {
            "method": "opcode_proxy_hash_vector",
            "input_shape": shape,
            "sequence_length": len(sequence),
            "used_sequence_length": min(len(sequence), shape),
            "numeric_tail": {
                "static_score": numeric_tail[0],
                "business_score": numeric_tail[1],
                "protection_score": numeric_tail[2],
                "dangerous_api_density": numeric_tail[3],
                "token_density": numeric_tail[4],
                "line_span_density": numeric_tail[5],
            },
        }

    def _calibrate(self, score: float, threshold: float) -> float:
        if threshold <= 0:
            return 1.0 if score > 0 else 0.0
        ratio = score / threshold
        confidence = 1.0 / (1.0 + math.exp(-3.0 * (ratio - 1.0)))
        return round(max(0.0, min(1.0, confidence)), 4)

    def _static_proxy(self, analysis: AnalysisInput, adapter_mode: str = "static_proxy_until_deepsvdd_runtime_is_available") -> List[ModelEvidence]:
        evidences: List[ModelEvidence] = []
        for fn in analysis.functions:
            score = self._proxy_anomaly_score(fn.features)
            if score < self.evidence_floor:
                continue
            evidences.append(ModelEvidence(
                evidence_id=f"{analysis.task_id}-deepsvdd-proxy-{_stable_hash(fn.function_id)}",
                model_id="DEEPSVDD_REENTRANCY_ANOMALY",
                scope="function",
                contract_name=fn.contract_name,
                function_signature=fn.signature,
                function_id=fn.function_id,
                vulnerability_id="VULN_UNKNOWN_ANOMALY",
                raw_score=score,
                calibrated_confidence=score,
                label="weak_anomaly",
                location_candidates=[{"start_line": fn.start_line, "end_line": fn.end_line}],
                feature_evidence=[{"type": "anomaly_feature_proxy", "features": fn.features}],
                metadata={
                    "adapter_mode": adapter_mode,
                    "runtime_error": self._runtime_error,
                    "encoder_path": str(self.encoder_path),
                    "meta_npz_path": str(self.meta_npz_path),
                },
            ))
        return evidences

    def _proxy_anomaly_score(self, features: dict) -> float:
        static_score = float(features.get("static_score", 0.0))
        business_score = float(features.get("business_score", 0.0))
        dangerous_count = len(features.get("dangerous_apis", []))
        score = 0.45 * static_score + 0.30 * business_score + 0.08 * dangerous_count
        return round(max(0.0, min(1.0, score)), 4)


def _token_to_unit_float(token: str) -> float:
    digest = sha1(token.encode("utf-8", errors="ignore")).digest()
    value = int.from_bytes(digest[:4], byteorder="big", signed=False)
    return value / 0xFFFFFFFF


def _stable_hash(value: str) -> str:
    return sha1(value.encode("utf-8", errors="ignore")).hexdigest()[:12]

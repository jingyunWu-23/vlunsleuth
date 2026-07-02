from __future__ import annotations

import json
import math
import os
import pickle
import sys
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
        lstm_model_path: str | None = None,
        tokenizer_path: str | None = None,
        max_len: int = 500,
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
        self.lstm_model_path = Path(
            lstm_model_path
            or os.getenv("SCG_DEEPSVDD_LSTM_MODEL")
            or default_lstm_model_path()
        ).resolve()
        self.tokenizer_path = Path(
            tokenizer_path
            or os.getenv("SCG_DEEPSVDD_TOKENIZER")
            or default_tokenizer_path()
        ).resolve()
        self.max_len = int(os.getenv("SCG_DEEPSVDD_MAX_LEN", str(max_len)))
        self.evidence_floor = float(os.getenv("SCG_DEEPSVDD_EVIDENCE_FLOOR", str(evidence_floor)))
        self._encoder = None
        self._feature_model = None
        self._tokenizer = None
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
            "lstm_model_path": str(self.lstm_model_path),
            "tokenizer_path": str(self.tokenizer_path),
            "lstm_layer_name": meta.get("layer_name", "LSTM"),
            "max_len": self.max_len,
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
            encoder, feature_model, tokenizer, meta = self._load_runtime()
        except Exception as exc:
            self._runtime_error = f"{type(exc).__name__}: {exc}"
            return self._static_proxy(analysis, adapter_mode="static_proxy_after_deepsvdd_load_error")

        evidences: List[ModelEvidence] = []
        for fn in analysis.functions:
            vector, vector_meta = self._extract_lstm_feature(fn, feature_model, tokenizer, int(meta["shape"]))
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
                    "lstm_model_path": str(self.lstm_model_path),
                    "tokenizer_path": str(self.tokenizer_path),
                    "threshold_percentile": meta.get("threshold_percentile"),
                    "nu": meta.get("nu"),
                    "regul": meta.get("regul"),
                    "latent_dim": int(meta["c"].shape[0]),
                },
            ))
        return evidences

    def _load_runtime(self) -> Tuple[Any, Any, Any, Dict[str, Any]]:
        if self._encoder is not None and self._feature_model is not None and self._tokenizer is not None and self._meta is not None:
            return self._encoder, self._feature_model, self._tokenizer, self._meta
        if not self.encoder_path.exists():
            raise FileNotFoundError(f"DeepSVDD encoder not found: {self.encoder_path}")
        if not self.meta_npz_path.exists():
            raise FileNotFoundError(f"DeepSVDD meta npz not found: {self.meta_npz_path}")
        if not self.lstm_model_path.exists():
            raise FileNotFoundError(f"DeepSVDD LSTM feature model not found: {self.lstm_model_path}")
        if not self.tokenizer_path.exists():
            raise FileNotFoundError(f"DeepSVDD tokenizer not found: {self.tokenizer_path}")

        try:
            import tensorflow as tf
        except ImportError:
            import keras as tf  # type: ignore

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
        self._encoder = tf.keras.models.load_model(self.encoder_path, compile=False)
        lstm_model = tf.keras.models.load_model(self.lstm_model_path, compile=False)
        layer_name = self._meta.get("layer_name", "LSTM")
        self._feature_model = tf.keras.Model(
            inputs=lstm_model.input,
            outputs=lstm_model.get_layer(str(layer_name)).output,
        )
        self._tokenizer = self._load_tokenizer()
        self._runtime_error = None
        return self._encoder, self._feature_model, self._tokenizer, self._meta

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

    def _extract_lstm_feature(self, fn: FunctionUnit, feature_model, tokenizer, shape: int) -> Tuple[np.ndarray, Dict[str, Any]]:
        sequence_text = " ".join(fn.features.get("opcode_proxy_sequence", []) or fn.features.get("token_sequence", []))
        if not sequence_text.strip():
            sequence_text = fn.code
        encoded = tokenizer.texts_to_sequences([sequence_text])

        try:
            import tensorflow as tf
        except ImportError:
            import keras as tf  # type: ignore

        input_matrix = tf.keras.preprocessing.sequence.pad_sequences(encoded, maxlen=self.max_len)
        features = feature_model.predict(input_matrix, verbose=0)
        vector = np.asarray(features[0], dtype="float32").reshape(-1)
        if vector.shape[0] != shape:
            raise ValueError(f"Expected LSTM feature shape {shape}, got {vector.shape[0]}.")

        return vector, {
            "method": "training_lstm_layer_feature",
            "input_shape": shape,
            "lstm_input_shape": list(input_matrix.shape),
            "lstm_output_shape": list(features.shape),
            "layer_name": self._meta.get("layer_name", "LSTM") if self._meta else "LSTM",
            "sequence_token_count": len(sequence_text.split()),
            "tokenizer_path": str(self.tokenizer_path),
            "lstm_model_path": str(self.lstm_model_path),
        }

    def _load_tokenizer(self):
        if self._tokenizer is not None:
            return self._tokenizer
        self._install_keras_preprocessing_alias()
        with self.tokenizer_path.open("rb") as handle:
            tokenizer = pickle.load(handle)
        self._normalize_tokenizer(tokenizer)
        return tokenizer

    def _normalize_tokenizer(self, tokenizer) -> None:
        defaults = {
            "analyzer": None,
            "filters": '!"#$%&()*+,-./:;<=>?@[\\]^_`{|}~\t\n',
            "lower": True,
            "split": " ",
            "char_level": False,
            "oov_token": None,
        }
        for key, value in defaults.items():
            if not hasattr(tokenizer, key):
                setattr(tokenizer, key, value)

    def _install_keras_preprocessing_alias(self) -> None:
        if "keras_preprocessing.text" in sys.modules:
            return
        try:
            import tensorflow.keras.preprocessing.text as text_module  # type: ignore
            import tensorflow.keras.preprocessing.sequence as sequence_module  # type: ignore
        except Exception:
            return
        import types

        package = types.ModuleType("keras_preprocessing")
        package.text = text_module
        package.sequence = sequence_module
        sys.modules.setdefault("keras_preprocessing", package)
        sys.modules.setdefault("keras_preprocessing.text", text_module)
        sys.modules.setdefault("keras_preprocessing.sequence", sequence_module)

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


def default_lstm_model_path() -> Path:
    return Path(__file__).resolve().parents[2] / "LG-DeepSVDD" / "pretrain" / "semantic features" / "LSTM" / "outputs" / "lstm_scg_reentrancy_gen0.h5"


def default_tokenizer_path() -> Path:
    return Path(__file__).resolve().parents[2] / "LG-DeepSVDD" / "pretrain" / "semantic features" / "LSTM" / "tok.pickle"


def _stable_hash(value: str) -> str:
    return sha1(value.encode("utf-8", errors="ignore")).hexdigest()[:12]

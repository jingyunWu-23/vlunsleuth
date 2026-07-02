from __future__ import annotations

import pickle
import sys
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Tuple

from backend.model_adapters.base import DetectionModel
from backend.schemas import AnalysisInput, FunctionUnit, ModelEvidence


LSTM_VULNERABILITIES = {
    "reentrancy": "VULN_REENTRANCY",
    "timestamp": "VULN_TIMESTAMP",
    "delegatecall": "VULN_DELEGATECALL",
    "SBunchecked_low_level_calls": "VULN_UNCHECKED_LOW_LEVEL_CALLS",
}

LSTM_MODEL_FILES = {
    "reentrancy": "lstm_scg_reentrancy_gen0.h5",
    "timestamp": "lstm_scg_timestamp_gen1000.h5",
    "delegatecall": "lstm_scg_delegatecall_gen0.h5",
    "SBunchecked_low_level_calls": "lstm_scg_SBunchecked_low_level_calls_gen1000.h5",
}


class LSTMAdapter(DetectionModel):
    """Known-vulnerability adapter.

    The class exposes the final inference interface now. Until the exact source
    to embedding path is locked down, it uses deterministic static signals as a
    fallback and reports that mode in metadata.
    """

    adapter_id = "lstm_adapter"
    model_family = "LSTM"
    workflow_model_ids = [
        "LSTM_ALL",
        "LSTM_REENTRANCY",
        "LSTM_TIMESTAMP",
        "LSTM_DELEGATECALL",
        "LSTM_UNCHECKED_LOW_LEVEL_CALLS",
    ]

    def __init__(
        self,
        model_dir: Optional[str] = None,
        target_vulnerabilities: Optional[Iterable[str]] = None,
        tokenizer_path: Optional[str] = None,
        max_len: int = 500,
    ) -> None:
        self.model_dir = Path(model_dir) if model_dir else None
        self.tokenizer_path = Path(tokenizer_path) if tokenizer_path else default_tokenizer_path()
        self.max_len = max_len
        self.target_vulnerabilities = list(target_vulnerabilities or LSTM_VULNERABILITIES)
        self.model_paths = self._resolve_h5_models()
        self._tf = None
        self._models: Dict[str, object] = {}
        self._tokenizer = None
        self._runtime_status: Dict[str, object] = {}

    def metadata(self) -> Dict[str, object]:
        data = super().metadata()
        data.update({
            "model_dir": str(self.model_dir) if self.model_dir else None,
            "tokenizer_path": str(self.tokenizer_path) if self.tokenizer_path else None,
            "discovered_h5_models": {key: str(value) for key, value in self.model_paths.items()},
            "target_vulnerabilities": self.target_vulnerabilities,
            "max_len": self.max_len,
            "runtime_status": self._runtime_status,
            "real_inference": "Enabled when tensorflow and tokenizer loading are available.",
        })
        return data

    def analyze(self, analysis: AnalysisInput) -> List[ModelEvidence]:
        evidences: List[ModelEvidence] = []
        for fn in analysis.functions:
            for vulnerability in self.target_vulnerabilities:
                canonical = normalize_vulnerability(vulnerability)
                score, inference_metadata = self._predict_or_fallback(fn, canonical)
                if score <= 0.05:
                    continue
                evidences.append(ModelEvidence(
                    evidence_id=f"{analysis.task_id}-lstm-{canonical}-{abs(hash(fn.function_id))}",
                    model_id=f"LSTM_{canonical.upper()}",
                    scope="function",
                    contract_name=fn.contract_name,
                    function_signature=fn.signature,
                    function_id=fn.function_id,
                    vulnerability_id=LSTM_VULNERABILITIES.get(canonical, canonical),
                    raw_score=score,
                    calibrated_confidence=score,
                    label="vulnerable" if score >= 0.55 else "suspicious",
                    location_candidates=[{"start_line": fn.start_line, "end_line": fn.end_line}],
                    feature_evidence=[{
                        "type": inference_metadata.get("feature_type", "lstm_input"),
                        "features": compact_lstm_features(fn),
                    }],
                    metadata={
                        "adapter_mode": inference_metadata.get("adapter_mode"),
                        "h5_model": str(self.model_paths.get(canonical, "")),
                        "tokenizer_path": str(self.tokenizer_path) if self.tokenizer_path else None,
                        "inference": inference_metadata,
                    },
                ))
        return evidences

    def _resolve_h5_models(self) -> Dict[str, Path]:
        base = self.model_dir or default_model_dir()
        paths: Dict[str, Path] = {}
        for key, filename in LSTM_MODEL_FILES.items():
            path = base / filename
            if path.exists():
                paths[key] = path
        return paths

    def _predict_or_fallback(self, fn: FunctionUnit, vulnerability: str) -> Tuple[float, Dict[str, object]]:
        model_path = self.model_paths.get(vulnerability)
        if model_path:
            try:
                model = self._load_model(vulnerability, model_path)
                input_matrix = self._encode_function(fn)
                prediction = model.predict(input_matrix, verbose=0)
                probability = float(prediction[0][1])
                return clamp(probability), {
                    "adapter_mode": "h5_inference",
                    "feature_type": "lstm_h5_token_ids",
                    "input_shape": list(input_matrix.shape),
                    "raw_prediction": [float(prediction[0][0]), float(prediction[0][1])],
                }
            except Exception as exc:
                self._runtime_status[f"{vulnerability}_h5_error"] = f"{type(exc).__name__}: {exc}"
        score = self._score(fn, vulnerability)
        return score, {
            "adapter_mode": "static_fallback_h5_unavailable",
            "feature_type": "static_fallback",
            "fallback_reason": self._runtime_status.get(f"{vulnerability}_h5_error", "h5 inference unavailable"),
        }

    def _load_tensorflow(self):
        if self._tf is not None:
            return self._tf
        try:
            import tensorflow as tf  # type: ignore
        except Exception as exc:
            self._runtime_status["tensorflow"] = f"unavailable: {type(exc).__name__}: {exc}"
            raise
        self._tf = tf
        self._runtime_status["tensorflow"] = "available"
        return self._tf

    def _load_model(self, vulnerability: str, model_path: Path):
        if vulnerability in self._models:
            return self._models[vulnerability]
        tf = self._load_tensorflow()
        model = tf.keras.models.load_model(str(model_path), compile=False)
        self._models[vulnerability] = model
        return model

    def _load_tokenizer(self):
        if self._tokenizer is not None:
            return self._tokenizer
        if not self.tokenizer_path or not self.tokenizer_path.exists():
            raise FileNotFoundError(f"LSTM tokenizer not found: {self.tokenizer_path}")
        self._install_keras_preprocessing_alias()
        try:
            with self.tokenizer_path.open("rb") as handle:
                self._tokenizer = pickle.load(handle)
            self._normalize_tokenizer(self._tokenizer)
        except ValueError as exc:
            raise RuntimeError(
                "Cannot load tokenizer. The file may use pickle protocol 5; use Python 3.8+ "
                "or install a compatible pickle5 backport."
            ) from exc
        return self._tokenizer

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
        try:
            import types

            package = types.ModuleType("keras_preprocessing")
            package.text = text_module
            package.sequence = sequence_module
            sys.modules.setdefault("keras_preprocessing", package)
            sys.modules.setdefault("keras_preprocessing.text", text_module)
            sys.modules.setdefault("keras_preprocessing.sequence", sequence_module)
        except Exception:
            return

    def _encode_function(self, fn: FunctionUnit):
        tf = self._load_tensorflow()
        real_embedding = fn.features.get("real_opcode_embedding")
        if real_embedding:
            return tf.constant([real_embedding], dtype="int32")
        tokenizer = self._load_tokenizer()
        sequence_text = fn.features.get("real_opcode_text") or " ".join(
            fn.features.get("opcode_proxy_sequence", []) or fn.features.get("token_sequence", [])
        )
        sequence = tokenizer.texts_to_sequences([sequence_text])
        return tf.keras.preprocessing.sequence.pad_sequences(sequence, maxlen=self.max_len)

    def _score(self, fn: FunctionUnit, vulnerability: str) -> float:
        dangerous = set(fn.features.get("dangerous_apis", []))
        code = fn.code.lower()
        if vulnerability == "reentrancy":
            base = 0.65 if dangerous.intersection({"low_level_call", "send", "transfer"}) and fn.features.get("state_update") else 0.0
            if "nonreentrant" in code:
                base -= 0.35
            return clamp(base)
        if vulnerability == "timestamp":
            return clamp(0.75 if "timestamp" in dangerous else 0.0)
        if vulnerability == "delegatecall":
            return clamp(0.85 if "delegatecall" in dangerous else 0.0)
        if vulnerability == "SBunchecked_low_level_calls":
            has_call = "low_level_call" in dangerous
            checked = "require(" in code or "success" in code or "assert(" in code
            return clamp(0.70 if has_call and not checked else 0.20 if has_call else 0.0)
        return 0.0


def normalize_vulnerability(vulnerability: str) -> str:
    mapping = {
        "VULN_REENTRANCY": "reentrancy",
        "VULN_TIMESTAMP": "timestamp",
        "VULN_DELEGATECALL": "delegatecall",
        "VULN_UNCHECKED_LOW_LEVEL_CALLS": "SBunchecked_low_level_calls",
        "unchecked_low_level_calls": "SBunchecked_low_level_calls",
    }
    return mapping.get(vulnerability, vulnerability)


def clamp(value: float) -> float:
    return round(max(0.0, min(1.0, value)), 4)


def default_model_dir() -> Path:
    return Path(__file__).resolve().parents[2] / "LG-DeepSVDD" / "pretrain" / "semantic features" / "LSTM" / "outputs"


def default_tokenizer_path() -> Path:
    return Path(__file__).resolve().parents[2] / "LG-DeepSVDD" / "pretrain" / "semantic features" / "LSTM" / "tok.pickle"


def compact_lstm_features(fn: FunctionUnit) -> Dict[str, object]:
    features = fn.features
    return {
        "dangerous_apis": features.get("dangerous_apis", []),
        "critical_statements": features.get("critical_statements", [])[:8],
        "token_count": features.get("token_count", 0),
        "real_opcode_available": features.get("real_opcode_available", False),
        "real_opcode_status": features.get("real_opcode_status"),
        "real_opcode_sequence_sample": features.get("real_opcode_sequence", [])[:80],
        "opcode_proxy_sequence_sample": features.get("opcode_proxy_sequence", [])[:80],
        "static_score": features.get("static_score", 0.0),
        "business_score": features.get("business_score", 0.0),
        "protection_score": features.get("protection_score", 0.0),
    }

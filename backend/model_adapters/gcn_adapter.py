from __future__ import annotations

import json
import os
import re
import subprocess
import sys
import tempfile
from hashlib import sha1
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from backend.model_adapters.base import DetectionModel
from backend.schemas import AnalysisInput, FunctionUnit, ModelEvidence, SourceFile


class GCNAdapter(DetectionModel):
    adapter_id = "gcn_adapter"
    model_family = "GCN"
    workflow_model_ids = ["GCN"]

    def __init__(
        self,
        detector_root: str | None = None,
        detector_script: str | None = None,
        model_path: str | None = None,
        python_executable: str | None = None,
        output_root: str | None = None,
        threshold: float | None = None,
        top_k: int = 0,
        timeout_seconds: int = 180,
    ) -> None:
        root = Path(detector_root or os.getenv("SCG_GCN_ROOT") or "cross-contract_detection/cross-contract_detection").resolve()
        self.detector_root = root
        self.detector_script = Path(
            detector_script
            or os.getenv("SCG_GCN_SCRIPT")
            or root / "detect_sol_copy_gradient_ranked_v3.py"
        ).resolve()
        self.model_path = Path(
            model_path
            or os.getenv("SCG_GCN_MODEL")
            or root / "detecting" / "BFS_EA_RGCN(SG)" / "BFS_EA_RGCN.pkl"
        ).resolve()
        self.python_executable = python_executable or os.getenv("SCG_GCN_PYTHON") or sys.executable
        self.output_root = Path(output_root or os.getenv("SCG_GCN_OUTPUT_ROOT") or "backend_outputs/gcn_generated").resolve()
        self.threshold = float(threshold if threshold is not None else os.getenv("SCG_GCN_THRESHOLD", "0.5"))
        self.top_k = int(os.getenv("SCG_GCN_TOP_K", str(top_k)))
        self.timeout_seconds = int(os.getenv("SCG_GCN_TIMEOUT", str(timeout_seconds)))
        self._last_runner_errors: List[str] = []

    def metadata(self) -> dict:
        data = super().metadata()
        data.update({
            "detector_root": str(self.detector_root),
            "detector_script": str(self.detector_script),
            "model_path": str(self.model_path),
            "python_executable": self.python_executable,
            "output_root": str(self.output_root),
            "threshold": self.threshold,
            "top_k": self.top_k,
            "runner_errors": self._last_runner_errors[-5:],
        })
        return data

    def analyze(self, analysis: AnalysisInput) -> List[ModelEvidence]:
        self._last_runner_errors = []
        real_evidences = self._analyze_with_runner(analysis)
        if real_evidences:
            return real_evidences
        return self._static_proxy(analysis)

    def _analyze_with_runner(self, analysis: AnalysisInput) -> List[ModelEvidence]:
        if not self.detector_script.exists():
            self._last_runner_errors.append(f"GCN detector script not found: {self.detector_script}")
            return []
        if not self.model_path.exists():
            self._last_runner_errors.append(f"GCN model file not found: {self.model_path}")
            return []

        evidences: List[ModelEvidence] = []
        for source, source_file, cleanup_dir in self._iter_source_files(analysis):
            try:
                result = self._run_detector(source, analysis.task_id)
                evidences.extend(self._result_to_evidences(analysis, source, source_file, result))
            except Exception as exc:
                self._last_runner_errors.append(f"{source}: {type(exc).__name__}: {exc}")
            finally:
                if cleanup_dir is not None:
                    cleanup_dir.cleanup()
        return evidences

    def _iter_source_files(
        self,
        analysis: AnalysisInput,
    ) -> List[Tuple[Path, SourceFile, Optional[tempfile.TemporaryDirectory[str]]]]:
        items: List[Tuple[Path, SourceFile, Optional[tempfile.TemporaryDirectory[str]]]] = []
        for source in analysis.sources:
            source_path = Path(source.path)
            if source_path.exists() and source_path.suffix.lower() == ".sol":
                items.append((source_path.resolve(), source, None))
                continue
            if not source.code.strip():
                continue
            tmp = tempfile.TemporaryDirectory(prefix="scg_gcn_source_")
            safe_name = re.sub(r"[^A-Za-z0-9_.-]+", "_", Path(source.path).name or "source.sol")
            if not safe_name.lower().endswith(".sol"):
                safe_name += ".sol"
            tmp_path = Path(tmp.name) / safe_name
            tmp_path.write_text(source.code, encoding="utf-8")
            items.append((tmp_path, source, tmp))
        return items

    def _run_detector(self, source_path: Path, task_id: str) -> Dict[str, Any]:
        run_output_root = self.output_root / task_id
        run_output_root.mkdir(parents=True, exist_ok=True)
        cmd = [
            self.python_executable,
            str(self.detector_script),
            "--sol",
            str(source_path),
            "--output-root",
            str(run_output_root),
            "--model",
            str(self.model_path),
            "--threshold",
            str(self.threshold),
            "--locate",
            "--top-k",
            str(self.top_k),
        ]
        completed = subprocess.run(
            cmd,
            cwd=str(self.detector_root),
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=self.timeout_seconds,
            check=False,
        )
        stdout = completed.stdout or ""
        stderr = completed.stderr or ""
        if completed.returncode != 0:
            raise RuntimeError(f"GCN runner exited {completed.returncode}: {stderr.strip() or stdout.strip()}")

        parsed = self._parse_runner_stdout(stdout)
        location_path = parsed.get("localization_json")
        if location_path:
            path = Path(str(location_path))
            if path.exists():
                parsed["localization"] = json.loads(path.read_text(encoding="utf-8"))
        parsed["stdout_tail"] = stdout[-4000:]
        parsed["stderr_tail"] = stderr[-2000:]
        return parsed

    def _parse_runner_stdout(self, stdout: str) -> Dict[str, Any]:
        parsed: Dict[str, Any] = {}
        for raw_line in stdout.splitlines():
            line = raw_line.strip()
            if not line or ":" not in line:
                continue
            key, value = line.split(":", 1)
            key = key.strip()
            value = value.strip()
            if key in {"score", "threshold"}:
                parsed[key] = _safe_float(value)
            elif key in {"sol", "ast_json", "graph_file", "edge_file", "localization_json"}:
                parsed[key] = value
            elif key in {"feature_mode", "result"}:
                parsed[key] = value
            elif key in {"node_types", "graph_nodes", "functions_found"}:
                parsed[key] = _safe_int(value)
        parsed["prediction"] = 1 if float(parsed.get("score", 0.0)) >= self.threshold else 0
        return parsed

    def _result_to_evidences(
        self,
        analysis: AnalysisInput,
        source_path: Path,
        source_file: SourceFile,
        result: Dict[str, Any],
    ) -> List[ModelEvidence]:
        score = _clip(float(result.get("score", 0.0)))
        locations = result.get("localization") or []
        if not isinstance(locations, list):
            locations = []

        evidences: List[ModelEvidence] = []
        for rank, item in enumerate(locations, 1):
            if not isinstance(item, dict):
                continue
            fn = self._match_function(analysis, source_file, item)
            if fn is None:
                continue
            final_score = _clip(float(item.get("final_score", item.get("model_score_norm", score)) or 0.0))
            model_score = _clip(float(item.get("model_score_norm", final_score) or 0.0))
            calibrated = _clip(max(score * 0.70 + final_score * 0.30, model_score * 0.85))
            if calibrated <= 0.0:
                continue
            label = str(item.get("role") or "cross_contract_candidate")
            evidences.append(ModelEvidence(
                evidence_id=self._evidence_id(analysis.task_id, source_path, fn, rank),
                model_id="GCN_CROSS_CONTRACT",
                scope="function",
                contract_name=fn.contract_name,
                function_signature=fn.signature,
                function_id=fn.function_id,
                vulnerability_id="VULN_CROSS_CONTRACT_RISK",
                raw_score=round(score, 4),
                calibrated_confidence=round(calibrated, 4),
                label=label,
                location_candidates=[{
                    "start_line": item.get("start_line") or fn.start_line,
                    "end_line": item.get("end_line") or fn.end_line,
                    "rank": rank,
                    "priority": item.get("priority"),
                    "role": item.get("role"),
                    "label": item.get("label"),
                }],
                feature_evidence=[{
                    "type": "gcn_gradient_localization",
                    "final_score": final_score,
                    "model_score_norm": model_score,
                    "node_score_norm": item.get("node_score_norm"),
                    "edge_score_norm": item.get("edge_score_norm"),
                    "rule_score": item.get("rule_score"),
                    "rule_hits": item.get("rule_hits", []),
                    "top_nodes": item.get("top_nodes", []),
                    "node_count": item.get("node_count"),
                    "edge_count": item.get("edge_count"),
                }],
                metadata={
                    "adapter_mode": "cross_contract_gcn_runner",
                    "source_path": str(source_path),
                    "detector_script": str(self.detector_script),
                    "model_path": str(self.model_path),
                    "graph_file": result.get("graph_file"),
                    "edge_file": result.get("edge_file"),
                    "localization_json": result.get("localization_json"),
                    "feature_mode": result.get("feature_mode"),
                    "prediction": result.get("prediction"),
                    "threshold": result.get("threshold", self.threshold),
                    "rank": rank,
                },
            ))
        return evidences

    def _match_function(
        self,
        analysis: AnalysisInput,
        source_file: SourceFile,
        item: Dict[str, Any],
    ) -> Optional[FunctionUnit]:
        contract = str(item.get("contract") or "")
        function_name = str(item.get("function") or "")
        start_line = _safe_int(item.get("start_line"))
        end_line = _safe_int(item.get("end_line")) or start_line
        source_name = Path(source_file.path).name

        candidates = [
            fn for fn in analysis.functions
            if Path(fn.source_path).name == source_name
            and (not contract or fn.contract_name == contract)
            and (not function_name or fn.name == function_name)
        ]
        if not candidates:
            candidates = [
                fn for fn in analysis.functions
                if (not contract or fn.contract_name == contract)
                and (not function_name or fn.name == function_name)
            ]
        if not candidates:
            return None
        if start_line:
            candidates.sort(key=lambda fn: 0 if fn.start_line <= start_line <= fn.end_line else abs(fn.start_line - start_line))
        return candidates[0]

    def _static_proxy(self, analysis: AnalysisInput) -> List[ModelEvidence]:
        if len(analysis.contracts) <= 1:
            return []
        evidences: List[ModelEvidence] = []
        for fn in analysis.functions:
            dangerous = set(fn.features.get("dangerous_apis", []))
            if not dangerous.intersection({"delegatecall", "low_level_call", "transfer", "send"}):
                continue
            score = 0.55 + min(0.35, len(dangerous) * 0.08)
            evidences.append(ModelEvidence(
                evidence_id=f"{analysis.task_id}-gcn-proxy-{_stable_hash(fn.function_id)}",
                model_id="GCN_CROSS_CONTRACT",
                scope="function",
                contract_name=fn.contract_name,
                function_signature=fn.signature,
                function_id=fn.function_id,
                vulnerability_id="VULN_CROSS_CONTRACT_RISK",
                raw_score=round(score, 4),
                calibrated_confidence=round(score, 4),
                label="cross_contract_static_proxy",
                location_candidates=[{"start_line": fn.start_line, "end_line": fn.end_line}],
                feature_evidence=[{
                    "type": "cross_contract_static_proxy",
                    "dangerous_apis": sorted(dangerous),
                    "called_functions": analysis.call_graph.get(fn.function_id, []),
                }],
                metadata={
                    "adapter_mode": "static_proxy_fallback",
                    "runner_errors": self._last_runner_errors[-5:],
                },
            ))
        return evidences

    def _evidence_id(self, task_id: str, source_path: Path, fn: FunctionUnit, rank: int) -> str:
        digest = _stable_hash(f"{source_path}:{fn.function_id}:{rank}")
        return f"{task_id}-gcn-{digest}"


def _stable_hash(value: str) -> str:
    return sha1(value.encode("utf-8", errors="ignore")).hexdigest()[:12]


def _safe_float(value: Any) -> float:
    try:
        return float(str(value).strip())
    except (TypeError, ValueError):
        return 0.0


def _safe_int(value: Any) -> int:
    try:
        return int(str(value).strip())
    except (TypeError, ValueError):
        return 0


def _clip(value: float) -> float:
    return max(0.0, min(1.0, value))

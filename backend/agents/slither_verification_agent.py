from __future__ import annotations

import json
import shutil
import subprocess
import tempfile
import zipfile
from dataclasses import asdict
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional

from backend.function_risk.risk_score import normalize_vulnerability
from backend.schemas import AuditReport, Finding, FunctionUnit


SLITHER_TIMEOUT_SECONDS = 120

DETECTOR_TO_VULN = {
    "reentrancy-benign": "VULN_REENTRANCY",
    "reentrancy-eth": "VULN_REENTRANCY",
    "reentrancy-events": "VULN_REENTRANCY",
    "reentrancy-no-eth": "VULN_REENTRANCY",
    "reentrancy-unlimited-gas": "VULN_REENTRANCY",
    "timestamp": "VULN_TIMESTAMP",
    "controlled-delegatecall": "VULN_DELEGATECALL",
    "delegatecall-loop": "VULN_DELEGATECALL",
    "unchecked-lowlevel": "VULN_UNCHECKED_LOW_LEVEL_CALLS",
    "unchecked-send": "VULN_UNCHECKED_LOW_LEVEL_CALLS",
}


def verify_report_with_slither(
    report: AuditReport,
    functions: List[FunctionUnit],
    source_path: str,
    output_dir: str | Path | None = None,
) -> Dict[str, Any]:
    result = run_slither(source_path, output_dir)
    result["finding_updates"] = []

    if result["status"] != "completed":
        for finding in report.findings:
            attach_slither_result(finding, result, confirmed_matches=[])
        return result

    detectors = result.get("detectors", [])
    function_by_key = {
        (fn.contract_name, fn.signature): fn
        for fn in functions
    }
    for finding in report.findings:
        fn = function_by_key.get((finding.contract_name, finding.function_signature))
        matches = match_detectors_to_finding(detectors, finding, fn)
        attach_slither_result(finding, result, matches)
        if matches:
            finding.status = "confirmed"
            finding.confidence = max(finding.confidence, max(float(item.get("confidence_score", 0.75)) for item in matches))
            result["finding_updates"].append({
                "finding_id": finding.finding_id,
                "status": finding.status,
                "matched_detectors": [item.get("check") for item in matches],
            })
    return result


def run_slither(source_path: str, output_dir: str | Path | None = None) -> Dict[str, Any]:
    executable = shutil.which("slither")
    if not executable:
        return {
            "tool": "slither",
            "status": "unavailable",
            "error": "Slither executable not found in PATH. Install with: pip install slither-analyzer",
            "detectors": [],
        }

    output_root = Path(output_dir) if output_dir else None
    if output_root:
        output_root.mkdir(parents=True, exist_ok=True)
    artifact_path = output_root / "slither_results.json" if output_root else None

    temp_dir: Optional[tempfile.TemporaryDirectory[str]] = None
    try:
        analysis_target = prepare_slither_target(source_path)
        if isinstance(analysis_target, tuple):
            target, temp_dir = analysis_target
        else:
            target = analysis_target

        json_path = artifact_path or Path(tempfile.gettempdir()) / "scg_slither_results.json"
        command = [
            executable,
            str(target),
            "--json",
            str(json_path),
            "--disable-color",
        ]
        completed = subprocess.run(
            command,
            cwd=str(target if target.is_dir() else target.parent),
            capture_output=True,
            text=True,
            timeout=SLITHER_TIMEOUT_SECONDS,
        )
        raw = read_json_file(json_path)
        detectors = normalize_slither_detectors(raw)
        return {
            "tool": "slither",
            "status": "completed",
            "exit_code": completed.returncode,
            "command": command_for_metadata(command),
            "artifact": str(json_path),
            "stdout": completed.stdout[-4000:],
            "stderr": completed.stderr[-4000:],
            "detector_count": len(detectors),
            "detectors": detectors,
        }
    except subprocess.TimeoutExpired as exc:
        return {
            "tool": "slither",
            "status": "timeout",
            "error": f"Slither timed out after {SLITHER_TIMEOUT_SECONDS} seconds.",
            "stdout": (exc.stdout or "")[-4000:] if isinstance(exc.stdout, str) else "",
            "stderr": (exc.stderr or "")[-4000:] if isinstance(exc.stderr, str) else "",
            "detectors": [],
        }
    except Exception as exc:
        return {
            "tool": "slither",
            "status": "error",
            "error": f"{type(exc).__name__}: {exc}",
            "detectors": [],
        }
    finally:
        if temp_dir is not None:
            temp_dir.cleanup()


def prepare_slither_target(source_path: str) -> Path | tuple[Path, tempfile.TemporaryDirectory[str]]:
    path = Path(source_path)
    if path.is_file() and path.suffix.lower() == ".zip":
        temp_dir = tempfile.TemporaryDirectory(prefix="scg_slither_")
        with zipfile.ZipFile(path) as archive:
            archive.extractall(temp_dir.name)
        return Path(temp_dir.name), temp_dir
    return path


def normalize_slither_detectors(raw: Dict[str, Any]) -> List[Dict[str, Any]]:
    detectors = raw.get("results", {}).get("detectors", []) if isinstance(raw, dict) else []
    normalized = []
    for item in detectors:
        check = str(item.get("check") or "")
        elements = item.get("elements") or []
        normalized.append({
            "check": check,
            "vulnerability_id": DETECTOR_TO_VULN.get(check),
            "impact": item.get("impact"),
            "confidence": item.get("confidence"),
            "confidence_score": confidence_to_score(item.get("confidence")),
            "description": item.get("description", ""),
            "first_markdown_element": item.get("first_markdown_element"),
            "locations": list(iter_locations(elements)),
        })
    return normalized


def iter_locations(elements: Iterable[Dict[str, Any]]) -> Iterable[Dict[str, Any]]:
    for element in elements:
        source_mapping = element.get("source_mapping") or {}
        lines = source_mapping.get("lines") or []
        yield {
            "name": element.get("name"),
            "type": element.get("type"),
            "filename": source_mapping.get("filename_absolute") or source_mapping.get("filename_relative"),
            "lines": lines,
            "start_line": min(lines) if lines else None,
            "end_line": max(lines) if lines else None,
        }


def match_detectors_to_finding(
    detectors: List[Dict[str, Any]],
    finding: Finding,
    fn: FunctionUnit | None,
) -> List[Dict[str, Any]]:
    target_vuln = normalize_vulnerability(finding.vulnerability_id)
    matches = []
    for detector in detectors:
        detector_vuln = detector.get("vulnerability_id")
        if normalize_vulnerability(detector_vuln) != target_vuln:
            continue
        if fn is None or detector_overlaps_function(detector, fn):
            matches.append(detector)
    return matches


def detector_overlaps_function(detector: Dict[str, Any], fn: FunctionUnit) -> bool:
    for location in detector.get("locations", []):
        if not same_source_file(location.get("filename"), fn.source_path):
            continue
        start_line = location.get("start_line")
        end_line = location.get("end_line")
        if start_line is None or end_line is None:
            return True
        if int(start_line) <= fn.end_line and int(end_line) >= fn.start_line:
            return True
    description = str(detector.get("description", ""))
    return fn.name and fn.name in description and fn.contract_name in description


def attach_slither_result(finding: Finding, result: Dict[str, Any], confirmed_matches: List[Dict[str, Any]]) -> None:
    plan = dict(finding.verification_plan or {})
    if confirmed_matches:
        status = "confirmed"
        summary = "Slither 命中同函数同类型漏洞。"
    elif result["status"] == "completed":
        status = "not_confirmed"
        summary = "Slither 已运行，但未命中同函数同类型漏洞；该结果不能单独证明不存在漏洞。"
    else:
        status = result["status"]
        summary = result.get("error", "Slither 未完成验证。")
    plan["slither"] = {
        "tool": "slither",
        "status": status,
        "summary": summary,
        "artifact": result.get("artifact"),
        "matched_detectors": [
            {
                "check": item.get("check"),
                "impact": item.get("impact"),
                "confidence": item.get("confidence"),
                "description": item.get("description"),
                "locations": item.get("locations", []),
            }
            for item in confirmed_matches
        ],
    }
    finding.verification_plan = plan


def same_source_file(left: str | None, right: str | None) -> bool:
    if not left or not right:
        return True
    left_clean = str(left).split("!")[-1].replace("\\", "/").lower()
    right_clean = str(right).split("!")[-1].replace("\\", "/").lower()
    return left_clean == right_clean or left_clean.endswith("/" + Path(right_clean).name) or right_clean.endswith("/" + Path(left_clean).name)


def read_json_file(path: Path) -> Dict[str, Any]:
    if not path.exists():
        return {}
    return json.loads(path.read_text(encoding="utf-8", errors="ignore") or "{}")


def confidence_to_score(confidence: Any) -> float:
    mapping = {
        "High": 0.9,
        "Medium": 0.75,
        "Low": 0.55,
        "Informational": 0.35,
    }
    return mapping.get(str(confidence), 0.65)


def command_for_metadata(command: List[str]) -> List[str]:
    return [Path(command[0]).name, *command[1:]]


def report_to_plain_dict(report: AuditReport) -> Dict[str, Any]:
    return asdict(report)

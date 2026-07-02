from __future__ import annotations

import json
import shutil
import subprocess
import tempfile
import zipfile
from dataclasses import asdict
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional

from backend.agents.llm_client import LLMClient, build_llm_client
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

VERIFICATION_SYSTEM_PROMPT = """你是智能合约安全验证智能体。你可以使用 Slither 工具结果、候选漏洞、函数源码和模型证据来判断候选漏洞是否被验证支持。
只返回严格 JSON，不要输出 Markdown。所有自然语言字段必须使用简体中文。
要求：
1. 区分工具未命中和漏洞不存在。Slither 未命中不能单独证明漏洞不存在。
2. 如果 Slither 命中同函数同漏洞类型，通常应给出 confirmed，除非命中位置明显不相关。
3. 如果 Slither 未命中，但源码语义明显不满足漏洞条件，可给出 rejected。
4. 如果证据不足，给出 inconclusive。
5. 不要修改上游模型原始分数，只能解释验证结论。"""


def verify_report_with_slither(
    report: AuditReport,
    functions: List[FunctionUnit],
    source_path: str,
    output_dir: str | Path | None = None,
    llm_service: "LLMVerificationService | None" = None,
) -> Dict[str, Any]:
    result = run_slither(source_path, output_dir)
    result["finding_updates"] = []
    llm_service = llm_service or LLMVerificationService()

    function_by_key = {(fn.contract_name, fn.signature): fn for fn in functions}

    if result["status"] != "completed":
        for finding in report.findings:
            fn = function_by_key.get((finding.contract_name, finding.function_signature))
            attach_slither_result(finding, result, confirmed_matches=[])
            attach_llm_verification_result(finding, llm_service.verify(finding, fn, result, []))
        return result

    detectors = result.get("detectors", [])
    for finding in report.findings:
        fn = function_by_key.get((finding.contract_name, finding.function_signature))
        matches = match_detectors_to_finding(detectors, finding, fn)
        attach_slither_result(finding, result, matches)
        llm_result = llm_service.verify(finding, fn, result, matches)
        attach_llm_verification_result(finding, llm_result)

        if matches:
            finding.status = "confirmed"
            finding.confidence = max(
                finding.confidence,
                max(float(item.get("confidence_score", 0.75)) for item in matches),
            )
            result["finding_updates"].append({
                "finding_id": finding.finding_id,
                "status": finding.status,
                "matched_detectors": [item.get("check") for item in matches],
                "llm_verification": llm_result.get("status"),
            })
        elif llm_result.get("status") == "rejected":
            finding.status = "rejected"
            result["finding_updates"].append({
                "finding_id": finding.finding_id,
                "status": finding.status,
                "matched_detectors": [],
                "llm_verification": "rejected",
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
        command = [executable, str(target), "--json", str(json_path), "--disable-color"]
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
    return bool(fn.name and fn.name in description and fn.contract_name in description)


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


def attach_llm_verification_result(finding: Finding, llm_result: Dict[str, Any]) -> None:
    plan = dict(finding.verification_plan or {})
    plan["llm_verification"] = {
        "status": llm_result.get("status", "inconclusive"),
        "summary": llm_result.get("summary", ""),
        "reasoning": llm_result.get("reasoning", []),
        "evidence_assessment": llm_result.get("evidence_assessment", ""),
        "recommended_next_steps": llm_result.get("recommended_next_steps", []),
        "model_api_status": llm_result.get("model_api_status", "unknown"),
    }
    finding.verification_plan = plan


class LLMVerificationService:
    def __init__(self, client: LLMClient | None = None) -> None:
        self.client = client or build_llm_client()

    def verify(
        self,
        finding: Finding,
        function: FunctionUnit | None,
        slither_result: Dict[str, Any],
        matched_detectors: List[Dict[str, Any]],
    ) -> Dict[str, Any]:
        payload = build_verification_payload(finding, function, slither_result, matched_detectors)
        try:
            result = self.client.complete_json(VERIFICATION_SYSTEM_PROMPT, payload)
            if not isinstance(result, dict):
                raise RuntimeError("LLM verification response must be a JSON object.")
            if str(result.get("status", "")).lower() not in {"confirmed", "rejected", "inconclusive"}:
                raise RuntimeError("LLM verification response did not contain a verification status.")
            result.setdefault("model_api_status", "called")
        except Exception as exc:
            result = build_local_verification_result(finding, function, slither_result, matched_detectors, exc)
        return normalize_verification_result(result)


def build_verification_payload(
    finding: Finding,
    function: FunctionUnit | None,
    slither_result: Dict[str, Any],
    matched_detectors: List[Dict[str, Any]],
) -> Dict[str, Any]:
    same_type_elsewhere = [
        item
        for item in slither_result.get("detectors", [])
        if normalize_vulnerability(item.get("vulnerability_id")) == normalize_vulnerability(finding.vulnerability_id)
        and item not in matched_detectors
    ][:5]
    return {
        "candidate_finding": {
            "finding_id": finding.finding_id,
            "status_before_verification": finding.status,
            "contract_name": finding.contract_name,
            "function_signature": finding.function_signature,
            "vulnerability_id": finding.vulnerability_id,
            "severity": finding.severity,
            "confidence": finding.confidence,
            "summary": finding.summary,
            "model_evidence": [compact_model_evidence(item) for item in finding.evidence],
        },
        "function": compact_function(function),
        "slither": {
            "status": slither_result.get("status"),
            "exit_code": slither_result.get("exit_code"),
            "detector_count": slither_result.get("detector_count", 0),
            "matched_detectors": compact_detectors(matched_detectors),
            "same_type_detectors_elsewhere": compact_detectors(same_type_elsewhere),
            "error": slither_result.get("error"),
            "stderr_tail": slither_result.get("stderr", "")[-1200:],
        },
        "output_schema": {
            "status": "confirmed | rejected | inconclusive",
            "summary": "简体中文字符串，说明验证结论",
            "reasoning": ["简体中文字符串"],
            "evidence_assessment": "简体中文字符串，说明 Slither 证据与候选漏洞之间的关系",
            "recommended_next_steps": ["简体中文字符串"],
        },
    }


def compact_function(function: FunctionUnit | None) -> Dict[str, Any]:
    if function is None:
        return {}
    return {
        "source_path": function.source_path,
        "contract_name": function.contract_name,
        "function_name": function.name,
        "signature": function.signature,
        "start_line": function.start_line,
        "end_line": function.end_line,
        "visibility": function.visibility,
        "mutability": function.mutability,
        "modifiers": function.modifiers,
        "dangerous_apis": function.features.get("dangerous_apis", []),
        "state_update": function.features.get("state_update"),
        "external_before_state_update": function.features.get("external_before_state_update"),
        "unchecked_low_level_call": function.features.get("unchecked_low_level_call"),
        "critical_statements": function.features.get("critical_statements", [])[:8],
        "code": function.code[:3000],
    }


def compact_model_evidence(evidence: Any) -> Dict[str, Any]:
    return {
        "evidence_id": getattr(evidence, "evidence_id", None),
        "model_id": getattr(evidence, "model_id", None),
        "vulnerability_id": getattr(evidence, "vulnerability_id", None),
        "raw_score": getattr(evidence, "raw_score", None),
        "calibrated_confidence": getattr(evidence, "calibrated_confidence", None),
        "label": getattr(evidence, "label", None),
    }


def compact_detectors(detectors: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    return [
        {
            "check": item.get("check"),
            "vulnerability_id": item.get("vulnerability_id"),
            "impact": item.get("impact"),
            "confidence": item.get("confidence"),
            "description": str(item.get("description", ""))[:1200],
            "locations": item.get("locations", [])[:5],
        }
        for item in detectors
    ]


def build_local_verification_result(
    finding: Finding,
    function: FunctionUnit | None,
    slither_result: Dict[str, Any],
    matched_detectors: List[Dict[str, Any]],
    exc: Exception,
) -> Dict[str, Any]:
    if matched_detectors:
        return {
            "status": "confirmed",
            "summary": "Slither 命中同函数同类型漏洞，验证智能体将该候选结论判定为已确认。",
            "reasoning": [
                "Slither detector 与候选漏洞类型一致。",
                "命中位置与候选函数行号或函数描述匹配。",
            ],
            "evidence_assessment": "工具证据支持该漏洞结论。",
            "recommended_next_steps": ["可继续生成修复建议，并在修复后重新运行 Slither。"],
            "model_api_status": f"fallback: {type(exc).__name__}: {exc}",
        }
    if slither_result.get("status") == "completed":
        semantic_reason = local_semantic_rejection_reason(finding, function)
        if semantic_reason:
            return {
                "status": "rejected",
                "summary": f"Slither 未命中，且源码语义不满足该漏洞类型：{semantic_reason}",
                "reasoning": ["Slither 没有发现同函数同类型 detector。", semantic_reason],
                "evidence_assessment": "工具结果和基础语义规则共同削弱该候选漏洞。",
                "recommended_next_steps": ["如该结论来自高分模型输出，建议回看模型输入特征和阈值。"],
                "model_api_status": f"fallback: {type(exc).__name__}: {exc}",
            }
        return {
            "status": "inconclusive",
            "summary": "Slither 未命中同函数同类型漏洞，但该结果不能单独证明漏洞不存在。",
            "reasoning": ["Slither 是静态分析工具，未命中可能来自规则覆盖不足、编译依赖缺失或路径条件复杂。"],
            "evidence_assessment": "工具结果没有确认候选漏洞，也不足以直接排除。",
            "recommended_next_steps": ["对高风险函数可补充人工复核或 Foundry PoC。"],
            "model_api_status": f"fallback: {type(exc).__name__}: {exc}",
        }
    return {
        "status": "inconclusive",
        "summary": "Slither 未完成验证，无法给出工具确认结论。",
        "reasoning": [slither_result.get("error", "Slither 工具不可用或执行失败。")],
        "evidence_assessment": "缺少可用工具证据。",
        "recommended_next_steps": ["安装或修复 Slither 后重新执行验证。"],
        "model_api_status": f"fallback: {type(exc).__name__}: {exc}",
    }


def local_semantic_rejection_reason(finding: Finding, function: FunctionUnit | None) -> str:
    if function is None:
        return ""
    dangerous = set(function.features.get("dangerous_apis", []))
    vuln = normalize_vulnerability(finding.vulnerability_id)
    if vuln == "VULN_REENTRANCY" and not dangerous.intersection({"low_level_call", "send", "transfer"}):
        return "函数没有可触发重入的外部转账或低级调用。"
    if vuln == "VULN_REENTRANCY" and not function.features.get("state_update"):
        return "函数没有与重入风险相关的状态更新。"
    if vuln == "VULN_TIMESTAMP" and "timestamp" not in dangerous:
        return "函数没有使用 block.timestamp 或 now。"
    if vuln == "VULN_DELEGATECALL" and "delegatecall" not in dangerous:
        return "函数没有 delegatecall 调用。"
    if vuln == "VULN_UNCHECKED_LOW_LEVEL_CALLS" and not function.features.get("unchecked_low_level_call"):
        return "函数没有未检查返回值的低级调用。"
    return ""


def normalize_verification_result(result: Dict[str, Any]) -> Dict[str, Any]:
    status = str(result.get("status", "inconclusive")).lower()
    if status not in {"confirmed", "rejected", "inconclusive"}:
        status = "inconclusive"
    normalized = dict(result)
    normalized["status"] = status
    normalized.setdefault("summary", "验证智能体未给出摘要。")
    normalized.setdefault("reasoning", [])
    normalized.setdefault("evidence_assessment", "")
    normalized.setdefault("recommended_next_steps", [])
    normalized.setdefault("model_api_status", "unknown")
    return normalized


def same_source_file(left: str | None, right: str | None) -> bool:
    if not left or not right:
        return True
    left_clean = str(left).split("!")[-1].replace("\\", "/").lower()
    right_clean = str(right).split("!")[-1].replace("\\", "/").lower()
    return (
        left_clean == right_clean
        or left_clean.endswith("/" + Path(right_clean).name)
        or right_clean.endswith("/" + Path(left_clean).name)
    )


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

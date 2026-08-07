from __future__ import annotations

import shutil
import importlib.util
from typing import Any, Dict, List

from backend.model_adapters.lstm_adapter import LSTM_MODEL_IDS, LSTM_THRESHOLDS, LSTM_VULNERABILITIES, LSTMAdapter
from backend.reporting.markdown_report import translate_vulnerability


def backend_capabilities() -> Dict[str, Any]:
    lstm = LSTMAdapter()
    vulnerabilities = []
    for target, vulnerability_id in LSTM_VULNERABILITIES.items():
        model_id = LSTM_MODEL_IDS.get(target)
        model_path = lstm.model_paths.get(target)
        vulnerabilities.append({
            "target": target,
            "vulnerability_id": vulnerability_id,
            "display_name": translate_vulnerability(vulnerability_id),
            "model_id": model_id,
            "model_family": "LSTM",
            "available": model_path is not None,
            "model_path": str(model_path) if model_path else None,
            "threshold": LSTM_THRESHOLDS.get(target, 0.55),
            "supports_slither_verification": slither_supports(vulnerability_id),
        })
    return {
        "modes": [
            {
                "mode": "known_full_scan",
                "display_name": "已知漏洞专项检测",
                "description": "传入 target_vulnerabilities 时只运行勾选的 LSTM 模型；不传时运行全部 LSTM。",
            },
            {
                "mode": "full_audit",
                "display_name": "完整审计",
                "description": "运行全部 LSTM、DeepSVDD 和 GCN，并执行推理定位流程。",
            },
            {
                "mode": "unknown_risk_scan",
                "display_name": "未知风险筛查",
                "description": "运行 DeepSVDD 和 LSTM 全量筛查。",
            },
            {
                "mode": "cross_contract_scan",
                "display_name": "跨合约风险检测",
                "description": "运行 GCN 跨合约检测。",
            },
        ],
        "lstm_vulnerabilities": vulnerabilities,
        "tools": tool_status(),
    }


def tool_status() -> Dict[str, Any]:
    slither_path = shutil.which("slither")
    return {
        "slither": {
            "available": slither_path is not None,
            "path": slither_path,
            "purpose": "对候选漏洞执行静态工具验证。",
        },
        "tensorflow": tensorflow_status(),
    }


def tensorflow_status() -> Dict[str, Any]:
    return {
        "available": importlib.util.find_spec("tensorflow") is not None,
        "version": None,
        "purpose": "加载 .h5 LSTM/DeepSVDD 模型执行推理。",
    }


def slither_supports(vulnerability_id: str) -> bool:
    return vulnerability_id in {
        "VULN_REENTRANCY",
        "VULN_TIMESTAMP",
        "VULN_DELEGATECALL",
        "VULN_UNCHECKED_LOW_LEVEL_CALLS",
        "VULN_ACCESS_CONTROL",
        "VULN_ARITHMETIC",
        "VULN_LOCKED_ETHER",
        "VULN_BAD_RANDOMNESS",
    }

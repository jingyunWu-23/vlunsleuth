from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List

from backend.schemas import AnalysisInput, AuditRequest


VULNERABILITY_TO_LSTM = {
    "reentrancy": "LSTM_REENTRANCY",
    "timestamp": "LSTM_TIMESTAMP",
    "delegatecall": "LSTM_DELEGATECALL",
    "SBunchecked_low_level_calls": "LSTM_UNCHECKED_LOW_LEVEL_CALLS",
    "unchecked_low_level_calls": "LSTM_UNCHECKED_LOW_LEVEL_CALLS",
    "VULN_REENTRANCY": "LSTM_REENTRANCY",
    "VULN_TIMESTAMP": "LSTM_TIMESTAMP",
    "VULN_DELEGATECALL": "LSTM_DELEGATECALL",
    "VULN_UNCHECKED_LOW_LEVEL_CALLS": "LSTM_UNCHECKED_LOW_LEVEL_CALLS",
    "cross_contract": "GCN",
    "cross_contract_risk": "GCN",
    "VULN_CROSS_CONTRACT_RISK": "GCN",
}


@dataclass
class Workflow:
    formal_models: List[str] = field(default_factory=list)
    background_screening: bool = True
    agents: List[str] = field(default_factory=list)

    def as_dict(self) -> Dict[str, object]:
        return {
            "formal_models": self.formal_models,
            "background_screening": self.background_screening,
            "agents": self.agents,
        }


def build_workflow(request: AuditRequest, analysis: AnalysisInput) -> Workflow:
    workflow = Workflow(background_screening=request.background_risk_screening)
    is_multi_contract = len(analysis.contracts) > 1

    for vulnerability in request.target_vulnerabilities:
        model_id = VULNERABILITY_TO_LSTM.get(vulnerability, vulnerability)
        workflow.formal_models.append(model_id)

    if request.mode == "known_full_scan":
        workflow.formal_models = ["LSTM_ALL"]
    elif request.mode == "unknown_risk_scan":
        workflow.formal_models.extend(["DEEPSVDD", "LSTM_ALL"])
    elif request.mode == "full_audit":
        workflow.formal_models.extend(["LSTM_ALL", "DEEPSVDD", "GCN"])
    elif request.mode == "cross_contract_scan":
        workflow.formal_models.append("GCN")

    if is_multi_contract and request.mode in {"cross_contract_scan", "full_audit"}:
        workflow.formal_models.append("GCN")

    workflow.formal_models = list(dict.fromkeys(workflow.formal_models))
    workflow.agents.append("reasoning_localization")
    if request.need_verification:
        workflow.agents.append("verification")
    if request.need_repair:
        workflow.agents.append("repair")
    workflow.agents.append("report_service")
    return workflow

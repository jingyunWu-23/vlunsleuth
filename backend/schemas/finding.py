from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from .evidence import ModelEvidence, RiskVector


@dataclass
class Finding:
    finding_id: str
    scope: str
    status: str
    contract_name: str
    function_signature: str
    vulnerability_id: str
    severity: str
    confidence: float
    summary: str
    evidence: List[ModelEvidence] = field(default_factory=list)
    knowledge: List[Dict[str, Any]] = field(default_factory=list)
    location: List[Dict[str, Any]] = field(default_factory=list)
    verification_allowed: bool = True
    repair_allowed: bool = True
    recommendation: Optional[str] = None
    reasoning: Dict[str, Any] = field(default_factory=dict)
    verification_plan: Dict[str, Any] = field(default_factory=dict)
    repair_suggestion: Dict[str, Any] = field(default_factory=dict)


@dataclass
class Warning:
    warning_id: str
    scope: str
    status: str
    contract_name: str
    function_signature: str
    target_vulnerability: str
    score: float
    summary: str
    recommended_action: Dict[str, str]
    evidence: List[ModelEvidence] = field(default_factory=list)
    verification_allowed: bool = False
    repair_allowed: bool = False


@dataclass
class AuditReport:
    task_id: str
    mode: str
    workflow: Dict[str, Any]
    risk_vectors: List[RiskVector]
    findings: List[Finding]
    warnings: List[Warning]
    metadata: Dict[str, Any] = field(default_factory=dict)

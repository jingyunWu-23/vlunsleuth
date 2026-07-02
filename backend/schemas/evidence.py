from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional


@dataclass
class ModelEvidence:
    evidence_id: str
    model_id: str
    scope: str
    contract_name: str
    function_signature: str
    function_id: str
    vulnerability_id: Optional[str]
    raw_score: float
    calibrated_confidence: float
    label: str
    location_candidates: List[Dict[str, Any]] = field(default_factory=list)
    feature_evidence: List[Dict[str, Any]] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class RiskVector:
    function_id: str
    contract_name: str
    function_signature: str
    anomaly_score: float = 0.0
    gcn_score: float = 0.0
    static_score: float = 0.0
    business_score: float = 0.0
    knowledge_score: float = 0.0
    consistency_score: float = 0.0
    protection_score: float = 0.0
    r_func: float = 0.0
    selected_scores: Dict[str, float] = field(default_factory=dict)
    warning_scores: Dict[str, float] = field(default_factory=dict)
    category_evidence_scores: Dict[str, float] = field(default_factory=dict)
    evidence_quality_scores: Dict[str, float] = field(default_factory=dict)
    component_reasons: Dict[str, Any] = field(default_factory=dict)

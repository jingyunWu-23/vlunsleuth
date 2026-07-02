from __future__ import annotations

from dataclasses import dataclass, field
from typing import List, Optional


AuditMode = str


@dataclass
class AuditRequest:
    task_id: str
    source_path: str
    mode: AuditMode = "full_audit"
    target_vulnerabilities: List[str] = field(default_factory=list)
    need_verification: bool = False
    need_repair: bool = True
    background_risk_screening: bool = True
    background_screening_action: str = "warn_only"
    output_dir: Optional[str] = None

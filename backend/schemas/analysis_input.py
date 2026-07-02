from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional


@dataclass
class SourceFile:
    path: str
    code: str
    imports: List[str] = field(default_factory=list)
    pragmas: List[str] = field(default_factory=list)

    @property
    def name(self) -> str:
        return Path(self.path).name


@dataclass
class FunctionUnit:
    source_path: str
    contract_name: str
    name: str
    signature: str
    start_line: int
    end_line: int
    code: str
    kind: str = "function"
    visibility: str = "unknown"
    mutability: str = "nonpayable"
    modifiers: List[str] = field(default_factory=list)
    internal_calls: List[str] = field(default_factory=list)
    external_calls: List[Dict[str, Any]] = field(default_factory=list)
    features: Dict[str, Any] = field(default_factory=dict)

    @property
    def function_id(self) -> str:
        return f"{self.source_path}:{self.contract_name}.{self.name}:{self.start_line}"


@dataclass
class ContractUnit:
    source_path: str
    name: str
    start_line: int
    end_line: int
    code: str
    functions: List[FunctionUnit] = field(default_factory=list)
    inheritance: List[str] = field(default_factory=list)
    state_variables: List[str] = field(default_factory=list)


@dataclass
class AnalysisInput:
    task_id: str
    sources: List[SourceFile]
    contracts: List[ContractUnit]
    functions: List[FunctionUnit]
    call_graph: Dict[str, List[str]] = field(default_factory=dict)
    target_vulnerability: Optional[str] = None

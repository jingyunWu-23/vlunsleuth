from __future__ import annotations

import re
from collections import defaultdict, deque
from pathlib import PurePosixPath
from typing import Any, Dict, Iterable, List, Set, Tuple

from backend.schemas import ContractUnit, Finding, RiskVector, SourceFile, Warning


RISK_THRESHOLD = 0.55


def analyze_project_components(
    sources: List[SourceFile],
    contracts: List[ContractUnit],
    call_graph: Dict[str, List[str]],
) -> Dict[str, Any]:
    """Group contracts by explicit project-level relationships.

    The grouping is intentionally conservative: unrelated contracts remain
    isolated unless there is an import, inheritance, contract reference, or
    known function-call relationship connecting them.
    """

    contract_keys = [contract_key(item) for item in contracts]
    key_by_name: Dict[str, List[str]] = defaultdict(list)
    key_by_source: Dict[str, List[str]] = defaultdict(list)
    contract_by_key = {contract_key(item): item for item in contracts}
    source_by_path = {source.path: source for source in sources}

    for contract in contracts:
        key = contract_key(contract)
        key_by_name[contract.name].append(key)
        key_by_source[contract.source_path].append(key)

    edges: List[Dict[str, str]] = []
    seen_edges: Set[Tuple[str, str, str]] = set()

    def add_edge(source: str, target: str, relation: str, detail: str = "") -> None:
        if not source or not target or source == target:
            return
        if source not in contract_by_key or target not in contract_by_key:
            return
        edge_key = tuple(sorted((source, target)) + [relation])
        if edge_key in seen_edges:
            return
        seen_edges.add(edge_key)
        edges.append({
            "source": source,
            "target": target,
            "relation": relation,
            "detail": detail,
        })

    for source in sources:
        source_contracts = key_by_source.get(source.path, [])
        for imported in source.imports:
            for target_path in resolve_imported_source(source.path, imported, source_by_path):
                for left in source_contracts:
                    for right in key_by_source.get(target_path, []):
                        add_edge(left, right, "import", imported)

    for contract in contracts:
        source_key = contract_key(contract)
        for base in contract.inheritance:
            for target_key in key_by_name.get(base, []):
                add_edge(source_key, target_key, "inheritance", base)

        referenced_names = referenced_contract_names(contract, set(key_by_name))
        for name in referenced_names:
            for target_key in key_by_name.get(name, []):
                add_edge(source_key, target_key, "contract_reference", name)

    function_owner = {
        fn.function_id: contract_key(contract)
        for contract in contracts
        for fn in contract.functions
    }
    function_by_contract_name = {
        f"{fn.contract_name}.{fn.name}": contract_key(contract)
        for contract in contracts
        for fn in contract.functions
    }
    for source_fn, called in call_graph.items():
        source_contract = function_owner.get(source_fn)
        if not source_contract:
            continue
        for called_name in called:
            target_contract = function_by_contract_name.get(called_name)
            if target_contract:
                add_edge(source_contract, target_contract, "function_call", called_name)

    components = connected_components(contract_keys, edges)
    return {
        "contract_count": len(contracts),
        "source_file_count": len(sources),
        "component_count": len(components),
        "isolated_contract_count": sum(1 for item in components if len(item["contracts"]) == 1),
        "edge_count": len(edges),
        "edges": edges,
        "components": components,
    }


def summarize_contract_status(
    contracts: List[ContractUnit],
    risk_vectors: List[RiskVector],
    findings: List[Finding],
    warnings: List[Warning],
    risk_threshold: float = RISK_THRESHOLD,
) -> Dict[str, Any]:
    contract_keys = [contract_key(item) for item in contracts]
    risk_by_contract: Dict[str, float] = defaultdict(float)
    finding_counts: Dict[str, int] = defaultdict(int)
    warning_counts: Dict[str, int] = defaultdict(int)

    for vector in risk_vectors:
        key = named_contract_key(vector.contract_name)
        risk_by_contract[key] = max(risk_by_contract[key], float(vector.r_func))
    for finding in findings:
        finding_counts[named_contract_key(finding.contract_name)] += 1
    for warning in warnings:
        warning_counts[named_contract_key(warning.contract_name)] += 1

    rows = []
    abnormal_count = 0
    for contract in contracts:
        key = contract_key(contract)
        name_key = named_contract_key(contract.name)
        finding_count = finding_counts.get(name_key, 0)
        warning_count = warning_counts.get(name_key, 0)
        max_risk = round(risk_by_contract.get(name_key, 0.0), 4)
        abnormal = finding_count > 0 or warning_count > 0 or max_risk >= risk_threshold
        abnormal_count += int(abnormal)
        rows.append({
            "contract_key": key,
            "contract_name": contract.name,
            "source_path": contract.source_path,
            "function_count": len(contract.functions),
            "finding_count": finding_count,
            "warning_count": warning_count,
            "max_r_func": max_risk,
            "status": "abnormal" if abnormal else "normal",
            "status_reason": contract_status_reason(finding_count, warning_count, max_risk, risk_threshold),
        })

    return {
        "input_contract_count": len(contract_keys),
        "normal_contract_count": len(contract_keys) - abnormal_count,
        "abnormal_contract_count": abnormal_count,
        "risk_threshold": risk_threshold,
        "contracts": rows,
    }


def function_contract_map(contracts: List[ContractUnit]) -> Dict[str, str]:
    return {
        fn.function_id: contract_key(contract)
        for contract in contracts
        for fn in contract.functions
    }


def contract_component_map(project_analysis: Dict[str, Any]) -> Dict[str, str]:
    result: Dict[str, str] = {}
    for component in project_analysis.get("components", []):
        component_id = str(component.get("component_id") or "")
        for key in component.get("contracts", []):
            result[str(key)] = component_id
    return result


def connected_components(contract_keys: List[str], edges: List[Dict[str, str]]) -> List[Dict[str, Any]]:
    graph: Dict[str, Set[str]] = {key: set() for key in contract_keys}
    edge_count_by_component: Dict[str, int] = defaultdict(int)
    for edge in edges:
        source = edge["source"]
        target = edge["target"]
        graph.setdefault(source, set()).add(target)
        graph.setdefault(target, set()).add(source)

    visited: Set[str] = set()
    components: List[Dict[str, Any]] = []
    for key in sorted(graph):
        if key in visited:
            continue
        queue = deque([key])
        visited.add(key)
        members: List[str] = []
        while queue:
            current = queue.popleft()
            members.append(current)
            for neighbor in sorted(graph.get(current, [])):
                if neighbor not in visited:
                    visited.add(neighbor)
                    queue.append(neighbor)
        member_set = set(members)
        component_edges = [edge for edge in edges if edge["source"] in member_set and edge["target"] in member_set]
        component_id = f"component_{len(components) + 1:03d}"
        edge_count_by_component[component_id] = len(component_edges)
        components.append({
            "component_id": component_id,
            "contracts": sorted(members),
            "contract_count": len(members),
            "edge_count": len(component_edges),
            "relations": sorted({edge["relation"] for edge in component_edges}),
            "is_isolated": len(members) == 1 and not component_edges,
        })
    return components


def resolve_imported_source(current_path: str, imported: str, source_by_path: Dict[str, SourceFile]) -> List[str]:
    cleaned = imported.strip().strip("\"'")
    match = re.search(r"['\"]([^'\"]+\.sol)['\"]", cleaned)
    if match:
        cleaned = match.group(1)
    current_virtual = normalize_virtual_path(current_path)
    current_dir = str(PurePosixPath(current_virtual).parent)
    candidates = {
        normalize_virtual_path(cleaned),
        str(PurePosixPath(current_dir) / cleaned),
        PurePosixPath(cleaned).name,
    }
    result = []
    for source_path in source_by_path:
        virtual = normalize_virtual_path(source_path)
        if virtual in candidates or PurePosixPath(virtual).name in candidates:
            result.append(source_path)
    return sorted(set(result))


def normalize_virtual_path(path: str) -> str:
    text = str(path).replace("\\", "/")
    if "!" in text:
        text = text.split("!", 1)[1]
    return text.lstrip("./")


def referenced_contract_names(contract: ContractUnit, known_names: Set[str]) -> Set[str]:
    references: Set[str] = set()
    code = contract.code
    for name in known_names:
        if name == contract.name:
            continue
        patterns = [
            rf"\bnew\s+{re.escape(name)}\b",
            rf"\b{re.escape(name)}\s*\(",
            rf"\b{re.escape(name)}\s*\.",
            rf"\b{re.escape(name)}\s+[A-Za-z_][A-Za-z0-9_]*\b",
        ]
        if any(re.search(pattern, code) for pattern in patterns):
            references.add(name)
    return references


def contract_status_reason(finding_count: int, warning_count: int, max_risk: float, threshold: float) -> str:
    if finding_count:
        return "has_findings"
    if warning_count:
        return "has_warnings"
    if max_risk >= threshold:
        return "high_risk_score"
    return "no_confirmed_or_high_risk_signal"


def contract_key(contract: ContractUnit) -> str:
    return f"{contract.source_path}:{contract.name}"


def named_contract_key(contract_name: str) -> str:
    return str(contract_name or "").strip()

from __future__ import annotations

from collections import defaultdict
from typing import Any, Dict, Iterable, List, Set

from backend.schemas import FunctionUnit, ModelEvidence, RiskVector


DEFAULT_WARNING_CATEGORIES = [
    "VULN_REENTRANCY",
    "VULN_TIMESTAMP",
    "VULN_DELEGATECALL",
    "VULN_UNCHECKED_LOW_LEVEL_CALLS",
    "VULN_CROSS_CONTRACT_RISK",
    "VULN_UNKNOWN_ANOMALY",
]

SWC_TO_VULN = {
    "SWC-104": "VULN_UNCHECKED_LOW_LEVEL_CALLS",
    "SWC-107": "VULN_REENTRANCY",
    "SWC-112": "VULN_DELEGATECALL",
    "SWC-116": "VULN_TIMESTAMP",
}

VULN_ALIASES = {
    "reentrancy": "VULN_REENTRANCY",
    "timestamp": "VULN_TIMESTAMP",
    "delegatecall": "VULN_DELEGATECALL",
    "SBunchecked_low_level_calls": "VULN_UNCHECKED_LOW_LEVEL_CALLS",
    "unchecked_low_level_calls": "VULN_UNCHECKED_LOW_LEVEL_CALLS",
}


def compute_risk_vectors(
    functions: Iterable[FunctionUnit],
    evidence_by_function: Dict[str, List[ModelEvidence]],
    selected_vulnerabilities: List[str],
    warning_categories: List[str] | None = None,
) -> List[RiskVector]:
    selected = [normalize_vulnerability(item) for item in selected_vulnerabilities]
    categories = warning_categories or DEFAULT_WARNING_CATEGORIES
    vectors: List[RiskVector] = []
    for fn in functions:
        evidences = evidence_by_function.get(fn.function_id, [])
        components = compute_components(fn, evidences)
        vector = RiskVector(
            function_id=fn.function_id,
            contract_name=fn.contract_name,
            function_signature=fn.signature,
            anomaly_score=components["A_f"],
            gcn_score=components["G_f"],
            static_score=components["S_f"],
            business_score=components["B_f"],
            knowledge_score=components["K_f"],
            consistency_score=components["C_f"],
            protection_score=components["P_f"],
            r_func=compute_r_func(components),
            component_reasons=components["reasons"],
        )
        for vulnerability in selected:
            vector.selected_scores[vulnerability] = compute_r_selected(fn, evidences, components, vulnerability)
        for category in categories:
            normalized = normalize_vulnerability(category)
            if normalized in selected:
                continue
            e_category = category_evidence_score(fn, evidences, normalized)
            q_evidence = evidence_quality_score(fn, evidences, normalized)
            warning_score = compute_r_warning(vector.r_func, e_category, q_evidence)
            vector.category_evidence_scores[normalized] = e_category
            vector.evidence_quality_scores[normalized] = q_evidence
            vector.warning_scores[normalized] = warning_score
        vectors.append(vector)
    return sorted(vectors, key=lambda item: item.r_func, reverse=True)


def compute_components(fn: FunctionUnit, evidences: List[ModelEvidence]) -> Dict[str, Any]:
    anomaly = max((ev.calibrated_confidence for ev in evidences if ev.model_id.startswith("DEEPSVDD")), default=0.0)
    gcn = max((ev.calibrated_confidence for ev in evidences if ev.model_id.startswith("GCN")), default=0.0)
    static = max(
        float(fn.features.get("static_score", 0.0)),
        max((ev.calibrated_confidence for ev in evidences if ev.model_id == "STATIC_RULES"), default=0.0),
    )
    business = float(fn.features.get("business_score", 0.0))
    knowledge = max((ev.calibrated_confidence for ev in evidences if ev.model_id == "RAG_KNOWLEDGE"), default=0.0)
    consistency = consistency_score(evidences)
    protection = float(fn.features.get("protection_score", 0.0))
    return {
        "A_f": anomaly,
        "G_f": gcn,
        "S_f": static,
        "B_f": business,
        "K_f": knowledge,
        "C_f": consistency,
        "P_f": protection,
        "reasons": {
            "A_f": explain_component("DeepSVDD anomaly evidence", anomaly, evidences, "DEEPSVDD"),
            "G_f": explain_component("GCN cross-contract evidence", gcn, evidences, "GCN"),
            "S_f": {
                "score": static,
                "dangerous_apis": fn.features.get("dangerous_apis", []),
                "critical_statement_count": len(fn.features.get("critical_statements", [])),
                "unchecked_low_level_call": fn.features.get("unchecked_low_level_call", False),
                "external_before_state_update": fn.features.get("external_before_state_update", False),
            },
            "B_f": {
                "score": business,
                "visibility": fn.visibility,
                "mutability": fn.mutability,
                "asset_terms": fn.features.get("asset_terms", False),
            },
            "K_f": explain_component("RAG knowledge match", knowledge, evidences, "RAG_KNOWLEDGE"),
            "C_f": {
                "score": consistency,
                "independent_sources": sorted(independent_sources(evidences)),
            },
            "P_f": {
                "score": protection,
                "protection_terms": fn.features.get("protection_terms", []),
            },
        },
    }


def compute_r_func(components: Dict[str, Any]) -> float:
    return clip(
        0.25 * components["A_f"]
        + 0.15 * components["G_f"]
        + 0.20 * components["S_f"]
        + 0.15 * components["B_f"]
        + 0.15 * components["K_f"]
        + 0.10 * components["C_f"]
        - 0.20 * components["P_f"]
    )


def compute_r_selected(
    fn: FunctionUnit,
    evidences: List[ModelEvidence],
    components: Dict[str, Any],
    vulnerability: str,
) -> float:
    if not semantic_category_allowed(fn, vulnerability):
        return 0.0
    lstm = max(
        (
            ev.calibrated_confidence
            for ev in evidences
            if ev.model_id.startswith("LSTM") and normalize_vulnerability(ev.vulnerability_id or ev.model_id) == vulnerability
        ),
        default=0.0,
    )
    static_category = static_category_score(fn, vulnerability)
    gcn_category = components["G_f"] if vulnerability == "VULN_CROSS_CONTRACT_RISK" else min(components["G_f"], 0.35)
    knowledge_category = knowledge_category_score(evidences, vulnerability)
    consistency = components["C_f"]
    anomaly = components["A_f"]
    protection = category_protection_score(fn, vulnerability)
    return clip(
        0.50 * lstm
        + 0.15 * static_category
        + 0.10 * gcn_category
        + 0.10 * knowledge_category
        + 0.10 * consistency
        + 0.05 * anomaly
        - 0.20 * protection
    )


def compute_r_warning(r_func: float, e_category: float, q_evidence: float) -> float:
    return clip(r_func * e_category * q_evidence)


def category_evidence_score(fn: FunctionUnit, evidences: List[ModelEvidence], category: str) -> float:
    if not semantic_category_allowed(fn, category):
        return 0.0
    knowledge = knowledge_category_score(evidences, category)
    static = static_category_score(fn, category)
    gcn = max((ev.calibrated_confidence for ev in evidences if ev.model_id.startswith("GCN")), default=0.0)
    consistency = category_consistency(evidences, category)
    return clip(0.35 * knowledge + 0.30 * static + 0.20 * gcn + 0.15 * consistency)


def evidence_quality_score(fn: FunctionUnit, evidences: List[ModelEvidence], category: str) -> float:
    if not semantic_category_allowed(fn, category):
        return 0.0
    sources = category_sources(fn, evidences, category)
    if not sources:
        return 0.0
    if sources.issuperset({"model", "static", "knowledge"}):
        return 0.9
    if sources.issuperset({"static", "knowledge"}):
        return 0.7
    if sources.issuperset({"llm", "knowledge"}):
        return 0.5
    if "model" in sources or "static" in sources or "knowledge" in sources:
        return 0.45
    return 0.2


def static_category_score(fn: FunctionUnit, category: str) -> float:
    if not semantic_category_allowed(fn, category):
        return 0.0
    dangerous = set(fn.features.get("dangerous_apis", []))
    score = 0.0
    if category == "VULN_REENTRANCY":
        if dangerous.intersection({"low_level_call", "send", "transfer"}) and fn.features.get("state_update"):
            score = max(score, 0.75)
        if fn.features.get("external_before_state_update"):
            score = max(score, 0.85)
    elif category == "VULN_TIMESTAMP":
        if "timestamp" in dangerous:
            score = max(score, 0.85)
    elif category == "VULN_DELEGATECALL":
        if "delegatecall" in dangerous:
            score = max(score, 0.9)
    elif category == "VULN_UNCHECKED_LOW_LEVEL_CALLS":
        if fn.features.get("unchecked_low_level_call"):
            score = max(score, 0.85)
        elif "low_level_call" in dangerous:
            score = max(score, 0.45)
    elif category == "VULN_CROSS_CONTRACT_RISK":
        if dangerous.intersection({"delegatecall", "low_level_call", "send", "transfer"}):
            score = max(score, 0.65)
    elif category == "VULN_UNKNOWN_ANOMALY":
        score = max(score, float(fn.features.get("static_score", 0.0)))
    return clip(score)


def knowledge_category_score(evidences: List[ModelEvidence], category: str) -> float:
    values = []
    for ev in evidences:
        if ev.model_id != "RAG_KNOWLEDGE":
            continue
        evidence_categories = categories_from_evidence(ev)
        if category in evidence_categories or not evidence_categories:
            values.append(ev.calibrated_confidence)
    return max(values, default=0.0)


def category_protection_score(fn: FunctionUnit, category: str) -> float:
    base = float(fn.features.get("protection_score", 0.0))
    terms = set(fn.features.get("protection_terms", []))
    if category == "VULN_REENTRANCY" and "nonReentrant" in terms:
        return max(base, 0.8)
    if category in {"VULN_REENTRANCY", "VULN_UNCHECKED_LOW_LEVEL_CALLS"} and "require(" in terms:
        return max(base, 0.35)
    return base


def category_consistency(evidences: List[ModelEvidence], category: str) -> float:
    sources = set()
    for ev in evidences:
        if ev.model_id == "STATIC_RULES" and static_or_unknown(category):
            sources.add("static")
        elif ev.model_id == "RAG_KNOWLEDGE" and (category in categories_from_evidence(ev) or not categories_from_evidence(ev)):
            sources.add("knowledge")
        elif ev.model_id.startswith("LSTM") and normalize_vulnerability(ev.vulnerability_id or ev.model_id) == category:
            sources.add("lstm")
        elif ev.model_id.startswith("DEEPSVDD") and category == "VULN_UNKNOWN_ANOMALY":
            sources.add("deepsvdd")
        elif ev.model_id.startswith("GCN") and category == "VULN_CROSS_CONTRACT_RISK":
            sources.add("gcn")
    return min(1.0, len(sources) / 3.0)


def category_sources(fn: FunctionUnit, evidences: List[ModelEvidence], category: str) -> Set[str]:
    if not semantic_category_allowed(fn, category):
        return set()
    sources: Set[str] = set()
    if static_category_score(fn, category) > 0:
        sources.add("static")
    if knowledge_category_score(evidences, category) > 0:
        sources.add("knowledge")
    for ev in evidences:
        if ev.model_id.startswith(("LSTM", "DEEPSVDD", "GCN")):
            if category in categories_from_evidence(ev) or (
                category == "VULN_UNKNOWN_ANOMALY" and ev.model_id.startswith("DEEPSVDD")
            ):
                sources.add("model")
    return sources


def semantic_category_allowed(fn: FunctionUnit, category: str) -> bool:
    """Hard semantic guards used to suppress impossible vulnerability labels."""
    category = normalize_vulnerability(category)
    dangerous = set(fn.features.get("dangerous_apis", []))
    read_only = is_read_only_function(fn)
    has_state_update = bool(fn.features.get("state_update"))
    has_external = bool(dangerous.intersection({"low_level_call", "send", "transfer", "delegatecall"}))

    if category == "VULN_UNKNOWN_ANOMALY":
        return True
    if category == "VULN_REENTRANCY":
        return (not read_only) and has_state_update and bool(dangerous.intersection({"low_level_call", "send", "transfer"}))
    if category == "VULN_UNCHECKED_LOW_LEVEL_CALLS":
        return (not read_only) and "low_level_call" in dangerous and bool(fn.features.get("unchecked_low_level_call"))
    if category == "VULN_TIMESTAMP":
        return "timestamp" in dangerous
    if category == "VULN_DELEGATECALL":
        return (not read_only) and "delegatecall" in dangerous
    if category == "VULN_CROSS_CONTRACT_RISK":
        return has_external or bool(fn.external_calls)
    return True


def is_read_only_function(fn: FunctionUnit) -> bool:
    mutability = (fn.mutability or "").lower()
    signature = (fn.signature or "").lower()
    code = (fn.code or "").lower()
    return mutability in {"view", "pure"} or " view " in f" {signature} " or " pure " in f" {signature} " or " view " in f" {code} " or " pure " in f" {code} "


def consistency_score(evidences: List[ModelEvidence]) -> float:
    return min(1.0, len(independent_sources(evidences)) / 5.0)


def independent_sources(evidences: List[ModelEvidence]) -> Set[str]:
    independent: Set[str] = set()
    for evidence in evidences:
        if evidence.model_id.startswith("LSTM"):
            independent.add("lstm")
        elif evidence.model_id.startswith("DEEPSVDD"):
            independent.add("deepsvdd")
        elif evidence.model_id.startswith("GCN"):
            independent.add("gcn")
        elif evidence.model_id == "STATIC_RULES":
            independent.add("static")
        elif evidence.model_id == "RAG_KNOWLEDGE":
            independent.add("knowledge")
    return independent


def explain_component(label: str, score: float, evidences: List[ModelEvidence], model_prefix: str) -> Dict[str, Any]:
    matched = [ev for ev in evidences if ev.model_id.startswith(model_prefix)]
    return {
        "label": label,
        "score": score,
        "evidence_ids": [ev.evidence_id for ev in matched],
        "max_confidence": max((ev.calibrated_confidence for ev in matched), default=0.0),
    }


def categories_from_evidence(evidence: ModelEvidence) -> Set[str]:
    categories: Set[str] = set()
    if evidence.vulnerability_id:
        categories.add(normalize_vulnerability(evidence.vulnerability_id))
    for item in evidence.feature_evidence:
        if item.get("type") != "rag_matches":
            continue
        for match in item.get("matches", []):
            swc = match.get("swc_id")
            if swc in SWC_TO_VULN:
                categories.add(SWC_TO_VULN[swc])
    if evidence.model_id.startswith("DEEPSVDD"):
        categories.add("VULN_UNKNOWN_ANOMALY")
    if evidence.model_id.startswith("GCN"):
        categories.add("VULN_CROSS_CONTRACT_RISK")
    return categories


def normalize_vulnerability(vulnerability: str | None) -> str:
    if not vulnerability:
        return "UNKNOWN"
    if vulnerability in VULN_ALIASES:
        return VULN_ALIASES[vulnerability]
    if vulnerability in SWC_TO_VULN:
        return SWC_TO_VULN[vulnerability]
    if vulnerability.startswith("VULN_"):
        return vulnerability
    upper = vulnerability.upper()
    for alias, canonical in VULN_ALIASES.items():
        if alias.upper() in upper:
            return canonical
    return vulnerability


def static_or_unknown(category: str) -> bool:
    return category in {
        "VULN_REENTRANCY",
        "VULN_TIMESTAMP",
        "VULN_DELEGATECALL",
        "VULN_UNCHECKED_LOW_LEVEL_CALLS",
        "VULN_CROSS_CONTRACT_RISK",
        "VULN_UNKNOWN_ANOMALY",
    }


def clip(value: float) -> float:
    return round(max(0.0, min(1.0, value)), 4)

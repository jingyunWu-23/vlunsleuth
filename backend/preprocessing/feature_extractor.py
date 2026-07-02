from __future__ import annotations

import re
import os
from typing import Dict, List

from backend.preprocessing.bytecode_embedding import attach_real_opcode_embeddings
from backend.preprocessing.solidity_parser import mask_comments, parse_sources
from backend.schemas import AnalysisInput, FunctionUnit, SourceFile


DANGEROUS_PATTERNS = {
    "delegatecall": r"\.delegatecall\s*\(",
    "low_level_call": r"\.call(?:\s*\{[^}]*\})?\s*\(",
    "send": r"\.send\s*\(",
    "transfer": r"\.transfer\s*\(",
    "selfdestruct": r"\bselfdestruct\s*\(",
    "tx_origin": r"\btx\.origin\b",
    "timestamp": r"\bblock\.timestamp\b|\bnow\b",
}
TOKEN_RE = re.compile(r"0x[0-9A-Fa-f]+|\d+|[A-Za-z_][A-Za-z0-9_]*|==|!=|<=|>=|&&|\|\||=>|[{}()\[\].,;:+\-*/%<>=!]")
STATE_UPDATE_RE = re.compile(r"(\+\+|--|\+=|-=|\*=|/=|%=|(?<![=!<>])=(?!=))")
REQUIRE_RE = re.compile(r"\b(require|assert|revert)\s*\(")

OPCODE_PROXY_MAP = {
    "require": "ASSERT",
    "assert": "ASSERT",
    "revert": "REVERT",
    "if": "JUMPI",
    "for": "LOOP",
    "while": "LOOP",
    "return": "RETURN",
    "emit": "LOG",
    "transfer": "CALL_VALUE",
    "send": "CALL_VALUE",
    "call": "CALL",
    "delegatecall": "DELEGATECALL",
    "staticcall": "STATICCALL",
    "selfdestruct": "SELFDESTRUCT",
    "suicide": "SELFDESTRUCT",
    "block": "ENV",
    "timestamp": "ENV",
    "tx": "ENV",
    "origin": "ENV",
    "msg": "CALLER",
    "sender": "CALLER",
    "value": "CALLVALUE",
}


def build_analysis_input(task_id: str, sources: List[SourceFile], target_vulnerability: str | None = None) -> AnalysisInput:
    contracts, call_graph = parse_sources(sources)
    functions = [fn for contract in contracts for fn in contract.functions]
    for fn in functions:
        fn.features.update(extract_static_features(fn))
    analysis = AnalysisInput(
        task_id=task_id,
        sources=sources,
        contracts=contracts,
        functions=functions,
        call_graph=call_graph,
        target_vulnerability=target_vulnerability,
    )
    if os.getenv("SCG_ENABLE_REAL_OPCODE", "1") != "0":
        result = attach_real_opcode_embeddings(analysis)
        for fn in functions:
            fn.features.setdefault("real_opcode_status", result.status)
            if result.warnings:
                fn.features.setdefault("real_opcode_warnings", result.warnings[:5])
    return analysis


def extract_static_features(fn: FunctionUnit) -> Dict[str, object]:
    code = fn.code
    searchable = mask_comments(code)
    tokens = tokenize_solidity(searchable)
    opcode_proxy = build_opcode_proxy(tokens)
    dangerous = [name for name, pattern in DANGEROUS_PATTERNS.items() if re.search(pattern, searchable)]
    state_update = bool(STATE_UPDATE_RE.search(searchable))
    access_check = any(token in code for token in ("onlyOwner", "hasRole", "require(", "assert("))
    external_interaction = any(item in dangerous for item in ("delegatecall", "low_level_call", "send", "transfer"))
    asset_terms = any(token in code.lower() for token in ("withdraw", "transfer", "deposit", "mint", "burn", "claim"))
    protection_terms = [token for token in ("nonReentrant", "onlyOwner", "whenNotPaused", "require(") if token in code]
    critical_statements = extract_critical_statements(fn)
    unchecked_low_level_call = has_unchecked_low_level_call(searchable)
    external_before_state_update = has_external_before_state_update(searchable)
    loop_external_call = has_loop_external_call(searchable)
    static_score = saturating_score([
        0.30 if external_interaction else 0.0,
        0.25 if state_update and external_interaction else 0.0,
        0.25 if "delegatecall" in dangerous else 0.0,
        0.20 if "tx_origin" in dangerous else 0.0,
        0.20 if "timestamp" in dangerous else 0.0,
        0.15 if asset_terms else 0.0,
        0.20 if unchecked_low_level_call else 0.0,
        0.20 if external_before_state_update else 0.0,
        0.20 if loop_external_call else 0.0,
    ])
    business_score = business_sensitivity(fn, asset_terms)
    protection_score = min(1.0, len(protection_terms) * 0.18)
    return {
        "dangerous_apis": dangerous,
        "state_update": state_update,
        "access_check": access_check,
        "asset_terms": asset_terms,
        "protection_terms": protection_terms,
        "unchecked_low_level_call": unchecked_low_level_call,
        "external_before_state_update": external_before_state_update,
        "loop_external_call": loop_external_call,
        "external_calls": fn.external_calls,
        "internal_calls": fn.internal_calls,
        "critical_statements": critical_statements,
        "token_sequence": tokens[:1000],
        "opcode_proxy_sequence": opcode_proxy[:1000],
        "token_count": len(tokens),
        "line_span": max(1, fn.end_line - fn.start_line + 1),
        "static_score": static_score,
        "business_score": business_score,
        "protection_score": protection_score,
    }


def saturating_score(parts: List[float]) -> float:
    product = 1.0
    for item in parts:
        product *= 1.0 - max(0.0, min(1.0, item))
    return round(1.0 - product, 4)


def business_sensitivity(fn: FunctionUnit, asset_terms: bool) -> float:
    code_lower = fn.code.lower()
    if any(token in code_lower for token in ("selfdestruct", "suicide")):
        return 1.0
    if any(token in code_lower for token in ("upgrade", "implementation", "delegatecall")):
        return 0.8
    if any(token in code_lower for token in ("owner", "admin", "role", "onlyowner")):
        return 0.7
    if asset_terms:
        return 0.6
    if re.search(r"\b(view|pure)\b", fn.signature):
        return 0.05
    return 0.2


def tokenize_solidity(code: str) -> List[str]:
    return [token for token in TOKEN_RE.findall(code) if token.strip()]


def build_opcode_proxy(tokens: List[str]) -> List[str]:
    sequence: List[str] = []
    for token in tokens:
        lower = token.lower()
        if lower in OPCODE_PROXY_MAP:
            sequence.append(OPCODE_PROXY_MAP[lower])
        elif re.fullmatch(r"\d+|0x[0-9a-fA-F]+", token):
            sequence.append("PUSH")
        elif token in {"=", "+=", "-=", "*=", "/=", "%=", "++", "--"}:
            sequence.append("SSTORE_OR_ASSIGN")
        elif token in {"+", "-", "*", "/", "%"}:
            sequence.append("ARITH")
        elif token in {"==", "!=", "<=", ">=", "<", ">"}:
            sequence.append("COMPARE")
        elif token in {"&&", "||", "!"}:
            sequence.append("LOGIC")
        elif token == ".":
            sequence.append("MEMBER")
        elif token == "{":
            sequence.append("BLOCK_START")
        elif token == "}":
            sequence.append("BLOCK_END")
        elif token == "(":
            sequence.append("ARG_START")
        elif token == ")":
            sequence.append("ARG_END")
        elif re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", token):
            sequence.append("IDENT")
        else:
            sequence.append("SYM")
    return sequence


def extract_critical_statements(fn: FunctionUnit) -> List[Dict[str, object]]:
    statements: List[Dict[str, object]] = []
    for offset, line in enumerate(fn.code.splitlines(), 0):
        stripped = line.strip()
        if not stripped:
            continue
        roles: List[str] = []
        if any(re.search(pattern, stripped) for pattern in DANGEROUS_PATTERNS.values()):
            roles.append("external_call")
        if STATE_UPDATE_RE.search(stripped) and not stripped.startswith(("require", "assert")):
            roles.append("state_update")
        if REQUIRE_RE.search(stripped) or "onlyOwner" in stripped or "hasRole" in stripped:
            roles.append("guard")
        if "tx.origin" in stripped or "block.timestamp" in stripped or re.search(r"\bnow\b", stripped):
            roles.append("environment_dependency")
        if roles:
            statements.append({
                "line": fn.start_line + offset,
                "code": stripped[:500],
                "roles": sorted(set(roles)),
            })
    return statements


def has_unchecked_low_level_call(code: str) -> bool:
    if not re.search(DANGEROUS_PATTERNS["low_level_call"], code):
        return False
    call_lines = [line for line in code.splitlines() if re.search(DANGEROUS_PATTERNS["low_level_call"], line)]
    for line in call_lines:
        if "require" in line or "assert" in line or "success" in line or "bool" in line:
            return False
    return True


def has_external_before_state_update(code: str) -> bool:
    external_match = re.search(
        r"\.(?:call|delegatecall|staticcall|send|transfer)(?:\s*\{[^}]*\})?\s*\(",
        code,
    )
    state_match = STATE_UPDATE_RE.search(code)
    return bool(external_match and state_match and external_match.start() < state_match.start())


def has_loop_external_call(code: str) -> bool:
    loop_match = re.search(r"\b(for|while)\s*\(", code)
    external_match = re.search(r"\.(?:call|delegatecall|staticcall|send|transfer)(?:\s*\{[^}]*\})?\s*\(", code)
    return bool(loop_match and external_match and loop_match.start() < external_match.start())

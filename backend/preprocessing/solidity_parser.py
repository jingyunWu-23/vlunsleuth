from __future__ import annotations

import re
from typing import Dict, List, Tuple

from backend.schemas import ContractUnit, FunctionUnit, SourceFile


CONTRACT_RE = re.compile(r"\b(contract|library|interface)\s+([A-Za-z_][A-Za-z0-9_]*)([^{;]*)\{")
FUNCTION_RE = re.compile(r"\b(function|constructor|fallback|receive|modifier)\b\s*([A-Za-z_][A-Za-z0-9_]*)?")
CALL_RE = re.compile(r"\b([A-Za-z_][A-Za-z0-9_]*)\s*\(")
PRAGMA_RE = re.compile(r"pragma\s+solidity\s+([^;]+);")
IMPORT_RE = re.compile(r"import\s+([^;]+);")
STATE_LINE_RE = re.compile(r"^\s*(?:mapping\s*\([^)]+\)|[A-Za-z_][A-Za-z0-9_<>\[\].]*)\s+[^;{}()]+;")
EXTERNAL_CALL_RE = re.compile(
    r"(?P<target>[A-Za-z_][A-Za-z0-9_\.]*)\s*\.\s*(?P<api>call|delegatecall|staticcall|callcode|send|transfer)\b"
)
SOLIDITY_KEYWORDS = {
    "if", "for", "while", "return", "require", "assert", "revert", "emit",
    "function", "modifier", "constructor", "fallback", "receive", "new",
    "address", "uint", "uint256", "int", "bool", "string", "bytes", "memory",
    "storage", "calldata", "public", "private", "internal", "external", "view",
    "pure", "payable", "returns",
}
VISIBILITY = {"public", "private", "internal", "external"}
MUTABILITY = {"view", "pure", "payable"}


def line_starts(code: str) -> List[int]:
    starts = [0]
    starts.extend(match.end() for match in re.finditer(r"\n", code))
    return starts


def pos_to_line(starts: List[int], pos: int) -> int:
    line = 1
    for idx, start in enumerate(starts):
        if start <= pos:
            line = idx + 1
        else:
            break
    return line


def find_matching_brace(code: str, open_pos: int) -> int:
    depth = 0
    in_string = ""
    in_line_comment = False
    in_block_comment = False
    i = open_pos
    while i < len(code):
        ch = code[i]
        nxt = code[i + 1] if i + 1 < len(code) else ""
        if in_line_comment:
            if ch == "\n":
                in_line_comment = False
        elif in_block_comment:
            if ch == "*" and nxt == "/":
                in_block_comment = False
                i += 1
        elif in_string:
            if ch == "\\":
                i += 1
            elif ch == in_string:
                in_string = ""
        else:
            if ch == "/" and nxt == "/":
                in_line_comment = True
                i += 1
            elif ch == "/" and nxt == "*":
                in_block_comment = True
                i += 1
            elif ch in {"'", '"'}:
                in_string = ch
            elif ch == "{":
                depth += 1
            elif ch == "}":
                depth -= 1
                if depth == 0:
                    return i
        i += 1
    return len(code) - 1


def parse_sources(sources: List[SourceFile]) -> Tuple[List[ContractUnit], Dict[str, List[str]]]:
    contracts: List[ContractUnit] = []
    call_graph: Dict[str, List[str]] = {}
    for source in sources:
        parsed_contracts = parse_source(source)
        contracts.extend(parsed_contracts)
        for contract in parsed_contracts:
            function_names = {fn.name for fn in contract.functions}
            for fn in contract.functions:
                calls = sorted({
                    call for call in fn.internal_calls
                    if call in function_names
                })
                fn.internal_calls = calls
                call_graph[fn.function_id] = calls
    return contracts, call_graph


def parse_source(source: SourceFile) -> List[ContractUnit]:
    code = source.code
    searchable = mask_comments(code)
    source.pragmas = PRAGMA_RE.findall(searchable)
    source.imports = [item.strip() for item in IMPORT_RE.findall(searchable)]
    starts = line_starts(code)
    contracts: List[ContractUnit] = []
    for match in CONTRACT_RE.finditer(searchable):
        open_pos = searchable.find("{", match.end() - 1)
        close_pos = find_matching_brace(code, open_pos)
        inheritance = parse_inheritance(match.group(3) or "")
        functions = parse_functions(source.path, match.group(2), code, searchable, open_pos + 1, close_pos, starts)
        state_variables = parse_state_variables(code[open_pos + 1:close_pos])
        contracts.append(ContractUnit(
            source_path=source.path,
            name=match.group(2),
            start_line=pos_to_line(starts, match.start()),
            end_line=pos_to_line(starts, close_pos),
            code=code[match.start():close_pos + 1],
            functions=functions,
            inheritance=inheritance,
            state_variables=state_variables,
        ))
    return contracts


def parse_inheritance(header_tail: str) -> List[str]:
    match = re.search(r"\bis\s+(.+)", header_tail)
    if not match:
        return []
    return [part.strip().split("(")[0].strip() for part in match.group(1).split(",") if part.strip()]


def parse_functions(
    source_path: str,
    contract_name: str,
    code: str,
    searchable: str,
    start: int,
    end: int,
    starts: List[int],
) -> List[FunctionUnit]:
    functions: List[FunctionUnit] = []
    for match in FUNCTION_RE.finditer(searchable, start, end):
        kind = match.group(1)
        if kind == "function" and not match.group(2):
            continue
        next_open = searchable.find("{", match.end(), end)
        next_semi = searchable.find(";", match.end(), end)
        if next_open == -1 or (next_semi != -1 and next_semi < next_open):
            continue
        close_pos = find_matching_brace(code, next_open)
        if close_pos > end:
            continue
        name = match.group(2) or kind
        signature = " ".join(code[match.start():next_open].strip().split())
        signature_meta = parse_signature_metadata(signature, kind, name)
        internal_calls = sorted({
            call for call in CALL_RE.findall(code[match.start():close_pos + 1])
            if call not in SOLIDITY_KEYWORDS and call != name
        })
        external_calls = parse_external_calls(code[match.start():close_pos + 1], starts, match.start())
        functions.append(FunctionUnit(
            source_path=source_path,
            contract_name=contract_name,
            name=name,
            signature=signature,
            start_line=pos_to_line(starts, match.start()),
            end_line=pos_to_line(starts, close_pos),
            code=code[match.start():close_pos + 1],
            kind=kind,
            visibility=signature_meta["visibility"],
            mutability=signature_meta["mutability"],
            modifiers=signature_meta["modifiers"],
            internal_calls=internal_calls,
            external_calls=external_calls,
        ))
    return functions


def parse_signature_metadata(signature: str, kind: str, name: str) -> Dict[str, object]:
    tokens = re.findall(r"[A-Za-z_][A-Za-z0-9_]*", signature)
    visibility = next((token for token in tokens if token in VISIBILITY), "unknown")
    mutability = next((token for token in tokens if token in MUTABILITY), "nonpayable")
    if "payable" in tokens:
        mutability = "payable"
    ignored = SOLIDITY_KEYWORDS | {kind, name}
    modifiers = [
        token for token in tokens
        if token not in ignored and token not in VISIBILITY and token not in MUTABILITY
    ]
    return {"visibility": visibility, "mutability": mutability, "modifiers": modifiers}


def parse_external_calls(code: str, starts: List[int], base_pos: int) -> List[Dict[str, object]]:
    calls: List[Dict[str, object]] = []
    for match in EXTERNAL_CALL_RE.finditer(code):
        calls.append({
            "target": match.group("target"),
            "api": match.group("api"),
            "line": pos_to_line(starts, base_pos + match.start()),
        })
    seen = {(item["api"], item["line"]) for item in calls}
    for offset, line in enumerate(code.splitlines()):
        for api in ("delegatecall", "staticcall", "callcode", "call", "send", "transfer"):
            if re.search(rf"\.\s*{api}\b", line):
                absolute_line = pos_to_line(starts, base_pos) + offset
                key = (api, absolute_line)
                if key not in seen:
                    calls.append({"target": "unknown", "api": api, "line": absolute_line})
                    seen.add(key)
    return calls


def parse_state_variables(contract_body: str) -> List[str]:
    variables: List[str] = []
    depth = 0
    for raw_line in contract_body.splitlines():
        line = raw_line.strip()
        if "{" in line:
            depth += line.count("{")
        if depth == 0 and line and not line.startswith(("//", "/*")) and STATE_LINE_RE.match(line):
            if not any(line.startswith(prefix) for prefix in ("event ", "error ", "using ", "struct ", "enum ")):
                variables.append(line[:300])
        if "}" in line:
            depth = max(0, depth - line.count("}"))
    return variables


def mask_comments(code: str) -> str:
    chars = list(code)
    i = 0
    in_string = ""
    while i < len(chars):
        ch = chars[i]
        nxt = chars[i + 1] if i + 1 < len(chars) else ""
        if in_string:
            if ch == "\\":
                i += 2
                continue
            if ch == in_string:
                in_string = ""
        elif ch in {"'", '"'}:
            in_string = ch
        elif ch == "/" and nxt == "/":
            chars[i] = " "
            chars[i + 1] = " "
            i += 2
            while i < len(chars) and chars[i] != "\n":
                chars[i] = " "
                i += 1
            continue
        elif ch == "/" and nxt == "*":
            chars[i] = " "
            chars[i + 1] = " "
            i += 2
            while i + 1 < len(chars):
                if chars[i] == "*" and chars[i + 1] == "/":
                    chars[i] = " "
                    chars[i + 1] = " "
                    i += 2
                    break
                if chars[i] != "\n":
                    chars[i] = " "
                i += 1
            continue
        i += 1
    return "".join(chars)

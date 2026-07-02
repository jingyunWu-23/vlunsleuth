from __future__ import annotations

import json
import os
import pickle
import re
import shutil
import subprocess
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional

from backend.schemas import AnalysisInput, SourceFile


DEFAULT_MAX_LEN = 500


@dataclass
class ContractOpcodeArtifact:
    source_path: str
    contract_name: str
    runtime_bytecode: str
    opcode_sequence: List[str]
    simplified_opcode_text: str
    embedding: List[int] = field(default_factory=list)
    compiler: Dict[str, Any] = field(default_factory=dict)


@dataclass
class OpcodeEmbeddingResult:
    status: str
    artifacts: List[ContractOpcodeArtifact] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)


def attach_real_opcode_embeddings(
    analysis: AnalysisInput,
    tokenizer_path: str | Path | None = None,
    solc_path: str | None = None,
    max_len: int = DEFAULT_MAX_LEN,
) -> OpcodeEmbeddingResult:
    result = build_real_opcode_embeddings(
        analysis.sources,
        tokenizer_path=tokenizer_path,
        solc_path=solc_path,
        max_len=max_len,
    )
    artifact_by_contract = {
        (artifact.source_path, artifact.contract_name): artifact
        for artifact in result.artifacts
    }
    artifact_by_name = {
        artifact.contract_name: artifact
        for artifact in result.artifacts
    }
    for contract in analysis.contracts:
        artifact = artifact_by_contract.get((contract.source_path, contract.name)) or artifact_by_name.get(contract.name)
        if artifact is None:
            continue
        contract_features = {
            "real_opcode_available": True,
            "real_opcode_sequence": artifact.opcode_sequence,
            "real_opcode_text": artifact.simplified_opcode_text,
            "real_opcode_embedding": artifact.embedding,
            "real_runtime_bytecode_size": len(artifact.runtime_bytecode) // 2,
            "real_opcode_compiler": artifact.compiler,
        }
        for fn in contract.functions:
            fn.features.update(contract_features)
    return result


def build_real_opcode_embeddings(
    sources: Iterable[SourceFile],
    tokenizer_path: str | Path | None = None,
    solc_path: str | None = None,
    max_len: int = DEFAULT_MAX_LEN,
) -> OpcodeEmbeddingResult:
    source_list = list(sources)
    compiler = resolve_solidity_compiler(solc_path)
    if compiler is None:
        return OpcodeEmbeddingResult(
            status="compiler_unavailable",
            warnings=[
                "Solidity compiler not found. Set SCG_SOLC_PATH to solc/solcjs to enable real opcode embedding."
            ],
            metadata={"real_opcode_available": False},
        )

    try:
        compiled = compile_sources_standard_json(source_list, compiler)
    except Exception as exc:
        return OpcodeEmbeddingResult(
            status="compile_error",
            warnings=[f"{type(exc).__name__}: {exc}"],
            metadata={"real_opcode_available": False, "compiler": compiler},
        )

    tokenizer = None
    try:
        tokenizer = load_tokenizer(tokenizer_path or default_tokenizer_path())
    except Exception as exc:
        tokenizer_error = f"{type(exc).__name__}: {exc}"
    else:
        tokenizer_error = None
    artifacts: List[ContractOpcodeArtifact] = []
    warnings: List[str] = []
    if tokenizer_error:
        warnings.append(f"Tokenizer unavailable; real opcode generated without embedding: {tokenizer_error}")
    source_path_by_key = source_path_mapping(source_list)
    for source_key, contracts in compiled.get("contracts", {}).items():
        for contract_name, payload in contracts.items():
            bytecode = (
                payload.get("evm", {})
                .get("deployedBytecode", {})
                .get("object", "")
            )
            if not bytecode:
                warnings.append(f"No runtime bytecode for {source_key}:{contract_name}")
                continue
            opcode_sequence = simplify_opcode_sequence(disassemble_evm(bytecode))
            opcode_text = " ".join(opcode_sequence)
            embedding = encode_opcode_text(tokenizer, opcode_text, max_len=max_len) if tokenizer is not None else []
            artifacts.append(ContractOpcodeArtifact(
                source_path=source_path_by_key.get(source_key, source_key),
                contract_name=contract_name,
                runtime_bytecode=normalize_hex(bytecode),
                opcode_sequence=opcode_sequence,
                simplified_opcode_text=opcode_text,
                embedding=embedding,
                compiler={
                    "path": compiler["path"],
                    "kind": compiler["kind"],
                    "source_key": source_key,
                    "max_len": max_len,
                },
            ))

    return OpcodeEmbeddingResult(
        status="ok" if artifacts else "no_runtime_bytecode",
        artifacts=artifacts,
        warnings=warnings,
        metadata={
            "real_opcode_available": bool(artifacts),
            "real_embedding_available": any(artifact.embedding for artifact in artifacts),
            "artifact_count": len(artifacts),
            "compiler": compiler,
            "max_len": max_len,
        },
    )


def resolve_solidity_compiler(solc_path: str | None = None) -> Optional[Dict[str, str]]:
    candidate = solc_path or os.getenv("SCG_SOLC_PATH")
    if candidate:
        path = Path(candidate)
        if path.exists():
            return {"path": str(path.resolve()), "kind": compiler_kind(path.name)}
        found = shutil.which(candidate)
        if found:
            return {"path": found, "kind": compiler_kind(Path(found).name)}
    for name in ("solc", "solcjs", "solc.cmd", "solcjs.cmd"):
        found = shutil.which(name)
        if found:
            return {"path": found, "kind": compiler_kind(Path(found).name)}
    node = shutil.which("node")
    multi_wrapper = Path(__file__).resolve().parent / "solcjs_multi_compile.js"
    if node and multi_wrapper.exists() and (Path(__file__).resolve().parents[2] / "node_modules").exists():
        return {"path": node, "kind": "solcjs_multi", "script": str(multi_wrapper)}
    workspace_bin = Path(__file__).resolve().parents[2] / "node_modules" / ".bin"
    for name in ("solcjs.cmd", "solc.cmd", "solcjs", "solc"):
        local = workspace_bin / name
        if local.exists():
            return {"path": str(local), "kind": compiler_kind(local.name)}
    return None


def compiler_kind(name: str) -> str:
    lowered = name.lower()
    return "solcjs" if "solcjs" in lowered or lowered.endswith(".js") else "solc"


def compile_sources_standard_json(sources: List[SourceFile], compiler: Dict[str, str]) -> Dict[str, Any]:
    source_entries = standard_json_sources(sources)
    request = {
        "language": "Solidity",
        "sources": {
            key: {"content": value["code"]}
            for key, value in source_entries.items()
        },
        "settings": {
            "optimizer": {"enabled": False},
            "outputSelection": {
                "*": {
                    "*": [
                        "evm.bytecode.object",
                        "evm.deployedBytecode.object",
                    ]
                }
            },
        },
    }
    cmd = compiler_command(compiler)
    completed = subprocess.run(
        cmd,
        input=json.dumps(request),
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=int(os.getenv("SCG_SOLC_TIMEOUT", "60")),
        check=False,
    )
    output_text = completed.stdout or ""
    if completed.returncode != 0 and not output_text.strip():
        raise RuntimeError((completed.stderr or "").strip() or f"Compiler exited {completed.returncode}")
    payload = parse_compiler_json(output_text)
    errors = payload.get("errors", [])
    fatal_errors = [
        item for item in errors
        if item.get("severity") == "error"
    ]
    if fatal_errors:
        formatted = "; ".join(item.get("formattedMessage") or item.get("message", "") for item in fatal_errors[:5])
        raise RuntimeError(formatted)
    return payload


def compiler_command(compiler: Dict[str, str]) -> List[str]:
    if compiler.get("kind") == "solcjs_multi":
        return [compiler["path"], compiler["script"]]
    return [compiler["path"], "--standard-json"]


def parse_compiler_json(output_text: str) -> Dict[str, Any]:
    stripped = output_text.strip()
    if not stripped:
        raise RuntimeError("Compiler produced empty output.")
    start = stripped.find("{")
    end = stripped.rfind("}")
    if start < 0 or end < start:
        raise RuntimeError(f"Compiler output is not JSON: {stripped[:500]}")
    return json.loads(stripped[start:end + 1])


def standard_json_sources(sources: List[SourceFile]) -> Dict[str, Dict[str, str]]:
    keys: Dict[str, Dict[str, str]] = {}
    for source in sources:
        key = source_key(source)
        keys[key] = {"code": source.code, "path": source.path}
        basename = Path(key).name
        if basename not in keys:
            keys[basename] = {"code": source.code, "path": source.path}
    return keys


def source_path_mapping(sources: List[SourceFile]) -> Dict[str, str]:
    mapping: Dict[str, str] = {}
    for source in sources:
        key = source_key(source)
        mapping[key] = source.path
        mapping.setdefault(Path(key).name, source.path)
    return mapping


def source_key(source: SourceFile) -> str:
    raw = source.path
    if "!" in raw:
        return raw.split("!", 1)[1].replace("\\", "/")
    path = Path(raw)
    return path.name if path.is_absolute() else raw.replace("\\", "/")


def load_tokenizer(tokenizer_path: str | Path):
    install_keras_preprocessing_alias()
    with Path(tokenizer_path).open("rb") as handle:
        tokenizer = pickle.load(handle)
    normalize_tokenizer(tokenizer)
    return tokenizer


def encode_opcode_text(tokenizer, opcode_text: str, max_len: int = DEFAULT_MAX_LEN) -> List[int]:
    sequences = tokenizer.texts_to_sequences([opcode_text])
    sequence = [int(value) for value in (sequences[0] if sequences else [])]
    if len(sequence) > max_len:
        sequence = sequence[-max_len:]
    if len(sequence) < max_len:
        sequence = [0] * (max_len - len(sequence)) + sequence
    return sequence


def install_keras_preprocessing_alias() -> None:
    if "keras_preprocessing.text" in sys.modules:
        return
    try:
        import tensorflow.keras.preprocessing.text as text_module  # type: ignore
        import tensorflow.keras.preprocessing.sequence as sequence_module  # type: ignore
    except Exception:
        return
    import types

    package = types.ModuleType("keras_preprocessing")
    package.text = text_module
    package.sequence = sequence_module
    sys.modules.setdefault("keras_preprocessing", package)
    sys.modules.setdefault("keras_preprocessing.text", text_module)
    sys.modules.setdefault("keras_preprocessing.sequence", sequence_module)


def normalize_tokenizer(tokenizer) -> None:
    defaults = {
        "analyzer": None,
        "filters": '!"#$%&()*+,-./:;<=>?@[\\]^_`{|}~\t\n',
        "lower": True,
        "split": " ",
        "char_level": False,
        "oov_token": None,
    }
    for key, value in defaults.items():
        if not hasattr(tokenizer, key):
            setattr(tokenizer, key, value)


def default_tokenizer_path() -> Path:
    return Path(__file__).resolve().parents[2] / "LG-DeepSVDD" / "pretrain" / "semantic features" / "LSTM" / "tok.pickle"


def disassemble_evm(bytecode: str) -> List[str]:
    data = bytes.fromhex(normalize_hex(bytecode))
    opcodes: List[str] = []
    pc = 0
    while pc < len(data):
        opcode = data[pc]
        name = EVM_OPCODE_NAMES.get(opcode, f"UNKNOWN_{opcode:02X}")
        opcodes.append(name)
        pc += 1
        if 0x60 <= opcode <= 0x7F:
            pc += opcode - 0x5F
    return opcodes


def simplify_opcode_sequence(opcodes: Iterable[str]) -> List[str]:
    simplified: List[str] = []
    for opcode in opcodes:
        if re.fullmatch(r"PUSH\d+", opcode):
            simplified.append("PUSH")
        elif re.fullmatch(r"DUP\d+", opcode):
            simplified.append("DUP")
        elif re.fullmatch(r"SWAP\d+", opcode):
            simplified.append("SWAP")
        elif re.fullmatch(r"LOG\d+", opcode):
            simplified.append("LOG")
        else:
            simplified.append(opcode)
    return simplified


def normalize_hex(bytecode: str) -> str:
    cleaned = bytecode.strip()
    if cleaned.startswith("0x"):
        cleaned = cleaned[2:]
    cleaned = re.sub(r"[^0-9a-fA-F]", "", cleaned)
    if len(cleaned) % 2:
        cleaned = "0" + cleaned
    return cleaned


EVM_OPCODE_NAMES = {
    0x00: "STOP", 0x01: "ADD", 0x02: "MUL", 0x03: "SUB", 0x04: "DIV", 0x05: "SDIV",
    0x06: "MOD", 0x07: "SMOD", 0x08: "ADDMOD", 0x09: "MULMOD", 0x0A: "EXP", 0x0B: "SIGNEXTEND",
    0x10: "LT", 0x11: "GT", 0x12: "SLT", 0x13: "SGT", 0x14: "EQ", 0x15: "ISZERO",
    0x16: "AND", 0x17: "OR", 0x18: "XOR", 0x19: "NOT", 0x1A: "BYTE", 0x1B: "SHL",
    0x1C: "SHR", 0x1D: "SAR",
    0x20: "SHA3",
    0x30: "ADDRESS", 0x31: "BALANCE", 0x32: "ORIGIN", 0x33: "CALLER", 0x34: "CALLVALUE",
    0x35: "CALLDATALOAD", 0x36: "CALLDATASIZE", 0x37: "CALLDATACOPY", 0x38: "CODESIZE",
    0x39: "CODECOPY", 0x3A: "GASPRICE", 0x3B: "EXTCODESIZE", 0x3C: "EXTCODECOPY",
    0x3D: "RETURNDATASIZE", 0x3E: "RETURNDATACOPY", 0x3F: "EXTCODEHASH",
    0x40: "BLOCKHASH", 0x41: "COINBASE", 0x42: "TIMESTAMP", 0x43: "NUMBER", 0x44: "DIFFICULTY",
    0x45: "GASLIMIT", 0x46: "CHAINID", 0x47: "SELFBALANCE", 0x48: "BASEFEE", 0x49: "BLOBHASH",
    0x4A: "BLOBBASEFEE",
    0x50: "POP", 0x51: "MLOAD", 0x52: "MSTORE", 0x53: "MSTORE8", 0x54: "SLOAD",
    0x55: "SSTORE", 0x56: "JUMP", 0x57: "JUMPI", 0x58: "PC", 0x59: "MSIZE", 0x5A: "GAS",
    0x5B: "JUMPDEST", 0x5C: "TLOAD", 0x5D: "TSTORE", 0x5E: "MCOPY", 0x5F: "PUSH0",
    **{0x60 + i: f"PUSH{i + 1}" for i in range(32)},
    **{0x80 + i: f"DUP{i + 1}" for i in range(16)},
    **{0x90 + i: f"SWAP{i + 1}" for i in range(16)},
    **{0xA0 + i: f"LOG{i}" for i in range(5)},
    0xF0: "CREATE", 0xF1: "CALL", 0xF2: "CALLCODE", 0xF3: "RETURN", 0xF4: "DELEGATECALL",
    0xF5: "CREATE2", 0xFA: "STATICCALL", 0xFD: "REVERT", 0xFE: "INVALID", 0xFF: "SELFDESTRUCT",
}

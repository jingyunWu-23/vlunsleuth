from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Tuple


ROOT = Path(__file__).resolve().parents[2]
DEFAULT_JSONL = ROOT / "dataset" / "knowledge" / "unified_multi_agent_knowledge.jsonl"


class JsonlKnowledgeStore:
    def __init__(self, jsonl_path: str | Path = DEFAULT_JSONL) -> None:
        self.jsonl_path = Path(jsonl_path)
        self._entries: Optional[List[Dict[str, Any]]] = None
        self._indexed_entries: Optional[List[Tuple[Dict[str, Any], set]]] = None

    @property
    def entries(self) -> List[Dict[str, Any]]:
        if self._entries is None:
            self._entries = list(self._load())
        return self._entries

    @property
    def indexed_entries(self) -> List[Tuple[Dict[str, Any], set]]:
        if self._indexed_entries is None:
            self._indexed_entries = [(entry, entry_token_set(entry)) for entry in self.entries]
        return self._indexed_entries

    def search(
        self,
        query: str,
        top_k: int = 5,
        knowledge_type: str | None = None,
        agent: str | None = None,
        swc_id: str | None = None,
    ) -> List[Dict[str, Any]]:
        query_tokens = tokenize(query)
        ranked = []
        for entry, haystack in self.indexed_entries:
            if knowledge_type and entry.get("knowledge_type") != knowledge_type:
                continue
            if agent and agent not in entry.get("agent_targets", []):
                continue
            if swc_id and entry.get("swc_id") != swc_id:
                continue
            ranked.append((score_tokens(haystack, query_tokens), entry))
        ranked.sort(key=lambda item: item[0], reverse=True)
        return [entry for item_score, entry in ranked[:top_k] if item_score > 0]

    def _load(self) -> Iterable[Dict[str, Any]]:
        if not self.jsonl_path.exists():
            return []
        with self.jsonl_path.open("r", encoding="utf-8") as f:
            for line in f:
                if line.strip():
                    yield json.loads(line)


def tokenize(text: str) -> List[str]:
    return [tok.lower() for tok in re.findall(r"[A-Za-z_][A-Za-z0-9_]*|SWC-\d+|\d+", text)]


def score_entry(entry: Dict[str, Any], query_tokens: List[str]) -> int:
    if not query_tokens:
        return 0
    parts = [
        entry.get("swc_id", ""),
        entry.get("vulnerability_name", ""),
        entry.get("contract_name", ""),
        entry.get("function_name", ""),
        entry.get("storage", {}).get("embedding_text", ""),
    ]
    return score_tokens(set(tokenize("\n".join(str(part) for part in parts))), query_tokens)


def entry_token_set(entry: Dict[str, Any]) -> set:
    parts = [
        entry.get("swc_id", ""),
        entry.get("vulnerability_name", ""),
        entry.get("contract_name", ""),
        entry.get("function_name", ""),
        entry.get("storage", {}).get("embedding_text", ""),
    ]
    return set(tokenize("\n".join(str(part) for part in parts)))


def score_tokens(haystack: set, query_tokens: List[str]) -> int:
    return sum(1 for token in query_tokens if token in haystack)

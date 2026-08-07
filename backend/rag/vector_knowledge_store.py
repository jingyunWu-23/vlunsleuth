from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Tuple

import joblib
import numpy as np


ROOT = Path(__file__).resolve().parents[2]
DEFAULT_VECTOR_INDEX = ROOT / "dataset" / "knowledge" / "vector_index" / "knowledge_vector_index.joblib"


class VectorKnowledgeStore:
    def __init__(self, index_path: str | Path = DEFAULT_VECTOR_INDEX) -> None:
        self.index_path = Path(index_path)
        self._loaded = False
        self._vectorizer = None
        self._matrix = None
        self._entries: List[Dict[str, Any]] = []
        self._meta: Dict[str, Any] = {}

    @property
    def entries(self) -> List[Dict[str, Any]]:
        self._ensure_loaded()
        return self._entries

    @property
    def meta(self) -> Dict[str, Any]:
        self._ensure_loaded()
        return self._meta

    def search(
        self,
        query: str,
        top_k: int = 5,
        knowledge_type: str | None = None,
        agent: str | None = None,
        swc_id: str | None = None,
    ) -> List[Dict[str, Any]]:
        self._ensure_loaded()
        if not query.strip() or self._matrix is None or self._vectorizer is None:
            return []

        query_vector = self._vectorizer.transform([query])
        raw_scores = self._matrix @ query_vector.T
        scores = np.asarray(raw_scores.toarray() if hasattr(raw_scores, "toarray") else raw_scores).ravel()
        if scores.size == 0:
            return []

        candidates = []
        for idx, score in enumerate(scores):
            if score <= 0:
                continue
            entry = self._entries[idx]
            if knowledge_type and entry.get("knowledge_type") != knowledge_type:
                continue
            if agent and agent not in normalize_agent_targets(entry.get("agent_targets")):
                continue
            if swc_id and entry.get("swc_id") != swc_id:
                continue
            candidates.append((float(score), idx, entry))

        candidates.sort(key=lambda item: item[0], reverse=True)
        results: List[Dict[str, Any]] = []
        for score, _, entry in candidates[:top_k]:
            item = dict(entry)
            retrieval = dict(item.get("retrieval") or {})
            retrieval["vector_similarity"] = round(score, 6)
            retrieval["backend"] = "tfidf_vector"
            item["retrieval"] = retrieval
            results.append(item)
        return results

    def _ensure_loaded(self) -> None:
        if self._loaded:
            return
        if not self.index_path.exists():
            raise FileNotFoundError(
                f"Vector knowledge index not found: {self.index_path}. "
                "Run tools/build_vector_knowledge_base.py first."
            )
        payload = joblib.load(self.index_path)
        self._vectorizer = payload["vectorizer"]
        self._matrix = payload["matrix"]
        self._entries = payload["entries"]
        self._meta = payload.get("meta", {})
        self._loaded = True


def normalize_agent_targets(value: Any) -> List[str]:
    if value is None:
        return []
    if isinstance(value, list):
        return [str(item) for item in value]
    if isinstance(value, str):
        try:
            parsed = json.loads(value)
            if isinstance(parsed, list):
                return [str(item) for item in parsed]
        except json.JSONDecodeError:
            pass
        return [part.strip() for part in value.split(",") if part.strip()]
    return [str(value)]


def normalize_knowledge_record(record: Dict[str, Any], source_path: str | Path) -> Tuple[Dict[str, Any], str] | None:
    if "metadata" in record and "text" in record:
        metadata = dict(record.get("metadata") or {})
        text = str(record.get("text") or "")
        entry = metadata
        entry.setdefault("content", {"summary": text[:2000]})
        entry.setdefault("storage", {"embedding_text": text})
    else:
        entry = dict(record)
        text = build_embedding_text(entry)

    if not text.strip():
        return None

    entry["agent_targets"] = normalize_agent_targets(entry.get("agent_targets"))
    entry.setdefault("knowledge_id", stable_knowledge_id(entry, text))
    entry.setdefault("source_jsonl", str(source_path))
    return entry, text


def build_embedding_text(entry: Dict[str, Any]) -> str:
    storage = entry.get("storage") if isinstance(entry.get("storage"), dict) else {}
    retrieval = entry.get("retrieval") if isinstance(entry.get("retrieval"), dict) else {}
    if storage.get("embedding_text"):
        return str(storage["embedding_text"])
    if retrieval.get("primary_query_text"):
        return str(retrieval["primary_query_text"])

    parts = [
        entry.get("knowledge_type", ""),
        entry.get("swc_id", ""),
        entry.get("cwe_id", ""),
        entry.get("vulnerability_name", ""),
        entry.get("risk_level", ""),
        entry.get("project_name", ""),
        entry.get("contract_name", ""),
        entry.get("function_name", ""),
        json.dumps(entry.get("content", {}), ensure_ascii=False),
        json.dumps(entry.get("evidence", {}), ensure_ascii=False)[:4000],
    ]
    return "\n".join(str(part) for part in parts if part)


def stable_knowledge_id(entry: Dict[str, Any], text: str) -> str:
    import hashlib

    base = "|".join(
        str(entry.get(key, ""))
        for key in ("dataset", "case_id", "knowledge_type", "swc_id", "contract_name", "function_name")
    )
    digest = hashlib.sha1((base + text[:1000]).encode("utf-8", errors="ignore")).hexdigest()[:16]
    return f"kb_{digest}"


def iter_jsonl_records(paths: Iterable[Path]) -> Iterable[Tuple[Path, Dict[str, Any]]]:
    for path in paths:
        with path.open("r", encoding="utf-8", errors="ignore") as handle:
            for line in handle:
                line = line.strip()
                if not line:
                    continue
                try:
                    yield path, json.loads(line)
                except json.JSONDecodeError:
                    continue

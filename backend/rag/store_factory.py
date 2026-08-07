from __future__ import annotations

import os
from pathlib import Path
from typing import Any

from backend.rag.jsonl_knowledge_store import JsonlKnowledgeStore
from backend.rag.vector_knowledge_store import DEFAULT_VECTOR_INDEX, VectorKnowledgeStore


def get_default_knowledge_store() -> Any:
    backend = os.getenv("SCG_RAG_BACKEND", "vector").strip().lower()
    if backend in {"jsonl", "keyword"}:
        return JsonlKnowledgeStore(os.getenv("SCG_RAG_JSONL_PATH") or JsonlKnowledgeStore().jsonl_path)

    index_path = Path(os.getenv("SCG_RAG_VECTOR_INDEX") or DEFAULT_VECTOR_INDEX)
    if index_path.exists():
        return VectorKnowledgeStore(index_path)

    if os.getenv("SCG_RAG_REQUIRE_VECTOR", "0") == "1":
        return VectorKnowledgeStore(index_path)
    return JsonlKnowledgeStore(os.getenv("SCG_RAG_JSONL_PATH") or JsonlKnowledgeStore().jsonl_path)

from __future__ import annotations

import argparse
import json
from datetime import datetime
from pathlib import Path
from typing import List

import joblib
from sklearn.feature_extraction.text import TfidfVectorizer

from backend.rag.vector_knowledge_store import (
    DEFAULT_VECTOR_INDEX,
    ROOT,
    iter_jsonl_records,
    normalize_knowledge_record,
)


DEFAULT_JSONL_DIR = ROOT / "dataset"


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Build a local vector knowledge index from JSONL knowledge files.")
    parser.add_argument(
        "--input",
        action="append",
        type=Path,
        help="JSONL file or directory. Can be passed multiple times. Defaults to dataset/knowledge.",
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=DEFAULT_VECTOR_INDEX,
        help="Output .joblib vector index path.",
    )
    parser.add_argument("--max-features", type=int, default=120000)
    parser.add_argument("--ngram-max", type=int, default=2)
    parser.add_argument("--include-vector-metadata", action="store_true")
    return parser.parse_args()


def collect_jsonl_paths(inputs: List[Path], include_vector_metadata: bool) -> List[Path]:
    paths: List[Path] = []
    roots = inputs or [DEFAULT_JSONL_DIR]
    for item in roots:
        item = item.resolve()
        if item.is_file() and item.suffix.lower() == ".jsonl":
            paths.append(item)
        elif item.is_dir():
            for path in item.rglob("*.jsonl"):
                if not include_vector_metadata and "vector" in {part.lower() for part in path.parts}:
                    continue
                paths.append(path.resolve())
    return sorted(set(paths))


def build_index(args: argparse.Namespace) -> dict:
    paths = collect_jsonl_paths(args.input or [], args.include_vector_metadata)
    if not paths:
        raise FileNotFoundError("No JSONL knowledge files found.")

    entries = []
    texts = []
    seen = set()
    for source_path, record in iter_jsonl_records(paths):
        normalized = normalize_knowledge_record(record, source_path)
        if normalized is None:
            continue
        entry, text = normalized
        dedupe_key = entry.get("knowledge_id") or text[:1000]
        if dedupe_key in seen:
            continue
        seen.add(dedupe_key)
        entries.append(entry)
        texts.append(text)

    if not entries:
        raise ValueError("No valid knowledge records were extracted from JSONL files.")

    vectorizer = TfidfVectorizer(
        lowercase=True,
        token_pattern=r"(?u)\b[A-Za-z_][A-Za-z0-9_]*\b|SWC-\d+|\b\d+\b",
        ngram_range=(1, max(1, args.ngram_max)),
        max_features=args.max_features,
        min_df=1,
        norm="l2",
    )
    matrix = vectorizer.fit_transform(texts)
    meta = {
        "backend": "sklearn_tfidf_cosine",
        "created_at": datetime.now().isoformat(timespec="seconds"),
        "source_files": [str(path) for path in paths],
        "entry_count": len(entries),
        "feature_count": len(vectorizer.vocabulary_),
        "max_features": args.max_features,
        "ngram_range": [1, max(1, args.ngram_max)],
    }
    return {"vectorizer": vectorizer, "matrix": matrix, "entries": entries, "meta": meta}


def main() -> None:
    args = parse_args()
    payload = build_index(args)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    joblib.dump(payload, args.output, compress=3)
    print(json.dumps({
        "output": str(args.output),
        "entry_count": payload["meta"]["entry_count"],
        "feature_count": payload["meta"]["feature_count"],
        "source_files": payload["meta"]["source_files"],
    }, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()

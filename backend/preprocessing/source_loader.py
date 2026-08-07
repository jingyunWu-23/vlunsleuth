# -*- coding: utf-8 -*-
from __future__ import annotations

import zipfile
from pathlib import Path
from typing import List

from backend.schemas import SourceFile


def read_text(path: Path) -> str:
    data = path.read_bytes()
    for encoding in ("utf-8", "utf-8-sig", "gb18030", "gbk", "cp936", "latin-1"):
        try:
            return data.decode(encoding)
        except UnicodeError:
            continue
    return data.decode("latin-1", errors="replace")


def load_sources(source_path: str) -> List[SourceFile]:
    path = Path(source_path)
    if not path.exists():
        raise FileNotFoundError(f"Source path does not exist: {source_path}")

    sources: List[SourceFile] = []
    if path.is_file() and path.suffix.lower() == ".sol":
        sources.append(SourceFile(path=str(path), code=read_text(path)))
    elif path.is_file() and path.suffix.lower() == ".zip":
        with zipfile.ZipFile(path) as archive:
            for name in sorted(archive.namelist()):
                if name.lower().endswith(".sol") and not name.endswith("/"):
                    data = archive.read(name)
                    code = data.decode("utf-8", errors="ignore")
                    sources.append(SourceFile(path=f"{path}!{name}", code=code))
    elif path.is_dir():
        for item in sorted(path.rglob("*.sol")):
            sources.append(SourceFile(path=str(item), code=read_text(item)))
    else:
        raise ValueError(f"Unsupported source input: {source_path}")

    if not sources:
        raise ValueError(f"No Solidity source files found under: {source_path}")
    return sources

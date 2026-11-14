from __future__ import annotations
import json
from pathlib import Path
from typing import Any

def load_json(path: str | Path) -> Any:
    return json.loads(Path(path).read_text(encoding="utf-8"))

def load_bytes(path: str | Path) -> bytes:
    return Path(path).read_bytes()

def load_store(path: str | Path) -> dict:
    p = Path(path)
    if not p.exists():
        return {"items": {}}
    data = load_json(p)
    if not isinstance(data, dict) or "items" not in data or not isinstance(data["items"], dict):
        raise ValueError("store must be object with items object")
    return data

def save_store(path: str | Path, data: dict) -> None:
    p = Path(path)
    tmp = p.with_suffix(p.suffix + ".tmp")
    tmp.write_text(json.dumps(data, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    tmp.replace(p)

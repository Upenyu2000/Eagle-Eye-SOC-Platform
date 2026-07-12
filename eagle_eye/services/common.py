from __future__ import annotations

import csv
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable


def flatten(value: Any, prefix: str = "") -> dict[str, Any]:
    output: dict[str, Any] = {}
    if isinstance(value, dict):
        for key, item in value.items():
            next_prefix = f"{prefix}.{key}" if prefix else str(key)
            output.update(flatten(item, next_prefix))
    elif isinstance(value, list):
        output[prefix] = value
    else:
        output[prefix] = value
    return output


def normalise_key(key: str) -> str:
    return "".join(character.lower() for character in key if character.isalnum())


def find_value(record: dict[str, Any], candidates: Iterable[str], default: Any = "") -> Any:
    flat = flatten(record)
    normalised = {normalise_key(key): value for key, value in flat.items()}
    candidate_keys = [normalise_key(item) for item in candidates]
    for candidate in candidate_keys:
        if candidate in normalised:
            return normalised[candidate]
    for key, value in normalised.items():
        if any(key.endswith(candidate) for candidate in candidate_keys):
            return value
    return default


def parse_time(value: Any) -> datetime:
    if isinstance(value, datetime):
        dt = value
    elif isinstance(value, (int, float)):
        dt = datetime.fromtimestamp(float(value), tz=timezone.utc)
    else:
        text = str(value or "").strip()
        if not text:
            return datetime.now(timezone.utc)
        text = text.replace("Z", "+00:00")
        try:
            dt = datetime.fromisoformat(text)
        except ValueError:
            for fmt in ("%Y-%m-%d %H:%M:%S", "%d/%m/%Y %H:%M:%S"):
                try:
                    dt = datetime.strptime(text, fmt)
                    break
                except ValueError:
                    continue
            else:
                return datetime.now(timezone.utc)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


def load_records(path: str | Path) -> list[dict[str, Any]]:
    source = Path(path)
    suffix = source.suffix.lower()
    if suffix == ".csv":
        with source.open("r", encoding="utf-8-sig", newline="") as handle:
            return [dict(row) for row in csv.DictReader(handle)]

    text = source.read_text(encoding="utf-8-sig")
    if suffix in {".ndjson", ".jsonl"}:
        return [json.loads(line) for line in text.splitlines() if line.strip()]

    data = json.loads(text)
    if isinstance(data, list):
        return [item for item in data if isinstance(item, dict)]
    if isinstance(data, dict):
        hits = data.get("hits", {}).get("hits") if isinstance(data.get("hits"), dict) else None
        if isinstance(hits, list):
            return [item.get("_source", item) for item in hits if isinstance(item, dict)]
        for key in ("records", "events", "value", "alerts"):
            if isinstance(data.get(key), list):
                return [item for item in data[key] if isinstance(item, dict)]
        return [data]
    raise ValueError("Unsupported telemetry format")

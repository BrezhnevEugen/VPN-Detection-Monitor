from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path


@dataclass(slots=True)
class MonitorConfig:
    feeds: list[str]
    keywords: list[str]
    phrases: list[str]
    company_boost: list[str]
    government_boost: list[str]
    priority_apps: list[str]

    @classmethod
    def load(cls, path: str | Path) -> "MonitorConfig":
        payload = json.loads(Path(path).read_text(encoding="utf-8"))
        return cls(
            feeds=payload.get("feeds", []),
            keywords=[item.lower() for item in payload.get("keywords", [])],
            phrases=[item.lower() for item in payload.get("phrases", [])],
            company_boost=[item.lower() for item in payload.get("company_boost", [])],
            government_boost=[item.lower() for item in payload.get("government_boost", [])],
            priority_apps=[item.lower() for item in payload.get("priority_apps", [])],
        )

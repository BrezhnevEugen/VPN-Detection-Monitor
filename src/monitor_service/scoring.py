from __future__ import annotations

from dataclasses import dataclass

from monitor_service.config import MonitorConfig
from monitor_service.feeds import FeedEntry


@dataclass(slots=True)
class ScoredEntry:
    entry: FeedEntry
    score: int
    matched_keywords: list[str]
    matched_phrases: list[str]
    matched_priority_apps: list[str]


def score_entry(entry: FeedEntry, config: MonitorConfig) -> ScoredEntry | None:
    haystack = " ".join([entry.title, entry.summary]).lower()

    matched_keywords = [word for word in config.keywords if word in haystack]
    matched_phrases = [phrase for phrase in config.phrases if phrase in haystack]
    matched_companies = [word for word in config.company_boost if word in haystack]
    matched_government = [word for word in config.government_boost if word in haystack]
    matched_priority_apps = [app for app in config.priority_apps if app in haystack]

    if not matched_keywords and not matched_phrases:
        if not matched_priority_apps:
            return None

    if not matched_phrases and not (matched_companies and matched_government) and not matched_priority_apps:
        return None

    score = len(matched_keywords) + len(matched_phrases) * 3
    if matched_companies:
        score += 3
    if matched_government:
        score += 3
    if matched_priority_apps:
        score += 6 + len(matched_priority_apps)

    if score < 4:
        return None

    return ScoredEntry(
        entry=entry,
        score=score,
        matched_keywords=matched_keywords,
        matched_phrases=matched_phrases,
        matched_priority_apps=matched_priority_apps,
    )

from __future__ import annotations

import logging
import time

from monitor_service.config import MonitorConfig
from monitor_service.feeds import fetch_entries
from monitor_service.scoring import score_entry
from monitor_service.storage import Storage


LOG = logging.getLogger(__name__)


class MonitorService:
    def __init__(self, config: MonitorConfig, storage: Storage) -> None:
        self.config = config
        self.storage = storage

    def run_once(self) -> dict[str, int]:
        stats = {"feeds": 0, "entries": 0, "matched": 0, "saved": 0, "errors": 0}
        for feed_url in self.config.feeds:
            stats["feeds"] += 1
            try:
                entries = fetch_entries(feed_url)
            except Exception as exc:  # noqa: BLE001
                stats["errors"] += 1
                LOG.warning("Feed fetch failed for %s: %s", feed_url, exc)
                continue

            for entry in entries:
                stats["entries"] += 1
                scored = score_entry(entry, self.config)
                if scored is None:
                    continue
                stats["matched"] += 1
                if self.storage.save(scored):
                    stats["saved"] += 1
        return stats

    def watch(self, interval_seconds: int) -> None:
        while True:
            stats = self.run_once()
            LOG.info("Cycle finished: %s", stats)
            time.sleep(interval_seconds)

from __future__ import annotations

import json
import sqlite3
from pathlib import Path

from monitor_service.scoring import ScoredEntry


SCHEMA_STATEMENTS = [
    """
    CREATE TABLE IF NOT EXISTS findings (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        link TEXT NOT NULL UNIQUE,
        source TEXT NOT NULL,
        title TEXT NOT NULL,
        summary TEXT NOT NULL,
        published_at TEXT,
        score INTEGER NOT NULL,
        matched_keywords TEXT NOT NULL,
        matched_phrases TEXT NOT NULL,
        matched_priority_apps TEXT NOT NULL DEFAULT '[]',
        created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS app_baselines (
        app_name TEXT PRIMARY KEY,
        rank_by_methods INTEGER,
        methods_count INTEGER,
        methods_json TEXT NOT NULL,
        notes TEXT NOT NULL,
        source_url TEXT NOT NULL,
        baseline_date TEXT NOT NULL,
        updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS scan_runs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        app_name TEXT NOT NULL,
        version TEXT NOT NULL,
        scan_target TEXT NOT NULL,
        scanned_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
        method_count INTEGER NOT NULL,
        methods_json TEXT NOT NULL,
        summary_json TEXT NOT NULL,
        UNIQUE(app_name, version, scan_target)
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS scan_hits (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        run_id INTEGER NOT NULL,
        method_id TEXT NOT NULL,
        file_path TEXT NOT NULL,
        line_no INTEGER,
        snippet TEXT NOT NULL,
        FOREIGN KEY(run_id) REFERENCES scan_runs(id) ON DELETE CASCADE
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS news_methods (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        method_key TEXT NOT NULL,
        label TEXT NOT NULL,
        description TEXT NOT NULL,
        evidence TEXT NOT NULL,
        source_link TEXT NOT NULL,
        source_title TEXT NOT NULL,
        source_kind TEXT NOT NULL DEFAULT 'news',
        scanner_method_id TEXT,
        status TEXT NOT NULL,
        created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
        updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
        UNIQUE(method_key, source_link)
    )
    """,
]


FINDINGS_COLUMNS = {
    "matched_priority_apps": "TEXT NOT NULL DEFAULT '[]'",
}


class Storage:
    def __init__(self, db_path: str | Path) -> None:
        self.db_path = Path(db_path)
        self.conn = sqlite3.connect(self.db_path)
        self.conn.row_factory = sqlite3.Row
        self._initialize()

    def _initialize(self) -> None:
        for statement in SCHEMA_STATEMENTS:
            self.conn.execute(statement)
        self._ensure_columns("findings", FINDINGS_COLUMNS)
        self.conn.commit()

    def _ensure_columns(self, table: str, columns: dict[str, str]) -> None:
        existing = {
            row["name"]
            for row in self.conn.execute(f"PRAGMA table_info({table})").fetchall()
        }
        for name, definition in columns.items():
            if name not in existing:
                self.conn.execute(f"ALTER TABLE {table} ADD COLUMN {name} {definition}")

    def save(self, item: ScoredEntry) -> bool:
        return self.save_finding(
            link=item.entry.link,
            source=item.entry.source,
            title=item.entry.title,
            summary=item.entry.summary,
            published_at=item.entry.published_at,
            score=item.score,
            matched_keywords=item.matched_keywords,
            matched_phrases=item.matched_phrases,
            matched_priority_apps=item.matched_priority_apps,
        )

    def save_finding(
        self,
        *,
        link: str,
        source: str,
        title: str,
        summary: str,
        published_at: str | None,
        score: int,
        matched_keywords: list[str],
        matched_phrases: list[str],
        matched_priority_apps: list[str],
    ) -> bool:
        cursor = self.conn.execute(
            """
            INSERT OR IGNORE INTO findings (
                link, source, title, summary, published_at, score,
                matched_keywords, matched_phrases, matched_priority_apps
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                link,
                source,
                title,
                summary,
                published_at,
                score,
                json.dumps(matched_keywords, ensure_ascii=False),
                json.dumps(matched_phrases, ensure_ascii=False),
                json.dumps(matched_priority_apps, ensure_ascii=False),
            ),
        )
        self.conn.commit()
        return cursor.rowcount > 0

    def latest(self, limit: int = 20) -> list[sqlite3.Row]:
        cursor = self.conn.execute(
            """
            SELECT title, link, source, score, published_at, created_at, matched_priority_apps
            FROM findings
            ORDER BY COALESCE(published_at, created_at) DESC, score DESC
            LIMIT ?
            """,
            (limit,),
        )
        return cursor.fetchall()

    def upsert_app_baseline(self, app: dict) -> None:
        self.conn.execute(
            """
            INSERT INTO app_baselines (
                app_name, rank_by_methods, methods_count, methods_json,
                notes, source_url, baseline_date
            ) VALUES (?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(app_name) DO UPDATE SET
                rank_by_methods = excluded.rank_by_methods,
                methods_count = excluded.methods_count,
                methods_json = excluded.methods_json,
                notes = excluded.notes,
                source_url = excluded.source_url,
                baseline_date = excluded.baseline_date,
                updated_at = CURRENT_TIMESTAMP
            """,
            (
                app["app_name"],
                app["rank_by_methods"],
                app["methods_count"],
                json.dumps(app["methods"], ensure_ascii=False),
                app["notes"],
                app["source_url"],
                app["baseline_date"],
            ),
        )
        self.conn.commit()

    def save_scan_run(self, result: dict) -> int:
        cursor = self.conn.execute(
            """
            INSERT INTO scan_runs (
                app_name, version, scan_target, method_count, methods_json, summary_json
            ) VALUES (?, ?, ?, ?, ?, ?)
            ON CONFLICT(app_name, version, scan_target) DO UPDATE SET
                method_count = excluded.method_count,
                methods_json = excluded.methods_json,
                summary_json = excluded.summary_json,
                scanned_at = CURRENT_TIMESTAMP
            RETURNING id
            """,
            (
                result["app_name"],
                result["version"],
                result["scan_target"],
                len(result["methods"]),
                json.dumps(result["methods"], ensure_ascii=False),
                json.dumps(result["summary"], ensure_ascii=False),
            ),
        )
        run_id = int(cursor.fetchone()[0])
        self.conn.execute("DELETE FROM scan_hits WHERE run_id = ?", (run_id,))
        self.conn.executemany(
            """
            INSERT INTO scan_hits (run_id, method_id, file_path, line_no, snippet)
            VALUES (?, ?, ?, ?, ?)
            """,
            [
                (
                    run_id,
                    hit["method_id"],
                    hit["file_path"],
                    hit["line_no"],
                    hit["snippet"],
                )
                for hit in result["hits"]
            ],
        )
        self.conn.commit()
        return run_id

    def app_baselines(self) -> list[sqlite3.Row]:
        return self.conn.execute(
            """
            SELECT app_name, rank_by_methods, methods_count, methods_json, notes, baseline_date
            FROM app_baselines
            ORDER BY rank_by_methods ASC, app_name ASC
            """
        ).fetchall()

    def latest_scan_runs(self, limit: int = 50) -> list[sqlite3.Row]:
        return self.conn.execute(
            """
            SELECT id, app_name, version, scan_target, scanned_at, method_count, methods_json, summary_json
            FROM scan_runs
            ORDER BY scanned_at DESC, method_count DESC
            LIMIT ?
            """,
            (limit,),
        ).fetchall()

    def recent_scan_hits(self, limit: int = 200) -> list[sqlite3.Row]:
        return self.conn.execute(
            """
            SELECT h.run_id, r.app_name, r.version, h.method_id, h.file_path, h.line_no, h.snippet
            FROM scan_hits h
            JOIN scan_runs r ON r.id = h.run_id
            ORDER BY r.scanned_at DESC, r.app_name ASC, h.method_id ASC, h.file_path ASC
            LIMIT ?
            """,
            (limit,),
        ).fetchall()

    def save_news_method_candidates(self, candidates: list[dict[str, str | None]]) -> int:
        saved = 0
        for candidate in candidates:
            scanner_method_id = candidate.get("scanner_method_id")
            status = "confirmed_in_code" if scanner_method_id and self.has_scanned_method(scanner_method_id) else "news_only"
            cursor = self.conn.execute(
                """
                INSERT INTO news_methods (
                    method_key, label, description, evidence, source_link,
                    source_title, source_kind, scanner_method_id, status
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(method_key, source_link) DO UPDATE SET
                    label = excluded.label,
                    description = excluded.description,
                    evidence = excluded.evidence,
                    source_title = excluded.source_title,
                    source_kind = excluded.source_kind,
                    scanner_method_id = excluded.scanner_method_id,
                    status = excluded.status,
                    updated_at = CURRENT_TIMESTAMP
                """,
                (
                    candidate["method_key"],
                    candidate["label"],
                    candidate["description"],
                    candidate["evidence"],
                    candidate["source_link"],
                    candidate["source_title"],
                    candidate["source_kind"],
                    scanner_method_id,
                    status,
                ),
            )
            saved += cursor.rowcount
        self.conn.commit()
        return saved

    def latest_news_methods(self, limit: int = 20) -> list[sqlite3.Row]:
        return self.conn.execute(
            """
            SELECT method_key, label, description, evidence, source_link, source_title,
                   source_kind, scanner_method_id, status, created_at, updated_at
            FROM news_methods
            ORDER BY updated_at DESC, created_at DESC
            LIMIT ?
            """,
            (limit,),
        ).fetchall()

    def has_scanned_method(self, method_id: str) -> bool:
        row = self.conn.execute(
            """
            SELECT 1
            FROM scan_hits
            WHERE method_id = ?
            LIMIT 1
            """,
            (method_id,),
        ).fetchone()
        return row is not None

    def scan_report(self, app_name: str, version: str | None = None) -> dict | None:
        if version:
            run = self.conn.execute(
                """
                SELECT id, app_name, version, scan_target, scanned_at, method_count, methods_json, summary_json
                FROM scan_runs
                WHERE app_name = ? AND version = ?
                ORDER BY scanned_at DESC
                LIMIT 1
                """,
                (app_name, version),
            ).fetchone()
        else:
            run = self.conn.execute(
                """
                SELECT id, app_name, version, scan_target, scanned_at, method_count, methods_json, summary_json
                FROM scan_runs
                WHERE app_name = ?
                ORDER BY scanned_at DESC
                LIMIT 1
                """,
                (app_name,),
            ).fetchone()
        if run is None:
            return None

        baseline = self.conn.execute(
            """
            SELECT app_name, rank_by_methods, methods_count, methods_json, notes, baseline_date
            FROM app_baselines
            WHERE lower(app_name) = lower(?)
            LIMIT 1
            """,
            (app_name,),
        ).fetchone()
        history = self.conn.execute(
            """
            SELECT app_name, version, scanned_at, method_count, methods_json, summary_json
            FROM scan_runs
            WHERE app_name = ?
            ORDER BY scanned_at DESC
            LIMIT 10
            """,
            (app_name,),
        ).fetchall()
        hits = self.conn.execute(
            """
            SELECT method_id, file_path, line_no, snippet
            FROM scan_hits
            WHERE run_id = ?
            ORDER BY method_id ASC, file_path ASC, line_no ASC
            """,
            (run["id"],),
        ).fetchall()

        return {
            "run": {
                "app_name": run["app_name"],
                "version": run["version"],
                "scan_target": run["scan_target"],
                "scanned_at": run["scanned_at"],
                "method_count": run["method_count"],
                "methods": json.loads(run["methods_json"]),
                "summary": json.loads(run["summary_json"]),
            },
            "baseline": None
            if baseline is None
            else {
                "app_name": baseline["app_name"],
                "rank_by_methods": baseline["rank_by_methods"],
                "methods_count": baseline["methods_count"],
                "methods": json.loads(baseline["methods_json"]),
                "notes": baseline["notes"],
                "baseline_date": baseline["baseline_date"],
            },
            "history": [
                {
                    "app_name": row["app_name"],
                    "version": row["version"],
                    "scanned_at": row["scanned_at"],
                    "method_count": row["method_count"],
                    "methods": json.loads(row["methods_json"]),
                    "summary": json.loads(row["summary_json"]),
                }
                for row in history
            ],
            "hits": [
                {
                    "method_id": row["method_id"],
                    "file_path": row["file_path"],
                    "line_no": row["line_no"],
                    "snippet": row["snippet"],
                }
                for row in hits
            ],
        }

    def close(self) -> None:
        self.conn.close()

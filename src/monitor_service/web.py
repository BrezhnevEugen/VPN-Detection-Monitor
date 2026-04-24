from __future__ import annotations

import html
import json
import sqlite3
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse


def run_dashboard(db_path: str, host: str = "127.0.0.1", port: int = 8000) -> None:
    server = ThreadingHTTPServer((host, port), _build_handler(db_path))
    print(f"Dashboard running on http://{host}:{port}")
    server.serve_forever()


def _build_handler(db_path: str):
    db_file = str(Path(db_path).resolve())

    class DashboardHandler(BaseHTTPRequestHandler):
        def do_GET(self) -> None:  # noqa: N802
            parsed = urlparse(self.path)
            query = parse_qs(parsed.query)
            limit = _safe_int(query.get("limit", ["50"])[0], default=50, minimum=1, maximum=200)
            min_score = _safe_int(query.get("min_score", ["0"])[0], default=0, minimum=0, maximum=50)

            if parsed.path == "/":
                html_body = _render_page(db_file, limit=limit, min_score=min_score)
                self._send_html(html_body)
                return

            if parsed.path == "/api/findings":
                payload = _load_dashboard_data(db_file, limit=limit, min_score=min_score)
                self._send_json(payload)
                return

            self.send_error(404, "Not found")

        def log_message(self, format: str, *args) -> None:  # noqa: A003
            return

        def _send_html(self, body: str) -> None:
            encoded = body.encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(encoded)))
            self.end_headers()
            self.wfile.write(encoded)

        def _send_json(self, payload: dict) -> None:
            encoded = json.dumps(payload, ensure_ascii=False).encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Content-Length", str(len(encoded)))
            self.end_headers()
            self.wfile.write(encoded)

    return DashboardHandler


def _connect(db_path: str) -> sqlite3.Connection:
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    return conn


def _load_dashboard_data(db_path: str, limit: int, min_score: int) -> dict:
    with _connect(db_path) as conn:
        findings = conn.execute(
            """
            SELECT title, link, source, score, published_at, created_at,
                   matched_keywords, matched_phrases, matched_priority_apps, summary
            FROM findings
            WHERE score >= ?
            ORDER BY COALESCE(published_at, created_at) DESC, score DESC
            LIMIT ?
            """,
            (min_score, limit),
        ).fetchall()

        totals = conn.execute(
            """
            SELECT
                COUNT(*) AS total,
                COALESCE(MAX(score), 0) AS top_score,
                COUNT(DISTINCT source) AS sources
            FROM findings
            WHERE score >= ?
            """,
            (min_score,),
        ).fetchone()

        baselines = conn.execute(
            """
            SELECT app_name, rank_by_methods, methods_count, methods_json, notes, baseline_date
            FROM app_baselines
            ORDER BY rank_by_methods ASC, app_name ASC
            """
        ).fetchall()

        runs = conn.execute(
            """
            SELECT id, app_name, version, scan_target, scanned_at, method_count, methods_json, summary_json
            FROM scan_runs
            ORDER BY scanned_at DESC, method_count DESC
            LIMIT 50
            """
        ).fetchall()

        hits = conn.execute(
            """
            SELECT h.run_id, r.app_name, r.version, h.method_id, h.file_path, h.line_no, h.snippet
            FROM scan_hits h
            JOIN scan_runs r ON r.id = h.run_id
            ORDER BY r.scanned_at DESC, r.app_name ASC, h.method_id ASC, h.file_path ASC
            LIMIT 200
            """
        ).fetchall()

    return {
        "summary": {
            "total": totals["total"],
            "top_score": totals["top_score"],
            "sources": totals["sources"],
            "priority_apps": len(baselines),
            "scan_runs": len(runs),
        },
        "findings": [
            {
                "title": row["title"],
                "link": row["link"],
                "source": row["source"],
                "score": row["score"],
                "published_at": row["published_at"],
                "created_at": row["created_at"],
                "matched_keywords": json.loads(row["matched_keywords"]),
                "matched_phrases": json.loads(row["matched_phrases"]),
                "matched_priority_apps": json.loads(row["matched_priority_apps"]),
                "summary": row["summary"],
            }
            for row in findings
        ],
        "baselines": [
            {
                "app_name": row["app_name"],
                "rank_by_methods": row["rank_by_methods"],
                "methods_count": row["methods_count"],
                "methods": json.loads(row["methods_json"]),
                "notes": row["notes"],
                "baseline_date": row["baseline_date"],
            }
            for row in baselines
        ],
        "scan_runs": [
            {
                "id": row["id"],
                "app_name": row["app_name"],
                "version": row["version"],
                "scan_target": row["scan_target"],
                "scanned_at": row["scanned_at"],
                "method_count": row["method_count"],
                "methods": json.loads(row["methods_json"]),
                "summary": json.loads(row["summary_json"]),
            }
            for row in runs
        ],
        "scan_hits": [
            {
                "run_id": row["run_id"],
                "app_name": row["app_name"],
                "version": row["version"],
                "method_id": row["method_id"],
                "file_path": row["file_path"],
                "line_no": row["line_no"],
                "snippet": row["snippet"],
            }
            for row in hits
        ],
    }


def _render_page(db_path: str, limit: int, min_score: int) -> str:
    payload = _load_dashboard_data(db_path, limit=limit, min_score=min_score)
    cards = "\n".join(_render_card(item) for item in payload["findings"]) or "<p>No findings yet.</p>"
    baseline_rows = "\n".join(_render_baseline_row(item) for item in payload["baselines"]) or "<tr><td colspan='5'>No baseline data yet.</td></tr>"
    run_cards = "\n".join(_render_run_card(item) for item in payload["scan_runs"][:12]) or "<p>No scans yet.</p>"
    hit_rows = "\n".join(_render_hit_row(item) for item in payload["scan_hits"][:40]) or "<tr><td colspan='5'>No scan hits yet.</td></tr>"
    summary = payload["summary"]

    return f"""<!doctype html>
<html lang="ru">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>VPN Detection Monitor</title>
  <meta http-equiv="refresh" content="60">
  <style>
    :root {{
      --bg: #f2efe8;
      --panel: #fffdf8;
      --ink: #1e1e1b;
      --muted: #6d665d;
      --accent: #aa3a2a;
      --accent-soft: #f6d7c8;
      --border: #d9d0c3;
      --shadow: rgba(52, 39, 28, 0.08);
    }}
    * {{ box-sizing: border-box; }}
    body {{
      margin: 0;
      font-family: "Iowan Old Style", "Palatino Linotype", Georgia, serif;
      color: var(--ink);
      background:
        radial-gradient(circle at top left, rgba(170,58,42,0.08), transparent 28%),
        linear-gradient(180deg, #f7f4ee 0%, var(--bg) 100%);
    }}
    .wrap {{ max-width: 1220px; margin: 0 auto; padding: 28px 18px 42px; }}
    .hero, .panel, .card, .stat {{ background: var(--panel); border: 1px solid var(--border); border-radius: 22px; box-shadow: 0 10px 30px var(--shadow); }}
    .hero {{ padding: 28px; }}
    h1 {{ margin: 0 0 10px; font-size: clamp(2rem, 4vw, 3.8rem); line-height: 0.95; max-width: 12ch; }}
    .lede {{ margin: 0; max-width: 72ch; color: var(--muted); font-size: 1.02rem; }}
    .stats {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(150px, 1fr)); gap: 12px; margin-top: 18px; }}
    .stat {{ padding: 16px 18px; }}
    .stat strong {{ display:block; font-size: 1.7rem; }}
    .stat span {{ color: var(--muted); font-size: .95rem; }}
    .controls {{ display:flex; flex-wrap:wrap; gap:14px; margin-top:18px; }}
    label {{ display:grid; gap:6px; color: var(--muted); font-size:.92rem; }}
    input {{ width:120px; padding:10px 12px; border-radius:10px; border:1px solid var(--border); }}
    button {{ border:0; border-radius:999px; padding:11px 18px; background: var(--accent); color: white; cursor:pointer; }}
    .grid {{ display:grid; grid-template-columns: 1.2fr .8fr; gap:18px; margin-top:18px; }}
    .stack {{ display:grid; gap:18px; }}
    .panel {{ padding:18px; overflow:hidden; }}
    .panel h2 {{ margin:0 0 10px; font-size:1.4rem; }}
    .panel p.meta {{ margin:0 0 14px; color:var(--muted); }}
    .list {{ display:grid; gap:14px; }}
    .card {{ padding:16px; }}
    .eyebrow {{ display:flex; justify-content:space-between; gap:12px; color:var(--muted); font-size:.9rem; margin-bottom:8px; }}
    .badge {{ display:inline-flex; align-items:center; padding:5px 9px; border-radius:999px; background: var(--accent-soft); color: var(--accent); font-weight:700; }}
    .card h3 {{ margin:0 0 8px; font-size:1.2rem; line-height:1.15; }}
    .card a {{ color:inherit; text-decoration-color: rgba(170,58,42,0.35); }}
    .summary {{ color:var(--muted); margin:0 0 12px; line-height:1.45; }}
    .tags {{ display:flex; flex-wrap:wrap; gap:8px; }}
    .tags span {{ padding:6px 10px; border-radius:999px; background:#f3eee6; color:#51493f; font-size:.86rem; }}
    table {{ width:100%; border-collapse: collapse; font-size:.94rem; }}
    th, td {{ text-align:left; padding:10px 8px; border-bottom:1px solid var(--border); vertical-align: top; }}
    th {{ color: var(--muted); font-weight:600; }}
    .mono {{ font-family: ui-monospace, SFMono-Regular, Menlo, monospace; font-size:.87rem; word-break: break-all; }}
    @media (max-width: 980px) {{ .grid {{ grid-template-columns: 1fr; }} }}
    @media (max-width: 640px) {{
      .wrap {{ padding:16px 12px 28px; }}
      .hero, .panel, .card {{ border-radius:18px; }}
      input {{ width:100%; }}
    }}
  </style>
</head>
<body>
  <main class="wrap">
    <section class="hero">
      <h1>VPN Detection Monitor</h1>
      <p class="lede">Локальная витрина для приоритетного мониторинга приложений из рейтинга статьи и для статического сканирования декомпилированных APK-артефактов. Здесь видно базовую таблицу из статьи, свежие новости по приложениям и динамику найденных методов по версиям.</p>
      <div class="stats">
        <div class="stat"><strong>{summary["total"]}</strong><span>News findings</span></div>
        <div class="stat"><strong>{summary["top_score"]}</strong><span>Top relevance score</span></div>
        <div class="stat"><strong>{summary["sources"]}</strong><span>News sources</span></div>
        <div class="stat"><strong>{summary["priority_apps"]}</strong><span>Tracked apps</span></div>
        <div class="stat"><strong>{summary["scan_runs"]}</strong><span>Saved scans</span></div>
      </div>
      <form class="controls" method="get" action="/">
        <label>Minimum score<input type="number" name="min_score" value="{min_score}" min="0" max="50"></label>
        <label>Rows<input type="number" name="limit" value="{limit}" min="1" max="200"></label>
        <button type="submit">Update View</button>
      </form>
    </section>

    <section class="grid">
      <div class="stack">
        <section class="panel">
          <h2>Priority News</h2>
          <p class="meta">Новости из лент, где упомянуты приоритетные приложения или соседние сигналы по теме.</p>
          <div class="list">{cards}</div>
        </section>
        <section class="panel">
          <h2>Baseline From Article</h2>
          <p class="meta">Базовая точка из статьи на Хабре. `baseline_date` зафиксирован как `2026-04-01` по формулировке “начало апреля 2026”.</p>
          <table>
            <thead><tr><th>#</th><th>App</th><th>Methods</th><th>Signatures</th><th>Notes</th></tr></thead>
            <tbody>{baseline_rows}</tbody>
          </table>
        </section>
      </div>
      <div class="stack">
        <section class="panel">
          <h2>Scan Dynamics</h2>
          <p class="meta">Каждый запуск сканера сохраняет версию, путь, число методов и набор совпадений. Это и есть основа для динамики по релизам.</p>
          <div class="list">{run_cards}</div>
        </section>
        <section class="panel">
          <h2>Where Found</h2>
          <p class="meta">Последние срабатывания с точным файлом и строкой, чтобы было видно где именно обнаружен метод.</p>
          <table>
            <thead><tr><th>App</th><th>Version</th><th>Method</th><th>File</th><th>Snippet</th></tr></thead>
            <tbody>{hit_rows}</tbody>
          </table>
        </section>
      </div>
    </section>
  </main>
</body>
</html>"""


def _render_card(item: dict) -> str:
    tags = item["matched_priority_apps"] + item["matched_phrases"] + item["matched_keywords"]
    tags_html = "".join(f"<span>{html.escape(tag)}</span>" for tag in tags[:12])
    published = html.escape(item["published_at"] or item["created_at"] or "n/a")
    source = html.escape(item["source"])
    title = html.escape(item["title"])
    summary = html.escape((item["summary"] or "").strip())
    link = html.escape(item["link"], quote=True)
    return f"""
    <article class="card">
      <div class="eyebrow"><span>{source}</span><span class="badge">score {item["score"]}</span></div>
      <h3><a href="{link}" target="_blank" rel="noreferrer">{title}</a></h3>
      <p class="summary">{summary}</p>
      <div class="tags">{tags_html}</div>
      <div class="eyebrow" style="margin-top:10px"><span>Published: {published}</span></div>
    </article>"""


def _render_baseline_row(item: dict) -> str:
    methods = ", ".join(item["methods"])
    return (
        f"<tr><td>{item['rank_by_methods']}</td>"
        f"<td>{html.escape(item['app_name'])}</td>"
        f"<td>{item['methods_count']}</td>"
        f"<td>{html.escape(methods)}</td>"
        f"<td>{html.escape(item['notes'])}</td></tr>"
    )


def _render_run_card(item: dict) -> str:
    methods = "".join(f"<span>{html.escape(method)}</span>" for method in item["methods"])
    target = html.escape(item["scan_target"])
    scanned_at = html.escape(item["scanned_at"])
    files_scanned = item["summary"].get("files_scanned", 0)
    hits_count = item["summary"].get("hits_count", 0)
    return f"""
    <article class="card">
      <div class="eyebrow"><span>{html.escape(item["app_name"])} {html.escape(item["version"])}</span><span class="badge">{item["method_count"]} methods</span></div>
      <p class="summary">Scanned: <span class="mono">{target}</span></p>
      <div class="tags">{methods}</div>
      <div class="eyebrow" style="margin-top:10px"><span>{files_scanned} files</span><span>{hits_count} hits</span><span>{scanned_at}</span></div>
    </article>"""


def _render_hit_row(item: dict) -> str:
    file_part = f"{html.escape(item['file_path'])}:{item['line_no'] or '?'}"
    return (
        f"<tr><td>{html.escape(item['app_name'])}</td>"
        f"<td>{html.escape(item['version'])}</td>"
        f"<td>{html.escape(item['method_id'])}</td>"
        f"<td class='mono'>{file_part}</td>"
        f"<td class='mono'>{html.escape(item['snippet'])}</td></tr>"
    )


def _safe_int(raw: str, default: int, minimum: int, maximum: int) -> int:
    try:
        value = int(raw)
    except ValueError:
        return default
    return max(minimum, min(maximum, value))

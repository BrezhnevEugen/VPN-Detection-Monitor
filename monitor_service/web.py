from __future__ import annotations

import cgi
import html
import json
import sqlite3
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlencode, urlparse

from monitor_service.scanner import infer_app_metadata, prepare_scan_target, scan_path
from monitor_service.storage import Storage


MAX_UPLOAD_BYTES = 200 * 1024 * 1024
LEGACY_METHOD_DETAILS = {
    "tun0": {"label": "Tun interface probe", "category": "interface-probe", "severity": "high"},
    "transport_vpn": {"label": "Android VPN transport check", "category": "network-api", "severity": "high"},
    "proc_net_tcp": {"label": "Low-level proc/net socket probe", "category": "filesystem-probe", "severity": "high"},
    "vpn_flag_to_server": {"label": "VPN flag sent to backend or analytics", "category": "telemetry", "severity": "critical"},
    "proxy": {"label": "Proxy or SOCKS detection", "category": "proxy-check", "severity": "medium"},
    "tor": {"label": "Tor or Orbot signature", "category": "anonymity-check", "severity": "medium"},
}

def run_dashboard(db_path: str, host: str = "127.0.0.1", port: int = 8000) -> None:
    server = ThreadingHTTPServer((host, port), _build_handler(db_path))
    print(f"Dashboard running on http://{host}:{port}")
    server.serve_forever()


def _build_handler(db_path: str):
    db_file = str(Path(db_path).resolve())
    uploads_root = Path(db_file).resolve().parent / "uploads"
    archives_root = uploads_root / "archives"
    extracted_root = uploads_root / "extracted"
    archives_root.mkdir(parents=True, exist_ok=True)
    extracted_root.mkdir(parents=True, exist_ok=True)

    class DashboardHandler(BaseHTTPRequestHandler):
        def do_GET(self) -> None:  # noqa: N802
            parsed = urlparse(self.path)
            query = parse_qs(parsed.query)
            limit = _safe_int(query.get("limit", ["50"])[0], default=50, minimum=1, maximum=200)
            min_score = _safe_int(query.get("min_score", ["0"])[0], default=0, minimum=0, maximum=50)
            flash = {
                "level": query.get("scan_status", [""])[0],
                "message": query.get("scan_message", [""])[0],
            }

            if parsed.path == "/":
                html_body = _render_page(db_file, limit=limit, min_score=min_score, flash=flash)
                self._send_html(html_body)
                return

            if parsed.path == "/api/findings":
                payload = _load_dashboard_data(db_file, limit=limit, min_score=min_score)
                self._send_json(payload)
                return

            if parsed.path == "/report":
                app_name = (query.get("app", [""])[0] or "").strip()
                version = (query.get("version", [""])[0] or "").strip() or None
                if not app_name:
                    self.send_error(400, "Missing app parameter")
                    return
                storage = Storage(db_file)
                try:
                    report = storage.scan_report(app_name, version=version)
                finally:
                    storage.close()
                if report is None:
                    self.send_error(404, "Report not found")
                    return
                body = _render_report_markdown(report)
                encoded = body.encode("utf-8")
                filename = f"{_slugify(app_name)}-{_slugify(version or report['run']['version'])}.md"
                self.send_response(200)
                self.send_header("Content-Type", "text/markdown; charset=utf-8")
                self.send_header("Content-Disposition", f'attachment; filename="{filename}"')
                self.send_header("Content-Length", str(len(encoded)))
                self.end_headers()
                self.wfile.write(encoded)
                return

            self.send_error(404, "Not found")

        def do_POST(self) -> None:  # noqa: N802
            if self.path != "/scan-upload":
                self.send_error(404, "Not found")
                return

            try:
                self._handle_scan_upload()
            except Exception as exc:  # noqa: BLE001
                self._redirect_with_status("error", str(exc))

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

        def _handle_scan_upload(self) -> None:
            content_length = int(self.headers.get("Content-Length", "0") or "0")
            if content_length > MAX_UPLOAD_BYTES:
                raise ValueError("APK is too large. Limit is 200 MB.")

            form = cgi.FieldStorage(
                fp=self.rfile,
                headers=self.headers,
                environ={
                    "REQUEST_METHOD": "POST",
                    "CONTENT_TYPE": self.headers.get("Content-Type", ""),
                    "CONTENT_LENGTH": str(content_length),
                },
            )

            upload = form["bundle"] if "bundle" in form else None

            if upload is None or not getattr(upload, "filename", ""):
                raise ValueError("Please attach an APK file.")

            filename = Path(upload.filename).name
            if not _is_allowed_archive(filename):
                raise ValueError("Unsupported file type. Allowed: .apk.")
            archive_path = archives_root / filename
            archive_path.write_bytes(upload.file.read())

            extracted = prepare_scan_target(archive_path, extracted_root)
            metadata = infer_app_metadata(extracted, upload_name=filename)
            result = scan_path(extracted, app_name=metadata["app_name"], version=metadata["version"])
            storage = Storage(db_file)
            try:
                run_id = storage.save_scan_run(result)
            finally:
                storage.close()

            self._redirect_with_status(
                "success",
                f"Scan saved: {metadata['app_name']} {metadata['version']}, methods={len(result['methods'])}, run_id={run_id}",
            )

        def _redirect_with_status(self, level: str, message: str) -> None:
            query = urlencode({"scan_status": level, "scan_message": message})
            self.send_response(303)
            self.send_header("Location", f"/?{query}")
            self.end_headers()

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


def _render_page(db_path: str, limit: int, min_score: int, flash: dict[str, str] | None = None) -> str:
    payload = _load_dashboard_data(db_path, limit=limit, min_score=min_score)
    cards = "\n".join(_render_card(item) for item in payload["findings"]) or "<p>No findings yet.</p>"
    baseline_rows = "\n".join(_render_baseline_row(item) for item in payload["baselines"]) or "<tr><td colspan='5'>No baseline data yet.</td></tr>"
    run_cards = "\n".join(_render_run_card(item) for item in payload["scan_runs"][:12]) or "<p>No scans yet.</p>"
    hit_rows = "\n".join(_render_hit_row(item) for item in payload["scan_hits"][:40]) or "<tr><td colspan='5'>No scan hits yet.</td></tr>"
    summary = payload["summary"]
    flash_html = _render_flash(flash or {})

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
    input {{ width:120px; padding:10px 12px; border-radius:10px; border:1px solid var(--border); background:#fff; }}
    input[type="file"] {{ width:100%; padding:10px 0; border:0; background:transparent; }}
    button {{ border:0; border-radius:999px; padding:11px 18px; background: var(--accent); color: white; cursor:pointer; }}
    .grid {{ display:grid; grid-template-columns: 1.2fr .8fr; gap:18px; margin-top:18px; }}
    .stack {{ display:grid; gap:18px; }}
    .panel {{ padding:18px; overflow:hidden; }}
    .panel h2 {{ margin:0 0 10px; font-size:1.4rem; }}
    .panel p.meta {{ margin:0 0 14px; color:var(--muted); }}
    .flash {{ margin-top:18px; padding:14px 16px; border-radius:16px; border:1px solid var(--border); }}
    .flash.success {{ background:#eef6eb; color:#234326; border-color:#c7dec7; }}
    .flash.error {{ background:#fff0eb; color:#7b2d1f; border-color:#f0c9bd; }}
    .upload-panel {{ margin-top:18px; padding:18px; border-radius:20px; background:linear-gradient(180deg, #fffdfa, #f7f1e8); border:1px solid var(--border); }}
    .upload-panel h2 {{ margin:0 0 6px; font-size:1.25rem; }}
    .upload-panel p {{ margin:0; color:var(--muted); }}
    .upload-form {{ display:grid; grid-template-columns: 1.1fr 0.9fr 1.6fr auto; gap:16px; align-items:end; margin-top:16px; }}
    .upload-field {{ display:grid; gap:8px; }}
    .upload-field label {{ gap:4px; font-weight:600; color:var(--ink); }}
    .upload-field input[type="text"] {{ width:100%; min-height:52px; border-radius:16px; padding:14px 16px; }}
    .file-shell {{ display:flex; align-items:center; gap:12px; min-height:52px; padding:10px 14px; border:1px dashed #bfae97; border-radius:16px; background:#fff; }}
    .file-shell input[type="file"] {{ padding:0; }}
    .file-meta {{ margin-top:6px; color:var(--muted); font-size:.85rem; }}
    .upload-errors {{ display:none; margin-top:12px; padding:12px 14px; border-radius:14px; background:#fff0eb; border:1px solid #f0c9bd; color:#7b2d1f; }}
    .upload-errors.active {{ display:block; }}
    .upload-status {{ display:none; margin-top:12px; padding:12px 14px; border-radius:14px; background:#f3eee6; border:1px solid var(--border); color:#51493f; }}
    .upload-status.active {{ display:block; }}
    .upload-status strong {{ display:block; margin-bottom:6px; color:var(--ink); }}
    .upload-status-track {{ display:flex; flex-wrap:wrap; gap:8px; }}
    .upload-status-step {{ padding:6px 10px; border-radius:999px; background:#e7dfd3; color:#746b60; font-size:.86rem; }}
    .upload-status-step.active {{ background:var(--accent-soft); color:var(--accent); font-weight:700; }}
    .upload-status-step.done {{ background:#e4efe6; color:#355b3d; }}
    .upload-submit {{ min-height:52px; padding:14px 20px; font-weight:700; white-space:nowrap; }}
    .upload-submit[disabled] {{ opacity:0.72; cursor:progress; }}
    .list {{ display:grid; gap:14px; }}
    .card {{ padding:16px; }}
    .eyebrow {{ display:flex; justify-content:space-between; gap:12px; color:var(--muted); font-size:.9rem; margin-bottom:8px; }}
    .badge {{ display:inline-flex; align-items:center; padding:5px 9px; border-radius:999px; background: var(--accent-soft); color: var(--accent); font-weight:700; }}
    .card h3 {{ margin:0 0 8px; font-size:1.2rem; line-height:1.15; }}
    .card a {{ color:inherit; text-decoration-color: rgba(170,58,42,0.35); }}
    .summary {{ color:var(--muted); margin:0 0 12px; line-height:1.45; }}
    .tags {{ display:flex; flex-wrap:wrap; gap:8px; }}
    .tags span {{ padding:6px 10px; border-radius:999px; background:#f3eee6; color:#51493f; font-size:.86rem; }}
    .actions {{ display:flex; justify-content:flex-end; margin-top:12px; }}
    .actions a {{ display:inline-flex; align-items:center; padding:8px 12px; border-radius:999px; background:#f1ece2; text-decoration:none; }}
    table {{ width:100%; border-collapse: collapse; font-size:.94rem; }}
    th, td {{ text-align:left; padding:10px 8px; border-bottom:1px solid var(--border); vertical-align: top; }}
    th {{ color: var(--muted); font-weight:600; }}
    .mono {{ font-family: ui-monospace, SFMono-Regular, Menlo, monospace; font-size:.87rem; word-break: break-all; }}
    @media (max-width: 980px) {{ .grid {{ grid-template-columns: 1fr; }} .upload-form {{ grid-template-columns: 1fr 1fr; }} }}
    @media (max-width: 640px) {{
      .wrap {{ padding:16px 12px 28px; }}
      .hero, .panel, .card {{ border-radius:18px; }}
      input {{ width:100%; }}
      .upload-form {{ grid-template-columns: 1fr; }}
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
      {flash_html}
      <section class="upload-panel">
        <h2>Upload APK For Scan</h2>
        <form class="upload-form" id="scan-upload-form" method="post" action="/scan-upload" enctype="multipart/form-data" novalidate>
          <div class="upload-field">
            <label for="bundle">APK file</label>
            <div class="file-shell">
              <input id="bundle" type="file" name="bundle" accept=".apk" required>
            </div>
            <div class="file-meta">Название приложения и версия извлекаются автоматически из APK.</div>
          </div>
          <button class="upload-submit" type="submit">Upload And Scan</button>
        </form>
        <div id="upload-errors" class="upload-errors" aria-live="polite"></div>
        <div id="upload-status" class="upload-status" aria-live="polite"></div>
      </section>
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
  <script>
    (() => {{
      const form = document.getElementById('scan-upload-form');
      if (!form) return;
      const bundleInput = document.getElementById('bundle');
      const errorsBox = document.getElementById('upload-errors');
      const statusBox = document.getElementById('upload-status');
      const submitButton = form.querySelector('button[type="submit"]');
      const allowed = ['.apk'];

      function showErrors(messages) {{
        if (!messages.length) {{
          errorsBox.textContent = '';
          errorsBox.classList.remove('active');
          return;
        }}
        errorsBox.innerHTML = messages.map((msg) => `<div>${{msg}}</div>`).join('');
        errorsBox.classList.add('active');
      }}

      function renderStatus(activeIndex, doneIndex) {{
        const steps = ['Uploading', 'Decoding', 'Scanning'];
        const track = steps.map((label, index) => {{
          let className = 'upload-status-step';
          if (index < doneIndex) className += ' done';
          else if (index === activeIndex) className += ' active';
          return `<span class="${{className}}">${{label}}</span>`;
        }}).join('');
        statusBox.innerHTML = `<strong>Processing APK</strong><div class="upload-status-track">${{track}}</div>`;
        statusBox.classList.add('active');
      }}

      function validExtension(name) {{
        const lower = name.toLowerCase();
        return allowed.some((ext) => lower.endsWith(ext));
      }}

      form.addEventListener('submit', (event) => {{
        const messages = [];
        if (!bundleInput.files || !bundleInput.files.length) {{
          messages.push('Прикрепите APK-файл.');
        }} else if (!validExtension(bundleInput.files[0].name)) {{
          messages.push('Недопустимое расширение файла. Разрешено: .apk.');
        }}
        if (messages.length) {{
          event.preventDefault();
          showErrors(messages);
        }} else {{
          showErrors([]);
          renderStatus(0, 0);
          if (submitButton) {{
            submitButton.disabled = true;
            submitButton.textContent = 'Processing...';
          }}
          window.setTimeout(() => renderStatus(1, 1), 450);
          window.setTimeout(() => renderStatus(2, 2), 1400);
        }}
      }});
    }})();
  </script>
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
    categories = item["summary"].get("categories", {})
    severities = item["summary"].get("severity_counts", {})
    extra_tags = "".join(
        f"<span>{html.escape(name)}:{value}</span>" for name, value in {**categories, **severities}.items()
    )
    target = html.escape(item["scan_target"])
    scanned_at = html.escape(item["scanned_at"])
    files_scanned = item["summary"].get("files_scanned", 0)
    hits_count = item["summary"].get("hits_count", 0)
    report_query = urlencode({"app": item["app_name"], "version": item["version"]})
    return f"""
    <article class="card">
      <div class="eyebrow"><span>{html.escape(item["app_name"])} {html.escape(item["version"])}</span><span class="badge">{item["method_count"]} methods</span></div>
      <p class="summary">Scanned: <span class="mono">{target}</span></p>
      <div class="tags">{methods}</div>
      <div class="tags" style="margin-top:8px">{extra_tags}</div>
      <div class="eyebrow" style="margin-top:10px"><span>{files_scanned} files</span><span>{hits_count} hits</span><span>{scanned_at}</span></div>
      <div class="actions"><a href="/report?{report_query}">Export report</a></div>
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


def _render_flash(flash: dict[str, str]) -> str:
    level = flash.get("level", "")
    message = flash.get("message", "")
    if not level or not message:
        return ""
    if level not in {"success", "error"}:
        level = "success"
    return f'<div class="flash {level}">{html.escape(message)}</div>'


def _render_report_markdown(report: dict) -> str:
    run = report["run"]
    baseline = report["baseline"]
    history = report["history"]
    hits = report["hits"]
    summary = run["summary"]
    lines = [
        f"# Scan report: {run['app_name']} {run['version']}",
        "",
        f"- Scanned at: {run['scanned_at']}",
        f"- Scan target: `{run['scan_target']}`",
        f"- Methods found: {run['method_count']}",
        f"- Files scanned: {summary.get('files_scanned', 0)}",
        f"- Hits: {summary.get('hits_count', 0)}",
        "",
        "## Methods",
    ]
    for method in run["methods"]:
        details = summary.get("method_details", {}).get(method, LEGACY_METHOD_DETAILS.get(method, {}))
        label = details.get("label", method)
        category = details.get("category", "n/a")
        severity = details.get("severity", "n/a")
        lines.append(f"- `{method}`: {label} (`category={category}`, `severity={severity}`)")

    if baseline is not None:
        lines.extend(
            [
                "",
                "## Baseline comparison",
                f"- Baseline date: {baseline['baseline_date']}",
                f"- Baseline methods count: {baseline['methods_count']}",
                f"- Baseline methods: {', '.join(baseline['methods'])}",
                f"- Notes: {baseline['notes']}",
            ]
        )

    lines.extend(["", "## Recent history"])
    for item in history:
        lines.append(
            f"- {item['version']} at {item['scanned_at']}: {item['method_count']} methods ({', '.join(item['methods'])})"
        )

    lines.extend(["", "## Hits"])
    for hit in hits:
        location = f"{hit['file_path']}:{hit['line_no'] or '?'}"
        lines.append(f"- `{hit['method_id']}` at `{location}` -> `{hit['snippet']}`")
    lines.append("")
    return "\n".join(lines)


def _slugify(value: str) -> str:
    slug = "".join(ch.lower() if ch.isalnum() else "-" for ch in value)
    return "-".join(part for part in slug.split("-") if part) or "report"


def _is_allowed_archive(filename: str) -> bool:
    lower = filename.lower()
    return lower.endswith(".apk")


def _safe_int(raw: str, default: int, minimum: int, maximum: int) -> int:
    try:
        value = int(raw)
    except ValueError:
        return default
    return max(minimum, min(maximum, value))

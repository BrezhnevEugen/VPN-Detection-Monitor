from __future__ import annotations

import argparse
import logging

from monitor_service.config import MonitorConfig
from monitor_service.scanner import load_app_profiles, scan_path
from monitor_service.service import MonitorService
from monitor_service.storage import Storage
from monitor_service.web import run_dashboard


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Monitor tech-state signals from RSS feeds")
    parser.add_argument("--config", default="config/topics.json", help="Path to JSON config")
    parser.add_argument("--db", default="monitor.db", help="Path to SQLite database")
    parser.add_argument("--log-level", default="INFO", help="Logging level")

    subparsers = parser.add_subparsers(dest="command", required=True)

    subparsers.add_parser("run-once", help="Process feeds once")

    watch = subparsers.add_parser("watch", help="Run continuously")
    watch.add_argument("--interval", type=int, default=1800, help="Polling interval in seconds")

    show = subparsers.add_parser("show-latest", help="Show latest findings")
    show.add_argument("--limit", type=int, default=20, help="Rows to print")

    seed = subparsers.add_parser("seed-baseline", help="Load app baseline data into SQLite")
    seed.add_argument("--profiles", default="config/vpn_app_profiles.json", help="Path to app profiles JSON")

    scan = subparsers.add_parser("scan-dir", help="Scan decompiled app directory for VPN detection patterns")
    scan.add_argument("--app", required=True, help="Display name of the app")
    scan.add_argument("--version", required=True, help="Version label for dynamics")
    scan.add_argument("--path", required=True, help="Directory or file to scan")

    dashboard = subparsers.add_parser("dashboard", help="Run local web dashboard")
    dashboard.add_argument("--host", default="127.0.0.1", help="Bind host")
    dashboard.add_argument("--port", type=int, default=8000, help="Bind port")

    return parser


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()

    logging.basicConfig(
        level=getattr(logging, args.log_level.upper(), logging.INFO),
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )

    config = MonitorConfig.load(args.config)
    storage = Storage(args.db)
    service = MonitorService(config, storage)

    try:
        if args.command == "run-once":
            stats = service.run_once()
            print(stats)
            return 0

        if args.command == "watch":
            service.watch(args.interval)
            return 0

        if args.command == "show-latest":
            for row in storage.latest(args.limit):
                published = row["published_at"] or "n/a"
                print(f"[{row['score']:>2}] {row['title']}")
                print(f"     {row['link']}")
                print(f"     source={row['source']} published={published}")
            return 0

        if args.command == "seed-baseline":
            payload = load_app_profiles(args.profiles)
            for app in payload["apps"]:
                storage.upsert_app_baseline(
                    {
                        **app,
                        "source_url": payload["source_url"],
                        "baseline_date": payload["baseline_date"],
                    }
                )
            print({"seeded": len(payload["apps"])})
            return 0

        if args.command == "scan-dir":
            result = scan_path(args.path, app_name=args.app, version=args.version)
            run_id = storage.save_scan_run(result)
            print(
                {
                    "run_id": run_id,
                    "app": args.app,
                    "version": args.version,
                    "methods": result["methods"],
                    "hits": len(result["hits"]),
                }
            )
            return 0

        if args.command == "dashboard":
            storage.close()
            run_dashboard(args.db, host=args.host, port=args.port)
            return 0

        parser.error("Unknown command")
        return 2
    finally:
        storage.close()


if __name__ == "__main__":
    raise SystemExit(main())

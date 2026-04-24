from __future__ import annotations

import json
import re
from pathlib import Path


SCAN_FILE_SUFFIXES = {
    ".smali",
    ".java",
    ".kt",
    ".xml",
    ".txt",
    ".json",
    ".js",
    ".properties",
    ".gradle",
}


METHOD_PATTERNS = {
    "transport_vpn": [
        r"TRANSPORT_VPN",
        r"hasTransport\s*\(\s*NetworkCapabilities\.TRANSPORT_VPN",
        r"NetworkCapabilities[^\\n]{0,80}TRANSPORT_VPN",
    ],
    "tun0": [
        r"\btun0\b",
        r"\bvpn0\b",
        r"/sys/class/net/tun0",
    ],
    "proc_net_tcp": [
        r"/proc/net/tcp",
        r"/proc/net/tcp6",
        r"proc/net/tcp:27042",
    ],
    "proxy": [
        r"ProxyInfo",
        r"java\.net\.Proxy",
        r"http\.proxyHost",
        r"socksProxyHost",
        r"isProxySet",
    ],
    "tor": [
        r"\bTor\b",
        r"Orbot",
        r"9050",
        r"9150",
    ],
    "vpn_flag_to_server": [
        r"is_vpn",
        r"vpn_enabled",
        r"setVpn",
        r"VpnStatusResponse",
        r"isVpnConnected",
    ],
}


def scan_path(scan_target: str | Path, app_name: str, version: str) -> dict:
    base = Path(scan_target).resolve()
    if not base.exists():
        raise FileNotFoundError(f"Scan target does not exist: {base}")

    hits: list[dict] = []
    found_methods: set[str] = set()
    files_scanned = 0

    for path in _iter_candidate_files(base):
        files_scanned += 1
        try:
            text = path.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue

        lines = text.splitlines()
        for method_id, patterns in METHOD_PATTERNS.items():
            for pattern in patterns:
                regex = re.compile(pattern, flags=re.IGNORECASE)
                for index, line in enumerate(lines, start=1):
                    if not regex.search(line):
                        continue
                    found_methods.add(method_id)
                    hits.append(
                        {
                            "method_id": method_id,
                            "file_path": str(path.relative_to(base)),
                            "line_no": index,
                            "snippet": line.strip()[:220],
                        }
                    )
                    break
                else:
                    continue
                break

    return {
        "app_name": app_name,
        "version": version,
        "scan_target": str(base),
        "methods": sorted(found_methods),
        "hits": hits,
        "summary": {
            "files_scanned": files_scanned,
            "hits_count": len(hits),
        },
    }


def load_app_profiles(path: str | Path) -> dict:
    return json.loads(Path(path).read_text(encoding="utf-8"))


def _iter_candidate_files(base: Path):
    if base.is_file():
        yield base
        return
    for path in base.rglob("*"):
        if not path.is_file():
            continue
        if path.suffix.lower() in SCAN_FILE_SUFFIXES:
            yield path

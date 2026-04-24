from __future__ import annotations

import json
import re
import shutil
import subprocess
import tarfile
import time
import zipfile
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


METHOD_DEFINITIONS = {
    "transport_vpn": {
        "label": "Android VPN transport check",
        "category": "network-api",
        "severity": "high",
        "patterns": [
            r"TRANSPORT_VPN",
            r"hasTransport\s*\(\s*NetworkCapabilities\.TRANSPORT_VPN",
            r"NetworkCapabilities[^\\n]{0,80}TRANSPORT_VPN",
            r"ConnectivityManager[^\\n]{0,80}getNetworkCapabilities",
        ],
    },
    "vpn_service_probe": {
        "label": "VpnService or VPN capability probe",
        "category": "network-api",
        "severity": "high",
        "patterns": [
            r"\bVpnService\b",
            r"prepareVpn",
            r"isVpnActive",
            r"getActiveNetwork",
            r"activeNetworkInfo",
        ],
    },
    "tun_interface": {
        "label": "Tun/WireGuard/OpenVPN interface probe",
        "category": "interface-probe",
        "severity": "high",
        "patterns": [
            r"\btun0\b",
            r"\bvpn0\b",
            r"\butun[0-9]*\b",
            r"\bppp0\b",
            r"\bipsec[0-9]*\b",
            r"\bwg[0-9]*\b",
            r"wireguard",
            r"openvpn",
            r"/sys/class/net/tun0",
            r"NetworkInterface\.getNetworkInterfaces",
        ],
    },
    "proc_net_tcp": {
        "label": "Low-level proc/net socket probe",
        "category": "filesystem-probe",
        "severity": "high",
        "patterns": [
            r"/proc/net/tcp",
            r"/proc/net/tcp6",
            r"/proc/net/route",
            r"proc/net/tcp:27042",
            r"proc/net",
        ],
    },
    "proxy": {
        "label": "Proxy or SOCKS detection",
        "category": "proxy-check",
        "severity": "medium",
        "patterns": [
            r"ProxyInfo",
            r"java\.net\.Proxy",
            r"http\.proxyHost",
            r"https\.proxyHost",
            r"socksProxyHost",
            r"isProxySet",
            r"getDefaultProxy",
            r"ProxySelector",
        ],
    },
    "tor": {
        "label": "Tor or Orbot signature",
        "category": "anonymity-check",
        "severity": "medium",
        "patterns": [
            r"\bTor\b",
            r"Orbot",
            r"9050",
            r"9150",
        ],
    },
    "vpn_flag_to_server": {
        "label": "VPN flag sent to backend or analytics",
        "category": "telemetry",
        "severity": "critical",
        "patterns": [
            r"is_vpn",
            r"vpn_enabled",
            r"setVpn",
            r"VpnStatusResponse",
            r"isVpnConnected",
            r"vpnStatus",
            r"vpnDetected",
            r"vpn_state",
            r"proxy_enabled",
        ],
    },
    "dns_or_ip_telemetry": {
        "label": "DNS/IP telemetry tied to routing checks",
        "category": "telemetry",
        "severity": "medium",
        "patterns": [
            r"getByName",
            r"getHostAddress",
            r"publicIp",
            r"geoip",
            r"countryCode",
            r"exitNode",
        ],
    },
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
        for method_id, metadata in METHOD_DEFINITIONS.items():
            for pattern in metadata["patterns"]:
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
            "categories": _count_categories(found_methods),
            "severity_counts": _count_severities(found_methods),
            "method_details": {
                method_id: {
                    "label": METHOD_DEFINITIONS[method_id]["label"],
                    "category": METHOD_DEFINITIONS[method_id]["category"],
                    "severity": METHOD_DEFINITIONS[method_id]["severity"],
                }
                for method_id in sorted(found_methods)
            },
        },
    }


def load_app_profiles(path: str | Path) -> dict:
    return json.loads(Path(path).read_text(encoding="utf-8"))


def unpack_archive(archive_path: str | Path, extract_root: str | Path) -> Path:
    source = Path(archive_path).resolve()
    target_root = Path(extract_root).resolve()
    target_root.mkdir(parents=True, exist_ok=True)
    target = target_root / f"{source.stem}-{int(time.time())}"
    target.mkdir(parents=True, exist_ok=True)

    suffixes = source.suffixes
    if suffixes[-1:] == [".zip"]:
        with zipfile.ZipFile(source) as bundle:
            _extract_zip_safe(bundle, target)
        return target

    if suffixes[-2:] == [".tar", ".gz"] or suffixes[-1:] in ([".tgz"], [".tar"]):
        with tarfile.open(source) as bundle:
            _extract_tar_safe(bundle, target)
        return target

    raise ValueError(f"Unsupported archive format: {source.name}")


def prepare_scan_target(upload_path: str | Path, work_root: str | Path) -> Path:
    source = Path(upload_path).resolve()
    if source.suffix.lower() == ".apk":
        return decode_apk(source, work_root)
    return unpack_archive(source, work_root)


def decode_apk(apk_path: str | Path, output_root: str | Path) -> Path:
    apk = Path(apk_path).resolve()
    output_base = Path(output_root).resolve()
    output_base.mkdir(parents=True, exist_ok=True)
    target = output_base / f"{apk.stem}-decoded-{int(time.time())}"

    apktool = shutil.which("apktool")
    if not apktool:
        raise ValueError("APK upload requires apktool on the server. Please install it first.")

    try:
        subprocess.run(
            [apktool, "d", "-f", "-o", str(target), str(apk)],
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
    except subprocess.CalledProcessError as exc:
        stderr = (exc.stderr or "").strip()
        raise ValueError(f"APK decode failed: {stderr or 'apktool error'}") from exc
    return target


def _iter_candidate_files(base: Path):
    if base.is_file():
        yield base
        return
    for path in base.rglob("*"):
        if not path.is_file():
            continue
        if path.suffix.lower() in SCAN_FILE_SUFFIXES:
            yield path


def _extract_zip_safe(bundle: zipfile.ZipFile, target: Path) -> None:
    for member in bundle.infolist():
        member_path = target / member.filename
        _ensure_relative(member_path, target)
    bundle.extractall(target)


def _extract_tar_safe(bundle: tarfile.TarFile, target: Path) -> None:
    for member in bundle.getmembers():
        member_path = target / member.name
        _ensure_relative(member_path, target)
    bundle.extractall(target)


def _ensure_relative(candidate: Path, target: Path) -> None:
    candidate.resolve().relative_to(target.resolve())


def _count_categories(methods: set[str]) -> dict[str, int]:
    counts: dict[str, int] = {}
    for method_id in methods:
        category = METHOD_DEFINITIONS[method_id]["category"]
        counts[category] = counts.get(category, 0) + 1
    return counts


def _count_severities(methods: set[str]) -> dict[str, int]:
    counts: dict[str, int] = {}
    for method_id in methods:
        severity = METHOD_DEFINITIONS[method_id]["severity"]
        counts[severity] = counts.get(severity, 0) + 1
    return counts

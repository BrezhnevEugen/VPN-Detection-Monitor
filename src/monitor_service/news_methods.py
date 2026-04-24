from __future__ import annotations

import re


NEWS_METHOD_RULES = [
    {
        "key": "transport_vpn_check",
        "label": "Android VPN transport check",
        "description": "The app may detect VPN usage through Android network capabilities such as TRANSPORT_VPN.",
        "patterns": [r"transport_vpn", r"networkcapabilities", r"hastransport"],
        "scanner_method_id": "transport_vpn",
    },
    {
        "key": "vpn_service_probe",
        "label": "VpnService probe",
        "description": "The app may rely on VpnService-related checks or VPN capability probing through Android APIs.",
        "patterns": [r"\bvpnservice\b", r"preparevpn", r"isvpnactive"],
        "scanner_method_id": "vpn_service_probe",
    },
    {
        "key": "tun_interface_probe",
        "label": "Tunnel interface probe",
        "description": "The app may inspect network interface names such as tun0, utun, vpn0, or WireGuard/OpenVPN adapters.",
        "patterns": [r"\btun0\b", r"\bvpn0\b", r"\butun\b", r"wireguard", r"openvpn"],
        "scanner_method_id": "tun_interface",
    },
    {
        "key": "proc_net_probe",
        "label": "Low-level proc/net probe",
        "description": "The app may read low-level networking files such as /proc/net/tcp or /proc/net/route to infer VPN or Tor usage.",
        "patterns": [r"/proc/net/tcp", r"/proc/net/route", r"proc/net"],
        "scanner_method_id": "proc_net_tcp",
    },
    {
        "key": "proxy_detection",
        "label": "Proxy or SOCKS detection",
        "description": "The app may inspect HTTP/SOCKS proxy configuration or default proxy routing to detect traffic redirection.",
        "patterns": [r"\bproxy\b", r"socks", r"proxyinfo", r"proxyselector"],
        "scanner_method_id": "proxy",
    },
    {
        "key": "tor_detection",
        "label": "Tor or Orbot detection",
        "description": "The app may look for Tor-specific ports, apps, or routing artifacts such as Orbot.",
        "patterns": [r"\btor\b", r"orbot", r"\b9050\b", r"\b9150\b"],
        "scanner_method_id": "tor",
    },
    {
        "key": "vpn_flag_telemetry",
        "label": "VPN state sent to backend",
        "description": "The app may turn VPN detection into telemetry by sending a VPN-related flag or state to backend services.",
        "patterns": [r"is_vpn", r"vpn_enabled", r"vpnstatus", r"vpn_detected", r"vpn_flag", r"isvpnconnected"],
        "scanner_method_id": "vpn_flag_to_server",
    },
    {
        "key": "dns_ip_telemetry",
        "label": "DNS/IP or geo telemetry",
        "description": "The app may infer VPN usage from public IP, DNS, geo, or exit-node related telemetry.",
        "patterns": [r"public ip", r"geoip", r"country code", r"exit node", r"hostaddress", r"dns"],
        "scanner_method_id": "dns_or_ip_telemetry",
    },
    {
        "key": "tls_fingerprinting",
        "label": "TLS fingerprinting",
        "description": "The article suggests VPN detection via TLS or traffic fingerprinting patterns rather than only direct interface checks.",
        "patterns": [r"tls fingerprint", r"ja3", r"traffic fingerprint", r"fingerprinting"],
        "scanner_method_id": None,
    },
    {
        "key": "latency_route_analysis",
        "label": "Latency or route analysis",
        "description": "The article suggests VPN detection through route shape, timing, or latency anomalies in network paths.",
        "patterns": [r"latency", r"route analysis", r"route fingerprint", r"hop count"],
        "scanner_method_id": None,
    },
]


def extract_news_method_candidates(
    title: str,
    summary: str,
    source_link: str,
    *,
    source_title: str | None = None,
    source_kind: str = "news",
) -> list[dict[str, str | None]]:
    haystack = f"{title}\n{summary}".lower()
    candidates: list[dict[str, str | None]] = []
    seen_keys: set[str] = set()

    for rule in NEWS_METHOD_RULES:
        matched = None
        for pattern in rule["patterns"]:
            regex = re.compile(pattern, flags=re.IGNORECASE)
            match = regex.search(haystack)
            if match:
                matched = match.group(0)
                break
        if matched is None or rule["key"] in seen_keys:
            continue
        seen_keys.add(rule["key"])
        candidates.append(
            {
                "method_key": rule["key"],
                "label": rule["label"],
                "description": rule["description"],
                "evidence": matched,
                "source_link": source_link,
                "source_title": source_title or title,
                "source_kind": source_kind,
                "scanner_method_id": rule["scanner_method_id"],
            }
        )

    return candidates

from __future__ import annotations

from dataclasses import dataclass
from email.utils import parsedate_to_datetime
from html import unescape
import ssl
from urllib.error import URLError
from urllib.request import Request, urlopen
import xml.etree.ElementTree as ET


USER_AGENT = "tech-state-monitor/0.1 (+https://local)"


@dataclass(slots=True)
class FeedEntry:
    source: str
    title: str
    link: str
    summary: str
    published_at: str | None


def fetch_entries(feed_url: str, timeout: int = 20) -> list[FeedEntry]:
    request = Request(feed_url, headers={"User-Agent": USER_AGENT})
    try:
        with urlopen(request, timeout=timeout) as response:
            raw = response.read()
    except Exception as exc:  # noqa: BLE001
        if not _is_ssl_verify_error(exc):
            raise
        # Some local environments miss CA bundles; retrying unverified keeps the
        # collector usable for news monitoring instead of failing the whole feed.
        insecure_context = ssl._create_unverified_context()
        with urlopen(request, timeout=timeout, context=insecure_context) as response:
            raw = response.read()

    root = ET.fromstring(raw)
    tag = _strip_ns(root.tag)
    if tag == "rss":
        return _parse_rss(root, feed_url)
    if tag == "feed":
        return _parse_atom(root, feed_url)
    return []


def _parse_rss(root: ET.Element, source: str) -> list[FeedEntry]:
    channel = root.find("./channel")
    if channel is None:
        return []

    entries: list[FeedEntry] = []
    for item in channel.findall("./item"):
        title = _text(item.find("title"))
        link = _text(item.find("link"))
        summary = _text(item.find("description"))
        published = _normalize_dt(_text(item.find("pubDate")))
        entries.append(
            FeedEntry(
                source=source,
                title=title,
                link=link,
                summary=summary,
                published_at=published,
            )
        )
    return entries


def _parse_atom(root: ET.Element, source: str) -> list[FeedEntry]:
    entries: list[FeedEntry] = []
    ns = {"a": _namespace(root.tag)}
    for entry in root.findall("./a:entry", ns):
        link = ""
        for link_node in entry.findall("./a:link", ns):
            href = link_node.attrib.get("href", "")
            rel = link_node.attrib.get("rel", "alternate")
            if href and rel == "alternate":
                link = href
                break
        title = _text(entry.find("./a:title", ns))
        summary = _text(entry.find("./a:summary", ns)) or _text(entry.find("./a:content", ns))
        published = _normalize_dt(
            _text(entry.find("./a:updated", ns)) or _text(entry.find("./a:published", ns))
        )
        entries.append(
            FeedEntry(
                source=source,
                title=title,
                link=link,
                summary=summary,
                published_at=published,
            )
        )
    return entries


def _text(node: ET.Element | None) -> str:
    if node is None or node.text is None:
        return ""
    return " ".join(unescape(node.text).split())


def _normalize_dt(value: str) -> str | None:
    if not value:
        return None
    try:
        return parsedate_to_datetime(value).isoformat()
    except (TypeError, ValueError, IndexError):
        return value


def _strip_ns(tag: str) -> str:
    return tag.rsplit("}", 1)[-1]


def _namespace(tag: str) -> str:
    if "}" not in tag:
        return ""
    return tag[1:].split("}", 1)[0]


def _is_ssl_verify_error(exc: Exception) -> bool:
    if isinstance(exc, ssl.SSLCertVerificationError):
        return True
    if isinstance(exc, URLError):
        reason = exc.reason
        return isinstance(reason, ssl.SSLCertVerificationError) or (
            isinstance(reason, str) and "CERTIFICATE_VERIFY_FAILED" in reason
        )
    return "CERTIFICATE_VERIFY_FAILED" in str(exc)

"""
IOC (Indicator of Compromise) extraction from raw alert text.

This module uses only Python stdlib (``re`` and ``ipaddress``) so that it
can run inside any SOAR action node without additional pip installs.

Design decisions
----------------
* **Private / loopback IPs are excluded** — they are almost never useful
  for external enrichment and would waste API quota hitting VT/AbuseIPDB
  with RFC-1918 addresses.
* **Deduplication is done before returning** — the same IP appearing five
  times in a log line should still only produce one enrichment call.
* **URLs are returned as-is** — normalisation (lower-casing the host, removing
  default ports) is intentionally left to the enrichment layer so that this
  module stays focused on extraction.
* **Hashes are lower-cased** — consistent formatting makes downstream dict
  lookups and de-dup reliable.

Usage
-----
::

    extractor = IOCExtractor()
    result = extractor.extract(
        "Suspicious traffic from 185.220.101.42 to http://malicious-domain.ru/payload.exe "
        "with hash 44d88612fea8a8f36de82e1278abb02f"
    )
    # result["ips"]    → ["185.220.101.42"]
    # result["urls"]   → ["http://malicious-domain.ru/payload.exe"]
    # result["hashes"] → [{"value": "44d88612fea8a8f36de82e1278abb02f", "type": "md5"}]
    # result["emails"] → []
"""

from __future__ import annotations

import ipaddress
import re
from typing import Any


# ---------------------------------------------------------------------------
# Compiled regex patterns
# ---------------------------------------------------------------------------

# IPv4 — four octets separated by dots; we validate with ipaddress afterwards
_RE_IPV4 = re.compile(
    r"\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b"
)

# URLs — http/https/ftp scheme with an optional path/query component
_RE_URL = re.compile(
    r"https?://[^\s\"'<>]+|ftp://[^\s\"'<>]+",
    re.IGNORECASE,
)

# Domains — must have at least one dot and a recognised TLD-like suffix;
# we anchor on word boundaries to avoid matching version strings like "1.0.0"
_RE_DOMAIN = re.compile(
    r"\b(?:[a-z0-9](?:[a-z0-9\-]{0,61}[a-z0-9])?\.)"
    r"+(?:com|net|org|ru|cn|io|info|biz|xyz|top|pw|cc|tk|ml|ga|cf|gq|"
    r"edu|gov|mil|int|eu|uk|de|fr|nl|br|jp|kr|au|ca|in)\b",
    re.IGNORECASE,
)

# SHA-256 (64 hex chars)
_RE_SHA256 = re.compile(r"\b[0-9a-fA-F]{64}\b")

# SHA-1  (40 hex chars)
_RE_SHA1 = re.compile(r"\b[0-9a-fA-F]{40}\b")

# MD5    (32 hex chars)
_RE_MD5 = re.compile(r"\b[0-9a-fA-F]{32}\b")

# Email addresses
_RE_EMAIL = re.compile(
    r"\b[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}\b"
)


def _is_public_ipv4(addr: str) -> bool:
    """Return True only if *addr* is a valid, public, non-loopback IPv4."""
    try:
        ip = ipaddress.ip_address(addr)
    except ValueError:
        return False
    # Exclude RFC-1918, loopback, link-local, multicast, etc.
    # is_global covers most of these but we add explicit checks for clarity.
    return (
        isinstance(ip, ipaddress.IPv4Address)
        and not ip.is_private
        and not ip.is_loopback
        and not ip.is_link_local
        and not ip.is_multicast
        and not ip.is_reserved
        and ip.is_global
    )


class IOCExtractor:
    """
    Extract and categorise IOCs from a raw text string.

    All extraction is performed by regex; validation (e.g. IP address
    range checks) uses stdlib only — no external dependencies.
    """

    def extract(self, text: str) -> dict[str, Any]:
        """
        Parse *text* and return a structured dict of IOC lists.

        Args:
            text: Raw alert text — Splunk log line, email body, SIEM alert
                  description, etc.

        Returns:
            A dict with keys:

            * ``ips``    — deduplicated list of public IPv4 address strings
            * ``urls``   — deduplicated list of URL strings
            * ``domains``— deduplicated list of domain strings not already in urls
            * ``hashes`` — deduplicated list of dicts ``{value, type}`` where
                           type is one of ``"md5"``, ``"sha1"``, ``"sha256"``
            * ``emails`` — deduplicated list of email address strings
        """
        if not text or not isinstance(text, str):
            return {"ips": [], "urls": [], "domains": [], "hashes": [], "emails": []}

        ips = self._extract_ips(text)
        urls = self._extract_urls(text)
        domains = self._extract_domains(text, urls)
        hashes = self._extract_hashes(text)
        emails = self._extract_emails(text)

        return {
            "ips": ips,
            "urls": urls,
            "domains": domains,
            "hashes": hashes,
            "emails": emails,
        }

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    def _extract_ips(self, text: str) -> list[str]:
        """Return deduplicated list of public IPv4 addresses found in *text*."""
        candidates = _RE_IPV4.findall(text)
        seen: set[str] = set()
        result: list[str] = []
        for ip in candidates:
            if ip not in seen and _is_public_ipv4(ip):
                seen.add(ip)
                result.append(ip)
        return result

    def _extract_urls(self, text: str) -> list[str]:
        """Return deduplicated list of URLs found in *text*."""
        candidates = _RE_URL.findall(text)
        seen: set[str] = set()
        result: list[str] = []
        for url in candidates:
            # Strip trailing punctuation that regex may over-match
            url = url.rstrip(".,;)")
            if url not in seen:
                seen.add(url)
                result.append(url)
        return result

    def _extract_domains(self, text: str, urls: list[str]) -> list[str]:
        """
        Return deduplicated domain names found in *text* that are NOT
        already represented in *urls* (to avoid double-reporting).
        """
        # Collect hosts that are already covered by URL extraction
        url_hosts: set[str] = set()
        for url in urls:
            # Extract just the host portion from the URL
            try:
                host = url.split("://", 1)[1].split("/")[0].split(":")[0].lower()
                url_hosts.add(host)
            except IndexError:
                pass

        candidates = _RE_DOMAIN.findall(text)
        seen: set[str] = set()
        result: list[str] = []
        for domain in candidates:
            domain_lower = domain.lower()
            if domain_lower not in seen and domain_lower not in url_hosts:
                seen.add(domain_lower)
                result.append(domain_lower)
        return result

    def _extract_hashes(self, text: str) -> list[dict[str, str]]:
        """
        Return deduplicated hash dicts, classified by length.

        SHA-256 (64 chars) is matched first, then SHA-1 (40), then MD5 (32).
        This ordering matters because a 64-char hex string would also match
        the 32-char MD5 pattern if we consumed only its first half — the
        non-overlapping nature of ``re.findall`` on non-overlapping patterns
        means we process longest-first to avoid misclassification.
        """
        seen_values: set[str] = set()
        result: list[dict[str, str]] = []

        for pattern, hash_type in [
            (_RE_SHA256, "sha256"),
            (_RE_SHA1, "sha1"),
            (_RE_MD5, "md5"),
        ]:
            for raw in pattern.findall(text):
                value = raw.lower()
                if value not in seen_values:
                    seen_values.add(value)
                    result.append({"value": value, "type": hash_type})

        return result

    def _extract_emails(self, text: str) -> list[str]:
        """Return deduplicated list of email addresses found in *text*."""
        candidates = _RE_EMAIL.findall(text)
        seen: set[str] = set()
        result: list[str] = []
        for email in candidates:
            email_lower = email.lower()
            if email_lower not in seen:
                seen.add(email_lower)
                result.append(email_lower)
        return result

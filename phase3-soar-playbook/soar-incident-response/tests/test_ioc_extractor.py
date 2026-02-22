"""
Tests for IOCExtractor — runs entirely offline, no API keys required.

Run with:
    pytest tests/ -v
"""

from __future__ import annotations

import pytest

from src.ioc_extractor import IOCExtractor


@pytest.fixture
def extractor() -> IOCExtractor:
    return IOCExtractor()


# ---------------------------------------------------------------------------
# IP address extraction
# ---------------------------------------------------------------------------

class TestIPExtraction:
    def test_extracts_public_ip(self, extractor):
        result = extractor.extract("Traffic observed from 185.220.101.42")
        assert "185.220.101.42" in result["ips"]

    def test_excludes_private_ip_192168(self, extractor):
        result = extractor.extract("Source: 192.168.1.100")
        assert result["ips"] == []

    def test_excludes_private_ip_10x(self, extractor):
        result = extractor.extract("Internal host 10.0.0.1 connected out")
        assert result["ips"] == []

    def test_excludes_private_ip_172(self, extractor):
        result = extractor.extract("Host 172.16.5.10 is RFC-1918")
        assert result["ips"] == []

    def test_excludes_loopback(self, extractor):
        result = extractor.extract("Loopback 127.0.0.1 should not appear")
        assert result["ips"] == []

    def test_mixed_public_and_private(self, extractor):
        result = extractor.extract(
            "Traffic from 192.168.1.1 and 185.220.101.42 to 10.0.0.1"
        )
        assert result["ips"] == ["185.220.101.42"]

    def test_deduplication(self, extractor):
        result = extractor.extract("185.220.101.42 185.220.101.42 185.220.101.42")
        assert result["ips"].count("185.220.101.42") == 1

    def test_multiple_public_ips(self, extractor):
        result = extractor.extract(
            "Connections from 45.33.32.156 and 8.8.4.4 detected"
        )
        assert len(result["ips"]) == 2


# ---------------------------------------------------------------------------
# URL extraction
# ---------------------------------------------------------------------------

class TestURLExtraction:
    def test_extracts_http_url(self, extractor):
        result = extractor.extract("Visit http://malicious-domain.ru/payload.exe")
        assert any("malicious-domain.ru" in u for u in result["urls"])

    def test_extracts_https_url(self, extractor):
        result = extractor.extract("POST to https://evil.example.com/exfil?q=data")
        assert "https://evil.example.com/exfil?q=data" in result["urls"]

    def test_deduplication(self, extractor):
        url = "http://evil.ru/hook"
        result = extractor.extract(f"{url} {url} {url}")
        assert result["urls"].count(url) == 1

    def test_no_urls_when_absent(self, extractor):
        result = extractor.extract("No URLs here, just text 185.220.101.42")
        assert result["urls"] == []


# ---------------------------------------------------------------------------
# Hash extraction
# ---------------------------------------------------------------------------

class TestHashExtraction:
    MD5_HASH = "44d88612fea8a8f36de82e1278abb02f"
    SHA1_HASH = "da39a3ee5e6b4b0d3255bfef95601890afd80709"
    SHA256_HASH = (
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    )

    def test_extracts_md5(self, extractor):
        result = extractor.extract(f"File hash: {self.MD5_HASH}")
        hashes = result["hashes"]
        assert any(h["value"] == self.MD5_HASH and h["type"] == "md5" for h in hashes)

    def test_extracts_sha1(self, extractor):
        result = extractor.extract(f"SHA1: {self.SHA1_HASH}")
        hashes = result["hashes"]
        assert any(h["value"] == self.SHA1_HASH and h["type"] == "sha1" for h in hashes)

    def test_extracts_sha256(self, extractor):
        result = extractor.extract(f"SHA256: {self.SHA256_HASH}")
        hashes = result["hashes"]
        assert any(h["value"] == self.SHA256_HASH and h["type"] == "sha256" for h in hashes)

    def test_hash_lowercase_normalisation(self, extractor):
        upper_md5 = self.MD5_HASH.upper()
        result = extractor.extract(f"hash={upper_md5}")
        hashes = result["hashes"]
        assert any(h["value"] == self.MD5_HASH for h in hashes)

    def test_deduplication(self, extractor):
        result = extractor.extract(
            f"{self.MD5_HASH} {self.MD5_HASH} {self.MD5_HASH}"
        )
        values = [h["value"] for h in result["hashes"]]
        assert values.count(self.MD5_HASH) == 1


# ---------------------------------------------------------------------------
# Email extraction
# ---------------------------------------------------------------------------

class TestEmailExtraction:
    def test_extracts_email(self, extractor):
        result = extractor.extract("Phishing from attacker@evil.ru to victim@corp.com")
        assert "attacker@evil.ru" in result["emails"]
        assert "victim@corp.com" in result["emails"]

    def test_email_lowercase_normalisation(self, extractor):
        result = extractor.extract("From: ATTACKER@EVIL.RU")
        assert "attacker@evil.ru" in result["emails"]

    def test_deduplication(self, extractor):
        result = extractor.extract("a@b.com a@b.com a@b.com")
        assert result["emails"].count("a@b.com") == 1


# ---------------------------------------------------------------------------
# Edge cases
# ---------------------------------------------------------------------------

class TestEdgeCases:
    def test_empty_string(self, extractor):
        result = extractor.extract("")
        assert result == {"ips": [], "urls": [], "domains": [], "hashes": [], "emails": []}

    def test_none_input(self, extractor):
        result = extractor.extract(None)  # type: ignore[arg-type]
        assert result == {"ips": [], "urls": [], "domains": [], "hashes": [], "emails": []}

    def test_non_string_input(self, extractor):
        result = extractor.extract(12345)  # type: ignore[arg-type]
        assert result == {"ips": [], "urls": [], "domains": [], "hashes": [], "emails": []}

    def test_realistic_phishing_alert(self, extractor):
        """Smoke test against a realistic multi-IOC alert string."""
        alert = (
            "Phishing email received from spammer@evil-domain.ru "
            "User clicked link http://phish.example.com/login?token=abc123 "
            "Source IP 185.220.101.42 (external) internal relay 192.168.1.50 "
            "Attachment hash 44d88612fea8a8f36de82e1278abb02f"
        )
        result = extractor.extract(alert)
        assert "185.220.101.42" in result["ips"]
        assert result["ips"] == ["185.220.101.42"]  # 192.168.1.50 excluded
        assert "http://phish.example.com/login?token=abc123" in result["urls"]
        assert any(h["value"] == "44d88612fea8a8f36de82e1278abb02f" for h in result["hashes"])
        assert "spammer@evil-domain.ru" in result["emails"]

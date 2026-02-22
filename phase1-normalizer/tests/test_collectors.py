"""
Tests for the API collectors, webhook output, and configuration modules.

All network calls are mocked — no real API keys or internet access required.
"""

from __future__ import annotations

import json
from unittest.mock import MagicMock, patch

import pytest
import requests

from src.utils.config import Config, load_config
from src.outputs.webhook import send_webhook
from src.collectors import virustotal as vt_collector
from src.collectors import abuseipdb as abuse_collector

# ---------------------------------------------------------------------------
# Config tests
# ---------------------------------------------------------------------------


class TestConfig:
    def test_load_config_raises_without_vt_key(self):
        env = {"VIRUSTOTAL_API_KEY": "", "ABUSEIPDB_API_KEY": "abc"}
        with patch.dict("os.environ", env, clear=False):
            with pytest.raises(ValueError, match="VIRUSTOTAL_API_KEY"):
                load_config()

    def test_load_config_raises_without_abuse_key(self):
        env = {"VIRUSTOTAL_API_KEY": "abc", "ABUSEIPDB_API_KEY": ""}
        with patch.dict("os.environ", env, clear=False):
            with pytest.raises(ValueError, match="ABUSEIPDB_API_KEY"):
                load_config()

    def test_load_config_from_env(self):
        with patch.dict(
            "os.environ",
            {"VIRUSTOTAL_API_KEY": "vt-key", "ABUSEIPDB_API_KEY": "abuse-key"},
            clear=False,
        ):
            cfg = load_config()
        assert cfg.virustotal_api_key == "vt-key"
        assert cfg.abuseipdb_api_key == "abuse-key"

    def test_load_config_overrides(self):
        cfg = load_config(
            virustotal_api_key="vt-override",
            abuseipdb_api_key="abuse-override",
            ip_addresses=["1.2.3.4"],
            output_file="custom.json",
        )
        assert cfg.virustotal_api_key == "vt-override"
        assert cfg.ip_addresses == ["1.2.3.4"]
        assert cfg.output_file == "custom.json"

    def test_config_defaults(self):
        cfg = Config(virustotal_api_key="vt", abuseipdb_api_key="abuse")
        assert cfg.request_timeout == 30
        assert cfg.max_retries == 3
        assert cfg.retry_backoff_factor == 1.5
        assert cfg.webhook_url == ""


# ---------------------------------------------------------------------------
# VirusTotal collector tests
# ---------------------------------------------------------------------------


def _make_vt_config() -> Config:
    return Config(virustotal_api_key="fake-vt-key", abuseipdb_api_key="fake-abuse-key")


class TestVirusTotalCollector:
    def test_fetch_ip_report_success(self):
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {"data": {"id": "1.2.3.4"}}

        with patch("requests.Session.get", return_value=mock_resp):
            result = vt_collector.fetch_ip_report("1.2.3.4", _make_vt_config())

        assert result == {"data": {"id": "1.2.3.4"}}

    def test_fetch_ip_report_404_returns_empty(self):
        mock_resp = MagicMock()
        mock_resp.status_code = 404

        with patch("requests.Session.get", return_value=mock_resp):
            result = vt_collector.fetch_ip_report("0.0.0.0", _make_vt_config())

        assert result == {}

    def test_fetch_ip_report_401_raises_permission_error(self):
        mock_resp = MagicMock()
        mock_resp.status_code = 401

        with patch("requests.Session.get", return_value=mock_resp):
            with pytest.raises(PermissionError, match="invalid or expired"):
                vt_collector.fetch_ip_report("1.2.3.4", _make_vt_config())

    def test_fetch_file_report_success(self):
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {"data": {"id": "abc123"}}

        with patch("requests.Session.get", return_value=mock_resp):
            result = vt_collector.fetch_file_report("abc123", _make_vt_config())

        assert result == {"data": {"id": "abc123"}}

    def test_fetch_ip_report_rate_limit_then_success(self):
        rate_limit_resp = MagicMock()
        rate_limit_resp.status_code = 429
        rate_limit_resp.headers = {"Retry-After": "0"}

        success_resp = MagicMock()
        success_resp.status_code = 200
        success_resp.json.return_value = {"data": {"id": "1.2.3.4"}}

        with patch("requests.Session.get", side_effect=[rate_limit_resp, success_resp]):
            with patch("time.sleep"):
                result = vt_collector.fetch_ip_report("1.2.3.4", _make_vt_config())

        assert result == {"data": {"id": "1.2.3.4"}}

    def test_fetch_ip_report_timeout_raises(self):
        with patch(
            "requests.Session.get",
            side_effect=requests.exceptions.Timeout("timed out"),
        ):
            with pytest.raises(requests.exceptions.Timeout):
                vt_collector.fetch_ip_report("1.2.3.4", _make_vt_config())

    def test_fetch_ip_report_connection_error_raises(self):
        with patch(
            "requests.Session.get",
            side_effect=requests.exceptions.ConnectionError("no route"),
        ):
            with pytest.raises(requests.exceptions.ConnectionError):
                vt_collector.fetch_ip_report("1.2.3.4", _make_vt_config())

    def test_exhausted_rate_limits_raises_runtime_error(self):
        rate_limit_resp = MagicMock()
        rate_limit_resp.status_code = 429
        rate_limit_resp.headers = {"Retry-After": "0"}

        cfg = Config(
            virustotal_api_key="vt",
            abuseipdb_api_key="abuse",
            max_retries=1,
        )
        with patch("requests.Session.get", return_value=rate_limit_resp):
            with patch("time.sleep"):
                with pytest.raises(RuntimeError, match="failed after"):
                    vt_collector.fetch_ip_report("1.2.3.4", cfg)


# ---------------------------------------------------------------------------
# AbuseIPDB collector tests
# ---------------------------------------------------------------------------


class TestAbuseIPDBCollector:
    def test_fetch_ip_report_success(self):
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {"data": {"ipAddress": "1.2.3.4"}}

        with patch("requests.Session.get", return_value=mock_resp):
            result = abuse_collector.fetch_ip_report("1.2.3.4", _make_vt_config())

        assert result["data"]["ipAddress"] == "1.2.3.4"

    def test_fetch_ip_report_401_raises_permission_error(self):
        mock_resp = MagicMock()
        mock_resp.status_code = 401

        with patch("requests.Session.get", return_value=mock_resp):
            with pytest.raises(PermissionError, match="rejected"):
                abuse_collector.fetch_ip_report("1.2.3.4", _make_vt_config())

    def test_fetch_ip_report_403_raises_permission_error(self):
        mock_resp = MagicMock()
        mock_resp.status_code = 403

        with patch("requests.Session.get", return_value=mock_resp):
            with pytest.raises(PermissionError):
                abuse_collector.fetch_ip_report("1.2.3.4", _make_vt_config())

    def test_fetch_ip_report_422_returns_empty(self):
        mock_resp = MagicMock()
        mock_resp.status_code = 422

        with patch("requests.Session.get", return_value=mock_resp):
            result = abuse_collector.fetch_ip_report("not-an-ip", _make_vt_config())

        assert result == {}

    def test_fetch_ip_report_rate_limit_then_success(self):
        rate_limit_resp = MagicMock()
        rate_limit_resp.status_code = 429
        rate_limit_resp.headers = {"Retry-After": "0"}

        success_resp = MagicMock()
        success_resp.status_code = 200
        success_resp.json.return_value = {"data": {"ipAddress": "1.2.3.4"}}

        with patch("requests.Session.get", side_effect=[rate_limit_resp, success_resp]):
            with patch("time.sleep"):
                result = abuse_collector.fetch_ip_report("1.2.3.4", _make_vt_config())

        assert result["data"]["ipAddress"] == "1.2.3.4"

    def test_fetch_ip_report_timeout_raises(self):
        with patch(
            "requests.Session.get",
            side_effect=requests.exceptions.Timeout("timed out"),
        ):
            with pytest.raises(requests.exceptions.Timeout):
                abuse_collector.fetch_ip_report("1.2.3.4", _make_vt_config())


# ---------------------------------------------------------------------------
# Webhook output tests
# ---------------------------------------------------------------------------


class TestSendWebhook:
    def _sample_alerts(self) -> list[dict]:
        return [{"indicator_value": "1.2.3.4", "verdict": "malicious"}]

    def test_empty_url_returns_false(self):
        result = send_webhook(self._sample_alerts(), webhook_url="")
        assert result is False

    def test_successful_post_returns_true(self):
        mock_resp = MagicMock()
        mock_resp.ok = True
        mock_resp.status_code = 200

        with patch("requests.Session.post", return_value=mock_resp):
            result = send_webhook(self._sample_alerts(), webhook_url="https://example.com/hook")

        assert result is True

    def test_client_error_returns_false(self):
        mock_resp = MagicMock()
        mock_resp.ok = False
        mock_resp.status_code = 400

        with patch("requests.Session.post", return_value=mock_resp):
            result = send_webhook(self._sample_alerts(), webhook_url="https://example.com/hook")

        assert result is False

    def test_connection_error_returns_false(self):
        with patch(
            "requests.Session.post",
            side_effect=requests.exceptions.ConnectionError("no route"),
        ):
            result = send_webhook(self._sample_alerts(), webhook_url="https://example.com/hook")

        assert result is False

    def test_timeout_retries_then_fails(self):
        with patch(
            "requests.Session.post",
            side_effect=requests.exceptions.Timeout("timed out"),
        ):
            with patch("time.sleep"):
                result = send_webhook(
                    self._sample_alerts(),
                    webhook_url="https://example.com/hook",
                    max_retries=2,
                )

        assert result is False

    def test_payload_structure(self):
        captured = {}

        def capture_post(url, data, headers, timeout):
            captured["payload"] = json.loads(data)
            resp = MagicMock()
            resp.ok = True
            resp.status_code = 200
            return resp

        with patch("requests.Session.post", side_effect=capture_post):
            send_webhook(self._sample_alerts(), webhook_url="https://example.com/hook")

        payload = captured["payload"]
        assert payload["schema_version"] == "1.0"
        assert payload["alert_count"] == 1
        assert isinstance(payload["alerts"], list)

    def test_server_error_retries_then_fails(self):
        mock_resp = MagicMock()
        mock_resp.ok = False
        mock_resp.status_code = 500

        with patch("requests.Session.post", return_value=mock_resp):
            result = send_webhook(
                self._sample_alerts(),
                webhook_url="https://example.com/hook",
                max_retries=1,
            )

        assert result is False

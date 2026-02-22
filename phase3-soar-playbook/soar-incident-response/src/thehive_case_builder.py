"""
TheHive v4 case payload builder.

This module constructs properly formatted TheHive REST API ``POST /api/case``
payloads from a structured enrichment result and an IOC set.

TheHive severity mapping
------------------------
  1 = Low
  2 = Medium
  3 = High
  4 = Critical

TLP (Traffic Light Protocol) values
-------------------------------------
  0 = WHITE
  1 = GREEN
  2 = AMBER
  3 = RED

PAP (Permissible Actions Protocol) values
------------------------------------------
  0 = WHITE
  1 = GREEN
  2 = AMBER
  3 = RED

Design decisions
----------------
* The case description is rendered as Markdown because TheHive's UI renders
  it, giving analysts a rich view of the enrichment context directly in the
  case without needing to dig into raw JSON.
* We build observable dicts following the TheHive v4 ``artifact`` schema
  (``dataType``, ``data``, ``tlp``, ``tags``).
* Case type drives which template tags and default tasks are applied.

Usage
-----
::

    builder = TheHiveCaseBuilder()
    payload = builder.build(
        case_type="phishing",
        alert_title="Phishing email from attacker@evil.ru",
        iocs={"ips": ["185.220.101.42"], "urls": ["http://evil.ru/hook"], ...},
        score_result={"score": 8.4, "tier": "CRITICAL", "decision": "auto-escalate", ...},
        raw_enrichment={"vt_result": {...}, "abuse_result": {...}},
    )
    # payload is a dict ready for  requests.post(THEHIVE_URL + "/api/case", json=payload)
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any


# ---------------------------------------------------------------------------
# Severity / TLP / PAP lookup tables
# ---------------------------------------------------------------------------

_SCORE_TO_SEVERITY: list[tuple[float, int, str]] = [
    # (min_score_exclusive, severity_int, severity_label)
    (7.0, 4, "Critical"),
    (5.0, 3, "High"),
    (3.0, 2, "Medium"),
    (0.0, 1, "Low"),
]

_SEVERITY_TO_TLP: dict[int, int] = {
    4: 3,  # Critical → RED
    3: 2,  # High     → AMBER
    2: 1,  # Medium   → GREEN
    1: 0,  # Low      → WHITE
}

_SEVERITY_TO_PAP: dict[int, int] = {
    4: 2,  # Critical → AMBER (restrict active actions)
    3: 2,  # High     → AMBER
    2: 1,  # Medium   → GREEN
    1: 0,  # Low      → WHITE
}

# Map IOC dict keys to TheHive dataType values
_IOC_KEY_TO_DATATYPE: dict[str, str] = {
    "ips": "ip",
    "urls": "url",
    "domains": "domain",
    "emails": "mail",
}

# Default tasks per case type — provides analysts with a starting checklist
_CASE_TYPE_TASKS: dict[str, list[str]] = {
    "phishing": [
        "Verify sender domain reputation",
        "Extract and analyse all URLs in email body",
        "Check attachment hashes against VT",
        "Identify targeted users / check for credential compromise",
        "Block sender domain at email gateway",
        "Submit phishing report to abuse@domain",
        "Preserve evidence (EML, headers) and close case",
    ],
    "malware": [
        "Isolate affected endpoint(s)",
        "Collect memory and disk forensics",
        "Analyse binary in sandbox",
        "Check for lateral movement indicators",
        "Identify C2 infrastructure and block at perimeter",
        "Scan environment for additional infections",
        "Remediate and verify clean",
    ],
    "network_anomaly": [
        "Identify affected hosts and user accounts",
        "Review firewall and proxy logs around the event window",
        "Check for data exfiltration indicators (large outbound transfers)",
        "Correlate with recent vulnerability scan findings",
        "Block suspicious destinations at perimeter",
        "Determine if traffic is business-justified",
        "Document findings and close or escalate",
    ],
}


class TheHiveCaseBuilder:
    """
    Build TheHive v4 API case payloads from enrichment results and IOCs.

    The builder is intentionally stateless — each call to :meth:`build`
    produces an independent payload dict.
    """

    def build(
        self,
        case_type: str,
        alert_title: str,
        iocs: dict[str, Any],
        score_result: dict[str, Any],
        raw_enrichment: dict[str, Any] | None = None,
        source_alert_id: str | None = None,
    ) -> dict[str, Any]:
        """
        Construct a TheHive v4 case creation payload.

        Args:
            case_type:       One of ``phishing``, ``malware``, ``network_anomaly``.
            alert_title:     Short human-readable alert title.
            iocs:            IOC dict produced by :class:`IOCExtractor`.
            score_result:    Scoring dict produced by :class:`EnrichmentScorer`.
            raw_enrichment:  Raw VT + AbuseIPDB data for the description body.
            source_alert_id: Optional upstream alert ID for traceability.

        Returns:
            Dict ready for ``POST /api/case`` (TheHive v4).
        """
        score: float = score_result.get("score", 0.0)
        tier: str = score_result.get("tier", "INFO")
        decision: str = score_result.get("decision", "auto-close")

        severity = self._score_to_severity(score)
        tlp = _SEVERITY_TO_TLP.get(severity, 1)
        pap = _SEVERITY_TO_PAP.get(severity, 1)

        description = self._build_description(
            alert_title=alert_title,
            case_type=case_type,
            score=score,
            tier=tier,
            decision=decision,
            iocs=iocs,
            score_result=score_result,
            raw_enrichment=raw_enrichment or {},
            source_alert_id=source_alert_id,
        )

        observables = self._build_observables(iocs, tlp)
        tasks = self._build_tasks(case_type)
        tags = self._build_tags(case_type, tier, iocs)

        payload: dict[str, Any] = {
            "title": alert_title,
            "description": description,
            "severity": severity,
            "tlp": tlp,
            "pap": pap,
            "status": "New",
            "flag": severity >= 3,  # auto-flag High / Critical
            "tags": tags,
            "tasks": tasks,
            "observables": observables,
            "customFields": {
                "riskScore": {"float": score},
                "riskTier": {"string": tier},
                "soarDecision": {"string": decision},
                "caseType": {"string": case_type},
                "createdBy": {"string": "SOAR-Phase3"},
                "sourceAlertId": {"string": source_alert_id or ""},
            },
        }

        return payload

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _score_to_severity(score: float) -> int:
        """Map a 0–10 composite score to TheHive severity (1–4)."""
        for threshold, severity, _ in _SCORE_TO_SEVERITY:
            if score > threshold:
                return severity
        return 1  # fallback to Low

    def _build_description(
        self,
        alert_title: str,
        case_type: str,
        score: float,
        tier: str,
        decision: str,
        iocs: dict[str, Any],
        score_result: dict[str, Any],
        raw_enrichment: dict[str, Any],
        source_alert_id: str | None,
    ) -> str:
        """Render case description as Markdown for TheHive's UI."""
        ts = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
        lines: list[str] = [
            f"# {alert_title}",
            "",
            f"**Case Type:** {case_type}  ",
            f"**Created:** {ts}  ",
            f"**Source Alert ID:** {source_alert_id or 'N/A'}  ",
            "",
            "---",
            "",
            "## Risk Assessment",
            "",
            f"| Metric | Value |",
            f"|--------|-------|",
            f"| Composite Score | **{score}/10** |",
            f"| Risk Tier | **{tier}** |",
            f"| SOAR Decision | **{decision}** |",
            "",
        ]

        # Scoring breakdown
        breakdown = score_result.get("breakdown", {})
        if breakdown:
            lines += [
                "### Score Breakdown",
                "",
                "| Factor | Raw Score | Weight | Contribution | Reasoning |",
                "|--------|-----------|--------|--------------|-----------|",
            ]
            for factor, detail in breakdown.items():
                raw = detail.get("raw_score")
                raw_str = f"{raw:.2f}" if raw is not None else "N/A"
                lines.append(
                    f"| {factor} | {raw_str} | {detail['weight']:.0%} "
                    f"| {detail['contribution']:.2f} | {detail['reasoning']} |"
                )
            lines.append("")

        # IOC summary
        lines += ["## Extracted IOCs", ""]
        for key, label in [("ips", "IP Addresses"), ("urls", "URLs"),
                            ("domains", "Domains"), ("hashes", "File Hashes"),
                            ("emails", "Email Addresses")]:
            items = iocs.get(key, [])
            if items:
                lines.append(f"**{label}:** {len(items)} found")
                for item in items:
                    if isinstance(item, dict):
                        lines.append(f"- `{item['value']}` ({item['type']})")
                    else:
                        lines.append(f"- `{item}`")
                lines.append("")

        # Raw enrichment context
        vt = raw_enrichment.get("vt_result", {})
        abuse = raw_enrichment.get("abuse_result", {})

        if vt:
            lines += [
                "## VirusTotal Context",
                "",
                f"- **Malicious detections:** {vt.get('malicious', 'N/A')}",
                f"- **Suspicious detections:** {vt.get('suspicious', 'N/A')}",
                f"- **Total engines:** {vt.get('total', 'N/A')}",
                f"- **Community reputation:** {vt.get('reputation', 'N/A')}",
                "",
            ]
        if abuse:
            lines += [
                "## AbuseIPDB Context",
                "",
                f"- **Abuse confidence:** {abuse.get('confidence', 'N/A')}%",
                f"- **Total reports:** {abuse.get('total_reports', 'N/A')}",
                "",
            ]

        lines += [
            "---",
            "*This case was created automatically by the Phase 3 SOAR playbook.*",
        ]

        return "\n".join(lines)

    @staticmethod
    def _build_observables(
        iocs: dict[str, Any],
        tlp: int,
    ) -> list[dict[str, Any]]:
        """Convert IOC dict into TheHive v4 artifact/observable list."""
        observables: list[dict[str, Any]] = []

        for ioc_key, data_type in _IOC_KEY_TO_DATATYPE.items():
            for item in iocs.get(ioc_key, []):
                observables.append({
                    "dataType": data_type,
                    "data": item,
                    "tlp": tlp,
                    "tags": [f"soar-extracted", f"type:{data_type}"],
                    "message": f"Extracted by SOAR IOC extractor",
                    "ioc": True,
                    "sighted": True,
                })

        # Hashes need special handling — extract value from dict
        for hash_item in iocs.get("hashes", []):
            if isinstance(hash_item, dict):
                observables.append({
                    "dataType": "hash",
                    "data": hash_item["value"],
                    "tlp": tlp,
                    "tags": ["soar-extracted", f"hash-type:{hash_item['type']}"],
                    "message": f"File hash ({hash_item['type']}) extracted by SOAR",
                    "ioc": True,
                    "sighted": True,
                })

        return observables

    @staticmethod
    def _build_tasks(case_type: str) -> list[dict[str, Any]]:
        """Return a list of TheHive task dicts for the given case type."""
        task_titles = _CASE_TYPE_TASKS.get(
            case_type, _CASE_TYPE_TASKS["network_anomaly"]
        )
        return [
            {
                "title": title,
                "status": "Waiting",
                "flag": False,
                "order": idx,
            }
            for idx, title in enumerate(task_titles)
        ]

    @staticmethod
    def _build_tags(
        case_type: str,
        tier: str,
        iocs: dict[str, Any],
    ) -> list[str]:
        """Build a rich tag list for searchability in TheHive."""
        tags = [
            f"type:{case_type}",
            f"tier:{tier.lower()}",
            "soar:auto-created",
            "phase3-playbook",
        ]
        # Add IOC-type tags for quick filtering
        if iocs.get("ips"):
            tags.append("has:ip")
        if iocs.get("urls"):
            tags.append("has:url")
        if iocs.get("hashes"):
            tags.append("has:hash")
        if iocs.get("emails"):
            tags.append("has:email")
        return tags

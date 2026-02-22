"""
SOAR Incident Response — source package.

This package contains the core automation logic for the Phase 3
SOAR playbook:

  ioc_extractor       — parse raw alert text into typed IOC lists
  enrichment_scorer   — combine VT + AbuseIPDB results into a risk score
  thehive_case_builder — build TheHive v4 API case payloads
  slack_formatter     — build Slack Block Kit notification payloads
"""

"""Phase 2 – Splunk SIEM log ingestion pipeline – CLI entry point.

Usage examples
--------------
Generate 10 events of each type and print to stdout (no Splunk required)::

    python main.py --generate-only 10

Ship 5 events of each type to a live Splunk HEC endpoint::

    python main.py --ship 5

Ingest Phase 1 normalizer output from a JSON file::

    python main.py --ingest-normalizer /path/to/alerts.json

Run in continuous mode (Ctrl-C to stop)::

    python main.py --continuous

Dry-run (logs what would be sent, no actual HTTP calls)::

    python main.py --ship 5 --demo
"""

from __future__ import annotations

import argparse
import json
import sys
import time
from typing import List, Dict, Any

from src.utils.config import load_config
from src.utils.logger import configure_logging, get_logger
from src.generators.ssh_events import generate_ssh_failed_login, generate_ssh_successful_login
from src.generators.process_events import generate_suspicious_process
from src.generators.network_events import generate_suspicious_outbound, generate_dns_query
from src.generators.ioc_events import generate_ioc_match
from src.shippers.hec_shipper import HECShipper, HECError
from src.shippers.batch_manager import BatchManager
from src.integrations.normalizer_bridge import NormalizerBridge


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="phase2-pipeline",
        description="Splunk SIEM log ingestion and alerting pipeline (Phase 2)",
    )
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument(
        "--generate-only",
        metavar="N",
        type=int,
        help="Generate N events of each type and print as JSON to stdout",
    )
    mode.add_argument(
        "--ship",
        metavar="N",
        type=int,
        help="Generate and ship N events of each type to Splunk",
    )
    mode.add_argument(
        "--ingest-normalizer",
        metavar="FILE",
        dest="ingest_normalizer",
        help="Read a JSON file of Phase 1 NormalizedAlert dicts and ship to Splunk",
    )
    mode.add_argument(
        "--continuous",
        action="store_true",
        help="Continuously generate and ship events until Ctrl-C",
    )

    parser.add_argument(
        "--sourcetype",
        default=None,
        help="Override the default sourcetype for shipped events",
    )
    parser.add_argument(
        "--demo",
        action="store_true",
        help="Dry-run mode: log what would be sent without making HEC calls",
    )
    return parser


def _all_events(count: int) -> List[tuple[Dict[str, Any], str]]:
    """Return a flat list of (event_dict, sourcetype) tuples."""
    return (
        [(ev, "syslog:ssh") for ev in generate_ssh_failed_login(count)]
        + [(ev, "syslog:ssh") for ev in generate_ssh_successful_login(count)]
        + [(ev, "syslog:process") for ev in generate_suspicious_process(count)]
        + [(ev, "network:flow") for ev in generate_suspicious_outbound(count)]
        + [(ev, "network:dns") for ev in generate_dns_query(count)]
        + [(ev, "endpoint:ioc") for ev in generate_ioc_match(count)]
    )


def cmd_generate_only(count: int) -> None:
    """Print generated events as JSON to stdout without shipping."""
    log = get_logger("main")
    events = _all_events(count)
    log.info("Generated %d total events", len(events))
    for ev, sourcetype in events:
        record = {"sourcetype": sourcetype, "event": ev}
        print(json.dumps(record, default=str))


def cmd_ship(count: int, sourcetype_override: str | None, dry_run: bool) -> None:
    """Generate and ship events to Splunk."""
    log = get_logger("main")
    config = load_config()
    configure_logging(config.log_level, config.shipper_log_file)
    shipper = HECShipper(config, dry_run=dry_run)

    events = _all_events(count)
    log.info("Shipping %d events (dry_run=%s)", len(events), dry_run)

    with BatchManager(shipper, batch_size=config.batch_size) as bm:
        for ev, sourcetype in events:
            st = sourcetype_override or sourcetype
            try:
                bm.add_event(ev, sourcetype=st)
            except HECError as exc:
                log.error("HEC error: %s", exc)


def cmd_ingest_normalizer(filepath: str, dry_run: bool) -> None:
    """Ingest Phase 1 normalizer output from a JSON file."""
    log = get_logger("main")
    config = load_config()
    configure_logging(config.log_level, config.shipper_log_file)
    shipper = HECShipper(config, dry_run=dry_run)
    bridge = NormalizerBridge(shipper, config)
    try:
        n = bridge.ingest_alerts_file(filepath)
        log.info("Ingested %d alerts from %s", n, filepath)
    except (FileNotFoundError, ValueError) as exc:
        log.error("Failed to ingest normalizer file: %s", exc)
        sys.exit(1)


def cmd_continuous(sourcetype_override: str | None, dry_run: bool) -> None:
    """Loop forever, generating and shipping events every 5 seconds."""
    log = get_logger("main")
    config = load_config()
    configure_logging(config.log_level, config.shipper_log_file)
    shipper = HECShipper(config, dry_run=dry_run)
    log.info("Continuous mode started (Ctrl-C to stop)")
    try:
        while True:
            events = _all_events(1)
            with BatchManager(shipper, batch_size=config.batch_size) as bm:
                for ev, sourcetype in events:
                    try:
                        bm.add_event(ev, sourcetype=sourcetype_override or sourcetype)
                    except HECError as exc:
                        log.error("HEC error: %s", exc)
            log.info("Cycle complete – sleeping 5 s")
            time.sleep(5)
    except KeyboardInterrupt:
        log.info("Continuous mode stopped by user")


def main() -> None:
    parser = _build_parser()
    args = parser.parse_args()

    # Bootstrap logging with defaults before config is loaded.
    configure_logging("INFO")
    log = get_logger("main")

    if args.generate_only is not None:
        cmd_generate_only(args.generate_only)
    elif args.ship is not None:
        cmd_ship(args.ship, args.sourcetype, args.demo)
    elif args.ingest_normalizer:
        cmd_ingest_normalizer(args.ingest_normalizer, args.demo)
    elif args.continuous:
        cmd_continuous(args.sourcetype, args.demo)
    else:
        parser.print_help()
        sys.exit(1)


if __name__ == "__main__":
    main()

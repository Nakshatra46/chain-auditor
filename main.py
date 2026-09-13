#!/usr/bin/env python3
"""
Chain-Mind Auditor — CLI entry point.

Usage:
    python main.py source <contract_address>
        Fetch verified source + bytecode from Etherscan, run the local
        pattern-matching engine, print a readable report + JSON.

    python main.py txs <address> [--limit N]
        Fetch recent confirmed transactions for an address and run
        frequency/signature-based pattern matching over them (stand-in
        for pending-tx ingestion when no WSS mempool feed is configured).

    python main.py mempool
        Stream live pending transactions via a configured WSS provider
        (MEMPOOL_WSS_URL) and flag them in real time. See
        mempool_monitor.py.
"""
import re
import sys
import json
import argparse
import logging

from etherscan_client import EtherscanClient, EtherscanError
import pattern_engine
import report

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger("chain_mind_auditor.main")

ADDRESS_RE = re.compile(r"^0x[a-fA-F0-9]{40}$")


def validate_address(address: str) -> str:
    """Reject anything that isn't a well-formed address before it ever
    reaches an API call or the pattern engine — cheap, important
    sanitization against malformed/malicious input."""
    if not address or not ADDRESS_RE.match(address):
        raise ValueError(
            f"'{address}' is not a valid Ethereum address "
            f"(expected 0x + 40 hex characters)."
        )
    return address


def cmd_source(args):
    address = validate_address(args.address)
    client = EtherscanClient()

    try:
        source_info = client.get_source_code(address)
    except EtherscanError as exc:
        logger.error("Failed to fetch source code: %s", exc)
        source_info = {}

    try:
        bytecode = client.get_bytecode(address)
    except EtherscanError as exc:
        logger.warning("Failed to fetch bytecode: %s", exc)
        bytecode = ""

    result = pattern_engine.analyze_contract(address, source_info, bytecode)

    print(report.render_text(result))
    if args.json:
        print()
        print(report.render_json(result))


def cmd_txs(args):
    address = validate_address(args.address)
    client = EtherscanClient()

    try:
        txs = client.get_recent_transactions(address, limit=args.limit)
    except EtherscanError as exc:
        logger.error("Failed to fetch transactions: %s", exc)
        sys.exit(1)

    findings = pattern_engine.analyze_transactions(txs)

    print("=" * 64)
    print(f" Chain-Mind Auditor — Transaction Batch Report ({address})")
    print(f" Transactions analyzed: {len(txs)}")
    print("=" * 64)
    if not findings:
        print(" No suspicious patterns found in this batch.")
    for f in findings:
        tx_hash = f["hash"] or "(aggregate)"
        print(f"   [{f['flag']}] {tx_hash}: {f['detail']}")
    print("=" * 64)

    if args.json:
        print(json.dumps(findings, indent=2))


def cmd_mempool(args):
    from mempool_monitor import run_mempool_monitor
    run_mempool_monitor()


def build_parser():
    parser = argparse.ArgumentParser(
        prog="chain-mind-auditor",
        description="Local pattern-matching auditor for smart contracts "
                     "and transactions.",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    p_source = sub.add_parser("source", help="Analyze verified contract source")
    p_source.add_argument("address", help="Contract address (0x...)")
    p_source.add_argument("--json", action="store_true", help="Also print JSON output")
    p_source.set_defaults(func=cmd_source)

    p_txs = sub.add_parser("txs", help="Analyze recent transactions for an address")
    p_txs.add_argument("address", help="Address (0x...)")
    p_txs.add_argument("--limit", type=int, default=20, help="Number of transactions")
    p_txs.add_argument("--json", action="store_true", help="Also print JSON output")
    p_txs.set_defaults(func=cmd_txs)

    p_mempool = sub.add_parser("mempool", help="Stream live pending transactions (needs MEMPOOL_WSS_URL)")
    p_mempool.set_defaults(func=cmd_mempool)

    return parser


def main():
    parser = build_parser()
    args = parser.parse_args()
    try:
        args.func(args)
    except ValueError as exc:
        logger.error(str(exc))
        sys.exit(2)
    except KeyboardInterrupt:
        logger.info("Interrupted by user.")
        sys.exit(130)


if __name__ == "__main__":
    main()

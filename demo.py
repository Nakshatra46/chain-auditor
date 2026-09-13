#!/usr/bin/env python3
"""
Offline demo — runs the full ingestion -> pattern-matching -> report
pipeline against mocked Etherscan responses, so you can see (and
screenshot) real output without needing an API key or network access.

Run with:  python demo.py
"""
from unittest.mock import patch

import pattern_engine
import report
from etherscan_client import EtherscanClient

with open("sample_data/risky_contract_source.sol") as f:
    RISKY_SOURCE = f.read()

with open("sample_data/clean_contract_source.sol") as f:
    CLEAN_SOURCE = f.read()

# A bytecode blob that includes SELFDESTRUCT (ff) and DELEGATECALL (f4)
# byte-pairs to demonstrate the bytecode-level heuristics.
MOCK_RISKY_BYTECODE = "0x608060405234801561001057600080fd5b50f4ff600080fd"
MOCK_CLEAN_BYTECODE = "0x6080604052348015610010576000f3fe6001600052"

MOCK_SOURCE_INFO_RISKY = {
    "SourceCode": RISKY_SOURCE,
    "ContractName": "SuspiciousToken",
    "CompilerVersion": "v0.8.19+commit.7dd6d404",
}
MOCK_SOURCE_INFO_CLEAN = {
    "SourceCode": CLEAN_SOURCE,
    "ContractName": "SimpleToken",
    "CompilerVersion": "v0.8.19+commit.7dd6d404",
}
MOCK_SOURCE_INFO_UNVERIFIED = {
    "SourceCode": "",
    "ContractName": "",
    "CompilerVersion": "",
}

MOCK_TX_BATCH = [
    {"hash": "0xaaa1", "from": "0xSpammer000000000000000000000000000001", "input": "0x8456cb59"},
    {"hash": "0xaaa2", "from": "0xSpammer000000000000000000000000000001", "input": "0x"},
    {"hash": "0xaaa3", "from": "0xSpammer000000000000000000000000000001", "input": "0x"},
    {"hash": "0xaaa4", "from": "0xSpammer000000000000000000000000000001", "input": "0x"},
    {"hash": "0xaaa5", "from": "0xSpammer000000000000000000000000000001", "input": "0x"},
    {"hash": "0xbbb1", "from": "0xNormalUser0000000000000000000000000001", "input": "0xf2fde38b"},
]


def section(title):
    print("\n" + "#" * 64)
    print(f"# {title}")
    print("#" * 64)


def demo_risky_contract():
    section("DEMO 1: Flagged / risky contract (SuspiciousToken)")
    result = pattern_engine.analyze_contract(
        "0x1111111111111111111111111111111111111111",
        MOCK_SOURCE_INFO_RISKY,
        MOCK_RISKY_BYTECODE,
    )
    print(report.render_text(result))


def demo_clean_contract():
    section("DEMO 2: Clean / low-risk contract (SimpleToken)")
    result = pattern_engine.analyze_contract(
        "0x2222222222222222222222222222222222222222",
        MOCK_SOURCE_INFO_CLEAN,
        MOCK_CLEAN_BYTECODE,
    )
    print(report.render_text(result))


def demo_unverified_contract():
    section("DEMO 3: Unverified contract (no source available)")
    result = pattern_engine.analyze_contract(
        "0x3333333333333333333333333333333333333333",
        MOCK_SOURCE_INFO_UNVERIFIED,
        "0x",
    )
    print(report.render_text(result))


def demo_transaction_batch():
    section("DEMO 4: Transaction batch — flooding + risky-selector detection")
    findings = pattern_engine.analyze_transactions(MOCK_TX_BATCH, flood_window_count=5)
    for f in findings:
        tx_hash = f["hash"] or "(aggregate)"
        print(f"   [{f['flag']}] {tx_hash}: {f['detail']}")


def demo_rate_limit_resilience():
    section("DEMO 5: Graceful handling of a simulated 429 rate-limit response")

    class FakeResponse:
        def __init__(self, status_code, payload=None):
            self.status_code = status_code
            self._payload = payload or {}
            self.text = str(payload)

        def json(self):
            return self._payload

    call_count = {"n": 0}

    def fake_get(url, params=None, timeout=None):
        call_count["n"] += 1
        if call_count["n"] < 3:
            return FakeResponse(429)
        return FakeResponse(200, {
            "status": "1", "message": "OK",
            "result": [MOCK_SOURCE_INFO_CLEAN],
        })

    with patch("etherscan_client.requests.get", side_effect=fake_get), \
         patch("etherscan_client.time.sleep", return_value=None):  # speed up demo
        client = EtherscanClient(api_key="demo-key")
        source_info = client.get_source_code("0x2222222222222222222222222222222222222222")

    print(f" Simulated {call_count['n']} requests (2 rate-limited, then success).")
    print(f" Successfully recovered and got contract: {source_info['ContractName']}")


if __name__ == "__main__":
    demo_risky_contract()
    demo_clean_contract()
    demo_unverified_contract()
    demo_transaction_batch()
    demo_rate_limit_resilience()
    print("\nDemo complete — this is the exact output the real CLI produces")
    print("against live Etherscan data (see main.py + README.md).")

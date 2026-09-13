import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pattern_engine


class TestSourceAnalysis(unittest.TestCase):
    def test_unverified_contract_is_flagged_high(self):
        result = pattern_engine.analyze_contract(
            "0x1", {"SourceCode": "", "ContractName": "", "CompilerVersion": ""}, "0x"
        )
        self.assertFalse(result.verified)
        codes = [f.code for f in result.flags]
        self.assertIn("unverified_source", codes)
        self.assertGreaterEqual(result.risk_score, 30)

    def test_selfdestruct_detected(self):
        source = "contract C { function kill() public { selfdestruct(payable(msg.sender)); } }"
        result = pattern_engine.analyze_contract(
            "0x2", {"SourceCode": source, "ContractName": "C", "CompilerVersion": "v0.8"}, "0x"
        )
        codes = [f.code for f in result.flags]
        self.assertIn("selfdestruct_call", codes)

    def test_clean_contract_has_no_flags_besides_info(self):
        source = "contract C { function foo() public returns (bool) { return true; } }"
        result = pattern_engine.analyze_contract(
            "0x3", {"SourceCode": source, "ContractName": "C", "CompilerVersion": "v0.8"}, "0x"
        )
        codes = [f.code for f in result.flags]
        self.assertEqual(codes, ["no_known_patterns"])
        self.assertEqual(result.risk_score, 0)

    def test_centralization_ratio_flag(self):
        source = """
        contract C {
            function a() public onlyOwner {}
            function b() public onlyOwner {}
            function c() public onlyOwner {}
            function d() public {}
        }
        """
        result = pattern_engine.analyze_contract(
            "0x4", {"SourceCode": source, "ContractName": "C", "CompilerVersion": "v0.8"}, "0x"
        )
        codes = [f.code for f in result.flags]
        self.assertIn("high_centralization", codes)

    def test_sanitize_handles_null_bytes_and_size_cap(self):
        dirty = "contract C {}" + "\x00" * 10 + "A" * 500_000
        cleaned = pattern_engine._sanitize_source(dirty)
        self.assertNotIn("\x00", cleaned)
        self.assertLessEqual(len(cleaned), pattern_engine.MAX_SOURCE_CHARS)


class TestBytecodeAnalysis(unittest.TestCase):
    def test_selfdestruct_opcode_detected(self):
        flags = []
        pattern_engine._analyze_bytecode("0x60ff60", flags)
        codes = [f.code for f in flags]
        self.assertIn("bytecode_selfdestruct", codes)

    def test_empty_bytecode_no_crash(self):
        flags = []
        pattern_engine._analyze_bytecode("", flags)
        self.assertEqual(flags, [])
        pattern_engine._analyze_bytecode(None, flags)
        self.assertEqual(flags, [])


class TestTransactionAnalysis(unittest.TestCase):
    def test_flooding_detection(self):
        txs = [{"hash": f"0x{i}", "from": "0xSAME", "input": "0x"} for i in range(6)]
        findings = pattern_engine.analyze_transactions(txs, flood_window_count=5)
        flags = [f["flag"] for f in findings]
        self.assertIn("possible_flooding", flags)

    def test_risky_selector_detection(self):
        txs = [{"hash": "0xabc", "from": "0x1", "input": "0x8456cb59"}]
        findings = pattern_engine.analyze_transactions(txs)
        flags = [f["flag"] for f in findings]
        self.assertIn("risky_selector", flags)

    def test_empty_transaction_list(self):
        findings = pattern_engine.analyze_transactions([])
        self.assertEqual(findings, [])


if __name__ == "__main__":
    unittest.main()

"""
This is the actual detection logic - option 1 (local pattern matching,
no LLM). Everything here is just regex + simple opcode checks, nothing
clever. See DESIGN_NOTES.md for why I went this route instead of
shipping the source off to a model.

Fair warning: this is signature matching, not real symbolic execution.
It catches stuff that's been seen before (selfdestruct, delegatecall
misuse, blacklist functions...) and will happily miss anything novel.
"""
import re
from dataclasses import dataclass, field


MAX_SOURCE_CHARS = 400_000  # guard against pathological / huge inputs


@dataclass
class Flag:
    code: str
    severity: str  # "info" | "low" | "medium" | "high" | "critical"
    message: str


@dataclass
class AnalysisResult:
    address: str
    verified: bool
    contract_name: str
    compiler_version: str
    risk_score: int
    flags: list = field(default_factory=list)

    def to_dict(self):
        return {
            "address": self.address,
            "verified": self.verified,
            "contract_name": self.contract_name,
            "compiler_version": self.compiler_version,
            "risk_score": self.risk_score,
            "flags": [f.__dict__ for f in self.flags],
        }


SEVERITY_WEIGHT = {
    "info": 0,
    "low": 5,
    "medium": 15,
    "high": 30,
    "critical": 50,
}

# --- Bytecode-level opcode signatures (hex, no 0x prefix) ---------------
OPCODE_SELFDESTRUCT = "ff"
OPCODE_DELEGATECALL = "f4"
OPCODE_CALLCODE = "f2"

# --- Source-level regex signatures --------------------------------------
# Each entry: (name, compiled pattern, severity, message)
SOURCE_SIGNATURES = [
    (
        "selfdestruct_call",
        re.compile(r"\bselfdestruct\s*\(", re.IGNORECASE),
        "high",
        "Contract can self-destruct, potentially destroying funds/state.",
    ),
    (
        "delegatecall_use",
        re.compile(r"\bdelegatecall\b", re.IGNORECASE),
        "medium",
        "Uses delegatecall — code execution can be redirected to another "
        "contract; verify the target is trusted/immutable.",
    ),
    (
        "tx_origin_auth",
        re.compile(r"\btx\.origin\b", re.IGNORECASE),
        "medium",
        "Uses tx.origin for authorization, a known phishing-vulnerable pattern.",
    ),
    (
        "hidden_mint",
        re.compile(r"function\s+_?mint\s*\(", re.IGNORECASE),
        "low",
        "Contains a mint function — check who can call it and whether "
        "supply is capped.",
    ),
    (
        "blacklist_function",
        re.compile(r"\bblacklist\w*\s*\(", re.IGNORECASE),
        "medium",
        "Contains blacklist logic — can be used to selectively block "
        "addresses from transacting (common honeypot pattern).",
    ),
    (
        "pausable",
        re.compile(r"\bwhenNotPaused\b|\bfunction\s+pause\s*\(", re.IGNORECASE),
        "low",
        "Contract is pausable — an owner can freeze transfers.",
    ),
    (
        "hardcoded_fee_change",
        re.compile(r"function\s+set(Fee|Tax)\w*\s*\(", re.IGNORECASE),
        "medium",
        "Owner can change fees/taxes after deployment — watch for "
        "rug-pull-style fee hikes.",
    ),
    (
        "arbitrary_external_call",
        re.compile(r"\.call\s*\{[^}]*value", re.IGNORECASE),
        "low",
        "Uses low-level .call{value:...} — check for reentrancy guards.",
    ),
]

OWNER_MODIFIER_PATTERN = re.compile(r"\bonlyOwner\b")
EXTERNAL_FUNC_PATTERN = re.compile(
    r"function\s+\w+\s*\([^)]*\)\s*(external|public)", re.IGNORECASE
)


def _sanitize_source(source: str) -> str:
    """Strip null bytes and cap length before we throw regex at it.

    Learned this one the hard way while testing - a weird payload with
    embedded nulls made some of the patterns behave oddly, and there's
    no reason to run regex over a multi-MB blob if the actual contract
    source is a few hundred lines. Cheap insurance either way.
    """
    if not source:
        return ""
    cleaned = source.replace("\x00", "")
    if len(cleaned) > MAX_SOURCE_CHARS:
        cleaned = cleaned[:MAX_SOURCE_CHARS]
    return cleaned


def _analyze_bytecode(bytecode: str, flags: list):
    code = (bytecode or "").lower().replace("0x", "")
    if not code:
        return

    if OPCODE_SELFDESTRUCT in _opcode_positions(code):
        flags.append(Flag(
            "bytecode_selfdestruct", "medium",
            "Bytecode contains a SELFDESTRUCT (0xff) opcode footprint.",
        ))
    if OPCODE_DELEGATECALL in _opcode_positions(code):
        flags.append(Flag(
            "bytecode_delegatecall", "low",
            "Bytecode contains a DELEGATECALL (0xf4) opcode footprint.",
        ))
    if OPCODE_CALLCODE in _opcode_positions(code):
        flags.append(Flag(
            "bytecode_callcode", "low",
            "Bytecode contains a deprecated CALLCODE (0xf2) opcode footprint.",
        ))


def _opcode_positions(code: str) -> set:
    """Chops the hex into byte pairs and returns whatever's in there.

    Not a real disassembler - just checking "does this byte value show
    up anywhere in the bytecode." Good enough to catch the common case,
    bad enough that it'll sometimes flag a 0xff that's actually just
    PUSH data. Wrote a longer version of this complaint in
    DESIGN_NOTES.md.
    """
    pairs = {code[i:i + 2] for i in range(0, len(code) - 1, 2)}
    return pairs


def _analyze_source(source: str, flags: list):
    source = _sanitize_source(source)
    if not source:
        return

    for name, pattern, severity, message in SOURCE_SIGNATURES:
        if pattern.search(source):
            flags.append(Flag(name, severity, message))

    # Frequency-threshold heuristic: centralization risk.
    owner_hits = len(OWNER_MODIFIER_PATTERN.findall(source))
    external_funcs = len(EXTERNAL_FUNC_PATTERN.findall(source))
    if external_funcs > 0:
        ratio = owner_hits / external_funcs
        if ratio >= 0.5 and owner_hits >= 3:
            flags.append(Flag(
                "high_centralization",
                "medium",
                f"{owner_hits} of ~{external_funcs} external/public functions "
                f"are owner-restricted ({ratio:.0%}) — high centralization risk.",
            ))


def analyze_contract(address: str, source_info: dict, bytecode: str) -> AnalysisResult:
    flags = []

    verified = bool(source_info.get("SourceCode"))
    contract_name = source_info.get("ContractName") or "Unknown"
    compiler_version = source_info.get("CompilerVersion") or "Unknown"

    if not verified:
        flags.append(Flag(
            "unverified_source",
            "high",
            "Source code is NOT verified on Etherscan — cannot inspect "
            "logic directly. Treat with elevated caution.",
        ))
    else:
        _analyze_source(source_info.get("SourceCode", ""), flags)

    _analyze_bytecode(bytecode, flags)

    if not flags:
        flags.append(Flag(
            "no_known_patterns", "info",
            "No known risky patterns matched. This does not guarantee "
            "the contract is safe — only that it doesn't match this "
            "engine's current signature set.",
        ))

    risk_score = min(100, sum(SEVERITY_WEIGHT[f.severity] for f in flags))

    return AnalysisResult(
        address=address,
        verified=verified,
        contract_name=contract_name,
        compiler_version=compiler_version,
        risk_score=risk_score,
        flags=flags,
    )


# --- Transaction-level pattern matching (for mempool / recent-tx mode) --

# Just a handful of selectors I looked up by hand for the demo - in a
# real version of this you'd want to pull from an actual maintained
# list instead of hardcoding four of them here.
KNOWN_RISKY_SELECTORS = {
    "0x42966c68": "burn(uint256) — token burn call",
    "0x8456cb59": "pause() — contract pause call",
    "0xf2fde38b": "transferOwnership(address) — ownership transfer",
    "0x715018a6": "renounceOwnership() — ownership renounced",
}


def analyze_transactions(transactions: list, flood_window_count: int = 5) -> list:
    """
    Frequency + signature based analysis over a batch of transactions
    (works for both the Etherscan txlist fallback and live mempool feed).
    Returns a list of flag dicts, one set per suspicious transaction hash.
    """
    findings = []
    from_counts = {}

    for tx in transactions:
        sender = (tx.get("from") or "").lower()
        from_counts[sender] = from_counts.get(sender, 0) + 1

        input_data = (tx.get("input") or tx.get("data") or "")
        selector = input_data[:10].lower() if input_data else ""
        if selector in KNOWN_RISKY_SELECTORS:
            findings.append({
                "hash": tx.get("hash"),
                "flag": "risky_selector",
                "detail": KNOWN_RISKY_SELECTORS[selector],
            })

    for sender, count in from_counts.items():
        if count >= flood_window_count:
            findings.append({
                "hash": None,
                "flag": "possible_flooding",
                "detail": f"Address {sender} sent {count} transactions in "
                          f"this batch — possible spam/flooding pattern.",
            })

    return findings

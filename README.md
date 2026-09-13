# Chain-Mind Auditor

Task 2- a tool that pulls contract data off Etherscan
and runs it through a rule-based checker to flag sketchy patterns
(self-destruct, delegatecall, hidden blacklists, that kind of thing)
without needing an LLM in the loop.

I went with plain pattern-matching instead of wiring up an LLM mainly
because I wanted the flags to be explainable. If the script says
"selfdestruct found," I want to be able to point at the exact line of
regex that caught it, not hand-wave at a model's output. Full reasoning
is in DESIGN_NOTES.md.

## How it works, roughly

1. Pull the verified source + bytecode for an address off Etherscan
   (or recent transactions, if you're looking at an address instead of
   a contract).
2. Run it through `pattern_engine.py` — a pile of regexes for known-bad
   Solidity patterns, plus a couple of opcode checks on the raw
   bytecode, plus one frequency check (if almost every function is
   `onlyOwner`-gated, that's a centralization flag).
3. Print a score out of 100 and a list of what tripped it.

Nothing fancy — no ML model, no external calls beyond Etherscan itself.

## Getting it running

```bash
pip install -r requirements.txt
cp .env.example .env
```

Then you need an Etherscan key (free):

1. Sign up at https://etherscan.io/register
2. Go to https://etherscan.io/myapikey once you're logged in
3. Hit "+ Add", copy the key it gives you
4. Paste it into `.env`:
   ```
   ETHERSCAN_API_KEY=your_key_here
   ```

Free tier throttles you pretty hard (a handful of req/sec), which is
why there's a rate limiter + retry/backoff built into
`etherscan_client.py` — first version of this kept faceplanting on 429s
until I added that.

## Running it

Check a specific contract:

```bash
python main.py source 0xSomeContractAddress --json
```

Check an address's recent transaction history for flooding/known-bad
selectors:

```bash
python main.py txs 0xSomeAddress --limit 20
```

There's also a live mempool mode (bonus, needs a WebSocket URL from
Infura/Alchemy since Etherscan's REST API doesn't do pending txs):

```bash
python main.py mempool
```

### Don't have a key yet / just want to see it work

```bash
python demo.py
```

Runs the same pipeline against a couple of sample contracts I wrote by
hand (`sample_data/`) — one deliberately dodgy, one clean — plus a
fake batch of spam transactions and a simulated rate-limit to show the
retry logic actually kicks in. This is what I used for my own
screenshots before I had real API access set up.

## Tests

```bash
python -m unittest discover -s tests -v
```

## Layout

```
chain-mind-auditor/
├── main.py                # CLI
├── config.py               # env loading
├── etherscan_client.py     # API calls, rate limiting, retries
├── pattern_engine.py       # the actual detection logic
├── report.py               # turns results into text/JSON
├── mempool_monitor.py       # optional live pending-tx streaming
├── demo.py                  # offline run against sample contracts
├── sample_data/             # two contracts I wrote for testing
├── tests/
├── requirements.txt
└── .env.example
```

Stuff I know is rough

- The bytecode check is just scanning byte-pairs for opcodes like 0xff
  (selfdestruct) — it's not a real disassembler, so it'll occasionally
  flag a byte that's actually just PUSH data, not a real instruction.
  Didn't have time to write a proper EVM decoder for this.
- Real mempool streaming needs a node provider (Infura/Alchemy) since
  Etherscan itself has no pending-tx endpoint — `mempool_monitor.py`
  handles that but it's the one part I couldn't fully test end-to-end
  without paying for a higher-tier WS plan.
- This catches known patterns. It won't catch something genuinely new.
  It's a first-pass triage tool, not a substitute for an actual audit.

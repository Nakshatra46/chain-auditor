# Why I went with pattern-matching instead of an LLM

Honestly, the LLM route was tempting because it's less work to set up
— you just dump the source into a prompt and ask "is this sketchy."
But I kept coming back to one problem: I couldn't tell the difference
between "the model is right" and "the model sounds confident." For a
security tool, that's the whole ballgame.

With regex/opcode matching, every single flag traces back to something
concrete. If my script says a contract has a centralization problem,
that's because I counted `onlyOwner` hits against the number of public
functions and the ratio crossed a threshold I picked (0.5, with at
least 3 owner-gated functions — somewhat arbitrary, but at least it's a
number I can defend and tweak). That's not true of "the LLM said so."

A few other reasons this felt like the right call for this specific
project:

- **It's fast.** Regex over a contract's source is basically instant.
  If I ever wanted to batch this across hundreds of addresses, or run
  it live against the mempool (which I half-built — see
  `mempool_monitor.py`), LLM round-trip latency would actually be a
  bottleneck.
- **No extra API dependency.** Etherscan is already a dependency for
  fetching the data in the first place. Adding an LLM API on top means
  another key, another rate limit, another point where things can
  break silently.
- **The patterns it needs to catch are pretty well-known.** Self-destruct,
  delegatecall-to-arbitrary-target, hidden blacklist functions, tx.origin
  auth — these aren't subtle. They show up in write-ups about rug pulls
  and honeypots constantly. A rule engine is a genuinely good fit for
  "catch the stuff that's already been seen before."

## Where this approach actually falls short

I want to be upfront about this instead of glossing over it:

- It only catches what I told it to look for. Anything genuinely novel
  slides right past. This is triage, not a real audit.
- The bytecode scan especially is crude — I'm literally splitting the
  hex into byte pairs and checking if `ff` or `f4` show up anywhere.
  That's going to have false positives (a `PUSH1 0xff` that's just
  loading a constant, not actually calling SELFDESTRUCT). A proper fix
  would mean writing something closer to a real EVM disassembler, which
  felt out of scope for the time I had.
- If I were extending this, the natural move is a hybrid: keep the
  rule engine for the fast first pass, then only route the ambiguous
  or unverified contracts to an LLM for a second opinion. Didn't get
  there for this submission, but it's the obvious next step (and it'd
  pair with the on-device LLM bonus too).

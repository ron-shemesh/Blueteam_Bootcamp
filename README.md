# SENTRY — Blue-Team Process-Command Threat Analyst

SENTRY ingests a CSV of process commands (`process_name, command_line`), decides
which ones are malicious, and — on demand — reconstructs the attack story behind
them. It was built for the AI Red vs. Blue bootcamp, where an attacker tool hides
~20 malicious commands among ~200 benign ones and SENTRY has to find them, fast,
without false alarms.

## How it works

SENTRY is a **two-phase analyst**, split along the thing that matters most in a
real SOC — the clock.

**Phase 1 — Detection (fast, automatic, scored).**
1. A **deterministic engine** scores every command against 384 patterns and 31
   correlation rules grounded in MITRE ATT&CK, LOLBAS, and GTFOBins. It runs in
   milliseconds and is immune to manipulation.
2. Correlation links commands that are innocent alone but malicious together
   (recon → credential dump → staging → exfil).
3. When an API key is present, an **AI pass reviews the full command set against
   the rules' baseline** — keeping the strong signature hits, hunting for
   campaigns of individually-benign commands the rules missed (e.g. supply-chain
   poisoning), and dropping bait planted to cause false positives. Without a key
   the engine runs deterministic-only. Pattern-matching is the foundation; the AI
   is a full-context second analyst on top of it.

**Phase 2 — Investigation (on demand, off the clock).**
One click produces an AI-written incident report: the attack scenario, the
attacker's objective, a kill-chain summary, a trap detector (decoys the attacker
planted to bait false positives), a remediation playbook, and a red-team report
card grading the attacker's evasion.

The whole tool runs **without an API key** in deterministic mode; the key only
adds the AI confirmation pass and the AI-written report.

### What you see when you scan (progressive results)

The console answers in two stages so you never wait on a blank screen:

1. **Instantly (~0.1s):** a **"Confirmed by rules"** table fills with the
   high-confidence (score ≥ 0.9) deterministic detections — the concrete hits you
   can act on immediately — while a spinner shows the AI is still reviewing the
   rest. The timing reads e.g. `0.18s → …`.
2. **When the AI finishes (~30s):** a **"Found by AI"** table appears with the
   additional commands the AI surfaced (campaigns the rules missed). If the AI
   judges one of the high-confidence rule hits to be benign, that row is shown
   **struck-through in place** ("AI cleared as benign") rather than silently
   removed — the AI has the final say, transparently. The timing now reads both
   numbers, e.g. `0.18s → 30s`, labeled **detection → AI review**: the **0.18s**
   is the product's core detection speed; the second number is the AI's optional
   deep review, which varies run-to-run (typically ~25–45s) with the model.

The final verdict = the un-cleared rule hits + the AI's additions. Detection
quality is identical to a one-shot scan; this is purely about showing the fast,
trustworthy results first and the full picture as soon as it's ready.

## Clone and run

```bash
git clone https://github.com/ron-shemesh/Blueteam_Bootcamp.git
cd Blueteam_Bootcamp
python3 -m pip install -r requirements.txt          # anthropic, flask, pytest

# Run the web console, then open http://localhost:5050
python3 -m sentry.webapp
```

In the console: **Choose File** → pick a CSV → **Scan** → **🔍 Investigate**.

Prefer the command line?

```bash
python3 -m sentry.cli data/training/synthetic_evasive.csv --target 20 --investigate
```

## Enabling the AI features (optional)

The AI confirmation pass and the investigation report call the Anthropic API.
To enable them, put your key (`sk-ant-…`) into the project:

1. Open **`apikey.txt.example`** and replace the placeholder line with your key.
2. Rename the file to **`apikey.txt`** (it is gitignored, so your key is never
   committed).
3. Re-scan — the console status flips to **AI-assisted**.

Only a line starting with `sk-` is read, so the committed placeholder is ignored
until replaced. **Never commit a real key.** Skip this entirely and SENTRY still
runs in deterministic mode.

Note: the AI review reads the whole command set, so it adds latency (tens of
seconds) to a scan. The deterministic path (no key, or `--no-ai`) is instant — use
it when speed matters and turn the AI on for the deepest, most contextual analysis.

### Choosing the AI model (speed vs. depth)

The AI pass uses **`claude-sonnet-4-6`** by default. To trade some depth for
**faster** scans, set the `SENTRY_MODEL` environment variable to a lighter model
before launching:

```bash
SENTRY_MODEL=claude-haiku-4-5-20251001 python3 -m sentry.webapp   # faster
# or a more capable model for maximum analysis depth, e.g.:
SENTRY_MODEL=claude-opus-4-8 python3 -m sentry.webapp
```

## Sample data

Two ready datasets live in `data/training/` (220 rows each, 20 malicious):

- `synthetic_credential_theft.csv` — credential theft → ransomware staging.
- `synthetic_evasive.csv` — includes stealthy living-off-the-land techniques.

Regenerate them, or create fresh variants, with:

```bash
python3 tools/make_synthetic.py     # credential-theft scenario
python3 tools/make_evasive.py       # evasive / stealthy scenario
```

## Tests

```bash
python3 -m pytest -q
```

## Project layout

```
sentry/
  knowledge/       pattern, combo, and benign-baseline databases
  scoring.py       deterministic scoring        pipeline.py     stage orchestration
  correlation.py   cross-command combos         ai_confirm.py   AI confirmation pass
  investigate.py   deterministic investigation  narrate.py      AI investigation
  cli.py           command-line interface       webapp.py       SOC web console
data/training/     sample datasets
tools/             dataset generators
docs/              design spec + implementation plan
```

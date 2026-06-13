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
3. A **targeted AI pass** runs *only* when the rules don't already resolve the
   known count — confirming ambiguous cases and hunting for stealthy commands the
   rules missed. Pattern-matching is the engine; AI is the augmentation.

**Phase 2 — Investigation (on demand, off the clock).**
One click produces an AI-written incident report: the attack scenario, the
attacker's objective, a kill-chain summary, a trap detector (decoys the attacker
planted to bait false positives), a remediation playbook, and a red-team report
card grading the attacker's evasion.

The whole tool runs **without an API key** in deterministic mode; the key only
adds the AI confirmation pass and the AI-written report.

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

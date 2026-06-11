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

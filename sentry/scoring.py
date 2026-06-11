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

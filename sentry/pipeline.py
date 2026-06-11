# sentry/pipeline.py
from sentry.models import ScoredRecord, Verdict
from sentry.correlation import correlate


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


def run_deterministic(scored, target: int = 20):
    correlated = correlate(scored)
    return correlated, deterministic_verdict(correlated, target=target)


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

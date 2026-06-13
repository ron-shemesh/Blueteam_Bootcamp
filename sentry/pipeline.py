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


def _candidates(correlated):
    """Rows the rules consider worth judging (high or gray band, or escalated)."""
    return [s for s in correlated if s.band in ("HIGH", "GRAY") or s.escalated]


def run_full(scored, target: int = 20, client=None):
    correlated = correlate(scored)
    candidates = _candidates(correlated)
    # AI runs ONLY when the rules didn't land on exactly `target` candidates.
    # Exactly `target` => trust the deterministic result (fast, no AI call).
    ai_details = {}
    if client is None or len(candidates) == target:
        keep = cap_to_target(candidates, target)
    else:
        from sentry.ai_confirm import confirm
        try:
            ai_details = confirm(correlated, target, client, candidates)
            keep = set(ai_details)
        except Exception:
            keep = cap_to_target(candidates, target)  # AI failure -> deterministic

    verdicts = []
    for s in correlated:
        is_mal = s.command.row_id in keep
        v = _to_verdict(s, is_mal)
        # Rows the AI recovered have no deterministic signals -> use the AI's
        # technique/reason so every flagged row explains itself.
        if is_mal and not s.signals and s.command.row_id in ai_details:
            det = ai_details[s.command.row_id]
            v.reason = det.get("reason") or "Flagged by AI threat hunter"
            if det.get("technique"):
                v.mitre_technique = det["technique"]
        verdicts.append(v)
    return correlated, verdicts


def candidate_count(scored, target: int = 20) -> int:
    """How many commands the rules flag as worth judging (before the cap)."""
    return len(_candidates(correlate(scored)))


def ai_should_run(scored, target: int = 20) -> bool:
    """True if the rules did NOT find exactly `target` candidates (so AI is needed)."""
    return candidate_count(scored) != target


def ai_mode(scored, target: int = 20) -> str:
    """Which AI mode the candidate count implies: PRUNE (>target), HUNT (<target), VERIFY (==)."""
    n = candidate_count(scored)
    return "PRUNE" if n > target else "HUNT" if n < target else "VERIFY"

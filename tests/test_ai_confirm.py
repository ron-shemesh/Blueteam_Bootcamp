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

def test_confirm_fallback_when_client_none():
    # When client is None, run_full falls back to deterministic cap.
    # confirm() itself requires a client; test the fallback via run_full.
    from sentry.ingest import load_csv
    from sentry.scoring import score_all
    from sentry.pipeline import run_full
    rows = load_csv("tests/fixtures/mini.csv")
    scored = score_all(rows)
    correlated, verdicts = run_full(scored, target=4, client=None)
    malicious = [v for v in verdicts if v.verdict == "malicious"]
    assert len(malicious) == 4

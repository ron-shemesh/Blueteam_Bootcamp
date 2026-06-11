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

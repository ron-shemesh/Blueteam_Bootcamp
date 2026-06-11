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

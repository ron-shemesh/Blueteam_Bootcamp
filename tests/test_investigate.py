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


# Task 11
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

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

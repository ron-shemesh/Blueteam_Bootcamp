# sentry/knowledge/baselines.py
# Benign signals that REDUCE the risk score, protecting the false-positive score.
# Each tuple: (regex, negative_weight, description). Matched against the
# normalized command line (case-insensitive).
BENIGN_PATTERNS: list[tuple[str, float, str]] = [
    (r"^git\s+(status|pull|push|commit|log|diff|clone|fetch|checkout|branch|merge|rebase|add|stash)", -0.5, "git usage"),
    (r"^(npm|yarn|pnpm)\s+(install|run|test|build|ci|start|audit|publish|init)", -0.5, "node tooling"),
    (r"^(pip|pip3)\s+(install|list|show|freeze|uninstall)", -0.4, "pip usage"),
    (r"^python[0-9.]*\s+(?!-c)\S+\.py\b", -0.3, "python script run"),
    (r"^(ls|cd|pwd|cat|echo|grep|find|mkdir|rmdir|touch|head|tail|less|more|cp|mv|wc|sort|uniq|diff)\b", -0.35, "common shell ops"),
    (r"^docker\s+(ps|build|run|compose|images|logs|pull|push|exec|stop|start|rm)", -0.4, "docker usage"),
    (r"^kubectl\s+(get|apply|describe|logs|delete|exec|rollout|scale)", -0.4, "kubernetes usage"),
    (r"^(make|cmake|gradle|mvn|maven|bazel)\b", -0.4, "build tooling"),
    (r"^go\s+(build|test|run|mod|get|vet|fmt|install)", -0.4, "go tooling"),
    (r"^(cargo|rustc)\s+", -0.4, "rust tooling"),
    (r"^(dotnet|nuget)\s+(build|run|test|restore|publish)", -0.4, ".NET tooling"),
    (r"^java\s+-jar\b|^javac\b", -0.3, "java run/compile"),
    (r"^(psql|mysql|sqlite3|mongo|redis-cli)\b", -0.3, "database client"),
    (r"^(terraform|ansible|ansible-playbook|helm|vagrant)\b", -0.4, "infra tooling"),
    (r"^(systemctl\s+(status|list-units)|journalctl\b|service\s+\S+\s+status)", -0.3, "service status check"),
    (r"^(brew|apt|apt-get|yum|dnf|pacman)\s+(install|update|upgrade|list|search)", -0.3, "package manager"),
    (r"^(ssh-keygen|ssh-add|ssh-copy-id)\b", -0.2, "ssh key management"),
    (r"\.(py|js|ts|jsx|tsx|go|java|rb|rs|c|cpp|md|json|yaml|yml|html|css)\b", -0.15, "source/config file reference"),
]

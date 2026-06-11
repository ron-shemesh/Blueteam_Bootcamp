# sentry/knowledge/baselines.py
# Benign signals that REDUCE risk score (protect false-positive score).
# Each tuple: (regex, negative_weight, description)
BENIGN_PATTERNS: list[tuple[str, float, str]] = [
    (r"^git\s+(status|pull|push|commit|log|diff|clone)", -0.5, "git usage"),
    (r"^(npm|yarn|pnpm)\s+(install|run|test|build)", -0.5, "node tooling"),
    (r"^(pip|pip3|python3?)\s+", -0.3, "python tooling"),
    (r"^(ls|cd|pwd|cat|echo|grep|find|mkdir)\b", -0.4, "common shell ops"),
    (r"^docker\s+(ps|build|run|compose)", -0.4, "docker usage"),
    (r"^kubectl\s+", -0.4, "kubernetes usage"),
    (r"\.(py|js|ts|go|java|rb)\b", -0.2, "source file reference"),
]

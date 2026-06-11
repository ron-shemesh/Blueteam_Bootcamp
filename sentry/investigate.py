# sentry/investigate.py
from sentry.models import ScoredRecord

KILLCHAIN_ORDER = [
    "initial-access", "execution", "persistence", "privilege-escalation",
    "defense-evasion", "discovery", "credential-access", "lateral-movement",
    "collection", "command-and-control", "exfiltration", "impact",
]
_ORDER = {t: i for i, t in enumerate(KILLCHAIN_ORDER)}

SCENARIO_RULES = [
    ("impact", "Ransomware / destructive attack"),
    ("exfiltration", "Data exfiltration"),
    ("credential-access", "Credential theft"),
    ("lateral-movement", "Lateral movement"),
    ("persistence", "Persistence / foothold"),
    ("discovery", "Reconnaissance"),
]


def _tac(s: ScoredRecord) -> str:
    return s.tactic_hints[0] if s.tactic_hints else "execution"


def order_by_killchain(items: list[ScoredRecord]) -> list[ScoredRecord]:
    return sorted(items, key=lambda s: _ORDER.get(_tac(s), 99))


def name_scenario(items: list[ScoredRecord]) -> str:
    present = {_tac(s) for s in items}
    for tactic, name in SCENARIO_RULES:
        if tactic in present:
            return name
    return "Suspicious activity"


def _technique(s: ScoredRecord) -> str:
    for sig in s.signals:
        if "[T" in sig:
            return sig.split("[")[-1].rstrip("]")
    return ""


def build_story(items: list[ScoredRecord]) -> str:
    ordered = order_by_killchain(items)
    scenario = name_scenario(items)
    lines = [f"Scenario: {scenario}", "", "Reconstructed kill chain:"]
    for n, s in enumerate(ordered, 1):
        tech = _technique(s)
        suffix = f"  ({tech})" if tech else ""
        lines.append(f"  {n}. [{_tac(s)}] {s.command.command_line}{suffix}")
    return "\n".join(lines)


# append to sentry/investigate.py
REMEDIATION = {
    "credential-access": "Rotate all potentially exposed credentials; reset affected accounts.",
    "persistence": "Remove scheduled tasks / run-key entries; audit autostart locations.",
    "exfiltration": "Block egress to the destination; review data-loss logs.",
    "impact": "Isolate host; restore from backup; verify shadow copies.",
    "discovery": "Review for follow-on activity; the host was profiled.",
    "execution": "Kill the offending process tree; quarantine dropped payloads.",
    "command-and-control": "Block the C2 endpoint; inspect downloaded artifacts.",
    "lateral-movement": "Isolate source and target hosts; reset shared credentials.",
    "defense-evasion": "Re-enable cleared logs/protections; preserve forensic evidence.",
}


def find_traps(scored: list[ScoredRecord], malicious_ids=frozenset()) -> list[dict]:
    # A trap is a row that looked suspicious but we did NOT flag as malicious.
    # Exclude anything in the final malicious set — those are real detections.
    return [{"row_id": s.command.row_id, "command": s.command.command_line,
             "why_cleared": "Scary-looking but isolated — no linked rows or campaign chain."}
            for s in scored
            if s.decoy_candidate and s.command.row_id not in malicious_ids]


def remediation_playbook(items: list[ScoredRecord]) -> list[str]:
    seen, steps = set(), []
    for s in order_by_killchain(items):
        t = _tac(s)
        if t in REMEDIATION and t not in seen:
            seen.add(t)
            steps.append(f"[{t}] {REMEDIATION[t]}")
    return steps


def report_card(detected_ids: set[int], ground_truth_ids: set[int]) -> dict:
    caught = len(detected_ids & ground_truth_ids)
    total = len(ground_truth_ids) or 1
    evaded = total - caught
    recall = caught / total
    grade = ("A" if recall >= 0.95 else "B" if recall >= 0.85 else
             "C" if recall >= 0.7 else "D" if recall >= 0.5 else "F")
    quip = ("Flawless hunt — your tradecraft left fingerprints everywhere."
            if evaded == 0 else
            f"You slipped {evaded} past us — decent blending, but not enough.")
    return {"caught": caught, "evaded": evaded, "recall": round(recall, 2),
            "grade": grade, "comment": quip}


# Ordered by how "goal-like" the tactic is. Goal tactics (what the attacker
# ultimately wanted) rank above means tactics (how they got there), so the
# inferred objective reflects intent rather than the deepest mechanical step.
OBJECTIVE = {
    "impact": "Destroy or ransom data — the attacker reached the impact stage "
              "(shadow-copy deletion / recovery disabling).",
    "exfiltration": "Steal and exfiltrate data — the attacker staged and moved data out.",
    "credential-access": "Harvest credentials to expand access.",
    "collection": "Collect sensitive data for theft — staging was underway.",
    "lateral-movement": "Spread to other hosts across the environment.",
    "persistence": "Establish a durable foothold for return access.",
    "discovery": "Reconnaissance — the attacker was profiling the host.",
    "command-and-control": "Establish remote control and pull in additional tooling.",
    "execution": "Execute attacker-controlled code on the host.",
}


def infer_objective(items: list[ScoredRecord]) -> str:
    if not items:
        return "No malicious activity detected."
    present = {_tac(s) for s in items}
    for tactic, objective in OBJECTIVE.items():
        if tactic in present:
            return objective
    return "Suspicious activity of unclear objective."

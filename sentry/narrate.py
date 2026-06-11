"""AI-generated investigation narrative, with a deterministic fallback.

When a chat-capable client is supplied (and the API call succeeds) the attack
story is written by the LLM. Otherwise we fall back to the deterministic
kill-chain story so the tool always produces output, key or no key.
"""
import json
import sys
from sentry.investigate import build_story, _tac, _technique


def _facts(mal_records):
    return [{"tactic": _tac(s), "technique": _technique(s),
             "process": s.command.process_name,
             "command": s.command.command_line} for s in mal_records]


def ai_narrative(mal_records, client):
    """Return an LLM-written attack narrative, or None if unavailable/failed."""
    if not mal_records or client is None:
        return None
    prompt = (
        "You are a SOC analyst writing an incident summary. Below are the "
        "malicious process commands we detected, tagged with MITRE tactic and "
        "technique. Write a concise 3-5 sentence narrative of the attack: what "
        "the attacker did, in what order, and what they were ultimately after. "
        "Plain prose, no bullet points, no preamble.\n\n"
        + json.dumps(_facts(mal_records), indent=2)
    )
    model = getattr(client, "model", "?")
    print(f"\n[SENTRY][LLM CALL] narrative -> model={model}\n"
          f"------- PROMPT SENT TO LLM -------\n{prompt}\n"
          f"---------------------------------", file=sys.stderr, flush=True)
    try:
        text = client.chat(prompt)
        print(f"[SENTRY][LLM REPLY] {text[:200]}...", file=sys.stderr, flush=True)
        return text or None
    except Exception as e:
        print(f"[SENTRY][LLM ERROR] {e} -> falling back to deterministic", file=sys.stderr, flush=True)
        return None


def narrate(mal_records, client=None):
    """AI narrative when a client succeeds, else the deterministic kill-chain story."""
    return ai_narrative(mal_records, client) or build_story(mal_records)


_REQUIRED = ("scenario", "objective", "summary", "trap_analysis", "playbook", "report_comment")


def ai_investigation(mal_records, decoys, caught, evaded, client):
    """Ask the LLM to generate the whole investigation in one call.

    Returns a dict with keys in _REQUIRED, or None if there is no client / the
    call fails / the response is malformed (callers fall back to deterministic).
    """
    if not mal_records or client is None:
        return None
    decoy_cmds = [d["command"] for d in decoys]
    prompt = (
        "You are the lead incident-response analyst presenting findings to executives "
        "after a breach. A detection engine has CONFIRMED the commands in `malicious` "
        "below as part of the attack; each is tagged with its MITRE ATT&CK tactic and "
        "technique. The commands in `decoys` looked suspicious but were cleared as benign "
        "(likely bait the attacker planted to trigger false alarms).\n"
        f"Scoreboard: our blue team CAUGHT {caught} of the attacker's commands; they "
        f"EVADED {evaded}.\n\n"
        "Produce a tight, pitch-ready report. Respond with ONLY a JSON object (no markdown, "
        "no prose outside it) with EXACTLY these keys:\n"
        '  "scenario": a punchy attack name a CISO would recognise (e.g. "Active Directory '
        'credential theft -> ransomware staging"),\n'
        '  "objective": ONE sentence naming the attacker\'s ultimate goal and what was at risk,\n'
        '  "summary": 2-3 sentences telling the attack story in order, naming the key '
        "techniques in plain English (no row numbers, no raw command dumps),\n"
        '  "trap_analysis": 1-2 sentences on the decoys — what bait was planted and why we '
        "did not bite; if the decoy list is empty, say no decoys were detected,\n"
        '  "playbook": an array of 3-6 SHORT, concrete, prioritised remediation actions in '
        "imperative voice (e.g. 'Isolate the host', 'Rotate all local and domain credentials'),\n"
        '  "report_comment": a short, genuinely FUNNY one-liner roasting the RED TEAM about '
        "their tradecraft. If they evaded 0 (we caught everything), absolutely roast them for "
        "being completely busted; if they evaded several, give backhanded grudging respect.\n\n"
        "malicious: " + json.dumps(_facts(mal_records)) +
        "\ndecoys: " + json.dumps(decoy_cmds)
    )
    model = getattr(client, "model", "?")
    print(f"\n[SENTRY][LLM CALL] investigation -> model={model}\n"
          f"------- PROMPT SENT TO LLM -------\n{prompt}\n"
          f"---------------------------------", file=sys.stderr, flush=True)
    try:
        text = client.chat(prompt, max_tokens=2000)
        obj = json.loads(text[text.find("{"):text.rfind("}") + 1])
        if all(k in obj for k in _REQUIRED):
            print(f"[SENTRY][LLM REPLY] scenario={obj['scenario']!r}", file=sys.stderr, flush=True)
            return obj
        return None
    except Exception as e:
        print(f"[SENTRY][LLM ERROR] {e} -> falling back to deterministic", file=sys.stderr, flush=True)
        return None

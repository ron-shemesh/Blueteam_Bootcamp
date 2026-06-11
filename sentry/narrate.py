"""AI-generated investigation narrative, with a deterministic fallback.

When a chat-capable client is supplied (and the API call succeeds) the attack
story is written by the LLM. Otherwise we fall back to the deterministic
kill-chain story so the tool always produces output, key or no key.
"""
import json
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
    try:
        text = client.chat(prompt)
        return text or None
    except Exception:
        return None


def narrate(mal_records, client=None):
    """AI narrative when a client succeeds, else the deterministic kill-chain story."""
    return ai_narrative(mal_records, client) or build_story(mal_records)

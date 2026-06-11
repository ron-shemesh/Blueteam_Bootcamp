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


def ai_investigation(mal_records, client):
    """Ask the LLM to produce {scenario, objective, narrative} from the detections.

    Returns the parsed dict, or None if there is no client / the call fails /
    the response is malformed (callers fall back to deterministic answers).
    """
    if not mal_records or client is None:
        return None
    prompt = (
        "You are a senior SOC analyst performing incident response. A detection "
        "engine has already CONFIRMED the process commands below as malicious in a "
        "breach; each is tagged with its MITRE tactic and technique. Analyse them "
        "and respond ONLY with a JSON object with exactly these keys:\n"
        '  "scenario": a short attack name (e.g. "Credential theft & exfiltration"),\n'
        '  "objective": one sentence on the attacker\'s ultimate goal,\n'
        '  "narrative": a 3-5 sentence plain-prose account of the attack, in order.\n\n'
        + json.dumps(_facts(mal_records), indent=2)
    )
    model = getattr(client, "model", "?")
    print(f"\n[SENTRY][LLM CALL] investigation -> model={model}\n"
          f"------- PROMPT SENT TO LLM -------\n{prompt}\n"
          f"---------------------------------", file=sys.stderr, flush=True)
    try:
        text = client.chat(prompt, max_tokens=2000)
        obj = json.loads(text[text.find("{"):text.rfind("}") + 1])
        if all(k in obj for k in ("scenario", "objective", "narrative")):
            print(f"[SENTRY][LLM REPLY] scenario={obj['scenario']!r}", file=sys.stderr, flush=True)
            return obj
        return None
    except Exception as e:
        print(f"[SENTRY][LLM ERROR] {e} -> falling back to deterministic", file=sys.stderr, flush=True)
        return None

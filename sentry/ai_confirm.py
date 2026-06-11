# sentry/ai_confirm.py
import json
import os
from sentry.models import ScoredRecord


def choose_mode(flagged_count: int, target: int) -> str:
    if flagged_count > target:
        return "PRUNE"
    if flagged_count == target:
        return "VERIFY"
    return "HUNT"


def _payload(records: list[ScoredRecord]) -> list[dict]:
    return [{
        "row_id": s.command.row_id,
        "process": s.command.process_name,
        "command": s.command.command_line,
        "score": round(s.risk_score, 3),
        "signals": s.signals,
        "linked_rows": s.linked_rows,
        "combo_hits": s.combo_hits,
    } for s in records]


class AnthropicClient:
    """Real client. Returns list[int] of row_ids judged malicious."""
    def __init__(self, model="claude-fable-5"):
        from anthropic import Anthropic
        self.client = Anthropic(api_key=os.environ["ANTHROPIC_API_KEY"])
        self.model = model

    def judge(self, payload, mode, target):
        instructions = {
            "PRUNE": f"The deterministic engine flagged {len(payload)} commands but exactly "
                     f"{target} are malicious. Drop the weakest-evidence false positives. "
                     f"Return the {target} row_ids that are genuinely malicious.",
            "VERIFY": f"Confirm these {target} flagged commands. Swap out any that are benign "
                      f"for stronger candidates if obvious.",
            "HUNT": f"The engine found fewer than {target} malicious commands. You are given "
                    f"ALL commands with their scores. Find up to {target} genuinely malicious "
                    f"ones, including groups that are benign alone but malicious together. "
                    f"Do not guess: only include commands more likely malicious than benign.",
        }[mode]
        prompt = (
            "You are a SOC Tier-2 analyst reviewing process commands.\n"
            f"{instructions}\n"
            "Respond ONLY with JSON: {\"malicious_row_ids\": [<ints>]}.\n\n"
            f"Commands:\n{json.dumps(payload, indent=2)}"
        )
        import sys
        print(f"\n[SENTRY][LLM CALL] detection mode={mode} model={self.model} "
              f"({len(payload)} commands)\n------- PROMPT SENT TO LLM -------\n{prompt[:1200]}"
              f"\n... (payload of {len(payload)} commands) ...\n"
              f"---------------------------------", file=sys.stderr, flush=True)
        msg = self.client.messages.create(
            model=self.model, max_tokens=1024,
            messages=[{"role": "user", "content": prompt}],
        )
        text = msg.content[0].text
        start, end = text.find("{"), text.rfind("}") + 1
        return json.loads(text[start:end]).get("malicious_row_ids", [])

    def chat(self, prompt, max_tokens=600):
        """Free-form completion used by the investigation narrator."""
        msg = self.client.messages.create(
            model=self.model, max_tokens=max_tokens,
            messages=[{"role": "user", "content": prompt}],
        )
        return msg.content[0].text.strip()


def confirm(scored: list[ScoredRecord], target: int, client,
            candidates: list[ScoredRecord] | None = None) -> set[int]:
    if candidates is None:
        candidates = [s for s in scored if s.band in ("HIGH", "GRAY") or s.escalated]
    mode = choose_mode(len(candidates), target)
    review_set = scored if mode == "HUNT" else candidates
    raw = client.judge(_payload(review_set), mode, target)
    # Coerce defensively: an LLM may return ids as strings ("5") or floats.
    clean = []
    for rid in raw:
        try:
            clean.append(int(rid))
        except (ValueError, TypeError):
            pass
    keep = list(dict.fromkeys(clean))[:target]   # dedupe + hard cap at target
    return set(keep)

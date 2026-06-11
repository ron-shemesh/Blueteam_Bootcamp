# sentry/ai_confirm.py
import json
import os
from sentry.models import ScoredRecord


def _text(msg):
    """Extract the assistant's text, skipping thinking blocks (Fable 5 emits both)."""
    return "".join(b.text for b in msg.content
                   if getattr(b, "type", None) == "text").strip()


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
    def __init__(self, model=None):
        from anthropic import Anthropic
        self.client = Anthropic(api_key=os.environ["ANTHROPIC_API_KEY"])
        # Sonnet 4.6 by default: capable, fast, and (unlike Fable 5's dual-use
        # safeguards) it engages with defensive security analysis without refusing.
        self.model = model or os.environ.get("SENTRY_MODEL", "claude-sonnet-4-6")

    def judge(self, payload, mode, target):
        mode_instr = {
            "PRUNE": f"The rules engine flagged {len(payload)} candidates, but ground truth says "
                     f"EXACTLY {target} are malicious. Identify the {target} strongest; drop the "
                     f"weakest-evidence false positives.",
            "VERIFY": f"Confirm the {target} malicious commands and correct any obvious mistake.",
            "HUNT": f"The rules engine found FEWER than {target} malicious commands, so it missed "
                    f"some. Find ALL {target}. Pay special attention to stealthy LOLBins the rules "
                    f"under-scored, and to multi-step campaigns where each command looks benign "
                    f"alone but is malicious together. Return up to {target} row_ids.",
        }[mode]
        prompt = (
            "You are an elite blue-team threat hunter analysing process commands captured from a "
            "single host during ONE incident. Ground truth: exactly "
            f"{target} of these commands are malicious; the rest are ordinary background noise. "
            "Each row includes the detection engine's risk score and matched signals as HINTS — "
            "useful, but not authoritative.\n\n"
            "Malicious patterns to weigh: LOLBins abused for execution/persistence/evasion "
            "(certutil, bitsadmin, mshta, regsvr32, rundll32, wmic, schtasks, at, sc, esentutl, "
            "vssadmin, bcdedit, wevtutil, reg save); credential access (mimikatz, procdump on "
            "lsass, reg save SAM/SYSTEM, ntds.dit copy); encoded/obfuscated payloads (-enc, "
            "base64 blobs, hidden windows); download cradles (iwr/curl/certutil/bitsadmin to a "
            "URL); and multi-step campaigns that share a file/path or form a recon -> dump -> "
            "stage -> exfil chain. Benign noise = ordinary dev/admin/CI work (git, npm, docker, "
            "kubectl, python, routine file ops).\n\n"
            f"{mode_instr}\n\n"
            "For EVERY command you judge malicious, give its row_id, the MITRE technique id "
            "(e.g. T1003.001; best guess if unsure), and a short reason. Respond with ONLY this "
            "JSON and nothing else:\n"
            '{"detections": [{"row_id": <int>, "technique": "<Txxxx>", "reason": "<short why>"}]}\n\n'
            f"Commands:\n{json.dumps(payload, indent=2)}"
        )
        import sys
        print(f"\n[SENTRY][LLM CALL] detection mode={mode} model={self.model} "
              f"({len(payload)} commands)\n------- PROMPT SENT TO LLM -------\n{prompt[:1200]}"
              f"\n... (payload of {len(payload)} commands) ...\n"
              f"---------------------------------", file=sys.stderr, flush=True)
        msg = self.client.messages.create(
            model=self.model, max_tokens=4000,
            messages=[{"role": "user", "content": prompt}],
        )
        text = _text(msg)
        start, end = text.find("{"), text.rfind("}") + 1
        return json.loads(text[start:end]).get("detections", [])

    def chat(self, prompt, max_tokens=2000):
        """Free-form completion used by the investigation narrator."""
        msg = self.client.messages.create(
            model=self.model, max_tokens=max_tokens,
            messages=[{"role": "user", "content": prompt}],
        )
        return _text(msg)


def confirm(scored: list[ScoredRecord], target: int, client,
            candidates: list[ScoredRecord] | None = None) -> dict:
    """Return {row_id: {"technique", "reason"}} for the AI-judged malicious rows.

    Deduped and hard-capped at `target`. Defensive about the LLM returning ids as
    strings/floats or omitting fields.
    """
    if candidates is None:
        candidates = [s for s in scored if s.band in ("HIGH", "GRAY") or s.escalated]
    mode = choose_mode(len(candidates), target)
    review_set = scored if mode == "HUNT" else candidates
    raw = client.judge(_payload(review_set), mode, target)
    details = {}
    for item in raw:
        if isinstance(item, dict):
            rid, tech, reason = item.get("row_id"), item.get("technique"), item.get("reason")
        else:
            rid, tech, reason = item, None, None  # tolerate a bare id
        try:
            rid = int(rid)
        except (ValueError, TypeError):
            continue
        if rid in details:
            continue
        details[rid] = {"technique": tech, "reason": reason}
        if len(details) >= target:   # hard cap at target
            break
    return details

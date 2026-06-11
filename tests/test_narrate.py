from sentry.models import ScoredRecord, CommandRecord
from sentry.narrate import narrate, ai_narrative


def _mal(rid, tactic, cmd):
    rec = CommandRecord(row_id=rid, process_name="x", command_line=cmd)
    return ScoredRecord(command=rec, risk_score=0.9, band="HIGH",
                        tactic_hints=[tactic], signals=[f"sig [{'T1003.001'}]"])


class FakeChat:
    def chat(self, prompt, max_tokens=600):
        return "The attacker dumped credentials and exfiltrated data to a share."


class Boom:
    def chat(self, *a, **k):
        raise RuntimeError("no api key")


def test_narrate_uses_ai_when_client_present():
    out = narrate([_mal(1, "credential-access", "mimikatz")], client=FakeChat())
    assert "exfiltrat" in out.lower() or "credential" in out.lower()


def test_narrate_falls_back_without_client():
    out = narrate([_mal(1, "credential-access", "mimikatz")], client=None)
    assert "kill chain" in out.lower() or "scenario" in out.lower()


def test_ai_narrative_none_when_client_fails():
    assert ai_narrative([_mal(1, "credential-access", "y")], Boom()) is None

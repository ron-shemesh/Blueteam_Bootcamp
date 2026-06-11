# sentry/models.py
from dataclasses import dataclass, field
from typing import Literal, Optional

Band = Literal["LOW", "GRAY", "HIGH"]
Tactic = str  # e.g. "discovery", "credential-access", "exfiltration"


@dataclass
class CommandRecord:
    row_id: int
    process_name: str
    command_line: str
    normalized: str = ""          # lowercased command line for matching
    decoded: str = ""             # base64-decoded fragments appended, if any


@dataclass
class Pattern:
    id: str
    regex: str                    # matched against normalized/decoded text
    weight: float                 # contribution to risk score
    mitre_technique: str          # e.g. "T1003.001"
    tactic: Tactic
    description: str


@dataclass
class ComboPattern:
    id: str
    member_regexes: list[str]     # each must match some row
    min_members: int              # how many members must appear to trigger
    tactic: Tactic
    mitre_technique: str
    description: str
    require_shared_artifact: bool = False  # members must share a path/token


@dataclass
class ScoredRecord:
    command: CommandRecord
    risk_score: float = 0.0
    signals: list[str] = field(default_factory=list)       # human-readable "why"
    tactic_hints: list[Tactic] = field(default_factory=list)
    band: Band = "LOW"
    # correlation outputs:
    linked_rows: list[int] = field(default_factory=list)
    combo_hits: list[str] = field(default_factory=list)
    escalated: bool = False
    decoy_candidate: bool = False


@dataclass
class Verdict:
    row_id: int
    verdict: Literal["malicious", "benign"]
    confidence: float
    reason: str
    mitre_technique: Optional[str] = None
    tactic: Optional[Tactic] = None

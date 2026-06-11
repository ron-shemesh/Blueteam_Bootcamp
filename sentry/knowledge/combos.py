# sentry/knowledge/combos.py
from sentry.models import ComboPattern

COMBO_PATTERNS: list[ComboPattern] = [
    ComboPattern(
        "recon_sweep",
        member_regexes=[r"\bwhoami\b", r"\bnet\s+user\b", r"\bsysteminfo\b",
                        r"\bipconfig\b", r"\bnet\s+group\b", r"\bnltest\b"],
        min_members=3, tactic="discovery", mitre_technique="T1082",
        description="Host/account reconnaissance sweep",
    ),
    ComboPattern(
        "sam_theft_staging",
        member_regexes=[r"reg\s+save\s+hklm\\sam", r"\bcopy\b", r"compress|makecab|\.zip"],
        min_members=2, tactic="credential-access", mitre_technique="T1003.002",
        description="SAM credential theft + staging",
        require_shared_artifact=True,
    ),
    ComboPattern(
        "persistence_kit",
        member_regexes=[r"schtasks.*/create", r"\\(temp|appdata)\\[^\s]+\.(ps1|bat|exe)",
                        r"reg\s+add.*\\run"],
        min_members=2, tactic="persistence", mitre_technique="T1053.005",
        description="Persistence: scheduled task / run key + dropped payload",
    ),
    ComboPattern(
        "exfil_chain",
        member_regexes=[r"compress|makecab|\.zip|\.7z", r"(curl|iwr|invoke-webrequest|bitsadmin).*http",
                        r"copy.*\\\\"],
        min_members=2, tactic="exfiltration", mitre_technique="T1567",
        description="Data staging + exfiltration",
        require_shared_artifact=True,
    ),
]

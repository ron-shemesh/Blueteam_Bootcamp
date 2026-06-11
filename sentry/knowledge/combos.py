# sentry/knowledge/combos.py
#
# Correlation patterns: groups of commands that are individually benign (or only
# mildly suspicious) but malicious *together*. Detected by Stage 2 across the
# whole CSV. `require_shared_artifact=True` means the matched commands must also
# share a file/path/token (proves they're one campaign, not coincidence) and
# escalates them to high confidence; artifact-free combos only escalate to GRAY.
from sentry.models import ComboPattern

COMBO_PATTERNS: list[ComboPattern] = [
    ComboPattern(
        "recon_sweep",
        member_regexes=[r"\bwhoami\b", r"\bnet\s+(user|group|localgroup)\b",
                        r"\bsysteminfo\b", r"\bipconfig\b", r"\bnltest\b",
                        r"\b(quser|qwinsta)\b", r"\btasklist\b"],
        min_members=3, tactic="discovery", mitre_technique="T1082",
        description="Host/account reconnaissance sweep"),
    ComboPattern(
        "ad_recon",
        member_regexes=[r"\bnltest\b", r"\b(dsquery|adfind)\b",
                        r"net\s+group\s+.*domain", r"(get-ad(user|computer|group)|get-domain)",
                        r"(bloodhound|sharphound)"],
        min_members=2, tactic="discovery", mitre_technique="T1087.002",
        description="Active Directory reconnaissance"),
    ComboPattern(
        "linux_recon",
        member_regexes=[r"\buname\b", r"\bid\b", r"/etc/passwd", r"\b(ps\s+aux|ps\s+-ef)\b",
                        r"\b(netstat|ss\s+-)\b", r"\bhostname\b"],
        min_members=3, tactic="discovery", mitre_technique="T1082",
        description="Linux host reconnaissance"),
    ComboPattern(
        "sam_theft_staging",
        member_regexes=[r"reg\s+save\s+hklm\\(sam|system|security)", r"\bcopy\b",
                        r"(compress|makecab|\.zip|\.cab)"],
        min_members=2, tactic="credential-access", mitre_technique="T1003.002",
        description="SAM/SYSTEM credential theft + staging",
        require_shared_artifact=True),
    ComboPattern(
        "ntds_theft",
        member_regexes=[r"(ntdsutil|esentutl.*ntds)", r"vssadmin.*create.*shadow",
                        r"ntds\.dit", r"\bcopy\b.*ntds"],
        min_members=2, tactic="credential-access", mitre_technique="T1003.003",
        description="NTDS.dit Active Directory theft",
        require_shared_artifact=True),
    ComboPattern(
        "lsass_dump_chain",
        member_regexes=[r"(procdump|comsvcs|rundll32).*(lsass|minidump)", r"lsass\.dmp",
                        r"(mimikatz|sekurlsa|pypykatz)"],
        min_members=2, tactic="credential-access", mitre_technique="T1003.001",
        description="LSASS dump then offline parse",
        require_shared_artifact=True),
    ComboPattern(
        "persistence_kit",
        member_regexes=[r"schtasks.*/create", r"\\(temp|appdata|programdata)\\[^\s]+\.(ps1|bat|exe|dll)",
                        r"reg\s+add.*\\run", r"\bsc(\.exe)?\s+create", r"new-service"],
        min_members=2, tactic="persistence", mitre_technique="T1053.005",
        description="Persistence: task/service/run-key + dropped payload"),
    ComboPattern(
        "download_execute",
        member_regexes=[r"(certutil|bitsadmin|iwr|invoke-webrequest|curl|wget).*http",
                        r"\\(temp|appdata|programdata)\\[^\s]+\.(exe|ps1|dll|hta|scr)",
                        r"(rundll32|regsvr32|mshta|wscript|cscript|start)\b"],
        min_members=2, tactic="command-and-control", mitre_technique="T1105",
        description="Download then execute payload",
        require_shared_artifact=True),
    ComboPattern(
        "defense_evasion_combo",
        member_regexes=[r"(wevtutil\s+cl|clear-eventlog)", r"(set-mppreference.*-disable|windefend|amsi)",
                        r"auditpol\s+/(clear|disable)", r"(history\s+-c|\.bash_history)"],
        min_members=2, tactic="defense-evasion", mitre_technique="T1562.001",
        description="Disable defenses + clear logs"),
    ComboPattern(
        "lateral_movement_chain",
        member_regexes=[r"\b(psexec|wmiexec|smbexec)\b", r"wmic\s+/node:",
                        r"net\s+use\s+\\\\", r"(invoke-command|enter-pssession).*-computername",
                        r"schtasks.*/s\s"],
        min_members=2, tactic="lateral-movement", mitre_technique="T1021",
        description="Lateral movement across hosts"),
    ComboPattern(
        "stage_and_exfil",
        member_regexes=[r"(compress-archive|makecab|7z|rar|tar\s+-c|zip\s+-r)",
                        r"(curl|iwr|invoke-webrequest|bitsadmin|scp|rclone).*(http|@|:)",
                        r"copy.*\\\\"],
        min_members=2, tactic="exfiltration", mitre_technique="T1567",
        description="Data staging + exfiltration",
        require_shared_artifact=True),
    ComboPattern(
        "ransomware_impact",
        member_regexes=[r"vssadmin.*delete\s+shadows", r"bcdedit.*recoveryenabled\s+no",
                        r"wbadmin\s+delete", r"wmic\s+shadowcopy\s+delete",
                        r"(net\s+stop|taskkill\s+/f).*(sql|backup|veeam)"],
        min_members=2, tactic="impact", mitre_technique="T1490",
        description="Ransomware: destroy backups + recovery"),
    ComboPattern(
        "kerberoast_chain",
        member_regexes=[r"(getuserspns|kerberoast|rubeus.*kerberoast)", r"\b(klist|kinit)\b",
                        r"\b(hashcat|john)\b"],
        min_members=2, tactic="credential-access", mitre_technique="T1558.003",
        description="Kerberoast then offline crack"),
    ComboPattern(
        "linux_cred_exfil",
        member_regexes=[r"/etc/shadow", r"\bunshadow\b", r"(scp|curl.*-T|rclone)"],
        min_members=2, tactic="credential-access", mitre_technique="T1003.008",
        description="Linux credential theft + exfil"),
]

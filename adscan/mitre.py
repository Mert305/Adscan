"""Bulguları MITRE ATT&CK tekniklerine eşler (merkezî, anahtar-kelime tabanlı).

Her modüle elle id yazmak yerine; bulgunun source+reference+title metninden
en uygun ATT&CK tekniğini çıkarırız. `annotate(report)` boş olan `mitre`
alanlarını doldurur (elle verilmiş id'lere dokunmaz).
"""

from __future__ import annotations

from .findings import ScanReport

# (anahtar kelime, ATT&CK id, teknik adı) — sıralama önceliklidir (ilk eşleşen)
_RULES: list[tuple[str, str, str]] = [
    ("dcsync", "T1003.006", "OS Credential Dumping: DCSync"),
    ("ntds", "T1003.003", "OS Credential Dumping: NTDS"),
    ("secretsdump", "T1003.002", "OS Credential Dumping: SAM"),
    ("lsa", "T1003.001", "OS Credential Dumping: LSASS"),
    ("sam", "T1003.002", "OS Credential Dumping: SAM"),
    ("kerberoast", "T1558.003", "Steal or Forge Kerberos Tickets: Kerberoasting"),
    ("as-rep", "T1558.004", "Steal or Forge Kerberos Tickets: AS-REP Roasting"),
    ("asrep", "T1558.004", "Steal or Forge Kerberos Tickets: AS-REP Roasting"),
    ("golden", "T1558.001", "Steal or Forge Kerberos Tickets: Golden Ticket"),
    ("esc", "T1649", "Steal or Forge Authentication Certificates"),
    ("adcs", "T1649", "Steal or Forge Authentication Certificates"),
    ("certipy", "T1649", "Steal or Forge Authentication Certificates"),
    ("sertifika", "T1649", "Steal or Forge Authentication Certificates"),
    ("shadow cred", "T1556", "Modify Authentication Process"),
    ("relay", "T1557.001", "Adversary-in-the-Middle: LLMNR/NBT-NS Poisoning & SMB Relay"),
    ("poison", "T1557.001", "Adversary-in-the-Middle: LLMNR/NBT-NS Poisoning"),
    ("petitpotam", "T1187", "Forced Authentication"),
    ("coerce", "T1187", "Forced Authentication"),
    ("mitm6", "T1557", "Adversary-in-the-Middle"),
    ("zerologon", "T1068", "Exploitation for Privilege Escalation"),
    ("tombstone", "T1098", "Account Manipulation (tombstone reanimation)"),
    ("reanimation", "T1098", "Account Manipulation (tombstone reanimation)"),
    ("writable", "T1098", "Account Manipulation (ACL abuse)"),
    ("acl", "T1098", "Account Manipulation (ACL abuse)"),
    ("rbcd", "T1098", "Account Manipulation: RBCD"),
    ("bloodyad", "T1098", "Account Manipulation (ACL abuse)"),
    ("gpp", "T1552.006", "Unsecured Credentials: GPP Passwords"),
    ("cpassword", "T1552.006", "Unsecured Credentials: GPP Passwords"),
    ("laps", "T1555", "Credentials from Password Stores"),
    ("gmsa", "T1003", "OS Credential Dumping"),
    ("spray", "T1110.003", "Brute Force: Password Spraying"),
    ("reuse", "T1550.002", "Use Alternate Authentication Material: Pass the Hash"),
    ("pass-the-hash", "T1550.002", "Pass the Hash"),
    ("pwn3d", "T1078", "Valid Accounts"),
    ("yanal", "T1021.002", "Remote Services: SMB/Windows Admin Shares"),
    ("mssql", "T1505.001", "SQL Stored Procedures / xp_cmdshell"),
    ("winrm", "T1021.006", "Remote Services: WinRM"),
    ("trust", "T1482", "Domain Trust Discovery"),
    ("bloodhound", "T1069.002", "Permission Groups Discovery: Domain Groups"),
    ("grup enumere", "T1069.002", "Permission Groups Discovery: Domain Groups"),
    ("domain admins", "T1069.002", "Permission Groups Discovery: Domain Groups"),
    ("kullanıcı enumere", "T1087.002", "Account Discovery: Domain Account"),
    ("null", "T1135", "Network Share Discovery"),
    ("share", "T1135", "Network Share Discovery"),
    ("paylaşım", "T1135", "Network Share Discovery"),
    ("delegation", "T1134.001", "Access Token Manipulation / Delegation"),
    ("signing", "T1557.001", "AiTM: SMB Relay (signing disabled)"),
    ("smb", "T1046", "Network Service Discovery"),
    ("ldap", "T1087.002", "Account Discovery: Domain Account"),
    ("port", "T1046", "Network Service Discovery"),
    ("nmap", "T1046", "Network Service Discovery"),
]

# id -> ad (tekrarsız ATT&CK tablosu üretmek için)
TECH_NAMES = {tid: name for _, tid, name in _RULES}


def technique_for(text: str) -> str:
    """Verilen metne en uygun ATT&CK id'sini döndürür (yoksa '')."""
    low = text.lower()
    for kw, tid, _ in _RULES:
        if kw in low:
            return tid
    return ""


def annotate(report: ScanReport) -> None:
    """Rapordaki boş `mitre` alanlarını otomatik doldurur."""
    for f in report.findings:
        if not f.mitre:
            f.mitre = technique_for(f"{f.source} {f.reference} {f.title}")

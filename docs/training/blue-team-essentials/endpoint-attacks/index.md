---
title: Endpoint Attacks
tags:
  - training
  - blue-team
  - endpoint
---

# Endpoint Attacks { #endpoint-attacks }

!!! abstract "In one line"
    Once delivery succeeds, the attack moves onto the host. This section follows an intrusion on the endpoint step by step — initial exploitation (service-side and client-side), execution, persistence, discovery, privilege escalation, credential dumping, lateral movement, collection and exfiltration — with the process, logon and file evidence each step leaves and the ATT&CK technique it maps to.

## Reading order { #reading-order }

| # | Page | Key points |
| --- | --- | --- |
| 1 | [Initial Exploitation — Why the Endpoint Matters, Delivery, Service-Side and Client-Side Exploits](initial-exploitation.md) | What the endpoint sees that the network can't (Zeek `conn.log` vs Sysmon 3 for the same connection); attack stages → ATT&CK tactics → best evidence; where delivery ends; the three doors (exploit, social engineering, valid credentials); the attacker becomes the compromised process — "what was compromised and with what privileges?" (`Get-Process -IncludeUserName`, `ps --forest`); service-side exploits: listening ports with `Get-NetTCPConnection`/`ss -tlnp`, an IIS log line and a `w3wp.exe` → `cmd.exe` 4688 field by field; client-side exploits: `Zone.Identifier` (MotW) and a `WINWORD.EXE` → hidden PowerShell Sysmon 1; comparison table and triage checklist; edge-device exploitation, ClickFix (T1204.004), native Sysmon; practice questions |
| 2 | [Execution, Persistence and Discovery — What the Attacker Does Right After the Exploit](execution-persistence-discovery.md) | Post-exploitation and why clean-up cost climbs; ATT&CK tactics → techniques → sub-techniques (current tactic list incl. Stealth TA0005 / Defense Impairment TA0112); execution: payloads, shells vs C2 agents, breaking out of SQL with `xp_cmdshell` (15457 and `sqlservr.exe` → `cmd.exe` 4688), application control and AppLocker 8004; persistence as a trade-off, layered persistence and failed remediation, Run key (Sysmon 13), scheduled task (4698 XML) and service (7045) field by field; discovery: living off the land, `net group "Domain Admins" /domain`, burst detection with a 4688 PowerShell hunt; five-minute timeline; practice questions |
| 3 | [Privilege Escalation — Climbing from User to Admin](privilege-escalation.md) | The privilege ladder (user → local admin → many hosts → domain admin) and why it should start low; UAC integrity levels (`whoami /groups`); four ways escalation works (become, trick, abuse a privilege, exploit); weak permissions: `icacls` ACL read field by field, the plant (Sysmon 11) → trigger (4732 by SYSTEM `0x3E7`) → 4688 with `TokenElevationType`; service binaries/registry, unquoted service paths (sweep with `Get-CimInstance`), DLL search-order hijacking (Sysmon 7), modifiable tasks, Linux SUID/sudo (T1574.x, T1548); PowerUp in memory and 4104; kernel exploitation (T1068): three ingredients, Dirty Pipe, `uname -r`, auditd `auid` ≠ `uid`; BYOVD; Administrator protection; practice questions |
| 4 | [Credential Dumping and Mimikatz — From One Admin to Many Accounts](credential-dumping-mimikatz.md) | Credential Access (TA0006) and T1003 sub-techniques (LSASS, SAM, LSA secrets, cached, NTDS, DCSync, Linux); why dumping needs admin (`SeDebugPrivilege`, `PROCESS_VM_READ`) and still pays off; SSO and what `lsass.exe` keeps per authentication package (MSV1_0, Kerberos, WDigest, TsPkg, vault); which logon types leave reusable secrets; NT hash = credential (T1550.002/.003); Mimikatz (S0002) at defender level, a redacted dump result line by line, the WDigest `UseLogonCredential` trick; why blocking the file fails; evidence: Sysmon 10 `GrantedAccess 0x1010` and `UNKNOWN` call traces, `comsvcs.dll MiniDump` 4688, 4104 `Invoke-Mimikatz`/`TVqQ`, Sysmon 13, 4624 type 9 `seclogo` and NTLM type 3, 7045 driver; the one-admin-to-domain chain and how to break it (tiering, LAPS, Protected Users, Credential Guard, LSA protection, ASR); verifying Credential Guard/RunAsPPL; token theft, NTLM phase-out; practice questions |

!!! info "Coming next"
    Lateral movement, collection and exfiltration — how attackers use stolen credentials to reach other hosts, gather data and get it out (this closes the section).

## Things to remember { #must-know }

1. The network says *that* something happened; the endpoint says *which process, which user, what*.
2. The attacker becomes the compromised process or user — always ask what it was and what privileges it had.
3. Least privilege for services and users is the cheapest way to shrink the damage of any exploit.
4. Service-side: needs a reachable listening port, no user, repeatable — patch or firewall it. Client-side: needs a user, passes inbound firewalls, hard to repeat — expect persistence.
5. A server process (`w3wp.exe`, `java.exe`) or Office application spawning a shell or script host is one of the most reliable exploitation signals.

## Related references { #related }

- [Phishing delivery](../../../adversary/phishing-delivery.md)
- [Persistence](../../../adversary/persistence.md)
- [Windows event IDs](../../../basics/windows-event-ids.md)
- [Additional Network Protocols](../other-protocols/index.md) — the network side of lateral movement and exfiltration

---
title: Endpoint Defense
tags:
  - training
  - blue-team
  - endpoint
  - hardening
---

# Endpoint Defense { #endpoint-defense }

!!! abstract "In one line"
    The previous section followed the attacker across the host; this one walks the same road from the defender's side. Each attack stage gets its own layer — inventory, vulnerability scanning, patching and exploit protection against exploitation; hardening, antivirus, application control, file integrity monitoring and PAWs against installation; host firewalls against C2; auditing, behaviour analytics, DLP and logging against actions on objective — and each layer should both block and leave evidence the SOC can use.

## Reading order { #reading-order }

| # | Page | Key points |
| --- | --- | --- |
| 1 | [Inventory, Vulnerability Scanning, Patching and Exploit Protection — Stopping the Attack Before It Lands](inventory-vulns-patching.md) | Defence in depth along the kill chain (stage → what the attacker needs → endpoint controls); know your software: Uninstall-registry inventory and `dpkg-query` (backports), why not `Win32_Product`; active vs passive discovery; an `nmap -sS -sV -O --script ftp-anon,smb-os-discovery` scan read line by line (anonymous FTP, hidden Tomcat, Server 2012 R2 out of support), T1046/T1595; unauthenticated vs authenticated vulnerability scans side by side, "reboot pending", prioritising by severity, exploitation (KEV/EPSS), asset tier; patching OS, server and client software, CIS Controls v7 → v8.1 numbering, setting the emergency bar (Essential Eight 48 h), verifying with `Get-HotFix`, WindowsUpdateClient 19/20/43, `apt list --upgradable` and `reboot-required`; anti-exploitation: how DEP/ASLR/CFG/SEHOP work, EMET → Exploit Guard → today, `Get-ProcessMitigation`, Security-Mitigations logs, controlled folder access (1123/1124, T1486), network protection (1125/1126), ASR rules, `Get-MpPreference` GUIDs and actions, a 1121 Office → PowerShell block field by field, licensing and passive mode; practice questions |
| 2 | [Credential Guard, Application Guard, Host Firewalls and Antivirus — Isolating Secrets and Fencing the Host](vbs-firewall-antivirus.md) | Why LSASS secrets are the prize (T1003.001 → T1550.002/.003); VBS and the two trust levels (VTL0/VTL1), `LsaIso.exe` as the vault behind the hatch, what a dump looks like with Credential Guard; requirements and proving it runs (`Win32_DeviceGuard` Configured vs Running, `tasklist`, Wininit 13); what it doesn't protect (SAM, keyloggers, rogue SSP T1547.005, live sessions) and its side effects; LSA protection (`RunAsPPL`) vs Credential Guard; Application Guard for Edge/Office and File Block, and its retirement; host firewall roles across the chain, profiles, default-deny, `Get-NetFirewallProfile` read column by column, `pfirewall.log` field by field (SMB/RPC/WinRM probe), WFP 5157 XML (inbound Source = local!), `auditpol` failure-only, firewall tampering (T1562.004, 4946–4950); tactical logging; host vs network firewall inside a subnet and the workstation-to-workstation alert, outbound C2/exfil (T1571, T1048); AV: signatures vs ML, polymorphism, fileless and AMSI, tampering (5001/5007/5013), a 1116 read field by field (1117/1118), rarity-based triage; practice questions |

!!! info "Coming next"
    Application control and its bypasses, file integrity monitoring and catching persistence; then PAWs, Windows permissions and privileges, EDR, DLP, UEBA and audit policies (this closes the section).

## Things to remember { #must-know }

1. One layer is never enough — line controls up against the attack stages and make every layer both block and log.
2. You can't protect what you don't know you have: combine inventory (what is installed) with network scanning (what is exposed).
3. Authenticated scans decide patching; an unauthenticated "no critical findings" means "couldn't tell", not "safe".
4. Patch OS, server *and* client software, and agree on the emergency-patch bar before you need it. Installed is not patched until the reboot happened.
5. Anti-exploitation breaks the technique, not the specific bug — and its block events (Security-Mitigations, Defender 1121/1123/1126) are some of the highest-quality alerts a SOC gets. Audit mode protects nothing.

## Related { #related }

- [Endpoint Attacks](../endpoint-attacks/index.md) — the attacker's side of the same stages
- [Hardening by Windows version](../../../adversary/hardening-by-version.md)
- [Windows Event IDs](../../../basics/windows-event-ids.md)

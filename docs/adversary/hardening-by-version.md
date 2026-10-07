---
title: Hardening by Windows Version
tags:
  - adversary
  - hardening
  - reference
---

# Hardening by Windows Version

<div class="dfir-meta" markdown>
**Scope:** Windows XP / Server 2003 → Windows 11 / Server 2025 · **Use:** "which control can I actually deploy on this host?" · **Last updated:** 2026-10-07
</div>

!!! abstract "Summary"
    Each technique page ends with a *Remediation by Windows version* table. This page turns those around: **controls down the side, Windows versions across the top**, then a map from technique to control. Use it when scoping an environment with mixed OS versions, writing an incident's recommendations, or explaining why a legacy host must be isolated rather than "hardened".

## Legend

| Mark | Meaning |
|---|---|
| ✅ **Default** | On out of the box (for new installs) |
| ✅ | Built in, must be enabled/configured |
| 🔧 | Available via a specific update / add-on (named in the notes) |
| ⚠️ | Partial — limited edition, or weaker form |
| ❌ | Not available on this version |

## Support status (as of October 2026)

| Version | End of support | Implication |
|---|---|---|
| XP / Server 2003 | Apr 2014 / Jul 2015 | No security fixes except rare out-of-band (MS17-010, BlueKeep). **Isolate** |
| Vista / Server 2008 | Apr 2017 / Jan 2020 (ESU to Jan 2023, Azure to Jan 2024) | Isolate |
| 7 / Server 2008 R2 | Jan 2020 (ESU to Jan 2023) | Isolate or migrate |
| 8.1 / Server 2012 / 2012 R2 | Jan 2023 / Oct 2023 (Server 2012/2012 R2 ESU to Oct 2026) | Migrate |
| 10 | Oct 14 2025 — consumer & commercial ESU only | Migrate; still widely deployed |
| 11 / Server 2016 / 2019 / 2022 / 2025 | Supported (2016 extended support ends Jan 2027) | Full control set |

## Control matrix

| Control | XP / 2003 | Vista / 2008 | 7 / 2008 R2 | 8.1 / 2012 R2 | 10 / 2016 / 2019 | 11 / 2022 / 2025 |
|---|---|---|---|---|---|---|
| **No LM hash storage** (`NoLMHash`) | ✅ (set it) | ✅ Default | ✅ Default | ✅ Default | ✅ Default | ✅ Default |
| **WDigest plaintext off** (`UseLogonCredential=0`) | ❌ | ❌ | 🔧 KB2871997 | ✅ Default | ✅ Default | ✅ Default |
| **LSA protection** (`RunAsPPL`) | ❌ | ❌ | ❌ | ✅ | ✅ | ✅ Default on new 11 22H2+ installs (qualifying) |
| **Credential Guard** | ❌ | ❌ | ❌ | ❌ | ✅ Ent/Edu 1511+, Server 2016+ | ✅ Default 11 22H2+ Ent/Edu (qualifying HW) |
| **Remote Credential Guard** (RDP) | ❌ | ❌ | ❌ | ❌ | ✅ 1607+ | ✅ |
| **Restricted Admin** (RDP) | ❌ | ❌ | 🔧 KB2871997 / KB2973351 | ✅ | ✅ | ✅ |
| **Protected Users** group (client side) | ❌ | ❌ | 🔧 KB2871997 | ✅ | ✅ | ✅ |
| **Windows LAPS** (built-in) | ❌ | ❌ | ❌ | ❌ | ✅ 10 20H2+, Server 2019+ (Apr 2023 update) | ✅ |
| **Legacy LAPS** (MSI) | ⚠️ | ✅ | ✅ | ✅ | ✅ (deprecated) | ⚠️ not on 11 23H2+ |
| **gMSA** (service accounts) | ❌ | ❌ | ⚠️ sMSA only (2008 R2) | ✅ 2012+ | ✅ | ✅ |
| **UAC** | ❌ | ✅ | ✅ Default (slider) | ✅ Default | ✅ Default | ✅ Default (+ Administrator protection rolling out) |
| **AppLocker** | ❌ | ❌ | ✅ Ent/Ult, 2008 R2 | ✅ Ent | ✅ Ent/Edu | ✅ |
| **WDAC / App Control for Business** | ❌ | ❌ | ❌ | ❌ | ✅ | ✅ (+ Smart App Control on clean 11 installs) |
| **Software Restriction Policies** | ✅ | ✅ | ✅ | ✅ | ⚠️ deprecated | ⚠️ deprecated |
| **AMSI** | ❌ | ❌ | ❌ | ❌ | ✅ Default | ✅ Default |
| **PowerShell 5.1 script-block logging (4104)** | ❌ | ❌ | 🔧 WMF 5.1 | 🔧 WMF 5.1 | ✅ (auto-logs suspicious blocks) | ✅ |
| **PowerShell v2 removable** | n/a | n/a | ⚠️ | ✅ | ✅ | ✅ Removed in 11 24H2 / Server 2025 |
| **Defender Antivirus** (full AV) | ❌ | ⚠️ antispyware | ⚠️ MSE add-on | ✅ Default | ✅ Default | ✅ Default |
| **ASR rules** | ❌ | ❌ | ❌ | ⚠️ 2012 R2 via MDE unified agent | ✅ 1709+ / Server 2019 (2016 via MDE) | ✅ |
| **Tamper Protection** | ❌ | ❌ | ❌ | ❌ | ✅ 1903+ | ✅ Default |
| **HVCI / Memory integrity** | ❌ | ❌ | ❌ | ❌ | ✅ | ✅ Default on new installs |
| **Vulnerable Driver Blocklist** | ❌ | ❌ | ❌ | ❌ | ⚠️ opt-in | ✅ Default 11 22H2+ |
| **BitLocker** | ❌ | ✅ Ent/Ult, Server | ✅ Ent/Ult, Server | ✅ Pro/Ent | ✅ Pro/Ent | ✅ (device encryption default on many 11 24H2 devices) |
| **SMBv1 removed** | ❌ (required) | ❌ | 🔧 registry | ✅ removable | ✅ Not installed on clean 1709+ | ✅ Not installed |
| **SMB signing required** (all connections) | ✅ (set it) | ✅ (set it) | ✅ (set it) | ✅ (set it) | ✅ (set it) — DCs default | ✅ **Default 11 24H2 / Server 2025** |
| **LLMNR disable via GPO** | n/a (no LLMNR) | ✅ | ✅ | ✅ | ✅ | ✅ |
| **NTLMv1 / LM refuse** (`LmCompatibilityLevel=5`) | ✅ (set it) | ✅ | ✅ | ✅ | ✅ | ✅ NTLMv1 **removed** 11 24H2 / Server 2025 |
| **LDAP signing + channel binding** (DC) | ⚠️ signing only | ✅ signing; 🔧 CB (2020 updates) | 🔧 CB (2020 updates) | 🔧 CB (2020 updates) | ✅ | ✅ Stricter defaults on Server 2025 |
| **NLA for RDP** | ⚠️ client only (SP3) | ✅ | ✅ Default | ✅ Default | ✅ Default | ✅ Default |
| **Account lockout** default | ❌ | ❌ | ❌ | ❌ | ❌ | ✅ 11 22H2+ new installs |
| **Command line in 4688** | ❌ | ❌ | 🔧 KB3004375 | ✅ | ✅ | ✅ |
| **Advanced audit policy** | ❌ (basic) | ⚠️ via auditpol | ✅ GPO | ✅ | ✅ | ✅ |
| **Windows Event Forwarding** | 🔧 WinRM add-on | ✅ | ✅ | ✅ | ✅ | ✅ |
| **Sysmon** (current releases) | ❌ | ❌ | ⚠️ older Sysmon builds only | ✅ 2012 R2 | ✅ | ✅ (built-in Sysmon feature arriving in 11 / Server 2025) |

!!! note "Read the matrix as a ceiling, not a floor"
    "✅" means the control *can* be deployed. In incident work, always check whether it actually **was** — e.g. `Get-CimInstance -ClassName Win32_DeviceGuard -Namespace root\Microsoft\Windows\DeviceGuard` for Credential Guard / HVCI, `reg query HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v RunAsPPL`, `Get-MpComputerStatus | Select IsTamperProtected`, `Get-SmbServerConfiguration | Select RequireSecuritySignature,EnableSMB1Protocol`.

## Technique → controls

| Technique | Primary controls (in priority order) | Page |
|---|---|---|
| LSASS dumping | Tiered admin · Credential Guard · LSA PPL · WDigest off · ASR LSASS rule | [LSASS dumping](lsass-dumping.md) |
| SAM / LSA secrets / NTDS | LAPS · Tier 0 isolation · BitLocker · HiveNightmare fix · low CachedLogonsCount | [SAM & NTDS](sam-ntds-extraction.md) |
| DCSync | Minimal replication rights · 4662 auditing · Tiering · Protected Users | [DCSync](dcsync.md) |
| Kerberoasting | gMSA / long passwords · AES only · no SPNs on admins | [Kerberoasting](kerberoasting.md) |
| AS-REP roasting | Remove `DONT_REQ_PREAUTH` · AES only | [AS-REP roasting](asrep-roasting.md) |
| Golden / Silver / PtT | krbtgt rotation · patched DCs · Credential Guard · PAC validation | [Golden & Silver](golden-silver-tickets.md) |
| Pass-the-Hash | LAPS · deny network logon for local accounts · Credential Guard · SMB signing | [Pass-the-Hash](pass-the-hash.md) |
| LLMNR / NTLM relay | LLMNR+NBT-NS off · SMB signing · LDAP signing/CB · EPA · NTLMv1 off | [LLMNR & relay](llmnr-ntlm-relay.md) |
| ADCS ESC1 / ESC8 | Template hygiene · EPA/HTTPS or remove web enrol · strong cert mapping | [ADCS abuse](adcs-abuse.md) |
| PowerShell cradles | Script-block logging · AMSI · CLM + WDAC · remove PSv2 | [PowerShell cradles](powershell-cradles.md) |
| LOLBins | WDAC block rules · ASR · AppLocker · egress proxy | [LOLBins](lolbins.md) |
| WMI / WinRM | Restrict remote mgmt to admin hosts · JEA · WMI subscription monitoring | [WMI & WinRM](wmi-winrm.md) |
| PsExec / SMB | LAPS · host firewall 445 · SMB signing · 7045 monitoring | [PsExec & SMB](psexec-smb.md) |
| RDP | No internet RDP + MFA · NLA · Remote Credential Guard · lockout | [RDP](rdp.md) |
| Persistence | Autoruns baseline · 4698/7045 alerting · WDAC | [Persistence](persistence.md) |
| UAC bypass | No local admin · Always notify · Admin protection | [UAC bypass](uac-bypass.md) |
| Potato / tokens | Fix foothold · least-priv service accounts · Spooler off | [Token & Potato](token-impersonation-potato.md) |
| Process injection | EDR · ASR · Exploit Protection · HVCI · PPL | [Process injection](process-injection.md) |
| Defense evasion / log clearing | Off-host logging · Tamper Protection · driver blocklist · heartbeat | [Impair defenses](impair-defenses-log-clearing.md) |
| EternalBlue | MS17-010 · remove SMBv1 · block 445 · isolate legacy | [EternalBlue](eternalblue-smbv1.md) |
| PrintNightmare | Spooler off on servers/DCs · patches · driver-install restriction | [PrintNightmare](printnightmare.md) |

## What to do with a host that cannot be upgraded

Legacy Windows (XP/2003/7) survives in OT, labs, medical and embedded systems. Most controls above simply do not exist there, so the strategy shifts from *hardening the host* to *containing it*:

1. **Network isolation** — own VLAN, deny-by-default firewall, no SMB/RDP from the general network, no internet.
2. **No domain credentials** on the host — local accounts with unique passwords, no Domain Admin logons ever.
3. **Jump host** with modern controls is the only way in; monitor that jump host closely.
4. **Network-based detection** (Zeek, IDS) around the segment, because host logging is weak.
5. Document the risk acceptance and a replacement date.

## References

- [Microsoft — Windows lifecycle fact sheet](https://learn.microsoft.com/lifecycle/faq/windows)
- [Microsoft — Mitigating Pass-the-Hash and other credential theft v2](https://www.microsoft.com/download/details.aspx?id=36036)
- [Microsoft — Securing privileged access (enterprise access model)](https://learn.microsoft.com/security/privileged-access-workstations/privileged-access-access-model)
- Pages: [Adversary index](index.md) · [Windows Event IDs](../basics/windows-event-ids.md) · [Playbooks](../playbooks/index.md)

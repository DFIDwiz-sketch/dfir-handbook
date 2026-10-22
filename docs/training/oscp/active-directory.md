---
title: Active Directory
tags:
  - oscp
---

# Active Directory

<div class="dfir-meta" markdown>
**Exam weight:** 40 / 100 (10 + 10 + 20) · **Priority:** Highest · **Last updated:** 2026-10-22
</div>

!!! abstract "In one sentence"
    The AD set starts from a supplied domain user (assumed breach) and chains through two machines to the Domain Controller; partial points now count, but most passing write-ups clear all 40.

!!! info "Skeleton page"
    Structure only for now — the headings below are the plan. Fill each section as you study.

## Assumed-breach start { #assumed-breach-start }

- Validate the given credentials — where can this user log in (SMB, WinRM, RDP, MSSQL)?
- First look at the domain from that foothold

## Enumeration { #enumeration }

- BloodHound collection and the first queries to run
- Users, groups, SPNs, shares, ACLs (LDAP, SMB, PowerView)

## Credential attacks { #credential-attacks }

- Kerberoasting · AS-REP roasting · targeted Kerberoast (write rights on a user)
- Password spraying and reuse
- Cracking — hashcat modes, john

## Lateral movement { #lateral-movement }

- Pass-the-Hash · Pass-the-Ticket · Overpass-the-Hash
- PsExec / WMI / WinRM / RDP

## Domain compromise { #domain-compromise }

- DCSync · constrained delegation · GPO abuse · NTLM relay (check exam restrictions)

## Looting each machine { #looting }

- What to collect after admin on each host, because it usually unlocks the next one

## Tools { #tools }

- Impacket, NetExec, BloodHound, Rubeus, Mimikatz, bloodyAD

## Exam rules for AD { #exam-rules }

- Spoofing / poisoning restrictions — confirm in the [exam guide](exam-format.md#exam-rules)

## Related pages

Detection side of the same techniques:

- [Kerberoasting](../../adversary/kerberoasting.md) · [AS-REP Roasting](../../adversary/asrep-roasting.md) · [Pass-the-Hash](../../adversary/pass-the-hash.md)
- [DCSync](../../adversary/dcsync.md) · [Golden & Silver Tickets](../../adversary/golden-silver-tickets.md) · [AD CS Abuse](../../adversary/adcs-abuse.md)
- [LLMNR / NTLM Relay](../../adversary/llmnr-ntlm-relay.md) · [LSASS Dumping](../../adversary/lsass-dumping.md) · [SAM / NTDS Extraction](../../adversary/sam-ntds-extraction.md)
- [PsExec / SMB](../../adversary/psexec-smb.md) · [WMI / WinRM](../../adversary/wmi-winrm.md) · [RDP](../../adversary/rdp.md)
- Next step in the chain: [Pivoting & tunnelling](pivoting.md)

## References

- [OffSec — OSCP Exam with AD Preparation](https://help.offsec.com/hc/en-us/articles/4547917816468-Offensive-Security-OSCP-Exam-with-AD-Preparation)

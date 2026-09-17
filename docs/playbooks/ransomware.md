---
title: Ransomware
tags:
  - playbook
  - ransomware
---

# Ransomware Response

<div class="dfir-meta" markdown>
**Scenario:** Files encrypted, ransom note present, or mass file-rename in progress · **Last updated:** 2026-09-17
</div>

!!! abstract "When to use this"
    Mass file encryption or a ransom note (`*.README.txt`, `HOW_TO_DECRYPT.*`), a sudden storm of file renames with a new extension, shadow copies deleted, or backups tampered with. Ransomware is usually the **end** of an intrusion that ran for days or weeks — treat the encryption as the last stage, not the whole incident.

!!! danger "First: is it still running?"
    If encryption is active, **containment beats collection** for the spreading hosts — isolate them from the network now (disable switch port / pull the cable / EDR-isolate; do **not** power off, you lose RAM and running keys). But capture RAM from at least one affected host first if you can do it in seconds — the key material and the running encryptor may be in memory.

## 1. Triage (first 15 minutes)

- Confirm scope: which hosts, which shares, how fast is it spreading? Check file-server logs and EDR for the rename storm.
- Identify the **strain**: the ransom note name, the appended extension, and the note text usually name it — search [ID-Ransomware / No More Ransom] with a sample note + encrypted file. This tells you whether a **decryptor exists** and whether the group **exfiltrates** (double extortion).
- Preserve one affected host's **RAM** ([imaging](../tools/imaging-collection.md)) and a sample encrypted file + note before remediation touches anything.
- Do **not** pay or negotiate on your own authority — that is a leadership/legal/insurance decision. Do not delete the notes or encrypted files.

## 2. Collect

| Source | What | How |
|---|---|---|
| Affected host RAM | Running encryptor, keys | [WinPmem / FTK](../tools/imaging-collection.md) — before isolation kills the process if possible |
| Triage artifacts (patient-zero + spreaders) | Execution, persistence, lateral movement | [KAPE `!SANS_Triage`](../tools/kape.md) or [Velociraptor](../tools/velociraptor.md) hunt |
| `$MFT` + `$UsnJrnl` | The encryption timeline — exact start, order of directories, file count | [MFT/USN](../windows/mft-usn.md) — the `$J` shows the rename storm start/stop and traversal order |
| Event logs | Deployment method, log clears | [Event logs](../windows/event-logs.md) — `7045`, `4688`, `1102`, `4104` |
| Backups | State, whether attacker deleted/encrypted them | Backup console + `vssadmin`/`wbadmin` history |
| Network | C2 (pre-encryption), exfil (double extortion) | [Zeek](../network/index.md) / [Arkime](../network/arkime/index.md) / [SRUM](../windows/srum.md) |

## 3. Analyse — reconstruct the whole intrusion

The encryption is stage N; find stages 1…N−1:

- **Encryption timeline & patient zero**: `$UsnJrnl` gives the exact first encrypted file and host — [MFT/USN mass-activity hunt](../windows/mft-usn.md). Which host started first is usually where deployment ran.
- **Deployment method**: mass simultaneous encryption across hosts points to a push — GPO, PsExec, PDQ, or the domain controller. Look for [PsExec/SMB](../adversary/psexec-smb.md) `7045`, [WMI/WinRM](../adversary/wmi-winrm.md), or a scheduled task pushed fleet-wide ([persistence](../adversary/persistence.md)).
- **Shadow-copy / backup destruction** (runs just before encryption): `vssadmin delete shadows`, `wbadmin delete`, `bcdedit /set recoveryenabled no`, `wevtutil cl` — catch it with the [LOLBin command-line search](../splunk/security-searches.md#what-ran).
- **Initial access & dwell**: work backwards — [beaconing/C2](../network/beaconing-c2.md), [credential dumping](../adversary/lsass-dumping.md), [lateral movement](../adversary/psexec-smb.md), [phishing delivery](../adversary/phishing-delivery.md). The group was likely in for days.
- **Exfiltration** (double extortion): large uploads before encryption — [data exfiltration playbook](data-exfiltration.md), [SRUM](../windows/srum.md), Zeek `orig_bytes`.

## 4. Contain / Eradicate

- Isolate all affected and adjacent hosts; disable the account(s) and mechanism used to deploy (GPO, service, task).
- **Reset credentials domain-wide** if a DC or domain admin was involved — assume every hash was dumped ([LSASS](../adversary/lsass-dumping.md)); rotate `krbtgt` **twice**.
- Remove persistence on every touched host ([Autoruns / ASEP](../adversary/persistence.md)).
- Block C2 and exfil infrastructure at egress.
- Do not bring hosts back until you know the initial-access vector is closed, or you get re-encrypted.

## 5. Recover & lessons

- Rebuild from **known-good backups** taken before the dwell period started (verify they're clean and not attacker-tampered). Decryptors exist for some strains — check before assuming total loss, but never trust the attacker's decryptor blindly.
- Restore in a **cleaned, credential-reset** environment, not the compromised one.
- Report per legal/regulatory obligation (in Australia, consider the OAIC Notifiable Data Breaches scheme and any sector rules; escalate to leadership/legal early).
- Post-incident: patch the initial vector, deploy/expand EDR + Sysmon, enable [script-block logging](../adversary/powershell-cradles.md), protect backups (offline/immutable), and tier admin accounts.

## Useful queries

```spl
index=botsv3 sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventID=1
| eval cmd=lower(CommandLine)
| where match(cmd,"vssadmin.*delete|wbadmin.*delete|bcdedit.*(recoveryenabled|bootstatuspolicy)|wevtutil\s+cl|wmic.*shadowcopy.*delete|shadowcopy delete")
| table _time, host, User, Image, cmd
| sort 0 _time
```

Shadow-copy and backup deletion almost always immediately precedes encryption. `vssadmin delete shadows` removes restore points, `bcdedit /set recoveryenabled no` disables Windows recovery, `wevtutil cl` clears logs — finding the host and time of these commands pinpoints the deployment moment and host.

```spl
index=botsv3 sourcetype="WinEventLog:System" EventCode=7045
| table _time, host, Service_Name, Service_File_Name | sort 0 _time
```

Many ransomware families and their deployment tools (PsExec) install a service — `7045` across many hosts in a tight window shows the push.

## References

- [No More Ransom (decryptors + ID)](https://www.nomoreransom.org/) · [ID Ransomware](https://id-ransomware.malwarehunterteam.com/)
- [CISA — #StopRansomware guide](https://www.cisa.gov/stopransomware)
- [OAIC — Notifiable Data Breaches (AU)](https://www.oaic.gov.au/privacy/notifiable-data-breaches)
- Pages: [MFT/USN](../windows/mft-usn.md) · [PsExec/SMB](../adversary/psexec-smb.md) · [LSASS dumping](../adversary/lsass-dumping.md) · [Data exfiltration](data-exfiltration.md)

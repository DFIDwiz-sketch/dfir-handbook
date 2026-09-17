---
title: Lateral Movement & Domain Compromise
tags:
  - playbook
  - lateral-movement
  - active-directory
---

# Lateral Movement & Domain Compromise

<div class="dfir-meta" markdown>
**Scenario:** Attacker moving host-to-host, or Domain Admin / DC compromise suspected · **Last updated:** 2026-09-17
</div>

!!! abstract "When to use this"
    Evidence that an attacker is no longer on one box — logons appearing across hosts with one account, admin shares accessed, services installed remotely, or signs the domain itself is compromised (DCSync, golden ticket, `krbtgt` concerns, mass GPO changes). This is the highest-stakes on-prem scenario: if the domain is owned, **every credential and every host is suspect**.

## 1. Triage (first 15 minutes)

- Establish **which accounts** and **which hosts** are involved so far. Is a **privileged** account (Domain Admin, or a service account with wide rights) implicated?
- Look for the **choke-point** technique: [LSASS dumping](../adversary/lsass-dumping.md) (creds stolen), then [Pass-the-Hash](../adversary/pass-the-hash.md) / [Kerberoasting](../adversary/kerberoasting.md) (creds used), then [PsExec/WMI/WinRM](../adversary/psexec-smb.md) (movement).
- Check for **domain-level** compromise signs: DCSync (replication from a non-DC), `krbtgt` activity, new Domain Admins, GPO changes pushing payloads.
- Do **not** start resetting everything blindly yet — scope first so containment is complete and simultaneous, or the attacker re-enters.

## 2. Collect

| Source | What | Where |
|---|---|---|
| **DC** Security logs | Kerberos/NTLM auth for the whole domain | `4768/4769/4771/4776`, `4662` (DCSync), `4720/4728/4732` (account/group changes) |
| Each involved host | Logon + execution + service artifacts | [KAPE](../tools/kape.md) / [Velociraptor fleet hunt](../tools/velociraptor.md) |
| AD | Group membership, ACL changes, new objects | AD audit, BloodHound collection for attack paths |
| Network | Internal auth & movement | [Zeek](../network/index.md) `ntlm.log`, `kerberos.log`, `smb_files.log`, internal `445/135/3389/5985` |

Velociraptor is ideal here — hunt one artifact (e.g. `Windows.EventLogs.RDPAuth`, LSASS-access, a specific service name) across **all** hosts at once.

## 3. Analyse — map the movement graph

- **Credential theft points**: where was [LSASS dumped](../adversary/lsass-dumping.md)? Every host with Sysmon 10 LSASS access is a place creds were harvested.
- **Which credential, where used**: pivot each compromised account through [4624 type 3 NTLM](../adversary/pass-the-hash.md) and [4648](../splunk/security-searches.md) to see every host it reached. Build the **source→target graph** ([Arkime Connections view](../network/arkime/hunting-workflows.md#workflow-3-lateral-movement-with-connections) does this visually).
- **Movement technique per hop**: [PsExec `7045`+`5145`](../adversary/psexec-smb.md), [WMI/WinRM parents](../adversary/wmi-winrm.md), RDP `4624/10`+`4778`.
- **Domain compromise**:
    - **DCSync**: `4662` on a DC with replication GUIDs (`DS-Replication-Get-Changes`) from a non-DC account, or Zeek/Arkime `drsuapi` RPC — someone pulling password hashes from AD.
    - **Golden/silver ticket**: TGTs/TGS with anomalies (lifetime, missing `4768` for a ticket that's in use, encryption downgrades). If `krbtgt` may be stolen, a golden ticket grants domain-wide access invisibly.
    - **New privileged accounts / group changes**: `4720`→`4732` into Domain Admins; `4728` into privileged global groups.
    - **AdminSDHolder / ACL backdoors, GPO abuse**: persistence at the domain level.

## 4. Contain / Eradicate

Containment must be **coordinated and near-simultaneous**, or the attacker moves as you clean:

- Isolate all known compromised hosts at once.
- **Reset credentials**: every account the attacker touched, all privileged accounts, and — if the DC or a domain admin was compromised — **reset `krbtgt` twice** (two resets, waited out, invalidate golden tickets), then plan a broader tiered reset.
- Remove attacker-created accounts, group memberships, ACL changes, GPOs, and persistence on every host.
- Revoke Kerberos tickets where possible; block C2/exfil.
- Rebuild DCs from clean media if DC-level compromise is confirmed — you cannot trust a compromised DC.

## 5. Recover & lessons

- Restore into a **tiered, credential-reset** environment. Validate AD integrity (no lingering backdoor ACLs/GPOs/accounts) with BloodHound and AD audits.
- Harden: **tier 0/1/2 admin model** (workstation creds can't reach servers/DCs), LAPS, Protected Users group, LSASS protection + Credential Guard, disable NTLM where possible, AES Kerberos, monitor `4662` DCSync and `4768/4769` anomalies, and privileged-access workstations for admins.

## Useful queries

```spl
index=botsv3 sourcetype=WinEventLog EventCode=4624 Logon_Type=3 Authentication_Package=NTLM
| eval user=mvindex(Account_Name,1)
| where NOT match(user,"\\$$")
| stats dc(host) as targets, values(host) as where_to, values(Source_Network_Address) as from by user
| where targets >= 3
| sort - targets
```

`4624 type 3` = network logon, `NTLM` package. One non-computer account authenticating to three or more distinct hosts over NTLM is the lateral-movement fan-out — `values(host)` lists where it went and `values(Source_Network_Address)` where from. See [Pass-the-Hash](../adversary/pass-the-hash.md).

```spl
index=botsv3 sourcetype=WinEventLog EventCode=4662 Access_Mask=0x100
| where match(Properties,"(?i)DS-Replication-Get-Changes|1131f6a|9923a32a")
| table _time, host, Account_Name, Object_Name, Properties
```

`4662` on a DC with the replication extended-right GUIDs (`DS-Replication-Get-Changes-All`) from an account that isn't a DC is **DCSync** — the attacker is pulling password hashes straight from Active Directory. Any non-DC, non-service account here is critical.

```spl
index=botsv3 sourcetype=WinEventLog EventCode IN (4720,4728,4732,4756)
| eval action=case(EventCode==4720,"user created",EventCode==4728,"added to global group",EventCode==4732,"added to local group",EventCode==4756,"added to universal group")
| search Group_Name IN ("Domain Admins","Enterprise Admins","Administrators","Schema Admins") OR EventCode=4720
| table _time, host, Subject_Account_Name, action, Account_Name, Member_Name, Group_Name
| sort 0 _time
```

New accounts and additions to privileged groups. An addition to Domain/Enterprise Admins outside a change window, especially minutes after a `4720` account creation, is domain persistence.

## References

- [MITRE ATT&CK — Lateral Movement (TA0008)](https://attack.mitre.org/tactics/TA0008/) · [DCSync T1003.006](https://attack.mitre.org/techniques/T1003/006/)
- [Microsoft — krbtgt reset guidance](https://learn.microsoft.com/en-us/defender-for-identity/) · [AD tiered admin model](https://learn.microsoft.com/en-us/security/privileged-access-workstations/)
- Pages: [Pass-the-Hash](../adversary/pass-the-hash.md) · [Kerberoasting](../adversary/kerberoasting.md) · [PsExec/SMB](../adversary/psexec-smb.md) · [WMI/WinRM](../adversary/wmi-winrm.md) · [LSASS dumping](../adversary/lsass-dumping.md) · [Arkime Connections](../network/arkime/hunting-workflows.md)

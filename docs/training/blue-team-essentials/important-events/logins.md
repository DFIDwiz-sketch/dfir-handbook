---
title: "Login Events — 4624/4625 and Logon Types, 4648 Explicit Credentials, Linux Logins and Login Failures"
tags:
  - training
  - blue-team
  - windows
  - linux
  - logging
  - authentication
---

# Login Events — 4624/4625 and Logon Types, 4648 Explicit Credentials, Linux Logins and Login Failures { #logins }

!!! abstract "What this page covers"
    The login events every analyst reads daily. Windows **4624** (successful logon) and **4625** (failed logon): a full event field by field, what *Account Domain* really tells you (a domain name or a computer name), every **logon type** and what each one means for an investigation, the **Logon ID** that ties a logon to everything the session did, how to cut the enormous noise from computer accounts and system logons, and the **Status/SubStatus** codes that explain why a logon failed. **4648** (logon with explicit credentials, the "runas" event): who did it, which account they borrowed, and against which server — and why it is logged on the *source* machine. Then Linux: how an SSH login is spread over several syslog lines tied together by a PID, where those lines live, and the many different shapes a Linux login failure takes. Worked PowerShell and shell commands read line by line, a SOC checklist, the 2026 view and practice questions.

!!! note "Labels"
    **[Supplement]** = practical material you need to know, **[Correction]** = a commonly repeated claim that is wrong or outdated, **[Changed]**/**[Caution]** = what has changed recently and what is risky to do the old way. Hostnames, domains, accounts, IPs and file names are invented for illustration (`.example`, documentation and private IPs).

## The 8 key points { #key-points }

1. **4624** = an account successfully logged on; **4625** = a logon attempt failed. Both are in the **Security** channel and are written on the machine **being logged on to** (the target), not the one the user sits at.
2. The fields that matter most are **who** (`TargetUserName`, `TargetDomainName`), **how** (`LogonType`, `LogonProcessName`, `AuthenticationPackageName`) and **from where** (`IpAddress`, `WorkstationName`). For a local account, the "domain" is the **computer's own name**.
3. **Logon type** tells you the *kind* of logon: 2 console, 3 network (file share, most remote admin tools), 4 batch (scheduled task), 5 service, 7 unlock/reconnect, 8 network with cleartext password, 9 new credentials (`runas /netonly`, also pass-the-hash tools), 10 RDP, 11 cached domain logon. Learn them by heart.
4. **[Correction]** Type 11 is not "a domain account at the keyboard" — that is still type 2. Type 11 means the domain controller could not be reached and Windows used **cached** credentials. And type 2 does not prove physical presence: remote-control tools and `runas` also create type 2.
5. **`TargetLogonId`** is the session's serial number. The same value appears in 4672 (admin privileges), 4688 (processes started), 4634/4647 (logoff) — it links a logon to everything that happened in it.
6. Most 4624s are noise: **computer accounts** (names ending in `$`), `SYSTEM`, `LOCAL SERVICE`, `DWM-*`, `UMFD-*`, `ANONYMOUS LOGON`. Filter them for hunting, but never delete them from collection — attackers abuse machine accounts too.
7. **4648** = a process used **explicit credentials** — "user X ran something as account Y against server Z". It is logged on the **source** machine, so it shows where a stolen account is being used *from*. Unusual X→Y pairs are a classic lateral-movement signal.
8. Linux has no event ID for logins. An SSH login is **several lines** from `sshd` (and PAM) tied by the **PID**, in `/var/log/auth.log`, `/var/log/secure` or the journal; failures come in many wordings (`Invalid user`, `Failed password`, `authentication failure`) that each need their own search pattern.

## Why login events matter { #why }

Almost every intrusion has to log on somewhere. A phished user's session, a stolen password sprayed at the VPN, a service account reused on a file server, a hijacked admin moving from desktop to server — each of these leaves a login record. An attacker can bring new malware and you may never see it, but if they want to *use* an account they must authenticate, and the system writes that down.

Think of a building with a guest book at every door. The guest book does not tell you what a visitor did inside, but it tells you who came in, which door they used (front door, loading dock, side window), when, and where they came from. Join up the books from every door and you can trace someone moving through the building. Login events are those guest books: **4624/4625** are the entries, **logon type** is the door, `IpAddress` is "arrived from", and the **Logon ID** is the visitor badge number that lets you match what they did inside.

Back to the technical reality: on Windows, logins are written by the Local Security Authority (LSA) into the **Security** channel when the audit subcategory **Logon** (under *Logon/Logoff*) is enabled. On Linux they are written by `sshd`, `login`, display managers and PAM through syslog or the systemd journal. The rest of this page is learning to read those entries quickly and correctly.

## Windows 4624: a successful logon { #4624 }

### When it fires { #4624-when }

Event **4624 — "An account was successfully logged on"** is written by the computer that *accepted* the logon, every time a new logon session is created. Sitting at the keyboard, opening a file share, a scheduled task starting, a service starting under its own account, a web server checking a password, an RDP connection — all of these create a 4624 on the machine that received them. That is why it is one of the most frequent events in any Windows estate: domain controllers and file servers can write thousands per minute.

Attackers care about it because it records their **use of valid accounts** (MITRE ATT&CK **T1078**, Valid Accounts; **T1078.002** domain accounts, **T1078.003** local accounts) and their **lateral movement** — remote logons over SMB (**T1021.002**), RDP (**T1021.001**) or WinRM (**T1021.006**) all leave a 4624 on the target.

### A complete event { #4624-sample }

A user `CORP\j.park` maps a share on file server `FS-02` from workstation `WS-114` (`10.20.7.31`). The EventData section of the 4624 on `FS-02` looks like this (System section shortened; see [Windows event structure](../windows-logging/event-structure-channels.md) for the full layout):

```xml
<System>
  <EventID>4624</EventID>
  <TimeCreated SystemTime="2026-11-20T01:12:44.1904530Z" />
  <Channel>Security</Channel>
  <Computer>FS-02.corp.example</Computer>
</System>
<EventData>
  <Data Name="SubjectUserSid">S-1-0-0</Data>
  <Data Name="SubjectUserName">-</Data>
  <Data Name="SubjectDomainName">-</Data>
  <Data Name="SubjectLogonId">0x0</Data>
  <Data Name="TargetUserSid">S-1-5-21-1004336348-1177238915-682003330-3108</Data>
  <Data Name="TargetUserName">j.park</Data>
  <Data Name="TargetDomainName">CORP</Data>
  <Data Name="TargetLogonId">0x2a91c7f</Data>
  <Data Name="LogonType">3</Data>
  <Data Name="LogonProcessName">Kerberos</Data>
  <Data Name="AuthenticationPackageName">Kerberos</Data>
  <Data Name="WorkstationName">-</Data>
  <Data Name="LogonGuid">{3f0d2a6e-9b41-0c55-7e12-8a4d6b2f1c90}</Data>
  <Data Name="TransmittedServices">-</Data>
  <Data Name="LmPackageName">-</Data>
  <Data Name="KeyLength">0</Data>
  <Data Name="ProcessId">0x0</Data>
  <Data Name="ProcessName">-</Data>
  <Data Name="IpAddress">10.20.7.31</Data>
  <Data Name="IpPort">51522</Data>
  <Data Name="ImpersonationLevel">%%1833</Data>
  <Data Name="RestrictedAdminMode">-</Data>
  <Data Name="TargetOutboundUserName">-</Data>
  <Data Name="TargetOutboundDomainName">-</Data>
  <Data Name="VirtualAccount">%%1843</Data>
  <Data Name="TargetLinkedLogonId">0x0</Data>
  <Data Name="ElevatedToken">%%1843</Data>
</EventData>
```

In Event Viewer's friendly view the same data is grouped under headings such as *Subject*, *Logon Information*, *New Logon*, *Process Information*, *Network Information* and *Detailed Authentication Information*. The `%%` numbers are message codes that the viewer replaces with words: `%%1842` = Yes, `%%1843` = No, `%%1833` = Impersonation.

### Field by field { #4624-fields }

- `SubjectUserSid` / `SubjectUserName` / `SubjectLogonId` — the account *on this machine* that requested the logon. For a network logon the request came from outside, so it is empty (`S-1-0-0`, `-`, `0x0`). For a console or RDP logon it is usually the computer itself (`S-1-5-18`, `FS-02$`, `0x3e7`) — Windows' `winlogon` asking LSA to log the user in. Don't mistake the subject for the person logging on.
- `TargetUserSid` / `TargetUserName` — **who logged on.** This is the account name you hunt on. The SID is more reliable than the name (names can be renamed, SIDs cannot).
- `TargetDomainName` — the account's **authority**. For a domain account it is the domain (`CORP`). For a **local** account it is the **computer name** — the local administrator on `WS-114` appears as `WS-114\Administrator`. Writing it as `DOMAIN\user` makes this easy to see: `CORP\j.park` is a domain user; `FS-02\backupadm` is an account that exists only on that one server. A local account logging on over the network to many machines is a red flag for shared local admin passwords being abused (a pass-the-hash favourite).
- `TargetLogonId` — the new session's **Logon ID** (`0x2a91c7f`). Remember it: you will search for it in other events.
- `LogonType` — **what kind of logon** (next section). `3` = network.
- `LogonProcessName` — the trusted process that handled the logon: `User32` (interactive/RDP via `winlogon`), `NtLmSsp` (NTLM), `Kerberos`, `Advapi` (API logons such as services, IIS, some scripts), `seclogo` (Secondary Logon service — `runas`).
- `AuthenticationPackageName` — the protocol: `Kerberos`, `NTLM` or `Negotiate` (picks between them). With `NTLM`, `LmPackageName` shows the version (`NTLM V2`, or `NTLM V1` — a weakness worth reporting).
- `WorkstationName` — the name the client *claims* for itself. Kerberos network logons often leave it blank; NTLM fills it in. It is supplied by the client, so attacker tools can set it to anything — trust it less than `IpAddress`.
- `ProcessId` / `ProcessName` — the local process that made the logon (for example `C:\Windows\System32\svchost.exe` for RDP, `C:\Windows\System32\services.exe` for services). Empty for network logons.
- `IpAddress` / `IpPort` — **where the logon came from.** For network and RDP logons this is the client's address — the field you pivot on to follow movement. `-` or `127.0.0.1`/`::1` means a local logon.
- `ImpersonationLevel` — how far the server may act as the user. `Delegation` (`%%1840`) means the server can pass the identity on to other servers — normal for some services, interesting when it is unexpected.
- `RestrictedAdminMode` — for RDP, whether *Restricted Admin* was used (credentials not sent to the server).
- `VirtualAccount` — whether the account is a virtual service account.
- `ElevatedToken` / `TargetLinkedLogonId` — whether the session got a full administrator token. When an admin logs on interactively with User Account Control, Windows creates **two linked sessions** (one filtered, one elevated) — you will see two 4624s pointing at each other's Logon ID. That is normal, not a double logon.

### Logon types { #logon-types }

Not all logons are equal. The logon type is the single most useful field for telling "Jin opened a share" from "someone RDP'd into the server" from "a service started".

| Type | Name | What causes it | Investigation meaning |
| --- | --- | --- | --- |
| 2 | Interactive | Logging on at the console; `runas` (without `/netonly`); many remote-control tools (VNC-style, remote support) because they drive the console | Someone used the desktop of *this* machine. Not proof of physical presence. |
| 3 | Network | Accessing a share (`\\FS-02\finance`), `net use`, PsExec-style service creation, WMI, WinRM/PowerShell remoting, most RPC | The most common lateral-movement type. Follow `IpAddress`. No credentials are left in memory on the target. |
| 4 | Batch | Scheduled tasks running as a user | New task + new account = possible persistence (**T1053.005**). |
| 5 | Service | A service starting under its configured account | Expected for known services; a new service account or a user account used as a service is worth a look (pair with 7045). |
| 7 | Unlock | Unlocking a locked workstation; reconnecting to an existing RDP session | Usually benign; for RDP it can replace a type 10 on reconnection. |
| 8 | NetworkCleartext | The password reached the server in clear text: IIS Basic authentication, LDAP simple binds on a DC | A protocol is exposing passwords — a finding by itself. |
| 9 | NewCredentials | `runas /netonly`, and pass-the-hash / overpass-the-hash tools that start a process with injected credentials (`LogonProcessName` = `seclogo`) | Local identity stays the same; the borrowed credentials are used only on the network. Rare in normal use — high-value hunting field (**T1550.002**). |
| 10 | RemoteInteractive | Remote Desktop | Someone had a full desktop over the network (**T1021.001**). Watch for RDP between workstations or from unusual sources. |
| 11 | CachedInteractive | Domain user logging on at the console when no domain controller could be reached (laptop offline) | Windows used cached credentials. Expected for travellers. |
| 12 | CachedRemoteInteractive | Like 11, but over RDP | Rare. |
| 13 | CachedUnlock | Unlock using cached credentials | Rare. |

**[Correction]** You will often see "a domain account at the keyboard is type 11". It is not: with the domain controller reachable, a domain user at the console is a **type 2**, exactly like a local user. Type 11 only appears when cached credentials are used. Similarly, "type 2 means the attacker has physical access" is too strong — an attacker with a remote-control tool, or one who runs `runas`, also creates type 2. Read type 2 as "this logon happened on this machine's own desktop session", then look at the parent process and network activity to see how.

**[Supplement] RDP leaves more than one logon.** With Network Level Authentication (the default), the server first checks credentials as a **type 3** logon, then creates the desktop session as **type 10**. Reconnecting to a disconnected session can appear as type 7. The RDP-specific channels (`Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational` event 1149, `LocalSessionManager/Operational` 21/24/25) fill in the rest — see [SSH, RDP, VNC](../other-protocols/ssh-rdp-vnc.md).

### The Logon ID: following one session { #logon-id }

`TargetLogonId` is like the wristband number at a hospital: every test and treatment the patient gets is labelled with it. Windows stamps the same number on later events:

| Event | Field carrying the Logon ID | What it adds |
| --- | --- | --- |
| 4672 — special privileges assigned to new logon | `SubjectLogonId` | The session has admin-level rights (SeDebugPrivilege etc.). Written right after 4624 for administrators. |
| 4688 — a new process was created | `SubjectLogonId` | Every program started in the session (when process auditing is on). |
| 4634 — an account was logged off / 4647 — user initiated logoff | `TargetLogonId` | When the session ended — gives the session length. |
| 4648 — logon with explicit credentials | `SubjectLogonId` | The session borrowed another account. |

So the workflow is: find the suspicious 4624 → copy `TargetLogonId` → search the same computer's events for that value → read what that session did. Logon IDs are only unique **per computer and per boot**, so always search together with the computer name.

### Cutting the noise { #noise }

On a domain controller, the overwhelming majority of 4624s come from **computer accounts** — each machine has an account (`WS-114$`, `FS-02$`) and logs on to the domain constantly to fetch policy and tickets. Other common sources of noise are `SYSTEM` (`S-1-5-18`), `LOCAL SERVICE`, `NETWORK SERVICE`, `DWM-1`/`DWM-2` (Desktop Window Manager) and `UMFD-0`/`UMFD-1` (font driver host), created at every interactive logon, and `ANONYMOUS LOGON` network sessions.

A practical first filter for hunting user activity is: drop `TargetUserName` ending in `$`, drop the well-known service identities, keep types 2, 3, 7, 9, 10 and 11. Here is that filter run against a local Security log with PowerShell:

```powershell
Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4624; StartTime=(Get-Date).AddHours(-24)} |
  ForEach-Object {
    $d = @{}; ([xml]$_.ToXml()).Event.EventData.Data | ForEach-Object { $d[$_.Name] = $_.'#text' }
    [pscustomobject]@{ Time=$_.TimeCreated; User="$($d.TargetDomainName)\$($d.TargetUserName)";
                       Type=$d.LogonType; Auth=$d.AuthenticationPackageName; From=$d.IpAddress; LogonId=$d.TargetLogonId }
  } |
  Where-Object { $_.User -notmatch '\$$' -and $_.User -notmatch '\\(SYSTEM|LOCAL SERVICE|NETWORK SERVICE|DWM-\d+|UMFD-\d+|ANONYMOUS LOGON)$' -and $_.Type -in '2','3','7','9','10','11' } |
  Format-Table -AutoSize
```

Line by line:

- `Get-WinEvent -FilterHashtable @{...}` — reads events, with the filtering done by the event log service (fast). `LogName='Security'` picks the channel, `Id=4624` the event, `StartTime=(Get-Date).AddHours(-24)` the last 24 hours.
- `ForEach-Object { ... }` — for each event:
    - `$d = @{}` makes an empty dictionary; `([xml]$_.ToXml()).Event.EventData.Data` turns the event into XML and walks every `<Data Name="...">` element; `$d[$_.Name] = $_.'#text'` stores each field by name. This is reading fields by name, never by parsing the message text.
    - `[pscustomobject]@{...}` builds one tidy row: time, `DOMAIN\user`, type, authentication package, source IP and Logon ID.
- `Where-Object { ... }` — keeps rows where the user does not end in `$` (`'\$$'` = a literal `$` at the end), is not one of the built-in identities, and the type is one we care about.
- `Format-Table -AutoSize` — prints a table.

What the output looks like on `FS-02`:

```
Time                  User               Type Auth     From         LogonId
----                  ----               ---- ----     ----         -------
20/11/2026 1:12:44 AM CORP\j.park        3    Kerberos 10.20.7.31   0x2a91c7f
20/11/2026 1:40:02 AM CORP\svc_scan      3    NTLM     10.20.9.200  0x2b02a11
20/11/2026 2:03:17 AM FS-02\backupadm    3    NTLM     10.20.7.88   0x2b11e40
20/11/2026 2:03:19 AM FS-02\backupadm    10   Negotiate 10.20.7.88  0x2b11f9d
```

Reading it: `j.park` opening a share is ordinary. `svc_scan` from the scanner's address with NTLM is probably the vulnerability scanner — confirm and allow-list it. The last two rows are the interesting ones: a **local** account of `FS-02` (`FS-02\backupadm`) logging on over the network and then by **RDP**, from a workstation (`10.20.7.88`) rather than an admin jump host. Next step: search `0x2b11f9d` in 4688 on `FS-02` to see what was run, and look for the same local account on other servers.

**[Caution]** Filtering computer accounts is for *hunting*, not for *collection*. Machine accounts are abused in real attacks (relayed machine authentication, forged service tickets, resource-based constrained delegation abuse), and a machine account logging on from an IP that is not that machine is itself a strong signal. Keep the events; filter in the query.

## Windows 4625: a failed logon { #4625 }

### When it fires { #4625-when }

**4625 — "An account failed to log on"** is written by the machine that refused the logon: a mistyped password at the console, a share connection with a bad password, an RDP attempt, a service whose stored password has expired. It has nearly the same fields as 4624 plus three that say *why* it failed: `Status`, `SubStatus` and `FailureReason`. Failures need the *Logon* subcategory's **Failure** auditing enabled — check your audit policy rather than assuming it is on.

Attackers generate 4625 when guessing (**T1110.001**, Password Guessing), spraying one password across many accounts (**T1110.003**, Password Spraying) or trying stolen credentials that turn out to be stale (**T1110.004**, Credential Stuffing).

### A sample { #4625-sample }

An RDP-exposed jump server `JMP-01` receives a guess from the internet:

```xml
<EventData>
  <Data Name="SubjectUserSid">S-1-0-0</Data>
  <Data Name="TargetUserSid">S-1-0-0</Data>
  <Data Name="TargetUserName">administrator</Data>
  <Data Name="TargetDomainName">JMP-01</Data>
  <Data Name="Status">0xc000006d</Data>
  <Data Name="FailureReason">%%2313</Data>
  <Data Name="SubStatus">0xc000006a</Data>
  <Data Name="LogonType">3</Data>
  <Data Name="LogonProcessName">NtLmSsp </Data>
  <Data Name="AuthenticationPackageName">NTLM</Data>
  <Data Name="WorkstationName">KALI</Data>
  <Data Name="LmPackageName">-</Data>
  <Data Name="KeyLength">0</Data>
  <Data Name="ProcessName">-</Data>
  <Data Name="IpAddress">203.0.113.77</Data>
  <Data Name="IpPort">0</Data>
</EventData>
```

- `TargetUserSid` `S-1-0-0` — "nobody": the logon never got as far as an account session.
- `TargetUserName` / `TargetDomainName` — the name *attempted* (`administrator`) and, because the attempt was against a local account, the computer name.
- `Status` `0xc000006d` with `FailureReason` `%%2313` ("Unknown user name or bad password") — the general reason. `SubStatus` gives the precise one: `0xc000006a` = the user exists, **the password was wrong**.
- `LogonType` `3` with `NtLmSsp` / `NTLM` — this is how RDP with Network Level Authentication fails: the credential check happens as a network logon before any desktop exists. So failed RDP guessing usually shows type **3**, not 10.
- `WorkstationName` `KALI` — the client's claimed name. A real clue sometimes, but trivially changed.
- `IpAddress` `203.0.113.77` — the source. Many failures from one address = guessing; one failure per account across many accounts from one or a few addresses = spraying.

### Status and SubStatus codes { #status-codes }

| Code | Meaning | What it suggests |
| --- | --- | --- |
| `0xc0000064` | User name does not exist | Username guessing or a typo; many different names = enumeration |
| `0xc000006a` | Correct user, wrong password | Password guessing against a real account |
| `0xc0000234` | Account locked out | The guessing has already tripped the lockout (look for 4740 on the DC) |
| `0xc0000072` | Account disabled | Someone is trying an account that was switched off — stale stolen credentials, or a leaver |
| `0xc0000193` | Account expired | Similar to disabled |
| `0xc0000071` | Password expired | Often a service with an old password — or an attacker with an old one |
| `0xc0000224` | User must change password at next logon | Usually benign |
| `0xc000006f` | Logon outside allowed hours | Policy hit |
| `0xc0000070` | Logon from a workstation not allowed for this account | Restricted admin accounts being tried elsewhere — interesting |
| `0xc000015b` | Logon type not granted (e.g. "deny log on through RDP") | Someone tried an account in a way policy forbids — very interesting for admin and service accounts |
| `0xc0000133` | Clock difference too large | Time sync problem, usually Kerberos |

**[Supplement] Where domain failures also show up.** When the account is a domain account, the domain controller logs its own view: **4771** (Kerberos pre-authentication failed — failure code `0x18` = bad password) and **4776** (NTLM credential validation, with an error code). Spraying against many hosts is often easiest to see on the DCs, because every attempt ends there. Kerberos events are covered in a later page of this section.

## Windows 4648: logon with explicit credentials { #4648 }

### What it is { #4648-what }

Linux users know `sudo` and `su`: "run this as someone else". Windows has the equivalent — `runas`, "Run as different user", `net use \\server\share /user:...`, PsExec with `-u`, saved RDP credentials, and API calls that pass a username and password to start a process or connect to a server. Whenever a process **uses credentials other than those of the logged-on user**, Windows writes **4648 — "A logon was attempted using explicit credentials"**.

The crucial difference from 4624: 4648 is written on the **source** machine — the one where the credentials were *typed or injected* — not on the target. So the pair "4648 on `WS-114` naming `FS-02`" + "4624 type 3 on `FS-02` from `WS-114`'s IP" lets you stitch both ends of a hop together.

### A sample { #4648-sample }

```xml
<EventData>
  <Data Name="SubjectUserSid">S-1-5-21-1004336348-1177238915-682003330-3108</Data>
  <Data Name="SubjectUserName">j.park</Data>
  <Data Name="SubjectDomainName">CORP</Data>
  <Data Name="SubjectLogonId">0x1c3e9a0</Data>
  <Data Name="LogonGuid">{00000000-0000-0000-0000-000000000000}</Data>
  <Data Name="TargetUserName">adm.lee</Data>
  <Data Name="TargetDomainName">CORP</Data>
  <Data Name="TargetLogonGuid">{00000000-0000-0000-0000-000000000000}</Data>
  <Data Name="TargetServerName">FS-02.corp.example</Data>
  <Data Name="TargetInfo">FS-02.corp.example</Data>
  <Data Name="ProcessId">0x1f24</Data>
  <Data Name="ProcessName">C:\Windows\System32\net.exe</Data>
  <Data Name="IpAddress">-</Data>
  <Data Name="IpPort">-</Data>
</EventData>
```

- `SubjectUserName` `j.park` / `SubjectLogonId` — **who** did it: the user whose session ran the command (and the session, so you can find the 4688 that started `net.exe`).
- `TargetUserName` / `TargetDomainName` `CORP\adm.lee` — **which account's credentials were used** ("Account Whose Credentials Were Used" in the friendly view).
- `TargetServerName` / `TargetInfo` — **where** they were used: here the file server. For a local `runas` it is `localhost`.
- `ProcessName` — **what** used them: `net.exe` (a `net use` with `/user:`). `runas.exe`, `mstsc.exe` (RDP client), `svchost.exe` (scheduled tasks, services), `lsass.exe`, `consent.exe` (UAC credential prompt) are other common values. A script host or an unknown binary here is suspicious.

### How it catches an attacker { #4648-use }

Imagine an attacker has a backdoor on `WS-114`, Jin's laptop, and has also stolen the password of `adm.lee`, a server administrator. From Jin's session they cannot read the finance share — so they "become" `adm.lee` with `runas` or `net use /user:CORP\adm.lee`. The 4648 above is the result: Jin's session using an administrator's credentials against a server. If you know that `adm.lee` should only ever be used from the admin jump hosts, this is an anomaly you can alert on directly: *subject account ≠ target account, target account is privileged, source host is not an admin host.*

Mapping to ATT&CK: using stolen credentials is **T1078** (Valid Accounts); creating a process as another user with `runas` falls under **T1134.002** (Access Token Manipulation: Create Process with Token); the hop to the server is lateral movement such as **T1021.002**. A 4624 **type 9** (`seclogo`) next to a 4648 on the same machine is what `runas /netonly` — and many pass-the-hash tools — look like.

**[Caution]** 4648 is noisier than its reputation: UAC prompts where an admin types credentials, scheduled tasks, some backup and management agents, and the RDP client with saved credentials all generate it. Baseline the normal `ProcessName` + `TargetUserName` pairs per host role, then alert on the rest.

## Linux logins { #linux-logins }

### One login, several lines { #linux-multiline }

Linux logins are easier for a human to read and harder for a SIEM to parse. There is no event ID and no fixed schema: the login is written as free-text syslog messages, and a single SSH login is split across **several lines** of partial information, mixed in with every other authentication message on the system. On Debian/Ubuntu they land in **`/var/log/auth.log`**, on Red Hat-style systems in **`/var/log/secure`**, and on journald-only systems (such as Debian 12 and later without rsyslog) only in the **journal** — see [Linux log files and the journal](../linux-logging/log-files-journal.md).

A key-based SSH login to `web-01`:

```
Nov 20 03:02:11 web-01 sshd[4590]: Connection from 198.51.100.61 port 57356 on 10.20.30.41 port 22 rdomain ""
Nov 20 03:02:11 web-01 sshd[4590]: Postponed publickey for deploy from 198.51.100.61 port 57356 ssh2 [preauth]
Nov 20 03:02:11 web-01 sshd[4590]: Accepted publickey for deploy from 198.51.100.61 port 57356 ssh2: ED25519 SHA256:kq3V0bXa1nYv7k0Lr2Wc9mT4Jt8sQ1eZpHfUo6dNgAs
Nov 20 03:02:11 web-01 sshd[4590]: pam_unix(sshd:session): session opened for user deploy(uid=1003) by deploy(uid=0)
Nov 20 03:02:11 web-01 systemd-logind[612]: New session 57 of user deploy.
Nov 20 03:02:11 web-01 sshd[4590]: Starting session: shell on pts/0 for deploy from 198.51.100.61 port 57356 id 0
```

Line by line:

- `sshd[4590]: Connection from 198.51.100.61 port 57356 on 10.20.30.41 port 22` — a TCP connection arrived (shown at higher `LogLevel`, such as `VERBOSE`). Client address and port, then the server's own address and port. **`[4590]` is the PID** — the thread that ties every following line together.
- `Postponed publickey for deploy ... [preauth]` — the client offered a public key; the server asked it to prove it holds the private key. `[preauth]` = still before authentication.
- `Accepted publickey for deploy from 198.51.100.61 ... ED25519 SHA256:kq3V...` — **the authentication succeeded**: method (`publickey`, or `password`, `keyboard-interactive`), user, source, and the **key fingerprint**. This one line carries most of the story; the fingerprint tells you *which* key was used, so you can check it against `~deploy/.ssh/authorized_keys` (an unknown key there is persistence, **T1098.004**).
- `pam_unix(sshd:session): session opened for user deploy(uid=1003)` — PAM (Pluggable Authentication Modules), the shared authentication layer most Linux programs use, opened the session. PAM lines look the same whether the program is `sshd`, `sudo`, `su`, `cron` or a display manager — the program is in brackets (`sshd:session`).
- `systemd-logind[612]: New session 57 of user deploy.` — the login manager registered session 57. Different program, different PID — correlating by time and user is needed here.
- `Starting session: shell on pts/0 for deploy ...` — a shell on pseudo-terminal `pts/0`. At logout you will see `Disconnected from user deploy ...` and `session closed for user deploy`.

Successful remote logins to Linux map to the same ATT&CK techniques as on Windows: **T1078** (Valid Accounts) and, for SSH as a lateral-movement channel, **T1021.004**.

To pull all lines of one login together, search the PID:

```
grep 'sshd\[4590\]' /var/log/auth.log
journalctl _PID=4590
```

- `grep 'sshd\[4590\]'` — the backslashes make `[` and `]` literal, so this matches only lines from that sshd process.
- `journalctl _PID=4590` — the journal equivalent; `_PID` is a trusted field set by journald, so it cannot be forged by the sender.

**[Changed]** Since OpenSSH 9.8, per-connection work runs in a separate binary, `sshd-session`. On distributions with that version many of these lines are tagged `sshd-session[4590]:` instead of `sshd[4590]:`. Parsers and alerts that match the literal text `sshd[` need updating to catch both.

### Local and desktop logins { #linux-local }

Logins at the console or a graphical login screen come from different programs and look different: `login[...]` for a text console, `gdm-password]`, `lightdm` or `sddm` for desktops, each through PAM:

```
Nov 20 08:15:42 lab-ws3 gdm-password]: pam_unix(gdm-password:session): session opened for user m.choi(uid=1001) by (uid=0)
```

The PAM service name (`gdm-password`) tells you the door; `uid=1001` identifies the account. There is no source IP, because there is no network.

## Linux login failures { #linux-failures }

Windows has one ID for failures (4625). Linux has none, so you must know the **shape** of each kind of failure, from each kind of login program, and search for all of them:

```
Nov 20 03:10:02 web-01 sshd[4711]: Invalid user oracle from 203.0.113.45 port 40122
Nov 20 03:10:04 web-01 sshd[4711]: Failed password for invalid user oracle from 203.0.113.45 port 40122 ssh2
Nov 20 03:10:09 web-01 sshd[4715]: Failed password for root from 203.0.113.45 port 40130 ssh2
Nov 20 03:10:15 web-01 sshd[4715]: error: maximum authentication attempts exceeded for root from 203.0.113.45 port 40130 ssh2 [preauth]
Nov 20 03:12:30 web-01 sshd[4730]: Connection closed by authenticating user deploy 203.0.113.45 port 40166 [preauth]
Nov 20 08:19:19 lab-ws3 lightdm: pam_unix(lightdm:auth): authentication failure; logname= uid=0 euid=0 tty=:0 ruser= rhost=  user=m.choi
Nov 20 09:01:55 web-01 sudo: pam_unix(sudo:auth): authentication failure; logname=deploy uid=1003 euid=0 tty=/dev/pts/0 ruser=deploy rhost=  user=deploy
Nov 20 09:02:03 web-01 sudo:   deploy : 3 incorrect password attempts ; TTY=pts/0 ; PWD=/home/deploy ; USER=root ; COMMAND=/bin/bash
```

- `Invalid user oracle from 203.0.113.45` — **bad username**: no such account. Lists of common service names (`oracle`, `test`, `pi`, `ubuntu`) from one IP are automated scanning.
- `Failed password for invalid user oracle` — the password attempt that followed for the non-existent account.
- `Failed password for root from 203.0.113.45` — **bad password for a real account** over SSH. Repeated quickly = guessing (**T1110.001**).
- `maximum authentication attempts exceeded for root` — the client hit `MaxAuthTries` in one connection.
- `Connection closed by authenticating user deploy ... [preauth]` — a real user's key or password attempt was abandoned before success. Often a client offering the wrong key; in bulk, a key-spraying tool.
- `lightdm: pam_unix(lightdm:auth): authentication failure; ... tty=:0 ... user=m.choi` — a **bad password on the desktop** login screen. `tty=:0` is the local graphical display; `rhost=` is empty because nobody connected over the network.
- `sudo: pam_unix(sudo:auth): authentication failure; ... user=deploy` and `3 incorrect password attempts` — someone in `deploy`'s session typed the wrong password for sudo three times. After a web compromise, an intruder trying passwords on `sudo` looks exactly like this (privilege escalation attempt).

Note what is **never** logged: the password itself. Remote failures carry the source IP and the username tried; local ones carry the terminal and user.

**[Caution] Passwords in the username field.** Users sometimes type their password into the *username* box. The log then contains `Invalid user <their password> from ...` in clear text. Treat auth logs as sensitive data: restrict who can read them in the SIEM, and expect to find this when you search.

A quick count of SSH failures per source address:

```
grep -hE 'Failed password|Invalid user' /var/log/auth.log /var/log/auth.log.1 |
  grep -oE 'from [0-9a-f.:]+' | sort | uniq -c | sort -rn | head -5
```

- `grep -hE 'Failed password|Invalid user' ...` — finds both failure shapes (`-E` allows `|` for "or"; `-h` hides file names) in the current and last rotated log.
- `grep -oE 'from [0-9a-f.:]+'` — prints only the `from <address>` part (`-o`), IPv4 or IPv6.
- `sort | uniq -c` — groups identical addresses and counts them.
- `sort -rn | head -5` — largest counts first, top five.

Output:

```
    412 from 203.0.113.45
     37 from 198.51.100.200
      3 from 10.20.30.12
```

`203.0.113.45` is clearly guessing. The internal `10.20.30.12` with three failures is probably a person mistyping — unless the next line in the log is an `Accepted` for that same address, in which case read on. The journal equivalent is `journalctl -u ssh --since today -g 'Failed password|Invalid user'` (`-g` greps the message; the unit is `sshd` on Red Hat-style systems).

## Windows and Linux side by side { #comparison }

| | Windows | Linux |
| --- | --- | --- |
| Success | 4624 (Security channel) | `Accepted ... for <user> from <ip>` (sshd), `session opened` (PAM) |
| Failure | 4625 with Status/SubStatus | `Invalid user`, `Failed password`, `authentication failure`, and more |
| Kind of logon | `LogonType` field | Which program wrote it (`sshd`, `login`, `gdm`, `sudo`) and PAM service name |
| Source | `IpAddress`, `WorkstationName` | `from <ip> port <n>`, `rhost=` |
| Session link | `TargetLogonId` | PID, `systemd-logind` session number, auditd `ses`/`auid` |
| Explicit credentials | 4648 | `sudo` / `su` lines |
| Where | Security log on the target | `auth.log` / `secure` / journal on the target |

## Putting it to work in a SOC { #soc-use }

- Confirm audit policy: *Logon* success **and** failure, *Special Logon* (4672) and *Logoff* on all Windows systems; check what actually arrives, not what the GPO says.
- Collect Security logs from **domain controllers, servers and workstations** — 4648 lives on the workstations.
- Normalise: `user`, `domain`, `logon_type`, `src_ip`, `auth_package`, `logon_id`, `host`. Store both name and SID.
- Hunt and alert on: RDP (type 10) between workstations; local accounts (`TargetDomainName` = host name) logging on over the network to many hosts; type 9 with `seclogo` outside known admin tools; NTLM where Kerberos is expected; 4648 where a normal user's session uses a privileged account; failures with `0xc000015b`, `0xc0000070`, `0xc0000072`; many 4625/4771 across many accounts from one source (spraying).
- For Linux: parse `Accepted`/`Failed`/`Invalid user`/`authentication failure` for every login program in use, handle `sshd-session`, and keep key fingerprints.
- Always pivot from a login to what the session did: Logon ID on Windows, PID/session/`auid` on Linux.

## The 2026 view { #trends }

!!! success "[2026 Current] Still valid"
    Events 4624, 4625, 4648, 4672 and 4634/4647, their fields and the logon type numbers are unchanged and remain the foundation of Windows identity investigation. Linux login lines from `sshd` and PAM still look as shown, and still have no event ID. The workflow — find the logon, read its type and source, follow the session ID — is exactly what analysts do today, whether in a SIEM, an EDR console or a timeline tool.

!!! info "[Changed] What has changed"
    - **Identity moved partly to the cloud.** In hybrid and cloud-first organisations many logins never touch a Windows Security log: Microsoft Entra ID sign-in logs (interactive and non-interactive), identity-provider logs and VPN/SSO logs are now as important as 4624. Identity threat detection products (for example Microsoft Defender for Identity) analyse DC authentication traffic and events for you, but the underlying events are the same ones on this page.
    - **NTLM is being retired.** NTLMv1 has been removed from Windows 11 24H2 and Windows Server 2025, those releases added richer NTLM auditing, and Microsoft has published a phased plan to disable NTLM by default in a future release (no fixed date as of late 2026). Expect `AuthenticationPackageName = NTLM` to become rarer — and therefore more meaningful when it appears.
    - **More fields in 4624.** Since Windows 10 / Server 2016 the event includes `ElevatedToken`, `TargetLinkedLogonId`, `VirtualAccount`, `RestrictedAdminMode` and `ImpersonationLevel`; older guides and parsers may miss them.
    - **OpenSSH 9.8 `sshd-session`** and **journald-only distributions** mean Linux login logs may carry a new tag or live only in the journal.

!!! warning "[Caution] Wrong or risky to do the old way"
    - **Don't read type 11 as "domain user at the keyboard"** (that is type 2), and don't read type 2 as proof of physical access.
    - **Don't drop computer-account logons at collection time.** Filter them in queries; machine-account abuse is real.
    - **Don't trust `WorkstationName`.** The client sets it. Prefer `IpAddress`, and check it against DHCP/asset data.
    - **Don't expect RDP brute force to show as type 10.** With NLA it fails as type 3.
    - **Don't look for 4648 on the target.** It is on the machine where the credentials were used from.
    - **Don't assume failure auditing is on.** Verify that 4625 actually arrives from each system.
    - **Treat Linux auth logs as sensitive** — passwords typed into the username field appear in clear text.

## Practice questions { #quiz }

### Question 1

On file server `FS-02` you see a 4624 with `TargetUserName` = `Administrator`, `TargetDomainName` = `WS-207`, `LogonType` = `3`, `AuthenticationPackageName` = `NTLM`, `IpAddress` = `10.20.7.88`. Five minutes later the same pattern appears on two other servers. What does each field tell you, and what is your hypothesis?

??? success "Answer and explanation"
    - `TargetUserName` `Administrator` with `TargetDomainName` `WS-207` — this is the **local** Administrator account of a workstation called `WS-207` (the "domain" of a local account is its computer name). Yet it logged on to `FS-02`, a different machine. That only works if `FS-02` has a local `Administrator` with the **same password or hash** — a sign of shared local admin credentials.
    - `LogonType` `3` — a network logon (share, PsExec-style service, WMI), the usual lateral-movement type.
    - `NTLM` — local accounts can't use Kerberos across machines, so NTLM is expected here, and NTLM with a reused hash is exactly what pass-the-hash relies on.
    - `IpAddress` `10.20.7.88` — the source; check which host that is (it may not be `WS-207` — the domain field names the account's home, not the source).

    **Hypothesis:** someone holding the local Administrator hash/password is moving laterally to servers (**T1550.002** Pass the Hash / **T1078.003** Local Accounts, via **T1021.002**). Next: on `10.20.7.88` look for 4648 and type 9 logons, process creation around that time and EDR alerts; on the servers, follow each `TargetLogonId` into 4688/7045. Remediation includes unique local admin passwords (Windows LAPS) and blocking network logon for local accounts.

### Question 2

A spraying alert fires: 120 failed logons in 10 minutes from `198.51.100.23`, one attempt for each of 120 different users. Most 4625s have SubStatus `0xc000006a`, a few `0xc0000064`, and one user has `0xc0000234`. Then a 4624 for `CORP\h.yoon` from the same IP. Interpret the codes and say what you do first.

??? success "Answer and explanation"
    - One attempt per user across many users from one source is **password spraying** (**T1110.003**) — designed to stay under lockout thresholds.
    - `0xc000006a` — the user exists and the password was wrong: the attacker has a list of **real** usernames.
    - `0xc0000064` — user doesn't exist: a few names on their list are wrong or stale.
    - `0xc0000234` — that account is locked out (also look for 4740 on the DC).
    - The 4624 for `h.yoon` from the same IP is the critical event: **the spray succeeded** for one account.

    **First:** treat `h.yoon` as compromised — reset the password, revoke sessions/tokens (including cloud sessions if the account is synchronised), and check MFA. Then take the 4624's `LogonType` and `TargetLogonId` and follow the session (4672, 4688, 4648, file access). Block the source and search all logs (VPN, Entra ID sign-ins, DCs' 4771/4776) for the same IP and for other successes.

### Question 3

On Ubuntu server `web-01` you find these lines. Explain each, decide what happened, and say what you check next.

```
Nov 20 04:41:10 web-01 sshd[6120]: Accepted password for www-data from 203.0.113.45 port 41890 ssh2
Nov 20 04:41:10 web-01 sshd[6120]: pam_unix(sshd:session): session opened for user www-data(uid=33) by www-data(uid=0)
Nov 20 04:43:57 web-01 sudo: pam_unix(sudo:auth): authentication failure; logname=www-data uid=33 euid=0 tty=/dev/pts/2 ruser=www-data rhost=  user=www-data
Nov 20 04:44:05 web-01 sudo:   www-data : 3 incorrect password attempts ; TTY=pts/2 ; PWD=/var/www/html ; USER=root ; COMMAND=/bin/bash
```

??? success "Answer and explanation"
    - Line 1 — a **successful SSH password login as `www-data`** from an external address. `www-data` is the web server's service account; it should never log in interactively, and normally has no usable password or shell. Someone set a password (or abused a misconfiguration) and logged in (**T1078**, **T1021.004**).
    - Line 2 — PAM opened the session for uid 33 (`www-data`). The PID `6120` ties it to line 1.
    - Line 3 — in that session (`tty=/dev/pts/2`), `sudo` authentication failed for `www-data`.
    - Line 4 — three wrong passwords trying to run `/bin/bash` as **root** from `/var/www/html`: an attempt to escalate privileges after getting in.

    **What happened:** probably a web compromise (webshell) used to give `www-data` a password or shell, then direct SSH access, then an attempt to become root. **Check next:** `/etc/passwd` and `/etc/shadow` for `www-data`'s shell and password change (and `passwd`/`chpasswd`/`usermod` in auth and audit logs); `~www-data/.ssh/authorized_keys`; web access logs before 04:41 for a webshell; all logins from `203.0.113.45` (`grep`, `last -F`, journal); auditd/EDR records for commands in that session; and other privilege-escalation attempts (SUID abuse, kernel exploits). Preserve logs off the host first.

## Related { #related }

- [Important Events](index.md) — this section's overview
- [Windows event structure and channels](../windows-logging/event-structure-channels.md) — how to read the XML and why fields beat message text
- [How Windows event logging works](../windows-logging/how-event-logging-works.md) — audit policy and where the Security log comes from
- [Linux log files and the systemd journal](../linux-logging/log-files-journal.md) — where Linux auth lines are stored
- [Windows Event Logs (EVTX)](../../../windows/event-logs.md)
- [Linux Authentication & Shell History](../../../linux/auth-and-history.md)
- [Credential dumping and Mimikatz](../endpoint-attacks/credential-dumping-mimikatz.md) — where pass-the-hash credentials come from
- [SMB](../other-protocols/smb.md) and [SSH, RDP, VNC](../other-protocols/ssh-rdp-vnc.md) — the network side of these logons

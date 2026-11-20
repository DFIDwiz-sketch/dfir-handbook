---
title: "PAWs, Permissions and Privileges, EDR, DLP, UEBA and Audit Logging — Guarding the Admin, Recording Everything"
tags:
  - training
  - blue-team
  - endpoint
  - hardening
  - edr
  - dlp
  - ueba
  - logging
---

# PAWs, Permissions and Privileges, EDR, DLP, UEBA and Audit Logging — Guarding the Admin, Recording Everything { #paw-edr-dlp-ueba }

!!! abstract "What this page covers"
    The last layers of endpoint defence in depth. First, privileged access workstations (PAWs): why admin credentials must never be typed on a normal machine, the "clean source" idea, tiering, and how a SOC spots a tier-0 account logging on where it shouldn't (4624, 4672). Second, Windows permissions and privileges: the difference between *what objects you can touch* (ACLs) and *what actions you may take* (privileges such as `SeDebugPrivilege`, `SeBackupPrivilege`, `SeLoadDriverPrivilege`, `SeImpersonatePrivilege`), read with `icacls` and `whoami /priv`, and how each privilege leads to escalation. Third, EDR — the flight data recorder on every host — what it records, what a process-tree record looks like field by field, and why the *response* half matters as much as detection; plus XDR. Fourth, DLP: classification, content inspection, the three insider/outsider use cases and why it slows rather than stops a determined attacker. Fifth, UEBA: baselines, peer groups, anomaly scores and the base-rate problem. Finally, audit policies and centralised logging (`auditpol`, command-line logging, `auditd` rules, forwarding, 1102), and the defence-in-depth summary. Practice questions with explanations at the end.

!!! note "Labels"
    **[Supplement]** = practical material you need to know, **[Correction]** = a commonly repeated claim that is wrong or outdated, **[Changed]**/**[Caution]** = what has changed recently and what is risky to do the old way. Hostnames, domains, accounts, IPs, file names and hashes are invented for illustration (`.example`, documentation and private IPs).

## The 8 key points { #key-points }

1. A **privileged access workstation (PAW)** is a separate, locked-down computer (or isolated VM) used *only* for admin work. Admin accounts are never used on everyday machines, so phishing or a drive-by on the everyday machine can't steal them.
2. The **clean source principle**: anything you control *from* a device is only as secure as that device. A compromised laptop undermines the jump server, the admin account and everything administered through them.
3. **Permissions** (ACLs) decide *which objects* — files, folders, registry keys, services — an account can read or change. Correct defaults protect system binaries from being swapped for backdoored copies; weak ACLs are one of the most common escalation paths.
4. **Privileges** (user rights) decide *which actions* an account can take regardless of ACLs: debugging any process, backing up any file, loading drivers, impersonating tokens. Several of them are "admin in disguise" and lead straight to escalation or credential theft.
5. **EDR** records process, file, registry, network, DLL and service activity *and the relationships between them* on every host, so you can replay what happened. Its **response** half — isolate, kill, collect, run scripts — gives the SOC a safe, out-of-band way to act without typing admin credentials into a possibly compromised machine. XDR extends the same idea across email, identity, cloud and network data.
6. **DLP** looks for sensitive data where it shouldn't be or going where it shouldn't go (USB, personal cloud, email, web uploads), using classification labels and content patterns. It is excellent at preventing mistakes and catching careless insiders; a determined attacker will eventually get around it (encryption, compression, slow drip).
7. **UEBA** builds statistical baselines per user, host and peer group and scores deviations. Its bet is that anomalies are more likely to be malicious — true often enough to cut noise massively, but on a billion events even 0.001 % is 10,000 leads. A human with domain knowledge still decides.
8. **Audit policy + centralised logging** underpins everything else: the audit policy decides what gets recorded, and shipping the logs off the host quickly means an attacker who clears them (T1070.001) on the endpoint can't erase the copy. The goal of defence in depth is a trap at every stage, so the attacker is slowed down and eventually trips one.

## Privileged access workstations — keep admin keys off the street { #paw }

### Why this matters { #paw-why }

Imagine the master key to every office in a building. You wouldn't carry it around in your pocket while you go shopping, sit in cafés and let strangers bump into you — you'd keep it in a safe room and only take it out there. Admin credentials are that master key, and an everyday workstation is the street: it reads email, opens attachments, browses the web and runs whatever the user installs. Those are exactly the things phishing and drive-by attacks target.

Technically, the danger comes from how Windows handles logons. When an account logs on interactively (at the console, through RDP, via `runas`), the Local Security Authority (`lsass.exe`) keeps material that lets the user reach other resources without typing the password again — NT hashes, Kerberos tickets and keys (see [Credential Dumping and Mimikatz](../endpoint-attacks/credential-dumping-mimikatz.md)). Anyone with admin on that machine can read it (T1003.001) and reuse it elsewhere (pass-the-hash T1550.002, pass-the-ticket T1550.003). So if a domain admin ever logs on to a helpdesk PC that an attacker already controls, the attacker gets domain admin — no exploit needed.

### What a PAW is { #paw-what }

A PAW is a dedicated device for privileged tasks. In practice it means:

- **Separate accounts first.** The admin has a normal account (`j.park`) for email and browsing and a separate privileged account (`adm-j.park`) for administration. Without this, a PAW makes no sense.
- **A separate device or isolated environment.** The privileged account is used only on the PAW. Options range from a dedicated physical laptop (strongest) to a hardened VM where the *host* is the PAW and the everyday desktop runs as a guest inside it — never the other way round. If the everyday OS is the host, compromising it compromises the guest PAW too.
- **Locked down hard.** No email, no general web browsing (or only an allowlist of admin portals), application control in enforce mode, Credential Guard, full-disk encryption, managed by its own management plane, local admin rights removed, USB restricted.
- **Logon restrictions in the other direction.** Privileged accounts are *denied* the right to log on to ordinary workstations and member servers via Group Policy (`Deny log on locally`, `Deny log on through Remote Desktop Services`) or authentication policies/silos, so even a careless admin physically can't type the credentials in the wrong place.

### Clean source and tiering { #clean-source }

The clean source principle says the security of a system depends on the security of everything that controls it. Picture a chain: PAW → jump server → domain controller. If the PAW is compromised, the attacker can watch the admin's keystrokes (T1056.001), hijack their sessions or steal their tokens, and the jump server's hardening is irrelevant. That's why the *device* is the foundation, not an optional extra.

This leads naturally to **tiering**: accounts and devices are split by what they control. A simplified version:

| Tier | Controls | Examples | May log on to |
| --- | --- | --- | --- |
| 0 (control plane) | Identity itself | Domain controllers, AD CS, Entra ID global admins, identity sync servers | Tier-0 systems and tier-0 PAWs only |
| 1 (management/servers) | Servers and applications | File, database, application servers | Tier-1 systems and PAWs |
| 2 (user access) | Workstations and users | Helpdesk, desktop support | Workstations |

The rule is "never log on downwards": a tier-0 account never authenticates to a tier-1 or tier-2 machine, because the lower machine is easier to compromise and would expose the higher credential.

### What the SOC watches { #paw-detection }

A PAW programme gives the SOC a crisp, high-value detection: *a privileged account authenticated somewhere it shouldn't*. Here is what that looks like on a workstation that is not a PAW.

```xml
<Event>
  <System>
    <EventID>4624</EventID>
    <TimeCreated SystemTime="2026-11-18T22:41:07.512Z" />
    <Computer>WS-HR-0142.corp.example</Computer>
  </System>
  <EventData>
    <Data Name="SubjectUserName">WS-HR-0142$</Data>
    <Data Name="TargetUserName">adm-j.park</Data>
    <Data Name="TargetDomainName">CORP</Data>
    <Data Name="TargetLogonId">0x8A3F21C</Data>
    <Data Name="LogonType">10</Data>
    <Data Name="LogonProcessName">User32</Data>
    <Data Name="AuthenticationPackageName">Negotiate</Data>
    <Data Name="WorkstationName">WS-HR-0142</Data>
    <Data Name="IpAddress">10.20.4.77</Data>
    <Data Name="ElevatedToken">%%1842</Data>
  </EventData>
</Event>
```

- `EventID 4624` — "An account was successfully logged on". It fires on the machine being logged *on to*, for every successful logon. Attackers care because every logon of a privileged account onto a weak machine is a credential-theft opportunity, and defenders care because it is the record of where credentials have been exposed.
- `Computer WS-HR-0142` — a human-resources workstation. That's the problem: it isn't a PAW or a server in tier 0/1.
- `TargetUserName adm-j.park` — the account that logged on; the `adm-` prefix marks it as privileged in this naming convention. (`SubjectUserName WS-HR-0142$` is the local machine account that processed the logon — normal.)
- `TargetLogonId 0x8A3F21C` — the session ID; use it to tie this logon to later events (processes in 4688, privileges in 4672, logoff in 4634).
- `LogonType 10` — RemoteInteractive, i.e. RDP. An RDP logon leaves reusable credentials in LSASS on *this* machine. (Type 2 = console, 3 = network, 9 = `runas /netonly`-style NewCredentials; all logon types are covered later in the Important Events section.)
- `LogonProcessName User32` and `AuthenticationPackageName Negotiate` — an interactive logon processed by Winlogon, negotiated (Kerberos by preference, NTLM fallback). Typical for RDP.
- `IpAddress 10.20.4.77` — where the RDP session came from. Is that the admin's PAW? If it's another everyday workstation, two rules were broken.
- `ElevatedToken %%1842` — "Yes": the session received an elevated (admin) token.

Right after it you'd normally see:

```
EventID 4672  Special privileges assigned to new logon.
  SubjectUserName : adm-j.park
  SubjectLogonId  : 0x8A3F21C
  PrivilegeList   : SeSecurityPrivilege SeBackupPrivilege SeRestorePrivilege
                    SeTakeOwnershipPrivilege SeDebugPrivilege
                    SeLoadDriverPrivilege SeImpersonatePrivilege ...
```

**4672** fires whenever a new logon session receives any of a set of sensitive privileges — in practice, whenever an administrator-equivalent account logs on. The `SubjectLogonId` matches the 4624's `TargetLogonId`, which confirms the same session. Attackers care because these privileges are what make credential dumping and driver loading possible; defenders use 4672 as a simple "admin logged on here" signal.

The detection rule writes itself: *alert when a member of the privileged groups produces 4624 (types 2, 10, 11 or 9) or 4672 on any host that is not in the PAW or tier-0/tier-1 lists*. It is rare, easy to explain to the admin team, and every hit is either a policy violation or an attacker using a stolen admin account.

**[Supplement]** Microsoft's current guidance describes PAWs as part of a wider *privileged access strategy* (the enterprise access model): privileged devices, privileged accounts and intermediaries such as jump servers or cloud admin portals are secured together. For Essential Eight, restricting administrative privileges explicitly includes using separate privileged accounts and secure admin workstations — relevant if you work under Australian frameworks.

## Windows permissions and privileges { #permissions-privileges }

### Two different questions { #two-questions }

An analogy: in an office building, the **locks on each door** decide who can open which room — that's permissions. Your **job title** decides what you're allowed to *do* no matter which room you're in — a fire warden may pull the alarm, a security guard may check everybody's bags. That's privileges. Attackers love both: a door left unlocked (weak ACL) or a job title that quietly lets you do something powerful (dangerous privilege).

- **Permissions** are entries in an object's access control list (ACL). They apply to files, folders, registry keys, services, named pipes, shares and AD objects. They answer "can account X read/write/delete *this object*?"
- **Privileges** (also called user rights, `Se…Privilege`) live in the account's access token and are granted by policy (Local Security Policy → User Rights Assignment, or GPO). They answer "can account X perform *this type of action* at all?" — sometimes *bypassing* ACLs.

### Permissions protect the system's integrity { #permissions }

Windows ships with careful default ACLs. Most of `C:\Windows\System32` is owned by `TrustedInstaller` (the servicing account), and even administrators only have read and execute by default — they'd have to take ownership first. That's deliberate: it stops casual or automated tampering with system binaries.

```
C:\> icacls C:\Windows\System32\utilman.exe
C:\Windows\System32\utilman.exe NT SERVICE\TrustedInstaller:(F)
                                BUILTIN\Administrators:(RX)
                                NT AUTHORITY\SYSTEM:(RX)
                                BUILTIN\Users:(RX)
                                APPLICATION PACKAGE AUTHORITY\ALL APPLICATION PACKAGES:(RX)
                                APPLICATION PACKAGE AUTHORITY\ALL RESTRICTED APPLICATION PACKAGES:(RX)

Successfully processed 1 files; Failed processing 0 files
```

- `NT SERVICE\TrustedInstaller:(F)` — only the servicing account has full control. This is the healthy default.
- `BUILTIN\Administrators:(RX)` and `NT AUTHORITY\SYSTEM:(RX)` — read and execute only. Admins can run the file but can't overwrite it without first taking ownership.
- `BUILTIN\Users:(RX)` — ordinary users can run it.
- The two `APPLICATION PACKAGE AUTHORITY` lines let sandboxed (Store/AppContainer) apps read it — normal.

Why this particular file? `utilman.exe` is the Ease of Access tool you can launch from the *logon screen*, where it runs as SYSTEM. A classic backdoor replaces it (or `sethc.exe`, the sticky-keys handler) with `cmd.exe`, giving a SYSTEM shell at the logon screen without a password — **Accessibility Features, T1546.008**. If you ever see this file's ACL showing `Administrators:(F)` or an owner other than `TrustedInstaller`, someone has taken ownership — investigate. File integrity monitoring on these binaries (see [Application Control, FIM and Catching Persistence](appcontrol-fim-persistence.md)) and regular permission audits catch it.

The opposite case — permissions that are *too weak* — was covered in [Privilege Escalation](../endpoint-attacks/privilege-escalation.md): a service binary or registry key writable by `Users` lets anyone swap in their own code and have SYSTEM run it.

### Privileges control what you can do after logon { #privileges }

See your own privileges with `whoami /priv`. Here is an elevated administrator prompt (trimmed):

```
C:\> whoami /priv

PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                               State
============================= ========================================= ========
SeBackupPrivilege             Back up files and directories             Disabled
SeRestorePrivilege            Restore files and directories             Disabled
SeDebugPrivilege              Debug programs                            Disabled
SeLoadDriverPrivilege         Load and unload device drivers            Disabled
SeImpersonatePrivilege        Impersonate a client after authentication Enabled
SeTakeOwnershipPrivilege      Take ownership of files or other objects  Disabled
SeChangeNotifyPrivilege       Bypass traverse checking                  Enabled
```

- `Privilege Name` — the internal name you'll see in logs (4672, 4673, 4674) and tools.
- `Description` — the name used in User Rights Assignment.
- `State` — **Disabled doesn't mean "not held"**. If the line appears, the account holds the privilege; a program just has to switch it on (`AdjustTokenPrivileges`) before using it, which any tool does in one call. Absent from the list = not held.

The dangerous ones and why:

| Privilege | Legitimate purpose | How attackers abuse it | ATT&CK |
| --- | --- | --- | --- |
| `SeDebugPrivilege` | Debuggers attaching to any process | Open `lsass.exe` and read its memory → credentials | T1003.001 |
| `SeBackupPrivilege` | Backup software reading every file | Read files regardless of ACLs, e.g. save `HKLM\SAM` and `HKLM\SYSTEM` (local hashes) or copy `NTDS.dit` on a DC | T1003.002, T1003.003 |
| `SeRestorePrivilege` | Restoring backups | Write any file regardless of ACLs — replace a service binary or `utilman.exe` | T1574, T1546.008 |
| `SeLoadDriverPrivilege` | Installing drivers | Load a vulnerable signed driver and use it to reach the kernel (BYOVD), often to kill EDR | T1068, T1562.001 |
| `SeImpersonatePrivilege` | Services acting on behalf of clients (IIS, SQL) | "Potato" techniques trick SYSTEM into authenticating to the attacker's process, then impersonate it | T1134.001 |
| `SeTakeOwnershipPrivilege` | Recovering orphaned files | Take ownership of any object, then rewrite its ACL | T1222.001 |

The backup example is worth spelling out because it shows how a privilege bypasses ACLs. Members of **Backup Operators** are not administrators, and the SAM registry hive is unreadable to them normally. But the backup privilege tells Windows "let this account read anything *for backup purposes*", so:

```
C:\> reg save HKLM\SAM C:\Users\Public\s.hiv
The operation completed successfully.
C:\> reg save HKLM\SYSTEM C:\Users\Public\y.hiv
The operation completed successfully.
```

- `reg save HKLM\SAM <file>` — writes a copy of the SAM hive (local account hashes) to a file. The SYSTEM hive holds the boot key needed to decrypt it.
- `The operation completed successfully.` — with backup privilege, this works even though the account can't open the key normally.

The attacker then copies both files off and extracts the hashes offline. The same logic applies to virtual machines: whoever can snapshot or clone a running VM gets a copy of its memory — including LSASS — so hypervisor and backup admins are effectively tier-0 for the systems they protect.

**Evidence to look for:** 4688 (or Sysmon 1) for `reg.exe save HKLM\SAM|SECURITY|SYSTEM`, `ntdsutil`, `wbadmin`, `diskshadow` or `vssadmin` outside known backup jobs; 4673/4674 ("a privileged service was called" / "an operation was attempted on a privileged object") showing `SeBackupPrivilege` or `SeDebugPrivilege` used by unexpected processes (these are noisy, so collect them selectively); membership changes to Backup Operators and similar groups (4728/4732/4756); 7045 for new kernel drivers.

The defensive rule: treat every account holding these privileges as privileged, keep groups such as Backup Operators, Server Operators and Print Operators empty unless needed, and review User Rights Assignment GPOs as carefully as group membership.

## EDR — a flight data recorder on every endpoint { #edr }

### Why it exists { #edr-why }

Antivirus answers one question about one file: "bad or not?" Most post-exploitation activity doesn't involve a file antivirus would flag — it's `powershell.exe` with odd arguments, `rundll32.exe` loading something from `AppData`, a new service, a connection to an unusual IP. Each step alone looks normal; the *sequence* is the attack. Windows event logs show pieces of it, but often without the links between them, and only if the audit policy was set right.

**Endpoint detection and response (EDR)** fills that gap. Think of the black box in an aircraft: it doesn't stop a crash, but it records everything so investigators can reconstruct exactly what happened, second by second. EDR is that recorder for every host — and, unlike a black box, it also lets you take the controls remotely.

### What it records { #edr-records }

An EDR agent (a kernel driver plus a user-mode service) records events such as process creation and termination with full command lines, parent/child relationships, file creation/modification/deletion, registry changes, network connections with the owning process, DLL and driver loads, service and scheduled-task creation, logons, and suspicious memory operations such as one process opening or writing into another. Each event carries hashes, signer information, user and integrity level, and IDs that tie it to its process. The console then draws the relationships as a process tree and timeline.

A simplified process-creation record, as you'd see it in an EDR's raw telemetry or export:

```json
{
  "event_type": "ProcessCreate",
  "timestamp": "2026-11-18T09:14:52.318Z",
  "device": { "name": "WS-FIN-0031", "os": "Windows 11 24H2" },
  "process": {
    "pid": 7412,
    "name": "powershell.exe",
    "path": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
    "command_line": "powershell.exe -nop -w hidden -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoA...",
    "sha256": "9f2c...e41a",
    "signer": "Microsoft Windows",
    "user": "CORP\\m.lee",
    "integrity": "Medium"
  },
  "parent": {
    "pid": 5120,
    "name": "WINWORD.EXE",
    "command_line": "\"C:\\Program Files\\Microsoft Office\\root\\Office16\\WINWORD.EXE\" /n \"C:\\Users\\m.lee\\Downloads\\Invoice_4471.docm\""
  },
  "network_after": [
    { "remote_ip": "203.0.113.45", "remote_port": 443, "seconds_after_start": 2 }
  ]
}
```

- `event_type` / `timestamp` — what happened and when (UTC).
- `device` — which host; the console lets you pivot to everything else on it.
- `process.name` / `path` — `powershell.exe` from its genuine location, signed by Microsoft. Antivirus would see nothing wrong with the binary itself.
- `command_line` — the important part. `-nop` (no profile), `-w hidden` (no window), `-enc` (Base64-encoded UTF-16 command). `SQBFAFgA` decodes to `IEX` — Invoke-Expression, i.e. "run this downloaded text as code" (T1059.001).
- `user` / `integrity` — running as the logged-on user at medium integrity, so not yet elevated.
- `parent` — **`WINWORD.EXE`** opening a macro-enabled document from `Downloads`. Word starting PowerShell is the classic sign of a malicious macro (T1204.002 user execution, T1566.001 phishing attachment).
- `network_after` — two seconds later the new PowerShell process connects to `203.0.113.45:443`, most likely to download the next stage (T1105).

No single field proves anything; the chain *document from Downloads → Word → hidden encoded PowerShell → outbound connection* is unmistakable. This relationship data is what EDR adds over plain logs.

### The "R": response { #edr-response }

Detection is half the value. The other half is that EDR gives the security team a separate, authenticated channel to every host:

- **Isolate (contain) the host** — cut all network traffic except to the EDR cloud, so the attacker loses their C2 but you keep your investigation channel.
- **Kill a process, quarantine or delete a file, remove a persistence entry.**
- **Collect** files, memory or a triage package for analysis.
- **Live response** — a restricted remote shell or script execution on the host.
- **Block a hash or indicator** across the fleet.

Why "out of band" matters: if you RDP to a suspect host with a domain admin account to investigate, you've just done exactly what the PAW section warned against — put admin credentials onto a machine the attacker may control. EDR live response runs through the agent under its own identity, so no reusable credentials land on the host. For a SOC, this is a force multiplier: one analyst can scope and contain an incident across hundreds of hosts in minutes.

### Attackers know about EDR too { #edr-evasion }

Expect attempts to blind it: stopping or uninstalling the agent, tampering with its configuration, blocking its network traffic to the cloud, or loading a vulnerable driver to kill it from the kernel (T1562.001, T1068). Defences and signals: **tamper protection** turned on, an alert when an agent stops reporting ("sensor offline" while the host is still talking on the network is suspicious), alerts on new kernel drivers (7045 with a `.sys` image, Sysmon 6), and Microsoft's vulnerable driver blocklist.

### XDR { #xdr }

**Extended detection and response (XDR)** applies the EDR idea across more data sources: endpoint plus email, identity, cloud workloads, SaaS and network. The value is correlation — the phishing email, the user's sign-in from a new country, the endpoint process chain and the cloud file download appear as one incident instead of four unrelated alerts in four consoles. In practice "XDR" is mostly a vendor platform (the same vendor's EDR, email and identity products feeding one console), sometimes with third-party data added; there is no strict standard definition.

## DLP — keeping sensitive data where it belongs { #dlp }

### What it is for { #dlp-what }

**Data loss prevention (DLP)** targets the end of the attack: discovery of where the data is, collection, and exfiltration (TA0010). It comes in two main forms:

- **Network DLP** inspects traffic (web proxy, email gateway, sometimes SSL-decrypted flows) for sensitive content leaving.
- **Endpoint (host) DLP** watches files on the device and what users do with them: copy to USB, upload in a browser, paste into a web app, print, send by email, sync to a personal cloud folder.

Modern products also cover cloud apps (via API or a CASB) and increasingly generative-AI prompts.

### How it decides { #dlp-how }

DLP needs to answer two things: *is this data sensitive*, and *is this movement allowed*?

**Sensitive** comes from:

1. **Classification labels** — a label applied by the user or automatically (`PROTECTED`, `OFFICIAL: Sensitive`, `Confidential – HR`), stored in the file's metadata.
2. **Content inspection** — patterns (regular expressions plus checks), keywords, document fingerprints (a hash of a template, e.g. a contract form) and exact data matching (hashes of a real customer table).

A card number pattern shows why "plus checks" matters:

```
\b(?:4\d{3}|5[1-5]\d{2})[ -]?\d{4}[ -]?\d{4}[ -]?\d{4}\b
```

- `\b … \b` — word boundaries, so the number isn't part of a longer string.
- `(?:4\d{3}|5[1-5]\d{2})` — starts with 4 (Visa-style) or 51–55 (Mastercard-style), plus three more digits.
- `[ -]?` — an optional space or dash between groups.
- `\d{4}` ×3 — the remaining digit groups.

On its own this matches plenty of order numbers and serial numbers. Real DLP engines add a **Luhn checksum** test (the check digit card numbers carry), require nearby keywords ("card", "expiry", "CVV"), and set a **count threshold** (one match = probably noise, 500 matches in one file = a data dump). The same logic applies to tax file numbers, passport numbers, health identifiers and so on.

**Allowed** comes from policy: "files labelled `PROTECTED` may not be copied to removable media or uploaded to non-corporate cloud storage; warn and require a justification for `OFFICIAL: Sensitive`; block and alert for more than 50 card numbers."

A simplified endpoint DLP alert:

```
Alert: DLP policy match - "PII bulk to removable media"
Time:        2026-11-19T17:52:10Z
Device:      WS-HR-0142.corp.example
User:        CORP\s.kim
Activity:    FileCopiedToRemovableMedia
File:        C:\Users\s.kim\Documents\staff_export_2026.xlsx
Destination: E:\  (USB, VendorID 0x0781, Serial 4C53000123456789)
Label:       OFFICIAL: Sensitive
Matched:     Tax File Number x 1,248 ; Date of Birth x 1,251
Action:      Blocked (user override not permitted)
```

- `Activity FileCopiedToRemovableMedia` — the action the endpoint agent intercepted (T1052.001, exfiltration over USB).
- `File` — a staff export in the user's Documents.
- `Destination` — the USB device, with vendor ID and serial number so you can identify the physical stick and correlate with device-connection events on other machines.
- `Label` — the classification already on the file.
- `Matched` — content inspection results: 1,248 tax file numbers is clearly bulk personal data, not an accident with one record.
- `Action Blocked` — the copy didn't happen. Still worth triage: why was an HR user moving a full staff export to USB at 17:52, just before going home?

### The three use cases { #dlp-use-cases }

- **Non-malicious insider** — the most common and the one DLP is best at. An employee emails a spreadsheet to their personal address to work from home, or puts health records on an unencrypted stick. A pop-up ("This file contains sensitive personal information — use the approved share") fixes most of it. This is mistake prevention and policy enforcement.
- **Malicious insider** — an employee deliberately stealing, corrupting or destroying data before leaving or to sell it (T1052, T1567, T1485). DLP raises alerts on unusual volume, destination or timing; combined with HR context (resignation, performance process) this is often how cases start.
- **Malicious outsider** — an attacker who has taken over accounts and wants to stage and export data (see [Lateral Movement, Collection and Exfiltration](../endpoint-attacks/lateral-collection-exfil.md)). DLP can block or flag the obvious exfil paths.

### Its limits { #dlp-limits }

DLP is only as good as two things: **classification** (unlabelled data with no recognisable pattern is invisible) and **visibility** (encrypted archives, custom protocols, screenshots, unmanaged devices, personal phones photographing a screen). An attacker who puts data into a password-protected archive with encrypted file names (`7z -mhe=on -p`), or drips it out slowly through an allowed cloud service, will usually get past content inspection. So treat DLP as a tripwire that *slows* a determined attacker and produces useful signals (big encrypted archives, unusual upload volume), not as a wall.

## UEBA — finding the unusual { #ueba }

### The idea { #ueba-idea }

DLP and most SIEM rules say "alert when X happens". **User and entity behaviour analytics (UEBA)** says "learn what normally happens, then tell me what is different". The "entities" are not only users but also hosts, IP addresses, service accounts, applications and devices.

A security guard who has worked the same building for ten years doesn't need a rulebook to notice that the accountant who always leaves at 5 p.m. is in the server room at 2 a.m. That's UEBA: an automated version of "that's odd for *this* person".

### How it works, simply { #ueba-how }

1. **Collect** activity: logons (4624/4625), VPN and cloud sign-ins, file access, process execution, proxy logs, DLP events.
2. **Build baselines** per entity and per **peer group** (people with the same role or department): usual hours, usual hosts, usual countries, usual data volume, usual applications.
3. **Score** new activity statistically — how far from the baseline is it? First-time events ("first time this user logged on to this server", "first time this account used this country") are a big part of it.
4. **Combine** several small anomalies on one entity into a risk score, so one odd event is ignored but five odd events in an hour surface.

A simplified UEBA finding:

```
Entity:         CORP\svc-backup (service account)
Risk score:     87 / 100   (baseline 5)
Time window:    2026-11-19 01:10 – 01:48 UTC
Anomalies:
  - Interactive logon (LogonType 10) - never seen for this account in 90 days
  - Logon to DC01.corp.example - first time; peer group (service accounts) 0 %
  - Source host WS-ENG-0077 - first time
  - Process: ntdsutil.exe - first time for this account
  - Outbound volume from WS-ENG-0077: 4.2 GB (baseline 50 MB/day)
```

- `Entity` — a backup service account: it normally runs scheduled jobs and never logs on interactively.
- `Risk score 87 (baseline 5)` — many anomalies stacked within 38 minutes.
- Each anomaly line on its own might be explainable; together they tell the story of a stolen service account (T1078.002) used over RDP to reach a domain controller, running `ntdsutil` (likely an `NTDS.dit` copy, T1003.003) and pushing gigabytes out. That is exactly what UEBA is good at — the attack used valid credentials and built-in tools, so no signature would fire.

### The base-rate problem { #ueba-base-rate }

The core assumption is "anomalies are more likely to be evil". That's true, but *more likely* is not *likely*. Do the arithmetic: if UEBA throws away 99.999 % of a billion daily events as normal, 0.001 % of 1,000,000,000 is still **10,000** events a day. Most anomalies are benign — a new project, a reorganisation, travel, a new tool, the first day of a new employee, an admin doing month-end maintenance.

So UEBA needs: a **training period** (often weeks) on historical data before its scores mean anything; **tuning** to suppress known benign patterns; and **analysts with domain knowledge** who know that the finance team runs large exports every quarter-end. Anomaly is a reason to look, not a verdict. Use UEBA scores to *prioritise* and *enrich* alerts (this user is also at risk score 87) rather than as stand-alone alerts.

## Audit policies and centralised logging { #audit-logging }

### Why it underpins everything { #audit-why }

Every detection on this page — the PAW logon rule, the privilege-use events, the DLP and UEBA inputs — depends on two things: the event being **recorded** in the first place, and the record **surviving** long enough to be analysed. The **audit policy** controls the first; **centralised logging** (SIEM or log management) controls the second.

Event logs are the audit trail: who changed what, when, from where. But they live on the host, and an attacker with admin rights can clear them (`wevtutil cl Security`, T1070.001). When the Security log is cleared Windows writes **1102** ("The audit log was cleared"), which names the account that did it — but only if that event is shipped off the host before the attacker does anything else. Forwarding logs within seconds is what makes them trustworthy.

### Windows: what gets logged { #windows-audit-policy }

By default Windows records far less than a SOC needs. Check the effective policy with `auditpol`:

```
C:\> auditpol /get /category:"Logon/Logoff","Detailed Tracking"
System audit policy
Category/Subcategory                      Setting
Logon/Logoff
  Logon                                   Success and Failure
  Logoff                                  Success
  Account Lockout                         Success
  Special Logon                           Success
  Other Logon/Logoff Events               No Auditing
Detailed Tracking
  Process Creation                        No Auditing
  Process Termination                     No Auditing
  DPAPI Activity                          No Auditing
  RPC Events                              No Auditing
```

- `auditpol /get /category:…` — shows the *advanced* audit policy in effect for the listed categories (`/category:*` shows all).
- `Logon … Success and Failure` — 4624 and 4625 are recorded. Good.
- `Special Logon Success` — this is what produces **4672**, which the PAW detection above needs.
- `Process Creation No Auditing` — the big gap. Without it there is no **4688**, so no record of what programs ran unless you have Sysmon or EDR. Turn it on, *and* enable the separate setting "Include command line in process creation events" (Administrative Templates → System → Audit Process Creation), or 4688 will show `powershell.exe` without its arguments.

Other high-value subcategories usually enabled in a SOC baseline: Security Group Management (4728/4732/4756), User Account Management (4720, 4722, 4738), Security System Extension (4697 service install), Other Object Access Events (4698 scheduled tasks), Kerberos Authentication Service and Service Ticket Operations (4768/4769), plus PowerShell script block logging (4104). Also raise the maximum Security log size well above the old default so local logs aren't overwritten within hours.

The detail of how Windows event logging works — channels, providers, XML structure — is the topic of the next section, Windows Logging.

### Linux: syslog and auditd { #linux-audit }

On Linux the equivalents are the syslog daemon (rsyslog or syslog-ng), the systemd journal, and the kernel audit system (`auditd`). Two small examples:

```
# /etc/audit/rules.d/soc.rules
-w /etc/passwd -p wa -k identity
-w /etc/sudoers -p wa -k priv_change
-a always,exit -F arch=b64 -S execve -F euid=0 -F auid>=1000 -F auid!=unset -k root_cmds
```

- `-w /etc/passwd -p wa -k identity` — watch the file for **w**rites and **a**ttribute changes; tag matching records with the key `identity` so you can search for them (`ausearch -k identity`).
- `-w /etc/sudoers -p wa -k priv_change` — the same for the sudo configuration (privilege changes).
- `-a always,exit -F arch=b64 -S execve` — record every 64-bit `execve` system call (every program launch) at exit…
- `-F euid=0 -F auid>=1000 -F auid!=unset` — …but only when it runs as root (`euid=0`) and was started by a real logged-in user (`auid`, the login UID that survives `sudo`/`su`, is a normal user ID). This catches people running commands as root while avoiding system daemons.
- `-k root_cmds` — the search key.

```
# /etc/rsyslog.d/90-forward.conf
*.* @@siem.corp.example:6514
```

- `*.*` — every facility, every severity.
- `@@` — forward over **TCP** (a single `@` would be UDP, which silently drops messages). Port 6514 is conventionally syslog over TLS; TLS itself needs extra settings not shown here.
- `siem.corp.example` — the central collector.

Syslog formats, facilities and the journal are covered in the Linux Logging section that follows.

### What the SOC must know { #audit-soc }

Analysts don't need to be the people who configure every audit setting, but they must know *what is and isn't being collected*, because the absence of an event only means something if the event would have been recorded. "No 4688 for `ntdsutil` on DC01" is evidence only if process creation auditing is on there and the logs arrived. Keep a short coverage map: which log sources, from which hosts, with which policy, and how fast they arrive. Application and device logs (web servers, VPN, firewalls, cloud audit logs) belong on that map too.

## Defence in depth — the summary { #defence-in-depth-summary }

Lining the controls up against the attack stages shows the point of this whole section:

| Stage | Traps on the endpoint |
| --- | --- |
| Delivery / exploitation | Patching, exploit protection, ASR, antivirus, browser and Office hardening |
| Installation | Application control, FIM, antivirus, persistence monitoring, permissions |
| Privilege escalation / credential access | Correct ACLs and privileges, LSA protection, Credential Guard, PAWs and tiering |
| C2 | Host firewall, EDR network telemetry, outbound filtering |
| Actions on objective | DLP, UEBA, EDR, audit logging |

No single trap is perfect, and that isn't the goal. Each one forces the attacker to slow down, choose a quieter technique or take a risk. The more traps, the slower they move; the slower they move, the longer we have to notice the one mistake that trips an alert — and the less damage they can do before we remove them. Damage grows the further an attacker gets, so catching them early is far cheaper than catching them at the last stage. Every layer should therefore both **block** and **leave evidence** in the central logs.

## The 2026 view { #trends }

!!! success "[2026 Current] Still valid"
    Separate admin accounts and dedicated admin devices, the clean source principle, "never log on downwards", the difference between ACL permissions and privileges and the danger of `SeDebug`/`SeBackup`/`SeRestore`/`SeLoadDriver`/`SeImpersonate`, EDR as recorder plus remote-response channel, DLP's dependence on classification and visibility, UEBA's base-rate problem, and centralised logging as the foundation of detection — all still hold. Event IDs 4624, 4672, 4673/4674, 4688, 1102 and 7045 are unchanged.

!!! info "[Changed] What has changed"
    - **EDR is now table stakes and the market has consolidated.** Several vendors once named alongside EDR have changed hands — Panda Security became part of WatchGuard, Carbon Black is under Broadcom, and in 2025 the MSSP LevelBlue acquired Cybereason. Most organisations now buy EDR inside a broader XDR or managed detection and response (MDR) service rather than as a stand-alone tool.
    - **After the July 2024 global outage caused by a faulty security-agent update**, Microsoft launched the Windows Resiliency Initiative and announced (2025) a Windows endpoint security platform that lets antivirus/EDR vendors run more of their code outside the kernel. Rollout depends on vendor adoption; check what your vendor supports rather than assuming.
    - **SIEM, XDR and UEBA are merging.** Microsoft Sentinel is moving into the unified Defender portal (the Azure-portal experience is being retired on a timeline Microsoft has pushed into 2027) and has added an AI-assisted UEBA "behaviors" layer that summarises raw logs into behaviours. Other vendors bundle UEBA into their SIEM/XDR too, so it is now often a feature rather than a separate product.
    - **DLP now covers generative AI.** Endpoint and browser DLP policies can inspect what users paste or upload into AI assistants and web AI apps, and Microsoft Purview added DLP for prompts to Microsoft 365 Copilot. "Pasting sensitive data into a chatbot" is a top DLP use case in 2026.
    - **Privileged access went cloud and identity first.** Microsoft's guidance frames PAWs within a privileged access strategy (enterprise access model) with cloud-managed devices, just-in-time elevation (Entra PIM) and phishing-resistant MFA for admins. Tier 0 now includes the cloud identity plane — Entra global admins, identity-sync servers and the device-management console.
    - **Sysmon is becoming a built-in Windows feature** (rolling out in 2026 for Windows 11 and Server 2025), which makes rich process, network and registry telemetry easier to get without third-party installs — it still needs configuration and collection.

!!! warning "[Caution] Wrong or risky to do the old way"
    - **Don't run the PAW as a VM on the everyday desktop.** If the everyday OS is the host, compromising it compromises the PAW. The PAW must be the host (or a separate device).
    - **Don't investigate a suspect host by RDP-ing in with a domain admin account.** Use EDR live response or a dedicated, restricted IR account; otherwise you hand the attacker your credentials.
    - **Don't read "Disabled" in `whoami /priv` as "safe".** The privilege is held and can be enabled in one call.
    - **Don't treat backup, hypervisor and EDR consoles as ordinary tier 1/2.** Whoever can snapshot a DC, read every file, or run scripts on every endpoint through the EDR console is effectively tier 0.
    - **Don't rely on DLP as an exfiltration wall.** Encrypted archives and slow uploads through allowed services get past it; pair it with network monitoring and UEBA.
    - **Don't raise UEBA anomalies straight to incidents.** Use them to prioritise and enrich; and don't expect useful scores before the training period is over.
    - **Don't forward syslog over plain UDP** for security logs, and don't leave process-creation auditing off or the command-line option disabled. Make sure 1102 and agent-offline events alert immediately.

## Practice questions { #quiz }

### Question 1

The SIEM shows a 4624 on `WS-HR-0142` with `TargetUserName adm-r.choi`, `LogonType 10`, `IpAddress 10.20.4.91`, followed by a 4672 with the same logon ID. `adm-r.choi` is a Domain Admins member. `10.20.4.91` is r.choi's everyday laptop. What two rules were broken, what is the risk, and what would you check next?

??? success "Answer and explanation"
    **Two rules broken:** (1) the privileged account was used from an everyday laptop instead of a PAW — so the credentials were typed on a machine that reads email and browses the web; (2) a tier-0 account logged on *downwards* to a tier-2 workstation (HR PC) via RDP, which leaves reusable credential material in LSASS on that workstation. The 4672 with the same logon ID confirms the session had admin-level privileges.

    **Risk:** if either the laptop (keylogging, token theft, T1056.001) or the HR workstation (LSASS dump, T1003.001) is or becomes compromised, the attacker gets domain admin and can reuse it with pass-the-hash/ticket (T1550.002/.003). It may also not have been r.choi at all — a stolen admin account looks exactly like this.

    **Next checks:** confirm with r.choi (and the change calendar) whether this was them; review EDR/4688 on both machines around that time for suspicious processes, especially anything opening `lsass.exe` (Sysmon 10) on `WS-HR-0142`; look for other logons by `adm-r.choi` across the estate in the last days; if anything is doubtful, reset the account's password, revoke its sessions and Kerberos tickets, and treat both hosts as potentially exposed. Long term: deny privileged groups logon to workstations via GPO/authentication policies and alert on every violation.

### Question 2

A helpdesk account is a member of **Backup Operators** "so it can restore users' files". On a member server you find, in 4688 events: `reg.exe save HKLM\SAM C:\Users\Public\s.hiv` and `reg.exe save HKLM\SYSTEM C:\Users\Public\y.hiv`, run by that account, followed by an outbound SMB connection from the server to a workstation. The account isn't a local administrator. How was this possible, what did the attacker get, and what would you change?

??? success "Answer and explanation"
    **How:** Backup Operators hold **`SeBackupPrivilege`** (and `SeRestorePrivilege`). Backup privilege lets the holder read any file or registry hive *for backup purposes*, bypassing the ACLs that normally keep non-admins out of the SAM. So `reg save` works even though the account isn't an admin. This is credential access via the SAM, **T1003.002**.

    **What they got:** the SAM hive holds the NT hashes of *local* accounts on that server, and the SYSTEM hive holds the boot key needed to decrypt them. With both copied off (the outbound SMB connection), the attacker can extract the local Administrator hash offline. If the local admin password is the same on other servers (no LAPS), that hash works everywhere via pass-the-hash (T1550.002). On a domain controller, the same privilege would allow copying `NTDS.dit` — every domain hash.

    **Changes:** remove the helpdesk account from Backup Operators and give file-restore through a purpose-built tool or delegated share permissions instead; keep built-in operator groups empty; treat any account with backup/restore/debug/driver privileges as privileged (PAW, tiering, monitoring); deploy LAPS so local admin passwords are unique; and alert on `reg save` of SAM/SECURITY/SYSTEM outside known backup jobs.

### Question 3

Your manager proposes: "We'll buy UEBA instead of renewing EDR — UEBA will find anything unusual anyway." Give three reasons this is a poor trade, using what each tool actually does.

??? success "Answer and explanation"
    Any three of these:

    - **Different data.** EDR records detailed host activity — full command lines, parent/child process chains, file/registry/network events tied to processes. UEBA works on whatever logs it is fed, usually summarised (logons, sign-ins, file access). Without EDR (or good Sysmon and audit logging), UEBA has nothing like "Word → hidden encoded PowerShell → outbound connection" to analyse.
    - **No response.** EDR's "R" — isolating a host, killing a process, collecting files, live response without exposing admin credentials — has no UEBA equivalent. UEBA can tell you *something is odd*; it can't contain anything.
    - **The base-rate problem.** UEBA flags anomalies, and most anomalies are benign; even 0.001 % of a billion events is 10,000 leads. It needs a training period and tuning, and analysts still need EDR-level detail to decide whether an anomaly is malicious.
    - **Known-bad is missed.** An attack that looks like normal activity for that user (a phishing payload running at 10 a.m. on their usual workstation) may score low in UEBA, while EDR behavioural detections and prevention would catch the malicious technique itself.
    - **Defence in depth.** They are complementary layers aimed at different stages: EDR across execution, persistence, escalation and C2; UEBA mainly for valid-account misuse and insider activity. Replacing one with the other removes a trap rather than adding one.

## Related { #related }

- [Application Control, File Integrity Monitoring and Catching Persistence](appcontrol-fim-persistence.md) — the previous layer · [Credential Guard, Application Guard, Host Firewalls and Antivirus](vbs-firewall-antivirus.md) · [Inventory, Vulnerability Scanning, Patching and Exploit Protection](inventory-vulns-patching.md)
- [Privilege Escalation](../endpoint-attacks/privilege-escalation.md) · [Credential Dumping and Mimikatz](../endpoint-attacks/credential-dumping-mimikatz.md) · [Lateral Movement, Collection and Exfiltration](../endpoint-attacks/lateral-collection-exfil.md)
- [LSASS Credential Dumping](../../../adversary/lsass-dumping.md) · [SAM, LSA Secrets & NTDS.dit Extraction](../../../adversary/sam-ntds-extraction.md) · [Pass-the-Hash](../../../adversary/pass-the-hash.md) · [Token Impersonation & Potato Attacks](../../../adversary/token-impersonation-potato.md)
- [Impair Defenses & Log Clearing](../../../adversary/impair-defenses-log-clearing.md) · [Windows Event Logs (EVTX)](../../../windows/event-logs.md) · [Windows Event IDs](../../../basics/windows-event-ids.md)

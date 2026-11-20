---
title: "Credential Dumping and Mimikatz — From One Admin to Many Accounts"
tags:
  - training
  - blue-team
  - endpoint
  - credential-access
---

# Credential Dumping and Mimikatz — From One Admin to Many Accounts { #credential-dumping-mimikatz }

!!! abstract "What this page covers"
    What happens right after an attacker becomes admin on one Windows host: they **dump credentials** — read the passwords, hashes and tickets that Windows keeps for **every** user signed in to that machine — and use them to log in as someone else, somewhere else. Why this needs admin rights in the first place, and why it is still worth it for an attacker who already *is* admin. How Windows single sign-on works and why it means `lsass.exe` holds your secrets in memory. What **Mimikatz** is, what it can and can't recover on modern Windows (usually a hash, not plaintext), and why "just block Mimikatz" doesn't work (recompiled, renamed, rewritten in PowerShell, run only in memory, and many look-alike tools). Then the chain that makes credential dumping so dangerous: a machine with many users signed in turns one compromise into many stolen accounts, and the attacker hops host to host until a domain admin is caught. Every sample (Sysmon 10 access to `lsass.exe` with `GrantedAccess` decoded, Sysmon 13 WDigest change, PowerShell 4104, a redacted dump result, 4624 logon type 9 `seclogo` and network logon with NTLM, 7045 for a driver, Credential Guard and LSA protection checks) is broken down field by field. Practice questions at the end.

!!! note "Labels"
    **[Supplement]** = practical material you need to know, **[Correction]** = a commonly repeated claim that is wrong or outdated, **[Changed]**/**[Caution]** = what has changed recently and what is risky to do the old way. Hostnames, domains, accounts, IPs, hashes and file names are invented for illustration (`.example`, documentation and private IPs).

## The 8 key points { #key-points }

1. **Credential Access (TA0006)** is its own ATT&CK tactic; dumping credentials from the operating system is **T1003 OS Credential Dumping**, and reading them out of the `lsass.exe` process is **T1003.001 LSASS Memory**. In practice it works as **privilege escalation by identity**: the attacker uses access they already have to *become other accounts*.
2. It is different from the escalation tricks on the previous page because it **requires admin (or SYSTEM) first**. Reading another process's memory or the protected parts of the registry is something only administrators can do.
3. Why bother if you're already admin? Because the dump gives you **every account signed in to that machine**, not just your own — and sometimes the **plaintext password**, which works everywhere that password works.
4. Windows stores credentials for **single sign-on**: you type your password once, and Windows keeps derived secrets (NTLM hash, Kerberos tickets, sometimes reversible forms) in memory in `lsass.exe` so it can answer for you later. That convenience is exactly what the attacker steals.
5. **Mimikatz** (ATT&CK software **S0002**) is the best-known tool that reads those secrets from `lsass.exe`. On modern, well-configured Windows it usually gets **hashes and tickets, not plaintext** — but a hash is enough to log in elsewhere (**T1550.002 Pass the Hash**, **T1550.003 Pass the Ticket**).
6. You can't defend by blocking one file: Mimikatz exists recompiled, custom-built, renamed, as a **PowerShell version that runs only in memory**, and as features inside other tools — plus many other tools dump LSASS the same way. **Detect the behaviour** (something opening `lsass.exe` to read its memory), not the file name.
7. The real danger is the **chain**: an admin on a server where many people are signed in can dump them all; each stolen account opens more machines; repeat until a **domain admin** is found. One machine becomes the whole network — this is how **lateral movement (TA0008)** is fuelled.
8. The best defences limit *what is there to steal* and *who can steal it*: keep admin credentials scarce and **never sign in to low-trust machines with high-privilege accounts**, unique local admin passwords (LAPS), **Credential Guard**, **LSA protection**, the **Protected Users** group, and the Defender rule that blocks credential theft from LSASS.

## Credential dumping as a tactic { #tactic }

### Where it sits in the attack { #where }

On the previous page the attacker climbed from a normal user to **local admin or SYSTEM** on one host. That is the end of the *first* climb, but it is only one machine. The attacker's real goals — the file server, the finance system, the domain controller — are elsewhere, and they need **accounts that work there**.

Credential dumping is the bridge. ATT&CK files it under the tactic **Credential Access (TA0006)**, technique **T1003 OS Credential Dumping**, with sub-techniques for each place Windows and Linux keep secrets:

| Sub-technique | Where the secrets come from | Admin needed? |
| --- | --- | --- |
| T1003.001 LSASS Memory | Memory of `lsass.exe` — signed-in users' hashes, tickets, sometimes plaintext | Yes (debug-level access to a SYSTEM process) |
| T1003.002 Security Account Manager | `SAM` registry hive — **local** account hashes | Yes |
| T1003.004 LSA Secrets | `SECURITY` hive — service account passwords, machine secrets | Yes (SYSTEM) |
| T1003.005 Cached Domain Credentials | `SECURITY` hive — slow-to-crack hashes of recent domain logons | Yes (SYSTEM) |
| T1003.003 NTDS | `ntds.dit` on a domain controller — **every** domain account | Yes, on a DC |
| T1003.006 DCSync | Asks a DC to replicate password data over the network | Replication rights (usually Domain Admin-level) |
| T1003.007 / .008 | Linux: process memory via `/proc`, `/etc/shadow` | root |

This page focuses on **T1003.001** because that is where the "many users at once" effect comes from. The others are covered in [SAM and NTDS extraction](../../../adversary/sam-ntds-extraction.md) and [DCSync](../../../adversary/dcsync.md).

### Why admin rights are required — and why it is still worth it { #why-admin }

Think of a hotel. Every guest has a key card for their own room. The front desk keeps a master record of all key-card codes in a locked back office. A burglar who has picked one guest's lock (a normal user) can only get into that room. A burglar who has got into the back office (admin) can copy **every guest's code** — and the front desk computer will happily cut new cards from them.

Technically:

- `lsass.exe` runs as **SYSTEM**. To read its memory, a process needs a handle with **`PROCESS_VM_READ`** access to it. Windows only grants that to processes that already have admin rights with **`SeDebugPrivilege`** (debug programs), which by default belongs to `Administrators` — not to normal users.
- The `SAM` and `SECURITY` registry hives are locked to SYSTEM, so even admins have to take extra steps (save the hive, or read it as SYSTEM).

So a normal user can't dump credentials. That is why credential dumping comes **after** privilege escalation. But once admin, the attacker gains three things they didn't have:

1. **Other people's accounts.** The dump returns everyone signed in: the help-desk tech who fixed something yesterday, the scheduled task's service account, the admin who used RDP last week (if their session is still alive).
2. **A form that works elsewhere.** An NTLM hash or a Kerberos ticket can be **replayed** to other machines without ever knowing the password. If the attacker gets **plaintext**, they can also use it in web portals, VPNs, email — anywhere the user reused it.
3. **Persistence through identity.** Malware gets cleaned up; a stolen password keeps working until someone resets it. Many "eradicated" incidents come back because the attacker simply logs in again.

!!! tip "[Supplement] What exactly is a “hash” here, and why it is as good as a password"
    Windows doesn't store your password; it stores the **NT hash** (often called the NTLM hash) — a fixed 32-hex-character value computed from the password. The NTLM authentication protocol proves you know the password by doing maths **with the hash**, not with the password itself. So whoever holds the hash can answer the server's challenge exactly as you would. That is why "they only got the hash" is not reassuring: for NTLM it **is** the credential. Kerberos is similar: a stolen ticket (TGT or service ticket) can be presented as-is until it expires. See [Pass-the-Hash](../../../adversary/pass-the-hash.md) and [Golden and Silver tickets](../../../adversary/golden-silver-tickets.md).

## How Windows single sign-on puts secrets in memory { #sso }

Here is the design choice that makes all of this possible. Microsoft wants you to **type your password once**. After you sign in, opening a file share, your mailbox, an intranet site or a printer should just work — that's **single sign-on (SSO)**.

To do that, Windows has to answer authentication requests **on your behalf**, minutes or hours after you typed the password. So at sign-in the **Local Security Authority Subsystem Service**, `lsass.exe`, keeps what it needs in its own memory, organised by **authentication packages** (security support providers):

| Package | What it keeps | Why |
| --- | --- | --- |
| **MSV1_0** (NTLM) | The NT hash | Answer NTLM challenges for file shares, older apps |
| **Kerberos** | Tickets (TGT, service tickets) and keys derived from the password | Get new service tickets without asking you again |
| **WDigest** | Historically a **reversibly stored plaintext** password | Old HTTP Digest authentication — **off by default** since Windows 8.1 / Server 2012 R2 |
| **TsPkg / CredSSP** | Credentials delegated for RDP / remote sign-in | Pass your sign-in to a remote server |
| **Credential Manager (vault)** | Saved passwords for sites, shares, apps | "Remember my credentials" |

That table *is* the attacker's shopping list. A tool that can read `lsass.exe` memory and understands these structures can pull out a hash per user, tickets per session, and plaintext wherever a package still keeps it.

The analogy: SSO is like handing a trusted concierge copies of all your keys so they can open doors for you all day. It's convenient — until someone robs the concierge.

!!! tip "[Supplement] Which logons leave reusable secrets behind"
    Not every logon parks credentials in `lsass.exe` on the machine being logged on to. This matters enormously for the "many users" problem below.

    | Logon type (4624 `LogonType`) | Example | Reusable secrets left on that host? |
    | --- | --- | --- |
    | 2 Interactive | Signing in at the keyboard | **Yes** |
    | 10 RemoteInteractive | Normal RDP session | **Yes** |
    | 4 Batch / 5 Service | Scheduled task or service with a stored password | **Yes** (and the password is in LSA secrets) |
    | 9 NewCredentials | `runas /netonly` | **Yes** (the alternate credentials) |
    | 3 Network | Opening `\\server\share`, most remote management | **No** (normally only proves identity; no password or reusable hash stored) |

    So an admin who manages a server over a network logon (type 3) leaves far less behind than one who RDPs in (type 10). RDP's **Restricted Admin** mode and **Remote Credential Guard** exist to make RDP behave more like a network logon in this respect.

## Mimikatz { #mimikatz }

### What it is { #what }

**Mimikatz** is an open-source Windows security tool written by a French researcher and first released around 2011. It started as a proof that Windows kept recoverable credentials in memory, and grew into a toolbox for nearly everything to do with Windows credentials: reading them from `lsass.exe`, reading the SAM and LSA secrets, exporting and injecting Kerberos tickets, forging tickets, DCSync, and more. It shows up in breach report after breach report — from ransomware crews to state-sponsored groups — because it is effective, free and well documented. ATT&CK tracks it as software **S0002**.

It is also the main reason for the rule you hear from every defender: **don't use an admin account for daily work, and never sign in to ordinary machines with a domain admin account.** Every time you do, you leave a key in the concierge's pocket.

### How it works, at the level a defender needs { #how-it-works }

You do not need to run Mimikatz to defend against it. You need to know **what it touches**, because that is what you can see:

1. **It needs privilege.** It enables `SeDebugPrivilege` (only possible for admins) or runs as SYSTEM.
2. **It opens a handle to `lsass.exe`** asking for memory-read rights. This is the single most important detection point.
3. **It reads and decodes memory** — locating each authentication package's structures and decrypting the stored secrets with keys that are also in `lsass.exe` memory.
4. **It prints or saves the results**: user name, domain, NT hash, sometimes a plaintext password, Kerberos tickets.

Its commands are grouped in *modules* (for example `sekurlsa` for reading LSASS, `lsadump` for SAM/LSA secrets/DCSync, `kerberos` for tickets). You will see those module names in PowerShell logs, command lines and EDR alerts, so it's worth recognising them — `sekurlsa::logonpasswords` is the classic "dump everything from LSASS" command.

Here is what a **result** looks like when defenders recover it from an attacker's output file or a script log (secrets redacted):

```
Authentication Id : 0 ; 4519873 (00000000:0044f7c1)
Session           : RemoteInteractive from 2
User Name         : b.santos
Domain            : CORP
Logon Server      : DC01
Logon Time        : 2026-11-17 09:12:40
SID               : S-1-5-21-1111111111-2222222222-3333333333-1188
        msv :
         [00000003] Primary
         * Username : b.santos
         * Domain   : CORP
         * NTLM     : [redacted - 32 hex characters]
        wdigest :
         * Username : b.santos
         * Domain   : CORP
         * Password : (null)
        kerberos :
         * Username : b.santos
         * Domain   : CORP.EXAMPLE
         * Password : (null)
```

Reading it line by line:

- `Authentication Id : 0 ; 4519873 (00000000:0044f7c1)` — the **logon session ID** (LUID). The hex value `0x44f7c1` is the same `TargetLogonId` you would find in that user's **4624** event — so you can tie the dump back to *when and how* that user signed in.
- `Session : RemoteInteractive from 2` — the user is signed in over **RDP** (logon type 10). Their secrets are here *because* they used RDP to this box.
- `User Name : b.santos` / `Domain : CORP` / `Logon Server : DC01` — who, which domain, and which DC authenticated them.
- `msv` → `NTLM : …` — the **NT hash**. This alone is enough for pass-the-hash.
- `wdigest` → `Password : (null)` — WDigest isn't caching plaintext (the default on modern Windows). On an old or misconfigured host this line would show the **actual password**.
- `kerberos` → `Password : (null)` — no plaintext from Kerberos either; tickets would be listed by the ticket commands.

A full dump contains one such block **per logon session** — which is the whole point of the next section.

!!! tip "[Supplement] Why old hosts leak plaintext, and the WDigest trick"
    On Windows 7 / Server 2008 R2 and earlier, WDigest kept a decryptable copy of your password by default, so Mimikatz printed plaintext. Microsoft turned that off (built-in from Windows 8.1 / Server 2012 R2, update for older versions), controlled by the registry value `HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest\UseLogonCredential`. Attackers with admin **set it back to `1`** and wait: the next time someone signs in, the plaintext is cached again. That change is easy to catch (Sysmon 13, below) — and ATT&CK files it under **T1112 Modify Registry**.

### Why "just block Mimikatz" doesn't work { #why-not-block }

A reasonable first thought: antivirus knows Mimikatz; block its hash and name, done. It fails for several reasons:

- **Recompiled from source.** The code is public. Compile it yourself and the file hash changes; small changes to strings and structure beat many signatures.
- **Custom builds.** Attackers strip the famous strings, rename functions, pack or encrypt it.
- **Other languages, no file at all.** It has been ported or wrapped into **PowerShell** (the old `Invoke-Mimikatz` script), C#, Python and others. A one-line download cradle can pull such a script from the internet and run it **entirely in memory** — nothing is written to disk for antivirus to scan ([PowerShell download cradles](../../../adversary/powershell-cradles.md)).
- **Built into frameworks.** Many command-and-control frameworks include Mimikatz-like features or load it as a module.
- **Other tools, same technique.** Instead of decoding in place, attackers often **dump the whole `lsass.exe` memory to a file** with a legitimate-looking tool or a built-in Windows DLL, copy the file out, and decode it offline on their own machine. Then *no* Mimikatz ever runs on your network.

So the defender's question is not "did `mimikatz.exe` run?" but "**did anything open `lsass.exe` to read its memory, or write a dump of it?**"

## Finding credential dumping in the logs { #evidence }

### 1. Something opened LSASS — Sysmon 10 { #sysmon10 }

Sysmon **event 10 (ProcessAccess)** records one process opening a handle to another. Configured to watch `lsass.exe`, it is the best single signal:

```
Event ID: 10   Process accessed
UtcTime:        2026-11-18 03:14:22.508
SourceProcessId: 7344
SourceImage:    C:\Users\Public\Music\svchost64.exe
SourceUser:     CORP\adm.jlee
TargetProcessId: 712
TargetImage:    C:\Windows\system32\lsass.exe
TargetUser:     NT AUTHORITY\SYSTEM
GrantedAccess:  0x1010
CallTrace:      C:\Windows\SYSTEM32\ntdll.dll+9d204|C:\Windows\System32\KERNELBASE.dll+2c13e|UNKNOWN(00000204A1B3C2D1)
```

- `Event ID 10` — "process accessed": a handle was opened. It doesn't say what was read, only that the door was opened with certain rights.
- `SourceImage C:\Users\Public\Music\svchost64.exe` — the **opener**. A "svchost" look-alike in a **public user folder** is a fake: the real `svchost.exe` lives in `System32`. Legitimate LSASS openers are a short, known list (your EDR/AV, `MsMpEng.exe`, `wininit.exe`, some management agents).
- `SourceUser CORP\adm.jlee` — an admin account. Remember: dumping *needs* admin, so an admin source user is expected for an attack, not reassuring.
- `TargetImage …\lsass.exe` — the target is the credential store.
- `GrantedAccess 0x1010` — the access mask, which tells you *what kind* of door was opened. Decode it as bits:
    - `0x1000` = `PROCESS_QUERY_LIMITED_INFORMATION` (basic info about the process)
    - `0x0010` = `PROCESS_VM_READ` (**read its memory**)
    - Together, `0x1010` = "let me read LSASS memory" — the classic Mimikatz-style mask. Other masks worth alerting on include `0x1410`, `0x1438`, `0x143a` and `0x1fffff` (full access). Many harmless tools ask only for `0x1000` or `0x1400` (query information, no memory read).
- `CallTrace … UNKNOWN(00000204A1B3C2D1)` — the chain of code that made the call. Normal entries name a DLL on disk. **`UNKNOWN`** means code running from memory that isn't backed by any file — typical of injected or reflectively loaded tools. This is how you catch in-memory Mimikatz even when nothing touched the disk.

### 2. A dump file was written — Sysmon 11 / 4688 { #dump-file }

If the attacker dumps LSASS to a file instead, look for the process that did it and the file it wrote:

```
EventID:            4688
NewProcessName:     C:\Windows\System32\rundll32.exe
CommandLine:        rundll32.exe C:\Windows\System32\comsvcs.dll, MiniDump 712 C:\Windows\Temp\wd.bin full
ParentProcessName:  C:\Windows\System32\cmd.exe
SubjectUserName:    adm.jlee
TokenElevationType: %%1937
```

- `NewProcessName …\rundll32.exe` — `rundll32` runs a function exported from a DLL. A favourite **living-off-the-land** binary ([LOLBins](../../../adversary/lolbins.md)).
- `CommandLine … comsvcs.dll, MiniDump 712 … full` — calls the `MiniDump` function of a built-in Windows DLL on **process ID 712** — which, from the Sysmon 10 event above, is `lsass.exe` — and writes a **full memory dump** to `C:\Windows\Temp\wd.bin`. The file extension is deliberately not `.dmp`.
- `TokenElevationType %%1937` — an **elevated** token (UAC "yes" was given or bypassed). Again: admin is required.

Pair it with **Sysmon 11 (file created)** for `wd.bin`, and with **Sysmon 10** showing `rundll32.exe` opening `lsass.exe`. Then hunt for the file being copied out (SMB from that host, a cloud upload, a new archive). See [LSASS dumping](../../../adversary/lsass-dumping.md) for the wider family (dump utilities, Task Manager's "Create dump file", custom dumpers).

### 3. The PowerShell version in memory — 4104 { #ps4104 }

When the PowerShell port runs from a download cradle, script block logging captures its body:

```
Log Name:       Microsoft-Windows-PowerShell/Operational
Event ID:       4104
Level:          Warning
Computer:       SRV-APP-07.corp.example
User:           CORP\adm.jlee
Message:        Creating Scriptblock text (3 of 112):
                ...
                function Invoke-Mimikatz
                ...
                $PEBytes64 = "TVqQAAMAAAAEAAAA//8AALgAAAAAAAAAQAAAAAAA...
ScriptBlock ID: 0c4a8f1e-5b77-4d2a-9e63-4f1d0a2b9c11
Path:
```

- `Level Warning` — PowerShell itself marked this block **suspicious** and logged it automatically.
- `(3 of 112)` — a very large script split across 112 events; join them with the `ScriptBlock ID`.
- `function Invoke-Mimikatz` — the classic function name (attackers often rename it, so don't rely on this alone).
- `$PEBytes64 = "TVqQ…"` — a long Base64 string starting with `TVqQ`, which is Base64 for `MZ` — the start of a **Windows executable**. The script carries a whole program inside itself and loads it into memory. A huge Base64 blob that begins with `TVqQ` in a script block is suspicious whatever the function is called.
- `Path:` empty — not from a file on disk; it came from memory or the command line.

AMSI lets Defender or your EDR inspect the same text at run time and block it.

### 4. Someone turned plaintext caching back on — Sysmon 13 { #wdigest }

```
Event ID: 13   Registry value set
UtcTime:      2026-11-18 03:09:57.114
Image:        C:\Windows\System32\reg.exe
TargetObject: HKLM\System\CurrentControlSet\Control\SecurityProviders\WDigest\UseLogonCredential
Details:      DWORD (0x00000001)
User:         CORP\adm.jlee
```

- `TargetObject …\WDigest\UseLogonCredential` — the switch for plaintext caching.
- `Details DWORD (0x00000001)` — set to **1 = on**. On a modern Windows host there is almost never a legitimate reason. Alert on any write of `1` here, then expect a dump after the next sign-in.

### 5. Stolen credentials being used — 4624 { #use }

The dump itself is quiet on the network; **using** the result is not. Two patterns are worth knowing (logon events get their own page in a later section):

On the attacker's host, a pass-the-hash launcher typically starts a process with **new credentials**:

```
EventID:                   4624
LogonType:                 9
LogonProcessName:          seclogo
AuthenticationPackageName: Negotiate
SubjectUserName:           adm.jlee
TargetUserName:            adm.jlee
TargetOutboundUserName:    c.ito
TargetOutboundDomainName:  CORP
```

- `4624` — "an account was successfully logged on".
- `LogonType 9` — **NewCredentials**: "keep my local identity, but use *different* credentials for network access" — what `runas /netonly` does. Legitimate, but rare on most workstations and servers.
- `LogonProcessName seclogo` — the Secondary Logon service. Logon type 9 with `seclogo` from an unusual process is a well-known pass-the-hash pattern.
- `TargetOutboundUserName c.ito` — the network identity being used: **someone else's account**, i.e. the stolen credential.

On the machine the attacker moves to, the logon arrives as a network logon using NTLM:

```
EventID:                   4624
Computer:                  FS-FIN-02.corp.example
LogonType:                 3
TargetUserName:            c.ito
LogonProcessName:          NtLmSsp
AuthenticationPackageName: NTLM
LmPackageName:             NTLM V2
KeyLength:                 0
WorkstationName:           SRV-APP-07
IpAddress:                 10.20.4.37
```

- `LogonType 3` — network logon (share access, remote service, etc.).
- `TargetUserName c.ito` — the account used.
- `AuthenticationPackageName NTLM` / `LogonProcessName NtLmSsp` — NTLM rather than Kerberos. In a modern domain most logons between domain machines use Kerberos; pass-the-hash forces **NTLM**.
- `KeyLength 0` — no session key — common for NTLM network logons and often seen with pass-the-hash.
- `WorkstationName SRV-APP-07` / `IpAddress 10.20.4.37` — **where** it came from. If `c.ito` is a finance user who has never signed in from an application server, this is the lead.

No single 4624 proves pass-the-hash, but *Sysmon 10 on SRV-APP-07 → 4624 type 9 seclogo → new NTLM type 3 logons from SRV-APP-07 for accounts that never used it* is a chain that very rarely has an innocent explanation.

### 6. Breaking LSA protection — 7045 { #driver }

If LSA protection is on (below), plain Mimikatz can't open `lsass.exe`. Attackers then try to remove the protection using a **kernel driver** — Mimikatz ships one (`mimidrv.sys`), and vulnerable signed drivers are used the same way (BYOVD, see [Privilege Escalation](privilege-escalation.md#kernel)). Loading a driver creates a service:

```
EventID:      7045
Service Name: mimidrv
Image Path:   C:\Users\Public\Music\mimidrv.sys
Service Type: kernel mode driver
Start Type:   demand start
Account Name:
```

- `Service Type kernel mode driver` — code that will run **in the kernel**.
- `Image Path` in a public user folder — drivers belong in `System32\drivers` or vendor folders.
- `Service Name mimidrv` — the default name, though anyone serious will rename it. The *shape* (new kernel driver from a user-writable path, just before LSASS access) is the real signal.

## From one admin to the whole network { #chain }

### The chain, step by step { #steps }

Here is why attackers love this so much. Follow one compromise:

```
[Alice's laptop]          admin: Alice           signed in: Alice
      | dump  -> Alice's hash
      v
[App server SRV-APP-07]   admin: Alice (help-desk group)   signed in: Bob, Charlie (RDP)
      | dump  -> Bob's and Charlie's hashes
      v
[Charlie's laptop]        admin: Charlie         signed in: Charlie, d.admin (left an RDP session)
      | dump  -> domain admin's hash
      v
[Domain admin's laptop / DC]  -> every account in the domain -> sensitive data, ransomware
```

1. **Alice's laptop.** Alice opens a malicious attachment; the attacker escalates to admin and dumps. They get **Alice's** credential. Alice is a member of a help-desk group that is local admin on many servers.
2. **SRV-APP-07.** With Alice's hash the attacker logs in to an application server where **Bob and Charlie are signed in over RDP**. Dump again: now they have **Bob's and Charlie's** credentials too. One compromise has become three.
3. **Charlie's laptop.** Charlie is admin on his own laptop. The attacker moves there, dumps, and finds that a **domain admin** RDP'd in to fix something last week and the session is still open.
4. **Game over.** With domain admin, the attacker can reach every machine and every account — steal data, push ransomware through Group Policy, create backdoor accounts.

The analogy: one picked lock gives you a master key ring from the front desk; one key on that ring opens the staff office, which has another ring; and eventually you find the building manager's ring.

Two lessons hide in the diagram:

- **A shared server with many signed-in users is a jackpot.** Terminal servers, jump hosts, and any server where admins RDP in are worth far more to an attacker than a single workstation. Protect them as such.
- **Admin rights are the chain's links.** Every hop worked because some account was **admin on the next machine**. If Alice weren't local admin on SRV-APP-07, or if Charlie weren't admin on his laptop, the chain would break. That's why "control your administrative credentials" is the single most important Windows-network defence.

### Breaking the chain { #defend }

| Defence | Which link it breaks |
| --- | --- |
| **Tiering / no high-privilege sign-in on low-trust machines** (domain admins only on DCs and dedicated admin workstations) | There's no domain-admin secret on Charlie's laptop to steal |
| **Unique local admin passwords — LAPS** (Windows LAPS is built in) | One stolen local admin hash no longer works on every workstation |
| **Remove standing local admin** for users and broad help-desk groups; use just-in-time elevation | The hop to the next machine fails |
| **Network logons instead of RDP for admin tasks**; RDP with **Restricted Admin** or **Remote Credential Guard** | Admins stop leaving reusable secrets on servers |
| **Protected Users group** for admins | No NTLM, no cached credentials, short Kerberos tickets — less to steal and shorter use |
| **Credential Guard** | NT hashes and Kerberos TGTs are moved into an isolated, virtualisation-protected process; reading `lsass.exe` no longer returns them |
| **LSA protection (RunAsPPL)** | `lsass.exe` runs as a protected process; even admin tools can't open it for memory read without a kernel driver |
| **Defender ASR rule "Block credential stealing from the Windows local security authority subsystem"** | Blocks untrusted processes from reading LSASS memory |
| **WDigest off and monitored** | No plaintext to recover |

!!! tip "[Supplement] Checking that Credential Guard and LSA protection are actually running"
    Don't assume — check. For Credential Guard:

    ```powershell
    Get-CimInstance -Namespace root\Microsoft\Windows\DeviceGuard -ClassName Win32_DeviceGuard |
      Select-Object SecurityServicesConfigured, SecurityServicesRunning
    ```

    ```
    SecurityServicesConfigured SecurityServicesRunning
    -------------------------- -----------------------
    {1, 2}                     {1, 2}
    ```

    - `Get-CimInstance … Win32_DeviceGuard` — queries the virtualisation-based security status.
    - `SecurityServicesConfigured {1, 2}` — what policy *asks* for: `1` = Credential Guard, `2` = memory integrity (HVCI).
    - `SecurityServicesRunning {1, 2}` — what is *actually running*. If `1` is missing here, Credential Guard is configured but not running (often a hardware or firmware gap).

    For LSA protection, look in the **System** log for **WinInit event 12**, written at boot: "LSASS.exe was started as a protected process with level: 4". If it is missing, LSASS is not protected. Plug-ins blocked from loading into protected LSASS appear in `Microsoft-Windows-CodeIntegrity/Operational` (for example events 3033 and 3063).

## The 2026 view { #trends }

!!! success "[2026 Current] Still valid"
    Credential dumping is still one of the most common steps in hands-on intrusions and ransomware cases, and LSASS memory (T1003.001) is still the favourite source. Mimikatz itself is still seen, but more often its **technique** appears through other tools, built-in Windows DLLs, custom dumpers and C2 modules — exactly why behaviour-based detection (handle to `lsass.exe`, dump file creation, `UNKNOWN` call traces) is the standard. The chain from one admin to many accounts still describes how most domain compromises happen, and "don't put privileged credentials on low-trust machines" is still the core advice.

!!! info "[Changed] What has changed"
    - **Credential Guard is on by default in more places.** Starting with Windows 11 22H2 and Windows Server 2025, Microsoft turns it on by default on domain-joined, non-domain-controller systems that meet the requirements (Enterprise/Education editions, VBS and Secure Boot capable hardware), without UEFI lock. Where it runs, dumping LSASS no longer yields NT hashes or TGTs of signed-in domain users.
    - **LSA protection is on by default on new enterprise installs.** On Windows 11 22H2 and later it is enabled automatically for **new installs** (not upgrades) that are enterprise-joined (AD, Entra or hybrid) and HVCI-capable. Attackers respond with kernel drivers and BYOVD to remove the protection — so watch new drivers (7045, Sysmon 6) as part of credential-theft detection.
    - **NTLM is on its way out.** NTLMv1 was removed in Windows 11 24H2 and Windows Server 2025, and in 2026 Microsoft published a phased plan to disable network NTLM by default in future Windows releases. That shrinks pass-the-hash, but most networks still allow NTLM today; check Microsoft's current guidance for the exact timing in your versions.
    - **Theft has moved toward tokens and the cloud.** In hybrid environments attackers increasingly steal **browser session cookies and cloud tokens** (Entra ID refresh tokens, primary refresh tokens) from endpoints — often with commodity infostealers — instead of or as well as NT hashes. ATT&CK covers this as **T1539 Steal Web Session Cookie** and **T1528 Steal Application Access Token**. LSASS protections don't stop this, so MFA alone is not enough; token protection and device-bound sessions matter.
    - **ATT&CK.** T1003 and its sub-techniques, T1550.002/.003 and Mimikatz (S0002) keep their IDs; the v19 tactic split of Defense Evasion into Stealth and Defense Impairment affects related techniques such as disabling protections, not credential access itself.

!!! warning "[Caution] Where the old way is wrong or risky today"
    - **Don't detect only the name or hash of `mimikatz.exe`.** It will be recompiled, renamed or run in memory. Detect LSASS access, dump creation, WDigest changes and unusual NTLM logons.
    - **Don't assume Credential Guard protects everything.** It doesn't protect the **SAM** (local accounts), **domain controllers** (not recommended there) or `ntds.dit`, and an admin attacker can still capture passwords **typed after** the compromise (for example with a malicious security support provider or a keylogger). Also check it is actually *running*, not just "Windows 11".
    - **Don't trust "it's only a hash".** For NTLM, the hash is the credential. Reset the password — and for very privileged accounts reset twice where Kerberos keys are involved (for `krbtgt`, follow the documented double-reset procedure).
    - **Don't use RDP with a domain admin account to "quickly check" a workstation or a shared server.** That's how the chain above reaches the top. Use a dedicated admin workstation and network-based tools, or Remote Credential Guard.
    - **Don't run LSASS-dumping tools yourself on production for "testing" without approval.** You'll create real credential files that someone must protect, and you'll train your own analysts to ignore the alert.

## Practice questions { #quiz }

### Question 1

On `SRV-APP-07` you find Sysmon event 10: `SourceImage = C:\Users\Public\Music\svchost64.exe`, `TargetImage = C:\Windows\system32\lsass.exe`, `GrantedAccess = 0x1010`, and the `CallTrace` ends in `UNKNOWN(...)`. The source user is `CORP\adm.jlee`. What does each detail tell you, and what do you do next?

??? success "Answer and explanation"
    `0x1010` = `PROCESS_QUERY_LIMITED_INFORMATION` + **`PROCESS_VM_READ`**: something asked to **read LSASS memory** — the core action of credential dumping (T1003.001). The source binary is a fake "svchost" in a public user folder, not a known LSASS opener such as the AV/EDR. `UNKNOWN` in the call trace means the calling code had no file backing it — an injected or in-memory tool. The admin source user is expected (dumping needs admin), so it means `adm.jlee` — or whoever has that session — is compromised.

    Next: isolate the host; treat **every account signed in to SRV-APP-07** around that time as stolen (list them from 4624 events and active sessions — RDP users especially); look for the earlier escalation and how `adm.jlee` was obtained; look for dump files (Sysmon 11), WDigest changes (Sysmon 13) and new drivers (7045); then hunt for **use** of those accounts elsewhere — new NTLM type 3 logons and 4624 type 9 `seclogo` from this host. Reset the affected passwords and review why so many users were signed in to an application server.

### Question 2

A terminal server has 40 users signed in over RDP, including two help-desk accounts that are local admin on all workstations. An attacker gets local admin on it. Why is this so much worse than local admin on a single laptop, and which three changes would most reduce the damage?

??? success "Answer and explanation"
    RDP sessions are **logon type 10** — they leave reusable secrets (NT hashes, Kerberos tickets) in that server's `lsass.exe`. With admin, one dump yields **40 accounts at once**, including two that are admin on every workstation, so the attacker can move to any PC and keep dumping until a more privileged account appears. A single laptop usually holds one or two users.

    The most effective changes: (1) **remove broad standing local admin** from help-desk accounts (just-in-time elevation) and use **LAPS** so local admin passwords differ per machine; (2) **keep privileged accounts off shared servers** — admins use network logons or Remote Credential Guard/Restricted Admin, and put admins in **Protected Users**; (3) turn on **Credential Guard and LSA protection** on that server (and verify they run), plus the ASR rule against LSASS credential theft and Sysmon 10 alerting on LSASS access.

### Question 3

A manager says: "We added the Mimikatz file hash to our antivirus block list and blocked any file named `mimikatz.exe`, so credential dumping is covered." How do you respond?

??? success "Answer and explanation"
    That covers only the least capable attacker. Mimikatz is open source, so a recompiled or modified build has a **different hash**; renaming defeats the name rule; the **PowerShell** and other ports can be pulled by a one-liner and run **only in memory**, with no file to scan; C2 frameworks include the same features; and attackers often skip Mimikatz entirely by **dumping `lsass.exe` to a file** with built-in Windows components (for example `rundll32 comsvcs.dll MiniDump`) and decoding it offline.

    What actually covers it: **behaviour detection** — Sysmon 10 / EDR alerts on processes opening `lsass.exe` with memory-read rights, dump-file creation, 4104 script-block logging and AMSI, WDigest registry changes, new kernel drivers — plus **prevention** that removes the prize: Credential Guard, LSA protection, the ASR rule, Protected Users, LAPS and keeping privileged accounts off low-trust machines.

## Related references { #related }

- [Privilege Escalation](privilege-escalation.md) — the step before this one · [Execution, Persistence and Discovery](execution-persistence-discovery.md)
- [LSASS dumping](../../../adversary/lsass-dumping.md) · [SAM and NTDS extraction](../../../adversary/sam-ntds-extraction.md) · [DCSync](../../../adversary/dcsync.md)
- [Pass-the-Hash](../../../adversary/pass-the-hash.md) · [Golden and Silver tickets](../../../adversary/golden-silver-tickets.md) · [PsExec over SMB](../../../adversary/psexec-smb.md)
- [SMB](../other-protocols/smb.md) — what lateral movement with stolen credentials looks like on the network
- [PowerShell download cradles](../../../adversary/powershell-cradles.md) · [LOLBins](../../../adversary/lolbins.md) · [Windows event IDs](../../../basics/windows-event-ids.md)

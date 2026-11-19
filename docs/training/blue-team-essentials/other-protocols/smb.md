---
title: "SMB — Why Attackers Love It, Versions and Negotiation, Typical Attacks"
tags:
  - training
  - blue-team
  - network
  - smb
  - lateral-movement
---

# SMB — Why Attackers Love It, Versions and Negotiation, Typical Attacks { #smb }

!!! abstract "What this page covers"
    What SMB (Server Message Block) is, why it is one of the most attacked and most successfully abused services inside a network, and why "the same local admin password on every PC" turns one phished laptop into a whole-network compromise. The SMB versions (dialects), how client and server agree on one, why SMB1 must be gone and what that does and doesn't mean for SMB2. Then the two families of SMB attack — logging in with valid credentials (PsExec style) and exploiting the SMB service itself (EternalBlue style) — followed step by step, with the Windows events (4624, 4672, 5140, 5145, 7045, 4697, 4688, Sysmon 1 and 3) and Zeek logs each step leaves. Practice questions with explanations at the end.

!!! note "Labels"
    **[Supplement]** = practical material you need to know, **[Correction]** = a commonly repeated claim that is wrong or outdated, **[Changed]**/**[Caution]** = what has changed recently and what is risky to do the old way. Hostnames, domains, accounts, IPs and file names are invented for illustration (`.example`, documentation and private IPs).

## The 8 key points { #key-points }

1. SMB is the **native Windows file and printer sharing protocol** (Samba implements it on Linux). It runs on **TCP 445** (and the older NetBIOS route on TCP 139), and in a Windows domain it is **open on almost every machine by default**.
2. Port 445 should **never be reachable to or from the internet**. Its danger is inside: once an attacker has one foothold, SMB is available almost everywhere for **reconnaissance and lateral movement**.
3. SMB is not just file copying. With an **administrator's username and password** for a remote machine, SMB lets you **run any program there and get an interactive command line** — similar in power to SSH, but it needs admin rights.
4. That is why **sharing the same admin password across machines** (for example the built-in local Administrator) is one of the deadliest mistakes: compromise one, and you can log in to all of them.
5. Client and server each list the versions (dialects) they speak and **use the highest one both support**. Current Windows speaks SMB **3.1.1**.
6. **SMB1 must be off.** Its weak design is what the worst SMB exploits of the past (EternalBlue and its siblings, used by WannaCry and NotPetya) relied on.
7. SMB attacks fall into two families: **valid credentials + a remote execution tool (PsExec style)** and **a server-side exploit against unpatched SMB (EternalBlue style)**. Either way, the attacker usually ends up as **Administrator or SYSTEM**, not as a normal user.
8. As admin, the attacker can dump the credentials of everyone logged on to that machine (Mimikatz and similar), get more accounts, and move again — so open SMB between workstations makes **a bad situation worse very quickly**.

## What SMB is { #what-is-smb }

When you open `\\SRV-FS-0001\Finance` in File Explorer, map a drive letter, print to a shared printer, or when a domain PC downloads Group Policy from `\\corp.victim.example\SYSVOL`, that is all SMB. It is the protocol Windows uses to say "let me open, read, write and lock files on that other computer," and much more besides, because SMB is also the carrier for **named pipes** — channels that let one computer call management functions on another (remote service control, the registry, scheduled tasks and so on, via DCE/RPC).

- **Windows native.** Every Windows client and server has an SMB client and an SMB server (the "Server" service, `LanmanServer`) built in.
- **Linux too.** Samba is the open-source implementation, so Linux file servers and NAS boxes speak SMB as well.
- **Ports.** **TCP 445** is "SMB directly over TCP" and is what modern systems use. **TCP 139** is the older route, SMB over NetBIOS session service (with UDP 137/138 for NetBIOS names and datagrams). Seeing 139 today usually means old devices or old settings.
- **Open by default in a domain.** Domain PCs need SMB to reach SYSVOL and NETLOGON on the domain controllers, administrators use it to manage PCs, and the Windows firewall on a domain profile commonly allows inbound "File and Printer Sharing". The result: in many networks, **every PC can reach 445 on every other PC**.

Think of a large office building. Each office (PC) has a front door for its own staff, but the building also has a **staff-only service corridor** behind every office, used by maintenance to reach any room with a master key. That corridor is SMB. It is never connected to the street (the internet), but anyone who gets inside the building and gets hold of the master key (an admin password) can walk into every office.

Technically: SMB has **administrative shares** that Windows creates automatically — `C$` (the whole C: drive), `ADMIN$` (the `C:\Windows` folder) and `IPC$` (the entry point for named pipes). Only administrators can use `C$` and `ADMIN$`. Those three shares are the "master key doors" that attack tools use.

## Why attackers love SMB { #why-attackers }

### Admin credentials = remote command execution { #remote-exec }

The key point as a defender: **with admin credentials for a machine, SMB gives you full remote control of it.** The pieces are all ordinary Windows features:

1. Authenticate to the target over SMB (NTLM or Kerberos).
2. Copy a program to `\\target\ADMIN$` (that is, into `C:\Windows`).
3. Open the named pipe `\\target\IPC$\svcctl` (the Service Control Manager's remote interface) and **create a service** that runs that program.
4. Start the service. Services run as **SYSTEM**, the highest local privilege.
5. Talk to the program through more named pipes to get an **interactive command line**.

That is exactly what Sysinternals PsExec does, and what many attack tools copy. To show that it really is just built-in features, here is the manual version an attacker (or administrator) could type:

```
C:\> net use \\10.20.30.52\ADMIN$ /user:LT-FIN-0419\Administrator *
C:\> copy updater.exe \\10.20.30.52\ADMIN$\updater.exe
C:\> sc \\10.20.30.52 create UpdSvc binPath= "C:\Windows\updater.exe" start= demand
C:\> sc \\10.20.30.52 start UpdSvc
```

Line by line:

- Line 1: `net use` connects to the `ADMIN$` share on `10.20.30.52` as the **local** Administrator of that machine (`LT-FIN-0419\Administrator`). `*` makes it prompt for the password. If it answers `The command completed successfully.`, the credentials are valid **and** they are admin on that machine (non-admins get `System error 5 has occurred. Access is denied.`).
- Line 2: `copy` writes `updater.exe` into `C:\Windows` on the remote machine, over SMB.
- Line 3: `sc \\host create` uses the remote service control interface (the `svcctl` pipe over SMB) to register a new service. `binPath=` is the program to run; the space after `=` is required by `sc`'s odd syntax. Output on success: `[SC] CreateService SUCCESS`.
- Line 4: `sc \\host start` starts it. The program now runs as SYSTEM. If it isn't a real service, `sc` reports error 1053 ("did not respond to the start or control request in a timely fashion") — but the program has already started, which is all the attacker needs.

Compare SSH: SSH also gives a remote shell, but any user with an account can log in. SMB remote execution needs **admin rights on the target** — which is why the next point matters so much.

### The shared local admin password problem { #shared-passwords }

Many organisations build PCs from one image, and the image has the same built-in local `Administrator` password on every machine. Now follow the attacker:

1. One user opens a phishing attachment. The attacker controls `LT-FIN-0412`.
2. The attacker gets admin on that PC (an exploit, or the user is already a local admin) and **extracts the local Administrator's password hash** from the SAM database.
3. That same password (or just its NTLM hash — see [pass-the-hash](../../../adversary/pass-the-hash.md)) works on **every other PC built from the same image**.
4. Port 445 is open between all PCs, so the attacker uses SMB to run code on all of them.

Back to the building: it's as if every office lock was keyed to the same key. Steal the key from one office and the whole building is open.

So **one phished machine + shared admin passwords + flat network with 445 open everywhere = full compromise.** The fix is not exotic: a **unique local admin password per machine** (Windows LAPS — see [Changed](#trends)), firewall rules that block 445 between workstations, and admin accounts that are never used on ordinary PCs.

### Worms ride the same road { #worms }

If the malware automates those steps, it becomes a **worm**. WannaCry (May 2017) spread by the EternalBlue exploit over SMB; NotPetya (June 2017) combined EternalBlue/EternalRomance with **stolen credentials and PsExec/WMI**, so even fully patched machines fell if an admin credential was found. That mix is why both spread through entire companies in hours.

## SMB versions and negotiation { #versions }

### The dialects { #dialects }

SMB has had many versions over the years. Each is called a **dialect**.

| Dialect | First shipped with | What it added (simplified) |
| --- | --- | --- |
| SMB1 / CIFS | Windows NT 4.0 era; the main dialect up to XP / Server 2003 R2 | The original. No real integrity protection on negotiation, no encryption, very chatty. CIFS is the name of the NT-era SMB1 dialect |
| SMB 2.0.2 | Windows Vista / Server 2008 | A complete redesign: far fewer commands, larger reads and writes, better signing (HMAC-SHA256) |
| SMB 2.1 | Windows 7 / Server 2008 R2 | Performance (leasing, larger MTU) |
| SMB 3.0 | Windows 8 / Server 2012 | **Encryption** (AES-CCM), multichannel, clustering features |
| SMB 3.0.2 | Windows 8.1 / Server 2012 R2 | Small improvements; option to remove SMB1 |
| SMB 3.1.1 | Windows 10 / Server 2016 | **Pre-authentication integrity** (SHA-512 hash of the negotiation, blocks downgrade), AES-GCM encryption. Later Windows added AES-256, signing with AES-GMAC, and SMB over QUIC |

<strong>[Correction]</strong> You'll often see "SMB 3.1" in lists. The actual dialect number is **3.1.1** (`0x0311`); there is no separate 3.1.

<strong>[Supplement]</strong> "SMB2" and "SMB3" are not two separate protocols. All 2.x and 3.x dialects use the **same SMB2 packet format**; 3.x is just higher dialect numbers with more features. That matters for the "turn off SMB2" advice below.

### How client and server pick one { #negotiation }

The first SMB message is **NEGOTIATE**. The client says "these are the dialects I speak," the server picks **the highest one both sides support**, and the rest of the session uses that. Like two people from different countries checking which languages they share and choosing the one both speak best.

Here is what it looks like in a capture, using tshark (Wireshark's command-line version):

```
$ tshark -r fs-session.pcap -Y "smb2.cmd == 0" -T fields -e frame.time -e ip.src -e ip.dst -e smb2.flags.response -e smb2.dialect
Nov 18, 2026 09:01:12.104  10.20.30.41  10.20.0.20  0  0x0202,0x0210,0x0300,0x0302,0x0311
Nov 18, 2026 09:01:12.106  10.20.0.20  10.20.30.41  1  0x0311
```

The command:

- `-r fs-session.pcap` — read this capture file.
- `-Y "smb2.cmd == 0"` — display filter: only SMB2 command 0, which is NEGOTIATE.
- `-T fields -e …` — print just these fields, tab-separated: time, source, destination, whether it's a response (`smb2.flags.response`, 0 = request, 1 = response), and the dialect(s).

The output:

- Line 1 — the client `10.20.30.41` (a Windows 11 laptop) offers **`0x0202` (2.0.2), `0x0210` (2.1), `0x0300`, `0x0302`, `0x0311`**.
- Line 2 — the file server `10.20.0.20` replies choosing **`0x0311`** = SMB 3.1.1. Everything after this is 3.1.1.

A client that only offers SMB1 doesn't send an SMB2 NEGOTIATE at all; it sends an SMB1 `Negotiate Protocol Request` listing strings like `NT LM 0.12`. In Wireshark the filter `smb` (as opposed to `smb2`) shows SMB1 traffic. **Any SMB1 on a modern network is a finding**: either an old device that needs replacing, or a scanner or exploit tool (many SMB1 exploits and scanners start with an SMB1 negotiate).

Checking on a Windows machine:

```powershell
Get-SmbConnection | Select-Object ServerName, ShareName, UserName, Dialect
```

- `Get-SmbConnection` — lists the SMB connections this machine (as a client) currently has open.
- `Select-Object` — shows only the columns we care about.

```
ServerName   ShareName  UserName          Dialect
----------   ---------  --------          -------
SRV-FS-0001  Finance    CORP\j.kim        3.1.1
dc01         IPC$       CORP\LT-FIN-0412$ 3.1.1
```

Every line should say 3.x. A `2.0.2`, or `1.5` (how Windows displays SMB1), points to an old server or NAS.

And whether SMB1 still exists on a machine:

```powershell
Get-WindowsOptionalFeature -Online -FeatureName SMB1Protocol | Select-Object FeatureName, State
Get-SmbServerConfiguration | Select-Object EnableSMB1Protocol, RequireSecuritySignature, EncryptData
```

```
FeatureName   State
-----------   -----
SMB1Protocol  Disabled

EnableSMB1Protocol RequireSecuritySignature EncryptData
------------------ ------------------------ -----------
             False                     True       False
```

- `SMB1Protocol Disabled` — the SMB1 component is not installed. This is the default on current Windows.
- `EnableSMB1Protocol False` — the server side won't accept SMB1.
- `RequireSecuritySignature True` — the server **requires signing** (each message carries a signature so it can't be altered or relayed).
- `EncryptData False` — encryption isn't forced for all shares (it can be enabled per share or globally).

<strong>[Supplement]</strong> Before removing SMB1 in a big network, you can find out who still uses it: `Set-SmbServerConfiguration -AuditSmb1Access $true` makes the server log **event 3000** in `Microsoft-Windows-SMBServer/Audit` each time a client connects with SMB1, with the client's address. Collect that for a few weeks, fix or replace those clients, then remove SMB1.

### Why SMB1 must go — and what about SMB2? { #smb1 }

SMB1 was designed in an era with no adversaries in mind. The negotiation can be tampered with (forced downgrade), signing is weak and slow so it was usually off, there's no encryption, and the code is old and complex. The 2017 MS17-010 bugs — exploited by **EternalBlue, EternalRomance, EternalSynergy and EternalChampion**, the NSA-built tools leaked by the Shadow Brokers — all live in **the SMB1 server code**. A machine with SMB1 removed simply doesn't have the vulnerable code path. Microsoft's own SMB team has been telling people to stop using SMB1 for years, and current Windows doesn't install it. See [EternalBlue and SMBv1](../../../adversary/eternalblue-smbv1.md) for the exploit itself.

<strong>[Correction]</strong> You may read "ideally turn off SMB2 as well." Be careful with that. Since 2.x and 3.x share one protocol stack, **disabling "SMB2" on Windows (`EnableSMB2Protocol $false`) also disables SMB 3.x** and breaks file sharing, Group Policy and much more; Microsoft explicitly advises against it. The sensible modern version of that advice is: **allow only SMB 3.x** by setting a minimum dialect (supported in Windows 11 24H2 and Windows Server 2025, for example `Set-SmbServerConfiguration -Smb2DialectMin SMB300`), after checking that nothing old still needs 2.x.

## Typical SMB attacks { #attacks }

SMB attacks fall into two families. This picture shows both:

```
                                     ┌─────────────────────────┐
                                     │ SRV-APP-0007 (unpatched)│ ◀── 2) exploit over 445
                                     └─────────────────────────┘     succeeds: SYSTEM
                                                  ▲
   Internet                                       │ SMB exploit (EternalBlue style)
  ┌────────┐   C2 over HTTPS    ┌──────────────┐  │
  │attacker│ ◀────────────────▶ │ LT-FIN-0412  │──┘
  └────────┘                    │ (phished)    │──┐
                                └──────────────┘  │ 1) PsExec with shared
                                     │            │    local admin password
                                     │            ▼
                                     │      ┌──────────────┐   ┌──────────────┐
                                     │      │ LT-FIN-0419  │──▶│ LT-HR-0233   │ ...
                                     │      └──────────────┘   └──────────────┘
                                     ▼
                         ┌──────────────────────────────┐
                         │ SRV-FS-0001 (patched,        │ ◀── exploit blocked:
                         │ host firewall blocks 445)    │     445 filtered
                         └──────────────────────────────┘
```

1. **Credential-based (PsExec style).** The phished laptop gives the attacker a foothold. Using the shared local admin password, they hop to `LT-FIN-0419`, then `LT-HR-0233`, and so on. No vulnerability is needed — **the login is "legitimate"**, which is why antivirus often says nothing.
2. **Exploit-based (EternalBlue style).** From the foothold, the attacker scans for open 445 and fires an exploit at each. `SRV-APP-0007` is unpatched and falls (SYSTEM). `SRV-FS-0001` is patched and its firewall filters 445 from workstations, so the exploit never lands.

In both cases the attacker typically becomes **Administrator or SYSTEM**, not a normal user. And once admin, tools like Mimikatz read the memory of LSASS (the process holding logon secrets) and pull the credentials of **everyone currently logged on** to that machine — maybe a helpdesk or domain admin who logged in to fix something. More accounts, more hops. See [LSASS dumping](../../../adversary/lsass-dumping.md).

### What a PsExec hop looks like in the logs { #psexec-logs }

Let's follow one hop: the attacker on `LT-FIN-0412` (`10.20.30.41`) runs PsExec against `LT-FIN-0419` (`10.20.30.52`) with the local Administrator account. More detail on the technique: [PsExec and SMB lateral movement](../../../adversary/psexec-smb.md).

**On the source (`LT-FIN-0412`) — Sysmon event 3 (network connection):**

```
Event ID: 3   Network connection detected
UtcTime:          2026-11-18 05:14:07.311
Image:            C:\Users\j.kim\AppData\Local\Temp\ps.exe
User:             CORP\j.kim
Protocol:         tcp
SourceIp:         10.20.30.41
DestinationIp:    10.20.30.52
DestinationPort:  445
```

- Sysmon (a free Microsoft tool that adds detailed logging) event **3** records which **process** made a network connection. Windows alone doesn't tell you that.
- `Image` — the program that connected. A **renamed PsExec running from a Temp folder** (`ps.exe`) — real admins don't run tools from a user's Temp.
- `DestinationPort 445` from a **workstation to another workstation**: normal PCs talk SMB to file servers and DCs, not to each other. This one connection is already a strong lead.

**On the target (`LT-FIN-0419`) — Security log 4624 (logon success):**

```
Event ID: 4624   An account was successfully logged on
Logon Type:                3
New Logon:  Account Name:  Administrator
            Account Domain: LT-FIN-0419
            Logon ID:      0x3E1A7F2
Network Information:
            Workstation Name: LT-FIN-0412
            Source Network Address: 10.20.30.41
Detailed Authentication Information:
            Logon Process:          NtLmSsp
            Authentication Package: NTLM
```

- **4624** fires on the machine being logged on to, every time a logon succeeds. (A failure is **4625**; a burst of 4625s for Administrator from one source across many PCs is password spraying or guessing.)
- `Logon Type 3` = **network logon**: someone accessed this machine over the network (SMB, for example), not at its keyboard (2) or via RDP (10).
- `Account Name Administrator`, `Account Domain LT-FIN-0419` — the **local** admin account of this PC, not a domain account. Domain environments rarely have a good reason for local-admin network logons between PCs.
- `Source Network Address 10.20.30.41` — where it came from. With [DHCP](dhcp.md) you turn that into `LT-FIN-0412`.
- `Authentication Package NTLM` — local accounts can't use Kerberos, so NTLM is expected here; it's also what [pass-the-hash](../../../adversary/pass-the-hash.md) uses.
- `Logon ID 0x3E1A7F2` — the session number. **Every following event in this session carries the same Logon ID**, so you can tie them together.

**4672 (special privileges assigned to new logon)** follows immediately with the same Logon ID: the session has admin-level privileges (`SeDebugPrivilege`, `SeBackupPrivilege` and so on). Attackers care because admin is required for this whole technique; defenders care because 4624 type 3 + 4672 from a workstation peer is "an admin just came in over the network."

**5140 (a network share object was accessed):**

```
Event ID: 5140   A network share object was accessed
Account Name:   Administrator      Logon ID: 0x3E1A7F2
Source Address: 10.20.30.41
Share Name:     \\*\ADMIN$
Share Path:     \??\C:\Windows
Access Mask:    0x1
```

- Fires the first time a session touches a share — but **only if "Audit File Share" is enabled** (it isn't by default on workstations).
- `Share Name \\*\ADMIN$` — the administrative share pointing at `C:\Windows`. Normal users never connect to `ADMIN$` on a colleague's PC. **This is the door attack tools use.**

**5145 (detailed file share check)** records the individual file: `Share Name \\*\ADMIN$`, `Relative Target Name PSEXESVC.exe`, `Accesses WriteData (or AddFile)`. It needs "Audit Detailed File Share", which is very noisy on file servers, but on workstations it's quiet enough to be useful.

**System log 7045 (a service was installed in the system):**

```
Event ID: 7045   Source: Service Control Manager
Service Name:       PSEXESVC
Service File Name:  %SystemRoot%\PSEXESVC.exe
Service Type:       user mode service
Service Start Type: demand start
Service Account:    LocalSystem
```

- **7045** is in the **System** log and is on by default: any new service writes it. **4697** is the Security-log twin (needs "Audit Security System Extension").
- `PSEXESVC` is PsExec's default service name (it can be renamed with an option). Impacket's psexec uses **random short names** and random `.exe` names; smbexec-style tools use `cmd.exe` itself as the service binary, so look for `Service File Name` containing `cmd.exe /c`, `%COMSPEC%` or `powershell`.
- Services in `C:\Windows\` with odd names, `demand start`, running as `LocalSystem`, created right after a type 3 logon from a peer: a classic lateral-movement pattern.

**4688 / Sysmon 1 (process creation):** `services.exe` → `PSEXESVC.exe` → `cmd.exe` → whatever the attacker types (`whoami`, `net group "domain admins" /domain`, a credential dumper). 4688 needs "Audit Process Creation" (and the command-line option) enabled; Sysmon 1 includes the command line and hashes by default.

Put together on a timeline (target clock, UTC):

```
05:14:07  4624  type 3, LT-FIN-0419\Administrator, from 10.20.30.41, NTLM, LogonID 0x3E1A7F2
05:14:07  4672  same LogonID, admin privileges
05:14:07  5140  \\*\ADMIN$ from 10.20.30.41
05:14:07  5145  ADMIN$\PSEXESVC.exe WriteData
05:14:08  7045  service PSEXESVC, %SystemRoot%\PSEXESVC.exe, LocalSystem
05:14:08  4688  services.exe -> PSEXESVC.exe
05:14:09  4688  PSEXESVC.exe -> cmd.exe
05:14:15  4688  cmd.exe -> whoami.exe
```

Eight seconds, and the story is complete: **who** (local Administrator), **from where** (`10.20.30.41`), **how** (SMB + new service), **what next** (commands as SYSTEM).

### What the same hop looks like on the wire — Zeek { #zeek-smb }

A network sensor running Zeek sees the same hop without touching the endpoints. Zeek writes several SMB-related logs:

```
# smb_mapping.log — which shares were connected
ts=2026-11-18T05:14:07Z uid=CmQ1z84 id.orig_h=10.20.30.41 id.resp_h=10.20.30.52 id.resp_p=445 path=\\10.20.30.52\ADMIN$ share_type=DISK

# smb_files.log — which files were opened/written
ts=2026-11-18T05:14:07Z uid=CmQ1z84 id.orig_h=10.20.30.41 id.resp_h=10.20.30.52 action=SMB::FILE_WRITE path=\\10.20.30.52\ADMIN$ name=PSEXESVC.exe size=383872

# dce_rpc.log — remote management calls over named pipes
ts=2026-11-18T05:14:08Z uid=CmQ1z84 id.orig_h=10.20.30.41 id.resp_h=10.20.30.52 named_pipe=svcctl endpoint=svcctl operation=CreateServiceW
ts=2026-11-18T05:14:08Z uid=CmQ1z84 id.orig_h=10.20.30.41 id.resp_h=10.20.30.52 named_pipe=svcctl endpoint=svcctl operation=StartServiceW
```

- `uid` — the connection ID. **The same `uid` in all three logs** means one TCP connection did all of this; you can also find it in [conn.log](../../../network/zeek/conn-log.md).
- `smb_mapping.log` `path=\\10.20.30.52\ADMIN$` — a workstation mapping another workstation's admin share.
- `smb_files.log` `name=PSEXESVC.exe` — an executable written to `ADMIN$`. If Zeek's file analysis is on, [files.log](../../../network/zeek/files-log.md) will have its hash.
- `dce_rpc.log` `endpoint=svcctl operation=CreateServiceW` then `StartServiceW` — **remote service creation and start**. That pair over SMB from a workstation is one of the most reliable network-side lateral movement signals. (Other endpoints to know: `atsvc`/`ITaskSchedulerService` = remote scheduled tasks, `winreg` = remote registry, `samr`/`lsarpc` = account and domain enumeration.)

<strong>[Supplement]</strong> When SMB 3 **encryption** is on, Zeek and Wireshark can see the negotiation and authentication but **not** the share paths, file names or RPC calls inside. Signing alone doesn't hide content. So in environments that encrypt SMB, endpoint logs (above) carry more of the weight, and connection metadata (who talks 445 to whom) becomes the network's main contribution.

### What an exploit attempt looks like { #exploit-signals }

The exploit family leaves different traces:

- **SMB1 negotiation where there should be none**, especially from a workstation to many hosts.
- **One source touching 445 on many hosts in seconds** — a scan to find targets. In `conn.log`, many short connections to `445` from one `id.orig_h`, many with `conn_state` `REJ` or `S0` (no answer).
- **IDS signatures.** Public exploits like EternalBlue have well-known network signatures (malformed SMB1 transaction requests, the DoublePulsar backdoor's "ping" responses).
- **On a hit, no logon events.** An exploit doesn't log on, so you may see no 4624 at all — just `lsass.exe` or `spoolsv.exe`-style system processes suddenly spawning `cmd.exe` or `rundll32.exe`, or a crash (`System` log bugcheck) if the exploit fails. Process-tree anomalies from SYSTEM processes are the endpoint clue.

## Defending SMB — what a SOC should push for { #defence }

- **Never expose 445 (or 139) to the internet,** in either direction. Outbound 445 matters too: blocking it stops leaks of NTLM hashes to attacker servers (a malicious link like `\\203.0.113.50\share` makes Windows try to authenticate).
- **Block 445 between workstations** with host firewalls. Workstations need SMB to file servers and DCs, not to each other. This one rule breaks most of the lateral movement above.
- **Unique local admin passwords** on every machine (Windows LAPS), and deny network logon for local accounts on workstations (the "Deny access to this computer from the network" right for the `Local account and member of Administrators group` principal).
- **Remove SMB1**, patch SMB, and require **signing** (blocks NTLM relay over SMB — see [LLMNR and NTLM relay](../../../adversary/llmnr-ntlm-relay.md)).
- **Protect credentials in memory** (Credential Guard, LSA protection) and keep privileged accounts off ordinary PCs (admin tiering).
- **Detect:** workstation-to-workstation 445; `ADMIN$`/`C$` access from non-admin hosts; 7045/4697 new services right after a type 3 logon; Zeek `svcctl CreateServiceW`; any SMB1.

## The 2026 view { #trends }

!!! success "[2026 Current] Still valid"
    SMB is still Windows' file-sharing and remote-management backbone on TCP 445, still open across most internal networks, and still one of the main roads for lateral movement and ransomware deployment. PsExec-style remote service creation, admin shares, the shared-local-admin-password problem, credential theft from LSASS after getting admin, and "SMB1 must be gone" are all exactly as described. The detection pairs (4624 type 3 + 4672 + 7045, Zeek `svcctl` calls) are unchanged.

!!! info "[Changed] What has changed"
    - **Secure defaults in Windows 11 24H2 and Windows Server 2025.** SMB **signing is required by default for all inbound and outbound connections** (previously only SYSVOL/NETLOGON and DC connections), **guest fallback is off** (Windows 11 Pro no longer allows guest access), an **authentication rate limiter** adds a 2-second delay after each failed NTLM or local Kerberos attempt (which makes password guessing over SMB slow), the SMB client **can block NTLM** for outbound connections, administrators can set **minimum and maximum dialects**, and SMB1 is not installed. Older NAS boxes that don't support signing may fail to connect after upgrading — the right fix is to update the NAS, not to switch signing off.
    - **NTLM is on the way out.** Microsoft has deprecated NTLM and removed NTLMv1 in Windows 11 24H2 and Windows Server 2025. NTLM (v2) itself still works and is still what local-account SMB logons and pass-the-hash use, so it remains very relevant to detection.
    - **SMB over QUIC** (SMB inside TLS 1.3 over UDP 443, for remote users without VPN) is available in all Windows Server 2025 editions. If you see SMB-to-server traffic on UDP 443, it may be legitimate — but it also means "445 blocked at the edge" no longer describes every SMB path.
    - **Windows LAPS** is built into Windows (since 2023 updates) and can store passwords in Entra ID or AD, so there's no excuse left for shared local admin passwords.
    - **SMB vulnerabilities didn't stop with 2017.** SMBGhost (CVE-2020-0796, SMB 3.1.1 compression) showed even SMB3 code can be wormable, and CVE-2025-33073 (an SMB client flaw that bypasses NTLM reflection protections and can give SYSTEM on machines that don't enforce signing) was patched in June 2025 and added to CISA's Known Exploited Vulnerabilities list in October 2025.
    - **Ransomware still pushes payloads over SMB** — copying the encryptor to `ADMIN$`/`C$` and starting it with services, scheduled tasks or PsExec — and often **encrypts file shares remotely over SMB** from one machine, so the file server shows mass file writes from a single client rather than local malware.

!!! warning "[Caution] Wrong or risky to do the old way"
    - **Don't disable "SMB2" to get rid of old dialects.** On Windows that also turns off SMB 3.x. Set a minimum dialect instead.
    - **Don't treat "445 is blocked at the internet edge" as enough.** The danger is internal; block 445 between workstations too.
    - **Don't rely only on network logs** if SMB encryption is on — share names and file names are hidden. Make sure 4624/4672/7045 (and ideally 5140/5145 on workstations, Sysmon 1/3) reach your SIEM.
    - **Don't hunt only for the name `PSEXESVC`.** It can be renamed, and other tools use random names or `cmd.exe` as the service binary. Hunt the behaviour: type 3 admin logon from a peer → admin share write → new service.
    - **Don't turn signing off to "fix" an old NAS or printer after a Windows upgrade.** That reopens NTLM relay. Update or replace the device.

## Practice questions { #quiz }

### Question 1

A colleague says, "SMB is just file sharing. The worst an attacker can do with it is read our documents." Explain why that is wrong, and what makes a shared local Administrator password so dangerous in a network where 445 is open between all PCs.

??? success "Answer and explanation"
    **Why it's wrong:** with **admin credentials** for a machine, SMB is a **remote execution** channel, not just file access. Through the admin shares (`ADMIN$`, `C$`) an attacker can copy a program onto the target, then use the `svcctl` named pipe over `IPC$` to create and start a **service** that runs it as **SYSTEM** — exactly what PsExec does — and get an interactive command line. It's comparable to SSH, except it needs admin rights.

    **Why shared passwords are deadly:** if every PC has the same local Administrator password, stealing it (or its NTLM hash) from **one** phished machine gives admin on **all** of them. With 445 reachable between PCs, the attacker can hop machine to machine (or a worm can do it automatically, as NotPetya did), and on each one dump the credentials of whoever is logged on, until they find a domain admin. One infected laptop → full compromise. The fixes: unique passwords per machine (Windows LAPS), block 445 between workstations, deny network logon for local admin accounts.

### Question 2

On `LT-HR-0233` (`10.20.30.77`) you find these events, all with Logon ID `0x51C0D9`. Describe what happened and list what you would check next.

```
07:42:10  4624  Logon Type 3, Account LT-HR-0233\Administrator, Source 10.20.30.52, NTLM
07:42:10  4672  special privileges
07:42:10  5140  \\*\ADMIN$
07:42:11  7045  Service Name: XbKq  File: %SystemRoot%\wQmTrGfA.exe  LocalSystem  demand start
```

??? success "Answer and explanation"
    **What happened:** someone at `10.20.30.52` logged on **over the network** (type 3) as this PC's **local Administrator** using NTLM, got admin privileges (4672), opened the **`ADMIN$`** share (5140), and within a second a **new service with a random name** (`XbKq`) running a **random-named exe from `C:\Windows`** as **SYSTEM** was installed (7045). That's remote service-based execution — the PsExec pattern, and the random names fit Impacket-style tools rather than real Sysinternals PsExec. This is lateral movement **from `10.20.30.52`** (which, in the example above, was itself a victim — `LT-FIN-0419`).

    **Next checks:**

    1. Process creation (4688/Sysmon 1) on `LT-HR-0233` after 07:42:11: what `wQmTrGfA.exe` launched (child processes, command lines), and its hash.
    2. Map `10.20.30.52` to a device with DHCP at 07:42, then look on that machine for the source side (Sysmon 3 to 445, the tool that ran) and how **it** was compromised — follow the chain back.
    3. Search all hosts for the same pattern (type 3 local Administrator logons from workstations, 7045 with random names) to find every hop.
    4. Credential exposure: which accounts were logged on to `LT-HR-0233`; assume their secrets are stolen and reset them. Rotate the local Administrator password everywhere (LAPS).
    5. Network: Zeek `dce_rpc.log` for `svcctl CreateServiceW` from `10.20.30.52` to others.

### Question 3

During a review you find these three things. For each, say whether it's a problem and what you'd do: (a) one old NAS that only negotiates SMB 2.0.2; (b) `smb` (SMB1) packets from a workstation to 40 different hosts within one minute; (c) a server admin proposes `Set-SmbServerConfiguration -EnableSMB2Protocol $false` "to get rid of old SMB2".

??? success "Answer and explanation"
    **(a)** Not an emergency, but a weakness. SMB 2.0.2 has no encryption and older signing, and if you move to an SMB 3.x-only minimum dialect that NAS will break. Plan a firmware update or replacement, check whether it supports signing (Windows 11 24H2/Server 2025 clients require signing by default), and keep it off networks where it isn't needed.

    **(b)** **A serious finding.** Modern Windows doesn't speak SMB1 by default, and one workstation touching 445 on 40 hosts in a minute is **scanning** — very likely an SMB1 exploit or vulnerability scanner (EternalBlue-style tools start with SMB1 negotiation). Treat the workstation as compromised: isolate it, check its process that made the connections (Sysmon 3), check the targets for signs of a successful exploit (unexpected child processes of system processes, crashes), and confirm SMB1 is removed everywhere.

    **(c)** **Don't do it.** On Windows, SMB 2.x and 3.x share one protocol stack, so disabling "SMB2" **also disables SMB 3.x**, breaking file shares and Group Policy. The correct way to drop old dialects is to set a minimum dialect (e.g. `-Smb2DialectMin SMB300` on Windows Server 2025 / Windows 11 24H2) after confirming no client still needs 2.x — like the NAS in (a).

## Related { #related }

- [PsExec and SMB lateral movement](../../../adversary/psexec-smb.md)
- [EternalBlue and SMBv1](../../../adversary/eternalblue-smbv1.md)
- [Pass-the-hash](../../../adversary/pass-the-hash.md) · [LSASS dumping](../../../adversary/lsass-dumping.md) · [LLMNR and NTLM relay](../../../adversary/llmnr-ntlm-relay.md)
- [Windows event IDs](../../../basics/windows-event-ids.md)
- [Zeek conn.log](../../../network/zeek/conn-log.md) · [Zeek files.log](../../../network/zeek/files-log.md)
- [DC, SMB and Snort rules lab](../../pcap-ir-labs/dc-smb-and-snort-rules.md)

---
title: "Credential Guard, Application Guard, Host Firewalls and Antivirus — Isolating Secrets and Fencing the Host"
tags:
  - training
  - blue-team
  - endpoint
  - hardening
  - credential-guard
  - firewall
  - antivirus
---

# Credential Guard, Application Guard, Host Firewalls and Antivirus — Isolating Secrets and Fencing the Host { #vbs-firewall-antivirus }

!!! abstract "What this page covers"
    The next layers after patching and exploit protection. First, virtualization-based security (VBS): how Credential Guard moves the secrets in LSASS into a separate, hypervisor-protected world so that even an administrator can no longer dump them, how to check that it is really running, and what it does *not* protect; then Application Guard, the same idea applied to risky browsing and Office documents (and why it is now retired). Second, host firewalls: profiles, default-deny, why outbound rules matter, how to read `pfirewall.log` and Windows Filtering Platform events (5156/5157), and why a host firewall beats a network firewall for stopping and *seeing* lateral movement. Third, antivirus: signatures vs machine learning, the in-memory gap, how attackers disable it, how to read Defender detection events (1116/1117) and how to find the one interesting detection among hundreds of boring ones. Practice questions with explanations at the end.

!!! note "Labels"
    **[Supplement]** = practical material you need to know, **[Correction]** = a commonly repeated claim that is wrong or outdated, **[Changed]**/**[Caution]** = what has changed recently and what is risky to do the old way. Hostnames, domains, accounts, IPs and file names are invented for illustration (`.example`, documentation and private IPs).

## The 8 key points { #key-points }

1. **Virtualization-based security (VBS)** uses the CPU's virtualization features and the Hyper-V hypervisor to create a small, separate "secure world" that the normal Windows kernel cannot read or change — even with SYSTEM or kernel access.
2. **Credential Guard** puts the secrets that LSASS holds (NTLM hashes, Kerberos tickets and keys) into that secure world, in a process called `LsaIso.exe`. `lsass.exe` still exists but only acts as a messenger. Dumping LSASS memory now returns encrypted blobs instead of usable hashes — this blunts **credential dumping (T1003.001)**, **pass-the-hash (T1550.002)** and **pass-the-ticket (T1550.003)**.
3. Credential Guard is **not** a complete fix: it does not protect local SAM accounts, keystrokes, passwords typed into apps, or a malicious security package that catches *new* logons. Check it is actually running (`Win32_DeviceGuard`, `LsaIso.exe`) instead of assuming.
4. **Application Guard** applied the same isolation to risky activity — untrusted websites in Edge and internet documents in Office ran inside a throwaway Hyper-V container. It is now **deprecated and removed** from current Windows 11; know it for older estates and exam questions, not for new designs.
5. **Host firewalls** work at several stages at once — exploitation, lateral movement, C2 and exfiltration. Use **profiles** (Domain/Private/Public), **default-deny inbound**, and outbound deny where you can define it.
6. Host firewall logs are a superb sensor **if they are filtered tactically** — log blocked connections on the ports attackers love (SMB, RDP, WinRM, SSH) and exclude known scanners; logging everything just floods the SIEM.
7. Compared with a network firewall alone, host firewalls **stop and record traffic between two machines on the same subnet** — traffic a network firewall never sees. "Workstation talked SMB to workstation" becomes a simple, high-value alert.
8. **Antivirus** mainly stops the installation stage. Signatures catch known malware; machine-learning engines catch new variants; in-memory scanning (e.g. via AMSI) closes the fileless gap. It can be bypassed, but it removes commodity noise — and the **rare, never-seen-before detection** is often the start of a real incident.

## Virtualization-based security — a separate room for secrets { #vbs }

### The problem Credential Guard solves { #why-credential-guard }

In [Credential Dumping and Mimikatz](../endpoint-attacks/credential-dumping-mimikatz.md) you saw why attackers love `lsass.exe`. The **Local Security Authority Subsystem Service** handles logons, so to make single sign-on work it keeps secrets in memory: NT hashes of logged-on users, Kerberos tickets (TGTs) and their session keys, and on badly configured systems even cleartext passwords. Anyone with administrator rights — specifically the ability to open another process's memory (`SeDebugPrivilege`) — can read that memory and walk away with those secrets. That is **T1003.001 OS Credential Dumping: LSASS Memory**, and it feeds directly into **T1550.002 Pass the Hash** and **T1550.003 Pass the Ticket** for lateral movement.

The classic defences — "don't let users be admins", "don't log on to workstations with domain admin accounts" — are good, but they all fail the moment an attacker gets SYSTEM. On a normal Windows system, SYSTEM can read everything. So the question becomes: can we keep a secret even from SYSTEM?

### The idea: a vault the building manager can't open { #vbs-idea }

Imagine a bank where the vault is not in the basement of the main building but in a separate, sealed building next door. Tellers in the main building can't walk in. They can only pass a request slip through a small hatch — "please check this signature", "please stamp this cheque" — and get the answer back. Even if a robber takes over the entire main building, including the manager's office and every master key, the vault is still out of reach; all the robber can do is pass slips through the hatch, and the vault staff only answer specific, well-defined questions.

Technically, the "separate building" is created by the **hypervisor**. When VBS is on, Windows boots Hyper-V underneath itself and splits the machine into two **virtual trust levels (VTLs)**:

- **VTL0 — the normal world.** The regular Windows kernel, drivers, `lsass.exe`, and all your applications. This is where an attacker lives, even with kernel access.
- **VTL1 — the secure world.** A tiny **secure kernel** and a few **trustlets** (isolated user-mode processes). The hypervisor uses the CPU's second-level address translation (SLAT) to mark VTL1 memory as off-limits to VTL0. The normal kernel can't map those pages, no matter what privilege it has.

With **Credential Guard** turned on, the secrets move into a trustlet called **`LsaIso.exe`** (LSA Isolated) in VTL1. `lsass.exe` is still running in VTL0 — logons still go through it — but when it needs to use a credential (for example to answer an NTLM challenge or get a Kerberos service ticket), it asks `LsaIso.exe` over a narrow, defined channel. `LsaIso.exe` does the cryptography and hands back only the *result*, never the hash or key itself. That narrow channel is the "hatch" in the analogy.

### What an attacker's dump looks like afterwards { #dump-with-cg }

You don't need to run an attack tool to understand the effect. When a dumping tool reads LSASS memory on a machine without Credential Guard, the output for a logged-on user contains a readable NT hash. With Credential Guard on, the same field is replaced by something like this (shortened, invented values):

```
Authentication Id : 0 ; 4810233 (00000000:00496ff9)
User Name         : m.lee
Domain            : CORP
        msv :
         [00000003] Primary
         * Username : m.lee
         * Domain   : CORP
           * LSA Isolated Data: NtlmHash
             Unk-Key  : 4a1f...e90c
             Encrypted: 7b22c1...0d3f9a (long encrypted blob)
```

Line by line:

- `Authentication Id`, `User Name`, `Domain` — the logon session the tool found. These are still visible; Credential Guard hides secrets, not the fact that someone is logged on.
- `msv` — the NTLM authentication package's data for that session.
- `LSA Isolated Data: NtlmHash` — the tool recognises the hash *is* there, but it is held in isolated form.
- `Encrypted: …` — a blob encrypted with a key that exists only inside VTL1. Without that key it is useless for pass-the-hash.

Kerberos tickets get the same treatment: the TGT session keys stay in `LsaIso.exe`, so stolen ticket data can't simply be replayed elsewhere.

### Requirements and how to check it is really on { #cg-requirements }

Credential Guard needs hardware and firmware support:

- 64-bit Windows, **UEFI** firmware (not legacy BIOS) and **Secure Boot**.
- CPU virtualization extensions (**Intel VT-x** or **AMD-V**) with **SLAT** (Intel EPT / AMD RVI).
- A **TPM** (1.2 or 2.0) is strongly recommended so the keys that protect Credential Guard's configuration are bound to the hardware.
- Edition: Windows 10/11 **Enterprise or Education**, and Windows Server 2016 or later. It is not supported on domain controllers (a DC stores credentials in the AD database, which Credential Guard doesn't cover).

It is enabled through Group Policy (*Computer Configuration → Administrative Templates → System → Device Guard → Turn On Virtualization Based Security*, Credential Guard option), Intune, or registry. "The policy is set" and "it is running" are different things — firmware settings, missing virtualization support, or a driver incompatibility can quietly stop it. Check:

```powershell
Get-CimInstance -Namespace root\Microsoft\Windows\DeviceGuard -ClassName Win32_DeviceGuard |
  Select-Object VirtualizationBasedSecurityStatus, SecurityServicesConfigured, SecurityServicesRunning
```

```
VirtualizationBasedSecurityStatus SecurityServicesConfigured SecurityServicesRunning
--------------------------------- -------------------------- -----------------------
                                2 {1, 2}                     {1, 2}
```

- `Get-CimInstance … Win32_DeviceGuard` — reads the Device Guard / VBS status class that Windows maintains.
- `VirtualizationBasedSecurityStatus 2` — VBS is enabled **and running** (`1` = enabled but not running, `0` = not enabled).
- `SecurityServicesConfigured {1, 2}` — what policy asked for: `1` = Credential Guard, `2` = memory integrity (HVCI, hypervisor-protected code integrity).
- `SecurityServicesRunning {1, 2}` — what is actually running. If `1` is in *Configured* but missing from *Running*, the policy is set but Credential Guard is not protecting anything. That gap is the line to report.

Two more quick checks:

```
C:\> tasklist /fi "imagename eq lsaiso.exe"

Image Name                     PID Session Name        Session#    Mem Usage
========================= ======== ================ =========== ============
LsaIso.exe                     812 Services                   0      1,820 K
```

- A running `LsaIso.exe` means the isolated LSA trustlet started. No such process → no Credential Guard.

In the **System** event log, source `Microsoft-Windows-Wininit`, **event 13** says Credential Guard (`LsaIso.exe`) was started and will protect LSA credentials; events reporting that it failed to start or that its configuration couldn't be loaded point to misconfiguration. Collect these from your fleet and you get a cheap "which machines are really protected?" report. `msinfo32` (System Summary → *Virtualization-based security Services Running*) shows the same thing for one machine.

### What Credential Guard does not protect { #cg-limits }

This is where people overestimate it. Credential Guard protects **derived secrets that LSA holds for domain accounts**. It does not protect:

- **Local accounts in the SAM.** Local password hashes are stored in the registry and on disk, outside LSA's isolated store. Dumping them (**T1003.002 Security Account Manager**) still works with admin rights — which is why unique local admin passwords (LAPS) still matter.
- **Keystrokes and screen.** A keylogger (**T1056.001**) sees the password as it is typed.
- **New logons caught by a malicious security package.** An attacker with admin rights can register a rogue Security Support Provider (**T1547.005**) that receives the cleartext password of users who log on *after* it is installed. Credential Guard protects what is stored, not what is typed in the future.
- **Passwords typed into other applications**, browsers' saved passwords, cached credentials for other protocols, or credentials sitting in files and scripts.
- **The account itself.** If the attacker can use the session (run commands as the logged-on user), they don't need the hash — they just act as that user while they're on the box.

And it has side effects you should know before rolling it out: it blocks NTLMv1, MS-CHAPv2 and Digest single sign-on, Kerberos unconstrained delegation and DES encryption for protected credentials. The common real-world complaint is Wi-Fi or VPN using PEAP-MSCHAPv2 with saved credentials breaking.

**[Supplement] Credential Guard vs LSA protection.** These two get confused all the time.

| | LSA protection (`RunAsPPL`) | Credential Guard |
| --- | --- | --- |
| What it does | Runs `lsass.exe` as a *protected process light*; non-protected processes can't open it for memory reads or inject into it | Moves the secrets themselves out of `lsass.exe` into VTL1 |
| Protects against | User-mode tools opening LSASS, even as admin | Also kernel-level attackers, because VTL0's kernel can't read VTL1 |
| Weak spot | An attacker who loads a kernel driver (often a vulnerable signed one) can remove the protection | Local SAM accounts, keyloggers, rogue SSPs, the limits above |
| Needs | No special hardware | VBS hardware, Enterprise/Education |

Use both. LSA protection logs attempts it blocks (in the `Microsoft-Windows-CodeIntegrity/Operational` log, e.g. a driver or DLL that failed to load into LSASS), and the ASR rule *Block credential stealing from the Windows local security authority subsystem* from [the previous page](inventory-vulns-patching.md#emet-exploit-guard) adds a third layer that also leaves Defender events.

**What the SOC takes from this:** on a Credential Guard machine, an LSASS access alert is still worth investigating — the attacker *tried* — but the blast radius is smaller. Conversely, when you scope a compromise, "was Credential Guard running on the hosts where the attacker had admin?" changes which accounts you must assume are stolen.

## Application Guard — isolating risky browsing and documents { #application-guard }

Credential Guard isolates *secrets*. **Microsoft Defender Application Guard (MDAG)** took the same hardware isolation and applied it to *risky activity*. The idea: you can't block every unknown website or every document from the internet, but you can open them in a disposable room that is thrown away afterwards.

- **Application Guard for Edge.** In enterprise mode the organisation defines trusted sites (intranet, known cloud services). When a user browses to anything else, Edge opens it in an isolated **Hyper-V container** — a lightweight virtual machine with its own kernel. A browser exploit that succeeds lands inside the container, not on the real laptop, and the container is discarded when the session ends. A standalone mode existed for Pro editions, and extensions brought the same isolation to Chrome and Firefox.
- **Application Guard for Office.** On Enterprise licences, Word, Excel and PowerPoint opened untrusted files — files downloaded from the internet, files from risky locations such as temp folders, and files covered by **File Block** — inside the container.
- **File Block** is a separate Office feature that is still worth knowing: administrators can block opening of old or rarely used file formats (for example legacy binary formats from long-retired Office versions) or force them into Protected View. Old formats are popular with attackers because they're parsed by old, less-hardened code.

**[Changed] Application Guard is retired.** Microsoft deprecated Application Guard for Edge (including the Chrome/Firefox extensions) and it is no longer available from Windows 11 24H2; Application Guard for Office is deprecated too. Microsoft now points customers to other controls — Edge's own security features and SmartScreen, Office **Protected View** and the internet-macro block, Microsoft Defender for Office 365 Safe Attachments and Safe Links, plus ASR rules and application control. If you find MDAG in an older environment, treat it as a control that is going away, and make sure something else is covering untrusted documents and browsing. The *idea* — open risky content in a disposable, isolated environment — lives on in remote browser isolation products and in sandbox features.

## Host firewalls — every machine as a gate and a sensor { #host-firewalls }

### What it is and why it does more than you think { #host-firewall-role }

A **host firewall** is a packet filter running on the endpoint itself: Windows Firewall (Windows Filtering Platform underneath), `nftables`/`iptables` with front-ends such as `ufw` or `firewalld` on Linux, the application firewall on macOS. It is usually filed under "exploit prevention" — block the port, and the vulnerable service can't be reached. But a well-configured host firewall touches four attack stages:

- **Exploitation** — inbound connections to services that shouldn't be reachable are dropped.
- **Lateral movement** — connections from a compromised neighbour to SMB, RDP, WinRM or SSH are dropped ([SMB](../other-protocols/smb.md), [SSH, RDP and VNC](../other-protocols/ssh-rdp-vnc.md), [PSRemoting](../other-protocols/psremoting-ftp-icmp.md)).
- **Command and control** — outbound connections to unexpected ports or from unexpected programs are blocked.
- **Exfiltration** — outbound protocols the machine never needs (SSH, FTP from a finance laptop) are blocked.

And each of those blocks can be logged. That's the part people forget: the host firewall turns *every* endpoint into a network sensor, including for traffic that never crosses a network firewall.

### Profiles, default-deny and outbound rules { #profiles }

Windows applies one of three **profiles** depending on which network it thinks it is on:

- **Domain** — it can reach a domain controller for its domain (it's on the corporate network or VPN). Typically the only profile where remote-management ports are open — and only *from management hosts*.
- **Private** — a network the user marked as trusted (home).
- **Public** — anything else: café, hotel, airport. Inbound should be closed completely.

The basic rules mirror a network firewall: **default-deny inbound** (only allow what is needed, from where it is needed) and, where you can define it, **default-deny outbound** with an allow list. Outbound deny is less common because it takes work — you have to know which programs need to talk to where — but it is one of the strongest C2 controls you can have.

Reading the current settings:

```powershell
Get-NetFirewallProfile |
  Select-Object Name, Enabled, DefaultInboundAction, DefaultOutboundAction, LogBlocked, LogAllowed, LogFileName
```

```
Name    Enabled DefaultInboundAction DefaultOutboundAction LogBlocked LogAllowed LogFileName
----    ------- -------------------- --------------------- ---------- ---------- -----------
Domain     True                Block                 Allow       True      False %systemroot%\system32\LogFiles\Firewall\pfirewall.log
Private    True                Block                 Allow      False      False %systemroot%\system32\LogFiles\Firewall\pfirewall.log
Public     True                Block                 Allow      False      False %systemroot%\system32\LogFiles\Firewall\pfirewall.log
```

- `Get-NetFirewallProfile` lists the three profiles; `Select-Object` keeps the useful columns.
- `Enabled True` — the firewall is on for every profile. `False` on any profile is a finding.
- `DefaultInboundAction Block` — good: inbound is default-deny. `DefaultOutboundAction Allow` — the common default; outbound is open unless a rule blocks it.
- `LogBlocked True` only on *Domain* — dropped packets are logged on the corporate network but not when the laptop is at home or in a hotel. Turning `LogBlocked` on for Private and Public gives you visibility when the device is off-site — the place it's most exposed.
- `LogAllowed False` — allowed connections are not logged. Leaving this off is usually right for the text log; logging every allowed packet is the flood the next section warns about.
- `LogFileName` — the default text log location.

### Reading the Windows Firewall text log { #pfirewall-log }

```
#Version: 1.5
#Software: Microsoft Windows Firewall
#Time Format: Local
#Fields: date time action protocol src-ip dst-ip src-port dst-port size tcpflags tcpsyn tcpack tcpwin icmptype icmpcode info path

2026-11-19 10:14:03 DROP TCP 10.30.5.41 10.30.5.42 51544 445 52 S 3871632402 0 64240 - - - RECEIVE
2026-11-19 10:14:03 DROP TCP 10.30.5.41 10.30.5.42 51545 135 52 S 1209847712 0 64240 - - - RECEIVE
2026-11-19 10:14:04 DROP TCP 10.30.5.41 10.30.5.42 51546 5985 52 S 2650012931 0 64240 - - - RECEIVE
```

The header first:

- `#Version`, `#Software` — the log format version and the producer.
- `#Time Format: Local` — timestamps are in the machine's **local time**, not UTC. Remember this when you line it up with SIEM data.
- `#Fields:` — the column names, in order. Each line below is one packet decision.

Now the first data line, field by field:

- `2026-11-19 10:14:03` — date and local time.
- `DROP` — the action (`ALLOW` or `DROP`).
- `TCP` — protocol.
- `10.30.5.41` → `10.30.5.42` — source and destination IP. This log is on `.42`, so `.41` was trying to reach *it*.
- `51544` → `445` — source port (random, high) and destination port. 445 is SMB.
- `52` — packet size in bytes.
- `S` — TCP flags: a bare SYN, i.e. the first packet of a new connection attempt.
- `3871632402` / `0` / `64240` — TCP sequence number, acknowledgement number and window size. Rarely needed in triage.
- `- - -` — ICMP type, ICMP code and info, empty for TCP.
- `RECEIVE` — direction: an inbound packet (`SEND` would be outbound).

All three lines together tell a story: within two seconds, `10.30.5.41` tried SMB (445), RPC endpoint mapper (135) and WinRM (5985) on its neighbour. Those are the three classic remote-execution routes (PsExec-style service creation over SMB, WMI/DCOM over RPC, PowerShell remoting over WinRM). If `.41` is an ordinary workstation, this is someone on that workstation trying to move laterally — ATT&CK **T1021.002 SMB/Windows Admin Shares**, **T1047 WMI**, **T1021.006 Windows Remote Management** — and every attempt failed and left a record.

The text log is limited: it rotates at a small default size (4 MB) and has no process information. For SIEM collection, the **Security event log** version is usually better.

### Windows Filtering Platform events { #wfp-events }

If you enable the audit subcategory *Filtering Platform Connection*, Windows writes connection decisions to the Security log:

- **5157** — the Windows Filtering Platform **blocked** a connection.
- **5156** — WFP **allowed** a connection. Very high volume; most organisations don't collect it everywhere.
- **5152 / 5153** — a packet was dropped/blocked (packet-level; from the *Filtering Platform Packet Drop* subcategory).

```
auditpol /set /subcategory:"Filtering Platform Connection" /failure:enable
```

- `auditpol /set` changes the audit policy; `/subcategory:"Filtering Platform Connection"` selects connection-level auditing; `/failure:enable` logs only **failures** — blocked connections (5157) — and not the flood of successes (5156). In a domain you'd set this via Group Policy *Advanced Audit Policy Configuration* instead.

A 5157 event on `.42` for the first attempt above (EventData only, values invented):

```xml
<EventData>
  <Data Name="ProcessID">4</Data>
  <Data Name="Application">System</Data>
  <Data Name="Direction">%%14592</Data>
  <Data Name="SourceAddress">10.30.5.42</Data>
  <Data Name="SourcePort">445</Data>
  <Data Name="DestAddress">10.30.5.41</Data>
  <Data Name="DestPort">51544</Data>
  <Data Name="Protocol">6</Data>
  <Data Name="FilterRTID">0</Data>
  <Data Name="LayerName">%%14610</Data>
  <Data Name="LayerRTID">44</Data>
</EventData>
```

- `ProcessID 4` / `Application System` — the local process that owns the port. PID 4 is the kernel `System` process, which owns SMB on 445. For outbound blocks this field is gold: it names the program that tried to connect (`\device\harddiskvolume3\users\public\rdr.exe`).
- `Direction %%14592` — a message code meaning **Inbound** (`%%14593` = Outbound). The Event Viewer shows the text; raw XML in a SIEM shows the code, so your parser must translate it.
- `SourceAddress / SourcePort` and `DestAddress / DestPort` — careful: for **inbound** events, WFP puts the *local* side in "Source" and the *remote* side in "Dest". So here the local machine `10.30.5.42:445` was the target and the remote `10.30.5.41` was the initiator. Getting this backwards is a classic analyst mistake.
- `Protocol 6` — IP protocol number: 6 = TCP, 17 = UDP, 1 = ICMP.
- `LayerName %%14610` — the WFP layer where the decision happened (here a receive/accept layer for inbound connections). `FilterRTID` identifies the filter that decided; `0` typically means the default block rather than a specific rule.

**[Supplement] Watch the firewall itself.** Attackers often turn the firewall off or add an allow rule (**T1562.004 Impair Defenses: Disable or Modify System Firewall**), for example with `netsh advfirewall set allprofiles state off` or a new inbound rule for their tool. Windows logs this: Security events **4946** (rule added), **4947** (rule modified), **4948** (rule deleted), **4950** (a firewall setting changed) when *MPSSVC Rule-Level Policy Change* auditing is on, and the `Microsoft-Windows-Windows Firewall With Advanced Security/Firewall` log records rule additions, changes and deletions (e.g. 2004, 2005, 2006) and profile setting changes, including which application made them. A firewall turned off on a workstation outside a change window deserves an alert.

### Using it tactically, not everywhere { #tactical-logging }

Host firewalls can produce enormous volumes, so "log everything on every host" ends with a full SIEM licence and nobody looking. The practical approach:

1. **Log blocks, not allows**, at least for the central feed.
2. **Focus on the ports attackers use** for exploitation and lateral movement: 445 (SMB), 135 and the RPC range, 3389 (RDP), 5985/5986 (WinRM), 22 (SSH), 80/443 on hosts that shouldn't serve web.
3. **Exclude known-good noise**: your vulnerability scanners, management servers and monitoring systems. If the scanner at `10.10.1.50` is expected to touch everything every Sunday, filter it out — otherwise every scan buries the real attempts.
4. **Write simple, sharp alerts** on what's left (next section).

Once the noise is gone, the payoff is huge: almost anything an attacker does to explore from a compromised workstation hits a closed port somewhere and leaves a trail.

## Host firewall vs network firewall { #host-vs-network }

Picture a subnet of workstations, `10.30.5.0/24`, behind a network firewall. An attacker controls `PC-1` (`10.30.5.41`) and wants `PC-2` (`10.30.5.42`) next door.

| | Network firewall only | Network + host firewalls |
| --- | --- | --- |
| Exploitation of PC-2 from PC-1 | Not stopped — the traffic never crosses the network firewall | Blocked on PC-2, and logged |
| Lateral movement PC-1 → PC-2 | Not prevented, **not visible** to the SOC | Blocked; "PC-1 tried SMB to PC-2" is in the SIEM |
| C2 / exfiltration from PC-1 | Seen (and maybe stopped) only at the network edge | Also blocked/logged on PC-1 itself, with the process name |

Why the left column is so bad: traffic between two machines on the same subnet goes through the local switch, not through the firewall. The network firewall, the proxy and most network sensors are blind to it. The attacker can try every neighbour, over and over, silently.

With host firewalls on the right, two things change. First, workstations don't accept SMB/RDP/WinRM from other workstations at all — only from the management servers that actually administer them. Second, every attempt becomes a log line. Because workstations normally have **no reason** to talk to each other on these ports, the detection logic is short:

> Alert when a host in the workstation range is the source of a blocked (or any) connection to TCP 445, 135, 3389 or 5985/5986 on another host in the workstation range, excluding the management and scanner hosts.

That one rule makes quiet lateral movement inside the subnet very hard.

Outbound rules help the other end of the chain:

- **C2 on unusual ports.** A workstation that suddenly tries to connect out on TCP 4444 (a default for some well-known exploitation frameworks) or another port it has never used is suspicious. Outbound blocks force attackers onto the few ports you allow (usually 80/443 through the proxy), where your web proxy and TLS inspection can see them — ATT&CK **T1571 Non-Standard Port**.
- **Exfiltration.** Blocking outbound SSH, FTP and similar protocols from user workstations shuts easy exfil channels (**T1048 Exfiltration Over Alternative Protocol**), and the logged attempts tell you someone tried.

**[Supplement]** The same thinking scales up into **micro-segmentation**: identity- or tag-based rules (pushed from an EDR, the firewall policy manager or a zero-trust product) that define which *roles* may talk to which. Host firewalls are the cheapest, built-in way to start.

## Antivirus — stopping the installation stage { #antivirus }

### What it does and where it struggles { #av-role }

**Antivirus (AV)** is one of the oldest security tools. Its main job is the **installation** stage: look at files before or as they run, and stop the malicious ones. Think of it as a guard at the door with a stack of "wanted" posters. Very good at stopping anyone on a poster; much less good at stopping someone in a new disguise.

**Signature-based** detection is the poster stack: byte patterns, strings or hashes taken from known malware samples. It reliably removes *known* bad files. It struggles with:

- **Unknown malware** — nobody has made a poster yet.
- **Obfuscated or packed files** (**T1027 Obfuscated Files or Information**) — the same malware wrapped so the bytes look different.
- **Polymorphic malware** — code that changes itself for every infection, so each copy has a new hash and different bytes.
- **In-memory-only (fileless) malware** — a script downloads code straight into RAM and runs it without ever writing a file (**T1620 Reflective Code Loading**, PowerShell download cradles). An engine that only scans files on disk never sees it.

To fight this, products moved to **signatureless, machine-learning** detection: models trained on huge numbers of good and bad samples learn the *characteristics* of malicious programs (structure, imports, entropy, behaviour) and can score a file they've never seen. Most modern engines blend both: signatures for speed and certainty, ML and cloud lookups for the new stuff, plus **behaviour monitoring** that watches what a program does after it starts.

**[Supplement] AMSI closes the fileless gap on Windows.** The **Antimalware Scan Interface** lets script hosts — PowerShell, Windows Script Host (VBScript/JScript), Office VBA macros, .NET — hand the *de-obfuscated* content they are about to run to the AV engine. That is how Defender can catch a script that was never written to disk, after the layers of encoding have been unwrapped. Attackers know this and try to disable or patch AMSI in memory; those attempts are themselves detectable by EDR and Defender.

So is AV still worth it? Yes. A skilled, targeted attacker will often get past it — but AV removes a large amount of commodity malware automatically, so the SOC can spend its time on what matters. And its logs are a valuable sensor.

### Attackers turning it off { #av-tamper }

Because AV is in the way, attackers frequently try to disable it — **T1562.001 Impair Defenses: Disable or Modify Tools** — by stopping the service, adding exclusions for their folder, or turning real-time protection off. The Defender operational log (`Microsoft-Windows-Windows Defender/Operational`) records these:

- **5001** — real-time protection was **disabled**.
- **5007** — Defender **configuration changed** (look for new exclusion paths, e.g. `Exclusions\Paths\C:\Users\Public`).
- **5013** — Tamper Protection **blocked** a change to Defender settings.
- **1116 / 1117** — malware detected / action taken (below).

An exclusion for `C:\Users\Public` or `C:\ProgramData\<random>` added at 2 a.m. by a script is one of the clearest signs of hands-on-keyboard activity there is. More detail in [Impair Defenses and Log Clearing](../../../adversary/impair-defenses-log-clearing.md).

### Reading a detection event { #av-detection-event }

```
Log Name:  Microsoft-Windows-Windows Defender/Operational
Event ID:  1116
Microsoft Defender Antivirus has detected malware or other potentially unwanted software.
 Name: Trojan:Win32/Generic!ml
 ID: 2147xxxxxx
 Severity: Severe
 Category: Trojan
 Path: file:_C:\Users\j.park\AppData\Roaming\Microsoft\Teams\upd\teamsupd.exe
 Detection Origin: Local machine
 Detection Type: Concrete
 Detection Source: Real-Time Protection
 User: CORP\j.park
 Process Name: C:\Windows\System32\rundll32.exe
 Security intelligence Version: 1.4xx.xxx.0
```

Field by field:

- `Event ID 1116` — Defender **detected** something. The follow-up **1117** says what *action* was taken (quarantined, removed, blocked); **1118/1119** mean the action failed. A 1116 with no 1117 — or with a 1118 — means the file may still be there.
- `Name: Trojan:Win32/Generic!ml` — the detection name: type (`Trojan`), platform (`Win32`), family (`Generic`), and suffix. `!ml` means a **machine-learning** model flagged it rather than a specific signature. "Generic" sounds boring, but it actually means "we don't know which family this is" — exactly what you'd expect for something new or targeted.
- `Severity: Severe`, `Category: Trojan` — vendor classification; useful for sorting, not for deciding importance.
- `Path` — where the file is. `AppData\Roaming\Microsoft\Teams\upd\teamsupd.exe` imitates an application folder, but the real collaboration app doesn't put an updater there. Masquerading paths (**T1036.005 Match Legitimate Name or Location**) are a classic.
- `Detection Source: Real-Time Protection` — caught when the file was accessed or executed (other sources: scheduled scan, AMSI, behaviour monitoring, downloads/attachments).
- `Process Name: rundll32.exe` — the process that touched the file. A system binary launching an unknown executable from AppData suggests something was *already running* that tried to start this second stage — so the question isn't only "was this file removed?" but "what launched it?".
- `Security intelligence Version` — the signature/model version, useful when a detection appears after an update for files that were already present.

### Finding the interesting needle { #av-outliers }

Most AV detections in a large organisation are boring: adware bundled with a free download, a known commodity trojan in an email attachment that was quarantined before anyone opened it, potentially unwanted toolbars. The trick is to look for **outliers**. A week of detections, summarised:

```
Count  Detection name                    Path pattern                               Hosts
  214  PUA:Win32/Bundler.Toolbar         C:\Users\*\Downloads\*setup*.exe             97
   61  Trojan:Script/Phish.Html          Outlook temp (attachments)                   58
    9  HackTool:Win32/Keygen             C:\Users\*\Downloads\*crack*                  7
    1  Trojan:Win32/Generic!ml          C:\Users\j.park\AppData\Roaming\...\upd\      1
```

- The top three rows are high-volume, spread across many hosts, in typical "user downloaded something dumb" locations. Clean up, educate, tune.
- The last row is the one to investigate first: **a single detection**, a name your environment has never seen, in a **location** no other detection has used, launched by `rundll32.exe`. One-off detections like this are often the visible tip of a deeper intrusion — the attacker's tooling that happened to be caught while the rest wasn't.

Ways to rank detections:

- **Name rarity** — first time this detection name appears in your environment.
- **Path rarity** — first time anything was detected in this folder, or a path mimicking a legitimate program.
- **File prevalence and reputation** — most AV and EDR products query the vendor's cloud for how many other organisations have seen the file. A file that **no one else in the world** has ever seen is very suspicious — legitimate software is almost never unique to you. (Defender for Endpoint and others expose this as "prevalence" or "first seen"; VirusTotal-style lookups of the *hash* — never uploading sensitive files — give a similar signal.)
- **Context** — what launched it, which user, which host role (a server or a domain admin's PAW is more important than a kiosk).

**[Caution]** Don't trust the detection name to describe the threat. Engines name things generically, and different vendors name the same file differently. Investigate by path, parent process, hash and prevalence — not by how scary the name sounds.

## Putting it together — what a SOC takes from these layers { #soc-use }

- **Credential Guard status per host** — collect `Win32_DeviceGuard` / Wininit 13 into your asset data. During an incident, it decides which credentials you must treat as stolen.
- **LSASS access attempts** — still alert on them even where Credential Guard runs; the *attempt* tells you an attacker has admin rights.
- **Host firewall blocks on lateral-movement ports between workstations** — one of the highest-value, lowest-noise detections you can build. Filter scanners and management hosts first.
- **Firewall and AV tampering** — 4946/4947/4950, firewall turned off, Defender 5001/5007 exclusions, 5013 tamper blocks: alert outside change windows.
- **AV detections by rarity** — triage the unique ones first, and always ask "what launched it?" and "was the action successful (1117 vs 1118)?".

## The 2026 view { #trends }

!!! success "[2026 Current] Still valid"
    Isolating secrets with VBS, "check it is running, not just configured", Credential Guard's limits (local SAM, keyloggers, rogue SSPs), host firewalls as both a control and a sensor across exploitation, lateral movement, C2 and exfiltration, default-deny inbound, tactical logging of blocks on lateral-movement ports, the host-vs-network-firewall visibility gap inside a subnet, and AV as a commodity-malware filter whose rare detections deserve attention — all still hold exactly as described. The Defender event IDs (1116/1117, 5001/5007/5013) and WFP events (5156/5157) are unchanged.

!!! info "[Changed] What has changed"
    - **Credential Guard is now on by default** on many machines: starting with Windows 11 22H2, it is enabled by default on Enterprise and Education devices that meet the requirements and aren't domain controllers, and Windows Server 2025 also enables it by default on eligible domain-joined (non-DC) servers. Memory integrity (HVCI) is on by default on many new Windows 11 devices. Still verify — older hardware, upgrades and firmware settings leave gaps.
    - **LSA protection is more common by default.** Newer Windows 11 installs turn on LSA protection (`RunAsPPL`) in many configurations. Attackers have answered by bringing their own **vulnerable signed drivers** to remove protections — which is why Microsoft's vulnerable driver block list and the matching ASR rule matter.
    - **Application Guard is gone.** MDAG for Edge was deprecated and isn't available from Windows 11 24H2; MDAG for Office is deprecated too. Its job now falls to Protected View, the default block on internet macros, Defender for Office 365, SmartScreen, ASR and application control, or third-party browser isolation.
    - **Naming.** "Windows Defender Firewall" is now simply **Windows Firewall** in Microsoft's documentation, and Windows' built-in AV is **Microsoft Defender Antivirus**; the "Defender ATP" console is now **Microsoft Defender for Endpoint** inside Microsoft Defender XDR.
    - **AV has merged into EDR/XDR.** Stand-alone signature AV has largely become one component of an EDR/XDR platform that blends signatures, ML, cloud reputation, AMSI and behaviour monitoring, with central prevalence data. After the July 2024 outage caused by a faulty security-product update, Microsoft began work on letting AV/EDR vendors run more of their code outside the Windows kernel; how far this goes is still developing, so check your vendor's current status.
    - **AI on both sides.** Vendors use larger ML models for classification and AI assistants for triage; attackers use AI to generate many unique variants and obfuscated scripts quickly, which makes hash- and signature-only detection even weaker and prevalence/behaviour signals more important.

!!! warning "[Caution] Wrong or risky to do the old way"
    - **Don't treat Credential Guard as "credential theft solved".** Local admin hashes (use LAPS), keyloggers, rogue SSPs and live session abuse still work. And don't skip the LSASS alerts on protected machines.
    - **Don't design new controls around Application Guard.** It's retired; plan for its replacements.
    - **Don't log every allowed connection from every host into the SIEM.** You'll pay for noise and miss the signal. Log blocks on the right ports, filter scanners, and keep 5156 for targeted use.
    - **Don't read WFP 5156/5157 Source/Dest naively.** For inbound events "Source" is the local machine.
    - **Don't leave the firewall log on only for the Domain profile.** Laptops are most exposed off-site — enable block logging on Public/Private too.
    - **Don't rely on signature AV as a significant barrier against a targeted attacker**, and don't dismiss a detection because its name says "Generic". A one-off detection in an unusual path is a lead.
    - **Don't upload sensitive or targeted files to public scanning services.** Look up the hash; uploading can tip off the attacker and leak data.

## Practice questions { #quiz }

### Question 1

During an incident, an attacker had SYSTEM on laptop `LT-HR-0219` for six hours. The laptop's `Win32_DeviceGuard` shows `SecurityServicesConfigured {1, 2}` and `SecurityServicesRunning {2}`, and there is no `LsaIso.exe` process. A colleague says, "Credential Guard is deployed through GPO everywhere, so the domain users who logged on there are safe." Is that right? What would change if the output had been `{1, 2}` / `{1, 2}`, and which credentials would you still treat as exposed?

??? success "Answer and explanation"
    **Not right.** *Configured* `{1, 2}` means the policy asked for Credential Guard (1) and memory integrity (2), but *Running* `{2}` means only memory integrity is active. No `LsaIso.exe` confirms it: the secrets are still in normal `lsass.exe` memory, and with SYSTEM the attacker could dump NT hashes and Kerberos tickets of everyone logged on. Treat **all domain accounts with sessions on that laptop during the six hours** as compromised (reset passwords, and for privileged accounts purge tickets / reset twice where relevant), and find out why Credential Guard didn't start (firmware virtualization off, Secure Boot, incompatible driver).

    **If it had been `{1, 2}` / `{1, 2}`:** stored domain hashes and TGT keys would have been isolated in VTL1, so dumping LSASS would not yield reusable domain hashes or tickets. But you would *still* treat as exposed: the **local accounts** in the SAM (especially the local admin — is LAPS in use?), **anyone who logged on during the six hours** (a rogue SSP or keylogger could capture their typed password), and any credentials stored in files, browsers or scripts on the box. Credential Guard reduces the blast radius; it doesn't make SYSTEM harmless.

### Question 2

The SIEM shows these Windows Firewall entries collected from workstation `10.30.5.42` (log on `.42`), and nothing similar from any other day:

```
2026-11-19 10:14:03 DROP TCP 10.30.5.41 10.30.5.42 51544 445 52 S 3871632402 0 64240 - - - RECEIVE
2026-11-19 10:14:03 DROP TCP 10.30.5.41 10.30.5.42 51545 135 52 S 1209847712 0 64240 - - - RECEIVE
2026-11-19 10:14:04 DROP TCP 10.30.5.41 10.30.5.42 51546 5985 52 S 2650012931 0 64240 - - - RECEIVE
```

`10.30.5.41` is another user's workstation, not a scanner or management server. Explain what happened, why the network firewall would not have seen it, and what you do next.

??? success "Answer and explanation"
    **What happened:** in one second, workstation `.41` tried to open new TCP connections (SYN, `S`) to `.42` on **445 (SMB)**, **135 (RPC endpoint mapper)** and **5985 (WinRM)** — the three main routes for remote execution (service creation over SMB/admin shares, WMI/DCOM, PowerShell remoting). `.42`'s host firewall dropped all three (`DROP`, `RECEIVE` = inbound). Workstations don't administer each other, so this looks like someone on `.41` attempting **lateral movement** (T1021.002, T1047, T1021.006).

    **Why the network firewall is blind:** both machines are on the same subnet, so the packets go through the access switch and never cross the network firewall. Without the host firewall log, this attempt would have been invisible.

    **Next steps:** treat `.41` as likely compromised. Check `.41`'s process creation logs/EDR around 10:14 for what made those connections (e.g. a tool or `powershell.exe` making remote calls), who was logged on, any recent logons (4624) and recent AV/ASR events; look for the same source trying other neighbours (other hosts' firewall logs); check whether any attempt *succeeded* somewhere the firewall is weaker (servers, hosts without the rule); then isolate `.41` and reset credentials used on it. Also make this a standing alert: workstation → workstation on 445/135/3389/5985.

### Question 3

A week of Defender detections contains 214 `PUA:Win32/Bundler.Toolbar` hits in Downloads folders, 61 HTML phishing attachments, and one `1116` event: `Trojan:Win32/Generic!ml`, path `C:\ProgramData\SysCache\svcupd.exe`, Process Name `C:\Windows\System32\wbem\WmiPrvSE.exe`, on a file server. There is a `1118` event for it a second later, and two hours earlier a `5007` event added the exclusion path `C:\ProgramData\SysCache`. Which do you look at first, and what do these three events together tell you?

??? success "Answer and explanation"
    **Look at the single `Generic!ml` detection first.** The PUA and phishing hits are high-volume, many-host commodity noise in typical locations. The one-off is rare by name, path and host role (a server), detected by an ML model (`!ml` — no known signature, so possibly new or targeted), in a folder that imitates a system cache.

    **The three events together:**

    - **5007** two hours earlier — someone changed Defender's configuration to **exclude** `C:\ProgramData\SysCache` — a typical attacker step (T1562.001) to make their tools invisible.
    - **1116** — Defender still detected `svcupd.exe` (for example through a path the exclusion didn't cover, behaviour monitoring or a cloud verdict), and it was launched by **`WmiPrvSE.exe`** — the WMI provider host — which suggests remote execution over **WMI** (T1047), i.e. lateral movement onto the file server.
    - **1118** — the remediation **failed**, so the file may still be there and may have run.

    So this is very likely a hands-on-keyboard intrusion on a server, not a stray piece of malware. Isolate the server, collect the file and its hash, find who changed the exclusion (the 5007 event's process/user, plus logon events on the server around that time), find the WMI source host, remove the exclusion, and scope other hosts for the same path, exclusion or hash. Don't let the boring "Generic" name lower the priority.

## Related { #related }

- [Inventory, Vulnerability Scanning, Patching and Exploit Protection](inventory-vulns-patching.md) — the previous layer, including ASR and controlled folder access
- [Credential Dumping and Mimikatz](../endpoint-attacks/credential-dumping-mimikatz.md) · [Lateral Movement, Collection and Exfiltration](../endpoint-attacks/lateral-collection-exfil.md)
- [LSASS dumping](../../../adversary/lsass-dumping.md) · [Pass-the-hash](../../../adversary/pass-the-hash.md) · [PsExec and SMB](../../../adversary/psexec-smb.md) · [WMI and WinRM](../../../adversary/wmi-winrm.md)
- [Impair Defenses and Log Clearing](../../../adversary/impair-defenses-log-clearing.md) · [PowerShell cradles](../../../adversary/powershell-cradles.md)
- [SMB](../other-protocols/smb.md) · [SSH, RDP and VNC](../other-protocols/ssh-rdp-vnc.md)
- [Windows Event IDs](../../../basics/windows-event-ids.md) · [Well-known ports](../../../basics/well-known-ports.md)

---
title: "Firewall and Object Access Events — Windows Firewall Logs (pfirewall.log, 5156/5157/5152/5154), iptables/UFW Logs, 4663/4657/4660"
tags:
  - training
  - blue-team
  - windows
  - linux
  - logging
  - firewall
---

# Firewall and Object Access Events — Windows Firewall Logs, iptables/UFW Logs, 4663/4657/4660 { #firewall-object-access }

!!! abstract "What this page covers"
    Two kinds of endpoint logs that answer "**what talked to what**" and "**who touched this important thing**". First, **host firewall logs**: why a firewall on every machine is a better network sensor than the big firewall at the edge (it sees traffic *inside* the network and knows **which process** made the connection), the two ways Windows Firewall can log — the text file **`pfirewall.log`** (format read field by field, limits, one file per profile) and the **Filtering Platform** events in the Security channel (**5156** allowed, **5157** connection blocked, **5152** packet dropped, **5154** listening), with a full 5156 read line by line — plus the events that record **changes to the firewall itself**. Then the Linux side: an **iptables/UFW** log line split into its syslog header and `KEY=value` pairs, why it is awkward to parse, and how the same format survives under nftables. Last, **object access auditing**: why a 4663 event only exists if someone deliberately put a watch on that file or registry key, how the two-step setup works (audit policy + SACL), and full **4663** (object accessed), **4657** (registry value modified) and **4660** (object deleted) events read field by field. SOC checklist, the 2026 view and practice questions.

!!! note "Labels"
    **[Supplement]** = practical material you need to know, **[Correction]** = a commonly repeated claim that is wrong or outdated, **[Changed]**/**[Caution]** = what has changed recently and what is risky to do the old way. Hostnames, domains, accounts, IPs and file names are invented for illustration (`.example`, documentation and private IPs).

## The 8 key points { #key-points }

1. A **host firewall** log is a network sensor on every endpoint. It sees east-west traffic between internal machines that never crosses the perimeter firewall, and — on Windows — it can tie each connection to the **process** that made it, which no network device can do.
2. Windows Firewall can log two ways: a **text file** (`%SystemRoot%\System32\LogFiles\Firewall\pfirewall.log`, off by default, one file per profile possible, maximum about 32 MB) or **Security channel events** from the *Filtering Platform* audit subcategories. The events are usually easier to collect because Security log forwarding already exists.
3. The key Filtering Platform events: **5156** connection allowed, **5157** connection blocked, **5152** packet dropped, **5154** an application is listening. 5156 contains the **application path and process ID**, direction, addresses, ports and protocol.
4. These events are **very high volume**. Turn them on deliberately, filter heavily (at the query, or with narrow, reviewed collection filters), and prefer blocked events, listening events and outbound connections from unusual processes.
5. Changes to the firewall itself (rules added, the firewall turned off) are logged separately — in the firewall's own channel and Security events 4946–4950 — and are worth alerting on: attackers open ports and disable the firewall (ATT&CK **T1562.004**).
6. A Linux **iptables/UFW** log line is a syslog line written by the **kernel**, followed by mostly `KEY=value` pairs (`IN=`, `OUT=`, `SRC=`, `DST=`, `PROTO=`, `SPT=`, `DPT=`) — but some items are bare flags (`DF`, `SYN`) and some keys are empty (`IN=`), so a parser must allow optional fields. There is **no process information**.
7. **Object access auditing** (4663, 4657, 4660) needs **two** things: the audit subcategory turned on **and** an audit entry (SACL) placed on each file, folder or registry key. Turning on the policy alone logs nothing. So an object access event usually means someone decided that object is important.
8. In 4663 read **Subject** (who), **Object** (what), **Process** (with which program) and **Access** (what kind — read, write, delete). 4657 adds the **old and new value** of a registry value; 4660 says an object was **deleted** and must be joined to an earlier event by its handle ID to learn the name.

## Why host firewall logs matter { #why-host-firewall }

Think of a big office building. The guard at the front door (the network firewall) checks everyone entering and leaving the building. But once people are inside, they can walk from office to office, and the guard never sees it. Now imagine a small lock and a visitor book on every office door. Each book records who came in, at what time, from which room — and, unlike the front guard, it also records the person's **name badge**, not just their face. Host firewalls are those per-door locks and books. The "name badge" is the **process** that opened the connection.

Back to the technical reality. Many organisations already run host firewalls because the operating system includes one (Windows Firewall, `nftables`/`iptables` front ends such as UFW or firewalld on Linux) or because the endpoint security suite ships one. For a SOC their value is mostly as a **log source**, for three reasons:

- **Inside-the-network visibility.** Lateral movement — SMB from one workstation to another, RDP between servers, WinRM, a scan of the internal subnet (T1046, Network Service Discovery) — usually never passes the perimeter firewall. A host firewall on the receiving machine sees it, allowed or blocked.
- **Process attribution.** The Windows Filtering Platform knows which program owns each socket. A 5156 saying `\device\harddiskvolume3\users\public\inv.exe` connected out to port 443 tells you far more than a network log saying "10.20.4.114 → 198.51.100.23:443".
- **Coverage off the corporate network.** A laptop at home or in a hotel is outside your network sensors; its host firewall log still records what it did, if you can collect it.

The catch is **volume**. A busy workstation makes thousands of connections an hour (browsers, updates, telemetry, name resolution). Sending all of it to the SIEM can cost more than every other source combined. The practical answer is to collect *selectively* — blocked traffic, listening events, inbound connections to workstations, outbound connections from unusual programs — rather than to skip the source.

[Supplement] A host firewall **blocking** something is also a detection: a workstation that suddenly generates hundreds of blocked inbound SMB attempts from a neighbour is watching a worm or an attacker probe in real time.

## Windows Firewall logging, option 1: pfirewall.log { #pfirewall }

### Turning it on { #pfirewall-config }

Windows Firewall (shown in older documentation as "Windows Firewall with Advanced Security", later "Windows Defender Firewall", and in current Microsoft documentation simply "Windows Firewall") has three **profiles**: **Domain** (connected to the corporate domain), **Private** (a trusted network such as home) and **Public** (everything else). Logging is configured **per profile**, and by default it is **off** for both dropped packets and successful connections.

In Group Policy it lives under *Computer Configuration → Windows Settings → Security Settings → Windows Firewall with Advanced Security → Properties → (profile) → Logging → Customize*. With PowerShell:

```powershell
Set-NetFirewallProfile -Profile Domain,Private,Public `
  -LogFileName '%SystemRoot%\System32\LogFiles\Firewall\pfirewall.log' `
  -LogMaxSizeKilobytes 32767 -LogBlocked True -LogAllowed True
Get-NetFirewallProfile | Select-Object Name, LogFileName, LogMaxSizeKilobytes, LogAllowed, LogBlocked
```

- Line 1 — `Set-NetFirewallProfile` changes the settings of the named profiles; here all three. The backtick (`` ` ``) continues the command on the next line.
- Line 2 — `-LogFileName` sets the file. The default name and folder are shown; you can give each profile its **own file** (for example `domainfw.log`, `publicfw.log`), which makes it obvious which profile was active when a laptop left the office.
- Line 3 — `-LogMaxSizeKilobytes 32767` raises the size limit from the default **4,096 KB** to the maximum (just under 32 MB). When the file is full, Windows renames it to `pfirewall.log.old` and starts a new one — so **only two files of history** exist on the host. `-LogBlocked` and `-LogAllowed` choose what to write.
- Line 4 — shows the result so you can check it:

```text
Name    LogFileName                                              LogMaxSizeKilobytes LogAllowed LogBlocked
----    -----------                                              ------------------- ---------- ----------
Domain  %SystemRoot%\System32\LogFiles\Firewall\pfirewall.log                  32767       True       True
Private %SystemRoot%\System32\LogFiles\Firewall\pfirewall.log                  32767       True       True
Public  %SystemRoot%\System32\LogFiles\Firewall\pfirewall.log                  32767       True       True
```

There is no built-in forwarding of this file. You collect it the way you collect any text log — a log agent tailing the file, or your SIEM's file-monitor input.

### Reading the file { #pfirewall-read }

The file starts with a W3C-style header that names the columns, then one space-separated line per event:

```text
#Version: 1.5
#Software: Microsoft Windows Firewall
#Time Format: Local
#Fields: date time action protocol src-ip dst-ip src-port dst-port size tcpflags tcpsyn tcpack tcpwin icmptype icmpcode info path pid

2026-11-20 10:14:03 ALLOW TCP 10.20.4.114 198.51.100.23 51544 443 0 - 0 0 0 - - - SEND 7996
2026-11-20 10:14:09 DROP TCP 10.20.4.37 10.20.4.114 49822 445 52 S 1928374650 0 64240 - - - RECEIVE 4
2026-11-20 10:14:09 DROP TCP 10.20.4.37 10.20.4.114 49823 3389 52 S 2203948811 0 64240 - - - RECEIVE 0
2026-11-20 10:14:12 ALLOW UDP 10.20.4.114 10.20.0.10 60512 53 0 - - - - - - - SEND 2312
2026-11-20 10:14:20 DROP ICMP 10.20.4.37 10.20.4.114 - - 60 - - - - 8 0 - RECEIVE 0
```

Header lines:

- `#Version: 1.5` — format version. The field list can differ slightly between Windows versions; **always parse by the `#Fields:` line**, not by fixed position.
- `#Time Format: Local` — times are in the machine's **local time**, not UTC. When you build a timeline across hosts in different time zones, convert first.
- `#Fields:` — the column names, in order. Recent Windows versions append `pid` (process ID) at the end; older ones stop at `path`.

Taking the first data line apart:

| Field | Value | Meaning |
| --- | --- | --- |
| `date` `time` | `2026-11-20 10:14:03` | Local time on the host |
| `action` | `ALLOW` | `ALLOW`, `DROP`, or for some entries `INFO-EVENTS-LOST` (the log could not keep up) |
| `protocol` | `TCP` | `TCP`, `UDP`, `ICMP`, or a protocol number |
| `src-ip` / `dst-ip` | `10.20.4.114` → `198.51.100.23` | Source and destination addresses |
| `src-port` / `dst-port` | `51544` → `443` | Ports (`-` for ICMP) |
| `size` | `0` | Packet size in bytes; usually `0` on allowed connections, filled for drops |
| `tcpflags` | `-` | TCP flags of the dropped packet (`S` = SYN, `A` = ACK, `F` = FIN, `R` = RST, `P` = PSH) |
| `tcpsyn` / `tcpack` / `tcpwin` | `0 0 0` | TCP sequence number, acknowledgement number and window size of a dropped packet |
| `icmptype` / `icmpcode` | `-` `-` | For ICMP: type and code (`8 0` = echo request, a ping) |
| `info` | `-` | Extra information for some entries |
| `path` | `SEND` | Direction relative to this host: `SEND` = outbound, `RECEIVE` = inbound, `FORWARD` if routed |
| `pid` | `7996` | The process ID that owned the connection (where present) |

Now read the five lines as a story. Line 1: this workstation (`10.20.4.114`) made an outbound HTTPS connection; process 7996 owned it. Lines 2 and 3: within the same second, `10.20.4.37` — another workstation — sent SYN packets (`S`) to this host on ports **445 (SMB)** and **3389 (RDP)**, and both were **dropped** inbound. Line 4: an ordinary DNS query to the internal DNS server. Line 5: the same neighbour sent a ping (`8 0`) that was dropped. A workstation probing its neighbour on SMB, RDP and ICMP is classic internal reconnaissance (T1046) or lateral movement attempts (T1021.001 RDP, T1021.002 SMB/Windows Admin Shares). You should immediately look at `10.20.4.37`: who is logged on, what processes it ran around 10:14.

Two limitations to remember. First, `pfirewall.log` holds a **process ID but not a process name**; you need a process log ([Process creation events](process-creation.md)) for the same host and time to turn `7996` into a program. Second, a local administrator — or malware running as one — can change the logging settings or delete the file, so forward it off the host quickly.

## Windows Firewall logging, option 2: Filtering Platform events in the Security log { #wfp-events }

### Turning them on { #wfp-config }

The engine behind Windows Firewall is the **Windows Filtering Platform (WFP)**. It can write audit events to the **Security** channel when two Advanced Audit Policy subcategories under *Object Access* are enabled:

```text
auditpol /set /subcategory:"Filtering Platform Connection" /success:enable /failure:enable
auditpol /set /subcategory:"Filtering Platform Packet Drop" /failure:enable
auditpol /get /subcategory:"Filtering Platform Connection","Filtering Platform Packet Drop"
```

- Line 1 — *Filtering Platform Connection*: Success gives **5156** (allowed connection) and **5158** (a program bound to a local port); Failure gives **5157** (blocked connection) and also controls **5154/5155** (a program was allowed / blocked from listening).
- Line 2 — *Filtering Platform Packet Drop*: Failure gives **5152** (a packet was dropped) and **5153** (a packet was vetoed by a more restrictive rule).
- Line 3 — shows the current setting:

```text
System audit policy
Category/Subcategory                      Setting
Object Access
  Filtering Platform Packet Drop          Failure
  Filtering Platform Connection           Success and Failure
```

In a domain, set these with Group Policy, not `auditpol` by hand. Be warned: *Success* on *Filtering Platform Connection* produces a 5156 for **almost every connection** the machine makes. Many organisations enable only Failure (blocked) everywhere, and Success only on servers or with collection-side filtering.

### The events and when they fire { #wfp-ids }

| Event | Name | When it fires | Why you care |
| --- | --- | --- | --- |
| **5156** | The Windows Filtering Platform has permitted a connection | A connection (TCP) or flow (UDP) was allowed, inbound or outbound | Process-to-network map: which program talked to which address and port |
| **5157** | The Windows Filtering Platform has blocked a connection | A connection matched a block rule | Probes and lateral movement hitting closed doors; malware whose outbound traffic is blocked |
| **5152** | The Windows Filtering Platform blocked a packet | A packet was dropped (often unsolicited inbound with no listener or rule) | Scans and noise; useful in bursts |
| **5154** | The Windows Filtering Platform has permitted an application or service to listen on a port for incoming connections | A program opened a listening port | New listeners = backdoors, bind shells, unexpected services |
| 5158 | The Windows Filtering Platform has permitted a bind to a local port | A program bound a local port (very noisy) | Rarely collected |

Attackers care because these events catch exactly what they try to do quietly: a beacon from an odd program to the internet (Command and Control, T1071), a new listener for a backdoor, or connections to admin ports across the network.

### A complete 5156 { #5156-sample }

The `inv.exe` from the process-creation story (a file `certutil` downloaded into `C:\Users\Public\`) now calls home:

```xml
<System>
  <EventID>5156</EventID>
  <TimeCreated SystemTime="2026-11-20T02:14:21.0937714Z" />
  <Channel>Security</Channel>
  <Computer>WS-114.corp.example</Computer>
  <Keywords>0x8020000000000000</Keywords>
</System>
<EventData>
  <Data Name="ProcessID">8124</Data>
  <Data Name="Application">\device\harddiskvolume3\users\public\inv.exe</Data>
  <Data Name="Direction">%%14593</Data>
  <Data Name="SourceAddress">10.20.4.114</Data>
  <Data Name="SourcePort">51561</Data>
  <Data Name="DestAddress">203.0.113.77</Data>
  <Data Name="DestPort">443</Data>
  <Data Name="Protocol">6</Data>
  <Data Name="FilterRTID">70241</Data>
  <Data Name="LayerName">%%14611</Data>
  <Data Name="LayerRTID">48</Data>
  <Data Name="RemoteUserID">S-1-0-0</Data>
  <Data Name="RemoteMachineID">S-1-0-0</Data>
</EventData>
```

Field by field:

- `Keywords` `0x8020000000000000` — the "Audit Success" keyword. A 5157 would carry `0x8010000000000000` (Audit Failure).
- `ProcessID` — `8124`, the process that owns the connection, in **decimal** here (unlike 4688, which uses hex `0x1fbc` for the same number). Converting between the two is a common stumbling block when you join events.
- `Application` — the program's path in **device form**: `\device\harddiskvolume3\` instead of `C:\`. Same file, different spelling. Normalise it (or match on the end of the path) before joining with process logs. A program in `\users\public\` making internet connections is suspicious on its own.
- `Direction` — `%%14593` = **Outbound**; `%%14592` = Inbound. Like other `%%` values, these are message-table codes that Event Viewer turns into words (see [Windows event structure and channels](../windows-logging/event-structure-channels.md)).
- `SourceAddress` / `SourcePort` — always the **local** side for outbound, the **remote** side for inbound. Read it together with `Direction`.
- `DestAddress` / `DestPort` — `203.0.113.77:443`, an internet address on the HTTPS port. Check it in proxy, DNS and threat-intelligence data.
- `Protocol` — the IP protocol number: `6` = TCP, `17` = UDP, `1` = ICMP.
- `FilterRTID` — the run-time ID of the WFP filter (rule) that allowed it. You can look it up on the host (`netsh wfp show filters`) to find which firewall rule matched.
- `LayerName` / `LayerRTID` — the WFP layer: `%%14611` (layer 48) = *ALE Connect* (outbound connection authorisation); for inbound accepts you would see the *Receive/Accept* layer (`%%14610`).
- `RemoteUserID` / `RemoteMachineID` — only filled when IPsec authentication is used; `S-1-0-0` = none.

The story is now complete across sources: 4688 shows `certutil` downloading `inv.exe` (T1105), a later 4688 shows `inv.exe` starting, and 5156 shows **that same file** connecting outbound to `203.0.113.77:443` — likely command and control over HTTPS (T1071.001). Network logs alone would only show "workstation → 203.0.113.77:443".

### Events that record changes to the firewall { #firewall-changes }

[Supplement] Attackers often open a port for a backdoor or remote access (`netsh advfirewall firewall add rule ...`, `New-NetFirewallRule`) or switch the firewall off (`netsh advfirewall set allprofiles state off`, `Set-NetFirewallProfile -Enabled False`). ATT&CK calls this **T1562.004, Impair Defenses: Disable or Modify System Firewall**. Watch for:

- In the Security channel (subcategory *MPSSVC Rule-Level Policy Change*): **4946** a rule was added, **4947** a rule was modified, **4948** a rule was deleted, **4950** a firewall setting was changed.
- In the firewall's own channel `Microsoft-Windows-Windows Firewall With Advanced Security/Firewall` (on by default): **2004** rule added, **2005** rule modified, **2006** rule deleted, **2003** a profile setting changed (for example the firewall turned off). Newer Windows 11 builds write a newer series of IDs for the same actions (for example **2097** for an added rule and **2071** in some builds); check which IDs your Windows versions produce before writing the detection.
- The process creation events for `netsh.exe advfirewall` or PowerShell `*-NetFirewallRule`/`Set-NetFirewallProfile` with their command lines.

A rule that allows inbound traffic to a program in a user-writable folder, or the Domain profile turned off on a server, deserves an immediate look.

## Linux host firewall logs: iptables, nftables and UFW { #iptables }

### Where the log comes from { #iptables-source }

On Linux, packet filtering happens in the kernel (**netfilter**). Rules are managed with `iptables` (older), `nft` (**nftables**, the modern replacement) or friendlier front ends such as **UFW** (Ubuntu) and **firewalld** (Red Hat family). A rule with a `LOG` action (iptables) or `log` statement (nftables) makes the **kernel** write a line to its log ring buffer. From there `rsyslog` writes it to a file — `/var/log/kern.log` or `/var/log/syslog` on Debian/Ubuntu, `/var/log/messages` on Red Hat — and UFW's rsyslog snippet sends its lines to `/var/log/ufw.log`. With the systemd journal you can read them with `journalctl -k` (see [Syslog](../linux-logging/syslog.md) and [Linux log files and the journal](../linux-logging/log-files-journal.md)).

A minimal iptables example that logs, then drops, new inbound SSH from outside the admin network:

```text
iptables -A INPUT -p tcp --dport 22 ! -s 10.20.9.0/24 -m conntrack --ctstate NEW -j LOG --log-prefix "SSH-DENY " --log-level 4
iptables -A INPUT -p tcp --dport 22 ! -s 10.20.9.0/24 -j DROP
```

- `-A INPUT` — append to the chain for traffic arriving at this host.
- `-p tcp --dport 22` — TCP to port 22.
- `! -s 10.20.9.0/24` — whose source is **not** the admin subnet.
- `-m conntrack --ctstate NEW` — only the first packet of a new connection (log once per connection, not per packet).
- `-j LOG --log-prefix "SSH-DENY " --log-level 4` — write a kernel log line starting with the prefix, at syslog severity 4 (warning). `LOG` does not stop the packet; that is why the second rule actually drops it.

The UFW equivalent is `ufw deny 22/tcp` plus `ufw logging on`; UFW then writes prefixes such as `[UFW BLOCK]`, `[UFW ALLOW]` and `[UFW AUDIT]`.

### Reading a line { #iptables-read }

Here are two lines from a Ubuntu server: one allowed outbound DNS query and one blocked inbound SSH attempt.

```text
Nov 20 07:32:33 web-01 kernel: [  945.682935] [UFW ALLOW] IN= OUT=ens33 SRC=10.20.30.15 DST=10.20.0.10 LEN=76 TOS=0x00 PREC=0x00 TTL=64 ID=61739 DF PROTO=UDP SPT=45469 DPT=53 LEN=56
Nov 20 07:35:02 web-01 kernel: [ 1094.120771] [UFW BLOCK] IN=ens33 OUT= MAC=00:50:56:aa:bb:cc:00:50:56:dd:ee:ff:08:00 SRC=203.0.113.45 DST=10.20.30.15 LEN=60 TOS=0x00 PREC=0x00 TTL=49 ID=21877 DF PROTO=TCP SPT=40122 DPT=22 WINDOW=64240 RES=0x00 SYN URGP=0
```

The syslog header (the same for every kernel line):

- `Nov 20 07:32:33` — the timestamp from the syslog daemon, in the host's local time and **without a year** (classic BSD syslog format).
- `web-01` — the host name.
- `kernel:` — the "program" is the kernel itself; there is no PID.
- `[  945.682935]` — seconds since boot from the kernel's own clock. Handy for ordering, useless for wall-clock time. Some setups hide it.
- `[UFW ALLOW]` / `[UFW BLOCK]` — the **log prefix** set in the rule. This is the only place the **action** appears; with plain iptables it says whatever the administrator wrote (`SSH-DENY `). A parser must know the local prefixes.

The body, field by field (second line):

| Field | Value | Meaning |
| --- | --- | --- |
| `IN=` | `ens33` | Interface the packet arrived on; **empty** for locally generated outbound packets (first line) |
| `OUT=` | (empty) | Interface it leaves on; empty for packets delivered to this host |
| `MAC=` | `00:50:56:aa:bb:cc` `00:50:56:dd:ee:ff` `08:00` | Destination MAC, source MAC and EtherType (`08:00` = IPv4) run together; only on inbound |
| `SRC=` / `DST=` | `203.0.113.45` → `10.20.30.15` | Source and destination IP |
| `LEN=` | `60` | Total IP packet length in bytes |
| `TOS=` / `PREC=` | `0x00` | Type of service / precedence bits; rarely useful |
| `TTL=` | `49` | Time to live remaining. Starting values are usually 64 (Linux) or 128 (Windows); 49 suggests a Linux-like sender about 15 hops away |
| `ID=` | `21877` | IP identification number |
| `DF` | (flag) | "Don't fragment" set — a **bare word, not key=value** |
| `PROTO=` | `TCP` | `TCP`, `UDP`, `ICMP` |
| `SPT=` / `DPT=` | `40122` → `22` | Source and destination port |
| `WINDOW=` / `RES=` | `64240` / `0x00` | TCP window size, reserved bits |
| `SYN` | (flag) | TCP flags appear as bare words (`SYN`, `ACK`, `FIN`, `RST`, `PSH`) |
| `URGP=` | `0` | Urgent pointer |

Note the second `LEN=` in the first line: the first `LEN=76` is the IP packet length; the second `LEN=56` is the **UDP** length. Same key, two meanings, in one line. This — together with bare flags, empty keys and fields that only appear for some protocols (`MAC=`, `WINDOW=`, ICMP `TYPE=`/`CODE=`) — is why these logs are awkward to parse. A good parser splits the header from the body, captures the prefix as the action, then reads `KEY=value` pairs and collects bare words as flags, taking the **first** `LEN` as the packet length.

From a security point of view the important fields are time, host, **action (prefix)**, interfaces (which side of the machine), **SRC/DST**, **PROTO** and **SPT/DPT**. The second line is an internet address trying SSH (SYN only, so the connection never started) and being blocked — normal background noise on an internet-facing server, but a **burst** of such lines from one source, or blocked SSH from an *internal* address, is worth a look (T1110 brute force, T1021.004 SSH lateral movement).

What the Linux line does **not** have: the **process**. Netfilter works on packets; it does not know which program sent them. For outbound traffic you would need auditd `connect` rules, an eBPF-based sensor or an EDR to tie it to a process.

[Supplement] nftables `log` statements use the same kernel logging path, so the line looks the same (prefix, then `IN=`/`OUT=`/`SRC=`...), and current UFW and firewalld use nftables underneath. Your parser does not need to change when the distribution moves from iptables to nftables.

### Windows and Linux firewall logs side by side { #fw-comparison }

| | Windows `pfirewall.log` | Windows 5156/5157/5152/5154 | Linux iptables/nftables/UFW |
| --- | --- | --- | --- |
| Where | Text file per profile | Security channel | Kernel log → `kern.log`/`syslog`/`messages`/`ufw.log`, journal |
| Default | Off | Off (audit subcategories) | Only for rules with `LOG`/`log` (UFW: `ufw logging on`) |
| Process | PID only (recent versions) | **Path + PID** | None |
| Time | Local, no zone | UTC in the event | Local syslog time, no year |
| Format | Space-separated, header names columns | Structured event fields | Syslog header + `KEY=value` + bare flags |
| Rotation/limit | Up to ~32 MB + one `.old` file | Security log size and forwarding | Normal log rotation |

## Windows object access auditing: 4663, 4657, 4660 { #object-access }

### Why these events are special { #object-access-why }

Picture a museum. Most rooms have no cameras. A few display cases holding the most valuable items have their own camera and a log that records every time the glass is opened. If you ever get an alert from one of those cases, you know two things straight away: someone touched the case, **and** someone, earlier, decided that case was valuable enough to watch.

Object access auditing works the same way. Windows does **not** log every file or registry access — that would be millions of events per hour. You must do two things:

1. **Enable the audit subcategory** in Advanced Audit Policy under *Object Access*: *Audit File System* (files and folders), *Audit Registry* (registry keys), and *Audit Kernel Object*, *Audit Removable Storage* or *Audit Detailed File Share* for related object types.
2. **Put an audit entry on each object you care about.** Every file, folder and registry key has a **SACL** (System Access Control List) besides the normal permissions list (DACL). An audit entry in the SACL says: "for *this* account or group, for *these* kinds of access (read, write, delete...), log success and/or failure". You set it in the object's *Properties → Security → Advanced → Auditing* tab, with `Set-Acl`, or centrally with Group Policy (*File System* and *Registry* policies, or **Global Object Access Auditing**, which applies a SACL to every file or key on the machine — use with great care).

Turning on the policy alone produces **nothing** for a file without a SACL. That is why the presence of object access events tells you something: someone chose that object. It may also mean someone wrote an **overly broad** SACL (for example `Everyone`, all access, on a whole drive), which floods the Security log and pushes useful events out — a common real-world mistake.

Good things to watch: folders with sensitive data (finance, HR, legal); credential stores and their backups (`ntds.dit` copies, `SAM`/`SECURITY` hive backups — T1003.002, T1003.003); **persistence locations in the registry** such as `HKLM\Software\Microsoft\Windows\CurrentVersion\Run` (T1547.001); security tool configuration keys (T1562.001); and "canary" or decoy files that nobody should ever open.

### Event 4663: an attempt was made to access an object { #4663 }

**4663** is written when an account **actually uses** an access right on an audited object — reads it, writes it, deletes it, changes its permissions. (Its companion **4656**, "a handle to an object was requested", fires when a program *asks* for access and includes failures; 4663 is usually the more useful one for "what really happened". **4658** records the handle being closed.)

A user account copies a file out of the finance share's audited folder:

```xml
<System>
  <EventID>4663</EventID>
  <TimeCreated SystemTime="2026-11-20T03:41:55.2201930Z" />
  <Channel>Security</Channel>
  <Computer>FS-02.corp.example</Computer>
</System>
<EventData>
  <Data Name="SubjectUserSid">S-1-5-21-1004336348-1177238915-682003330-3108</Data>
  <Data Name="SubjectUserName">j.park</Data>
  <Data Name="SubjectDomainName">CORP</Data>
  <Data Name="SubjectLogonId">0x8a3f21</Data>
  <Data Name="ObjectServer">Security</Data>
  <Data Name="ObjectType">File</Data>
  <Data Name="ObjectName">D:\Shares\Finance\Payroll\2026-11-payroll.xlsx</Data>
  <Data Name="HandleId">0x1c84</Data>
  <Data Name="AccessList">%%4416</Data>
  <Data Name="AccessMask">0x1</Data>
  <Data Name="ProcessId">0x4</Data>
  <Data Name="ProcessName"></Data>
  <Data Name="ResourceAttributes">S:AI</Data>
</EventData>
```

The four sections the event message shows, and the fields behind them:

- **Subject** — *who*: `SubjectUserSid`/`SubjectUserName`/`SubjectDomainName` = `CORP\j.park`; `SubjectLogonId` `0x8a3f21` links to the 4624 on `FS-02` that shows how they logged on — here it will be a **type 3 (network)** logon from their workstation (see [Login events](logins.md)).
- **Object** — *what*: `ObjectServer` is always `Security` for files; `ObjectType` `File` (or `Key` for registry, and also used for folders); `ObjectName` is the full path; `HandleId` `0x1c84` is the handle number — the key that ties together 4656, 4663, 4658 and 4660 for the same open.
- **Process Information** — *with which program*: `ProcessId` and `ProcessName`. Here `0x4` and an empty name mean the **System** process — that is what you see when the file is accessed **over the network through SMB**: the server's kernel (System, PID 4) does the work on the user's behalf. For local access you would see a real path such as `C:\Windows\explorer.exe` or `C:\Users\Public\inv.exe`. (For share access, *Audit Detailed File Share* event **5145** adds the client's IP address and share name.)
- **Access Request Information** — *what kind*: `AccessList` `%%4416` = **ReadData (or ListDirectory)**; `AccessMask` `0x1` is the same right as a number.

Common access rights for files you will meet:

| `AccessMask` | `AccessList` | Meaning for a file (folder) |
| --- | --- | --- |
| `0x1` | `%%4416` | ReadData (ListDirectory) |
| `0x2` | `%%4417` | WriteData (AddFile) |
| `0x4` | `%%4418` | AppendData (AddSubdirectory) |
| `0x80` | `%%4423` | ReadAttributes |
| `0x100` | `%%4424` | WriteAttributes |
| `0x10000` | `%%1537` | DELETE |
| `0x40000` | `%%1539` | WRITE_DAC — change permissions |
| `0x80000` | `%%1540` | WRITE_OWNER — take ownership |

Masks combine by adding bits: `0x6` = WriteData + AppendData.

How to read patterns, not single events: one user reading one payroll file is probably their job. The same account reading **hundreds of files across many folders in a few minutes** is collection for exfiltration (T1039, Data from Network Shared Drive) or ransomware enumeration; a burst of `WriteData` followed by `DELETE` on many files is how encryption-then-delete looks (T1486). `WRITE_DAC` on a sensitive folder by a non-admin is a permission change worth questioning (T1222.001).

### Event 4657: a registry value was modified { #4657 }

**4657** is written when a value under an audited registry key is created, changed or deleted (subcategory *Audit Registry*, plus a SACL on the key with "Set Value"). Its great strength is that it records the **old and new value**. An attacker adds a Run-key entry for persistence:

```xml
<EventData>
  <Data Name="SubjectUserSid">S-1-5-21-1004336348-1177238915-682003330-3108</Data>
  <Data Name="SubjectUserName">j.park</Data>
  <Data Name="SubjectDomainName">CORP</Data>
  <Data Name="SubjectLogonId">0x2b04e11</Data>
  <Data Name="ObjectName">\REGISTRY\MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Run</Data>
  <Data Name="ObjectValueName">OneDriveSyncHelper</Data>
  <Data Name="HandleId">0x2f8</Data>
  <Data Name="OperationType">%%1904</Data>
  <Data Name="OldValueType">-</Data>
  <Data Name="OldValue">-</Data>
  <Data Name="NewValueType">%%1873</Data>
  <Data Name="NewValue">C:\Users\Public\inv.exe -silent</Data>
  <Data Name="ProcessId">0x20d8</Data>
  <Data Name="ProcessName">C:\Windows\System32\reg.exe</Data>
</EventData>
```

- `ObjectName` — the key in **kernel form**: `\REGISTRY\MACHINE\` = `HKLM\`, `\REGISTRY\USER\<SID>\` = `HKU\<SID>\` (a user's `HKCU`). This is the machine-wide Run key: anything listed here starts when any user logs on.
- `ObjectValueName` — the value's name, `OneDriveSyncHelper`. Attackers pick names that look like legitimate software; the name proves nothing.
- `OperationType` — `%%1904` = **new value created**; `%%1905` = existing value modified; `%%1906` = value deleted.
- `OldValueType` / `OldValue` — `-` because the value did not exist before. For a modification you would see the previous data here — very useful when an attacker *replaces* the path of a legitimate entry.
- `NewValueType` / `NewValue` — `%%1873` = `REG_SZ` (a string); the data is the program to start: our `inv.exe` from a user-writable folder. This is **T1547.001, Boot or Logon Autostart Execution: Registry Run Keys**.
- `ProcessId` / `ProcessName` — `reg.exe` made the change, so a 4688 for `reg.exe add HKLM\...\Run /v OneDriveSyncHelper ...` should exist just before (T1112, Modify Registry).
- Note that writing to `HKLM\...\Run` requires admin rights: the attacker has already escalated by this point — check the logon and token of `SubjectLogonId` `0x2b04e11`.

### Event 4660: an object was deleted { #4660 }

**4660** says an audited object was deleted, but — confusingly — it contains **no object name**, only the `HandleId`, the subject and the process. To find *which* file was deleted, look for the 4663 (with `DELETE`, `0x10000`) or 4656 with the **same `HandleId`, same process ID and same host** a moment earlier:

```text
03:52:10.118  4663  FS-02  HandleId=0x2210  ProcessName=C:\Users\Public\inv.exe  ObjectName=D:\Shares\Finance\Payroll\2026-11-payroll.xlsx  AccessMask=0x10000
03:52:10.119  4660  FS-02  HandleId=0x2210  ProcessName=C:\Users\Public\inv.exe
```

- Line 1 — the 4663 names the file and shows `0x10000` (DELETE) being used through handle `0x2210`.
- Line 2 — one millisecond later, the 4660 with the same handle confirms the deletion actually happened.

Windows also has **4659** (a handle was requested with the intent to delete) for some cases. Mass deletion of audited files is typical of ransomware cleanup or an attacker covering tracks (T1070.004, Indicator Removal: File Deletion).

### Related object access events { #object-access-other }

- **4656** — a handle to an object was requested (includes failed attempts — good for "someone *tried* to open the canary file").
- **4658** — the handle was closed (lets you measure how long a file was held open).
- **4670** — permissions on an object were changed (old and new security descriptor).
- **5140 / 5145** — a network share was accessed / a file in a share was checked for access (subcategories *Audit File Share* / *Audit Detailed File Share*; include the client IP — see [SMB](../other-protocols/smb.md)).
- **4663 on `lsass.exe`** — with *Audit Kernel Object* enabled and an audit entry on the LSASS process, attempts to read its memory produce 4656/4663 with `ObjectType` = `Process`, a classic credential-dumping signal (T1003.001; see [Credential dumping and Mimikatz](../endpoint-attacks/credential-dumping-mimikatz.md)). EDR products usually catch this more reliably.

## Putting it to work in a SOC { #soc-use }

- **Decide what to collect from host firewalls.** At minimum: blocked inbound connections on workstations and servers (5157/5152 or `DROP` lines, UFW `BLOCK`), new listening ports (5154), and firewall configuration changes (4946–4950, firewall channel rule events). Add allowed connections (5156) on servers, or filtered to non-browser processes and non-standard ports on workstations.
- **Normalise** to common fields: `host`, `action`, `direction`, `src_ip`, `src_port`, `dst_ip`, `dst_port`, `protocol`, `process_path`, `process_id`. Convert device paths to drive letters, decimal/hex PIDs to one form, and local times to UTC.
- **Hunt and alert on:** workstation-to-workstation SMB/RDP/WinRM; one source hitting many hosts or many ports (blocked); programs in `Temp`, `Downloads`, `Public`, `ProgramData` making outbound connections; Office or script hosts connecting to the internet; new listeners on workstations; the firewall disabled or a broad allow rule added; internal sources in Linux `BLOCK` lines for SSH.
- **Put SACLs where they pay off.** Sensitive shares (read and delete), Run keys and other autostart keys (set value), security tool keys, decoy files (any access). Review SACL breadth; avoid `Everyone`/full access on whole volumes.
- **Join, don't stare at single events.** `SubjectLogonId` → 4624 (how they logged on), `ProcessName`/`ProcessId` → 4688 (what the process was), `HandleId` → 4663/4660 (what was deleted), 5156 `ProcessID` → 4688 `NewProcessId` (convert hex!).
- **Protect the evidence.** Forward off the host quickly; alert on 1102 (Security log cleared) and on audit policy changes (4719).

## The 2026 view { #trends }

!!! success "[2026 Current] Still valid as is"
    Windows Firewall's two logging options, the `pfirewall.log` format and its limits, the Filtering Platform events 5156/5157/5152/5154 and their fields, the iptables/UFW log format, and object access auditing with 4663/4657/4660 all work as described on current Windows 11, Windows Server 2025 and current Linux distributions. The idea behind them — a host firewall as a process-aware network sensor, and object auditing only where someone placed a SACL — is unchanged.

!!! info "[Changed] What has changed"
    - **Naming.** Microsoft's documentation now mostly calls the product simply **Windows Firewall** (it was "Windows Defender Firewall" for several years); the management snap-in still says "with Advanced Security". The logging settings did not change.
    - **Firewall-change event IDs.** Newer Windows 11 builds log rule changes in the firewall channel with newer IDs (such as 2097, and 2071 in some builds) alongside or instead of the older 2004–2006 series. Public detection rules (for example Sigma's) now look for all of them. Check what your build writes.
    - **nftables is the default packet filter** on current Debian, Ubuntu and Red Hat family releases; `iptables` commands are often a compatibility layer over it, and UFW and firewalld use it underneath. The kernel log line format seen by analysts stayed the same.
    - **EDR network telemetry** (Microsoft Defender for Endpoint, CrowdStrike Falcon, SentinelOne, Elastic Defend and others) now gives most organisations a process-to-connection record without enabling 5156 everywhere; Sysmon Event 3 (network connection) — available as the standalone tool and, in 2026, as an optional built-in Windows feature — does the same. 5156/5157 remain a useful agentless, independent source.
    - **Common schemas** (Elastic Common Schema, OCSF, Microsoft ASIM) define standard network and file-activity fields, so one detection can cover pfirewall, 5156, UFW and EDR data if you normalise at ingest.
    - **Cloud and identity first.** Much sensitive data now lives in SaaS and cloud storage, where "object access" is recorded by the service's audit log (for example Microsoft 365 file access events or cloud storage access logs), not by Windows 4663. On-premises file servers still need 4663.

!!! warning "[Caution] Wrong or risky if done the old way"
    - **Don't turn on Filtering Platform Connection Success on every machine and ship it all** — you will flood the SIEM and the Security log will roll over in minutes, pushing out logons and process events. Plan volume first.
    - **Don't assume `pfirewall.log` is on** or that it keeps history: it is off by default and keeps only the current file plus one `.old`.
    - **Don't compare `pfirewall.log` times with event times without converting** — local time versus UTC.
    - **Don't join 5156 `ProcessID` to 4688 `NewProcessId` without converting decimal to hex**, and normalise `\device\harddiskvolumeN\` paths.
    - **Don't expect a process in Linux firewall logs**; use auditd, eBPF sensors or EDR for that.
    - **Don't conclude "nobody touched the file" because there is no 4663** — without a SACL nothing is logged at all. Check the SACL first.
    - **Don't use Global Object Access Auditing or `Everyone`/full-control SACLs on whole drives** without testing; they can bury the Security log.
    - **Don't look for the file name in 4660** — follow the `HandleId` back to 4663/4656.

## Practice questions { #quiz }

### Question 1

On workstation `WS-207` you see these `pfirewall.log` lines (local time). What do they show, which fields matter, and what do you do next?

```text
2026-11-20 14:02:11 DROP TCP 10.20.4.91 10.20.4.207 50112 445 52 S 3391827401 0 64240 - - - RECEIVE 4
2026-11-20 14:02:11 DROP TCP 10.20.4.91 10.20.4.207 50113 135 52 S 1029384756 0 64240 - - - RECEIVE 0
2026-11-20 14:02:12 DROP TCP 10.20.4.91 10.20.4.207 50114 5985 52 S 2938475610 0 64240 - - - RECEIVE 0
```

??? success "Answer and explanation"
    - `DROP` + `RECEIVE` — inbound packets were **dropped** by this host's firewall.
    - `src-ip` `10.20.4.91` → `dst-ip` `10.20.4.207` — another **internal** machine (workstation range) is the source; this traffic would never be seen by the perimeter firewall.
    - `dst-port` `445`, `135`, `5985` — SMB, RPC endpoint mapper and WinRM (HTTP): the three classic doors for Windows remote administration and lateral movement.
    - `tcpflags` `S` — only SYN packets: connection attempts, not established sessions.
    - Three ports in about one second from the same source — an automated probe, not a person browsing.

    **What it shows:** `10.20.4.91` is scanning or trying to move laterally (T1046; T1021.002 SMB, T1021.006 WinRM). This host's firewall blocked it. **Next:** look at `10.20.4.91` — who is logged on (4624), what processes ran around 14:02 (4688/Sysmon/EDR), outbound connections from it; search other hosts' firewall logs for the same source to see how many machines it touched; and consider isolating it. Remember the times are local — convert before comparing with Security events in UTC.

### Question 2

A server shows a 5156 with `Application` = `\device\harddiskvolume2\windows\system32\rundll32.exe`, `Direction` = `%%14593`, `DestAddress` = `198.51.100.140`, `DestPort` = `8443`, `Protocol` = `6`, `ProcessID` = `5320`. Explain each field and how you would find what `rundll32.exe` was running.

??? success "Answer and explanation"
    - `Application` — the genuine `rundll32.exe` (device path form of `C:\Windows\System32\rundll32.exe`). The program is legitimate; it runs functions inside DLLs and is often abused to run malicious DLLs (T1218.011).
    - `Direction` `%%14593` — **outbound**.
    - `DestAddress`/`DestPort` — an internet address on TCP 8443, a non-standard HTTPS-like port. `rundll32.exe` itself has no reason to talk to the internet directly; whatever DLL it loaded does.
    - `Protocol` `6` — TCP.
    - `ProcessID` `5320` — decimal. In 4688 the same process appears as `NewProcessId` `0x14c8`.

    **Finding what it ran:** search 4688 (or Sysmon 1/EDR) on that host shortly before the 5156 for `NewProcessId` = `0x14c8` and `NewProcessName` ending in `rundll32.exe`. Its `CommandLine` shows which DLL and function (for example a DLL in `C:\ProgramData\` or `AppData`), and its `ParentProcessName` shows what launched it. Then check the destination in proxy/DNS/threat-intel data, collect the DLL for analysis, and look for the same destination elsewhere in the fleet. This is a likely C2 channel (T1071.001).

### Question 3

A colleague says: "I enabled *Audit File System* and *Audit Registry* in the domain audit policy yesterday, but there are no 4663 or 4657 events for the Run key or the finance share. The audit policy must be broken." What is the most likely reason, how do you fix it, and what should you be careful about?

??? success "Answer and explanation"
    The policy is probably fine. Object access auditing needs **two** things: the subcategory enabled (done) **and an audit entry (SACL) on each object**. Without a SACL on `HKLM\Software\Microsoft\Windows\CurrentVersion\Run` and on the finance share folders, Windows has nothing to log.

    **Fix:** add SACLs — on the Run key for *Set Value* (and *Create Subkey*/*Delete*) by `Everyone` or *Authenticated Users*, success; on the finance folders for *Read Data*, *Write Data*, *Delete* and *Change Permissions* by the relevant groups (success, and failure if you want attempts). Deploy them with Group Policy (*File System*/*Registry* security policy) so they apply consistently, and test: change a test value and read a test file, then check for 4657 and 4663.

    **Be careful:** keep the SACL narrow — not `Everyone`/full control on whole drives, and not Global Object Access Auditing without testing — or the Security log will fill and roll over, pushing out logon and process events. Check event volume on a pilot server first, raise the Security log size, and make sure the events are forwarded off the host.

## Related { #related }

- [Important Events](index.md) — this section's overview
- [Login events](logins.md) — the logon behind `SubjectLogonId`
- [Process creation events](process-creation.md) — turning a PID or `ProcessName` into a full command line
- [Windows event structure and channels](../windows-logging/event-structure-channels.md) — `%%` message codes and the firewall channel
- [Syslog](../linux-logging/syslog.md) — the header on every kernel firewall line
- [Linux log files and the systemd journal](../linux-logging/log-files-journal.md) — where `kern.log`, `ufw.log` and `messages` live
- [VBS, host firewalls and antivirus](../endpoint-defense/vbs-firewall-antivirus.md) — host firewalls as a defence
- [Application control, FIM and catching persistence](../endpoint-defense/appcontrol-fim-persistence.md) — watching Run keys and files from the defensive side
- [Lateral movement, collection and exfiltration](../endpoint-attacks/lateral-collection-exfil.md) — the attacker actions these logs catch
- [SMB](../other-protocols/smb.md) — share access and 5140/5145
- [Windows Event IDs](../../../basics/windows-event-ids.md)

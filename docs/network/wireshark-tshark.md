---
title: Wireshark & tshark
tags:
  - tool
  - network
  - pcap
---

# Wireshark & tshark

<div class="dfir-meta" markdown>
**Category:** Packet analysis · **Platform:** Windows / Linux / macOS · **Last updated:** 2026-09-16
</div>

!!! abstract "What they do"
    Wireshark is the GUI packet analyser; **tshark** is the same engine on the command line (scriptable, works on huge files, no GUI freeze). Use Zeek to find *which* flows matter, then Wireshark/tshark to read *what was inside them*. Filters below are **display filters** (Wireshark syntax) unless marked BPF.

## Two filter languages — don't mix them

| | Display filter (Wireshark / `tshark -Y`) | Capture filter (BPF: `tcpdump`, `tshark -f`, Wireshark capture options) |
|---|---|---|
| Syntax | `ip.addr == 10.0.0.5 && tcp.port == 445` | `host 10.0.0.5 and tcp port 445` |
| Applied | After capture, on parsed fields | In kernel, before capture — cheap |
| Power | Every dissected field (`http.host`, `tls.handshake.extensions_server_name`) | Only headers/offsets |

## Display filter cheat sheet

### Hosts, ports, conversations

```text
ip.addr == 10.0.0.5                       # either direction
ip.src == 10.0.0.5 && ip.dst == 203.0.113.7
ip.addr == 10.0.0.0/24                    # subnet
!(ip.addr == 10.0.0.53)                   # exclude the resolver
tcp.port == 445 || udp.port == 53
tcp.stream eq 42                          # one TCP conversation (get the number from a packet)
udp.stream eq 7
eth.addr == 00:0c:29:aa:bb:cc             # by MAC
frame.time >= "2026-09-16 02:00:00" && frame.time <= "2026-09-16 03:00:00"
frame.time_delta_displayed > 1            # gaps between displayed packets
```

### TCP behaviour

```text
tcp.flags.syn == 1 && tcp.flags.ack == 0  # SYNs only (scans, new connections)
tcp.flags.reset == 1                      # RSTs
tcp.analysis.flags                        # any TCP problem (retrans, dup ack, zero window…)
tcp.analysis.retransmission
tcp.len > 0                               # packets carrying data
tcp.payload contains "cmd.exe"            # string in payload (case-sensitive)
tcp matches "(?i)powershell"              # regex, case-insensitive
tcp.window_size == 0
```

### DNS

```text
dns                                       # all
dns.flags.response == 0                   # queries only
dns.qry.name contains "evil"
dns.qry.name matches "^[a-z0-9]{20,}\."   # long random first label (tunnel/DGA)
dns.qry.type == 16                        # TXT   (1 A, 28 AAAA, 5 CNAME, 15 MX, 10 NULL, 255 ANY)
dns.flags.rcode == 3                      # NXDOMAIN
dns.resp.ttl < 60
dns && !(ip.dst == 10.0.0.53)             # DNS not to the corporate resolver
dns.a == 203.0.113.7                      # answers containing this IP
```

### HTTP

```text
http.request                              # requests only
http.request.method == "POST"
http.host contains "cdn" || http.host matches "^\d+\.\d+\.\d+\.\d+$"   # raw-IP Host header
http.request.uri contains ".php?"
http.user_agent contains "python" || http.user_agent == ""
http.response.code == 200 && http.content_type contains "application/x-msdownload"
http.file_data contains "MZ"              # body starts like a PE
http.authorization                        # Basic/NTLM auth headers
http.cookie contains "session"
http.request.full_uri                     # (column-friendly) full URL
```

### TLS

```text
tls.handshake.type == 1                   # Client Hello
tls.handshake.type == 2                   # Server Hello
tls.handshake.type == 11                  # Certificate
tls.handshake.extensions_server_name contains "example"     # SNI
tls.handshake.extensions_server_name == ""  # no SNI... use: tls.handshake.type==1 && !tls.handshake.extensions_server_name
tls.handshake.ja3                          # JA3 (Wireshark 4.x+ computes it; older: tls.handshake.ja3_full via LUA)
x509sat.uTF8String contains "Cobalt"       # cert subject strings
x509af.notBefore                           # cert validity
tls.record.version == 0x0301              # TLS 1.0 records
tls.alert_message
```

### SMB / Windows protocols (lateral movement)

```text
smb2                                      # SMB2/3
smb2.cmd == 5                             # Create (open file)   3 Tree Connect, 9 Write, 8 Read, 6 Close
smb2.tree contains "ADMIN$" || smb2.tree contains "C$" || smb2.tree contains "IPC$"
smb2.filename contains ".exe" || smb2.filename contains "psexesvc"
smb2.cmd == 9 && smb2.filename contains "PSEXESVC"
ntlmssp.auth.username                     # NTLM user names in the clear (the hash isn't, the name is)
ntlmssp.messagetype == 0x00000003         # NTLM AUTHENTICATE
kerberos.CNameString                      # Kerberos principal
kerberos.msg_type == 12                   # TGS-REQ (10 AS-REQ, 11 AS-REP, 13 TGS-REP, 30 KRB-ERROR)
kerberos.etype == 23                      # RC4 — Kerberoasting hint on TGS-REQ/REP
dcerpc                                    # MS-RPC (135 + dynamic port)
svcctl                                    # Service Control Manager calls (PsExec CreateServiceW/StartServiceW)
svcctl.opnum == 12 || svcctl.opnum == 19  # CreateServiceW (12), StartServiceW (19)
wmi || dcom                               # WMI over DCOM
rdp || tcp.port == 3389
winrm || (http && tcp.port == 5985)
ldap.protocolOp == 3                      # LDAP searchRequest (enumeration: BloodHound = lots)
```

### Other useful

```text
icmp && data.len > 64                     # oversized ICMP (tunnel)
icmp.type == 8                            # echo request
ftp.request.command == "STOR" || ftp-data # uploads
smtp.req.command == "AUTH" || imf         # mail auth / actual messages
ssh.protocol                              # banner (version strings)
arp.duplicate-address-detected            # ARP spoofing
dhcp.option.hostname                      # hostnames from DHCP
nbns || llmnr || mdns                     # name-resolution poisoning targets (Responder)
frame contains "MZ" || frame contains "This program cannot be run"
```

## tshark recipes

```bash
# Read a pcap with a display filter, show default columns
tshark -r cap.pcap -Y 'http.request && ip.addr==10.0.0.25'

# Pick exact fields as TSV (-T fields), with header
tshark -r cap.pcap -Y 'http.request' -T fields -E header=y -E separator='\t' \
  -e frame.time -e ip.src -e ip.dst -e http.host -e http.request.method -e http.request.uri -e http.user_agent

# DNS queries with answers
tshark -r cap.pcap -Y 'dns.flags.response==1' -T fields -e frame.time -e ip.src -e dns.qry.name -e dns.a -e dns.resp.ttl

# TLS SNI + JA3 per Client Hello
tshark -r cap.pcap -Y 'tls.handshake.type==1' -T fields -e frame.time -e ip.src -e ip.dst -e tls.handshake.extensions_server_name -e tls.handshake.ja3

# Certificate subjects
tshark -r cap.pcap -Y 'tls.handshake.type==11' -T fields -e ip.src -e x509sat.printableString -e x509sat.uTF8String -e x509af.notBefore -e x509af.notAfter

# Conversations / endpoints statistics (like conn.log-lite)
tshark -r cap.pcap -q -z conv,tcp            # -z conv,ip / conv,udp
tshark -r cap.pcap -q -z endpoints,ip
tshark -r cap.pcap -q -z io,phs               # protocol hierarchy
tshark -r cap.pcap -q -z http,tree            # HTTP request/response stats
tshark -r cap.pcap -q -z dns,tree
tshark -r cap.pcap -q -z io,stat,60,'ip.addr==10.0.0.25'   # bytes per 60 s — beacon interval eyeballing

# Follow one TCP stream as text (like Follow → TCP Stream)
tshark -r cap.pcap -q -z follow,tcp,ascii,42
tshark -r cap.pcap -q -z follow,tls,ascii,42  # if you have keys loaded

# Export HTTP / SMB / FTP objects to a folder
tshark -r cap.pcap --export-objects http,./objs_http
tshark -r cap.pcap --export-objects smb,./objs_smb
tshark -r cap.pcap --export-objects imf,./objs_mail

# Split a huge pcap: only what matters (fast, then analyse the slice)
tshark -r huge.pcap -Y 'ip.addr==10.0.0.25' -w host25.pcap
editcap -A "2026-09-16 02:00:00" -B "2026-09-16 03:00:00" huge.pcap window.pcap     # by time
editcap -c 100000 huge.pcap chunk.pcap                                            # by packet count
mergecap -w all.pcap part1.pcap part2.pcap

# Capture info / sanity
capinfos cap.pcap                              # duration, first/last time, size, dropped
tshark -r cap.pcap -q -z expert                # expert info (malformed, retrans…)

# Decrypt TLS with a key log file (from a client with SSLKEYLOGFILE set) or RSA key
tshark -r cap.pcap -o tls.keylog_file:keys.log -Y http2
tshark -r cap.pcap -o "tls.keys_list:203.0.113.7,443,http,server.key"

# Live capture (BPF capture filter), rotate files
tshark -i eth0 -f 'not port 22' -b filesize:100000 -b files:20 -w /data/cap.pcap
tcpdump -i eth0 -nn -s0 -w cap.pcap 'host 10.0.0.25 and not port 22'
```

## Wireshark GUI habits that pay off

- **Columns**: add `tls.handshake.extensions_server_name`, `http.host`, `dns.qry.name`, `tcp.stream` as custom columns (right-click field → Apply as Column). Save as a profile ("DFIR").
- **Statistics → Conversations / Endpoints / Protocol Hierarchy** before reading a single packet — it's `conn.log` for pcaps.
- **Statistics → I/O Graph** with a filter for one host/dest and 1-s or 60-s interval: beacons draw a comb.
- **Analyze → Follow → TCP/TLS/HTTP Stream** to read a session as a conversation; **File → Export Objects** to carve files.
- **View → Time Display Format → UTC Date and Time** (⇧⌘/Ctrl+Alt+7) so your notes match Zeek/event logs (UTC).
- **Edit → Preferences → Protocols → TLS → (Pre)-Master-Secret log filename** for decryption when you have key logs.
- **Name Resolution off** for MAC/transport/network unless you want the pcap machine doing DNS lookups of attacker IPs (it will).
- Coloring rules: `tcp.flags.reset==1` red, `tcp.analysis.flags` yellow, `dns.flags.rcode!=0` orange — problems jump out.
- **Expert Information** (bottom-left circle) for malformed packets and protocol violations — evasion attempts live there.

## Gotchas

!!! warning
    - **Timestamps** come from the capture host's clock. Check `capinfos` first-packet time against a known event; an unsynced sensor shifts your whole timeline.
    - **`-s0` / snaplen**: truncated captures (default 96/262144 bytes) lose payload — `frame.cap_len < frame.len` tells you.
    - **VLAN / GRE / VXLAN / ERSPAN**: tunnelled captures need the right decode (`Decode As…`) or your filters see nothing.
    - **Checksums**: NIC offloading makes outgoing checksums look wrong; disable validation in preferences (Zeek needs `-C` for the same reason).
    - **`ip.addr == x` vs `ip.src == x`**: `!(ip.addr==x)` excludes packets where x is on *either* side — usually what you want, but `ip.addr != x` does **not** (it matches packets where at least one side ≠ x — nearly all of them).
    - **`contains` is case-sensitive**; use `matches "(?i)…"` for case-insensitive regex.
    - **Large pcaps**: Wireshark loads everything into memory; use tshark/editcap to slice first, or Arkime/Zeek to index.

## References

- [Wireshark display filter reference](https://www.wireshark.org/docs/dfref/)
- [tshark man page](https://www.wireshark.org/docs/man-pages/tshark.html)
- [SANS TCP/IP & tcpdump pocket reference](https://www.sans.org/posters/tcp-ip-and-tcpdump/)
- [Wireshark sample captures](https://wiki.wireshark.org/SampleCaptures) · [malware-traffic-analysis.net exercises](https://www.malware-traffic-analysis.net/)

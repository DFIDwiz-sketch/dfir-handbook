---
title: Arkime Search Syntax
tags:
  - tool
  - network
  - arkime
  - cheatsheet
---

# Arkime Search Syntax

<div class="dfir-meta" markdown>
**Category:** Cheat sheet · **Tool:** Arkime viewer · **Last updated:** 2026-09-16
</div>

!!! abstract "In one sentence"
    Arkime's expression language is `field operator value`, joined with `&&` / `||` / `!`, with wildcards, regex, lists and `EXISTS!` — learn about thirty field names and you can ask almost anything of months of traffic in one line.

## Operators

| Operator | Meaning | Example |
|---|---|---|
| `==` | equals (case-insensitive for strings) | `ip.dst == 203.0.113.7` |
| `!=` | not equals | `port.dst != 443` |
| `<` `<=` `>` `>=` | numeric compare | `databytes.src > 1000000` |
| `&&` `\|\|` `!` | and / or / not | `port.dst == 443 && !(protocols == tls)` |
| `( )` | grouping | `(port.dst == 80 \|\| port.dst == 8080) && ip.src == 10.0.0.0/8` |
| `[a, b, c]` | list — any of | `port.dst == [445, 135, 3389, 5985]` |
| `*` | wildcard (strings) | `host.http == *.ngrok.io` |
| `/regex/` | regex (strings; slow on big ranges) | `host.dns == /^[a-z0-9]{25,}\./` |
| `EXISTS!` | field is present | `cert.notbefore == EXISTS!` |
| `$shortcut` | saved list/variable (Settings → Shortcuts) | `ip.dst == $c2_ips` |
| `"…"` | quote values with spaces/special chars | `http.user-agent == "Mozilla/5.0 (compatible; MSIE 9.0*"` |

IPs accept CIDR (`10.0.0.0/8`), ranges are done with lists or multiple clauses. Time is chosen with the **date picker** or `date=…` in the URL; there is also `starttime`/`stoptime` in the API (epoch seconds).

## Field names you will actually use

Field names show up in SPIView and as you type (autocomplete). Most protocol fields have `.src`/`.dst` variants where direction matters; many have `.cnt` (distinct count in the session).

### Session & flow

| Field | Meaning |
|---|---|
| `ip`, `ip.src`, `ip.dst` | Address (either / source / destination) |
| `port`, `port.src`, `port.dst` | Port |
| `protocols` | Detected protocols in the session: `tcp`, `udp`, `http`, `tls`, `dns`, `smb`, `ssh`, `krb5`, `ntlm`, `rdp`, `quic`, `socks`, `dcerpc`, … |
| `ip.protocol` | IP protocol number / name (`tcp`, `udp`, `icmp`, `gre`) |
| `packets`, `packets.src`, `packets.dst` | Packet counts |
| `bytes`, `bytes.src`, `bytes.dst` | Bytes on the wire |
| `databytes`, `databytes.src`, `databytes.dst` | **Payload** bytes (no headers) |
| `session.length` | Duration in ms |
| `session.segments` | How many sessions this connection was split into |
| `rootId` | ID linking split sessions of one long connection |
| `starttime`, `stoptime` | First/last packet (API); UI uses the picker |
| `country`, `country.src`, `country.dst` / `asn.*` / `rir.*` | GeoIP / ASN / registry |
| `mac.src`, `mac.dst`, `vlan`, `node` | Layer 2, VLAN tag, sensor name |
| `tags` | Tags (from `-t`, WISE, Hunts, Cron queries, tagger) |
| `communityId` | Community ID hash (pivot to Zeek/Suricata) |
| `id` | Session id (URL-able) |

### HTTP

| Field | Meaning |
|---|---|
| `host.http` | Host header |
| `http.uri`, `http.uri.path`, `http.uri.key`, `http.uri.value` | Full URI / path / query keys & values |
| `http.method` | `GET`, `POST`, … |
| `http.statuscode` | Response code |
| `http.user-agent` | User agent |
| `http.referer`, `http.cookie.key`, `http.cookie.value`, `http.authorization`, `http.user` | Other headers / Basic-auth user |
| `http.request.header`, `http.response.header` | Header **names** present (order-insensitive) — fingerprint tools by missing headers |
| `http.request.body`, `http.response.body` | Body snippets (when body capture enabled) |
| `http.bodymagic` | Sniffed content type of body (`application/x-dosexec`) |
| `http.md5`, `http.sha256` | Hash of HTTP bodies (if enabled) |
| `http.hasheader.src/dst`, `http.hasheader.*.value` | Custom header extraction configured in `config.ini` |

### DNS

| Field | Meaning |
|---|---|
| `host.dns`, `host.dns.all` | Queried names (and all names incl. answers) |
| `dns.ip` | Resolved IPs |
| `dns.query.type`, `dns.query.class` | `A`, `TXT`, `NULL`… (recent Arkime: `dns.qt`) |
| `dns.status` | `NOERROR`, `NXDOMAIN`, … |
| `dns.opcode`, `dns.puny` | Opcode; punycode names |
| `host.dns.tokens` | Tokenised labels — free "contains a word" search |

### TLS / certificates

| Field | Meaning |
|---|---|
| `host.tls` (older: `tls.sni`) | SNI |
| `tls.version`, `tls.cipher` | Negotiated version / cipher |
| `tls.ja3`, `tls.ja3s`, `tls.ja4`, `tls.ja4s` | Fingerprints (ja4 needs the plugin/newer build) |
| `tls.sessionid`, `tls.srcSessionId`, `tls.dstSessionId` | Session IDs (resumption) |
| `cert.subject.cn`, `cert.issuer.cn`, `cert.subject.on`, `cert.issuer.on` | Subject/issuer CN and org |
| `cert.alt` | SANs |
| `cert.serial`, `cert.hash` | Serial, SHA-1 fingerprint |
| `cert.notbefore`, `cert.notafter`, `cert.validfor` | Validity (days) |
| `cert.remainingDays`, `cert.curve`, `cert.publicAlgorithm` | Extras |
| `cert.cnt` | Certificates in the session (0 on TLS 1.3 without decryption) |

### Windows / lateral movement protocols

| Field | Meaning |
|---|---|
| `smb.fn` | SMB filename(s) |
| `smb.share`, `smb.domain`, `smb.user`, `smb.host`, `smb.os`, `smb.ver` | Share, domain, user, hostname, OS string, dialect |
| `smb.user`, `http.user` | NTLM usernames (over SMB, or NTLM-over-HTTP for proxies/WinRM) |
| `krb5.realm`, `krb5.cname`, `krb5.sname` | Kerberos realm / client / service principal |
| `protocols == dcerpc` | MS-RPC sessions (PsExec/WMI/service control); opnums are **not** extracted — use Wireshark `svcctl` on the exported pcap |
| `protocols == rdp`, `rdp.hostname`, `rdp.user` | RDP; hostname/user only when the initial request is cleartext (mostly it is TLS) |
| `ldap.authtype`, `ldap.bindname` | LDAP bind details |
| `socks.ip`, `socks.port`, `socks.host`, `socks.user` | SOCKS proxy targets |

### SSH, mail, misc

| Field | Meaning |
|---|---|
| `ssh.ver`, `ssh.key`, `ssh.hassh`, `ssh.hasshServer` | Client/server version strings, host key, HASSH fingerprints |
| `email.src`, `email.dst`, `email.subject`, `email.fn`, `email.md5`, `email.host`, `email.x-mailer` | SMTP metadata & attachment names/hashes |
| `dhcp.host`, `dhcp.mac`, `dhcp.type` | DHCP hostnames — map IP ↔ hostname over time |
| `quic.host`, `quic.ua`, `quic.ver` | QUIC (HTTP/3) SNI etc. |
| `oui.src`, `oui.dst` | NIC vendor from MAC |
| `suricata.signature`, `suricata.category`, `suricata.severity`, `suricata.signatureId`, `suricata.gid`, `suricata.action` | Suricata alerts attached to the session (suricata plugin) |
| `wise.*` / configured names | WISE enrichment fields (e.g. `ip.dst.threatfeed`, `tags == wise-*`) |
| `file` | pcap filename the session lives in |
| `payload8.src`/`.dst` | First 8 bytes of payload (hex) — quick protocol fingerprint |

!!! info "Field names drift between versions"
    Arkime renamed a number of fields around v3–v5 (e.g. `tls.sni` → `host.tls`, `dns.query.type` → `dns.qt` in newer builds). When a field errors, open **SPIView** and hover the field header — it shows the exact expression name for *your* version. Autocomplete in the search box is authoritative.

## Recipes

```text
# Everything from one internal host to the internet in the window
ip.src == 10.0.0.25 && ip.dst != 10.0.0.0/8 && ip.dst != 192.168.0.0/16 && ip.dst != 172.16.0.0/12

# TLS to a raw IP (no SNI) on 443
port.dst == 443 && protocols == tls && host.tls != EXISTS!

# Self-signed or fresh certificates
cert.validfor < 30 || cert.validfor > 3650
cert.subject.cn == "*Cobalt*" || cert.serial == 146473198

# Rare/odd user agents
http.user-agent == [python*, curl*, Go-http-client*, PowerShell*, "Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 6.1*"] 
http.user-agent != EXISTS! && protocols == http                          # HTTP with no UA at all

# Executables downloaded over HTTP (body sniffing)
http.bodymagic == application/x-dosexec || http.bodymagic == application/x-msdownload

# POST to raw-IP hosts
http.method == POST && host.http == /^\d+\.\d+\.\d+\.\d+$/

# DNS tunnelling candidates
protocols == dns && (dns.qt == TXT || dns.qt == NULL) && ip.dst != 10.0.0.53
host.dns == /^[a-z0-9]{30,}\./
databytes.src > 100000 && protocols == dns                                # DNS sessions with lots of client payload

# Uploads: client sent far more than it received
databytes.src > 50000000 && databytes.dst < 1000000 && ip.dst != 10.0.0.0/8

# Long-lived connections (ms) — 1 hour
session.length > 3600000

# Lateral movement protocols internal → internal
ip.src == 10.0.0.0/8 && ip.dst == 10.0.0.0/8 && port.dst == [445, 135, 139, 3389, 5985, 5986, 22]
protocols == smb && smb.fn == [*.exe, *.dll, *.ps1, *.bat, *PSEXESVC*]
protocols == smb && smb.share == [*ADMIN$*, *C$*, *IPC$*]
protocols == krb5 && krb5.sname != *krbtgt*                              # service tickets for non-TGT SPNs (Kerberoast-ish); refine in SPIView

# Scanning: one source, many destinations, tiny sessions — best seen in SPIGraph on ip.dst, but as expression:
ip.src == 10.0.0.66 && packets <= 3 && bytes < 300

# Suricata-alerted sessions, high severity, external destinations
suricata.severity == 1 && ip.dst != 10.0.0.0/8
suricata.signature == "*Cobalt Strike*" || suricata.signature == "*Meterpreter*"

# Tagged by a Hunt / WISE / your import
tags == hunt-mimikatz-string || tags == case01 || tags == wise-badip

# Pivot on Community ID from a Zeek uid you already have
communityId == "1:LQU9qZlK+B5F3KDmev6m5PMibrg="

# SSH client fingerprint (tools have distinct HASSH)
protocols == ssh && ssh.ver == [*libssh*, *paramiko*, *Go*]                # scripted SSH clients; compare ssh.hassh in SPIView
```

## URL & API tricks

```text
# Deep-link a search (share with a colleague / paste in a report)
https://arkime.example/sessions?expression=ip.dst%3D%3D203.0.113.7&date=-24&startTime=...&stopTime=...

# API: same expression, JSON out — great for scripting hunts
curl -s -u user:pass 'https://arkime.example/api/sessions?date=-24&expression=tls.ja3%3D%3D<hash>&length=1000&fields=firstPacket,source.ip,destination.ip,destination.port,http.host,tls.ja3' | jq .

# API: download pcap for an expression (whole result set!) — be careful with size
curl -s -u user:pass 'https://arkime.example/api/sessions/pcap?date=-1&expression=ip.dst%3D%3D203.0.113.7' -o c2.pcap

# API: unique values of a field (like SPIView export)
curl -s -u user:pass 'https://arkime.example/api/unique?date=-24&expression=protocols%3D%3Dhttp&field=http.user-agent&counts=1'
```

`date=-1` = last hour, `-24` = last day, `-168` = week; `date=-1` with explicit `startTime`/`stopTime` (epoch s) for exact windows. Use **Cron Queries** to run any expression on a schedule and **tag** matching sessions or fire a webhook — that is your home-grown alerting.

## References

- [Arkime — Search expressions & operators](https://arkime.com/settings#search-expressions) (also **Help → Fields** inside the viewer lists every field for your version)
- [Arkime API v3](https://arkime.com/apiv3)
- Related: [Zeek logs](../zeek/index.md) · [Beaconing & C2](../beaconing-c2.md) · [Wireshark & tshark](../wireshark-tshark.md)

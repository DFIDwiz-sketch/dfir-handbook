---
title: Dashboard 1 — Traffic Overview and Baselining
tags:
  - splunk
  - zeek
  - dashboard
  - baselining
---

# Dashboard 1 — Traffic Overview and Baselining { #overview-dashboard }

<div class="dfir-meta" markdown>
**Category:** Splunk · **Dashboard:** `zeek_traffic_overview.xml` (57 panels) · **Last updated:** 2026-11-26
</div>

!!! abstract "What this dashboard does"
    **Sections A–C are baselining** — capture window, log types, internal PCs and servers, names, users and OS first. **Sections D–I look for what does not fit** — external traffic, beacons, DNS, HTTP, TLS certificates, files, alerts. **Section J** lists everything one host did in time order; click a row to open every Zeek record of that connection (uid).

!!! tip "How to read this page"
    Each panel follows **purpose → query → line-by-line notes → example result → how to read it**. Queries are written to paste straight into the Search app with `index=zeek` and `pcap_case="<case>"` (replace `<case>`). Inside the dashboard those parts are tokens (`$idx$`, `$case$`, the Host IP filter). Example results are **made-up illustration values** (lab range 10.0.0.0/24, external addresses from the documentation ranges 198.51.100.x and 203.0.113.x).

## Section map { #map }

| Section | Question | Panels |
|---|---|---|
| **A** Capture at a glance | When, and how big? | 10 numbers |
| **B** What is in it | Which logs, services, ports, connection states? | log types, 3 pies, time chart, port table |
| **C** Who is who | Internal PCs, names, users, MACs, OS, server roles | 4 tables |
| **D** External traffic | With whom, how much, odd ports, beacons, exfiltration | 5 tables, bar, time chart |
| **E** DNS | Names looked up, rare names, odd names | 2 pies, 4 tables |
| **F** HTTP | Hosts, User-Agents, POSTs, downloaded programs, redirect chain | 3 pies, 6 tables |
| **G** TLS | SNI, versions, odd ports, self-signed certificates | pie, 3 tables |
| **H** Files | Which files moved, hashes, Windows programs | 2 pies, 2 tables |
| **I** Alerts and oddities | Snort, Zeek weird, Zeek notice | bar, 3 tables |
| **J** Activity timeline | Everything a host did; every record of one connection | 2 tables |

## Before the queries — shared pieces { #common }

### Dashboard queries vs queries on this page { #tokens }

| This page | In the dashboard | Meaning |
|---|---|---|
| `index=zeek` | `index=$idx$` | Zeek index box |
| `pcap_case="<case>"` | `$case$` | Case dropdown (`*` for All) |
| (none) | `(id_orig_h="$ip$" OR id_resp_h="$ip$")` | Host IP box (default `*` = all) |
| `span=1m` | `span=$span$` | Timeline bucket box |
| `IPC$`, `"%$"` | `IPC$$`, `"%$$"` | A literal `$` inside XML ([basics 4](dashboard-basics.md#dollar-cdata)) |

### Internal vs external { #scope }

Many panels decide whether an IP is **internal or external** with one line:

```spl
| eval dst_scope=case(match(id_resp_h,"^(22[4-9]|23[0-9]|255)\.|\.255$|^ff"),"multicast/broadcast", match(id_resp_h,"^(10\.|192\.168\.|172\.(1[6-9]|2[0-9]|3[01])\.|127\.|169\.254\.|0\.0\.0\.0$|fe80:|fc|fd)"),"internal", true(),"external")
```

- `eval new=case(cond1,val1, cond2,val2, true(),default)` — the value of the **first condition that matches**; `true()` = everything else.
- `match(field,"regex")` — true when the field matches.
- First condition — `224–239.x` (multicast), `255.x`, ending in `.255` (broadcast), `ff..` (IPv6 multicast): addresses that go to **many hosts**.
- Second — private ranges `10.`, `192.168.`, `172.16–31.`, plus `127.` (self), `169.254.` (auto address after DHCP failure), `0.0.0.0` (DHCP request), `fe80:`/`fc`/`fd` (internal IPv6).
- `\.` — in regex `.` means "any character", so a real dot is `\.`. `^` = start, `$` = end.
- The sender side (`id_orig_h`) gets `src_scope` the same way.

### Zeek conn.log fields { #conn-fields }

| Field | Meaning |
|---|---|
| `id_orig_h` / `id_orig_p` | IP / port of the side that **started** the connection (originator) |
| `id_resp_h` / `id_resp_p` | IP / port of the side that **answered** (responder) |
| `proto` | `tcp`, `udp`, `icmp` |
| `service` | Protocol Zeek recognised (`dns`, `http`, `ssl`, `smb` …); empty = not recognised |
| `orig_bytes` / `resp_bytes` | **Payload** bytes each side sent |
| `duration` | Seconds |
| `conn_state` | How the connection ended ([B3](#b3)) |
| `uid` | Connection tag that links to other logs |

---

## A. Capture at a glance { #a-glance }

**Purpose:** know the **size and time window** before anything else; every conclusion is about this window.

A1–A8 share one base search, **`b_kpi`**.

```spl
index=zeek sourcetype=zeek:conn pcap_case="<case>"
| eval src_scope=case(match(id_orig_h,"^(22[4-9]|23[0-9]|255)\.|\.255$|^ff"),"multicast/broadcast", match(id_orig_h,"^(10\.|192\.168\.|172\.(1[6-9]|2[0-9]|3[01])\.|127\.|169\.254\.|0\.0\.0\.0$|fe80:|fc|fd)"),"internal", true(),"external")
| eval dst_scope=case(match(id_resp_h,"^(22[4-9]|23[0-9]|255)\.|\.255$|^ff"),"multicast/broadcast", match(id_resp_h,"^(10\.|192\.168\.|172\.(1[6-9]|2[0-9]|3[01])\.|127\.|169\.254\.|0\.0\.0\.0$|fe80:|fc|fd)"),"internal", true(),"external")
| stats min(ts) as first max(ts) as last count as conns dc(eval(if(src_scope="internal",id_orig_h,null()))) as int_hosts dc(eval(if(dst_scope="external",id_resp_h,null()))) as ext_ips sum(eval(if(dst_scope="external",orig_bytes,0))) as ext_out sum(eval(if(dst_scope="external",resp_bytes,0))) as ext_in
```

- Line 1: connection logs only; the dashboard adds the Case and Host IP filters.
- Lines 2–3: [internal/external](#scope) — `src_scope` for the sender, `dst_scope` for the receiver.
- Line 4 `stats` (one summary row):
    - `min(ts) as first`, `max(ts) as last` — earliest and latest time.
    - `count as conns` — connections.
    - `dc(eval(if(src_scope="internal",id_orig_h,null()))) as int_hosts` — `dc()` = **distinct count**; `eval(if(cond,value,null()))` yields a value only when the condition holds → **internal IPs that started connections**.
    - `sum(eval(if(dst_scope="external",orig_bytes,0))) as ext_out` — bytes **sent** outside; received bytes are `ext_in`.

```text
first        last         conns  int_hosts  ext_ips  ext_out   ext_in       ← example result
1768870803   1768873375   1840   3          41       918233    22610004
```

Each number panel adds a **post-process** that picks one cell.

| Panel | Post-process | How to read it |
|---|---|---|
| A1 First event | `| eval v=strftime(first,"%Y-%m-%d %H:%M:%S") | fields v` | Capture start; compare with Snort/Arkime |
| A2 Last event | same with `last` | Capture end; nothing later is visible |
| A3 Duration | `| eval v=round((last-first)/60,1)` | Minutes. 30 min → Timeline bucket `1m`; hours → `5m`+ |
| A4 Connections | `| fields conns` | Total connections |
| A5 Internal hosts | `| fields int_hosts` | Internal IPs that **started** connections; 1 = a one-PC capture |
| A6 External IPs | `| fields ext_ips` | Browsing gives tens to hundreds; beacon-only traffic a handful |
| A7 MB sent | `| eval v=round(ext_out/1024/1024,2)` | Sent outside. **More than received = possible exfiltration** |
| A8 MB received | same with `ext_in` | Usually 10× or more what was sent |
| A9 Distinct names | `| stats count as v` on base `b_dnsq` | Names looked up in DNS ([E](#e-dns)) |
| A10 Snort alerts | own search (below) | Turns **red** when not 0 |

- `fields v` — keep only `v`; a number panel shows the first cell large.
- `round(x,1)` — one decimal. `/1024/1024` — bytes → MB.

```spl
index=snort sourcetype=snort:alert pcap_case="<case>"
| stats count as v
```

- `sourcetype=snort:alert` — where pcapbox puts Snort alerts. The dashboard adds `(src_ip="$ip$" OR dest_ip="$ip$")`.

---

## B. What is in the capture { #b-contents }

### B1. Zeek log types { #b1 }

```spl
index=zeek pcap_case="<case>"
| stats count by sourcetype
| sort - count
```

- No sourcetype → **every log type of the case**. IP field names differ per log, so the Host IP filter is not applied.

```text
sourcetype          count      ← example result
zeek:conn           1840
zeek:dns            702
zeek:ssl            311
zeek:http           188
zeek:files          160
zeek:dce_rpc        96
zeek:kerberos       44
zeek:smb_mapping    12
zeek:smb_files      9
zeek:ntlm           3
```

**How to read it — logs present and absent are both clues.**

| If you see | Meaning |
|---|---|
| `kerberos`, `ldap`, `dce_rpc`, `smb_*`, `ntlm` | Windows domain (AD) PCs; user and computer names are findable → [Dashboard 2](smb-dashboard.md) |
| `dhcp` | A PC got its IP during the capture; name and MAC directly (C4) |
| `pe` | Zeek saw a **Windows program (EXE/DLL)** in the traffic (H4) |
| `smtp`, `ftp` | Mail / FTP — clear text, content visible |
| `weird`, `notice` | Rule-breaking traffic / Zeek warnings (section I) |
| no `http` | All web is HTTPS; judge by SNI and certificates |

### B2. Connections by service { #b2 }

```spl
index=zeek sourcetype=zeek:conn pcap_case="<case>"
| fillnull value="(not recognised)" service
| stats count by service
| sort - count
```

- `fillnull value="(not recognised)" service` — keep connections with no service instead of dropping them.
- `stats count by service` — connections per service.

**How to read it:** a large `(not recognised)` share means protocols Zeek doesn't know (custom C2, encrypted tunnels) or connections with no data (`S0`). Check the ports in B6 and D3. Values like `smb,gssapi,ntlm` mean **several protocols in one connection**.

### B3. Connection states { #b3 }

```spl
index=zeek sourcetype=zeek:conn pcap_case="<case>"
| eval state=case(conn_state="SF","SF - opened and closed normally", conn_state="S0","S0 - no reply", conn_state="REJ","REJ - rejected", conn_state="S1","S1 - open, never closed", conn_state="S2","S2 - client closed, no server reply", conn_state="S3","S3 - server closed, no client reply", conn_state="RSTO","RSTO - client sent reset", conn_state="RSTR","RSTR - server sent reset", conn_state="RSTOS0","RSTOS0 - SYN then reset, no reply", conn_state="RSTRH","RSTRH - server SYN-ACK then reset", conn_state="SH","SH - SYN then FIN, no reply", conn_state="SHR","SHR - server SYN-ACK and FIN only", conn_state="OTH","OTH - no SYN seen (mid-stream)", true(), conn_state)
| stats count by state
| sort - count
```

- `eval state=case(conn_state="SF","SF - ...", ...)` — attach a **meaning** to each short code so the pie reads directly.

| Code | Meaning | Many of them means |
|---|---|---|
| `SF` | Opened and closed normally | normal |
| `S0` | Attempt, **no reply** | dead C2, scanning, blocked port |
| `REJ` | Rejected (RST) | closed-port scan, blocked C2 |
| `S1` | Open, never closed | long connection running past capture end |
| `RSTO` / `RSTR` | Client / server reset after opening | app-dependent, often normal |
| `SH`, `RSTOS0`, `RSTRH`, `SHR` | Odd half-open shapes | scans, partial capture |
| `OTH` | No SYN seen (mid-stream) | capture started mid-conversation |

UDP uses `SF` (both sides spoke) and `S0` (no reply) too.

### B4. Transport protocol · B5. Connections over time { #b4 }

```spl
index=zeek sourcetype=zeek:conn pcap_case="<case>"
| stats count by proto
```

```spl
index=zeek sourcetype=zeek:conn pcap_case="<case>"
| fillnull value="(not recognised)" service
| eval _time=ts
| timechart span=1m limit=10 useother=t count by service
```

- `eval _time=ts` — chart on Zeek's time ([basics 7](dashboard-basics.md#timechart)).
- `timechart span=1m limit=10 useother=t count by service` — per minute, per service. The in-panel **Split by** switches `service` for source IP, destination IP, port or state.

**How to read it:** people's PCs come in **bursts** (page loads). **Low bars at a steady interval** all the way through are beacon candidates → [D4](#d4). Switch Split by to **Destination IP** to see which destination it is.

### B6. Destination ports { #b6 }

```spl
index=zeek sourcetype=zeek:conn pcap_case="<case>"
| eval dst_scope=case(match(id_resp_h,"^(22[4-9]|23[0-9]|255)\.|\.255$|^ff"),"multicast/broadcast", match(id_resp_h,"^(10\.|192\.168\.|172\.(1[6-9]|2[0-9]|3[01])\.|127\.|169\.254\.|0\.0\.0\.0$|fe80:|fc|fd)"),"internal", true(),"external")
| fillnull value="-" service
| stats count as conns dc(id_orig_h) as clients dc(id_resp_h) as servers values(service) as service values(dst_scope) as scope by id_resp_p proto
| sort - conns
```

- `values(service) as service` — service names seen on that port. `values()` = distinct value list.
- `values(dst_scope) as scope` — internal or external.

```text
id_resp_p  proto  conns  clients  servers  service   scope        ← example result
53         udp    702    3        1        dns       internal
443        tcp    305    3        38       ssl       external
80         tcp    121    3        9        http      external
445        tcp    18     2        2        smb       internal
4143       tcp    9      1        1        -         external
```

**How to read it:** after the well-known ports (53, 80, 443, 445, 88, 389, 123), look at **unfamiliar** ones. A port like `4143` above — no service recognised (`-`), going external — gets a closer look in D3. Port meanings: [Well-known ports](../../../basics/well-known-ports.md).

---

## C. Who is who { #c-identity }

### C1. Internal hosts that start connections { #c1 }

```spl
index=zeek sourcetype=zeek:conn pcap_case="<case>"
| eval src_scope=case(match(id_orig_h,"^(22[4-9]|23[0-9]|255)\.|\.255$|^ff"),"multicast/broadcast", match(id_orig_h,"^(10\.|192\.168\.|172\.(1[6-9]|2[0-9]|3[01])\.|127\.|169\.254\.|0\.0\.0\.0$|fe80:|fc|fd)"),"internal", true(),"external")
| where src_scope="internal"
| stats count as sessions dc(id_resp_h) as destinations dc(id_resp_p) as ports sum(orig_bytes) as sent sum(resp_bytes) as received min(ts) as first max(ts) as last values(orig_l2_addr) as mac by id_orig_h
| eval sent_KB=round(sent/1024,1), received_KB=round(received/1024,1)
| eval first=strftime(first,"%Y-%m-%d %H:%M:%S"), last=strftime(last,"%Y-%m-%d %H:%M:%S")
| table id_orig_h mac sessions destinations ports sent_KB received_KB first last
| sort - sessions
```

- `where src_scope="internal"` — connections **started** inside.
- `dc(id_resp_h) as destinations`, `dc(id_resp_p) as ports` — distinct destinations and ports.
- `values(orig_l2_addr) as mac` — sender MAC (pcapbox's Zeek `mac-logging` adds it).
- `eval sent_KB=round(sent/1024,1)` — bytes → KB.
- `table fields...` — columns and order. `sort - sessions` — most connections first.

```text
id_orig_h   mac                sessions  destinations  ports  sent_KB  received_KB  first                last          ← example result
10.0.0.101  00:0c:29:aa:01:01  1210      44            9      612.4    20811.0      2026-01-20 01:00:03  2026-01-20 01:42:55
10.0.0.102  00:0c:29:aa:01:02  598       12            6      288.1    1210.6       2026-01-20 01:00:09  2026-01-20 01:42:50
10.0.0.10   00:0c:29:aa:00:10  32        3             2      4.2      3.0          2026-01-20 01:02:11  2026-01-20 01:40:02
```

**How to read it:** find the **main character** (the PC with most connections) first. Dozens of destinations = a person browsing; only 1–3 = more likely a program (beacon). A server like the DC (10.0.0.10) starting a few connections is normal (DNS forwarding, time sync).

### C2. Host identity — name, domain, users, MAC, OS hint { #c2 }

Windows PCs **say their own name** in several places; this panel collects four logs at once.

```spl
index=zeek pcap_case="<case>" (sourcetype=zeek:dhcp OR sourcetype=zeek:ntlm OR sourcetype=zeek:kerberos OR sourcetype=zeek:http)
| eval ip=if(sourcetype="zeek:dhcp", coalesce(assigned_addr, client_addr, requested_addr), id_orig_h)
| eval kc=mvindex(split(client,"/"),0), realm=mvindex(split(client,"/"),1)
| eval hostname_seen=case(sourcetype="zeek:dhcp", host_name, sourcetype="zeek:ntlm", hostname, sourcetype="zeek:kerberos" AND like(kc,"%$"), upper(rtrim(kc,"$")))
| eval user_seen=case(sourcetype="zeek:ntlm" AND len(username)>0 AND NOT like(username,"%$"), username."@".coalesce(domainname,"?"), sourcetype="zeek:kerberos" AND len(kc)>0 AND NOT like(kc,"%$"), kc."@".coalesce(realm,"?"))
| eval domain_seen=case(sourcetype="zeek:dhcp", domain, sourcetype="zeek:ntlm", domainname, sourcetype="zeek:kerberos", realm)
| eval mac_seen=if(sourcetype="zeek:dhcp", mac, null())
| eval ua=if(sourcetype="zeek:http", user_agent, null())
| eval os_hint=case(match(ua,"Windows NT 10\.0"),"Windows 10/11", match(ua,"Windows NT 6\.3"),"Windows 8.1", match(ua,"Windows NT 6\.2"),"Windows 8", match(ua,"Windows NT 6\.1"),"Windows 7", match(ua,"Windows NT 6\.0"),"Windows Vista", match(ua,"Windows NT 5\.1"),"Windows XP", match(ua,"iPhone|iPad"),"iOS", match(ua,"Android"),"Android", match(ua,"Macintosh|Mac OS X"),"macOS", match(ua,"Linux"),"Linux")
| where match(ip,"^(10\.|192\.168\.|172\.(1[6-9]|2[0-9]|3[01])\.)")
| stats values(hostname_seen) as hostname values(domain_seen) as domain values(user_seen) as users values(mac_seen) as mac values(os_hint) as os_hint dc(ua) as user_agents values(sourcetype) as seen_in by ip
| eval seen_in=replace(mvjoin(seen_in," "),"zeek:","")
| sort ip
```

- Line 1: DHCP, NTLM, Kerberos and HTTP together (`OR`).
- Line 2 `ip=if(sourcetype="zeek:dhcp", coalesce(assigned_addr, client_addr, requested_addr), id_orig_h)` — DHCP uses the address handed out, the others the sender IP. `coalesce(a,b,c)` = **first non-empty value**.
- Line 3: Kerberos `client` is `account/REALM`; `split(client,"/")` cuts it, `mvindex(list,0)` = account, `1` = realm.
- Line 4 `hostname_seen` — DHCP `host_name`, NTLM `hostname`, and a Kerberos account **ending in `$` is a computer account**: strip the `$` (`rtrim(kc,"$")`) and upper-case it.
- Line 5 `user_seen` — NTLM/Kerberos accounts not ending in `$` = **people**, as `user@DOMAIN`. `len(username)>0` = only when a name is actually there.
- Lines 8–9 `os_hint` — User-Agent `Windows NT x.y` → name: `10.0` = Windows 10/11, `6.3` = 8.1, `6.2` = 8, `6.1` = 7, `6.0` = Vista, `5.1` = XP.
- Line 10 `where match(ip,...)` — private IPs only.
- Line 11 `stats values(...) by ip` — all values seen, per IP.
- Line 12 `seen_in` — which logs mentioned it (`dhcp ntlm kerberos http`).

```text
ip          hostname  domain    users        mac                os_hint     user_agents  seen_in              ← example result
10.0.0.10   DC01      LAB                                                   0            kerberos
10.0.0.101  PC-01     LAB       alice@LAB    00:0c:29:aa:01:01  Windows 10  4            dhcp http kerberos ntlm
10.0.0.102  PC-02     LAB       bob@LAB      00:0c:29:aa:01:02  Windows 10  2            dhcp http kerberos
```

**How to read it:** a name or user **agreeing across several logs** is solid. Two or more users on one IP = shared PC, or someone using other credentials (SMB dashboard [F7](smb-dashboard.md#f-ntlm)). A jump in `user_agents` means programs other than the browser went to the web → F5.

### C3. Internal servers and roles { #c3 }

```spl
index=zeek sourcetype=zeek:conn pcap_case="<case>"
| eval dst_scope=case(match(id_resp_h,"^(22[4-9]|23[0-9]|255)\.|\.255$|^ff"),"multicast/broadcast", match(id_resp_h,"^(10\.|192\.168\.|172\.(1[6-9]|2[0-9]|3[01])\.|127\.|169\.254\.|0\.0\.0\.0$|fe80:|fc|fd)"),"internal", true(),"external")
| where dst_scope="internal" AND NOT (conn_state="S0" OR conn_state="REJ")
| eval role=case(id_resp_p=53,"DNS", id_resp_p=67,"DHCP server", id_resp_p=88,"Kerberos - domain controller", id_resp_p=389,"LDAP - domain controller", id_resp_p=636,"LDAPS - domain controller", id_resp_p=3268,"Global Catalog - domain controller", id_resp_p=464,"Kerberos password change - DC", id_resp_p=135,"RPC endpoint mapper", id_resp_p=445,"SMB file sharing", id_resp_p=139,"NetBIOS session (old SMB)", id_resp_p=137,"NetBIOS name", id_resp_p=138,"NetBIOS datagram", id_resp_p=123,"NTP time", id_resp_p=80,"Web (HTTP)", id_resp_p=443,"Web (HTTPS)", id_resp_p=8080,"Web proxy or alt HTTP", id_resp_p=3128,"Web proxy", id_resp_p=25,"Mail (SMTP)", id_resp_p=587,"Mail submission", id_resp_p=110,"Mail (POP3)", id_resp_p=143,"Mail (IMAP)", id_resp_p=3389,"Remote Desktop (RDP)", id_resp_p=5985,"WinRM (HTTP)", id_resp_p=5986,"WinRM (HTTPS)", id_resp_p=22,"SSH", id_resp_p=21,"FTP", id_resp_p=1433,"MS SQL", id_resp_p=9100,"Printer (RAW)", id_resp_p=5355,"LLMNR name lookup", id_resp_p=1900,"SSDP discovery", id_resp_p=5353,"mDNS", true(),"port ".id_resp_p."/".proto)
| stats dc(id_orig_h) as clients count as conns values(role) as roles by id_resp_h
| eval roles=mvindex(roles,0,11)
| sort - clients
```

- `where dst_scope="internal" AND NOT (conn_state="S0" OR conn_state="REJ")` — internal destinations that **answered**; no answer, no server.
- `eval role=case(id_resp_p=53,"DNS", id_resp_p=88,"Kerberos - domain controller", ...)` — role from the port; unknown ports become `port N/proto`.
- `stats dc(id_orig_h) as clients count as conns values(role) as roles by id_resp_h` — per server: clients, connections, roles.
- `mvindex(roles,0,11)` — at most 12 roles.

```text
id_resp_h   clients  conns  roles                                                                    ← example result
10.0.0.10   3        410    DNS, Kerberos - domain controller, LDAP - domain controller, NTP time, RPC endpoint mapper, SMB file sharing, port 49667/tcp
10.0.0.1    3        12     DHCP server
10.0.0.102  1        9      SMB file sharing, RPC endpoint mapper
```

**How to read it:** **88 + 389 + 445 + 53** together = **domain controller**. The gateway (often `.1` or `.254`) may also do DHCP/DNS. **A PC (10.0.0.102) looking like an SMB/RPC server** means another PC connected to it — a lateral movement candidate → [Dashboard 2](smb-dashboard.md).

### C4. DHCP { #c4 }

```spl
index=zeek sourcetype=zeek:dhcp pcap_case="<case>"
| sort 0 ts
| eval time=strftime(ts,"%Y-%m-%d %H:%M:%S"), msg_types=mvjoin(msg_types," ")
| table time client_addr requested_addr assigned_addr mac host_name client_fqdn domain server_addr msg_types
```

- `sort 0 ts` — time order; `0` = no row limit.
- `mvjoin(msg_types," ")` — multi-values as one string; the DHCP sequence (`DISCOVER OFFER REQUEST ACK`) shows.

**How to read it:** `host_name` is the PC name; the first six hex digits of `mac` are the vendor (OUI) — `00:0c:29` / `00:50:56` = VMware, `08:00:27` = VirtualBox. No DHCP log = the PC already had its IP when the capture began (use NTLM/Kerberos in C2).

---

## D. External traffic { #d-external }

D1 and D2 share the base **`b_ext`**.

```spl
index=zeek pcap_case="<case>" (sourcetype=zeek:conn OR sourcetype=zeek:ssl OR sourcetype=zeek:http)
| eval dst_scope=case(match(id_resp_h,"^(22[4-9]|23[0-9]|255)\.|\.255$|^ff"),"multicast/broadcast", match(id_resp_h,"^(10\.|192\.168\.|172\.(1[6-9]|2[0-9]|3[01])\.|127\.|169\.254\.|0\.0\.0\.0$|fe80:|fc|fd)"),"internal", true(),"external")
| where dst_scope="external"
| eval name=case(sourcetype="zeek:ssl", server_name, sourcetype="zeek:http", mvdedup(host))
| stats count(eval(sourcetype="zeek:conn")) as conns dc(id_orig_h) as clients values(id_resp_p) as ports values(name) as names sum(orig_bytes) as out sum(resp_bytes) as in min(ts) as first max(ts) as last by id_resp_h
| eval out_KB=round(out/1024,1), in_KB=round(in/1024,1), names=mvindex(names,0,4)
```

- Line 1: conn, ssl and http together — counts and bytes from conn, **names** from ssl (SNI) and http (Host).
- Line 3: external destinations only.
- Line 4 `name=case(sourcetype="zeek:ssl", server_name, sourcetype="zeek:http", mvdedup(host))` — SNI for TLS, Host header for HTTP. `mvdedup()` removes duplicate values (pcapbox can store `host` twice).
- Line 5 `count(eval(sourcetype="zeek:conn")) as conns` — count **conn rows only**; counting ssl/http rows too would inflate it.

### D1. External destinations — most connections first { #d1 }

```spl
| eval first=strftime(first,"%Y-%m-%d %H:%M:%S"), last=strftime(last,"%Y-%m-%d %H:%M:%S")
| table id_resp_h names ports conns clients out_KB in_KB first last
| sort - conns
```

```text
id_resp_h      names                                 ports    conns  clients  out_KB  in_KB    first                last          ← example result
203.0.113.20   cdn.example.com                       443      88     3        120.3   3401.2   2026-01-20 01:00:21  2026-01-20 01:41:10
198.51.100.7   update-check.example.net              443      36     1        18.9    2.1      2026-01-20 01:03:00  2026-01-20 01:42:30
198.51.100.44                                        4143     9      1        0       0        2026-01-20 01:07:12  2026-01-20 01:39:12
```

**How to read it:** the top is mostly CDNs, Microsoft, Google. Look for rows **shaped differently** — no name (third row), unusual port, many connections with small steady bytes (second row: beacon candidate → D4), `out_KB` larger than `in_KB` (exfiltration candidate → D5).

### D2. Rare external destinations { #d2 }

```spl
| where conns<=3 AND clients=1
| sort first
| eval first=strftime(first,"%Y-%m-%d %H:%M:%S"), last=strftime(last,"%Y-%m-%d %H:%M:%S")
| table first id_resp_h names ports conns out_KB in_KB
```

- `where conns<=3 AND clients=1` — 3 connections or fewer, one PC. Malware download servers are often **used once**.
- `sort first` — first-seen order, good for following the story.

### D3. External traffic on unusual ports { #d3 }

```spl
index=zeek sourcetype=zeek:conn pcap_case="<case>"
| eval dst_scope=case(match(id_resp_h,"^(22[4-9]|23[0-9]|255)\.|\.255$|^ff"),"multicast/broadcast", match(id_resp_h,"^(10\.|192\.168\.|172\.(1[6-9]|2[0-9]|3[01])\.|127\.|169\.254\.|0\.0\.0\.0$|fe80:|fc|fd)"),"internal", true(),"external")
| where dst_scope="external" AND NOT (id_resp_p=80 OR id_resp_p=443 OR id_resp_p=53 OR id_resp_p=123)
| fillnull value="-" service
| stats count as conns values(conn_state) as states sum(orig_bytes) as out sum(resp_bytes) as in min(ts) as first by id_orig_h id_resp_h id_resp_p proto service
| eval first=strftime(first,"%Y-%m-%d %H:%M:%S")
| sort - conns
```

- `NOT (id_resp_p=80 OR id_resp_p=443 OR id_resp_p=53 OR id_resp_p=123)` — drop web, DNS, NTP. `NOT (...)` = **not** the bracketed condition.
- `values(conn_state) as states` — only `S0`/`REJ` = **repeated failures** — a dead or blocked C2.

### D4. Beacon candidates — regular repeated connections { #d4 }

Malware asks its C2 server "any orders?" at a **steady interval** (a beacon); human browsing is irregular. This panel puts a number on **how regular** the intervals are.

```spl
index=zeek sourcetype=zeek:conn pcap_case="<case>"
| eval dst_scope=case(match(id_resp_h,"^(22[4-9]|23[0-9]|255)\.|\.255$|^ff"),"multicast/broadcast", match(id_resp_h,"^(10\.|192\.168\.|172\.(1[6-9]|2[0-9]|3[01])\.|127\.|169\.254\.|0\.0\.0\.0$|fe80:|fc|fd)"),"internal", true(),"external")
| where dst_scope="external"
| sort 0 ts
| streamstats current=f last(ts) as prev_ts by id_orig_h id_resp_h id_resp_p
| eval gap=ts-prev_ts
| stats count as conns avg(gap) as avg_gap stdev(gap) as sd_gap avg(orig_bytes) as avg_out min(ts) as first max(ts) as last by id_orig_h id_resp_h id_resp_p
| where conns>=5
| eval jitter=round(sd_gap/avg_gap,2), avg_gap=round(avg_gap,1), sd_gap=round(sd_gap,1), avg_out=round(avg_out,0), span_min=round((last-first)/60,1)
| sort jitter
| table id_orig_h id_resp_h id_resp_p conns avg_gap sd_gap jitter avg_out span_min
```

- Line 4 `sort 0 ts` — sort by time first; the next command looks at "the previous row".
- Line 5 `streamstats current=f last(ts) as prev_ts by id_orig_h id_resp_h id_resp_p` — within the same **source IP → destination IP:port** group, take the **previous connection's time** as `prev_ts`. `current=f` = exclude the current row.
- Line 6 `gap=ts-prev_ts` — seconds since the previous connection.
- Line 7 `stats count ... avg(gap) ... stdev(gap) ... by ...` — per group: connections, **average gap**, **standard deviation** (how much the gap wobbles).
- Line 8 `where conns>=5` — repeated at least 5 times.
- Line 9 `jitter=round(sd_gap/avg_gap,2)` — wobble ÷ average; **close to 0 = clockwork**. `span_min` = minutes from first to last.
- Line 10 `sort jitter` — most regular first.

```text
id_orig_h   id_resp_h     id_resp_p  conns  avg_gap  sd_gap  jitter  avg_out  span_min     ← example result
10.0.0.101  198.51.100.7  443        36     60.2     1.8     0.03    523      35.1
10.0.0.101  198.51.100.44 4143       9      240.0    0.9     0.00    0        32.0
10.0.0.101  203.0.113.20  443        88     27.5     61.4    2.23    1367     40.8
```

**How to read it:** row 1 — every 60 s (±2 s) with similar size → **beacon-shaped**. Row 2 — exactly every 4 minutes, zero data → retrying a silent C2. Row 3 — jitter 2.23 → irregular human browsing. But update checks and mail refreshes are **regular and normal** too; confirm with the name (D1) and content (F, G). More: [Beaconing & C2](../../../network/beaconing-c2.md).

### D5. Most data sent outside { #d5 }

```spl
index=zeek sourcetype=zeek:conn pcap_case="<case>"
| eval dst_scope=case(match(id_resp_h,"^(22[4-9]|23[0-9]|255)\.|\.255$|^ff"),"multicast/broadcast", match(id_resp_h,"^(10\.|192\.168\.|172\.(1[6-9]|2[0-9]|3[01])\.|127\.|169\.254\.|0\.0\.0\.0$|fe80:|fc|fd)"),"internal", true(),"external")
| where dst_scope="external"
| stats sum(orig_bytes) as out sum(resp_bytes) as in by id_orig_h id_resp_h
| sort - out
| head 10
| eval pair=id_orig_h." > ".id_resp_h, KB_sent=round(out/1024,1), KB_received=round(in/1024,1)
| table pair KB_sent KB_received
```

- `pair=id_orig_h." > ".id_resp_h` — one label for the bar. `head 10` — top 10.

**How to read it:** normal PCs receive ≫ send. A `KB_sent` bar **much longer** than `KB_received` is an upload — exfiltration, cloud backup or a file upload. Check the name (D1) and time.

### D6. Longest connections · D7. External connections over time { #d6 }

```spl
index=zeek sourcetype=zeek:conn pcap_case="<case>"
| where isnotnull(duration)
| sort - duration
| head 25
| eval time=strftime(ts,"%Y-%m-%d %H:%M:%S"), minutes=round(duration/60,1)
| table time id_orig_h id_resp_h id_resp_p proto service minutes orig_bytes resp_bytes conn_state uid
```

```spl
index=zeek sourcetype=zeek:conn pcap_case="<case>"
| eval dst_scope=case(match(id_resp_h,"^(22[4-9]|23[0-9]|255)\.|\.255$|^ff"),"multicast/broadcast", match(id_resp_h,"^(10\.|192\.168\.|172\.(1[6-9]|2[0-9]|3[01])\.|127\.|169\.254\.|0\.0\.0\.0$|fe80:|fc|fd)"),"internal", true(),"external")
| where dst_scope="external"
| eval _time=ts
| timechart span=1m limit=10 useother=t count by id_resp_h
```

- D6 `sort - duration | head 25` — the 25 longest; `minutes=round(duration/60,1)`.
- D7 — time chart per external destination (top 10).

**How to read it:** connections lasting tens of minutes with **few bytes** can be remote control (reverse shell, tunnel). Normal examples: messengers, video calls, Windows push notifications (443).

---

## E. DNS { #e-dns }

E4–E6 and A9 share the base **`b_dnsq`**.

```spl
index=zeek sourcetype=zeek:dns pcap_case="<case>"
| where isnotnull(query)
| eval q=lower(query)
| stats count as queries dc(id_orig_h) as clients values(id_orig_h) as srcs values(qtype_name) as types values(rcode_name) as rcodes values(answers) as answers min(ts) as first max(ts) as last by q
| eval answers=mvindex(answers,0,3)
```

- `where isnotnull(query)` — only rows with a name. `lower(query)` — `WPAD` and `wpad` become one.
- `stats ... by q` — per name: how often (`queries`), how many hosts (`clients`), who (`srcs`), types, response codes, answers, first and last time.
- `mvindex(answers,0,3)` — at most 4 answers.

### E1. Query types · E2. Response codes { #e1 }

```spl
index=zeek sourcetype=zeek:dns pcap_case="<case>"
| fillnull value="(none)" qtype_name
| stats count by qtype_name
| sort - count
```

```spl
index=zeek sourcetype=zeek:dns pcap_case="<case>"
| fillnull value="(no reply)" rcode_name
| stats count by rcode_name
| sort - count
```

| If you see | Meaning |
|---|---|
| `A`, `AAAA` | IPv4 / IPv6 address — most queries |
| `SRV` | Service lookup. `_ldap._tcp.dc._msdcs.<domain>` = **finding a DC** (normal for domain PCs) |
| `SOA` | Sent before a Windows PC **registers its own name** in DNS |
| `PTR` | IP → name |
| many `TXT`, `NULL` | DNS tunnel / C2 suspicion |
| many `NXDOMAIN` | Keeps asking for names that don't exist → DGA malware suspicion |

### E3. DNS servers used { #e3 }

```spl
index=zeek sourcetype=zeek:dns pcap_case="<case>"
| eval dst_scope=case(match(id_resp_h,"^(22[4-9]|23[0-9]|255)\.|\.255$|^ff"),"multicast/broadcast", match(id_resp_h,"^(10\.|192\.168\.|172\.(1[6-9]|2[0-9]|3[01])\.|127\.|169\.254\.|0\.0\.0\.0$|fe80:|fc|fd)"),"internal", true(),"external")
| stats count as queries dc(id_orig_h) as clients by id_resp_h id_resp_p dst_scope
| sort - queries
```

**How to read it:** domain PCs ask the DC. A PC asking an **external** resolver (e.g. `8.8.8.8`) directly bypasses company DNS — sometimes malware does this on purpose.

### E4. Rarest names · E5. Names in first-seen order { #e4 }

```spl
| sort queries, first
| head 100
| eval first=strftime(first,"%Y-%m-%d %H:%M:%S")
| table q queries clients types rcodes answers first
```

```spl
| sort first
| eval first=strftime(first,"%Y-%m-%d %H:%M:%S.%3N")
| table first q srcs queries types rcodes answers
```

- E4 `sort queries, first` — fewest queries first, ties by time. `head 100`.
- E5 `sort first` — **first-asked order**: follow the story through names — search → site → odd domain → …

```text
first                    q                          srcs        queries  types  rcodes    answers         ← E5 example result
2026-01-20 01:02:10.551  www.example.org            10.0.0.101  2        A      NOERROR   203.0.113.20
2026-01-20 01:02:12.004  cdn.example.com            10.0.0.101  6        A      NOERROR   203.0.113.20
2026-01-20 01:02:58.310  update-check.example.net   10.0.0.101  1        A      NOERROR   198.51.100.7
```

**How to read it:** malicious domains are usually **rare** (top of E4) and appear **right after** some moment (E5). In E5, look for first-time names just after a document opened or a download.

### E6. Odd names { #e6 }

```spl
| eval len=len(q), labels=mvcount(split(q,".")), t=mvjoin(types," "), r=mvjoin(rcodes," ")
| where len>=40 OR labels>=6 OR match(t,"TXT|NULL") OR match(r,"NXDOMAIN")
| sort - len
| eval first=strftime(first,"%Y-%m-%d %H:%M:%S")
| table q len labels queries types rcodes srcs first
```

- `len(q)` — name length. `mvcount(split(q,"."))` — number of labels.
- `where len>=40 OR labels>=6 OR match(t,"TXT|NULL") OR match(r,"NXDOMAIN")` — very long, many labels, TXT/NULL, or non-existent.

**How to read it:** many names with **long random strings** in front (`a8f3k2...x9.example.com`) suggest a DNS tunnel (data hidden in names). Normal exceptions: antivirus cloud lookups, long CDN names.

---

## F. HTTP { #f-http }

HTTP is the only web traffic whose **content is visible**. In pcapbox the `host` field = HTTP Host header.

### F1. Methods · F2. Status codes · F3. Response file types { #f1 }

```spl
index=zeek sourcetype=zeek:http pcap_case="<case>"
| fillnull value="(none)" method
| stats count by method
| sort - count
```

```spl
index=zeek sourcetype=zeek:http pcap_case="<case>"
| fillnull value="(no reply)" status_code
| stats count by status_code
| sort - count
```

```spl
index=zeek sourcetype=zeek:http pcap_case="<case>"
| eval mime=coalesce(mvindex(resp_mime_types,0),"(none)")
| stats count by mime
| sort - count
```

- F3 `mvindex(resp_mime_types,0)` — the response body type (Zeek detects it from the content); the first if several.

| If you see | Meaning |
|---|---|
| many `POST` | Client sends data — C2 check-ins, logins, uploads (F6) |
| `CONNECT` | HTTPS through a proxy |
| mostly `200` | Normal. `302`/`301` = redirect (→ F9), `404` = not found |
| `application/x-dosexec` | A **Windows program** came over HTTP → F7, H3 |

### F4. HTTP hosts · F5. User-Agents (rarest first) { #f4 }

```spl
index=zeek sourcetype=zeek:http pcap_case="<case>"
| eval h=mvdedup(host)
| stats count as requests dc(id_orig_h) as clients values(method) as methods dc(uri) as uris sum(response_body_len) as resp_bytes values(id_resp_h) as ips min(ts) as first by h
| eval resp_KB=round(resp_bytes/1024,1)
| eval first=strftime(first,"%Y-%m-%d %H:%M:%S")
| table h ips requests clients methods uris resp_KB first
| sort - requests
```

```spl
index=zeek sourcetype=zeek:http pcap_case="<case>"
| fillnull value="(none)" user_agent
| stats count as requests dc(id_orig_h) as clients values(id_orig_h) as srcs dc(host) as hosts min(ts) as first by user_agent
| eval first=strftime(first,"%Y-%m-%d %H:%M:%S")
| sort requests
| table user_agent requests clients srcs hosts first
```

- F4 `dc(uri) as uris` — distinct addresses opened on that host. `sum(response_body_len)` — body bytes received.
- F5 `sort requests` — **least-used User-Agent first**.

```text
user_agent                                                          requests  clients  srcs        hosts   ← F5 example result
Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 6.1; ...)             3         1        10.0.0.101  1
Microsoft-CryptoAPI/10.0                                            8         2        10.0.0.101  2
Mozilla/5.0 (Windows NT 10.0; Win64; x64) ... Chrome/120.0 ...      170       2        10.0.0.101  9
```

**How to read it:** a PC usually has 1–2 browser UAs. A **rare, old-looking** UA (`MSIE 7.0`) or a **non-browser** one (`WinHTTP`, `curl`, `PowerShell`, empty) appearing a few times on one host is likely a **script or malware**. Normal: `Microsoft-CryptoAPI` (certificate checks), `Windows-Update-Agent`, `Microsoft NCSI` (connectivity test).

### F6. POST requests { #f6 }

```spl
index=zeek sourcetype=zeek:http pcap_case="<case>" method=POST
| sort 0 ts
| eval time=strftime(ts,"%Y-%m-%d %H:%M:%S.%3N"), h=mvdedup(host)
| table time id_orig_h id_resp_h h uri request_body_len response_body_len status_code user_agent uid
```

- `method=POST` at the end of line 1 — POST requests only.
- `request_body_len` — bytes sent; `response_body_len` — bytes received.

**How to read it:** **repeated POSTs of similar size to one address** = C2 check-ins. The body isn't in Splunk; open it in **Arkime** by time or uid.

### F7. Programs, scripts, archives and documents over HTTP { #f7 }

```spl
index=zeek sourcetype=zeek:http pcap_case="<case>"
| eval mime=mvjoin(resp_mime_types,","), h=mvdedup(host)
| eval fname=lower(mvindex(split(mvindex(split(uri,"?"),0),"/"),-1)), ext=if(match(fname,"\."), mvindex(split(fname,"."),-1), "")
| where match(mime,"dosexec|x-msdownload|x-executable|java-archive|x-shockwave-flash|zip|x-rar|7z|octet-stream|hta|x-ms-shortcut|msi|msword|ms-excel|ms-powerpoint|officedocument|rtf|pdf") OR match(ext,"^(exe|dll|scr|ps1|vbs|hta|bat|cmd|msi|jar|zip|rar|7z|iso|lnk|doc|docm|xls|xlsm|ppt|pptm|rtf|swf)$")
| eval mismatch=if(match(mime,"dosexec") AND NOT match(ext,"^(exe|dll|scr|sys|msi|com)$"),"EXE under another name","")
| sort 0 ts
| eval time=strftime(ts,"%Y-%m-%d %H:%M:%S")
| table time id_orig_h id_resp_h h uri mime response_body_len mismatch status_code uid
```

- Line 3: the part of the URI before `?` (first piece of `split(uri,"?")`) → the last piece after `/` = **file name** → the last piece after `.` = **extension**.
- Line 4 `where match(mime,"dosexec|...") OR match(ext,"^(exe|dll|...)$")` — program/archive/document type, or such an extension.
- Line 5 `mismatch` — EXE content (`dosexec`) under a non-EXE name → **disguised program** (`.gif`, `.jpg`); shown red.

**How to read it:** for each row note **where (h, uri), who (id_orig_h), when**, then find its **hash** in H3.

### F8. HTTP straight to an IP, or without a Host header { #f8 }

```spl
index=zeek sourcetype=zeek:http pcap_case="<case>"
| eval h=mvdedup(host)
| where isnull(h) OR match(h,"^\d+\.\d+\.\d+\.\d+(:\d+)?$")
| sort 0 ts
| eval time=strftime(ts,"%Y-%m-%d %H:%M:%S")
| table time id_orig_h id_resp_h id_resp_p h method uri status_code user_agent uid
```

- `match(h,"^\d+\.\d+\.\d+\.\d+(:\d+)?$")` — Host is a numeric IP (with or without port). `\d+` = one or more digits.

**How to read it:** real websites are nearly always reached **by name**. HTTP straight to an IP is common in malware downloads and C2.

### F9. Web timeline with referrer (follow redirects) { #f9 }

```spl
index=zeek sourcetype=zeek:http pcap_case="<case>"
| sort 0 ts
| head 3000
| eval time=strftime(ts,"%Y-%m-%d %H:%M:%S.%3N"), h=mvdedup(host), ref=replace(referrer,"^https?://",""), mime=mvindex(resp_mime_types,0)
| table time id_orig_h method h uri ref status_code mime response_body_len user_agent uid
```

- `head 3000` — first 3000 rows in time order (narrow with Case / Host IP if needed).
- `ref=replace(referrer,"^https?://","")` — drop `http://`/`https://` from the Referer.

**How to read it:** **Referer** = "which page sent me here". Follow the chain compromised site → redirector → exploit kit / fake update page. A request with **no Referer and a different User-Agent** appearing suddenly is a newly started program, not the browser.

---

## G. TLS and certificates { #g-tls }

HTTPS hides the content but shows the **SNI** (site name requested) and the **certificate**.

### G1. TLS versions · G2. Server names (SNI) { #g1 }

```spl
index=zeek sourcetype=zeek:ssl pcap_case="<case>"
| fillnull value="(unknown)" version
| stats count by version
```

```spl
index=zeek sourcetype=zeek:ssl pcap_case="<case>"
| fillnull value="(no SNI)" server_name
| stats count as conns dc(id_orig_h) as clients values(id_resp_h) as ips values(id_resp_p) as ports values(version) as versions values(established) as established min(ts) as first by server_name
| eval first=strftime(first,"%Y-%m-%d %H:%M:%S")
| sort - conns
```

- G2 `fillnull value="(no SNI)" server_name` — keep nameless connections. `values(established)` — handshake finished (`true`/`false`).

**How to read it:** old versions (`TLSv10`, `SSLv3`) come from old malware or devices. Look for the **same suspicious names as D1/E4**. Only `established=false` = never connected.

### G3. TLS without SNI or not on 443 { #g3 }

```spl
index=zeek sourcetype=zeek:ssl pcap_case="<case>"
| where isnull(server_name) OR id_resp_p!=443
| stats count as conns values(version) as versions values(established) as established min(ts) as first max(ts) as last by id_orig_h id_resp_h id_resp_p server_name
| eval first=strftime(first,"%Y-%m-%d %H:%M:%S"), last=strftime(last,"%Y-%m-%d %H:%M:%S")
| sort - conns
```

**How to read it:** browsers almost always send SNI. **TLS to an IP without SNI**, or TLS on other ports (`8443`, `4443`, `447`), is common in C2.

### G4. Server certificates — self-signed and short-lived { #g4 }

```spl
index=zeek pcap_case="<case>" (sourcetype=zeek:ssl OR sourcetype=zeek:x509)
| eval fp=if(sourcetype="zeek:x509", fingerprint, mvindex(cert_chain_fps,0))
| where isnotnull(fp)
| stats values(server_name) as sni values(id_resp_h) as ips count(eval(sourcetype="zeek:ssl")) as conns values(certificate_subject) as subject values(certificate_issuer) as issuer values(san_dns) as san min(certificate_not_valid_before) as nvb max(certificate_not_valid_after) as nva by fp
| where conns>0 AND isnotnull(subject)
| eval self_signed=if(mvjoin(subject,"")=mvjoin(issuer,""),"YES",""), days_valid=round((nva-nvb)/86400,0), not_before=strftime(nvb,"%Y-%m-%d"), not_after=strftime(nva,"%Y-%m-%d"), san=mvindex(san,0,4)
| sort -self_signed, days_valid
| table sni ips conns subject issuer self_signed days_valid not_before not_after san
```

- Line 1: ssl and x509 together. x509 (certificate log) has no IPs, so it is linked to ssl through the **fingerprint**.
- Line 2 `fp=if(sourcetype="zeek:x509", fingerprint, mvindex(cert_chain_fps,0))` — x509's own fingerprint; for ssl, the **first** (server's own) certificate in the chain.
- Line 4 `stats ... by fp` — group by fingerprint to get SNI/IPs (ssl side) and subject/issuer/SAN/validity (x509 side) on one row — **joining two logs without `join`**.
- Line 5 `where conns>0 AND isnotnull(subject)` — rows with both sides.
- Line 7 `self_signed` — issuer equals subject → **self-signed**. `days_valid` — validity in days.
- Line 8 `sort -self_signed, days_valid` — self-signed first, then shortest validity.

```text
sni                ips            conns  subject                                        issuer                                         self_signed  days_valid   ← example result
(none)             198.51.100.9   14     CN=localhost,O=Default Company Ltd,C=XX        CN=localhost,O=Default Company Ltd,C=XX        YES          365
cdn.example.com    203.0.113.20   88     CN=cdn.example.com                             CN=Example TLS CA 2025,O=Example Trust,C=US                 90
```

**How to read it:** **OpenSSL default** values (`O=Default Company Ltd`, `CN=localhost`, `Internet Widgits Pty Ltd`) mean a quickly built server — very common for C2. Real sites use known CAs with the domain in the SAN. Let's Encrypt (90 days) is used by plenty of real sites, so **short validity alone is not malicious**.

---

## H. Files { #h-files }

Zeek writes files carried by HTTP, SMB, FTP and SMTP into `files.log` and **hashes** them (pcapbox loads `hash-all-files`).

### H1. File types · H2. Protocols { #h1 }

```spl
index=zeek sourcetype=zeek:files pcap_case="<case>"
| fillnull value="(unknown)" mime_type
| stats count by mime_type
| sort - count
```

```spl
index=zeek sourcetype=zeek:files pcap_case="<case>"
| fillnull value="(unknown)" file_source
| stats count by file_source
```

- `file_source` — protocol that carried the file (`HTTP`, `SMB`, `FTP_DATA`, `SMTP`). Zeek calls it `source`; pcapbox renamed it because it clashes with Splunk's `source`.

### H3. Programs, scripts, archives and documents (with hashes) { #h3 }

```spl
index=zeek sourcetype=zeek:files pcap_case="<case>"
| eval fname=coalesce(filename,"")
| where match(mime_type,"dosexec|x-msdownload|x-executable|java-archive|zip|x-rar|7z|x-msi|vnd.ms-cab|x-shockwave-flash|msword|ms-excel|ms-powerpoint|officedocument|rtf|pdf|x-ms-shortcut|iso9660") OR match(lower(fname),"\.(exe|dll|scr|ps1|vbs|js|hta|bat|cmd|msi|jar|lnk|iso|zip|rar|7z|docm|xlsm)$")
| sort 0 ts
| eval time=strftime(ts,"%Y-%m-%d %H:%M:%S"), KB=round(seen_bytes/1024,1), tx=mvjoin(tx_hosts,","), rx=mvjoin(rx_hosts,",")
| table time file_source tx rx mime_type fname KB md5 sha1 sha256 fuid
```

- `tx` (sender) → `rx` (receiver). `mvjoin(tx_hosts,",")` — multi-values as one string.
- `seen_bytes` — bytes Zeek actually saw; less than `total_bytes` = partly captured.

**How to read it:** compare `md5`/`sha256` with threat intel (VirusTotal, or internal IOC lists on a closed network). Encrypted payloads received over HTTP may **hash differently from the file on disk** (decoded after download).

### H4. Windows programs (PE) { #h4 }

```spl
index=zeek pcap_case="<case>" (sourcetype=zeek:files OR sourcetype=zeek:pe)
| eval f=if(sourcetype="zeek:pe", id, fuid)
| stats values(tx_hosts) as tx values(rx_hosts) as rx values(file_source) as proto values(filename) as fname values(md5) as md5 values(sha256) as sha256 values(machine) as machine values(os) as os values(subsystem) as subsystem values(is_exe) as is_exe values(is_64bit) as is_64bit values(has_cert_table) as signed values(compile_ts) as compile_ts min(ts) as first by f
| where isnotnull(machine)
| eval compiled=strftime(compile_ts,"%Y-%m-%d %H:%M:%S"), first=strftime(first,"%Y-%m-%d %H:%M:%S")
| table first tx rx proto fname is_exe is_64bit machine subsystem compiled signed md5 sha256
```

- `pe.log`'s `id` = files.log's `fuid` (file tag); `f` joins them.
- `compile_ts` — when the program was compiled. `has_cert_table` — code-signed or not.

**How to read it:** an unsigned EXE compiled **days before the incident** is suspicious — though attackers can fake the compile time.

---

## I. Alerts and oddities { #i-alerts }

### I1. Snort alerts by rule · I3. In time order { #i1 }

```spl
index=snort sourcetype=snort:alert pcap_case="<case>"
| stats count by msg
| sort - count
| head 15
```

```spl
index=snort sourcetype=snort:alert pcap_case="<case>"
| sort 0 _time
| eval time=strftime(_time,"%Y-%m-%d %H:%M:%S")
| table time sid msg src_ip src_port dest_ip dest_port
```

**How to read it:** an alert is a **starting point**, not a conclusion. Check HTTP (F9), DNS (E5) and files (H3) within ±1 minute of it. Count how often your own rules (`sid` ≥ 1000000) fired here too.

### I2. Zeek weird · I4. Zeek notice { #i2 }

```spl
index=zeek sourcetype=zeek:weird pcap_case="<case>"
| stats count min(ts) as first values(id_orig_h) as srcs values(id_resp_h) as dsts by name
| eval first=strftime(first,"%Y-%m-%d %H:%M:%S")
| sort - count
```

```spl
index=zeek sourcetype=zeek:notice pcap_case="<case>"
| sort 0 ts
| eval time=strftime(ts,"%Y-%m-%d %H:%M:%S")
| table time note msg sub src dst p uid
```

| weird `name` example | Meaning |
|---|---|
| `truncated_header`, `data_before_established` | Partial capture — usually harmless |
| `bad_HTTP_request`, `unknown_HTTP_method` | Rule-breaking HTTP — scanners, hand-made C2 |
| `dns_unmatched_reply` | Reply without a question |
| `possible_split_routing` | Only one direction captured |

Notices are warnings raised by Zeek scripts (e.g. `SSL::Invalid_Server_Cert`, scan detection); rare with pcapbox's default settings.

---

## J. Activity timeline and uid { #j-activity }

### J1. Activity timeline — every log in time order { #j1 }

Put an IP in **Host IP** and this table lists **what that host did, when**, one line at a time.

```spl
index=zeek pcap_case="<case>" (sourcetype=zeek:conn OR sourcetype=zeek:dns OR sourcetype=zeek:http OR sourcetype=zeek:ssl OR sourcetype=zeek:files OR sourcetype=zeek:smb_mapping OR sourcetype=zeek:smb_files OR sourcetype=zeek:dce_rpc OR sourcetype=zeek:ntlm OR sourcetype=zeek:kerberos)
| eval log=replace(sourcetype,"zeek:","")
| eval src=coalesce(id_orig_h, mvjoin(tx_hosts,",")), dst=coalesce(id_resp_h, mvjoin(rx_hosts,",")), dport=id_resp_p
| eval what=case(
    log="conn", coalesce(proto,"")." ".coalesce(service,"-")." state=".coalesce(conn_state,"")." out=".coalesce(orig_bytes,0)." in=".coalesce(resp_bytes,0),
    log="dns", coalesce(qtype_name,"")." ".coalesce(query,"")." > ".coalesce(mvjoin(answers," "), rcode_name, ""),
    log="http", coalesce(method,"")." ".coalesce(mvdedup(host),"").coalesce(uri,"")." [".coalesce(status_code,"-")."]",
    log="ssl", "TLS ".coalesce(server_name,"(no SNI)")." ".coalesce(version,""),
    log="files", coalesce(file_source,"")." ".coalesce(mime_type,"")." ".coalesce(filename,"")." ".coalesce(seen_bytes,"")." B md5=".coalesce(md5,""),
    log="smb_mapping", "MAP ".coalesce(path,""),
    log="smb_files", replace(coalesce(action,""),"SMB::","")." ".coalesce(path,"")." ".coalesce(name,""),
    log="dce_rpc", "RPC ".coalesce(endpoint,"")."::".coalesce(operation,""),
    log="ntlm", "NTLM ".coalesce(username,"")."@".coalesce(domainname,"")." from ".coalesce(hostname,"")." success=".coalesce(success,""),
    log="kerberos", "KRB ".coalesce(request_type,"")." ".coalesce(client,"")." > ".coalesce(service,"")." ".coalesce(error_msg,""))
| sort 0 ts
| head 5000
| eval time=strftime(ts,"%Y-%m-%d %H:%M:%S.%3N")
| table time log src dst dport what uid
```

- Line 1: conn, dns, http, ssl, files, SMB, RPC, NTLM and Kerberos logs together; the dashboard adds `(id_orig_h="$ip$" OR id_resp_h="$ip$" OR tx_hosts="$ip$" OR rx_hosts="$ip$")`.
- `log=replace(sourcetype,"zeek:","")` — drop `zeek:`.
- `src=coalesce(id_orig_h, mvjoin(tx_hosts,","))` — source IP, or the sender for files.
- `what=case(log="conn", ..., log="dns", ..., ...)` — a **one-line summary** per log type, e.g. conn = `tcp ssl state=SF out=517 in=4410`, dns = `A cdn.example.com > 203.0.113.20`, http = `GET www.example.org/index.html [200]`.
- `sort 0 ts | head 5000` — first 5000 rows in time order.

```text
time                     log    src         dst            dport  what                                                 uid        ← example result
2026-01-20 01:02:58.310  dns    10.0.0.101  10.0.0.10      53     A update-check.example.net > 198.51.100.7            CzX1...
2026-01-20 01:02:58.402  conn   10.0.0.101  198.51.100.7   443    tcp ssl state=SF out=517 in=2210                     CfA9...
2026-01-20 01:02:58.402  ssl    10.0.0.101  198.51.100.7   443    TLS update-check.example.net TLSv12                  CfA9...
```

**How to read it:** the same `uid` on conn and ssl = **one connection**. Found a suspicious row? **Click it.**

### J2. Every Zeek record of the clicked connection { #j2 }

```spl
index=zeek pcap_case="<case>" (uid="<uid>" OR conn_uids="<uid>" OR uids="<uid>")
| sort 0 ts
| eval time=strftime(ts,"%Y-%m-%d %H:%M:%S.%3N")
| table time sourcetype _raw
```

- `uid="<uid>" OR conn_uids="<uid>" OR uids="<uid>"` — the connection's `uid`, files' `conn_uids`, dhcp's `uids`.
- `table time sourcetype _raw` — `_raw` = Zeek's **whole original JSON line**, including fields not shown elsewhere.

**How to read it:** the panel stays **hidden until you click** a row. To see the same connection in Arkime, search by time and IP/port (`ip == 10.0.0.101 && port == 443`).

---

Next: [Dashboard 2 — SMB and the Windows domain](smb-dashboard.md) · Analysis order: [Analysing a PCAP with the dashboards](analysis-workflow.md)

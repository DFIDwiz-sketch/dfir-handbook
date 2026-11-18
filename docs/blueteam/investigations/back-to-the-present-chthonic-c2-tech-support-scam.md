---
title: Back to the Present — From Network Baselining to a .bit C2, a Tech Support Scam Pop-up, Snort Rules and a Ticket (Arkime + Splunk + Snort)
tags:
  - blue-team
  - pcap
  - baselining
  - arkime
  - splunk
  - zeek
  - snort
  - c2
  - dns
  - tech-support-scam
  - ticket
---

# Back to the Present — From Network Baselining to a .bit C2, a Tech Support Scam Pop-up, Snort Rules and a Ticket { #back-to-the-present }

!!! abstract "Case summary"
    A 12-minute capture of **one Windows 10 PC (DELOREAN-PC)** inside Marty and Doc's "stainless steel machine". We start with **network baselining** from scratch: internal IPs and ranges, the router, the DNS and DHCP servers, whether there is a DC, file server or web/mail server, how many devices there are, the protocols, the OS and the external communications. Then we follow what does not fit. Right after Office activity the PC **downloaded an `.exe` without a User-Agent**, and a minute later it began asking **external DNS servers, over TCP and bypassing the local DNS**, for a `.bit` domain (`amellet.bit`). It sent **39 encrypted HTTP/1.0 POSTs** to that address and received about **2.3 MB** (the same shape as **Chthonic-like C2**). Finally a **pop-under script** hidden in a website the user opened launched a **fake Windows Defender alert (tech support scam)**. We **write 14 Snort rules and test them against the PCAP**, and complete a **ticket** for the MC or another hunt team plus **leads for the host operator**.

| | |
|---|---|
| **Evidence** | 1 PCAP `2017-10-21-traffic-analysis-exercise.pcap` — 2017-10-21 04:51:53 – 05:03:52 UTC (11 min 59 s), 9,931 packets, 505 Arkime sessions, 510 Zeek connections |
| **Source** | malware-traffic-analysis.net 2017-10-21 exercise "Doc Brown and Marty McFly: Back to the Present" (team-training version with ticket and Snort rule tasks) |
| **Environment** | Closed network (no VirusTotal, no OSINT). Arkime v5.6.4 web UI, Splunk with Zeek logs, Snort 2.9 on the analysis PC |
| **Deliverables** | Network baseline, malicious-activity analysis, Snort rules to find the traffic again (tested), incident ticket, leads for the host operator |
| **Related pages** | [Arkime search syntax](../../network/arkime/search-syntax.md) · [Zeek logs](../../network/zeek/index.md) · [SPL cheatsheet](../splunk/spl-cheatsheet.md) · [Beaconing & C2](../../network/beaconing-c2.md) · [Previous case: Splunk + Arkime + Snort](phishing-red-herring-ek-driveby-ursnif-c2.md) |

!!! tip "How to read this page"
    Written so a complete beginner can follow from the first click to the finished ticket. Every step uses the same order:

    1. **Goal** — what this step is trying to find out
    2. **Query / command** — copy with the **copy button** at the top right of the code block
    3. **Explanation** — what each piece means
    4. **Result** — the values this PCAP actually produced
    5. **Reading the result** — what the values mean and why they matter
    6. **Ticket entry** — the operation-log line for this step

    Each step gives both an **Arkime** and a **Splunk** query. Arkime is best for looking deeply at one session (packet content, files); Splunk (Zeek) is best for counting and grouping everything. You can follow with just one of them.

!!! note "Where do the result values come from?"
    The Arkime results in steps C1–C4 are values confirmed on the real Arkime screen. The other values were confirmed by processing the same PCAP with **Zeek 7.0** and **tshark**. Arkime session counts and Zeek connection counts follow slightly different rules (for example when a UDP session is cut), so they can differ by a few. Contents such as IPs, domains, times and byte counts are the same.

!!! warning "The indicators on this page are real"
    Domains, IPs and hashes come from real malicious traffic in 2017. In prose and tables they are defanged (`hxxp`, `[.]`); inside code blocks (queries, rules, raw output) they are left as typed. **Never visit them.** Never open the extracted `.exe` outside an isolated analysis VM.

## Answers at a glance { #answers }

| Item | Answer | Status |
|---|---|---|
| Internal network | One: **10.0.1.0/24** (subnet mask 255.255.255.0) | Confirmed (DHCP) |
| Number of devices | **2** — 1 PC + 1 router (only 2 MAC addresses) | Confirmed |
| PC | **10.0.1.95 DELOREAN-PC**, MAC `60:a4:4c:6a:b2:1f` (ASUSTek), **Windows 10 64-bit**, IE11, workgroup **DOC-BROWN-GROUP** (not domain-joined) | Confirmed |
| Router / gateway | **10.0.1.1**, MAC `00:04:5a:f8:1a:ac` (Linksys) — also the DNS server | Confirmed |
| DHCP server | **10.0.1.254** — **same MAC** as the router, i.e. another IP of the same Linksys device | Confirmed |
| DNS server | **10.0.1.1** (as given by DHCP). DNS suffix `localdomain` | Confirmed |
| DC / file server / web or mail server | **None** — no Kerberos, LDAP, SMB (445) or mail-port connections at all | Confirmed |
| Protocols | DNS (UDP and **TCP**), HTTP, TLS, DHCP, NetBIOS (137/138), LLMNR, ICMP | Confirmed |
| First malicious event | **04:52:47 UTC** — download of `hxxp://jgbennett[.]com/3cgconsulting.com/30_723bio_152.exe` without a User-Agent (61,440-byte PE, SHA256 `a56876fd…a490`) | Confirmed |
| Cause of the download | **Microsoft Office** started talking just before (04:52:40–46) → likely downloaded by a document macro | Assessed |
| C2 | `amellet[.]bit` → **35.198.166.240:80**. Queried over **TCP 53** against 9 external DNS servers. **39** HTTP/1.0 POSTs to `/a/` and `/html/` (04:54:03 – 05:02:05), no User-Agent, encrypted content, about **2.34 MB** received and **23 KB** sent | Confirmed |
| Malware family | **Chthonic** (Zeus variant)-like — matches public analysis. No hash lookup (closed network) | Assessed |
| Tech support scam | 05:02:26 **pop-under script** on `www.singlemoms[.]org` → 05:03:25 click → `helpcenterforall[.]bid` (302) → `krep2010123[.]tk/?number=888-779-0939` fake "Windows Defender: Zeus Virus Detected" page with alarm sound | Confirmed |
| Malicious activity window | **2017-10-21 04:52:47 – 05:03:31 UTC** | Confirmed |
| Lateral movement | **None** — there are no other internal PCs | Confirmed |
| Snort | 14 rules (sid 1000201–1000214); all behaved as expected in the PCAP test, 0 false positives on benign traffic | Confirmed |

---

## Part A — Scenario and plan { #scenario }

### What we were given { #given }

The task, summarised:

- Your friend **Marty** and his mate **Doc** called you in to help with the **Windows** running inside their "stainless steel machine".
- When they came back from the future they noticed **weird traffic**, recorded it in a PCAP and gave you a copy.
- Write a **ticket** that can be handed to the **MC** (Mission Commander) or **another hunt brick**.
- Include information that lets the **host operator** continue the investigation on the PC.
- Create **Snort rules** to find the traffic again.

The "stainless steel machine" is the **DeLorean**, the time-machine car from *Back to the Future*. That is why the hostname is `DELOREAN-PC` and the workgroup is `DOC-BROWN-GROUP`.

### Ticket template { #ticket-template }

The team template has these fields (see the [final ticket](#ticket)).

| Field | Content |
|---|---|
| `#INDEX ENTRY#` | One-line summary: `[] -- <YYMMDD HHMM> -- <IP> <hostname> -- <description> -- <ticket link>` |
| `DESCRIPTION OF INVESTIGATION` | **No more than two paragraphs.** Internal IPs and hostnames, external IPs and domains, protocol and port, directionality (who initiated), file names, verdict and type, life-cycle stages (C2 interval/state/bytes; exfil time/content/bytes/method) |
| `#IMPACTED MACHINES#` / `#EXTERNAL MACHINES#` | Internal and external IPs, names and ports. **Leave ephemeral ports blank**; leave LATERAL blank if there is no lateral movement |
| `#SEARCH QUERIES#` | Arkime (`MOLOCH:`) and Splunk queries — specific enough to return **only the traffic of interest** on a live network |
| `#EVIDENCE LOCATIONS#` | `Team<#>: /home/<user>/<evidence folder>/<file>` |
| `#OPERATION LOG#` | One line per action: `[<time>, <operator>] <what you looked for> - <Found / Not Found / Further Analysis Required>` |
| `TOOL OUTPUT / NOTES` | Tool output and its meaning, with the **same** `[<time>, <operator>]` stamp as the log line, so Ctrl+F finds both |

!!! note "Moloch = Arkime"
    `MOLOCH:` in the template is where Arkime queries go. Moloch is Arkime's old name.

### Plan { #plan }

1. **Baselining (Parts B and C):** learn what normal looks like first. You can only spot the odd thing once you know what is normal.
2. **Finding malicious activity (Part D):** follow each thing that departs from the baseline.
3. **Snort rules (Part E):** write rules that catch what we found and test them against the PCAP.
4. **Wrap-up and ticket (Part F, ticket):** timeline, IOCs, host-operator leads, ticket.

---

## Part B — Preparation { #prep }

### Step B0 — Record the evidence hash { #evidence-hash }

**Goal:** record the evidence file's fingerprint (hash) before analysis, so you can later prove the file did not change while you worked.

```bash
sha256sum 2017-10-21-traffic-analysis-exercise.pcap
md5sum 2017-10-21-traffic-analysis-exercise.pcap
```

- `sha256sum file` — computes the SHA256 hash (64 hex characters) from the file content. Change one byte and the value is completely different.
- `md5sum` — the same with MD5 (32 characters). Used to compare with older tools.

**Result:**

```text
a42fd8341966fbf385e54feaf24218eb1df0f408bc060baa5f5c22aeb1318846  2017-10-21-traffic-analysis-exercise.pcap
30d573501a9458f70fb72d991b0db556  2017-10-21-traffic-analysis-exercise.pcap
```

### Step B1 — Time zone and time range { #timezone }

**Goal:** the PCAP is from 2017. Both tools default to a "recent" range, so left alone they return **zero results**. And the ticket is written in **UTC**.

**Arkime:**

- Change the time range at the top to **All** (or a **Custom** range that covers the PCAP date).
- In **Settings**, set the time display (Timezone) to **UTC**.

**Splunk:**

- Set the Time picker to **All time**.
- Top right account name → **Preferences → Time zone** → UTC. If your environment does not allow that, use the `ts` field as below.

!!! warning "The Splunk `_time` trap"
    In the previous case Splunk could not read the time inside the Zeek logs, so **every event's `_time` was the day the logs were loaded** (2026). This page therefore uses **Zeek's `ts` field** (UTC epoch seconds) for times in Splunk queries. If `_time` correctly shows 2017-10-21 you can use `_time` instead.

### Step B2 — Which Zeek logs are in Splunk { #data-discovery }

**Goal:** confirm the real index and sourcetype names before writing queries.

```spl
| tstats count where index=zeek by sourcetype
| sort sourcetype
```

- Leading `|` — start with a **command**, not an event search.
- `tstats count` — counts **very fast** from index metadata instead of reading each event.
- `where index=zeek` — only the `zeek` index. Per company guidance we do not use `index=*`. If you do not know the index name, check **Settings → Indexes**.
- `by sourcetype` — one row per log type.
- `sort sourcetype` — sort by name.

**Result (log lines Zeek produced from this PCAP):**

| sourcetype | count | Contains |
|---|---|---|
| zeek:conn | 510 | Every connection (who, to whom, ports, bytes, state) |
| zeek:dhcp | 2 | IP assignment (hostname, MAC) |
| zeek:dns | 258 | DNS questions and answers (NetBIOS name queries are mixed in) |
| zeek:files | 343 | Files transferred (type, size, hash) |
| zeek:http | 304 | HTTP requests and responses |
| zeek:pe | 1 | Windows executable details |
| zeek:software | 3 | Software identified from User-Agents |
| zeek:ssl | 87 | TLS connections (site name) |
| zeek:weird | 11 | Odd traffic that breaks protocol rules |
| zeek:x509 | 21 | Certificates |

**Reading the result:** depending on the environment the sourcetype names may differ (`bro:conn:json`, `zeek_conn` …). If so, replace `sourcetype=zeek:conn` in the queries below. The fact that there are **no `kerberos`, `smb`, `ntlm` or `smtp` logs at all** is already a clue: this capture has no Windows domain logons, no file sharing and no mail.

**Check the field names:**

```spl
index=zeek sourcetype=zeek:conn
| head 1
```

- `head 1` — show only the first event. Check the names in the field list on the left.

In the previous lab environment field names used **underscores**: `id_orig_h` (source IP), `id_orig_p` (source port), `id_resp_h` (destination IP), `id_resp_p` (destination port), `proto`, `service`, `orig_bytes`, `resp_bytes`, `conn_state`, `ts`. This page uses those names. If your fields have **dots** (`id.orig_h`), change the underscores to dots, and inside `eval`/`where` wrap them in single quotes: `'id.orig_h'`.

---

## Part C — Network baselining { #baselining }

Baselining means **drawing "what this network normally looks like"**. Once you know what is there, what should not be there stands out. The order:

```text
data range → internal IPs and ranges → devices (hostname, MAC) → router → server roles (DNS, DHCP, DC, file, web, mail)
→ protocols → OS → external communications
```

### Step C1 — Data range: from when to when, and how much { #time-range }

**Goal:** set the time range for the analysis and the reference for ticket times.

**Arkime:** **empty** search box → Search → **Sessions** tab.

- N in "Showing 1 - 50 of **N** entries" above the list = number of sessions
- Click the **Start Time** column header to sort ascending/descending for the first and last session times

**Result (Arkime screen):**

```text
Start  2017/10/21 04:51:53     End  2017/10/21 05:03:53     (00:12:00)
Showing 1 - 50 of 505 entries
```

**Splunk:**

```spl
index=zeek sourcetype=zeek:conn
| stats count AS connections min(ts) AS first_seen max(ts) AS last_seen
| eval first_seen=strftime(first_seen, "%Y-%m-%d %H:%M:%S"), last_seen=strftime(last_seen, "%Y-%m-%d %H:%M:%S")
```

- `stats count AS connections` — count connections and name the result `connections`. `AS` means "name it".
- `min(ts) AS first_seen max(ts) AS last_seen` — `ts` is the time the connection **started** (UTC epoch seconds). Get the earliest and latest.
- `eval ... strftime(number, "format")` — turn a number like `1508561513` into a readable date. `%Y`=year, `%m`=month, `%d`=day, `%H:%M:%S`=hour:minute:second. A comma lets you change two fields at once.

**Result:**

```text
connections  first_seen           last_seen
510          2017-10-21 04:51:53  2017-10-21 05:03:26
```

**Reading the result:**

- A **short 12-minute capture**. This is not a needle-in-a-haystack hunt through hours of data; it is a cut-out of the incident, so many sessions may be related.
- Why Splunk's `last_seen` is 05:03:26: `ts` is the connection **start**. The last connection started at 05:03:26 and lasted until 05:03:52.
- Arkime 505, Zeek 510 — a small difference from different counting rules. If they are **similar**, you know both tools are looking at the same data.
- Note the shape of Arkime's bar graph: steady activity 04:52–04:56, nearly quiet 04:57–05:00, clustered again 05:00–05:01, **spike around 05:02:30**. Part D explains why.

**Ticket entry:**

```text
[261119 0030, Sung] Establishing data time range and session count - Found
```

### Step C2 — Internal IPs and internal range { #internal-ips }

**Goal:** decide who "we" are, so we can separate internal from external.

There are only three private (internal) IP ranges. Memorise them.

```text
10.0.0.0/8       10.x.x.x
172.16.0.0/12    172.16.x.x ~ 172.31.x.x
192.168.0.0/16   192.168.x.x
```

Notation like `/8` or `/24` is **CIDR**: how many leading bits are the network part. `/24` means addresses that share the first three octets (e.g. 10.0.1.0 – 10.0.1.255) are one network.

**Arkime:**

```text
ip.src == 10.0.0.0/8 || ip.src == 172.16.0.0/12 || ip.src == 192.168.0.0/16
```

- `ip.src` — source IP. Arkime understands CIDR directly.
- `||` — "or". Matches if any of the three ranges matches.

→ **SPIView** tab → **Src IP**, **Dst IP** and **Protocols** in the **General** section.

**Result (Arkime screen):**

```text
Src IP     10.0.1.95 (501)  10.0.1.254 (2)
Dst IP     10.0.1.1 (158)  35.198.166.240 (34)  188.165.200.156 (31)  23.56.3.183 (20)
           13.107.4.52 (19)  198.232.125.32 (18)  52.183.114.173 (17)  13.107.21.200 (11)
           204.79.197.200 (11)  10.0.1.255 (8)  224.0.0.252 (7)  ...  10.0.1.95 (2)  ...
Protocols  tcp (328)  dns (188)  udp (174)  http (166)  tls (87)  http2 (24)  llmnr (7)  dhcp (2)  icmp (1)
```

**Splunk — activity per internal IP:**

```spl
index=zeek sourcetype=zeek:conn (id_orig_h=10.0.0.0/8 OR id_orig_h=172.16.0.0/12 OR id_orig_h=192.168.0.0/16)
| stats count AS connections dc(id_resp_h) AS unique_destinations BY id_orig_h
| sort - connections
```

- First-line parentheses — only connections whose source is private. Splunk search also understands `field=CIDR`.
- `dc(id_resp_h)` — **distinct count**, the number of different destination IPs.
- `BY id_orig_h` — one row per source IP.
- `sort - connections` — most connections first (`-` = descending).

**Result:**

```text
id_orig_h    connections  unique_destinations
10.0.1.95    508          91
```

**Splunk — which subnets exist:**

```spl
index=zeek sourcetype=zeek:conn (id_orig_h=10.0.0.0/8 OR id_orig_h=172.16.0.0/12 OR id_orig_h=192.168.0.0/16)
| rex field=id_orig_h "^(?<subnet>\d+\.\d+\.\d+)\.\d+$"
| stats dc(id_orig_h) AS hosts values(id_orig_h) AS ips BY subnet
```

- `rex field=id_orig_h "regex"` — `rex` **cuts part of a value into a new field** with a regular expression.
- `^(?<subnet>\d+\.\d+\.\d+)\.\d+$` — `\d+` is one or more digits, `\.` is a dot. Cut the first three octets (`10.0.1`) out as `subnet`. `(?<name>...)` means "give this part a name".
- `values(id_orig_h)` — list of distinct values.

**Result:**

```text
subnet   hosts  ips
10.0.1   1      10.0.1.95
```

**Reading the result:**

- **Only one internal PC starts connections: 10.0.1.95.** It started all 501 (Arkime) / 508 (Zeek) sessions.
- There is one internal range, **10.0.1.0/24**. `10.0.1.255` in Dst IP is the **broadcast address** that shouts to the whole /24, which supports /24 (confirmed by DHCP in step C4).
- **10.0.1.1 appears only as a destination, 158 times.** It never starts connections, it **only answers questions** — a server role.
- **10.0.1.254 started only 2 sessions**, and Dst IP contains `10.0.1.95 (2)`: those are from 10.0.1.254 to 10.0.1.95. Step C3 shows what they are.
- Two sessions are missing: 505 in total but 501 + 2 = **503**. So **2 sessions have a non-private source**. Also checked in step C3.
- `224.0.0.252 (7)` is **LLMNR** (Windows asking the local network for a name by multicast) and `10.0.1.255 (8)` is **NetBIOS broadcast**. Normal Windows noise.
- **Protocols shows `http (166)` far above `tls (87)`.** Even in 2017 much of the web was already encrypted, so this much plaintext HTTP is worth noting.

**Ticket entry:**

```text
[261119 0035, Sung] Identifying internal networks and active hosts - Found
```

### Step C3 — The 2 non-internal-source sessions and 10.0.1.254 { #non-internal }

**Goal:** see what the 2 missing sessions and 10.0.1.254's 2 sessions are. In particular, always check whether there is any **connection started from outside** (inbound).

**Arkime:**

```text
ip.src != 10.0.0.0/8 || ip.src == 10.0.1.254
```

- `ip.src != 10.0.0.0/8` — sessions whose source is **not** 10.x.x.x. `!=` means "not equal". This PCAP has no 172 or 192 ranges, so excluding the 10 range is enough.
- `ip.src == 10.0.1.254` — sessions started by 10.0.1.254.

→ **Sessions** tab.

**Result (Arkime screen, 4 sessions):**

```text
04:51:53  udp  0.0.0.0:68       -> 255.255.255.255:67   dhcp  313 B
04:51:53  udp  10.0.1.254:67    -> 10.0.1.95:68         dhcp  300 B
04:53:08  udp  0.0.0.0:68       -> 255.255.255.255:67   dhcp  313 B
04:53:08  udp  10.0.1.254:67    -> 10.0.1.95:68         dhcp  300 B
```

**Reading the result:**

DHCP is how a PC gets "an IP, please" when it joins a network. The ports are fixed: **67 = DHCP server, 68 = client (PC)**.

- The two `0.0.0.0` sessions are the 2 missing ones. Before a PC has confirmed its IP it uses `0.0.0.0` as the source, and since it does not know where the server is it shouts to `255.255.255.255` (broadcast to the whole network). This is **normal**.
- So **there are no connections started from outside.** All 505 sessions started inside. "None" is also a result, so it goes in the ticket.
- **10.0.1.254 = DHCP server** (it answered from port 67).
- In Splunk (Zeek) the same DHCP shows as `10.0.1.95 → 10.0.1.254:67`, because Zeek records DHCP connections in the **client → server** direction. Remember that tools decide "source" differently.
- The same thing happened **twice, 75 seconds apart** (04:51:53, 04:53:08). That happens when a PC boots or reconnects to a network. We come back to the second one in the Part D timeline.

**Ticket entry:**

```text
[261119 0040, Sung] Identifying non-internal-source sessions (possible inbound) - Not Found
```

`Not Found` means "we looked for connections from outside and there were **none**".

### Step C4 — Device details: hostname, MAC, network settings (DHCP) { #dhcp }

**Goal:** a DHCP request contains the **hostname** and **MAC address** the PC announces about itself, and the server's reply contains network settings such as the **subnet mask, gateway and DNS server**. The core of the baseline comes out in one go.

**Arkime:**

```text
protocols == dhcp
```

- `protocols` — the list of protocols Arkime identified. `== dhcp` keeps DHCP sessions only.

→ **SPIView** → **dhcp** section (if it is not shown, **Load All** at the top right).

**Result (Arkime screen):**

```text
Client MAC   60:a4:4c:6a:b2:1f (4)        Client MAC Cnt  1
Client OUI   ASUSTek COMPUTER INC. (4)
Host         delorean-pc (2)
Transaction id  15a2b597 (2)  d0ad6ea9 (2)
Type         ACK (2)  REQUEST (2)
```

**Splunk:**

```spl
index=zeek sourcetype=zeek:dhcp
| eval t=strftime(ts, "%H:%M:%S")
| table t client_addr server_addr assigned_addr mac host_name domain lease_time msg_types
```

- `eval t=strftime(ts, "%H:%M:%S")` — make a readable time in a new field `t`.
- `table field list` — show only the fields you want, as a table.
- `client_addr` / `assigned_addr` — the PC's IP / the IP the server gave.
- `server_addr` — DHCP server.
- `mac` — hardware address. Changes much less than an IP.
- `host_name` — the **computer name** the PC announced.
- `domain` — the **DNS suffix** the server handed out.
- `lease_time` — how long the IP is lent (seconds).
- `msg_types` — DHCP message types.

**Result:**

```text
t         client_addr  server_addr  assigned_addr  mac                host_name    domain       lease_time  msg_types
04:51:53  10.0.1.95    10.0.1.254   10.0.1.95      60:a4:4c:6a:b2:1f  DELOREAN-PC  localdomain  1800.0      REQUEST ACK
04:53:08  10.0.1.95    10.0.1.254   10.0.1.95      60:a4:4c:6a:b2:1f  DELOREAN-PC  localdomain  1800.0      REQUEST ACK
```

**Reading the result:**

- **Hostname DELOREAN-PC.** Matches "DeLorean" in the task. Host shows `(2)` in Arkime because only the PC's two REQUESTs carry the name.
- **MAC `60:a4:4c:6a:b2:1f`.** A MAC is a unique number per network card. An IP can change but a MAC rarely does, so it is the most reliable clue for the host operator to find **exactly which machine**.
- **OUI = ASUSTek.** The first 6 hex digits of the MAC (`60:a4:4c`) identify the manufacturer. An ASUS network card — an ordinary PC or laptop.
- **Only REQUEST and ACK, no DISCOVER or OFFER.** DHCP normally has four steps:

    ```text
    DISCOVER  PC: "Is there a DHCP server?"
    OFFER     Server: "How about this IP?"
    REQUEST   PC: "I'll take that IP"
    ACK       Server: "Confirmed, use it"
    ```

    Missing the first two means the PC **only re-confirmed the IP it already had (10.0.1.95)**. That is what happens on reboot or reconnect. Two Transaction ids confirm **two separate requests**.

- **`domain = localdomain`** — not a company AD domain, but the default name a home router hands out. A first clue that this is a home or small-office router environment.
- **`lease_time = 1800` s = 30 minutes.**

**Settings inside the DHCP server's reply (packet detail).** Zeek's and Arkime's DHCP fields do not show the gateway or DNS server; you see them by opening the packet. In Arkime open the `10.0.1.254 -> 10.0.1.95` session and look at the packet, or if the analysis PC has Wireshark/tshark:

```bash
tshark -r 2017-10-21-traffic-analysis-exercise.pcap -Y "dhcp.option.dhcp == 5" -V | grep -E "^ +(DHCP Server Identifier|Subnet Mask|Router|Domain Name Server|Domain Name|IP Address Lease Time):" | head -6
```

- `-r file` — read the PCAP.
- `-Y "dhcp.option.dhcp == 5"` — display filter. DHCP message type 5 = **ACK** (the server's confirmed reply) only.
- `-V` — show each packet decoded layer by layer in detail.
- `| grep -E "^ +(A|B|C):"` — keep only the lines you want. `-E` is extended regex, `^ +` is "the line starts with spaces", `(A|B|C)` is "A or B or C".
- `| head -6` — the same ACK appears twice, so look at the first 6 lines (the first ACK).

```text
DHCP Server Identifier: 10.0.1.254
IP Address Lease Time: 30 minutes (1800)
Subnet Mask: 255.255.255.0
Router: 10.0.1.1
Domain Name Server: 10.0.1.1
Domain Name: localdomain
```

→ **Subnet 255.255.255.0 = /24 confirmed, gateway (Router) = 10.0.1.1, DNS server = 10.0.1.1.**

- One more: the PC's request contains **Vendor class identifier: `MSFT 5.0`**. Every Windows version since Windows 2000 sends this, so it is evidence that **the OS is Windows** (step C8).

**Ticket entry:**

```text
[261119 0045, Sung] Identifying hostname, MAC and network settings via DHCP - Found
```

### Step C5 — How many devices, and who is the router (MAC) { #devices-router }

**Goal:** the number of IPs and the number of devices can differ. One device can hold several IPs, and devices with static IPs do not show up in DHCP. So we count devices by **MAC address**, and the same method finds the **router**.

**Key idea:** packets going outside are sent not to the remote server's MAC but to the **router's (gateway's) MAC**. So outbound packets have **exactly one** destination MAC even across hundreds of IPs, and that is the router. A MAC only means something inside the same LAN.

**Arkime — method 1: bring out the MAC fields**

```text
ip.src == 10.0.1.95 && ip.dst != 10.0.0.0/8 && ip.dst != 224.0.0.0/4 && ip.dst != 255.255.255.255
```

- `ip.src == 10.0.1.95` — sent by the PC.
- `ip.dst != 10.0.0.0/8` — destination is not internal.
- `ip.dst != 224.0.0.0/4` — exclude multicast (224–239).
- `ip.dst != 255.255.255.255` — exclude full broadcast. Only **truly outbound sessions** remain.

→ **SPIView** → in the **General** section, type `mac` in "Search for fields to display in this category" → click **Src MAC** and **Dst MAC** to load them. In the same way type `oui` to load **Src OUI** and **Dst OUI**.

!!! question "Question: there is no ethernet section in SPIView and no Src MAC either"
    Depending on Arkime's version or configuration, the MAC fields (`mac.src`, `mac.dst`) may be **hidden inside the general section**, or not stored at all. First put `mac.src == 60:a4:4c:6a:b2:1f` in the search box. If sessions come back, the field exists but is not shown; if you get 0, this Arkime does not store MACs. Then use **method 2**. (The DHCP Client MAC earlier was not from the Ethernet header but a **value written inside the DHCP message**, which is why it appeared separately.)

**Arkime — method 2: read the first 12 bytes of a packet**

Even without MAC fields, the packet itself contains the MACs. An Ethernet frame always starts like this:

```text
bytes 0–5    destination MAC (6 bytes)
bytes 6–11   source MAC (6 bytes)
bytes 12–13  next layer type (08 00 = IPv4)
```

1. From the query above, click **+** on any session (e.g. 35.198.166.240) to open the session detail.
2. In the packet area options choose **hex** and turn on **Show Frames** (show the raw frames). The names may differ slightly by version.
3. Look at the first line of the first packet the PC sent.

**Result (first packet 10.0.1.95 → 35.198.166.240):**

```text
0000  00 04 5a f8 1a ac 60 a4 4c 6a b2 1f 08 00 45 00   ..Z...`.Lj....E.
      └─ destination MAC ─┘└─── source MAC ───┘└type┘
```

**Doing the same for 10.0.1.1's DNS reply and 10.0.1.254's DHCP reply:**

```text
10.0.1.1   -> 10.0.1.95 (DNS)   0000  60 a4 4c 6a b2 1f 00 04 5a f8 1a ac 08 00 ...
10.0.1.254 -> 10.0.1.95 (DHCP)  0000  60 a4 4c 6a b2 1f 00 04 5a f8 1a ac 08 00 ...
                                       └ dest = the PC ─┘ └ source = ? ───┘
```

**Summary (all MACs in the PCAP):**

```text
Source MAC   00:04:5a:f8:1a:ac  The Linksys Group, Inc.   6,046 packets
             60:a4:4c:6a:b2:1f  ASUSTek COMPUTER INC.     3,885 packets
Dest MAC     the two above + ff:ff:ff:ff:ff:ff (broadcast) + 01:00:5e:00:00:fc (LLMNR multicast)
```

**Reading the result:**

- Every outbound packet's destination MAC is the single **`00:04:5a:f8:1a:ac`**. That is the **router's MAC**. The first 6 digits `00:04:5a` belong to **Linksys** (home/small-office routers).
- 10.0.1.1's DNS reply and 10.0.1.254's DHCP reply both come from **the same MAC**. So **one router uses two IPs: 10.0.1.1 (gateway, DNS) and 10.0.1.254 (DHCP).** This also matches "Router: 10.0.1.1" from DHCP in step C4.
- The whole PCAP has **only two** real device MACs. **2 devices: the PC (DELOREAN-PC) and the Linksys router.** `ff:ff:ff:ff:ff:ff` and `01:00:5e:...` are not devices but "send to everyone" addresses.
- **3 IPs (10.0.1.95, 10.0.1.1, 10.0.1.254) ≠ 3 devices.** Counting IPs alone would have been wrong.

**Splunk:** Zeek's conn.log does not record MACs by default (enabling the `mac-logging` script on the sensor adds `orig_l2_addr` and `resp_l2_addr`). So in Splunk we check **how many internal IPs there are** and **each IP's role**, and look at MACs in Arkime or the DHCP log.

```spl
index=zeek sourcetype=zeek:conn
| eval ip=mvappend(id_orig_h, id_resp_h)
| mvexpand ip
| where cidrmatch("10.0.0.0/8", ip) OR cidrmatch("172.16.0.0/12", ip) OR cidrmatch("192.168.0.0/16", ip)
| stats count BY ip
```

- `eval ip=mvappend(id_orig_h, id_resp_h)` — put the source and destination IPs into one field as **multiple values (multivalue)**.
- `mvexpand ip` — **spread** the multiple values into one row each. Now every IP, source or destination, can be counted at once.
- `where cidrmatch("range", ip)` — `cidrmatch` is true if the IP is inside the range. `where` keeps only rows where the condition is true.
- `stats count BY ip` — how often each IP appears.

**Result:**

```text
ip           count
10.0.1.1     161
10.0.1.254   2
10.0.1.255   6
10.0.1.95    508
```

`10.0.1.255` is the broadcast address, not a device. **3 real internal IPs**; by MAC, **2 devices**.

**Ticket entry:**

```text
[261119 0050, Sung] Counting devices and identifying gateway via MAC addresses - Found
```

### Step C6 — Server roles: DNS, DHCP, DC, file, web and mail servers { #server-roles }

**Goal:** find which servers exist inside. **Key idea:** a server reveals itself by **destination port**. If PCs connect to the same port on the same IP, that IP is the server for that service.

Reading roles from ports (worth memorising):

| Port | Service | Role |
|---|---|---|
| 53 | DNS | DNS server |
| 67/68 | DHCP | DHCP server / client |
| 88, 464 | Kerberos | **DC** (domain logon) |
| 389, 636, 3268 | LDAP, LDAPS, Global Catalog | **DC** |
| 135, 139, 445 | RPC, NetBIOS session, SMB | DC or **file server** |
| 80, 443, 8080 | HTTP, HTTPS | Web server |
| 25, 587, 110, 143, 993, 995 | SMTP, POP3, IMAP | Mail server |
| 123 | NTP | Time server |
| 3389, 5985 | RDP, WinRM | Remote administration |
| 137, 138 | NetBIOS name / datagram | Windows name announcements (not a server) |

**Arkime:**

```text
ip.dst == 10.0.0.0/8
```

→ **SPIView** → **Dst IP** and **Dst Port** in General.

- Only sessions to internal destinations, because we are looking for internal servers.

**Splunk — connections and ports received by internal IPs:**

```spl
index=zeek sourcetype=zeek:conn (id_resp_h=10.0.0.0/8 OR id_resp_h=172.16.0.0/12 OR id_resp_h=192.168.0.0/16 OR id_resp_h=224.0.0.0/4 OR id_resp_h=255.255.255.255) id_resp_p<10000
| stats dc(id_orig_h) AS clients count AS connections values(id_resp_p) AS ports values(proto) AS proto BY id_resp_h
| sort - connections
```

- First line — connections to internal, multicast or broadcast destinations, and `id_resp_p<10000` (destination port below 10000) to drop ephemeral-port noise.
- `dc(id_orig_h) AS clients` — how many different hosts connected.
- `values(id_resp_p) AS ports` — which ports it was contacted on.

**Result:**

```text
id_resp_h        clients  connections  ports         proto
10.0.1.1         1        161          3 53 137      icmp udp
224.0.0.252      1        7            5355          udp
10.0.1.255       1        6            137 138       udp
255.255.255.255  1        2            67            udp
10.0.1.254       1        2            67            udp
```

(`3` is not a port but ICMP type 3 "Destination unreachable". Zeek writes the ICMP type in the port field.)

**Double-check that there are no DC, file or mail services:**

```spl
index=zeek sourcetype=zeek:conn id_resp_p IN (88, 135, 139, 389, 445, 464, 636, 3268, 3389, 5985, 25, 110, 143, 465, 587, 993, 995)
| stats count BY id_resp_h id_resp_p
```

- `id_resp_p IN (...)` — destination port is one of the list. DC (88, 389, 464, 636, 3268), file (135, 139, 445), remote admin (3389, 5985), mail (25, 110, 143, 465, 587, 993, 995).

**Result:** `No results found.`

**Confirm the DNS server:**

```spl
index=zeek sourcetype=zeek:dns
| stats count dc(id_orig_h) AS clients values(proto) AS proto BY id_resp_h
| sort - count
```

- In dns.log, the side **that received the question** (`id_resp_h`) is the DNS server.

**Result:**

```text
id_resp_h        count  clients  proto
10.0.1.1         195    1        udp
188.165.200.156  31     1        tcp      ← !!
224.0.0.252      14     1        udp
10.0.1.255       12     1        udp
144.76.133.38    2      1        tcp      ← !!
130.255.78.223   1      1        tcp      ← !!
31.3.135.232     1      1        tcp      ← !!
62.113.203.99    1      1        tcp      ← !!
93.170.96.235    1      1        tcp      ← !!
```

**Reading the result:**

- **DNS server = 10.0.1.1** (the router), the same as DHCP said.
- **DHCP server = 10.0.1.254** (the same router).
- **No DC.** Not a single Kerberos (88) or LDAP (389) connection. The PC asked DNS 12 times for `_ldap._tcp.dc._msdcs.DOC-BROWN-GROUP.localdomain` (the SRV query that finds a DC) and **never got an answer**. Windows looked for a DC out of habit; there is none.
- **No file server.** No SMB (445) or NetBIOS session (139) connections. 137/138 are name announcements, not file sharing.
- **No internal web or mail server.** No 80/443/mail ports to internal destinations.
- **`224.0.0.252` and `10.0.1.255` are not servers** but LLMNR multicast and NetBIOS broadcast. They are in dns.log because Zeek also parses NetBIOS name queries (UDP 137) as DNS. Those rows show `qtype_name` `NIMLOC` (type 32), which in NetBIOS is the "NB (name)" query.
- **!! — the PC asked 6 external DNS servers over TCP.** A normal PC asks **the DNS server DHCP gave it (10.0.1.1)**, usually over **UDP**. Asking external DNS servers directly, and over TCP, is **the first big departure from the baseline**. Step D3 digs into it.

**Workgroup seen in NetBIOS (Arkime session detail or tshark):** the PC broadcast the **workgroup** name `DOC-BROWN-GROUP` and made itself the **master browser**. The master browser keeps the list of Windows PCs on the network; since this is the only Windows machine, it took the job itself. **A workgroup, not a domain = a home/small environment without AD**, confirmed again.

**Ticket entry:**

```text
[261119 0055, Sung] Identifying server roles (DNS, DHCP, DC, file/web/mail) - Found
```

### Step C7 — Protocols in use { #protocols }

**Goal:** list the protocols this network normally uses. Something not on the list, or a protocol on an unexpected port, is a warning sign.

**Arkime:** the **Protocols** list from step C2:

```text
tcp (328)  dns (188)  udp (174)  http (166)  tls (87)  http2 (24)  llmnr (7)  dhcp (2)  icmp (1)
```

**Splunk:**

```spl
index=zeek sourcetype=zeek:conn
| stats count BY proto service
| sort - count
```

- `proto` — transport (tcp, udp, icmp).
- `service` — the protocol Zeek identified **from the content**, not from the port.

**Result:**

```text
proto  service  count
udp    dns      169
tcp    http     157
tcp    ssl      87
tcp    -        51
tcp    dns      37     ← DNS over TCP
udp    dhcp     4
udp    -        4
icmp   -        1
```

**Reading the result:**

- **Normal picture:** DNS (UDP), HTTP, TLS (`ssl`), DHCP, NetBIOS, LLMNR — a typical single Windows PC behind a home router.
- **`tcp dns 37`** — 37 DNS connections over TCP: the external DNS servers from step C6. DNS normally uses UDP; TCP is for very large answers or server-to-server copies. A PC using TCP DNS is **unusual**.
- **`tcp - 51`** — TCP connections whose protocol Zeek could not identify. In this PCAP they were mostly **connections the browser opened in advance and never used** (state S1/S3, no data) and **failed TCP DNS connections** (130.255.73.90, 37.187.16.17, 85.159.213.210 — no answer / refused). Not an unknown protocol on an odd port.
- **`icmp 1`** — the PC telling the router "Port unreachable". Common noise when a DNS answer arrives late, after the PC has closed the port.
- Arkime's `http2 (24)` is HTTP/2 negotiated inside TLS (Zeek counts it as `ssl`).

**Ticket entry:**

```text
[261119 0100, Sung] Reviewing protocol distribution - Found
```

### Step C8 — What is the OS { #os }

**Goal:** knowing the OS tells the host operator what to look at (event logs, registry …). The clues are in several places.

**① User-Agent (easiest).** The self-introduction a program attaches to an HTTP request.

**Arkime:**

```text
ip.src == 10.0.1.95 && protocols == http
```

→ **SPIView** → **User-Agent** (`http.user-agent`) in the **http** section.

**Splunk:**

```spl
index=zeek sourcetype=zeek:http id_orig_h=10.0.1.95
| fillnull value="(none)" user_agent
| stats count BY user_agent
| sort - count
```

- `fillnull value="(none)" user_agent` — fill `(none)` into events that **have no** `user_agent` field. Without it, `stats` silently drops empty values and requests without a User-Agent vanish from the result. (Zeek logs loaded as TSV store an empty field as `-`.)

**Result:**

```text
user_agent                                                            count
Mozilla/5.0 (Windows NT 10.0; WOW64; Trident/7.0; rv:11.0) like Gecko  164
(none)                                                                 123   ← !!
Microsoft-CryptoAPI/10.0                                               9
Microsoft-WNS/10.0                                                     8
```

- `Windows NT 10.0` — **Windows 10** (or Server 2016 and later). For reference, `6.1` = Windows 7, `6.3` = Windows 8.1.
- `WOW64` — a **32-bit program** running on 64-bit Windows, i.e. **64-bit Windows 10**.
- `Trident/7.0; rv:11.0` — **Internet Explorer 11**.
- `Microsoft-CryptoAPI/10.0` — what Windows uses when checking certificate status (OCSP).
- `Microsoft-WNS/10.0` — used by Windows 10 Start-menu **live tiles** (news, weather).
- **`(none)` 123 — requests with no User-Agent at all.** Browsers and Windows components almost always send one. This becomes the most important clue in Part D.

**② Zeek software.log:**

```spl
index=zeek sourcetype=zeek:software
| table host software_type name unparsed_version
```

- The **software list** Zeek worked out from User-Agents and similar.

```text
host       software_type  name                 unparsed_version
10.0.1.95  HTTP::BROWSER  Microsoft-WNS        Microsoft-WNS/10.0
10.0.1.95  HTTP::BROWSER  MSIE                 Mozilla/5.0 (Windows NT 10.0; WOW64; Trident/7.0; rv:11.0) like Gecko
10.0.1.95  HTTP::BROWSER  Microsoft-CryptoAPI  Microsoft-CryptoAPI/10.0
```

**③ Other clues (Arkime session detail / tshark):**

- **DHCP Vendor class `MSFT 5.0`** (step C4) — Windows.
- **OS version `10.0` in the NetBIOS browser announcement** — broadcast by the PC. Windows 10.
- **IP TTL 128** — the default TTL (remaining hops) of packets the PC sends is 128. Windows uses 128; Linux and macOS usually 64. In Arkime's packet hex it is the 9th byte of the IP header (offset `0x16` in the frame; `80` on the second line of the C5 example).
- **DNS query names** — `dns.msftncsi.com` (Windows internet-connectivity check), `win10.ipv6.microsoft.com`, `client.wns.windows.com`, `tile-service.weather.microsoft.com` — all queries Windows 10 makes at start-up.
- **Office domains** — `officeclient.microsoft.com`, `nexus.officeapps.live.com`, `messaging.office.com` → **Microsoft Office is installed and was started.** This becomes important in step D2.

**Reading the result:** **DELOREAN-PC = 64-bit Windows 10, IE11, Microsoft Office installed.** No sign of any other OS (Mac, Linux, Android).

**Ticket entry:**

```text
[261119 0105, Sung] Identifying operating system and software of 10.0.1.95 - Found
```

### Step C9 — External communications overview { #external }

**Goal:** see the big picture of who outside the PC talks to and how much. Most of it is normal services like Microsoft and Google; we are looking for the **strangers** mixed in.

**Arkime:**

```text
ip.src == 10.0.1.95 && ip.dst != 10.0.0.0/8 && ip.dst != 224.0.0.0/4 && ip.dst != 255.255.255.255
```

→ **SPIView** → **Dst IP** and **Dst Port** in General, **Host** in the **dns** section and **Host** (SNI) in the **tls** section.

**Splunk — summary per external destination:**

```spl
index=zeek sourcetype=zeek:conn id_orig_h=10.0.1.95 NOT (id_resp_h=10.0.0.0/8 OR id_resp_h=172.16.0.0/12 OR id_resp_h=192.168.0.0/16 OR id_resp_h=224.0.0.0/4 OR id_resp_h=255.255.255.255)
| stats count AS connections sum(orig_bytes) AS bytes_out sum(resp_bytes) AS bytes_in values(id_resp_p) AS ports values(service) AS service BY id_resp_h
| sort - connections
```

- `NOT (...)` — destination is **not** internal, multicast or broadcast, i.e. truly external.
- `sum(orig_bytes) AS bytes_out` — total bytes the PC **sent** (important for exfiltration).
- `sum(resp_bytes) AS bytes_in` — total bytes the other side **sent** (important for downloads).

**Result (top 15 of 87 external IPs, 332 connections):**

```text
id_resp_h        connections  bytes_out  bytes_in   ports  service
35.198.166.240   34           25,484     2,350,698  80     http        ← !!
188.165.200.156  31           961        6,231      53     dns         ← !!
23.56.3.183      20           40,742     281,646    80     http -
13.107.4.52      19           6,424      59,933     80     http
198.232.125.32   18           8,798      253,507    80     http -
52.183.114.173   17           108,232    81,852     443    ssl
13.107.21.200    11           19,681     290,534    443    ssl
204.79.197.200   11           22,415     289,096    443    ssl
104.43.139.11    6            7,352      41,922     443    ssl
173.194.206.94   6            4,829      336,724    80     http -
34.206.190.189   6            24,063     10,240     80     http
173.194.206.154  5            7,129      175,185    443    ssl
65.52.108.254    4            9,815      15,568     443    ssl
23.79.207.65     4            852        18,427     80     http
23.73.31.19      4            1,824      27,469     443    ssl
```

**Outbound ports:**

```spl
index=zeek sourcetype=zeek:conn id_orig_h=10.0.1.95 NOT (id_resp_h=10.0.0.0/8 OR id_resp_h=224.0.0.0/4 OR id_resp_h=255.255.255.255)
| stats count BY proto id_resp_p
```

```text
proto  id_resp_p  count
tcp    80         196
tcp    443        90
tcp    53         46     ← !!
```

**Site names (TLS SNI):**

```spl
index=zeek sourcetype=zeek:ssl
| stats count BY server_name id_resp_h
| sort - count
```

- `server_name` — the **name of the site** the browser announces when starting a TLS connection (SNI). Visible even though the content is encrypted.

**Result (summary):** `www.bing.com`, `watson.telemetry.microsoft.com`, `messaging.office.com`, `securepubads.g.doubleclick.net`, `client.wns.windows.com`, `cdn.onenote.net`, `nexus.officeapps.live.com`, `login.live.com` … — **all Microsoft, Google and ad services.** No odd certificates and no TLS on odd ports.

**Reading the result:**

- External traffic uses only three ports: **80, 443 and 53 (TCP)**. 80/443 are ordinary, but there are **46 TCP 53 connections**.
- **35.198.166.240 is #1 by connections and by bytes received (about 2.35 MB).** Receiving that much over plaintext HTTP from something that is not Microsoft or Google is suspicious.
- **188.165.200.156** is the external DNS server from step C6: 31 connections on TCP 53.
- TLS is all big legitimate services → the suspicious traffic in this case is in **plaintext HTTP and TCP DNS**.
- Zeek's notice.log has 7 `SSL::Invalid_Server_Cert`, but they are all Microsoft/Google certificates, failing with "unable to get local issuer certificate" (the sensor lacks a root-certificate store). **Sensor-side noise**, unrelated to the incident.

**Find rare domains:**

```spl
index=zeek sourcetype=zeek:dns qtype_name=A
| stats count BY query
| sort count
```

- `qtype_name=A` — only queries for IPv4 addresses (drops NetBIOS and SRV noise).
- `sort count` — **fewest first.** Domains looked up only once or twice float to the top. Malicious domains often hide there.

**Result (some of those looked up only once):** `jgbennett.com`, `contentstorage.osi.office.net`, `officeclient.microsoft.com`, `messaging.office.com`, `www.singlemoms.org`, dozens of ad domains … and, not at the top but notable, **`amellet.bit` 37 times** (all TCP, external servers).

**Ticket entry:**

```text
[261119 0110, Sung] Reviewing external communications overview - Further Analysis Required
```

Why `Further Analysis Required`: we found suspicious candidates in the external traffic (35.198.166.240, TCP DNS, requests without a User-Agent) and will confirm them in Part D.

### Step C10 — Baseline summary { #baseline-summary }

| Item | Value |
|---|---|
| Capture | 2017-10-21 04:51:53 – 05:03:52 UTC, 505 sessions (Arkime) / 510 connections (Zeek) |
| Internal range | 10.0.1.0/24 (mask 255.255.255.0), broadcast 10.0.1.255 |
| Devices | 2 — 1 PC, 1 router |
| PC | 10.0.1.95 DELOREAN-PC, MAC 60:a4:4c:6a:b2:1f (ASUSTek), 64-bit Windows 10, IE11, MS Office, workgroup DOC-BROWN-GROUP |
| Router / gateway | 10.0.1.1, MAC 00:04:5a:f8:1a:ac (Linksys) |
| DNS server | 10.0.1.1 (UDP 53), suffix `localdomain` |
| DHCP server | 10.0.1.254 (same device as the router), 30-minute lease |
| DC / file / web / mail server | None (workgroup environment, no Kerberos, LDAP, SMB or mail ports) |
| Other devices (printers etc.) | None |
| Internal protocols | DHCP, DNS (UDP), NetBIOS 137/138, LLMNR 5355, ICMP |
| External protocols | HTTP 80, TLS 443, **DNS over TCP 53 (abnormal)** |
| External communications | 87 external IPs — mostly Microsoft, Google, ads. Exceptions: 35.198.166.240 (HTTP 2.35 MB), external DNS servers (TCP 53) |
| Inbound | None |

**Departures from the baseline (checked in Part D):**

1. 123 HTTP requests with **no** User-Agent
2. Queries to **external DNS servers over TCP** (46 connections)
3. An unfamiliar IP, 35.198.166.240, with a large plaintext HTTP download
4. A session spike around 05:02:30

---

## Part D — Finding the malicious activity { #malicious }

We follow the four departures from the baseline one by one, in the order **the strangest thing → what came before and after it**.

### Step D1 — Who sends HTTP requests without a User-Agent { #no-ua }

**Goal:** step C8 found 123 requests without a User-Agent. Browsers and Windows components almost always send one, so the ones without are likely **custom-built programs (including malware)**.

**Arkime:**

```text
protocols == http && http.user-agent != EXISTS!
```

- `http.user-agent` — the User-Agent field of HTTP requests.
- `!= EXISTS!` — sessions where that field **does not exist at all**. (`== EXISTS!` means sessions where it does.)

→ **SPIView** → **Host** in the **http** section, and **Dst IP** in General.

**Splunk:**

```spl
index=zeek sourcetype=zeek:http NOT user_agent=*
| fillnull value="-" host
| stats count AS requests dc(uid) AS connections values(method) AS method values(version) AS http_ver BY host id_resp_h
| sort - requests
```

- `NOT user_agent=*` — `user_agent=*` means "the field has any value at all". Adding `NOT` keeps only events **without the field**. (For TSV Zeek logs search `user_agent="-"`.)
- `fillnull value="-" host` — fill `-` into requests that also have no Host header, so they are not dropped from the result.
- `dc(uid)` — Zeek's `uid` is the **unique ID of one connection**. Distinct uids = number of connections.
- `values(version)` — HTTP version.

**Result:**

```text
host                     id_resp_h        requests  connections  method  http_ver
www.msftconnecttest.com  13.107.4.52      73        19           GET     1.1
amellet.bit              35.198.166.240   39        34           POST    1.0
-                        (6 ad servers)   8         8            -       1.0
ocsp.digicert.com        72.21.91.29      2         2            POST    1.0
jgbennett.com            107.180.41.148   1         1            GET     1.1
```

**Reading the result:**

- **`jgbennett.com`, 1** — a GET that looks like it fetched one file. Step D2.
- **`amellet.bit`, 39** — nothing but HTTP/1.0 POSTs, 39 of them, to an unfamiliar top-level domain `.bit`. Steps D3 and D4.
- **`www.msftconnecttest.com`, 73** — the address Windows uses to check "am I online?". But the real Windows check (NCSI) normally sends User-Agent `Microsoft NCSI` and does not ask dozens of times within seconds. Step D6.
- **`-`, 8** — rows with no Host and no method. Opening them shows only **`408 Request Timeout` responses that ad servers sent while closing idle connections**. No request, therefore no User-Agent → **normal noise**.
- **`ocsp.digicert.com`, 2** — certificate revocation checks (OCSP) sent as POST. **Normal** Windows behaviour.

**Ticket entry:**

```text
[261119 0115, Sung] Reviewing HTTP requests without User-Agent - Found
```

### Step D2 — First malicious event: an `.exe` download without a User-Agent { #exe-download }

**Goal:** confirm what was downloaded from `jgbennett.com`, when and how, and record the file hash.

**Arkime:**

```text
host.http == jgbennett.com
```

- `host.http` — the value of the HTTP request's Host header.

→ **Sessions** → **+** on the session → session detail. View the packet area as **natural** (human-readable text).

**Result (session detail):**

```text
2017/10/21 04:52:47 UTC  10.0.1.95:49691 -> 107.180.41.148:80

GET /3cgconsulting.com/30_723bio_152.exe HTTP/1.1
Host: jgbennett.com
Connection: Keep-Alive

HTTP/1.1 200 OK
Date: Sat, 21 Oct 2017 04:52:49 GMT
Server: Apache
Last-Modified: Thu, 19 Oct 2017 12:45:16 GMT
Content-Length: 61440
Content-Type: application/x-msdownload

MZ......................@...............!..L.!This program cannot be run in DOS mode.
```

**Splunk:**

```spl
index=zeek sourcetype=zeek:http host="jgbennett.com"
| eval t=strftime(ts, "%Y-%m-%d %H:%M:%S")
| table t uid id_orig_h id_orig_p id_resp_h id_resp_p method host uri user_agent status_code resp_mime_types response_body_len resp_fuids
```

- `resp_fuids` — the **ID of the file** received in the response. This ID links to files.log.

```spl
index=zeek sourcetype=zeek:files mime_type="application/x-dosexec"
| eval t=strftime(ts, "%H:%M:%S")
| table t fuid tx_hosts rx_hosts source mime_type seen_bytes total_bytes md5 sha1
```

- `mime_type="application/x-dosexec"` — the file type Zeek decided from **the first bytes of the content**. `x-dosexec` is a Windows executable (EXE/DLL). A renamed extension does not fool it.
- `tx_hosts` / `rx_hosts` — the side that **sent** / **received** the file.
- `seen_bytes` / `total_bytes` — bytes actually seen / original size. Equal means **the whole file was captured**, which is what makes the hash trustworthy.

```spl
index=zeek sourcetype=zeek:pe
| eval compiled=strftime(compile_ts, "%Y-%m-%d %H:%M:%S")
| table id machine compiled os subsystem is_64bit uses_aslr uses_dep has_cert_table section_names
```

- zeek:pe — the result of reading a Windows executable's header.
- `compile_ts` — the **compile time** written in the executable (can be faked, but useful).
- `has_cert_table` — whether it has a **digital signature**.

**Result:**

```text
t                    id_orig_h  id_orig_p  id_resp_h       method  host           uri                                    user_agent  status_code  resp_mime_types        response_body_len
2017-10-21 04:52:47  10.0.1.95  49691      107.180.41.148  GET     jgbennett.com  /3cgconsulting.com/30_723bio_152.exe   (none)      200          application/x-dosexec  61440

t         tx_hosts        rx_hosts   mime_type              seen_bytes  total_bytes  md5                               sha1
04:52:47  107.180.41.148  10.0.1.95  application/x-dosexec  61440       61440        658c30fcd1508a65df8b9b9b397a9459  fe4116d0e66350f54042361e3a87c942ee98529d

machine  compiled             os          subsystem    is_64bit  uses_aslr  uses_dep  has_cert_table  section_names
I386     2017-07-16 07:29:21  Windows XP  WINDOWS_GUI  false     false      true      false           .text .data
```

**Getting the SHA256.** By default Zeek computes only MD5 and SHA1. Team reporting and threat-intel sharing usually use SHA256, so extract the file and compute it yourself. Download the file from the Arkime session detail, or extract all HTTP files with tshark on the analysis VM.

```bash
mkdir -p http_objects
tshark -r 2017-10-21-traffic-analysis-exercise.pcap --export-objects http,http_objects
sha256sum http_objects/30_723bio_152.exe
file http_objects/30_723bio_152.exe
```

- `--export-objects http,folder` — save every file transferred over HTTP into that folder. **Never run them.**
- `file file` — tells you the file type from its content.

```text
a56876fd456d0737eecc4a8bbe3154b35314ab28accb29abf0df7c518c81a490  http_objects/30_723bio_152.exe
http_objects/30_723bio_152.exe: PE32 executable (GUI) Intel 80386, for MS Windows, 2 sections
```

**Reading the result:**

- **No User-Agent.** The request has only two header lines, `Host` and `Connection`. A person downloading with the browser would have sent IE11's User-Agent. A **non-browser program** (script, macro, other malware) fetched it.
- **No Referer either.** It was not reached by clicking a link on a web page; the program **knew the address directly**.
- The path uses **another domain name as a folder** (`/3cgconsulting.com/…`) — a common shape when malicious files are planted on a hacked web server.
- The file was **fully captured** (`seen_bytes = total_bytes = 61440`) and starts with `MZ` = Windows executable. `Content-Type: application/x-msdownload` is also an executable type.
- **32-bit GUI program, unsigned, only two sections (`.text`, `.data`).** Normal programs usually have more sections and a signature. A small (60 KB) file with few sections is often a **packer wrapping the real malware**.
- The server's `Last-Modified` is **2017-10-19** (two days earlier) — a freshly uploaded file.

**What happened just before?** Look at DNS queries from 30 seconds before the download.

```spl
index=zeek sourcetype=zeek:dns qtype_name=A ts>=1508561520 ts<=1508561570
| eval t=strftime(ts, "%H:%M:%S")
| table t query answers
| sort t
```

- `ts>=1508561520 ts<=1508561570` — a time range in epoch seconds. 1508561520 = 04:52:00 and 1508561570 = 04:52:50 (UTC). The same instant regardless of time-zone settings, so it is precise.

**Result:**

```text
t         query                          answers
04:52:01  www.bing.com                   13.107.21.200 204.79.197.200
04:52:02  tile-service.weather...        23.79.207.65
04:52:40  contentstorage.osi.office.net  23.79.196.182
04:52:42  fs.microsoft.com               23.79.211.200
04:52:42  messaging.office.com           104.43.139.11
04:52:46  nexus.officeapps.live.com      104.43.140.223
04:52:46  officeclient.microsoft.com     137.116.74.190
04:52:47  jgbennett.com                  107.180.41.148    ← .exe download 1 s later
04:52:52  nexus.officeapps.live.com      104.43.140.223
04:52:52  nexusrules.officeapps.live.com 40.117.144.240
```

**Reading the result:** from 04:52:40 come the queries **Microsoft Office** makes when it starts (`officeclient`, `nexus.officeapps`, `messaging.office`), and **one second later** the PC looks up `jgbennett.com` and downloads the `.exe`. That matches the common infection pattern where opening an Office document lets a **macro or script inside the document download a file**. The document itself is not in the capture (no mail, webmail or file-download traces), so this is **"assessed"**, and it becomes a lead for the host operator.

**Ticket entries:**

```text
[261119 0120, Sung] Reviewing EXE download from jgbennett.com - Found
[261119 0125, Sung] Reviewing activity immediately before EXE download (DNS) - Found
```

### Step D3 — The `.bit` domain, external DNS servers and TCP DNS { #bit-dns }

**Goal:** see what the "queries to external DNS servers over TCP" from steps C6 and C9 asked.

**Arkime:**

```text
port.dst == 53 && ip.protocol == tcp
```

- `port.dst == 53` — destination port 53 (DNS).
- `ip.protocol == tcp` — TCP only. DNS is normally UDP, so we isolate TCP.

→ **SPIView** → **Dst IP** in General, **Host** in the **dns** section.

```text
host.dns == *.bit
```

- `host.dns` — the name asked in DNS. `*` is "any characters" — every name ending in `.bit`.

**Splunk — what was asked:**

```spl
index=zeek sourcetype=zeek:dns query="*.bit"
| eval t=strftime(ts, "%H:%M:%S")
| table t id_orig_h id_resp_h proto query qtype_name rcode_name answers TTLs
| sort t
```

**Result (first part of 37 rows):**

```text
t         id_resp_h        proto  query        rcode_name  answers         TTLs
04:53:52  130.255.78.223   tcp    amellet.bit  NOERROR     (none)
04:54:03  188.165.200.156  tcp    amellet.bit  NOERROR     35.198.166.240  400
04:54:44  144.76.133.38    tcp    amellet.bit  NOERROR     35.198.166.240  133
04:54:46  62.113.203.99    tcp    amellet.bit  NOERROR     (none)
04:54:47  93.170.96.235    tcp    amellet.bit  NOERROR     (none)
04:54:58  31.3.135.232     tcp    amellet.bit  NOERROR     35.198.166.240  343
04:55:00  188.165.200.156  tcp    amellet.bit  NOERROR     35.198.166.240  342
...       (every 2–3 s until 04:56:11, mostly 188.165.200.156)
05:00:52  188.165.200.156  tcp    amellet.bit  NOERROR     35.198.166.240
05:02:05  188.165.200.156  tcp    amellet.bit  NOERROR     35.198.166.240
```

**Splunk — which DNS servers it connected to, and whether it worked:**

```spl
index=zeek sourcetype=zeek:conn proto=tcp id_resp_p=53
| stats count min(ts) AS first BY id_resp_h conn_state
| eval first=strftime(first, "%H:%M:%S")
| sort first
```

- `conn_state` — Zeek's connection state. `SF` = opened and closed normally, `S0` = SYN sent but **no reply**, `REJ` = **refused** (RST), `RSTRH` = the responder side reset the connection.

**Result:**

```text
id_resp_h        conn_state  count  first
130.255.78.223   SF          1      04:53:52
130.255.73.90    S0          2      04:53:53
188.165.200.156  SF          31     04:54:03
144.76.133.38    SF          2      04:54:44
62.113.203.99    SF          1      04:54:46
93.170.96.235    SF          1      04:54:46
85.159.213.210   S0          2      04:54:47
37.187.16.17     REJ         3      04:54:57
31.3.135.232     SF          1      04:54:58
130.255.73.90    RSTRH       1      04:55:08
85.159.213.210   RSTRH       1      04:56:03
```

**Reading the result:**

- **Only one name was asked: `amellet.bit`** (37 times).
- **`.bit` is not a top-level domain of the ordinary internet.** It is registered on the **Namecoin** blockchain, so ordinary DNS servers (the router, the ISP, Google DNS) cannot answer it. That is why the malware **carries its own list of DNS servers that know `.bit`** and asks them in turn. It actually tried **9**: 3 gave empty answers (NOERROR with no answers), 3 could not be connected to, and 3 returned `35.198.166.240`.
- **Why does malware use `.bit`?** Ordinary domains can be seized or blocked by registrars or authorities; Namecoin names are much harder to take down. It is a way for the attacker **not to lose the C2 address**.
- **Why TCP?** The only explanation is that the malware is built that way. The result is that it **completely bypassed** the router's DNS (10.0.1.1), and anyone watching only the company DNS server **would not see these queries at all**. So "internal PC → external TCP 53" is a good detection point (Part E, sid 1000204).
- The answer was always the single `35.198.166.240`. The TTL (how long the answer may be cached) was 400 s the first time; after that each server returned whatever remained in its cache, so the values vary (133, 343, 342 …). The responses also carried `amellet.bit`'s name-server information (`a.dnspod.com` and others).
- **It asks again every time.** It re-queries DNS right before each C2 connection (D4), so the times of the 37 queries and the 34 C2 connections almost overlap.

**Ticket entry:**

```text
[261119 0130, Sung] Reviewing DNS over TCP to external resolvers - Found
```

### Step D4 — C2 traffic: HTTP POSTs to `amellet.bit` { #c2 }

**Goal:** see what was exchanged with 35.198.166.240.

**Arkime:**

```text
host.http == amellet.bit
```

→ **Sessions**: **34**. **+** on any session → natural view.

**Result (first session 04:54:03, 10.0.1.95:57622 → 35.198.166.240:80):**

```text
POST /a/ HTTP/1.0
Host: amellet.bit
Content-Length: 1584

`Z8;..QK.:...=.S....*...2n..&......i'..D,h.#..T-L...X....{..kWf9A.r...   (1,584 unreadable bytes)

HTTP/1.0 200 OK
X-Powered-By: PHP/5.3.3
Content-type: text/html
Content-Length: 158064
Date: Sat, 21 Oct 2017 04:47:14 GMT
Server: lighttpd/1.4.45

.5W..l1..j....t....qy..b..OJT.W.......N...E.c...N....6j.wE+.c)...   (unreadable bytes)
```

**Splunk — each request:**

```spl
index=zeek sourcetype=zeek:http host="amellet.bit"
| sort ts
| streamstats current=f last(ts) AS prev_ts
| eval t=strftime(ts, "%H:%M:%S"), gap=round(ts-prev_ts, 1)
| table t id_orig_p method uri version status_code request_body_len response_body_len gap
```

- `sort ts` — sort by time. `streamstats` calculates **from top to bottom**, so sort first.
- `streamstats current=f last(ts) AS prev_ts` — attach **the previous row's `ts`** to each row. `current=f` means "calculate without the current row".
- `gap=round(ts-prev_ts, 1)` — the **interval (seconds)** from the previous request, to one decimal. The basic method for finding beacons (signals at a regular interval).
- `request_body_len` / `response_body_len` — size of the **body** sent / received (headers excluded).

**Result (39 rows):**

```text
t         id_orig_p  uri     ver  status  req_len  resp_len  gap
04:54:03  57622      /a/     1.0  200     1584     157261
04:54:44  61982      /a/     1.0  200     1584     132464    41.1
04:54:59  55225      /html/  1.0  200     240      153808    14.6
04:55:01  63017      /html/  1.0  200     240      116737    1.8
04:55:03  54665      /html/  1.0  200     368      1168      2.9
04:55:06  53280      /html/  1.0  200     400      4752      2.7
04:55:08  53132      /html/  1.0  200     400      17248     1.4
04:55:09  60208      /html/  1.0  200     400      256752    1.6
04:55:12  53918      /html/  1.0  200     400      43840     2.5
04:55:14  63963      /html/  1.0  200     400      250688    2.3
04:55:17  51539      /html/  1.0  200     400      17552     2.6
04:55:18  58180      /html/  1.0  200     400      225872    1.7
04:55:33  54278      /html/  1.0  200     384      448       14.5
04:55:35  59593      /html/  1.0  200     400      4592      1.8
04:55:37  64718      /html/  1.0  200     432      1168      2.2
04:55:39  58093      /html/  1.0  200     432      250688    2.2
04:55:42  49338      /html/  1.0  200     432      43840     2.8
04:55:44  59990      /html/  1.0  200     432      4752      2.3
04:55:46  54150      /a/     1.0  200     1680     80        1.7
04:55:46  54149      /html/  1.0  200     432      256752    0.2
04:55:49  56621      /html/  1.0  200     432      225872    2.6
04:55:51  58354      /html/  1.0  200     432      17248     2.5
04:55:53  53211      /html/  1.0  200     224      80        1.6
...       (80-byte responses continue until 04:56:11; 5 connections carry 2 POSTs each)
05:00:52  49513      /html/  1.0  200     432      76752     281.4
05:02:05  61115      /html/  1.0  200     432      77248     72.5
```

**Totals:**

```spl
index=zeek sourcetype=zeek:http host="amellet.bit"
| stats count AS posts dc(uid) AS connections sum(request_body_len) AS sent sum(response_body_len) AS received min(ts) AS first max(ts) AS last BY uri
| eval first=strftime(first, "%H:%M:%S"), last=strftime(last, "%H:%M:%S")
```

```text
uri     posts  connections  sent    received   first     last
/a/     3      3            4,848   289,805    04:54:03  04:55:46
/html/  36     31           18,144  2,053,089  04:54:59  05:02:05
```

**Zeek weird.log:**

```spl
index=zeek sourcetype=zeek:weird
| stats count BY name id_resp_h
```

```text
name                               id_resp_h          count
unexpected_multiple_HTTP_requests  35.198.166.240     5
inflate_failed                     (ad/CDN servers)   5
possible_split_routing             23.56.3.183        1
```

**Reading the result:**

- **Direction:** the **PC always connected to the server first** (outbound). Common for C2, because firewalls usually do not block outgoing connections.
- **HTTP/1.0, no User-Agent, no Content-Type.** Normal programs on Windows 10 in 2017 almost all use HTTP/1.1 and send a User-Agent. Sending a minimal hand-made header set is **the shape of malware**.
- **Both directions are encrypted.** Neither request nor response bodies contain meaningful text. The response claims `Content-type: text/html` but is not HTML (Zeek's `resp_mime_types` is empty = no known format).
- **Two paths: `/a/` and `/html/`.** `/a/` (send 1,584 bytes, receive 130–160 KB) looks like **check-in and configuration**, `/html/` like **downloading modules or extra data**. `/html/` response sizes **256,752 / 250,688 / 225,872 / 43,840 / 17,248 / 4,752 bytes each appear twice**: the same module set was **downloaded twice**.
- **About 2.34 MB received, about 23 KB sent.** Far more was received → the main activity was **downloading extra capability (modules)**. The 23 KB sent could contain PC information or stolen data, but it is encrypted, so **the content cannot be confirmed**.
- **`unexpected_multiple_HTTP_requests` ×5** — HTTP/1.0 is one request per connection, yet 5 connections carried two POSTs. More evidence of hand-written HTTP code that bends the rules. (The other weird entries are noise from ad-server compression errors and similar.)
- **The server clock is about 6 min 49 s slow.** The packet time is 04:54:03 but the server's `Date` is 04:47:14. A small fingerprint for finding the same C2 server in other incidents.
- Server `lighttpd/1.4.45` + `X-Powered-By: PHP/5.3.3` — PHP 5.3.3 dates from 2010. Running a C2 panel on an old PHP is common.

**Malware family:** looking up a `.bit` C2 address through external DNS and downloading modules with encrypted POSTs matches **Chthonic, a Zeus-family banking trojan**. Public analysis of this exercise also identified Chthonic. But we are on a closed network and did not look up the hash, so we write **"consistent with Chthonic — unconfirmed"**.

**Ticket entries:**

```text
[261119 0135, Sung] Reviewing C2 HTTP sessions to amellet.bit (35.198.166.240) - Found
[261119 0140, Sung] Assessing malware family from C2 pattern - Further Analysis Required
```

### Step D5 — C2 timing: is it a beacon? { #c2-timing }

**Goal:** see whether the C2 calls in at a regular interval (a beacon). Knowing the interval tells you what to expect when watching the same PC later.

From the `gap` column in step D4:

```text
04:54:03 – 04:54:44   two /a/ check-ins (41 s apart)
04:54:59 – 04:56:11   34 /html/ requests, 0.2–4 s apart (bulk module download)
04:56:11 – 05:00:52   4 min 41 s quiet
05:00:52, 05:02:05    two /html/ requests (73 s apart)
```

**Reading the result:** within the 12-minute capture **there is no regular beacon interval.** Most of it is the **bulk download of configuration and modules** right after infection, then only two contacts at 05:00:52 and 05:02:05. A longer capture would be needed to establish the beacon interval. The ticket says "no stable beacon interval within 12-min capture".

**Ticket entry:**

```text
[261119 0145, Sung] Measuring C2 check-in intervals - Found
```

### Step D6 — A flood of User-Agent-less connectivity checks (`msftconnecttest`) { #connecttest }

**Goal:** check the 73 `www.msftconnecttest.com` requests from step D1.

**Arkime:**

```text
host.http == www.msftconnecttest.com
```

**Splunk:**

```spl
index=zeek sourcetype=zeek:http host="www.msftconnecttest.com"
| eval minute=strftime(ts, "%H:%M")
| stats count BY minute user_agent
```

- `eval minute=strftime(ts, "%H:%M")` — drop the seconds to make a field for grouping **by minute**.

**Result:**

```text
minute  user_agent  count
04:55   (none)      6
04:56   (none)      1
05:00   (none)      18
05:01   (none)      42
05:02   (none)      6
```

A request in the session detail looks like this:

```text
GET /connecttest.txt HTTP/1.1
Connection: Keep-Alive
Host: www.msftconnecttest.com
```

**Reading the result:**

- Windows 10's real connectivity check (NCSI) normally sends `User-Agent: Microsoft NCSI` and runs once or twice when the network changes. Here there is no User-Agent and up to **42 per minute**.
- The times **coincide with C2 activity**: 04:55 (during module download), 05:00:51–05:02 (around the 05:00:52 and 05:02:05 C2 POSTs).
- The header shape (`Connection` and `Host` only) also resembles the `.exe` download request in step D2.
- So it looks like **the malware checking for internet access before contacting the C2**. Because it uses a legitimate Microsoft address this alone does not prove maliciousness, so it stays **assessed**, and the host operator is asked to confirm **which process made the connections**.

**Ticket entry:**

```text
[261119 0150, Sung] Reviewing repeated msftconnecttest.com requests without User-Agent - Further Analysis Required
```

### Step D7 — The 05:02:30 spike and a tech support scam pop-up { #tech-support-scam }

**Goal:** look at the 05:02:30 spike in step C1's graph and the last suspicious domains left over from D1.

**Arkime:**

```text
ip.src == 10.0.1.95 && host.http == [www.singlemoms.org, helpcenterforall.bid, krep2010123.tk]
```

- `== [a, b, c]` — equal to any item in the list. Shorter than several `||`.

**Splunk:**

```spl
index=zeek sourcetype=zeek:http host IN ("www.singlemoms.org", "helpcenterforall.bid", "krep2010123.tk")
| eval t=strftime(ts, "%H:%M:%S")
| table t id_orig_p id_resp_h method host uri referrer status_code resp_mime_types response_body_len
| sort t
```

- `referrer` — the Referer header, where the browser says "which page I came from". The most important field when rebuilding a web chain.

**Result:**

```text
t         id_resp_h       method  host                  uri                         referrer                                 status  mime              len
05:02:26  104.18.61.210   GET     www.singlemoms.org    /                           -                                        200     text/html         71878
05:02:28  104.18.61.210   GET     www.singlemoms.org    /states.swf                 http://www.singlemoms.org/               200     x-shockwave-flash 31838
05:02:30  104.18.61.210   GET     www.singlemoms.org    /states.xml                 http://www.singlemoms.org/states.swf     200     text/plain        6137
...
05:03:25  162.244.35.33   GET     helpcenterforall.bid  /index/?MCPKV8              -                                        302     -                 0
05:03:25  162.244.35.36   GET     krep2010123.tk        /?number=888-779-0939       -                                        200     text/html         4374
05:03:26  162.244.35.36   GET     krep2010123.tk        /landinf/defender.png       http://krep2010123.tk/?number=888-...    200     image/png         13386
05:03:26  162.244.35.36   GET     krep2010123.tk        /files/css                  http://krep2010123.tk/?number=888-...    200     text/plain        18
05:03:31  162.244.35.36   GET     krep2010123.tk        /favicon.ico                -                                        404     text/html         169
05:03:31  162.244.35.36   GET     krep2010123.tk        /landinf/err.mp3            http://krep2010123.tk/?number=888-...    206     audio/mpeg        251342
```

**Finding why it went to `helpcenterforall.bid`.** The Referer is empty, so Zeek alone cannot say where it came from. You need the **content** of the page opened just before, `www.singlemoms.org/`. In Arkime open the `host.http == www.singlemoms.org && http.uri == /` session (natural) and use the browser's find (Ctrl+F) for `helpcenter`. This response was not gzip-compressed, only chunked, so it reads as-is with the odd chunk-size number in between.

**Result (script at the end of the page, with line breaks and comments added):**

```javascript
function checkTarget(a){
  if(!getCookie("popundr")){                               // if there is no "popundr" cookie (first time only)
    doOpen("http://helpcenterforall.bid/index/?MCPKV8");   // open a new window and send it to this address
    setCookie("popundr",1,864e5)                           // keep the cookie for 24 h (86,400,000 ms)
  }
}
...
document.addEventListener("click", checkTarget, !1)       // run checkTarget on any click on the page
PopWin.blur(); _Top.window.focus()                         // hide the new window "behind" the current one (pop-under)
```

**Text of the `krep2010123.tk` page (HTML tags removed):**

```text
Security Warning
Windows Defender Alert : Zeus Virus Detected In Your Computer !!
Please Do Not Shut Down or Reset Your Computer.
The following data will be compromised if you continue: 1. Passwords 2. Browser History
3. Credit Card Information 4.Local Hard Disk Files.
...
Call Microsoft Technical Department: 888-779-0939 (Toll Free)
```

**Reading the result:**

- **What the 05:02:30 spike is:** the user opened `www.singlemoms.org` in IE11. The page pulled in **dozens of ad and analytics domains** at once (media.net, doubleclick, openx, addthis, statcounter …), so sessions bunched up. That by itself is what an ad-heavy site looks like.
- **But a "pop-under" script was hidden at the end of the page.** On the user's **first click anywhere** on the page it opens a new window, sends it to `helpcenterforall.bid`, and **hides that window behind** the current one. That is why the Referer was empty (the address was changed from a blank `about:blank` window).
- 05:03:25 the user clicks → `helpcenterforall.bid` sends a **302** to `krep2010123.tk/?number=888-779-0939` → a **fake Windows Defender alert** page, a shield image (`defender.png`), an **alarm sound** (`err.mp3`, 251 KB), and **"Call Microsoft on 888-779-0939"**.
- This is a **tech support scam**. Calling the number gets a fake agent who has you install a remote-access tool and then takes money or steals information. **It is not a malware infection**, but if the user called or allowed remote access it becomes **a second incident**. Something the host operator and the user must confirm.
- A funny coincidence: the fake alert says "**Zeus** Virus Detected", and this PC really was running **Zeus-family (Chthonic-like)** malware. It is just fixed wording on the scam page, unrelated to any real detection.
- **The two events are separate.** `.exe` → C2 (04:52–05:02) and website pop-under → scam page (05:02–05:03) show no trace of a link. Put both in one ticket, but make it clear they are separate.

**Ticket entries:**

```text
[261119 0155, Sung] Reviewing session spike at 05:02:30 (www.singlemoms.org and ad networks) - Found
[261119 0200, Sung] Reviewing redirect to helpcenterforall.bid / krep2010123.tk (tech support scam) - Found
```

### Step D8 — Scope: other PCs, lateral movement, exfiltration { #scope }

**Goal:** check whether other PCs were hit, whether it spread internally (lateral movement), and whether information left (exfiltration).

```spl
index=zeek sourcetype=zeek:conn (id_resp_h IN (107.180.41.148, 35.198.166.240, 162.244.35.33, 162.244.35.36) OR (proto=tcp id_resp_p=53))
| stats count BY id_orig_h
```

- Count every **internal source** that connected to the malicious IPs or used TCP DNS.

**Result:** a single row, `10.0.1.95` (there are no other PCs in the capture).

```spl
index=zeek sourcetype=zeek:conn id_orig_h=10.0.1.95 (id_resp_h=10.0.0.0/8 OR id_resp_h=172.16.0.0/12 OR id_resp_h=192.168.0.0/16) NOT id_resp_h IN (10.0.1.1, 10.0.1.254, 10.0.1.255)
```

- Did the PC connect to any internal IP **other than** the router, DHCP and broadcast?

**Result:** `No results found.`

**Reading the result:**

- **Other infected PCs: none** — the capture has only one PC.
- **Lateral movement: none** — the PC never connected to another internal device (no SMB, RDP or WinRM).
- **Exfiltration:** **22,992 bytes of POST bodies** (about 23 KB, 39 POSTs) went to the C2. They are encrypted, so **what left cannot be determined**. Zeus-family malware commonly sends PC information, saved passwords and banking-site input, so we write **"possible, content unconfirmed"**. No large uploads (multi-MB POSTs).

**Ticket entries:**

```text
[261119 0205, Sung] Checking other internal hosts contacting IOCs and lateral movement - Not Found
[261119 0206, Sung] Assessing data sent to C2 (possible exfil) - Further Analysis Required
```

---

## Part E — Writing and testing Snort rules { #snort }

### Step E0 — Preparation { #snort-prep }

```bash
snort -V
grep -n "ipvar HOME_NET" /etc/snort/snort.conf
grep -n "ipvar EXTERNAL_NET" /etc/snort/snort.conf
grep -n "local.rules" /etc/snort/snort.conf
```

- `snort -V` — version. With **2.9.x**, use the rules below as they are. Snort 3 has a different HTTP syntax ([step E5](#snort3)).
- `grep -n "text" file` — show lines containing the text, with line numbers.
- **`ipvar HOME_NET`** — the range Snort treats as "internal". If it is, say, `10.0.0.0/24`, our PC `10.0.1.95` is not "internal" and **no rule using `$HOME_NET` will fire.** Change it to `10.0.0.0/8` or `any` for testing.
- **`ipvar EXTERNAL_NET`** — "external". Usually `any` or `!$HOME_NET` (anything not internal). The rules below were tested with both.
- **`include $RULE_PATH/local.rules`** — must not start with `#`.
- If the old **test rule sid 1000100** (a "test" rule that fires on every TCP packet) is there, comment it out with `#`. It buries the results.

### Step E1 — Rule anatomy revisited { #rule-anatomy }

```text
alert tcp $HOME_NET any -> $EXTERNAL_NET $HTTP_PORTS (msg:"..."; ...options...; sid:1000201; rev:1;)
└─┬─┘ └┬┘ └───┬───┘ └┬┘ └┬┘ └─────┬─────┘ └────┬────┘ └──────────────────┬──────────────────┘
action proto  src IP  src port dir  dst IP      dst port                 options (in parentheses)
```

The **header** (before the parentheses) says *which packets to look at*; the **options** (inside) say *what to look for in them*. Options end with `;`, and **a rule must be on one line**.

| Option | Meaning |
|---|---|
| `msg:"…"` | Alert title |
| `flow:established,to_server` | Only data going **to the server** after the connection is set up (`to_client` = the other way) |
| `flags:S` | TCP **SYN** (connection-opening packet) only |
| `content:"text"` | Must contain this text. `\|3a\|` = hex bytes (`3a` = `:`, `22` = `"`, `0d 0a` = line break) |
| `content:!"text"` | Must **not** contain this text |
| `nocase` | Ignore case |
| `depth:6` | Only within the first 6 bytes |
| `distance:0; within:20` | **Right after the previous match, within 20 bytes** |
| `http_method` / `http_uri` / `http_header` | Where in HTTP to look for the preceding `content` (method / URI / headers) |
| `file_data` | Start matching in the **HTTP response body** (decompressed, de-chunked) |
| `pcre:"/regex/flags"` | Regular expression. `U` = URI, `H` = headers, `i` = ignore case, `m` = multi-line |
| `flowbits:set,name` / `isset,name` / `noalert` | Mark the connection / check the mark / this rule itself does not alert |
| `threshold:type limit, track by_src, count 1, seconds 600` | Alert **once per 600 s** per source |
| `classtype` | Alert classification (sets the priority) |
| `sid` / `rev` | Rule number / revision. Your own rules use **1,000,000 and above** |

Rules come in two kinds:

- **IOC rules** — the exact domain/IP/file name from this case. Precise, but miss it once the attacker changes them.
- **Behaviour rules** — the **shape** of the attack. Still fire when domains/IPs change, with some false-positive risk.

### Step E2 — The rules one by one { #snort-rules }

#### A. DNS — `.bit` and external TCP DNS (sid 1000201–1000204) { #rules-dns }

```text
alert tcp $HOME_NET any -> $EXTERNAL_NET 53 (msg:"LOCAL C2 DNS query amellet.bit over TCP"; flow:established,to_server; content:"|07|amellet|03|bit|00|"; nocase; classtype:trojan-activity; sid:1000201; rev:1;)
alert tcp $HOME_NET any -> any 53 (msg:"LOCAL DNS query for .bit (Namecoin) domain over TCP"; flow:established,to_server; content:"|03|bit|00|"; nocase; classtype:policy-violation; sid:1000202; rev:1;)
alert udp $HOME_NET any -> any 53 (msg:"LOCAL DNS query for .bit (Namecoin) domain over UDP"; content:"|03|bit|00|"; nocase; classtype:policy-violation; sid:1000203; rev:1;)
alert tcp $HOME_NET any -> $EXTERNAL_NET 53 (msg:"LOCAL Internal host DNS over TCP to external resolver"; flags:S; threshold:type limit, track by_src, count 1, seconds 600; classtype:policy-violation; sid:1000204; rev:1;)
```

- **DNS writes names as "length + characters" instead of dots.** `amellet.bit` → `|07|amellet|03|bit|00|` = 7 characters `amellet`, 3 characters `bit`, end (`00`). The text `amellet.bit` never appears in the packet, so `content:"amellet.bit"` with a dot **will never match.**
- **TCP DNS uses the same format**, just with a 2-byte length prefix, so an unanchored `content` still matches.
- **sid 1000201 (IOC)** — TCP DNS asking for `amellet.bit`. `flow:established,to_server` = the question the PC sent to the DNS server after the connection was set up.
- **sid 1000202/1000203 (behaviour)** — **any `.bit` name.** A name ending in `|03|bit|00|` is `.bit`. Company PCs have almost no reason to ask for `.bit`, so false positives are rare, and it still fires if the attacker changes the `.bit` name. Two rules, TCP and UDP: this time it was TCP but other variants may use UDP. The UDP rule has no `flow` (UDP has no "connection").
- **sid 1000204 (behaviour)** — an internal PC **opening a TCP connection (SYN)** to port 53 **outside**. `threshold:type limit, track by_src, count 1, seconds 600` = alert **once per 10 minutes** for the same PC. Without it, this PCAP alone fires 46 times. In a company network `!$DNS_SERVERS` (anything that is not the company DNS server) is more precise than `$EXTERNAL_NET` — but only if `DNS_SERVERS` is set to the real DNS server IPs.

Converting any domain into DNS format:

```bash
python3 -c "
d='amellet.bit'
print(''.join('|%02x|%s' % (len(l), l) for l in d.split('.')) + '|00|')"
```

- `d.split('.')` — split on dots → `['amellet', 'bit']`.
- `'|%02x|%s' % (len(l), l)` — each part as `|length (2 hex digits)|part`.
- Result: `|07|amellet|03|bit|00|`

#### B. C2 — IP, Host, POST shape (sid 1000205–1000207) { #rules-c2 }

```text
alert tcp $HOME_NET any -> 35.198.166.240 any (msg:"LOCAL C2 connection attempt to known C2 IP 35.198.166.240"; flags:S; classtype:trojan-activity; sid:1000205; rev:1;)
alert tcp $HOME_NET any -> $EXTERNAL_NET $HTTP_PORTS (msg:"LOCAL C2 HTTP request Host amellet.bit"; flow:established,to_server; content:"Host|3a| amellet.bit"; http_header; nocase; classtype:trojan-activity; sid:1000206; rev:1;)
alert tcp $HOME_NET any -> $EXTERNAL_NET $HTTP_PORTS (msg:"LOCAL Chthonic-like C2 POST - HTTP/1.0 to /a/ or /html/ without User-Agent"; flow:established,to_server; content:"POST /"; depth:6; content:" HTTP/1.0|0d 0a|"; distance:0; within:20; content:"POST"; http_method; pcre:"/^\/(?:a|html)\/$/U"; content:!"User-Agent|3a|"; http_header; classtype:trojan-activity; sid:1000207; rev:1;)
```

- **sid 1000205 (IOC)** — **SYN only** (`flags:S`) to the C2 IP. An IP-only rule without `flags:S` fires on **every packet**, thousands of times. Always narrow IP rules like this. Any port (`any`).
- **sid 1000206 (IOC)** — `Host: amellet.bit` in the HTTP headers. `|3a|` = `:`. Fires **even if the IP changes**, as long as the domain is the same.
- **sid 1000207 (behaviour)** — looks only at **the shape of the C2 request**, not the domain or IP. **All** conditions must match:
    - `content:"POST /"; depth:6;` — the **first 6 bytes** of the packet are `POST /`. (The request line is not in the HTTP header buffer, so we look in the raw packet.)
    - `content:" HTTP/1.0|0d 0a|"; distance:0; within:20;` — ` HTTP/1.0` + line break within the next 20 bytes. So the request line is `POST /short-path HTTP/1.0`.
    - `content:"POST"; http_method;` — Snort's HTTP parsing also sees the method as POST.
    - `pcre:"/^\/(?:a|html)\/$/U"` — the URI is **exactly** `/a/` or `/html/`. `^` = start, `$` = end, `(?:a|html)` = a or html, `U` = in the URI.
    - `content:!"User-Agent|3a|"; http_header;` — **no** `User-Agent:` header.

#### C. The first download — URL and "EXE without a User-Agent" (sid 1000208–1000210) { #rules-exe }

```text
alert tcp $HOME_NET any -> $EXTERNAL_NET $HTTP_PORTS (msg:"LOCAL Malware download URL jgbennett.com 30_723bio_152.exe"; flow:established,to_server; content:"Host|3a| jgbennett.com"; http_header; nocase; content:"/30_723bio_152.exe"; http_uri; nocase; classtype:trojan-activity; sid:1000208; rev:1;)
alert tcp $HOME_NET any -> $EXTERNAL_NET $HTTP_PORTS (msg:"LOCAL EXE requested without User-Agent - set flowbit"; flow:established,to_server; content:"GET"; http_method; content:".exe"; http_uri; nocase; pcre:"/\.exe$/Ui"; content:!"User-Agent|3a|"; http_header; flowbits:set,exe.noua; flowbits:noalert; classtype:trojan-activity; sid:1000209; rev:1;)
alert tcp $EXTERNAL_NET $HTTP_PORTS -> $HOME_NET any (msg:"LOCAL Windows EXE downloaded by non-browser client (no User-Agent)"; flow:established,to_client; flowbits:isset,exe.noua; file_data; content:"MZ"; within:2; content:"This program cannot be run in DOS mode"; distance:0; within:200; classtype:trojan-activity; sid:1000210; rev:1;)
```

- **sid 1000208 (IOC)** — the exact download URL. Two conditions: Host header and URI.
- **sid 1000209 + 1000210 (behaviour, a flowbits pair)** — alert when "an `.exe` was requested without a User-Agent **and** the response really is a Windows executable".
    - **1000209 (request):** GET + URI ending in `.exe` (`pcre:"/\.exe$/Ui"`) + no User-Agent → `flowbits:set,exe.noua` **marks this connection**, and `flowbits:noalert` means no alert yet.
    - **1000210 (response):** the reverse direction (`$EXTERNAL_NET $HTTP_PORTS -> $HOME_NET any`, `to_client`) = **the server's response**. `flowbits:isset,exe.noua` = only on marked connections. `file_data;` = in the response **body**, `content:"MZ"; within:2;` = the body's **first 2 bytes** are `MZ` (executable marker), and within 200 bytes after that `This program cannot be run in DOS mode` (in every Windows EXE).
    - Why two rules? The request alone could be a fake that is only *named* `.exe`; the response alone also catches legitimate update downloads. To see **"something that is not a browser + received a real EXE"** you have to tie request and response together, and that is what flowbits does.

#### D. Tech support scam (sid 1000211–1000214) { #rules-scam }

```text
alert tcp $HOME_NET any -> $EXTERNAL_NET $HTTP_PORTS (msg:"LOCAL Tech support scam domain helpcenterforall.bid or krep2010123.tk"; flow:established,to_server; pcre:"/^Host\x3a\s*(?:helpcenterforall\.bid|krep2010123\.tk)/Hmi"; classtype:bad-unknown; sid:1000211; rev:1;)
alert tcp $HOME_NET any -> $EXTERNAL_NET $HTTP_PORTS (msg:"LOCAL Tech support scam landing - phone number in URI"; flow:established,to_server; content:"number="; http_uri; pcre:"/[?&]number=\d{3}-\d{3}-\d{4}/U"; classtype:bad-unknown; sid:1000212; rev:1;)
alert tcp $EXTERNAL_NET $HTTP_PORTS -> $HOME_NET any (msg:"LOCAL Tech support scam page - fake Microsoft call-now text"; flow:established,to_client; threshold:type limit, track by_dst, count 1, seconds 60; file_data; content:"Call Microsoft"; nocase; content:"Toll Free"; nocase; distance:0; within:100; classtype:bad-unknown; sid:1000213; rev:1;)
alert tcp $EXTERNAL_NET $HTTP_PORTS -> $HOME_NET any (msg:"LOCAL Injected popunder script on website (popundr cookie)"; flow:established,to_client; file_data; content:"doOpen(|22|http"; content:"setCookie(|22|popundr|22|"; distance:0; within:100; classtype:web-application-activity; sid:1000214; rev:1;)
```

- **sid 1000211 (IOC)** — either of the two scam domains. `content` cannot do "or", so use a regex: `^Host\x3a\s*(?:A|B)`. `\x3a` = `:`, `\s*` = zero or more spaces, `H` = in the HTTP headers, `m` = `^` matches **at the start of each line** (headers are multi-line), `i` = ignore case.
- **sid 1000212 (behaviour)** — a **phone number** shaped `number=000-000-0000` in the URI. This scam family changes domains often but tends to keep passing the phone number in the URL. `content:"number="; http_uri;` filters quickly first and the slower regex runs after (good practice).
- **sid 1000213 (behaviour)** — `Call Microsoft` in the response body with `Toll Free` within 100 bytes after it. In the first test it fired **twice** on the same response, so `threshold … track by_dst, count 1, seconds 60` (once per 60 s per PC) was added. This is why you test.
- **sid 1000214 (behaviour)** — catches the **hacked or malvertising website** side. In the response body, `doOpen("http` and then `setCookie("popundr"` within 100 bytes. `|22|` = `"`. Even when the scam domain changes, it finds sites carrying the same pop-under code. `file_data` sees the body **after gunzip and de-chunking**, so it matches compressed pages too (this page was chunked).

### Step E3 — Testing against the PCAP { #snort-test }

1. Paste the 14 lines into `local.rules` (e.g. `sudo nano /etc/snort/rules/local.rules`).
2. Syntax check:

```bash
sudo snort -T -c /etc/snort/snort.conf
```

- `-T` — validate the configuration and rules without running. On success the last line is `Snort successfully validated the configuration!`.
- An error we actually hit: `Unknown ClassType: social-engineering` — a classification that does not exist in Snort 2.9's `classification.config`. List the valid ones with `grep "config classification" /etc/snort/classification.config`. That is why the scam rules use `bad-unknown`.

3. Run against the PCAP and count per rule:

```bash
mkdir -p /tmp/snorttest
sudo snort -c /etc/snort/snort.conf -r 2017-10-21-traffic-analysis-exercise.pcap -A console -q -k none -U -l /tmp/snorttest | grep -o "\[1:[0-9]*:[0-9]*\] [^[]*" | sort | uniq -c
```

- `-r file` — read a **PCAP file** instead of a live interface.
- `-A console` — print alerts to the screen.
- `-q` — hide the start-up banner.
- `-k none` — **turn off checksum verification.** Captures often contain packets with "wrong" checksums (NIC offloading); if Snort drops them, rules silently fail to fire. This PCAP gives the same result without `-k none`, but make it a habit.
- `-U` — show times in **UTC**.
- `-l /tmp/snorttest` — a test log folder, so the real `alert.log` stays clean.
- `grep -o "\[1:[0-9]*:[0-9]*\] [^[]*"` — extract just `[1:sid:rev] title` from each alert line.
- `sort | uniq -c` — group identical lines and count them.

### Step E4 — Actual results { #snort-results }

**Reading one alert line:**

```text
10/21-04:52:47.886843  [**] [1:1000210:1] LOCAL Windows EXE downloaded by non-browser client (no User-Agent) [**] [Classification: A Network Trojan was detected] [Priority: 1] {TCP} 107.180.41.148:80 -> 10.0.1.95:49691
```

- `10/21-04:52:47.886843` — packet time (UTC because of `-U`).
- `[1:1000210:1]` — `[engine:sid:rev]` — which rule fired.
- `{TCP} source -> destination` — the matching packet. 1000210 is a **response** rule, so the direction is server → PC.

**Results per rule (identical with `HOME_NET 10.0.0.0/8` and `HOME_NET any`):**

| sid | Rule | Kind | Expected | **Actual** | First – last (UTC) |
|---|---|---|---|---|---|
| 1000201 | TCP DNS `amellet.bit` | IOC | 37 (queries in D3) | **37** ✅ | 04:53:52 – 05:02:05 |
| 1000202 | TCP DNS `.bit` | Behaviour | 37 | **37** ✅ | 04:53:52 – 05:02:05 |
| 1000203 | UDP DNS `.bit` | Behaviour | 0 (no UDP this time) | **0** ✅ | — |
| 1000204 | External TCP 53 SYN (once per 10 min) | Behaviour | 1 | **1** ✅ | 04:53:52 |
| 1000205 | C2 IP SYN | IOC | 34 (C2 connections) | **34** ✅ | 04:54:03 – 05:02:05 |
| 1000206 | Host `amellet.bit` | IOC | 39 (POSTs) | **39** ✅ | 04:54:03 – 05:02:05 |
| 1000207 | C2 POST shape | Behaviour | 39 | **39** ✅ | 04:54:03 – 05:02:05 |
| 1000208 | Download URL | IOC | 1 | **1** ✅ | 04:52:47 |
| 1000209 | (mark only, no alert) | — | 0 | **0** ✅ | — |
| 1000210 | EXE received without User-Agent | Behaviour | 1 | **1** ✅ | 04:52:47 |
| 1000211 | Scam domains | IOC | 6 (requests) | **6** ✅ | 05:03:25 – 05:03:31 |
| 1000212 | Phone number in URI | Behaviour | 1 | **1** ✅ | 05:03:25 |
| 1000213 | Scam page text | Behaviour | 1 | **1** ✅ (2 before threshold) | 05:03:26 |
| 1000214 | Pop-under script | Behaviour | 1 | **1** ✅ | 05:02:27 |

**Reading the result:**

1. **Every rule fired the expected number of times.** The expected counts came from the Zeek/Arkime counts in Part D. Writing the expected count **before** writing the rule lets you check the result immediately.
2. **0 false positives.** The capture also contains traffic to Microsoft, Google, Bing and dozens of ad networks, yet every alert IP belongs to the malicious chain (107.180.41.148, 35.198.166.240, the external DNS servers, 104.18.61.210, 162.244.35.33/36). In particular, 1000210 did not fire on the **63 other sessions without a User-Agent** (C2, msftconnecttest, OCSP) — thanks to the `.exe` + `MZ` conditions.
3. **flowbits worked.** 1000209 only set the mark, and 1000210 fired once on the response in the same connection.
4. **Testing showed where a threshold was needed.** 1000213 initially fired twice on the same response.

!!! question "Question: why is the output not in time order?"
    Snort checks HTTP rules **after reassembling the TCP stream**, so the alert is printed when reassembly finishes and can appear after other alerts. Each alert's **time** is still the real packet time. Sort the timeline by **time**, not by output order.

### Step E5 — If you use Snort 3 { #snort3 }

In Snort 3, buffers such as `http_uri` and `http_header` go **before** the `content` (sticky buffers). sid 1000206, for example, becomes:

```text
alert http $HOME_NET any -> $EXTERNAL_NET any ( msg:"LOCAL C2 HTTP request Host amellet.bit"; flow:established,to_server; http_header; content:"Host|3a| amellet.bit",nocase; classtype:trojan-activity; sid:1000206; rev:2; )
```

- `alert http` — Snort 3 accepts `http` as the protocol and recognises HTTP **by content** instead of by port.
- `http_header;` — every `content` after this is searched in the headers.
- `content:"…",nocase` — options attach with a comma.
- `file_data` keeps the same name in Snort 3. The DNS rules (A) can be used as they are.
- This Snort 3 example shows the syntax only; this time the rules were tested with Snort 2.9 only. On a Snort 3 sensor, run `snort -T` and the PCAP test again.

**Ticket entries:**

```text
[261119 0215, Sung] Writing Snort rules for DNS/.bit, C2, EXE download and tech support scam (sid 1000201-1000214) - Found
[261119 0230, Sung] Testing Snort rules against PCAP (snort -A console -q -k none -U) - Found
```

---

## Part F — Timeline, IOCs, host-operator leads { #results }

### Timeline (UTC, 2017-10-21) { #timeline }

| Time | Event |
|---|---|
| 04:51:53 | Capture starts. DELOREAN-PC re-confirms 10.0.1.95 via DHCP; Windows 10 start-up traffic (NCSI, live tiles, Bing, DC SRV queries — no answer) |
| 04:52:40 – 04:52:46 | **Microsoft Office starts** (`contentstorage.osi.office.net`, `messaging.office.com`, `nexus.officeapps.live.com`, `officeclient.microsoft.com`) |
| **04:52:47** | **First malicious event:** DNS for `jgbennett.com` (107.180.41.148) → GET `/3cgconsulting.com/30_723bio_152.exe`, **no User-Agent or Referer**, 61,440-byte PE, SHA256 `a56876fd…a490` |
| 04:53:08 | DHCP re-request and Windows start-up traffic again (network reconnect) |
| 04:53:52 | First **`.bit` DNS query**, over **TCP 53** to external DNS 130.255.78.223 — empty answer |
| 04:54:03 | 188.165.200.156 answers `amellet.bit` = **35.198.166.240** → **first C2 POST `/a/`** (sent 1,584 / received 157,261 bytes) |
| 04:54:44 | Second `/a/` check-in |
| 04:54:59 – 04:56:11 | 34 `/html/` POSTs, 0.2–4 s apart — **module download** (about 2 MB, same set twice). 9 external DNS servers tried |
| 04:55:08 | 6 User-Agent-less `msftconnecttest.com` checks (assessed: malware internet check) |
| 04:56:11 – 05:00:51 | C2 quiet |
| 05:00:51 – 05:02:31 | 66 User-Agent-less `msftconnecttest.com` checks, with **C2 POSTs at 05:00:52 and 05:02:05** |
| 05:02:26 | User opens `www.singlemoms.org` in IE11 → dozens of ad networks (session spike) |
| 05:02:27 | **Pop-under script** received in the page (Snort sid 1000214) |
| 05:03:25 | Click → `helpcenterforall.bid/index/?MCPKV8` (162.244.35.33) **302** → `krep2010123.tk/?number=888-779-0939` (162.244.35.36) |
| 05:03:26 – 05:03:31 | Fake "Windows Defender Alert: Zeus Virus Detected" page, `defender.png`, **alarm sound `err.mp3`** |
| 05:03:52 | Capture ends |

### IOC table { #iocs }

| Type | Value | Description | Action |
|---|---|---|---|
| Domain | jgbennett[.]com | Malicious EXE distribution (likely hacked server) | Block |
| IP | 107.180.41.148 | jgbennett[.]com | Block / look up |
| URL | hxxp://jgbennett[.]com/3cgconsulting.com/30_723bio_152.exe | Download URL | Block |
| File | 30_723bio_152.exe, 61,440 bytes | 32-bit GUI PE, unsigned, compile time 2017-07-16 | Hunt on hosts |
| SHA256 | a56876fd456d0737eecc4a8bbe3154b35314ab28accb29abf0df7c518c81a490 | File above | Intel lookup |
| MD5 / SHA1 | 658c30fcd1508a65df8b9b9b397a9459 / fe4116d0e66350f54042361e3a87c942ee98529d | File above | Intel lookup |
| Domain | amellet[.]bit | C2 (Namecoin `.bit`) | Block / block all `.bit` |
| IP | 35.198.166.240 | C2, HTTP 80, lighttpd/1.4.45, PHP/5.3.3 | Block |
| URI | `/a/`, `/html/` (HTTP/1.0 POST, no User-Agent) | C2 paths | Detect |
| IP | 188.165.200.156, 144.76.133.38, 130.255.78.223, 62.113.203.99, 93.170.96.235, 31.3.135.232, 130.255.73.90, 37.187.16.17, 85.159.213.210 | External DNS servers used by the malware (TCP 53) | Block direct external DNS |
| Domain / IP | helpcenterforall[.]bid / 162.244.35.33 | Scam redirector | Block |
| Domain / IP | krep2010123[.]tk / 162.244.35.36 | Tech support scam page | Block |
| Phone | 888-779-0939 | Scam phone number | Check with user |
| Domain / IP | www.singlemoms[.]org / 104.18.61.210 (Cloudflare) | Site carrying the pop-under script | Monitor / inform user |
| Behaviour | Repeated User-Agent-less `www.msftconnecttest.com` | Assessed: malware internet check | Note |

### Leads for the host operator { #host-leads }

The network evidence translated into **clues to look for inside the PC**. Each event ID is explained.

1. **Isolate and capture memory first.** Isolate DELOREAN-PC (10.0.1.95, MAC `60:a4:4c:6a:b2:1f`) and **capture memory before rebooting**. Zeus-family malware hides inside other processes (injection) and leaves few disk traces.
2. **Time windows:** **04:52:30 – 04:56:15 UTC** (Office start → EXE → C2 modules), and 05:00:50 – 05:03:35 UTC.
3. **Find the Office document** opened around 04:52:40:
    - **Sysmon event ID 1** (process created, with command line and parent) / **Security 4688** (a new process has been created): child processes of `WINWORD.EXE` or `EXCEL.EXE` (`cmd.exe`, `powershell.exe`, `wscript.exe`, or the EXE itself).
    - Recent-documents lists, Office's `Trusted Records` registry key (whether the user clicked "Enable Content"), documents in download or mail temp folders, `Zone.Identifier` (marks files downloaded from the internet).
4. **Find the EXE.** `30_723bio_152.exe` (SHA256 above) — it may have been renamed, so search **by hash**.
    - **Sysmon event ID 11** (file created): executables created around 04:52:47. Check `%TEMP%` and `%APPDATA%`.
    - **Prefetch**, **Amcache**: execution traces and SHA1 (`fe4116d0…529d`).
5. **Processes that made network connections.**
    - **Sysmon event ID 3** (a process made a network connection): processes that connected to 107.180.41.148:80, 35.198.166.240:80 and **TCP 53 on external IPs**. Check whether the process that hit `www.msftconnecttest.com` without a User-Agent is the same one (verifies the D6 assessment).
    - **Sysmon event ID 22** (DNS query, Sysmon 10+): the process that asked for `amellet.bit`. This malware asked **directly over TCP**, bypassing Windows DNS, so ID 22 may be empty — then ID 3 is the reference.
6. **Injection.** **Sysmon event ID 8** (CreateRemoteThread: one process creates a thread inside another), **ID 10** (one process accesses another's memory). Public analyses report that the Chthonic loader runs inside legitimate processes such as `msiexec.exe` — check for a `msiexec.exe` running without its normal parent.
7. **Persistence.** **Sysmon event ID 13** (registry value set) — auto-run keys such as `HKCU\Software\Microsoft\Windows\CurrentVersion\Run`. **Security 4698** (a scheduled task was created), **System 7045** (a new service was installed).
8. **The 04:53:08 DHCP re-request** — the network reconnected 21 s after the download. Check the **System log** (network profile, adapter events) for an adapter restart, wake from sleep or user action.
9. **Banking details and passwords.** Zeus-family malware steals browser input and saved passwords. Have the user **change passwords (especially banking and email) from a different, clean device**. About 23 KB left encrypted to the C2.
10. **Tech support scam.** Ask the user whether, after 05:03:25, they **called 888-779-0939** or installed/allowed a remote-access tool (TeamViewer, AnyDesk, LogMeIn …). If so, handle it as a **separate incident**. IE's `popundr` cookie (24 h) is also a trace.

---

## Incident ticket { #ticket }

Operator name, ticket link and evidence paths are placeholders; the operation-log times are illustrative. The ticket body is in English per the team template. Domains in the description are defanged (`[.]`); search queries and rules keep the original values because they have to work.

```text
#INDEX ENTRY#

[] -- 171021 0452 -- 10.0.1.95 DELOREAN-PC -- Malware infection: EXE download without User-Agent after Office activity, Chthonic-like C2 to amellet.bit via external DNS-over-TCP; separate tech support scam popup -- <ticket-link>


#TICKET METADATA#

OPERATORS: Sung

TIME OF INCIDENT: 171021 04:52:47 UTC

RELATED TICKETS:
N/A

DESCRIPTION OF INVESTIGATION:

At 171021 04:52:47 UTC DELOREAN-PC (10.0.1.95, MAC 60:a4:4c:6a:b2:1f, Windows 10 x64, workgroup DOC-BROWN-GROUP, not domain-joined) initiated an HTTP GET (TCP 80, outbound) to 107.180.41.148 (jgbennett[.]com) for /3cgconsulting.com/30_723bio_152.exe and received a 61,440-byte Windows PE (SHA256 a56876fd456d0737eecc4a8bbe3154b35314ab28accb29abf0df7c518c81a490). The request had no User-Agent or Referer (non-browser client) and followed Microsoft Office start-up traffic 1-7 s earlier, consistent with a malicious document macro (document not in capture - UNCONFIRMED). From 04:53:52 the host bypassed its DNS server (10.0.1.1) and queried the Namecoin domain amellet[.]bit over DNS-over-TCP (TCP 53, outbound) against 9 external resolvers (37 queries; answers from 188.165.200.156, 144.76.133.38, 31.3.135.232), resolving to 35.198.166.240. Between 04:54:03 and 05:02:05 it made 39 encrypted HTTP/1.0 POSTs (TCP 80, outbound, 34 connections) to 35.198.166.240 /a/ (3, check-in) and /html/ (36, module download), no User-Agent/Content-Type, server lighttpd/1.4.45 PHP/5.3.3 (server clock ~6m49s slow). C2 state: active; ~2.34 MB received, ~23 KB sent; burst every 0.2-4 s during module download (04:54:59-04:56:11), then 05:00:52 and 05:02:05 - no stable beacon interval within the 12-min capture. Assessed as Chthonic (Zeus variant)-like banking trojan - UNCONFIRMED (closed network, no hash lookup).

Possible exfil: 22,992 bytes of encrypted POST bodies sent to 35.198.166.240:80 between 04:54:03 and 05:02:05 via HTTP POST; content unknown (encrypted). No large uploads. Separately, at 05:02:26 the user browsed www.singlemoms[.]org (104.18.61.210) in IE11; the page contained an injected pop-under script that on first click (05:03:25) opened helpcenterforall[.]bid/index/?MCPKV8 (162.244.35.33, HTTP 302) -> krep2010123[.]tk/?number=888-779-0939 (162.244.35.36), a fake "Windows Defender Alert: Zeus Virus Detected" tech support scam page with alarm audio (err.mp3). No link observed between the two events. No other internal hosts, no lateral movement, no inbound connections. Network baseline: 10.0.1.0/24, 2 devices (PC + Linksys router 10.0.1.1 [gateway/DNS] / 10.0.1.254 [DHCP], MAC 00:04:5a:f8:1a:ac); no DC, file, web or mail server.


#IMPACTED MACHINES#

INTERNAL IP/s & HOSTNAME/s:
10.0.1.95 DELOREAN-PC (MAC 60:a4:4c:6a:b2:1f ASUSTek; Windows 10 x64; IE11; MS Office; workgroup DOC-BROWN-GROUP; DNS suffix localdomain)

INTERNAL SOURCE PORT/s: (If Ephemeral Leave Blank.)


LATERAL DESTINATION IP/s & HOSTNAME/s: (If No Lateral Leave Blank.)


LATERAL DESTINATION PORT/s: (If No Lateral OR If Ephemeral Leave Blank.)



#EXTERNAL MACHINES#

EXTERNAL IP/s & HOSTNAME/s:
107.180.41.148 jgbennett[.]com (EXE download)
35.198.166.240 amellet[.]bit (C2)
188.165.200.156, 144.76.133.38, 130.255.78.223, 62.113.203.99, 93.170.96.235, 31.3.135.232, 130.255.73.90, 37.187.16.17, 85.159.213.210 (external DNS-over-TCP resolvers used by malware)
162.244.35.33 helpcenterforall[.]bid (scam redirector)
162.244.35.36 krep2010123[.]tk (tech support scam page)
104.18.61.210 www.singlemoms[.]org (site carrying pop-under script)

EXTERNAL SOURCE PORT/s: (If Ephemeral Leave Blank.)


EXTERNAL DESTINATION PORT/s: (If Ephemeral Leave Blank.)
80/tcp (HTTP: download, C2, scam), 53/tcp (DNS-over-TCP)


#SEARCH QUERIES#

ARKIME (MOLOCH):
ip == 10.0.1.95 && (ip.dst == [107.180.41.148, 35.198.166.240] || host.http == [jgbennett.com, amellet.bit])
ip.src == 10.0.1.95 && port.dst == 53 && ip.protocol == tcp && ip.dst != 10.0.0.0/8
host.dns == *.bit
host.http == amellet.bit && http.method == POST && http.user-agent != EXISTS!
ip.src == 10.0.1.95 && host.http == [www.singlemoms.org, helpcenterforall.bid, krep2010123.tk]

SPLUNK:
index=zeek sourcetype=zeek:http (host="jgbennett.com" OR host="amellet.bit") | eval t=strftime(ts,"%Y-%m-%d %H:%M:%S") | table t uid id_orig_h id_orig_p id_resp_h method host uri version user_agent status_code request_body_len response_body_len
index=zeek sourcetype=zeek:dns query="*.bit" | eval t=strftime(ts,"%H:%M:%S") | table t id_orig_h id_resp_h proto query rcode_name answers
index=zeek sourcetype=zeek:conn proto=tcp id_resp_p=53 NOT id_resp_h=10.0.0.0/8 | stats count by id_orig_h id_resp_h conn_state
index=zeek sourcetype=zeek:files mime_type="application/x-dosexec" | table ts tx_hosts rx_hosts seen_bytes md5 sha1
index=zeek sourcetype=zeek:http host IN ("www.singlemoms.org", "helpcenterforall.bid", "krep2010123.tk") | eval t=strftime(ts,"%H:%M:%S") | table t id_resp_h host uri referrer status_code resp_mime_types


#EVIDENCE LOCATIONS#

Team<#>: /home/<username>/evidence/2017-10-21-traffic-analysis-exercise.pcap (original, SHA256 a42fd8341966fbf385e54feaf24218eb1df0f408bc060baa5f5c22aeb1318846)
Team<#>: /home/<username>/evidence/171021_delorean-pc_malicious_sessions.pcap (Arkime "Download PCAP" of the search queries above, SHA256 <insert>)
Team<#>: /home/<username>/evidence/http_objects/30_723bio_152.exe (DO NOT EXECUTE, SHA256 a56876fd456d0737eecc4a8bbe3154b35314ab28accb29abf0df7c518c81a490)
Team<#>: /home/<username>/evidence/snort/local.rules (sid 1000201-1000214)


#OPERATION LOG / ANALYST NOTES#

[261119 0030, Sung] Establishing data time range and session count - Found
[261119 0035, Sung] Identifying internal networks and active hosts - Found
[261119 0040, Sung] Identifying non-internal-source sessions (possible inbound) - Not Found
[261119 0045, Sung] Identifying hostname, MAC and network settings via DHCP - Found
[261119 0050, Sung] Counting devices and identifying gateway via MAC addresses - Found
[261119 0055, Sung] Identifying server roles (DNS, DHCP, DC, file/web/mail) - Found
[261119 0100, Sung] Reviewing protocol distribution - Found
[261119 0105, Sung] Identifying operating system and software of 10.0.1.95 - Found
[261119 0110, Sung] Reviewing external communications overview - Further Analysis Required
[261119 0115, Sung] Reviewing HTTP requests without User-Agent - Found
[261119 0120, Sung] Reviewing EXE download from jgbennett.com - Found
[261119 0125, Sung] Reviewing activity immediately before EXE download (DNS) - Found
[261119 0130, Sung] Reviewing DNS over TCP to external resolvers - Found
[261119 0135, Sung] Reviewing C2 HTTP sessions to amellet.bit (35.198.166.240) - Found
[261119 0140, Sung] Assessing malware family from C2 pattern - Further Analysis Required
[261119 0145, Sung] Measuring C2 check-in intervals - Found
[261119 0150, Sung] Reviewing repeated msftconnecttest.com requests without User-Agent - Further Analysis Required
[261119 0155, Sung] Reviewing session spike at 05:02:30 (www.singlemoms.org and ad networks) - Found
[261119 0200, Sung] Reviewing redirect to helpcenterforall.bid / krep2010123.tk (tech support scam) - Found
[261119 0205, Sung] Checking other internal hosts contacting IOCs and lateral movement - Not Found
[261119 0206, Sung] Assessing data sent to C2 (possible exfil) - Further Analysis Required
[261119 0210, Sung] Hash reputation lookup - Not Performed: closed network; hashes recorded for MC/intel follow-up
[261119 0215, Sung] Writing Snort rules for DNS/.bit, C2, EXE download and tech support scam (sid 1000201-1000214) - Found
[261119 0230, Sung] Testing Snort rules against PCAP (snort -A console -q -k none -U) - Found


[Time -- Operator]

Tool Output / Notes:

[261119 0030, Sung] Arkime, empty query, Bounding: Last Packet.
  Data range 2017/10/21 04:51:53 - 05:03:53 UTC (12:00). 505 sessions. Zeek conn: 510 (ts 04:51:53 - 05:03:26).
  Activity graph: steady 04:52-04:56, near-quiet 04:57-05:00, clusters 05:00-05:01, spike ~05:02:30.
[261119 0035, Sung] Arkime: ip.src == 10.0.0.0/8 || ip.src == 172.16.0.0/12 || ip.src == 192.168.0.0/16
  Src IP: 10.0.1.95 (501), 10.0.1.254 (2). Internal network 10.0.1.0/24. 10.0.1.1 only as destination (158).
  Protocols: tcp 328, udp 174, icmp 1 / dns 188, http 166, tls 87, http2 24, llmnr 7, dhcp 2.
  Top external dst: 35.198.166.240 (34), 188.165.200.156 (31), 23.56.3.183 (20), 13.107.4.52 (19).
[261119 0040, Sung] Arkime: ip.src != 10.0.0.0/8 || ip.src == 10.0.1.254 -> 4 sessions, all DHCP (udp 67/68).
  04:51:53 and 04:53:08: 0.0.0.0:68 -> 255.255.255.255:67 and 10.0.1.254:67 -> 10.0.1.95:68.
  No externally-initiated (inbound) sessions.
[261119 0045, Sung] Arkime protocols == dhcp / zeek:dhcp:
  10.0.1.95 DELOREAN-PC, MAC 60:a4:4c:6a:b2:1f (ASUSTek), REQUEST/ACK x2 (xid 15a2b597, d0ad6ea9).
  DHCP ACK: server 10.0.1.254, mask 255.255.255.0, router 10.0.1.1, DNS 10.0.1.1, domain localdomain, lease 1800 s.
  Client vendor class MSFT 5.0.
[261119 0050, Sung] Ethernet headers: only 2 source MACs - 60:a4:4c:6a:b2:1f (10.0.1.95) and 00:04:5a:f8:1a:ac (Linksys).
  All outbound traffic to dst MAC 00:04:5a:f8:1a:ac; 10.0.1.1 (DNS) and 10.0.1.254 (DHCP) both sourced from 00:04:5a:f8:1a:ac
  -> one Linksys router with 2 IPs. 2 devices total.
[261119 0055, Sung] zeek:conn internal responders: 10.0.1.1 (53/udp, 137/udp), 10.0.1.254 (67/udp), 10.0.1.255 (137,138), 224.0.0.252 (5355).
  id_resp_p IN (88,135,139,389,445,464,636,3268,3389,5985,25,110,143,465,587,993,995) -> 0 results. No DC/file/web/mail server.
  DC SRV _ldap._tcp.dc._msdcs.DOC-BROWN-GROUP.localdomain x12 - no answer. NetBIOS: workgroup DOC-BROWN-GROUP, DELOREAN-PC local master browser.
  zeek:dns servers: 10.0.1.1 udp (195); EXTERNAL tcp: 188.165.200.156 (31), 144.76.133.38 (2), 130.255.78.223, 31.3.135.232, 62.113.203.99, 93.170.96.235 (1 each).
[261119 0100, Sung] zeek:conn proto/service: udp dns 169, tcp http 157, tcp ssl 87, tcp - 51 (idle/failed), tcp dns 37, udp dhcp 4, udp - 4, icmp 1.
[261119 0105, Sung] UA: "Mozilla/5.0 (Windows NT 10.0; WOW64; Trident/7.0; rv:11.0) like Gecko" 164, NONE 123, Microsoft-CryptoAPI/10.0 9, Microsoft-WNS/10.0 8.
  Windows 10 x64 (WOW64), IE11. NetBIOS browser OS 10.0. TTL 128. Office domains (officeclient.microsoft.com, nexus.officeapps.live.com).
[261119 0110, Sung] External: 87 IPs, 332 conns, ports 80 (196), 443 (90), 53/tcp (46). TLS SNI all Microsoft/Google/ad networks.
  35.198.166.240:80 34 conns, 25,484 B out / 2,350,698 B in (largest).
[261119 0115, Sung] zeek:http NOT user_agent=*: www.msftconnecttest.com 73 req/19 conn; amellet.bit 39/34 (POST, HTTP/1.0);
  (no host) 8 = server 408 timeouts on idle ad connections; ocsp.digicert.com 2 (POST OCSP); jgbennett.com 1.
[261119 0120, Sung] 171021 04:52:47 10.0.1.95:49691 -> 107.180.41.148:80 GET jgbennett.com /3cgconsulting.com/30_723bio_152.exe HTTP/1.1
  Headers: Host, Connection: Keep-Alive only (no User-Agent, no Referer).
  -> 200 Apache, Content-Type application/x-msdownload, Content-Length 61440, Last-Modified Thu, 19 Oct 2017 12:45:16 GMT.
  zeek:files application/x-dosexec seen 61440/61440, MD5 658c30fcd1508a65df8b9b9b397a9459, SHA1 fe4116d0e66350f54042361e3a87c942ee98529d
  SHA256 a56876fd456d0737eecc4a8bbe3154b35314ab28accb29abf0df7c518c81a490. zeek:pe I386 GUI, compiled 2017-07-16 07:29:21, unsigned, sections .text .data.
[261119 0125, Sung] DNS 04:52:40 contentstorage.osi.office.net, 04:52:42 fs.microsoft.com, messaging.office.com,
  04:52:46 nexus.officeapps.live.com, officeclient.microsoft.com, 04:52:47 jgbennett.com -> 107.180.41.148 (1 s before download).
  Office started immediately before non-browser EXE download -> likely macro document (not in capture).
[261119 0130, Sung] zeek:dns query="*.bit": amellet.bit A x37, all TCP to external resolvers, 04:53:52 - 05:02:05.
  Answer 35.198.166.240 (TTL 400 first), NS a.dnspod.com. Empty answers: 130.255.78.223, 62.113.203.99, 93.170.96.235.
  Failed TCP 53: 130.255.73.90 (S0), 37.187.16.17 (REJ), 85.159.213.210 (S0). Internal DNS 10.0.1.1 bypassed.
[261119 0135, Sung] Arkime host.http == amellet.bit -> 34 sessions. Sample 04:54:03 10.0.1.95:57622 -> 35.198.166.240:80
  POST /a/ HTTP/1.0 | Host: amellet.bit | Content-Length: 1584 | (binary body)
  -> HTTP/1.0 200 OK | X-Powered-By: PHP/5.3.3 | Content-type: text/html | Content-Length: 158064 | Date: 04:47:14 GMT | Server: lighttpd/1.4.45 | (binary)
  Totals: /a/ 3 POST, 4,848 B sent / 289,805 B recv; /html/ 36 POST, 18,144 B sent / 2,053,089 B recv.
  Repeated response sizes 256752/250688/225872/43840/17248/4752 (module set downloaded twice).
  zeek:weird unexpected_multiple_HTTP_requests x5 (2 POSTs on one HTTP/1.0 connection).
[261119 0140, Sung] .bit C2 via hard-coded external resolvers + encrypted HTTP/1.0 POST module download: consistent with Chthonic (Zeus variant). UNCONFIRMED.
[261119 0145, Sung] C2 gaps: /a/ 04:54:03, 04:54:44 (41 s); /html/ 0.2-4 s 04:54:59-04:56:11; quiet 4m41s; 05:00:52, 05:02:05 (73 s). No stable beacon in 12 min.
[261119 0150, Sung] www.msftconnecttest.com /connecttest.txt, no UA: 04:55 x6, 04:56 x1, 05:00 x18, 05:01 x42, 05:02 x6 - coincides with C2 activity.
  Likely malware connectivity check (legit NCSI uses UA "Microsoft NCSI"). Host operator to confirm process.
[261119 0155, Sung] 05:02:26 GET www.singlemoms.org/ (104.18.61.210, IE11) -> ~60 ad/analytics domains loaded -> session spike.
[261119 0200, Sung] www.singlemoms.org/ body contains pop-under script: on first click doOpen("http://helpcenterforall.bid/index/?MCPKV8"), setCookie("popundr",1,864e5).
  05:03:25 :61354 -> 162.244.35.33:80 GET helpcenterforall.bid/index/?MCPKV8 (no referrer) -> 302 Location http://krep2010123.tk/?number=888-779-0939
  05:03:25 :61356 -> 162.244.35.36:80 GET krep2010123.tk/?number=888-779-0939 200 text/html 4374 "Windows Defender Alert : Zeus Virus Detected ... Call Microsoft Technical Department: 888-779-0939 (Toll Free)"
  05:03:26 /landinf/defender.png 200; 05:03:31 /landinf/err.mp3 206 audio/mpeg 251,342 B. Server nginx/1.10.2.
[261119 0205, Sung] IOC IPs / TCP 53 contacted only by 10.0.1.95. 10.0.1.95 -> other internal IPs (excl. 10.0.1.1/.254/.255): 0 results.
[261119 0206, Sung] 22,992 B encrypted POST bodies to C2 (04:54:03-05:02:05). Content unknown.
[261119 0230, Sung] snort -c snort.conf -r <pcap> -A console -q -k none -U (HOME_NET 10.0.0.0/8 and any - same result)
  1000201 37 | 1000202 37 | 1000203 0 | 1000204 1 | 1000205 34 | 1000206 39 | 1000207 39 | 1000208 1 | 1000210 1 |
  1000211 6 | 1000212 1 | 1000213 1 | 1000214 1 | alerts on benign traffic: 0


#SNORT RULES#
(sid 1000201-1000214 - see local.rules in EVIDENCE LOCATIONS)


#LEADS FOR HOST OPERATOR#
Isolate DELOREAN-PC (10.0.1.95 / 60:a4:4c:6a:b2:1f), capture memory before reboot. Windows: 04:52:30-04:56:15Z and 05:00:50-05:03:35Z.
Office document opened ~04:52:40Z: children of WINWORD/EXCEL (Sysmon 1 / 4688), Trusted Records, Zone.Identifier.
EXE by hash (SHA256 a56876fd...a490 / SHA1 fe4116d0...529d): Sysmon 11 ~04:52:47Z in %TEMP%/%APPDATA%, Prefetch, Amcache.
Process with connections to 107.180.41.148:80, 35.198.166.240:80, external TCP 53, and UA-less msftconnecttest.com (Sysmon 3; Sysmon 22 may be empty).
Injection (Sysmon 8/10; check msiexec.exe), persistence (Sysmon 13 Run keys, 4698, 7045).
Reset user passwords (banking, email) from a clean device.
Ask user whether 888-779-0939 was called / remote-access tool installed after 05:03:25Z (separate incident if yes).
```

---

## Copy-ready query sheet { #query-sheet }

Replace `<…>`. In Splunk use the **All time** range and `ts` for times.

**Splunk — baselining**

```spl
| tstats count where index=zeek by sourcetype
```

```spl
index=zeek sourcetype=zeek:conn
| stats count min(ts) AS first max(ts) AS last
| eval first=strftime(first, "%Y-%m-%d %H:%M:%S"), last=strftime(last, "%Y-%m-%d %H:%M:%S")
```

```spl
index=zeek sourcetype=zeek:conn (id_orig_h=10.0.0.0/8 OR id_orig_h=172.16.0.0/12 OR id_orig_h=192.168.0.0/16)
| stats count dc(id_resp_h) AS unique_destinations BY id_orig_h
| sort - count
```

```spl
index=zeek sourcetype=zeek:dhcp
| table ts client_addr server_addr assigned_addr mac host_name domain lease_time msg_types
```

```spl
index=zeek sourcetype=zeek:conn (id_resp_h=10.0.0.0/8 OR id_resp_h=172.16.0.0/12 OR id_resp_h=192.168.0.0/16) id_resp_p<10000
| stats dc(id_orig_h) AS clients count values(id_resp_p) AS ports BY id_resp_h
```

```spl
index=zeek sourcetype=zeek:conn id_resp_p IN (88, 135, 139, 389, 445, 464, 636, 3268, 3389, 5985, 25, 110, 143, 465, 587, 993, 995)
| stats count BY id_resp_h id_resp_p
```

```spl
index=zeek sourcetype=zeek:dns
| stats count values(proto) AS proto BY id_resp_h
| sort - count
```

```spl
index=zeek sourcetype=zeek:conn
| stats count BY proto service
```

```spl
index=zeek sourcetype=zeek:http id_orig_h=<host-IP>
| fillnull value="(none)" user_agent
| stats count BY user_agent
```

```spl
index=zeek sourcetype=zeek:conn id_orig_h=<host-IP> NOT (id_resp_h=10.0.0.0/8 OR id_resp_h=172.16.0.0/12 OR id_resp_h=192.168.0.0/16 OR id_resp_h=224.0.0.0/4 OR id_resp_h=255.255.255.255)
| stats count sum(orig_bytes) AS bytes_out sum(resp_bytes) AS bytes_in values(id_resp_p) AS ports BY id_resp_h
| sort - count
```

**Splunk — malicious activity**

```spl
index=zeek sourcetype=zeek:http NOT user_agent=*
| fillnull value="-" host
| stats count dc(uid) AS connections values(method) AS method values(version) AS ver BY host id_resp_h
```

```spl
index=zeek sourcetype=zeek:files mime_type="application/x-dosexec"
| table ts tx_hosts rx_hosts seen_bytes total_bytes md5 sha1
```

```spl
index=zeek sourcetype=zeek:dns NOT id_resp_h=<internal-DNS-IP> NOT id_resp_h=224.0.0.0/4 NOT id_resp_h=<broadcast>
| stats count values(query) AS queries BY id_resp_h proto
```

```spl
index=zeek sourcetype=zeek:http host="<domain>"
| sort ts
| streamstats current=f last(ts) AS prev_ts
| eval t=strftime(ts, "%H:%M:%S"), gap=round(ts-prev_ts, 1)
| table t method uri version request_body_len response_body_len gap
```

```spl
index=zeek sourcetype=zeek:weird
| stats count BY name id_resp_h
```

**Arkime**

```text
ip.src == 10.0.0.0/8 || ip.src == 172.16.0.0/12 || ip.src == 192.168.0.0/16
ip.src != 10.0.0.0/8
protocols == dhcp
ip.dst == 10.0.0.0/8
ip.src == <host-IP> && ip.dst != 10.0.0.0/8 && ip.dst != 224.0.0.0/4 && ip.dst != 255.255.255.255
protocols == http && http.user-agent != EXISTS!
port.dst == 53 && ip.protocol == tcp
host.dns == *.bit
host.http == <domain>
host.http == [<domain1>, <domain2>]
mac.src == <MAC>
```

**Snort**

```bash
sudo snort -T -c /etc/snort/snort.conf
sudo snort -c /etc/snort/snort.conf -r <file>.pcap -A console -q -k none -U -l /tmp/snorttest | grep -o "\[1:[0-9]*:[0-9]*\] [^[]*" | sort | uniq -c
```

**Analysis VM**

```bash
sha256sum <file>.pcap
tshark -r <file>.pcap -Y "dhcp.option.dhcp == 5" -V | grep -E "^ +(DHCP Server Identifier|Subnet Mask|Router|Domain Name Server|Domain Name|IP Address Lease Time):"
tshark -r <file>.pcap --export-objects http,http_objects
```

---

## Lessons learned { #lessons }

1. **Baseline first.** Because we knew "this PC asks the router DNS (10.0.1.1) over UDP", **asking external DNS over TCP** stood out immediately.
2. **Number of IPs ≠ number of devices.** There were 3 IPs, but by MAC only 2 devices (the router has two IPs).
3. **"None" is also a result.** Confirming and recording that there is **no** DC, file server, mail server, inbound connection or lateral movement saves the next person from searching again.
4. **The User-Agent tells you *who* made the request.** Splitting browser (IE11), Windows components (CryptoAPI, WNS) and **programs that send nothing** gathered the malicious traffic together. But "none" also contains normal noise (408 responses, OCSP), so check each one.
5. **A few seconds before and after tell you the cause.** Office queries 1–7 s before the EXE download pointed to the infection vector (document macro). It could not be confirmed, so it is written as "assessed" and passed on as a host lead.
6. **`.bit` and direct external DNS are strong signals.** Company PCs almost never ask for Namecoin names, and even less often use TCP 53 that bypasses company DNS. **Behaviour rules** like these survive the attacker changing domains and IPs.
7. **One capture can hold two incidents.** The malware C2 and the tech support scam pop-up are close in time but show no link. Do not merge them into one story; record them separately.
8. **Write the expected count before the rule, and test against the PCAP.** Testing caught a classtype error (`social-engineering`) and a duplicate alert (sid 1000213).
9. **You can still reach conclusions on a closed network.** Record hashes for others, judge by behaviour, and write families as "consistent with … – unconfirmed".

## References { #references }

- [Arkime search syntax](../../network/arkime/search-syntax.md) · [Analysing a PCAP with Arkime](../../network/arkime/offline-pcap-guide.md)
- [Zeek: conn](../../network/zeek/conn-log.md) · [dns](../../network/zeek/dns-log.md) · [http](../../network/zeek/http-log.md) · [files](../../network/zeek/files-log.md)
- [SPL cheatsheet](../splunk/spl-cheatsheet.md) · [Data discovery and time](../splunk/data-discovery.md)
- [Beaconing & C2](../../network/beaconing-c2.md) · [Snort rules for DC/SMB attacks](../../training/pcap-ir-labs/dc-smb-and-snort-rules.md)
- [Previous case: phishing red herring and exploit kit (Splunk + Arkime + Snort)](phishing-red-herring-ek-driveby-ursnif-c2.md) · [Arkime only — credential theft and TLS C2](arkime-only-credential-theft-tls-c2.md)
- [Playbook: compromised workstation](../playbooks/compromised-workstation.md)
- Original exercise: [malware-traffic-analysis.net — 2017-10-21 Doc Brown and Marty McFly: Back to the Present](https://malware-traffic-analysis.net/2017/10/21/index.html)
- Public analysis: [QA Cafe (CloudShark) — Windows 10 Malware Analysis Exercise](https://qacafe.com/resources/malware-exercise-2017-10-21)

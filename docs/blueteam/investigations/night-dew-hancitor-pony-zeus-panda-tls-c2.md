---
title: Night Dew — Hancitor check-ins to follow-up downloads, credential exfil and a self-signed TLS C2 (Arkime + CyberChef + Snort)
tags:
  - blue-team
  - pcap
  - arkime
  - cyberchef
  - snort
  - c2
  - hancitor
  - tls
---

# Night Dew — Hancitor check-ins to follow-up downloads, credential exfil and a self-signed TLS C2 { #night-dew }

!!! abstract "Case summary"
    A 43-minute capture of **one Windows 7 PC (CHICAGO-7FA3-PC, user faith.hoffman)** in an AD domain (NIGHTDEW). **35 seconds** after the user logged on, the PC checked its public IP at `api.ipify[.]org` and immediately sent `lysedsohap[.]com/4/forum.php` a **POST carrying its own details (hostname, domain\user, public IP, OS)**. Decoding the first reply in **CyberChef (Base64 → XOR 0x7A)** shows three "download from these URLs" commands. One second later the PC pulled **three encrypted files** from a hacked WordPress site, `wansaiful[.]com`. Within three seconds a **different program sent two encrypted POSTs** (likely credential theft), and two minutes later the PC started beaconing every ~5 minutes to a **TLS C2 with a self-signed certificate (`Default Company Ltd`)**, `robwassotdint[.]ru`. The pattern matches the classic **Hancitor → Pony → Zeus Panda Banker** chain. We **test 8 Snort rules against the PCAP** and finish with a single merged **report**.

| | |
|---|---|
| **Evidence** | One PCAP `2018-05-11-traffic-analysis-exercise.pcap` — 2018-05-11 02:06:51 – 02:49:40 UTC (42 min 49 s), 7,295 packets, SHA256 `b2c8d0fe…13e51e` |
| **Source** | malware-traffic-analysis.net 2018-05-11 exercise "Night Dew" |
| **Environment** | Closed network (no VirusTotal, no OSINT). Arkime web UI, CyberChef, tshark and Snort 2.9 on the analysis VM |
| **Deliverables** | Baseline, analysis of the malicious activity, CyberChef decode, Snort rules that find the traffic again (tested) |
| **Related pages** | [Arkime search syntax](../../network/arkime/search-syntax.md) · [Beaconing & C2](../../network/beaconing-c2.md) · [Invoice email — same Hancitor style](pcap-lab-06-invoice-macro-c2.md) · [Previous case: Back to the Present](back-to-the-present-chthonic-c2-tech-support-scam.md) |

!!! tip "How to read this page"
    Written so a complete beginner can follow from the first query to the finished report. Every step uses the same order.

    1. **Goal** — what this step is trying to find out
    2. **Query** — copy it with the **copy button** at the top right of the code block
    3. **Explanation** — what each piece means
    4. **Result** — the values this PCAP actually produced
    5. **Reading the result** — what the values mean and why they matter

!!! note "Where do the result values come from?"
    The SPIView values in steps 1-1 and 3-1 (Dst IP, Protocols, Hostname, URI, Useragent, …) were read from a real Arkime screen. The other values were confirmed by running **tshark** over the same PCAP. Field names (`cert.issuer.on`, `http.request.content-type`, …) can differ slightly between Arkime versions. If a query does not match, click the value in SPIView and choose **and** — Arkime inserts the expression your version understands.

!!! warning "The indicators on this page are real"
    Domains, IPs and hashes come from real 2018 malware traffic. Prose and tables use defanged forms (`hxxp`, `[.]`); code blocks (queries, rules, raw output) keep the values as typed. **Do not visit them.** Never open extracted files outside an isolated analysis VM.

## Answers at a glance { #answers }

**Bottom line:** from 2018-05-11 02:08:04 UTC CHICAGO-7FA3-PC (10.0.14.129, user faith.hoffman) was infected with a Hancitor-style downloader. It checked in to its C2 every 2 minutes, downloaded three more pieces of malware and sent two POSTs that most likely carried stolen credentials. It then beaconed every 5 minutes to a Zeus Panda Banker-style HTTPS C2.

| Item | Answer | Status |
|---|---|---|
| Infected PC | **10.0.14.129 CHICAGO-7FA3-PC**, MAC `00:1a:92:06:5c:7b` (ASUSTek), Windows 7 64-bit (NT 6.1) | Confirmed |
| User account | **faith.hoffman** (domain NIGHTDEW) | Confirmed |
| Domain / DC | **nightdew.org**, DC = **10.0.14.3 Nightdew-DC** | Confirmed |
| Gateway / DHCP | 10.0.14.1 (Cisco) | Confirmed |
| First malicious event | **02:08:04 UTC** public IP check at `api.ipify[.]org` → straight into a `lysedsohap[.]com` check-in | Confirmed |
| First C2 | `lysedsohap[.]com` **185.43.223.6:80**, POST `/4/forum.php` **21 times** (~2 min apart, 02:08:04–02:48:25) | Confirmed |
| Follow-up downloads | `wansaiful[.]com` **111.90.144.30:80**, three encrypted files (46,341 / 47,383 / 159,255 bytes, 02:08:05–02:08:15) | Confirmed |
| Exfiltration | Two encrypted POSTs to `lysedsohap[.]com` `/mlu/forum.php` (206 B) and `/d2/about.php` (234 B), 02:08:12–02:08:14 | Confirmed (content encrypted) |
| Second C2 | `robwassotdint[.]ru` **185.174.175.14:443**, **54** TLS sessions (02:10:16–02:45:46), self-signed certificate `Default Company Ltd` | Confirmed |
| Malware families | Hancitor + Pony (info stealer) + Zeus Panda Banker-like | Assessed (matches public reporting) |
| Initial access | No email or document download in the PCAP → infected before the capture, or a document opened right after logon (02:07:29) | Unconfirmed |
| Lateral movement | No other internal PC in the capture. **Correction:** the DC traffic is not all normal — 1,522 × `NetrLogonSamLogonWithFlags` in 32 s (02:08:12–02:08:45) is password guessing through the DC. See the [second pass](night-dew-arkime-splunk-netlogon-bruteforce.md#netlogon) | Corrected |
| Snort | 8 rules (sid 1000011–1000018), each fired exactly the expected number of times against the PCAP | Confirmed |

---

## Step 0 — Preparation: the PCAP and the Arkime time range { #prep }

**Goal:** record what you are analysing and make sure Arkime is showing the whole PCAP.

**Exercise scenario:** on Friday 2018-05-11 (UTC) an alert fired for a possibly infected Windows host and a colleague pulled the related traffic. Analyse it and write an incident report.

**PCAP facts (analysis VM, `capinfos` and `sha256sum`):**

```text
File        2018-05-11-traffic-analysis-exercise.pcap
SHA256      b2c8d0fed6765dc4d2036fae6587a3bac9c27184a3032bd3899eefac4d13e51e
Packets     7295
First       2018-05-11 02:06:51 UTC
Last        2018-05-11 02:49:40 UTC
Duration    about 42 min 49 s
```

- The hash proves "the file I analysed is exactly this file". Record it next to the evidence location in the report so the next analyst can check they have the same file.
- `capinfos` may print times in the computer's local time zone. Prefix it with `TZ=UTC` (`TZ=UTC capinfos file`) to get UTC. (In Adelaide time it shows 11:36:51 — 9 h 30 min later.)

**Arkime time range:**

```text
Start     2018/05/11 02:06:51
End       2018/05/11 02:50:00
Bounding  Last Packet
```

- **Start / End** — the search window. The last packet is at 02:49:40; setting the end **a little wider** (02:50:00) avoids losing sessions at the very end.
- **Bounding: Last Packet** — a session is shown if its **last packet** falls inside the window. With a wide enough window every bounding option returns everything.
- Keep Arkime showing UTC (Settings → Timezone Format → UTC). All report times are UTC.

**Where to look:**

| Tab | Use |
|---|---|
| **Sessions** | One session (connection) per row. Expand a row for details and packet content |
| **SPIView** | Values and counts per field. The number in brackets `(54)` is the **session count** |
| **Connections** | Graph of who talked to whom |

Click any value to get an **and** / **exclude** menu that adds it to the search expression — fewer typos than typing the expression yourself.

---

## Step 1 — Baseline: which devices and users are there { #baseline }

**Result:** there is only one internal PC, 10.0.14.129 (CHICAGO-7FA3-PC, user faith.hoffman). 10.0.14.3 is the domain controller (DC) and 10.0.14.1 is the gateway. Knowing the baseline first is what makes the "odd" things stand out later.

### 1-1. The big picture { #overview }

**Query:** **clear** the search box and press Search → **SPIView** → **general** section.

**Result (Arkime screen):**

```text
Src IP     10.0.14.129 (212)  10.0.14.1 (3)  0.0.0.0 (1)
Dst IP     10.0.14.3 (91)  185.174.175.14 (54)  10.0.14.1 (23)  185.43.223.6 (23)
           224.0.0.252 (5)  255.255.255.255 (4)  10.0.14.129 (3)  10.0.14.255 (3)
           224.0.0.22 (3)  239.255.255.250 (3)  111.90.144.30 (1)  173.223.52.18 (1)
           184.72.249.110 (1)  216.58.193.68 (1)
Protocols  tcp (131) udp (82) tls (55) dns (34) http (26) krb5 (25) ldap (12)
           dhcp (9) dcerpc (7) smb (6) llmnr (5) igmp (3) ntp (3) ssdp (3)
```

**Reading the result:**

- **Only one internal PC starts sessions: 10.0.14.129** (212). The 3 from 10.0.14.1 are DHCP server replies; 0.0.0.0 is the PC before it has an IP.
- **Nothing came in from outside first.** There is no external IP in Src IP.
- There are only six external IPs. Two stand out by count: 185.174.175.14 (54) and 185.43.223.6 (23). A normal user rarely hits the same external IP dozens of times in 42 minutes.
- `krb5`, `ldap`, `smb` and `dcerpc` mean a **Windows domain (Active Directory)**. That differs from [Back to the Present](back-to-the-present-chthonic-c2-tech-support-scam.md) (a home PC behind a router).

### 1-2. Hostname and MAC (DHCP) { #dhcp }

**Query:**

```text
protocols == dhcp
```

- `protocols` — the list of protocols Arkime identified.
- `== dhcp` — keep DHCP sessions only.

→ **SPIView** → **dhcp** section (if it is not shown, **Load All** at the top right).

**Result (values in the packets):**

```text
Host        Chicago-7fa3-PC
Client MAC  00:1a:92:06:5c:7b
Client OUI  ASUSTek COMPUTER INC.
Type        REQUEST, INFORM, ACK
Vendor      MSFT 5.0
```

**Reading the result:**

- **Host = Chicago-7fa3-PC** — the computer name the PC announced when it asked for an IP.
- **MAC = 00:1a:92:06:5c:7b, OUI = ASUSTek** — the network card's unique number. An IP can change but a MAC rarely does, so it is the host operator's most reliable way to find the machine.
- **MSFT 5.0** — the label the Windows (Vista and later) DHCP client adds.
- **REQUEST from 0.0.0.0 at 02:06:51** — the PC was starting up or rejoining the network and asked for its previous IP (10.0.14.129) again. This matters: **the capture starts right after the PC started** ([step 7 timeline](#timeline)).
- **INFORM** — the PC already has an IP and asks only for other settings. The **REQUESTs at 02:21:51 and 02:36:51** are 15-minute lease renewals. All normal.

### 1-3. User account and domain (Kerberos) { #kerberos }

**Goal:** in a Windows domain, logging on means asking the DC for Kerberos "tickets". Those requests carry the **account name**.

**Query:**

```text
protocols == krb5
```

→ **SPIView** → **krb5** section.

**Result:**

```text
cname   CHICAGO-7FA3-PC$   chicago-7fa3-pc$   faith.hoffman
realm   NIGHTDEW.ORG
sname   krbtgt/NIGHTDEW.ORG   cifs/nightdew-dc.nightdew.org
        ldap/Nightdew-DC.nightdew.org   host/chicago-7fa3-pc.nightdew.org
```

- `cname` — the **account** asking for a ticket. `realm` — the **domain**. `sname` — the **service** it wants.

**Reading the result:**

- **Names ending in `$` are computer accounts** (`CHICAGO-7FA3-PC$`). PCs log on to the domain too; do not confuse them with people.
- **faith.hoffman, with no `$`, is the person (user) account.** Expanding the session shows the ticket request at **02:07:29 UTC** — the moment the user logged on.
- **Domain = NIGHTDEW.ORG**, DC name = **Nightdew-DC.nightdew.org**.
- `cifs` (file sharing), `ldap` (directory lookups) and `host` are what logon and group policy normally use. The only file read over SMB is a group policy file (`sysvol\...\gpt.ini`). This is a **normal domain logon**.

### 1-4. Confirming the DC (DNS) { #dc }

**Query:**

```text
protocols == dns
```

→ **SPIView** → the **dns** section's **Host** (name asked) and **IP** (answer), plus **Dst IP** in general.

**What to look for:**

```text
Dst IP  10.0.14.3 (34)        ← the server receiving DNS questions
Host    _ldap._tcp.dc._msdcs.nightdew.org   → 10.0.14.3
        nightdew-dc.nightdew.org            → 10.0.14.3
```

- `_ldap._tcp.dc._msdcs.<domain>` is how Windows asks **"where is our domain's DC?"**. The answer is 10.0.14.3, so **10.0.14.3 = DC**.
- The DNS server is also 10.0.14.3 (the DC). In a domain the DC usually runs DNS.
- The PC never asked any other DNS server directly. The previous case's bypass (TCP DNS to external resolvers) is **not** present here.

### Baseline summary { #baseline-summary }

| IP | Name | MAC (vendor) | Role |
|---|---|---|---|
| 10.0.14.129 | CHICAGO-7FA3-PC | 00:1a:92:06:5c:7b (ASUSTek) | User PC, Windows 7 x64, faith.hoffman |
| 10.0.14.3 | Nightdew-DC.nightdew.org | 00:1e:4f:88:3f:a6 (Dell) | DC + DNS |
| 10.0.14.1 | — | 00:02:16:47:96:ef (Cisco) | Gateway + DHCP |

---

## Step 2 — External destinations: who did it talk to, and how much { #external }

**Result:** of six external IPs, three are suspicious (185.43.223.6, 111.90.144.30, 185.174.175.14) and one (api.ipify[.]org) is a legitimate service that the malware used. The other two are normal Windows and Google traffic.

**Query:**

```text
ip.src == 10.0.14.129 && ip.dst != [10.0.0.0/8, 224.0.0.0/4, 255.255.255.255]
```

- `ip.src == 10.0.14.129` — sessions **started** by the suspect PC.
- `&&` — AND; both conditions must be true.
- `ip.dst != [...]` — destination matches **none** of the list.
- `10.0.0.0/8` — all internal addresses. `224.0.0.0/4` — multicast (LLMNR, SSDP and other local broadcasts). `255.255.255.255` — broadcast. Removing these leaves **only traffic to the internet**.

→ Sort the **Sessions** tab by **Dst IP**, or read SPIView's general (Dst IP), http (Hostname) and tls sections together. For bytes, add the **Src Bytes / Dst Bytes** columns in the Sessions tab (right-click a column header → add column).

**Result (summary):**

| Dst IP | Port | Name (DNS / Host / SNI) | Sessions | First – last (UTC) | Sent / received | Verdict |
|---|---|---|---|---|---|---|
| 185.174.175.14 | 443 | robwassotdint[.]ru | 54 | 02:10:16 – 02:45:46 | ~120 KB / 1.65 MB | **Malicious** ([step 6](#tls-c2)) |
| 185.43.223.6 | 80 | lysedsohap[.]com | 23 | 02:08:04 – 02:48:25 | ~16 KB / 12 KB | **Malicious** ([step 3](#checkin), [step 5](#exfil)) |
| 111.90.144.30 | 80 | wansaiful[.]com | 1 | 02:08:05 – 02:08:15 | ~5 KB / 264 KB | **Malicious** ([step 4](#downloads)) |
| 184.72.249.110 | 80 | api.ipify[.]org | 1 | 02:08:04 | 0.5 KB / 0.5 KB | Legitimate service, **used by the malware** |
| 216.58.193.68 | 443 | www.google.com | 1 | 02:20:16 | 3.7 KB / 84 KB | Looks normal |
| 173.223.52.18 | 80 | www.msftncsi.com | 1 | 02:07:02 | 0.4 KB / 0.5 KB | Normal (Windows connectivity check) |

**Reading the result:**

- **185.174.175.14 — 54 sessions, 1.65 MB received.** The PC kept going back to one server for 35 minutes, and `robwassotdint[.]ru` is a meaningless string.
- **185.43.223.6 — 23 sessions.** Steady contact for 40 minutes; `lysedsohap[.]com` also looks random. More sent (16 KB) than received (12 KB) is the opposite of normal browsing.
- **111.90.144.30 — 264 KB received in one session.** Something was downloaded.
- **api.ipify[.]org** — a legitimate "what is my public IP?" service. A corporate PC rarely asks it, but **malware often does right after infection**. Look at the times: ipify at 02:08:04, lysedsohap[.]com 0.5 s later, wansaiful[.]com 1 s later. One chain.
- **www.google.com** — Google's genuine certificate (Google Internet Authority G3), one session only. Not enough to judge, so it stays out of the report.
- **www.msftncsi.com/ncsi.txt** — Windows' "is the internet reachable?" check, User-Agent `Microsoft NCSI`. Normal.

!!! tip "Spotting suspicious external IPs quickly"
    1. Many sessions to a single destination (beacon candidate)
    2. A domain name that is a random string
    3. A large download in one session
    4. Different external IPs appearing **within seconds of each other** (one program's sequence)

---

## Step 3 — HTTP check-ins: what was sent to lysedsohap[.]com { #checkin }

**Result:** the PC sent its own details (hostname, domain\user, public IP, OS) to `lysedsohap[.]com/4/forum.php` **21 times, about every 2 minutes**. The first reply held encrypted "download from these URLs" commands. A classic **downloader (Hancitor-style) C2**.

### 3-1. All HTTP at once { #http-overview }

**Query:**

```text
protocols == http
```

→ **SPIView** → **http** section.

**Result (Arkime screen):**

```text
Hostname   lysedsohap.com (23)  api.ipify.org (1)  wansaiful.com (1)  www.msftncsi.com (1)
URI        lysedsohap.com/4/forum.php (21)  lysedsohap.com/mlu/forum.php (1)
           lysedsohap.com/d2/about.php (1)  api.ipify.org/ (1)
           wansaiful.com/wp-content/plugins/easy-media-download/1, /2, /3
           www.msftncsi.com/ncsi.txt (1)
Useragent  Mozilla/5.0 (Windows NT 6.1; Win64; x64; Trident/7.0; rv:11.0) like Gecko (23)
           Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 6.1; WOW64; ...) (2)
           Microsoft NCSI (1)
http.request.content-type   application/x-www-form-urlencoded (21)  application/octet-stream (2)
http.request.referer        No data for this field
http.response.server        nginx/1.10.2 (23)  Cowboy (1)  nginx (1)
```

**Reading the result:**

- **23 of the 26 HTTP sessions go to lysedsohap[.]com**, 21 of them to the same path `/4/forum.php`. The same thing repeated to the same URL suggests a beacon.
- **There is no Referer at all.** A person clicking a link in a browser normally sends a Referer (the page they came from). A program **knew the URL and requested it directly**.
- **An IE11-looking User-Agent proves nothing.** A program can write any User-Agent it likes. The two `MSIE 7.0` entries (a 2007 browser) next to IE11 on a Windows 7 PC are odd in themselves ([step 5](#exfil)).
- **Two kinds of request body** — `x-www-form-urlencoded` (21) = text name=value pairs; `octet-stream` (2) = binary. Look at them separately.

### 3-2. Opening the first check-in { #first-checkin }

**Query:**

```text
ip.src == 10.0.14.129 && host.http == lysedsohap.com && http.uri == *4/forum.php*
```

- `host.http` — the HTTP Host name.
- `http.uri == *4/forum.php*` — `*` means "any characters"; URIs containing `4/forum.php`. (Arkime stores the URI with the host in front: `lysedsohap.com/4/forum.php`.)

→ The **Sessions** tab shows 21 rows. **Sort by Start Time**, expand the top one (02:08:04) with ⊕, and choose the **natural** (or ascii) view in the packet pane.

**Result (request):**

```text
POST /4/forum.php HTTP/1.1
Accept: */*
Content-Type: application/x-www-form-urlencoded
User-Agent: Mozilla/5.0 (Windows NT 6.1; Win64; x64; Trident/7.0; rv:11.0) like Gecko
Host: lysedsohap.com
Content-Length: 123
Cache-Control: no-cache

GUID=10412771973665002240&BUILD=09fhx05&INFO=CHICAGO-7FA3-PC @ NIGHTDEW\faith.hoffman&IP=173.236.56.182&TYPE=1&WIN=6.1(x64)
```

**The body, piece by piece:**

| Name | Value | Meaning |
|---|---|---|
| `GUID` | 10412771973665002240 | Unique ID per infected PC; how the attacker tells victims apart |
| `BUILD` | 09fhx05 | Malware build (campaign) name |
| `INFO` | CHICAGO-7FA3-PC @ NIGHTDEW\faith.hoffman | **hostname @ domain\user** — confirms the victim host and user from traffic alone |
| `IP` | 173.236.56.182 | The **public IP** that api.ipify[.]org just returned (the network's internet-facing address) |
| `TYPE` | 1 | Internal malware value |
| `WIN` | 6.1(x64) | Windows version 6.1 = **Windows 7, 64-bit** |

- **This explains the api.ipify[.]org call.** ipify's answer (173.236.56.182) went to the C2 0.5 s later, tying both sessions into one action without guesswork.
- **The body alone is enough for a malicious verdict.** Legitimate software does not send domain\user and the public IP to a random-named external server.

### 3-3. Decoding the first reply in CyberChef { #cyberchef }

**Result (response):**

```text
HTTP/1.1 200 OK
Server: nginx/1.10.2
Content-Type: text/html
Transfer-Encoding: chunked
X-Powered-By: PHP/5.4.45

59c
GKPTARZAEg4OCkBVVQ0bFAkbExwPFlQZFRdVDQpXGRUUDh8UDlUKFg8dExQJVR8bCQNXFx8e...
0
```

- `Transfer-Encoding: chunked` — the body is sent in chunks. `59c` is the next chunk's size (hex 0x59c = 1436 bytes) and the final `0` means "end". **They are not part of the body — leave them out when copying.**
- The body uses only `A-Z a-z 0-9 + /`: it looks like **Base64**.

**CyberChef recipe:**

1. Paste only the text between `59c` and `0` into Input. (If the packet split it across lines, remove the line breaks.)
2. **From Base64** — turns the Base64 back into bytes. Still unreadable.
3. **XOR** — Key `7a`, format **HEX**. XORs every byte with 0x7A, giving the original text.

**Result (CyberChef Output, wrapped for reading):**

```text
b..{l:http://wansaiful.com/wp-content/plugins/easy-media-download/1
       |http://www.victoryoutreachvallejo.com/wp-content/plugins/regenerate-thumbnails/includes/1
       |http://medleysoup.com/wp-content/plugins/comicpress-manager/1
       |http://radiantheartcoaching.com/blog/wp-content/themes/twentyten/1
       |http://hdmicablereviews.com/wp-content/plugins/google-sitemap-generator/1}
    {b:http://wansaiful.com/wp-content/plugins/easy-media-download/2|... (same 5 sites, /2)}
    {r:http://wansaiful.com/wp-content/plugins/easy-media-download/3|... (same 5 sites, /3)}
```

**Reading the result:**

- The first few bytes (`b..`) are meaningless; the **commands** follow, in three `{letter:URL|URL|...}` blocks.
- Each command lists **the same file on 5 servers** — a fallback list in case one is blocked. This PC **got everything from the first, wansaiful[.]com**, and never contacted the other four. Record those four as IOCs to hunt for on other networks.
- Every URL is in a **WordPress plugin/theme folder** (`wp-content/plugins/...`) — the typical shape of malware hidden on hacked legitimate WordPress sites.
- `l`, `b` and `r` are command letters that say how to run each downloaded file. Public analyses describe Hancitor using such letters to choose an execution method (run directly, inject into another process, …). The exact meaning per letter needs host confirmation, so the report says only "3 download commands".

**Later replies:** the 20 replies after 02:10:15 are all 12 bytes (e.g. `TGTGARRABw==`). The same recipe leaves `{n:}` at the end — "no new task, wait".

### 3-4. Measuring the beacon interval { #beacon-interval }

→ Sort the 21 results from 3-2 by **Start Time**.

```text
02:08:04  02:10:15  02:12:16  02:14:16  02:16:17  02:18:17  02:20:18
02:22:18  02:24:19  02:26:19  02:28:20  02:30:20  02:32:21  02:34:21
02:36:22  02:38:22  02:40:23  02:42:24  02:44:24  02:46:25  02:48:25
```

- After the first check-in the gap is **almost exactly 120.5 seconds**. People are not that regular; this is a timer-driven **automatic beacon**.
- The body is identical every time (123 bytes, same GUID) and the reply is `{n:}`. **The C2 was alive and waiting to issue the next task** when the capture ended.


---

## Step 4 — Follow-up downloads: three files from wansaiful[.]com { #downloads }

**Result:** one second after receiving the C2 commands the PC downloaded three files from `wansaiful[.]com` (111.90.144.30) (02:08:05–02:08:15, 252,979 bytes in total). They were served as `text/plain` and are encrypted, so they do not look like EXEs.

**Query:**

```text
ip.src == 10.0.14.129 && host.http == wansaiful.com
```

→ **Only one session** comes back. Expanding it shows **three requests** inside (SPIView's `URI Cnt 3 (1)`). With **keep-alive** one connection carries several requests, so session and request counts can differ.

**Result (session detail, three request/response pairs):**

```text
02:08:05  GET /wp-content/plugins/easy-media-download/1   Host: wansaiful.com
          200  Content-Type: text/plain  Content-Length: 46341   Last-Modified: Thu, 10 May 2018 13:29:43 GMT
02:08:13  GET /wp-content/plugins/easy-media-download/2
          200  Content-Type: text/plain  Content-Length: 47383   Last-Modified: Thu, 10 May 2018 13:29:50 GMT
02:08:14  GET /wp-content/plugins/easy-media-download/3
          200  Content-Type: text/plain  Content-Length: 159255  Last-Modified: Thu, 10 May 2018 13:29:58 GMT
User-Agent: Mozilla/5.0 (Windows NT 6.1; Win64; x64; Trident/7.0; rv:11.0) like Gecko   Referer: (none)
Server: nginx
```

**File hashes (extracted on the analysis VM):**

```bash
tshark -r 2018-05-11-traffic-analysis-exercise.pcap --export-objects http,http_objects
sha256sum http_objects/1 http_objects/2 http_objects/3
file http_objects/1
```

- `--export-objects http,folder` — saves every file transferred over HTTP into the folder. **Never run them.**
- `sha256sum` — the file's SHA256. `file` — identifies the file type from its content.
- Arkime also shows each request's **Body MD5** in the session detail and offers a file download link.

```text
File  Size(B)  MD5                               SHA256
/1    46341   ae9dfd2190b07927078cb4a19d0b2187  e1011c8688b88154d7c942895bd5a00abff857677581b638651a84d5eb77df45
/2    47383   74eb0ec9c04ddf315053773aba5bcb01  a19b56853afe9d6ba3d3b897b54dd3eee68730e630b48d7aae587a01bf5ffc74
/3    159255  b799ac083efb27e51c46ea1542f89b12  97ca86f8d6c62efb24219db591b7a97e261f25a40c5d9d92329d7e0d9ff8e4d9

file: data   (all three)
```

**Reading the result:**

- **They are exactly the first URL of each command decoded in step 3.** C2 reply (02:08:04) → download 1 s later (02:08:05). Command and execution are linked in the traffic.
- **`text/plain`, but the content is binary (`data`).** The server sets Content-Type however it likes; do not trust it. In Arkime check **http.bodymagic** (the type judged from the content) as well.
- **No `MZ` at the start.** Windows executables always begin with `MZ`; these files are encrypted. That evades "EXE download" detection — the downloader on the PC decrypts and runs them after download. So these hashes are of **the encrypted files seen on the network**, not of the executables written to disk. Say so in the report so the host operator is not misled.
- **Last-Modified is the previous day (2018-05-10), 7 seconds apart.** It looks like the attacker uploaded all three to the hacked site in one go the day before.
- The next clue is what new traffic appears after the download. Within 3 s, **two POSTs with an MSIE 7.0 User-Agent** ([step 5](#exfil)); 2 minutes later, **a TLS server never seen before** ([step 6](#tls-c2)). New programs had started running.

---

## Step 5 — Exfiltration: two binary POSTs { #exfil }

**Result:** right after the downloads, **a different program** sent encrypted data to the same C2 server twice (206 + 234 bytes). The header shape matches how the Pony credential stealer uploads. The content is encrypted, so the traffic alone does not show what was taken.

**Query:**

```text
ip.src == 10.0.14.129 && http.request.content-type == application/octet-stream
```

- `http.request.content-type` — the type of the **request** body (what the PC sent). Clicking `application/octet-stream (2)` from step 3-1 and choosing **and** inserts it for you.

→ **Two** sessions. Expand both and read the request headers.

**Result:**

```text
02:08:12  10.0.14.129:49200 -> 185.43.223.6:80
POST /mlu/forum.php HTTP/1.0
Host: lysedsohap.com
Accept: */*
Accept-Encoding: identity, *;q=0
Accept-Language: en-US
Content-Length: 206
Content-Type: application/octet-stream
Connection: close
Content-Encoding: binary
User-Agent: Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 6.1; WOW64; Trident/7.0; SLCC2; ...)

(206 bytes of binary — unreadable)

02:08:14  10.0.14.129:49202 -> 185.43.223.6:80
POST /d2/about.php HTTP/1.0
... (same header shape)  Content-Length: 234
```

**Reading the result — compared with the check-ins ([step 3](#checkin)):**

| Item | Check-in `/4/forum.php` | These two POSTs |
|---|---|---|
| HTTP version | 1.1 | **1.0** |
| User-Agent | IE11 (`rv:11.0`) | **MSIE 7.0** |
| Body | Readable `GUID=...` | **Encrypted binary** |
| Unusual header | None | `Content-Encoding: binary` |
| How often | Every 2 minutes | **Once each** |

- **Same server, different program.** The header habits are completely different. One of the files downloaded in step 4 most likely ran and sent these (right after the last download at 02:08:14).
- **`Content-Encoding: binary` is not a standard HTTP value** (standard ones are gzip, deflate, …). Odd headers like this act as a malware fingerprint and are good Snort material. This header combination plus the `MSIE 7.0` User-Agent is a known trait of the **Pony** credential stealer.
- **Sending once and stopping** is typical too. Pony usually gathers passwords saved in browsers, email and FTP clients, uploads them in one go and exits.
- **The amount is small (440 bytes in total).** There may have been few or no saved passwords. But **since you cannot verify what left, treat it as stolen** and recommend resetting faith.hoffman's password. In security, unknown means assume the worse.
- In the report, write the family as an assessment: "consistent with Pony – unconfirmed". In a closed network there was no hash lookup or sandbox to confirm it.

---

## Step 6 — TLS C2: robwassotdint[.]ru and a self-signed certificate { #tls-c2 }

**Result:** from 2 minutes after the downloads (02:10:16) the PC opened **54 TLS sessions in bursts about every 5 minutes** to `robwassotdint[.]ru` (185.174.175.14:443). The server used a **self-signed certificate** with OpenSSL defaults (`Default Company Ltd`), and the PC received about 1.65 MB. The content is encrypted, but the pattern matches a banking trojan's (Zeus Panda Banker-like) HTTPS C2.

### 6-1. All TLS at once { #tls-overview }

**Query:**

```text
ip.src == 10.0.14.129 && protocols == tls
```

→ **SPIView** → **tls** and **cert** sections (Load All if hidden).

**Result:**

```text
Host (SNI)    robwassotdint.ru (54)   www.google.com (1)
Dst IP        185.174.175.14 (54)   216.58.193.68 (1)
Version       TLSv1.2 (55)
Cipher        TLS_RSA_WITH_AES_128_CBC_SHA256 (54)   ...(google 1)
Cert Issuer   Default Company Ltd / Default City / XX  (54)
              Google Internet Authority G3 (1)
Cert Subject  Default Company Ltd / Default City / XX  (54)
              www.google.com (1)
Not Before    2018-04-29 19:20:31   Not After  2023-10-20 19:20:31
```

- **SNI** — the "site I want" name the PC sends **in clear text before encryption** when starting TLS. The content is encrypted; the name is not. Arkime puts the SNI in its host fields, so `host == robwassotdint.ru` finds it too.
- **Issuer** — who vouched for the certificate. **Subject** — whose certificate it is.

**Reading the result:**

- **Issuer and Subject are identical = self-signed.** The server made its own certificate, which a browser would warn about. Legitimate sites use a public CA's certificate, like Google's here.
- **`Default Company Ltd`, `Default City`, country `XX`** — the **defaults** OpenSSL fills in when you just press Enter at every prompt. Common on servers that attackers set up in a hurry. (The `Internet Widgits` certificate in the [IcedID case](icedid-tds-gzip-loader-backconnect.md) is the same kind of thing.)
- **The certificate has no domain name.** The SNI is robwassotdint[.]ru but the certificate has no CN and no such name. Legitimate certificates match.
- **Issued 2018-04-29** — a brand-new certificate, 12 days before the capture. Fresh infrastructure is another warning sign.
- Seeing the certificate in clear text is a TLS 1.2-era feature. In TLS 1.3 the certificate is encrypted too.

### 6-2. The connection pattern { #tls-pattern }

**Query:**

```text
ip.src == 10.0.14.129 && ip.dst == 185.174.175.14
```

→ Sort the **Sessions** tab by **Start Time** and look at the **Dst Bytes** column. The bar chart at the top (session count over time) also follows this query.

**Result (sessions per burst):**

```text
Burst start   Sessions   Notes
02:10:16          4
02:15:20          4
02:20:16          6
02:25:27          4
02:30:18          6
02:35:35          4
02:40:16         14       large downloads here: 159 – 206 KB per session
02:42:27          8       up to 524 KB and 421 KB per session
02:45:43          4
Total            54       ~120 KB sent / ~1.65 MB received
```

**Reading the result:**

- **Bursts roughly every 5 minutes.** Sessions come in pairs, and the small ones receive an almost identical 1,442 bytes. A machine-driven **beacon**.
- **Large sessions cluster at 02:40–02:42.** The beaconing C2 most likely pushed a configuration file or extra modules. Banking trojans receive "which bank sites to inject fake input fields into" (webinjects) this way.
- **Far less sent (120 KB) than received (1.65 MB).** No large exfiltration is visible, but because it is encrypted, a small one (passwords and so on) cannot be ruled out.
- **It starts right after the step 4 downloads.** At 02:10:16 the PC asked the DC (10.0.14.3) for robwassotdint[.]ru and connected to the answer, 185.174.175.14, straight away. It had never asked for that name before the downloads. Hence "a downloaded file ran and joined a new C2".
- The single `www.google.com` TLS session (02:20:16) has Google's genuine certificate and happens once, so it stays out of the report. Keep it in your analysis notes in case the host side needs it.

---

## Step 7 — Timeline: putting the events in order { #timeline }

**Result:** malicious activity started **35 seconds** after the user logged on, and the check-in, downloads and exfiltration were all done **within about 11 seconds**. Both C2 channels were still alive when the capture ended. All times are 2018-05-11 UTC.

| Time (UTC) | Event | Evidence (Arkime) |
|---|---|---|
| 02:06:51 | PC start-up / network join, DHCP REQUEST (0.0.0.0 → broadcast) | `protocols == dhcp` |
| 02:07:02 | Windows connectivity check (msftncsi) — normal | `host.http == www.msftncsi.com` |
| 02:07:29 | **faith.hoffman logs on** (Kerberos) | `protocols == krb5` |
| 02:08:04 | **Public IP check at api.ipify[.]org** → 0.5 s later **first lysedsohap[.]com check-in** (download commands received) | `host.http == lysedsohap.com` |
| 02:08:05 – 02:08:15 | **Three encrypted files downloaded from wansaiful[.]com** | `host.http == wansaiful.com` |
| 02:08:12, 02:08:14 | **Two encrypted POSTs** to `/mlu/forum.php` and `/d2/about.php` (likely credential exfil) | `http.request.content-type == application/octet-stream` |
| 02:10:15 | lysedsohap[.]com check-ins resume, then about every 2 min (`{n:}` = wait) | same query |
| 02:10:16 | **First DNS query for robwassotdint[.]ru → first TLS session** | `host == robwassotdint.ru` |
| 02:10 – 02:45 | TLS beacon about every 5 min, 54 sessions in total | `ip.dst == 185.174.175.14` |
| 02:40 – 02:42 | **Large downloads from the TLS C2** (up to 524 KB per session) | Dst Bytes column |
| 02:45:46 | Last TLS C2 session starts | — |
| 02:48:25 | Last lysedsohap[.]com check-in (capture ends 02:49:40) | — |

**Reading the result:**

- **Initial access is not in this PCAP.** There is no email, document download or Office traffic. In the previous case Office DNS lookups came just before the EXE download; there is no such clue here.
- **Two possibilities:** ① the PC was already infected before the capture and the malware auto-started at logon (persistence); ② the user opened an already-downloaded document right after logon. Starting 35 s after logon leans towards ①, but traffic alone cannot tell them apart.
- So the report says "initial access unconfirmed, host confirmation required" and lists where the host operator should look (Run keys, scheduled tasks, recently opened documents, email attachments).
- **No other internal PC in the capture.** But see the correction below: the DC traffic hides password guessing.

!!! warning "Correction from the second pass"
    This pass called the DC traffic normal. A [second pass with Zeek's DCE/RPC log](night-dew-arkime-splunk-netlogon-bruteforce.md#netlogon) found **1,522 `NetrLogonSamLogonWithFlags` calls in 32 seconds** (02:08:12–02:08:45) from 10.0.14.129 to the DC — password guessing through netlogon, starting 0.6 s after the `/mlu/forum.php` POST. It is also why the PC sent 948 KB. Check DC Event 4776 for the accounts and results.

`Not Found` is a result too. Recording "looked, not in the traffic" saves the next analyst from searching again.

---

## Step 8 — Snort rules and test results { #snort }

**Result:** tested against the PCAP, all 8 rules fired **exactly the number of times written down in advance**, and none fired on normal traffic (DC, Google, msftncsi). (Snort 2.9.20, `HOME_NET 10.0.14.0/24`)

### The rules { #snort-rules }

```text
alert tcp $HOME_NET any -> $EXTERNAL_NET $HTTP_PORTS (msg:"Hancitor-style check-in POST to /4/forum.php - Sung"; flow:to_server,established; content:"POST"; http_method; content:"/4/forum.php"; http_uri; content:"GUID="; http_client_body; depth:5; content:"&BUILD="; http_client_body; distance:0; content:"&INFO="; http_client_body; distance:0; classtype:trojan-activity; sid:1000011; rev:1;)

alert tcp $HOME_NET any -> $EXTERNAL_NET $HTTP_PORTS (msg:"Hancitor follow-up payload download from wansaiful.com - Sung"; flow:to_server,established; content:"GET"; http_method; content:"/wp-content/plugins/easy-media-download/"; http_uri; content:"wansaiful.com"; http_header; classtype:trojan-activity; sid:1000012; rev:1;)

alert tcp $HOME_NET any -> $EXTERNAL_NET $HTTP_PORTS (msg:"Pony-style credential exfil POST with Content-Encoding binary - Sung"; flow:to_server,established; content:"POST"; http_method; content:"Content-Type|3a| application/octet-stream"; http_header; content:"Content-Encoding|3a| binary"; http_header; classtype:trojan-activity; sid:1000013; rev:1;)

alert tcp $HOME_NET any -> $EXTERNAL_NET 443 (msg:"TLS Client Hello SNI robwassotdint.ru (Zeus Panda C2) - Sung"; flow:to_server,established; content:"|16 03|"; depth:2; content:"|01|"; offset:5; depth:1; content:"robwassotdint.ru"; nocase; classtype:trojan-activity; sid:1000014; rev:1;)

alert tcp $EXTERNAL_NET 443 -> $HOME_NET any (msg:"TLS certificate with OpenSSL default subject Default Company Ltd from external server - Sung"; flow:to_client,established; content:"Default Company Ltd"; classtype:bad-unknown; sid:1000015; rev:1;)

alert udp $HOME_NET any -> any 53 (msg:"DNS query for Hancitor C2 lysedsohap.com - Sung"; content:"|01 00 00 01 00 00 00 00 00 00|"; offset:2; depth:10; content:"|0a|lysedsohap|03|com|00|"; nocase; distance:0; classtype:trojan-activity; sid:1000016; rev:1;)

alert udp $HOME_NET any -> any 53 (msg:"DNS query for Zeus Panda C2 robwassotdint.ru - Sung"; content:"|01 00 00 01 00 00 00 00 00 00|"; offset:2; depth:10; content:"|0d|robwassotdint|02|ru|00|"; nocase; distance:0; classtype:trojan-activity; sid:1000017; rev:1;)

alert udp $HOME_NET any -> any 53 (msg:"DNS query for Hancitor payload host wansaiful.com - Sung"; content:"|01 00 00 01 00 00 00 00 00 00|"; offset:2; depth:10; content:"|09|wansaiful|03|com|00|"; nocase; distance:0; classtype:trojan-activity; sid:1000018; rev:1;)
```

### One rule taken apart (sid 1000011) { #rule-anatomy }

| Part | Meaning |
|---|---|
| `alert tcp` | Inspect TCP packets; alert on a match |
| `$HOME_NET any -> $EXTERNAL_NET $HTTP_PORTS` | Any internal port → external web ports (80 etc.). Direction matters |
| `flow:to_server,established` | Only data going to the server on an established TCP connection |
| `content:"POST"; http_method` | The HTTP method is POST |
| `content:"/4/forum.php"; http_uri` | The URI contains `/4/forum.php` |
| `content:"GUID="; http_client_body; depth:5` | The **first 5 bytes of the request body** are `GUID=` |
| `content:"&BUILD="; ... distance:0` | `&BUILD=` somewhere after that (`distance:0` = search from where the previous match ended) |
| `content:"&INFO="` | Then `&INFO=` |
| `classtype:trojan-activity` | Category: trojan activity |
| `sid:1000011; rev:1` | Rule number (local rules use 1000000+) and revision |

- **Why not just the URI?** `/4/forum.php` could exist on a real forum. Matching the body's `GUID=...&BUILD=...&INFO=` structure cuts false positives and still catches the malware if the attacker changes domains.
- **sid 1000013** looks only at the odd header combination (`octet-stream` + `Content-Encoding: binary`), with no domain or URI. **Behaviour rules** like this can catch the same malware talking to other servers.
- **sid 1000014** reads the SNI name inside the TLS Client Hello (`|16 03|` = TLS handshake, sixth byte `|01|` = Client Hello). It is visible because it is sent before encryption.
- **sid 1000015** looks the other way (server → PC) for `Default Company Ltd` in the certificate. It is not malware-only (test servers do this too), so the category is lowered to `bad-unknown`.
- In the DNS rules (1000016–1000018), `|01 00 00 01 00 00 00 00 00 00|` is the DNS header for "standard query, 1 question, 0 answers", so they match **questions** only, not answers. `|0a|lysedsohap|03|com|00|` is how DNS stores names (length + label): `0a` = 10-letter `lysedsohap`, `03` = 3-letter `com`, `00` = end.

### Testing { #snort-test }

```bash
sudo snort -T -c /etc/snort/snort.conf
sudo snort -c /etc/snort/snort.conf -r 2018-05-11-traffic-analysis-exercise.pcap -A console -q -k none -U -l /tmp/snorttest | grep -o "\[1:[0-9]*:[0-9]*\] [^[]*" | sort | uniq -c
```

- `-T` — check the configuration and rule syntax only. `-r` — read a PCAP file. `-A console` — print alerts to the screen. `-q` — quiet. `-k none` — also inspect packets with bad checksums (common in capture files). `-U` — UTC timestamps.
- `grep | sort | uniq -c` — counts alerts per sid.

**Result (against the expected counts):**

| sid | Rule | Expected | Actual |
|---|---|---|---|
| 1000011 | Hancitor check-in | 21 (`/4/forum.php` POSTs) | **21** |
| 1000012 | wansaiful.com download | 3 (3 requests) | **3** |
| 1000013 | Pony-style exfil POST | 2 | **2** |
| 1000014 | SNI robwassotdint.ru | 54 (TLS sessions) | **54** |
| 1000015 | `Default Company Ltd` certificate | 54 | **54** |
| 1000016 | DNS lysedsohap.com | 2 (query packets) | **2** |
| 1000017 | DNS robwassotdint.ru | 2 | **2** |
| 1000018 | DNS wansaiful.com | 1 | **1** |

- Count the expected numbers in Arkime (or tshark) **before** running the rules. More than expected means false positives; fewer means misses — fix the rule.
- Check also that sid 1000011 shows 21, not 23. The two Pony POSTs to the same server do not start with `GUID=` and must be excluded.

---

## Copy-ready queries { #query-sheet }

**Arkime**

```text
protocols == dhcp
protocols == krb5
protocols == dns
protocols == http
protocols == tls
ip.src == 10.0.14.129 && ip.dst != [10.0.0.0/8, 224.0.0.0/4, 255.255.255.255]
ip.src == 10.0.14.129 && host.http == lysedsohap.com
ip.src == 10.0.14.129 && host.http == lysedsohap.com && http.uri == *4/forum.php*
ip.src == 10.0.14.129 && host.http == wansaiful.com
ip.src == 10.0.14.129 && host.http == api.ipify.org
ip.src == 10.0.14.129 && http.request.content-type == application/octet-stream
ip.src == 10.0.14.129 && host.dns == [lysedsohap.com, wansaiful.com]
ip.src == 10.0.14.129 && ip.dst == 185.174.175.14
ip.src == 10.0.14.129 && ip.dst == 185.174.175.14 && port.dst == 443
host == robwassotdint.ru
host.dns == robwassotdint.ru
cert.issuer.on == "Default Company Ltd"
```

**CyberChef (Hancitor C2 reply)**

```text
From Base64  →  XOR (Key: 7a, HEX)
```

**Analysis VM**

```bash
TZ=UTC capinfos 2018-05-11-traffic-analysis-exercise.pcap
sha256sum 2018-05-11-traffic-analysis-exercise.pcap
tshark -r 2018-05-11-traffic-analysis-exercise.pcap --export-objects http,http_objects
sha256sum http_objects/*
```

---

## Lessons { #lessons }

1. **In a domain, Kerberos names the user.** A trailing `$` means a computer account; no `$` means a person. Here the malware's own `INFO=` field confirmed the same user.
2. **Legitimate services can be part of malicious activity.** api.ipify[.]org itself is fine, but its answer went to the C2 half a second later. What happened just before and after matters more than the destination alone.
3. **Beacons show themselves through intervals.** About 120 s for HTTP, about 5-minute bursts for TLS. Sort the Sessions tab by Start Time and list the times.
4. **Encryption still leaves patterns and metadata.** Without seeing TLS content, SNI, a default self-signed certificate, the interval and the byte counts were enough to call it C2.
5. **Do not trust Content-Type.** The `text/plain` files were encrypted binaries. Note in the report that network hashes may differ from on-disk hashes.
6. **Same server, different header habits = different program.** HTTP 1.1 vs 1.0, User-Agent and `Content-Encoding: binary` separated the check-ins from the exfiltration.
7. **Follow the infection chain.** Downloader (Hancitor) → commands → downloads → next-stage malware (info stealer, banking trojan). The first new destination after a download is almost always the next stage.
8. **Record what you could not find.** Initial access was not in the PCAP. "Not Found + where to look on the host" hands it to the host operator.

## References { #references }

- [Arkime search syntax](../../network/arkime/search-syntax.md) · [Analysing a PCAP with Arkime](../../network/arkime/offline-pcap-guide.md)
- [Beaconing & C2](../../network/beaconing-c2.md) · [Wireshark & tshark](../../network/wireshark-tshark.md)
- [Invoice email — Word macro to Hancitor-style C2](pcap-lab-06-invoice-macro-c2.md) · [Back to the Present](back-to-the-present-chthonic-c2-tech-support-scam.md) · [IcedID (Cold as Ice)](icedid-tds-gzip-loader-backconnect.md)
- [Playbook: compromised workstation](../playbooks/compromised-workstation.md)
- Original exercise: [malware-traffic-analysis.net — 2018-05-11 Traffic Analysis Exercise: Night Dew](https://malware-traffic-analysis.net/2018/05/11/index.html) · [answers page](https://malware-traffic-analysis.net/2018/05/11/page2.html)
- Hancitor + Zeus Panda Banker infection from the same week: [malware-traffic-analysis.net — 2018-05-14](https://malware-traffic-analysis.net/2018/05/14/index.html)
- Public list naming the same C2 URLs (`/4/forum.php`, `/mlu/forum.php`, `/d2/about.php`) as Hancitor/Pony C2: [Pastebin — HANCITOR](https://pastebin.com/HV3JCi5f)

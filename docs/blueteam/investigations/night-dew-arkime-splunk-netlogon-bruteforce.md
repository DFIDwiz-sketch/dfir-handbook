---
title: Night Dew, second pass — Arkime + Splunk (Zeek) on pcapbox, decoding every C2 reply, netlogon password guessing and one tested Snort rule
tags:
  - blue-team
  - pcap
  - arkime
  - splunk
  - zeek
  - cyberchef
  - snort
  - c2
  - tls
  - dce-rpc
---

# Night Dew, second pass — Arkime + Splunk (Zeek), netlogon password guessing and one Snort rule { #night-dew-2 }

!!! abstract "Case summary"
    The same malware-traffic-analysis.net 2018-05-11 "Night Dew" PCAP as the [first pass](night-dew-hancitor-pony-zeus-panda-tls-c2.md), worked again **from zero, as if the PCAP were unknown**, on the home-lab **pcapbox** VM. Arkime is the main tool; **Splunk with Zeek logs** is used wherever counting, sorting or protocol detail is easier there. One Windows 7 PC (**CHICAGO-7FA3-PC, user faith.hoffman**) checks in to `lysedsohap[.]com`, is told (Base64 + XOR `0x7a`) to download three encrypted files from a hacked WordPress site, sends **two small encrypted POSTs** (likely stolen passwords), starts a **second C2 over TLS** with a default self-signed certificate, and — new in this pass — makes **1,522 netlogon logon checks against the DC in 32 seconds** (password guessing). It ends with **one Snort rule** that fires on all 21 check-ins/beacons, a beginner's guide to testing it, and a short report.

| | |
|---|---|
| **Evidence** | `2018-05-11-traffic-analysis-exercise.pcap` — 2018-05-11 02:06:51 – 02:49:41 UTC (42 min 50 s), 216 sessions, SHA256 `b2c8d0fe…13e51e` |
| **Source** | [malware-traffic-analysis.net 2018-05-11 "Night Dew"](https://malware-traffic-analysis.net/2018/05/11/index.html) |
| **Environment** | Closed network. pcapbox VM: Arkime (tag = case name), Splunk (`index=zeek`, field `pcap_case`), Snort 2.9.20, CyberChef |
| **Deliverables** | Analysis, decoded C2 commands, one Snort rule tested against the PCAP |
| **Related pages** | [First pass (Arkime + CyberChef + 8 Snort rules)](night-dew-hancitor-pony-zeus-panda-tls-c2.md) · [Arkime search syntax](../../network/arkime/search-syntax.md) · [SPL cheat sheet](../splunk/spl-cheatsheet.md) · [Zeek logs](../../network/zeek/index.md) · [Beaconing & C2](../../network/beaconing-c2.md) |

!!! tip "How to read this page"
    Every step has the same order: **Goal → Arkime → Splunk (when it is easier) → Result → Reading the result**. The **Question** boxes are questions asked while working the case, with their answers. Every SPL query is explained line by line.

    The rule used throughout: **analyse an unknown PCAP**. No answer is taken from public write-ups; every finding comes from what the screen shows. Malware family names are therefore left **unconfirmed**.

!!! warning "The indicators on this page are real"
    Domains, IPs and hashes come from real 2018 malware traffic. Prose and tables are defanged (`hxxp`, `[.]`); code blocks keep the values as typed. **Do not visit them.** Do not run anything you extract.

## What this pass adds to the first pass { #what-is-new }

| Topic | First pass | This pass |
|---|---|---|
| DC traffic | "Normal domain activity only" | **1,522 × `NetrLogonSamLogonWithFlags` in 32 s = password guessing through the DC** ([Step 5](#netlogon)) |
| Tools | Arkime, tshark | Arkime **and Splunk (Zeek `conn`, `http`, `files`, `ssl`, `kerberos`, `dhcp`, `dce_rpc` logs)** |
| Second-component POSTs | Analysed (header pattern, family named) | Analysed from zero: Splunk POST summary + headers, family left unconfirmed ([3-6](#exfil)) |
| C2 replies | First reply decoded | First reply **and the beacon reply** (`{n:}` = no command) decoded; fallback download sites checked |
| Snort | 8 rules | **1 rule**, explained part by part, plus a full beginner's testing guide |

## Answers at a glance { #answers }

| Item | Answer | Status |
|---|---|---|
| Infected PC | **10.0.14.129, CHICAGO-7FA3-PC**, MAC `00:1a:92:06:5c:7b` (ASUSTek), Windows 7 x64 | Confirmed |
| User | **faith.hoffman** (domain NIGHTDEW) | Confirmed |
| First malicious event | **02:08:04 UTC** — public IP lookup, then C2 check-in | Confirmed |
| Initial access | Not in the capture. The malware was already on the PC and ran at logon | Inferred |
| HTTP C2 | `lysedsohap[.]com` 185.43.223.6:80, POST `/4/forum.php` × 21 (check-in + beacon every ~120 s) | Confirmed |
| Downloads | `wansaiful[.]com` 111.90.144.30:80, 3 encrypted files (`/1`, `/2`, `/3`) | Confirmed |
| Second component | POST `/mlu/forum.php` (206 B) and `/d2/about.php` (234 B) at 02:08:12–02:08:14, MSIE 7.0 User-Agent, encrypted body, `Content-Encoding: binary` — likely credential theft | Confirmed (content encrypted) |
| Password guessing | 1,522 netlogon logon checks to DC 10.0.14.3 in 32 s (02:08:12–02:08:45) | Confirmed (accounts and results not visible) |
| TLS C2 | `robwassotdint[.]ru` 185.174.175.14:443, 54 sessions, ~5-minute cycle, self-signed `Default Company Ltd` cert, ~1.5 MB delivered at 02:40–02:42 | Confirmed |
| External exfiltration | No large uploads. Two small encrypted POSTs (440 B in total) — treat as stolen credentials | Confirmed (content not readable) |
| Malware family | Downloader + second component + TLS C2 — names **not confirmed** | Not confirmed |

---

## Step 0 — Put the PCAP into pcapbox and fix the clock { #prep }

**Goal:** load the PCAP once, give it a **case name**, and make sure every tool shows **UTC**.

### 0-1. Ingest { #ingest }

1. Rename the PCAP to the case name you want, for example **`20180511_NIGHT_DEW.pcap`**.
2. Drop it into `\\10.50.10.60\incoming` from the host PC.
3. On pcapbox, watch the ingest log until the case is done:

```bash
tail -f /data/logs/ingest.log
```

- `tail -f` shows the end of the file and keeps printing new lines as they arrive. Press **Ctrl+C** to stop.
- Wait for `DONE case=20180511_NIGHT_DEW ...`. The `START` line above it has `sha256=` — that is the **evidence hash** for the report.

!!! question "Question: the current setup seems to add a tag to tell different PCAPs apart — is that right?"
    Yes. The **file name without the extension becomes the case name**, and every tool uses it:

    - **Arkime:** `capture -t <case>` tags every session → search `tags == 20180511_NIGHT_DEW`.
    - **Splunk (Zeek):** logs are written to `/data/zeek/<case>/`; `props.conf` extracts the folder name as the field **`pcap_case`** → `pcap_case=20180511_NIGHT_DEW`.
    - **Splunk (Snort):** `/data/snort/<case>/alert` → same `pcap_case` field in `index=snort`.
    - **Original copy:** `/data/pcap/<case>.pcap`.

    Same name dropped twice → a time suffix is added (no overwrite). Practice PCAPs reuse the same private IPs, so without the case name results from different exercises mix together.

    List the cases already loaded:

    ```spl
    index=zeek sourcetype=zeek:conn
    | stats count by pcap_case
    ```

    - `stats count by pcap_case` counts connections per case. Result:

    ```text
    pcap_case             count
    20180511_NIGHT_DEW    216
    ```

### 0-2. Make Arkime show UTC { #utc }

The first look at the same PCAP gave two different clocks:

```text
Arkime   11:36:51 – 12:19:41
Splunk   02:06:51 – 02:48:51
```

The difference is exactly **9 h 30 min**. Arkime displays times in the **browser's local time zone** (Adelaide was UTC+9:30 in May 2018); Splunk was already UTC. Reports are written in UTC, so fix Arkime once:

- Top-right user menu → **Settings** → **General** → **Timezone** → **UTC**.
- Splunk: account menu → **Preferences** → **Time zone** = UTC (because `strftime`/`convert` print in your Splunk time zone).
- Arkime time range: **All** (2018 data is outside "last hour").

Afterwards Arkime shows `2018/05/11 02:06:51 – 02:49:41 UTC`, which matches Splunk.

!!! note "Why do the end times differ by a minute?"
    Arkime's end is the **last packet** (02:49:41). Zeek's `ts` is the **start** of each connection, so the newest `ts` (02:48:51) is when the last connection began.

---

## Step 1 — The big picture { #overview }

**Goal:** before any detail — when does the capture start and end, how many internal PCs, and who talks the most?

### Arkime { #overview-arkime }

**Sessions** → time range **All** → search:

```text
tags == 20180511_NIGHT_DEW
```

Sort by **Start Time** (oldest first = capture start, click again = capture end). Then **SPIView** → **General**:

```text
Src IP     10.0.14.129 (212)  10.0.14.1 (3)  0.0.0.0 (1)
Dst IP     10.0.14.3 (91)  185.174.175.14 (54)  10.0.14.1 (23)  185.43.223.6 (23)
           224.0.0.252 (5)  255.255.255.255 (4)  10.0.14.129 (3)  10.0.14.255 (3)
           224.0.0.22 (3)  239.255.255.250 (3)  111.90.144.30 (1)  173.223.52.18 (1)
           184.72.249.110 (1)  216.58.193.68 (1)
Protocols  tcp (131) udp (82) tls (55) dns (34) http (26) krb5 (25) ldap (12)
           dhcp (9) dcerpc (7) smb (6) llmnr (5) igmp (3) ntp (3) ssdp (3)
```

### Splunk { #overview-splunk }

**Query ① — capture window and size**

```spl
index=zeek sourcetype=zeek:conn pcap_case=20180511_NIGHT_DEW
| stats min(ts) as first max(ts) as last count as sessions
| eval first=strftime(first,"%Y-%m-%d %H:%M:%S"), last=strftime(last,"%Y-%m-%d %H:%M:%S")
```

- Line 1: Zeek connection log (`conn.log`) for this case only.
- Line 2 `stats`: one summary row. `min(ts) as first` = earliest Zeek time, `max(ts) as last` = latest, `count as sessions` = number of connections.
- Line 3 `eval ... strftime(...)`: `ts` is seconds since 1970 (epoch); `strftime` turns it into a readable date.

```text
first                 last                  sessions
2018-05-11 02:06:51   2018-05-11 02:48:51   216
```

**Query ② — traffic per internal PC**

```spl
index=zeek sourcetype=zeek:conn pcap_case=20180511_NIGHT_DEW id_orig_h="10.0.14.*"
| stats count as sessions sum(orig_bytes) as sent sum(resp_bytes) as received by id_orig_h
| sort - sessions
```

- Line 1 `id_orig_h="10.0.14.*"`: only connections **started** by the LAN. `*` = anything.
- Line 2: per internal IP — connection count, bytes the PC sent (`orig_bytes`), bytes it received (`resp_bytes`).
- Line 3 `sort - sessions`: most connections first (`-` = descending).

```text
id_orig_h      sessions   sent      received
10.0.14.129    215        948119    2206707
```

### Reading the result { #overview-reading }

- **One PC only.** 10.0.14.129 starts almost everything. `0.0.0.0` is a PC asking DHCP for an address before it has one; `10.0.14.1` answers DHCP. The colleague who pulled the traffic most likely **filtered on the alerted host**, so treat **10.0.14.129 as the suspect**.
- **Internal destinations:** 10.0.14.3 (91) is the DC — normal for a domain PC. 224.x/239.x/255.255.255.255/10.0.14.255 are multicast and broadcast.
- **External destinations:** **185.174.175.14 (54)** and **185.43.223.6 (23)**; the other four external IPs have one session each. A person browsing hits dozens of IPs (CDNs, ads); repeated connections to two IPs look like a **program** (beacon). Put both on the suspect list.
- **Sent volume is high.** 948 KB sent vs 2.2 MB received. Workstations normally receive far more than they send. Keep this open — it is answered in [Step 5](#netlogon).
- `tls 55` is close to the 54 sessions to 185.174.175.14 — a hint to check later.

---

## Step 2 — Who is the suspect PC? { #identity }

**Goal:** the report needs **IP, MAC, host name and user account**. Know which protocol carries each:

- **MAC and host name → DHCP.** The PC sends both when it asks for an address.
- **User account → Kerberos.** A Windows domain logon tells the DC "I am this user".

### 2-1. DHCP { #dhcp }

**Arkime:**

```text
tags == 20180511_NIGHT_DEW && protocols == dhcp
```

- `protocols == dhcp` keeps DHCP sessions only; `&&` means "and". SPIView → **dhcp**:

```text
Client MAC   00:1a:92:06:5c:7b (9)
Client OUI   ASUSTek COMPUTER INC. (9)
Host         chicago-7fa3-pc (6)  chicago-7fa3-pc.nightdew.org (3)
Type         ACK (5)  INFORM (3)  REQUEST (3)
```

**Splunk:**

```spl
index=zeek sourcetype=zeek:dhcp pcap_case=20180511_NIGHT_DEW
| table _time client_addr assigned_addr mac host_name msg_types
```

- `table` shows only these columns: `client_addr` (the PC's current IP), `assigned_addr` (IP the server gave), `mac`, `host_name` (name the PC sent), `msg_types` (DISCOVER, OFFER, REQUEST, ACK, INFORM).

```text
_time                     client_addr   assigned_addr  mac                host_name        msg_types
2018-05-11 02:06:51.484   10.0.14.129   10.0.14.129    00:1a:92:06:5c:7b  Chicago-7fa3-PC  REQUEST ACK
2018-05-11 02:06:54.702   10.0.14.129                  00:1a:92:06:5c:7b  Chicago-7fa3-PC  INFORM ACK
2018-05-11 02:08:03.883   10.0.14.129                  00:1a:92:06:5c:7b  Chicago-7fa3-PC  INFORM ACK
2018-05-11 02:10:16.166   10.0.14.129                  00:1a:92:06:5c:7b  Chicago-7fa3-PC  INFORM ACK
2018-05-11 02:21:51.705   10.0.14.129   10.0.14.129    00:1a:92:06:5c:7b  Chicago-7fa3-PC  REQUEST ACK
2018-05-11 02:36:51.763   10.0.14.129   10.0.14.129    00:1a:92:06:5c:7b  Chicago-7fa3-PC  REQUEST ACK
```

**Reading:** one MAC everywhere (ASUSTek network card). Host name **Chicago-7fa3-PC**, FQDN `chicago-7fa3-pc.nightdew.org`. REQUEST/ACK every **15 minutes** (02:06:51 → 02:21:51 → 02:36:51) is lease renewal; INFORM is Windows asking for extra settings (for example proxy). **DHCP looks normal** — that is also worth knowing.

### 2-2. Kerberos { #kerberos }

**Arkime:**

```text
tags == 20180511_NIGHT_DEW && protocols == krb5
```

SPIView → **krb5**:

```text
cname   chicago-7fa3-pc$ (4)  CHICAGO-7FA3-PC$ (2)  faith.hoffman (2)
Realm   NIGHTDEW.ORG (21)  NIGHTDEW (2)  nightdew.org (2)
sname   krbtgt/NIGHTDEW.ORG (7)  cifs/nightdew-dc.nightdew.org (3)  ldap/Nightdew-DC.nightdew.org (3)
        LDAP/Nightdew-DC.nightdew.org (2)  chicago-7fa3-pc$@NIGHTDEW.ORG (2)  krbtgt/NIGHTDEW (2) ...
```

- A name ending in **`$`** is a **computer account** (the PC itself). A name without `$` is a **person**. The only person here is **faith.hoffman**.

!!! question "Question: what is the difference between cname and sname?"
    Every Kerberos request says **who** and **for what**.

    - **cname (client name)** — who is asking: a user (`faith.hoffman`) or a computer (`CHICAGO-7FA3-PC$`).
    - **sname (service name)** — what the ticket is for, written `service/server`:
        - `krbtgt/NIGHTDEW.ORG` — the "entry pass" (TGT) you get first at logon.
        - `cifs/nightdew-dc.nightdew.org` — file sharing (SMB) on the DC, for logon scripts and group policy.
        - `ldap/Nightdew-DC...` — directory (LDAP) lookups on the DC.
        - `host/chicago-7fa3-pc...`, `chicago-7fa3-pc$` — tickets for the PC itself.

    So "faith.hoffman (cname) asked for krbtgt (sname)" = **faith.hoffman logged on to the domain**.

**Splunk** (summary):

```spl
index=zeek sourcetype=zeek:kerberos pcap_case=20180511_NIGHT_DEW
| stats count by request_type client service success
```

- `stats count by ...` counts each combination.
- `request_type`: **AS** = first logon (TGT request), **TGS** = ticket for a service, **AP** = showing a ticket to a service.
- `client` = `account/realm`, `service` = sname, `success` = true/false.

```text
request_type  client                         service                                   success  count
AP            /NIGHTDEW.ORG                  LDAP/Nightdew-DC.nightdew.org/nightdew.org true     6
AS            CHICAGO-7FA3-PC$/NIGHTDEW.ORG  krbtgt/NIGHTDEW.ORG                       false    1
AS            CHICAGO-7FA3-PC$/NIGHTDEW.ORG  krbtgt/NIGHTDEW.ORG                       true     1
AS            faith.hoffman/NIGHTDEW         krbtgt/NIGHTDEW                           false    1
AS            faith.hoffman/NIGHTDEW         krbtgt/NIGHTDEW.ORG                       true     1
TGS           CHICAGO-7FA3-PC$/NIGHTDEW.ORG  cifs/nightdew-dc.nightdew.org             true     2
...
```

!!! question "Question: can I add the IP of the host that requested the ticket to this query?"
    Yes. Every Zeek log carries the connection fields, so `kerberos.log` has `id_orig_h` (who asked) and `id_resp_h` (the DC). Add time too and you see **when** the user logged on:

    ```spl
    index=zeek sourcetype=zeek:kerberos pcap_case=20180511_NIGHT_DEW client="faith.hoffman*"
    | table _time id_orig_h id_resp_h request_type client service success error_msg
    | sort _time
    ```

    - Line 1 `client="faith.hoffman*"`: only the person's rows; `*` because the value is `faith.hoffman/NIGHTDEW`.
    - Line 2: time, requesting IP, DC IP, type, account, service, success and the **error message**.
    - Line 3: oldest first.

    ```text
    _time                id_orig_h    id_resp_h  request_type  client                  service              success  error_msg
    2018-05-11 02:..:..  10.0.14.129  10.0.14.3  AS            faith.hoffman/NIGHTDEW  krbtgt/NIGHTDEW      false    <..>
    2018-05-11 02:..:..  10.0.14.129  10.0.14.3  AS            faith.hoffman/NIGHTDEW  krbtgt/NIGHTDEW.ORG  true     -
    ```

    Do not read `false` as "wrong password" straight away. Windows usually sends the first AS request **without** proof of the password; the DC refuses with **`KDC_ERR_PREAUTH_REQUIRED`** and the second request succeeds. Always read `error_msg`.

    The **AP** rows with client `/NIGHTDEW.ORG` (no name) are normal too: in AP the user name sits inside the encrypted ticket, so Zeek cannot see it.

**Reading:** IP 10.0.14.129, MAC 00:1a:92:06:5c:7b, host Chicago-7fa3-PC (DHCP name = Kerberos computer account `CHICAGO-7FA3-PC$` — two protocols agree), user **faith.hoffman**, DC/KDC 10.0.14.3.

---

## Step 3 — HTTP first: the check-in and the downloads { #http }

!!! question "Question: shouldn't we look at the HTTP connections first?"
    Yes — for an unknown PCAP, HTTP first is the better order:

    - **It is not encrypted.** URL, file name, User-Agent and the real file type are all visible; TLS shows little more than a server name.
    - **Infections usually start with a download**, often over HTTP, so HTTP finds **when it started**.
    - **It is small.** 26 HTTP sessions can be read top to bottom in time order.

    Following "the IP with the most sessions" also works, but it jumps into the middle of the story.

### 3-1. Which names led to the suspect IPs (DNS) { #dns }

**Arkime:**

```text
tags == 20180511_NIGHT_DEW && ip.dns == [185.174.175.14, 185.43.223.6]
```

- `ip.dns` = IPs inside DNS **answers**; `[A, B]` = A or B.

```text
02:08:04  10.0.14.129 -> 10.0.14.3:53  lysedsohap.com     -> 185.43.223.6
02:08:12  10.0.14.129 -> 10.0.14.3:53  lysedsohap.com     -> 185.43.223.6
02:10:16  10.0.14.129 -> 10.0.14.3:53  robwassotdint.ru   -> 185.174.175.14
02:40:16  10.0.14.129 -> 10.0.14.3:53  robwassotdint.ru   -> 185.174.175.14
```

**Reading:**

- Both names look like **random letters joined together**, not a company or service — common for malware domains (a reason to suspect, not proof).
- `robwassotdint.ru` is asked **exactly 30 minutes apart** (02:10:16 → 02:40:16). People do not re-visit the same site on the second; a cached DNS answer expiring or a program on a timer does.
- `lysedsohap.com` (02:08) comes **before** `robwassotdint.ru` (02:10), two minutes after logon. Look closely at HTTP around **02:08**.

### 3-2. All HTTP in time order { #http-list }

**Arkime:** `tags == 20180511_NIGHT_DEW && protocols == http`, sort by **Start Time**, then **SPIView → http** for Host, URI, User-Agent, Method, Status. Expand (`+`) a session to see headers and body.

**Splunk** (26 sessions in one table):

```spl
index=zeek sourcetype=zeek:http pcap_case=20180511_NIGHT_DEW
| sort _time
| table _time id_resp_h host method uri status_code resp_mime_types response_body_len user_agent
```

- `id_resp_h` server IP · `host` HTTP Host header (pcapbox copies it into Splunk's `host` field) · `method` GET/POST · `uri` path · `status_code` 200/404… · `resp_mime_types` file type Zeek found **by looking at the content** · `response_body_len` reply size · `user_agent` the program that asked.

```text
_time          id_resp_h       host               method  uri                                          status  mime        len     user_agent
02:07:02.035   173.223.52.18   www.msftncsi.com   GET     /ncsi.txt                                    200     text/plain  14      Microsoft NCSI
02:08:04.098   184.72.249.110  api.ipify.org      GET     /                                            200     text/plain  14      Mozilla/5.0 (Windows NT 6.1; Win64; x64; Trident/7.0; rv:11.0) like Gecko
02:08:04.575   185.43.223.6    lysedsohap.com     POST    /4/forum.php                                 200     text/plain  1436    Mozilla/5.0 (... Trident/7.0; rv:11.0) like Gecko
02:08:05.391   111.90.144.30   wansaiful.com      GET     /wp-content/plugins/easy-media-download/1    200                 46341   Mozilla/5.0 (... rv:11.0) like Gecko
02:08:12.248   185.43.223.6    lysedsohap.com     POST    /mlu/forum.php                               200                 20      Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 6.1; WOW64; ...)
02:08:13.732   111.90.144.30   wansaiful.com      GET     /wp-content/plugins/easy-media-download/2    200                 47383   Mozilla/5.0 (... rv:11.0) like Gecko
02:08:14.493   111.90.144.30   wansaiful.com      GET     /wp-content/plugins/easy-media-download/3    200                 159255  Mozilla/5.0 (... rv:11.0) like Gecko
02:08:14.739   185.43.223.6    lysedsohap.com     POST    /d2/about.php                                200                 13      Mozilla/4.0 (compatible; MSIE 7.0; ...)
02:10:15.697   185.43.223.6    lysedsohap.com     POST    /4/forum.php                                 200     text/plain  12      Mozilla/5.0 (... rv:11.0) like Gecko
02:12:16.219   185.43.223.6    lysedsohap.com     POST    /4/forum.php                                 200     text/plain  12      ...
... every ~2 minutes until 02:48:25 ...
```

**What to check in any HTTP list:** a `resp_mime_types` of `application/x-dosexec`, zip, Office or script — especially when it does not match the URI extension; a `host` that is a bare IP; a missing or odd User-Agent; POSTs; and the suspect names from DNS.

### 3-3. Reading the HTTP, line by line { #http-reading }

**① 02:07:02 `www.msftncsi[.]com/ncsi.txt` — normal.** User-Agent `Microsoft NCSI`, reply `Microsoft NCSI` (14 bytes): Windows checking "am I online?" right after logon. Ruling out the normal is part of the job.

**② 02:08:04.098 `api.ipify[.]org/` — suspicion starts.** ipify answers "what is my public IP?". People rarely browse it; programs use it to learn **where they are running**. Reply size **14 bytes** — remember it.

**③ 02:08:04.575 POST `lysedsohap[.]com/4/forum.php` — the key evidence.** Expand the session in Arkime; the request body is:

```text
GUID=10412771973665002240&BUILD=09fhx05&INFO=CHICAGO-7FA3-PC @ NIGHTDEW\faith.hoffman&IP=173.236.56.182&TYPE=1&WIN=6.1(x64)
```

This is the infected PC **registering with its C2 (check-in)**:

- `INFO=` — host name and `DOMAIN\user`, the same values found in Step 2.
- `IP=173.236.56.182` — **14 characters**. ipify's reply was 14 bytes half a second earlier: the malware looked up its public IP and **reported it straight away**. The two requests come from the same program.
- `WIN=6.1(x64)` — Windows 7 64-bit. `GUID`, `BUILD` — victim ID and malware build.
- The User-Agent pretends to be IE11.

The reply is 1,436 bytes of Base64-looking text — not a web page but **encoded commands** (decoded in [3-4](#decode)).

**④ 02:08:05–02:08:14 GET `wansaiful[.]com/wp-content/plugins/easy-media-download/1`, `/2`, `/3`.** One second after the check-in, a different server sends 46,341 / 47,383 / 159,255 bytes. Three warning signs: a **WordPress plugin path** (hacked WordPress sites are common malware storage), file names `1`, `2`, `3` with **no extension**, and an **empty `resp_mime_types`** (Zeek could not identify the content — a normal EXE would show `application/x-dosexec`, so these are probably **encrypted**).

**⑤ 02:08:12 `/mlu/forum.php` and 02:08:14 `/d2/about.php` — the User-Agent changed.** Same server, but `Mozilla/4.0 (compatible; MSIE 7.0; ...)`: a **different program** on the same PC. Most likely one of the files from ④ ran and reported in its own way. MSIE 7.0 is also not what a 2018 Windows 7 PC would really use. What these two POSTs sent is checked in [3-6](#exfil).

**⑥ 02:10:15–02:48:25 POST `/4/forum.php` every ~120 s.** 02:10:15, 02:12:16, 02:14:16, 02:16:17 … 02:48:25 (20 times). In Arkime every one is **573 / 1,183 bytes** and the reply is always 12 bytes. Nobody does that by hand: this is a **beacon** — "any new commands?".

**⑦ 02:10:16 the first `robwassotdint[.]ru` DNS query** — two minutes after the downloads, a new destination. Checked in [Step 4](#tls).

**Initial access is not in this capture.** It starts at logon (02:06:51) and the first check-in is 73 seconds later — there is no email, document or exploit download before it. The PC **was already infected**; the malware ran at logon. Write "initial infection vector not observed in this capture" in the report.

### 3-4. Decoding the C2 reply in CyberChef { #decode }

**Goal:** turn the 1,436-byte reply from ③ into readable text.

**How to recognise and break it:**

1. **Base64?** The text uses only `A–Z a–z 0–9 + /` (and `=`). Base64-decoding it gives unreadable bytes — so there is **one more layer**.
2. **Single-byte XOR is common.** A 1-byte key has only **256** possible values, so try them all (**brute force**). To pick the right one, use a **crib** — text you expect in the answer. The PC downloaded files right after this reply, so the reply probably contains URLs → crib **`http`**.
3. Only key **`0x7a`** (the letter `z`) produced `{l:http://wansaiful.com/wp-content/plugins/easy-media-dow...`.

**CyberChef recipe:**

1. Copy the whole reply body from Arkime (Destination side, from the first character to the last).
2. Recipe: **From Base64**.
3. Add **XOR Brute Force**: Key length `1`, Crib `http`. The row for key `7a` shows `{l:http://...`.
4. Replace XOR Brute Force with **XOR** (Key `7a`, **HEX**). The whole text appears.

**Result:**

```text
bÙ©{l:http://wansaiful.com/wp-content/plugins/easy-media-download/1|http://www.victoryoutreachvallejo.com/wp-content/plugins/regenerate-thumbnails/includes/1|http://medleysoup.com/wp-content/plugins/comicpress-manager/1|http://radiantheartcoaching.com/blog/wp-content/themes/twentyten/1|http://hdmicablereviews.com/wp-content/plugins/google-sitemap-generator/1}{b:http://wansaiful.com/wp-content/plugins/easy-media-download/2|http://www.victoryoutreachvallejo.com/wp-content/plugins/regenerate-thumbnails/includes/2|http://medleysoup.com/wp-content/plugins/comicpress-manager/2|http://radiantheartcoaching.com/blog/wp-content/themes/twentyten/2|http://hdmicablereviews.com/wp-content/plugins/google-sitemap-generator/2}{r:http://wansaiful.com/wp-content/plugins/easy-media-download/3|http://www.victoryoutreachvallejo.com/wp-content/plugins/regenerate-thumbnails/includes/3|http://medleysoup.com/wp-content/plugins/comicpress-manager/3|http://radiantheartcoaching.com/blog/wp-content/themes/twentyten/3|http://hdmicablereviews.com/wp-content/plugins/google-sitemap-generator/3}
```

**Reading:**

- The reply **was** a "download from these addresses" order, and the downloads followed one second later — reply and action line up.
- Three command codes (`l`, `b`, `r`), one file number each (1, 2, 3). What each letter does (run, inject, …) cannot be told from traffic alone, so call them "command codes".
- Each command lists **five sites**: if the first fails, try the next. The PC used only the first.
- All five are WordPress paths (`wp-content/plugins`, `themes`) — hacked WordPress sites used as file stores.
- The first 3 bytes (`bÙ©`) are a header of unknown meaning — leave it out of the report.

!!! warning "Put only values you verified yourself into the report"
    A screenshot-OCR decode can get a few characters wrong. Decode the **original text** yourself in CyberChef before writing URLs into a report.

!!! question "Question: why does it go into CyberChef like that? Please explain."
    **CyberChef** (published by GCHQ) runs in a browser and works like a kitchen: **Input** (ingredients) → **Recipe** (operations stacked in order: Base64, XOR, decompress, …) → **Output**, updated live. No code, and the recipe can be saved and written into a report so another analyst can **reproduce** it. At work, use the **offline version** (one HTML file) — pasting evidence into a website can leak data.

    **Why Base64 first, then XOR?** The server wrapped the commands twice: (1) XOR scrambled `{l:http://...}` into raw bytes; (2) Base64 turned those bytes into text that travels easily in HTTP. Unwrap in **reverse order** — the last wrapper comes off first.

    **Why hide it at all?** A plain `http://wansaiful.com/...1` in a reply is easy for an IDS or proxy to spot. One XOR layer beats simple pattern matching; a 1-byte key is still easy for an analyst.

    **XOR Brute Force and the crib.** XOR with the same key twice gives the original back, so you only need the key. Key length 1 → 256 tries. The crib (`http`) tells CyberChef which of the 256 results is right. **The crib came from what the traffic showed** (downloads right after the reply) — not from a guess.

    **A hint before decoding.** The Base64 text repeats the chunk **`Eg4OCkBV`**. Work it out:

    ```text
    plain        h    t    t    p    :    /
    XOR 0x7a     12   0e   0e   0a   40   55
    Base64       E g 4 O         C k B V
    ```

    `Eg4OCkBV` = `http:/` after XOR and Base64 — repeated because there are 15 URLs. **Repeated chunks inside an encoded blob mean repeated plain text and a short, fixed key.** Real encryption (AES etc.) shows no such repeats.

    **If `http` finds nothing:** try key length 2 or 4; try other cribs (`MZ` for an EXE, `<html`, `{`). If nothing works it is probably real encryption — the key must come from reversing the malware itself.

    Arkime has **Unbase64** and **UnXOR Brute** buttons, but CyberChef chains steps freely and keeps a reproducible recipe.

**Check the fallback sites.** The report needs to say whether the four other sites were contacted:

```text
tags == 20180511_NIGHT_DEW && host == [www.victoryoutreachvallejo.com, medleysoup.com, radiantheartcoaching.com, hdmicablereviews.com]
```

- `host` searches DNS, HTTP and TLS names at once.

```spl
index=zeek sourcetype=zeek:dns pcap_case=20180511_NIGHT_DEW query IN ("www.victoryoutreachvallejo.com","medleysoup.com","radiantheartcoaching.com","hdmicablereviews.com")
| table _time query answers
```

- `query IN (...)` keeps DNS queries for any name in the list.

**Result: nothing in either tool.** The first site worked, so the PC never needed the fallbacks. They are still **attacker infrastructure** — another PC contacting them would be a strong sign of the same infection — so they go into the IOC list as "not contacted".

**Decode the beacon reply too.** The beacon bodies are **identical** to the first check-in (same `GUID=...&INFO=...`, `Content-Length: 123`). Their 12-byte reply is `TGTGARRABw==`. Same recipe (From Base64 → XOR `7a`):

```text
(3-byte header) {n:}
```

The first reply was full of URLs; this one is a command letter with **nothing inside** → "no task right now". That is why every beacon reply is exactly 12 bytes. Once you know the method, reuse it on every reply.

### 3-5. What were the three files? { #files }

**Arkime:**

```text
tags == 20180511_NIGHT_DEW && host.http == wansaiful.com
```

Expand the session and look at the **start of the response body**. A Windows EXE starts with `MZ` and soon shows `This program cannot be run in DOS mode`. **Look only — do not download or run.**

**Splunk (`files.log`):**

```spl
index=zeek sourcetype=zeek:files pcap_case=20180511_NIGHT_DEW tx_hosts="111.90.144.30"
| table _time tx_hosts rx_hosts mime_type seen_bytes total_bytes md5 sha1
```

- `tx_hosts="111.90.144.30"` — files **sent by** that server · `mime_type` type Zeek found from the content · `seen_bytes` bytes actually in the capture · `total_bytes` the size the server announced (equal = **complete file**) · `md5`, `sha1` hashes for the IOC list.

```text
_time          tx_hosts       rx_hosts      mime_type  seen_bytes  total_bytes  md5                               sha1
02:08:05.661   111.90.144.30  10.0.14.129              46341       46341        ae9dfd2190b07927078cb4a19d0b2187  3f329bbc23037dae9ca3ec59cef5af9d27fc2581
02:08:13.972   111.90.144.30  10.0.14.129              47383       47383        74eb0ec9c04ddf315053773aba5bcb01  05e9e5bb412a6efdae73a2063b8f7a09bedfd7f5
02:08:14.743   111.90.144.30  10.0.14.129              159255      159255       b799ac083efb27e51c46ea1542f89b12  ad2ad300cd79496bce063b3624e0bf3e26da16ae
```

**Reading:**

1. **Encrypted blobs, not executables.** No `MZ`, no readable text. Zeek leaves `mime_type` empty; Arkime's libfile says only `application/octet-stream`.
2. **The server lies.** The header says `Content-Type: text/plain`; the content is not text. Headers are whatever the server writes — judge by **content** (that is what Zeek and Arkime's libfile do).
3. **Why encrypt?** So network tools do not see an "EXE download". The downloader decrypts them **in memory**; the key is inside the downloader, so traffic alone cannot decrypt them — that is malware reversing, beyond network analysis.
4. **One connection, three files.** Arkime shows one session (port 49199) with `Method GET (3)` and three Body MD5s — **keep-alive** — while Zeek lists three files. Same event, two views.
5. **Tools agree, files complete.** Arkime's Body MD5s equal Zeek's `md5`, and `seen_bytes = total_bytes` → all three downloads finished; "the download failed" is ruled out.
6. **Last-Modified** `2018-05-10 13:29:43 / 13:29:50 / 13:29:58 GMT`: uploaded **eight seconds apart, the day before** — a freshly prepared campaign. `X-Powered-By: PleskLin` is a hosting control panel, consistent with a hacked hosting site.
7. **Do not trust the server clock.** The reply `Date: 02:02:54 GMT` is five minutes off the packet time (02:08:05). Build timelines from **packet times**.
8. **These hashes are of the encrypted downloads.** The files that actually run on the PC (decrypted) have different hashes, so a hash lookup may find nothing. As **network IOCs** ("is this exact file downloaded again?") they are exact.

!!! tip "Copy hashes, do not retype them"
    Copy hashes straight from the Splunk result. One wrong character makes an IOC useless.

---

### 3-6. The second component's two POSTs — what was sent out? { #exfil }

**Goal:** every POST means the PC **sent** something. ⑤ showed two POSTs from a different program. Before moving on, check what they sent — a small POST can carry stolen passwords.

**Splunk — all POSTs in one table:**

```spl
index=zeek sourcetype=zeek:http pcap_case=20180511_NIGHT_DEW method=POST
| stats count sum(request_body_len) as sent_bytes values(user_agent) as user_agent by uri
| sort - count
```

- Line 1 `method=POST`: only requests that send data.
- Line 2 `stats ... by uri`: one row per path. `count` = how many times, `sum(request_body_len) as sent_bytes` = total bytes the PC sent in the **request body** (`request_body_len` is the request side; `response_body_len` is the reply side), `values(user_agent)` = every different User-Agent on that path.
- Line 3 `sort - count`: most frequent first.

```text
uri              count  sent_bytes  user_agent
/4/forum.php     21     2583        Mozilla/5.0 (Windows NT 6.1; Win64; x64; Trident/7.0; rv:11.0) like Gecko
/mlu/forum.php   1      206         Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 6.1; WOW64; ...)
/d2/about.php    1      234         Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 6.1; WOW64; ...)
```

`/4/forum.php` is 21 × 123 bytes — the check-in and beacons. The other two are sent **once each**.

**Arkime — read the headers:**

```text
tags == 20180511_NIGHT_DEW && http.request.content-type == application/octet-stream
```

- `http.request.content-type` — the type of the **request** body (what the PC sent). In SPIView → http, clicking `application/octet-stream` and choosing **and** inserts it for you.

Two sessions. Expand both:

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

**Reading — compare with the check-in:**

| Item | Check-in `/4/forum.php` | These two POSTs |
|---|---|---|
| HTTP version | 1.1 | **1.0** |
| User-Agent | IE11 (`rv:11.0`) | **MSIE 7.0** |
| Body | Readable `GUID=...` | **Encrypted binary** (`application/octet-stream`) |
| Odd header | None | **`Content-Encoding: binary`** |
| How often | Every 2 minutes | **Once each** |

1. **Same server, different program.** Every header habit is different. One of the files from [3-5](#files) most likely ran and sent these (02:08:12 falls between the downloads of `/1` and `/2`, and `/3` finishes at 02:08:14).
2. **`Content-Encoding: binary` is not a real HTTP value.** Standard values are `gzip`, `deflate`, `br`. A made-up header like this is a **fingerprint of one malware's code** — good for detection.
3. **Send once and stop** fits a password stealer: collect passwords saved in browsers, mail and FTP programs, upload them in one go, finish. This header pattern is reported for a known stealer family (named in the [first pass](night-dew-hancitor-pony-zeus-panda-tls-c2.md#exfil)); here, with no hash lookup or sandbox, the family stays **unconfirmed**.
4. **The content is encrypted, so treat it as stolen.** 440 bytes may mean only a few saved passwords — or none. When you cannot see what left, assume the worse: **reset faith.hoffman's password**.
5. **It connects to Step 5.** The netlogon password guessing starts at 02:08:12.835 — **0.6 s after** the `/mlu/forum.php` POST (02:08:12.248). The same program likely sent its data and then started guessing.
6. Not exfiltration by size: 440 bytes will never show up in a "top uploads" search. **Open every POST**, even small ones.

!!! tip "A second Snort rule, if you want one"
    `Content-Type: application/octet-stream` + `Content-Encoding: binary` in a POST would catch this program on any server. This pass keeps **one** rule ([Step 6](#snort)); the [first pass](night-dew-hancitor-pony-zeus-panda-tls-c2.md#snort) has a tested version of this rule (sid 1000013, 2 alerts).

---

## Step 4 — The second C2 over TLS { #tls }

**Goal:** the IP with 54 sessions. TLS hides the content, but **when, how often, how much and which certificate** are visible.

**Arkime:**

```text
tags == 20180511_NIGHT_DEW && ip == 185.174.175.14
```

Sort by Start Time; expand one session and read the **TLS** and certificate sections:

```text
Time          2018/05/11 02:10:16 – 02:10:17 UTC
Dst IP/Port   185.174.175.14 : 443
Hosts         robwassotdint.ru
Version       TLSv1.2
Cipher        TLS_RSA_WITH_AES_128_CBC_SHA256
JA3           4d7a28d6f2263ed61de88ca66eb011e3
JA3s          80b3a14bccc8598a1f3bbe83e71f735f
JA4           t12d210500_b973bfd88a0e_677eed04e9fb
Certificate   Serial 00becd5c26e55fc46f [86:af:39:2e:9b:42:ec:50:e2:87:f6:42:9e:f7:48:4c:48:bb:bd:95]
              Not Before 2018/04/29 19:20:31 UTC   Not After 2023/10/20 19:20:31 UTC   Days Valid For 2,000
              Issuer Org Default Company Ltd   Subject Org Default Company Ltd
```

**Splunk ① — intervals and connection state:**

```spl
index=zeek sourcetype=zeek:conn pcap_case=20180511_NIGHT_DEW id_resp_h="185.174.175.14"
| sort _time
| delta _time as gap
| table _time id_resp_p service duration orig_bytes resp_bytes conn_state gap
```

- `sort _time` oldest first · `delta _time as gap` = **seconds since the previous connection** (similar values repeating = beacon) · `conn_state` how the connection ended:
    - `SF` normal start and normal end · `S0` request sent, no answer · `REJ` refused · `RSTO`/`RSTR` reset by the client (O) / server (R).

```text
_time          id_resp_p  service  duration  orig_bytes  resp_bytes  conn_state  gap
02:10:16.395   443        ssl      0.84      516         1060        SF
02:10:17.044   443        ssl      1.35      1774        6761        SF          0.65
02:10:18.407   443        ssl      0.76      548         1060        SF          1.36
02:10:18.981   443        ssl      1.32      1758        12297       SF          0.57
02:15:20.311   443        ssl      0.75      548         1060        SF          301.33
02:15:20.873   443        ssl      1.32      1854        1513        SF          0.56
...
02:40:18.725   443        ssl      2.56      1774        152790      SF          0.57
02:40:21.910   443        ssl      2.39      1774        197264      SF          0.50
02:40:24.908   443        ssl      2.38      1758        174971      SF          0.57
02:42:28.043   443        ssl      2.97      1758        403937      SF          0.57
02:42:31.691   443        ssl      2.81      1758        502927      SF          0.60
...
02:45:46.021   443        ssl      1.32      1822        1513        SF          0.58
```

**Splunk ② — TLS summary:**

```spl
index=zeek sourcetype=zeek:ssl pcap_case=20180511_NIGHT_DEW id_resp_h="185.174.175.14"
| stats count min(_time) as first max(_time) as last by server_name version cipher established
| convert ctime(first) ctime(last)
```

- `server_name` = SNI (an empty one would also be a clue — browsers almost always send it) · `established` = handshake finished · `convert ctime()` turns epoch into a readable date.

```text
server_name       version  cipher                           established  count  first                       last
robwassotdint.ru  TLSv12   TLS_RSA_WITH_AES_128_CBC_SHA256  true         54     05/11/2018 02:10:16.589867  05/11/2018 02:45:46.215120
```

**Reading:**

1. **It starts two minutes after the downloads** (02:08:14 → 02:10:16), at the same second as the first `robwassotdint.ru` DNS query — a new channel created by a downloaded file, **separate** from the `lysedsohap.com` downloader C2.
2. **The certificate gives it away.** Issuer = Subject = `Default Company Ltd`, `Default City`, `XX` → **self-signed**, filled with the **OpenSSL defaults** you get by pressing Enter at every prompt. Created 12 days before the infection, valid **2,000 days** (normal certificates: about a year).
3. **~5-minute cycle** (`gap` 288–301 s: 02:10, 02:15, 02:20 … 02:45), in **pairs**: a short connection of exactly **548 / 1,060 bytes** (0.75 s — the handshake and certificate, then close) and a data connection of ~1.8 / 1.5 KB (1.3 s). Fixed sizes and fixed timing = automated **C2 beacon**. A different period from the 2-minute HTTP beacon → a different program.
4. **02:40–02:42: about 1.5 MB comes down** (152,790 / 197,264 / 174,971 / 403,937 / 502,927 / 22,702 / 38,723 bytes) — most of the 2.2 MB the PC received. The 02:42:27 burst is off-cycle (gap 105 s), right after the big transfer. Likely **extra modules or settings** from the C2; contents are encrypted, so the report states only sizes and times.
5. All 54 sessions `SF` and `established = true` — the channel worked until the capture ended (02:45:46).
6. `TLS_RSA_WITH_AES_128_CBC_SHA256` is an old cipher — not evidence by itself, but worth noting.
7. **JA3/JA4** fingerprint the TLS client. On Windows, malware that uses the system TLS library can share a browser's fingerprint, so compare with the PC's other, normal TLS sessions before using JA3 as an IOC.

!!! question "Question: are Issuer CN, Subject CN, Issuer Org and Subject Org all the same thing?"
    No. **Subject** = who the certificate belongs to (the server). **Issuer** = who signed it (normally a certificate authority). Each of the two names has several fields:

    | Field | Meaning |
    |---|---|
    | **CN** (Common Name) | Main name. Subject CN = usually the **domain** (`www.example.com`); Issuer CN = the **CA's name** |
    | **O** (Organization) — shown as **Org** in Arkime | Company or organisation |
    | OU | Department |
    | L | City |
    | ST | State or province |
    | C | Two-letter country code |

    A normal server certificate (example):

    ```text
    Subject : CN=www.example.com,  O=Example Corp,       C=US
    Issuer  : CN=Example CA 2018,  O=Example Trust Inc,  C=US
    ```

    This one:

    ```text
    Subject : C=XX, L=Default City, O=Default Company Ltd   (no CN)
    Issuer  : C=XX, L=Default City, O=Default Company Ltd   (no CN)
    ```

    Three warning signs: **Subject = Issuer** (self-signed), **every field is a default**, and **no Subject CN** — the PC asked for `robwassotdint.ru` (SNI) but the certificate does not name it. A browser would warn; the traffic carried on, so the client **does not check certificates** — malware.

    Arkime fields: `cert.subject.cn`, `cert.issuer.cn` (CN) · `cert.subject.on`, `cert.issuer.on` (Org). A hunting query for lazy C2 certificates:

    ```text
    cert.issuer.on == "Default Company Ltd" && cert.subject.on == "Default Company Ltd"
    ```

    `cert.hash` finds the exact certificate even if the IP or domain changes:

    ```text
    cert.hash == 86:af:39:2e:9b:42:ec:50:e2:87:f6:42:9e:f7:48:4c:48:bb:bd:95
    ```

---

## Step 5 — Where did 948 KB go? Netlogon password guessing { #netlogon }

**Goal:** Step 1 showed **948 KB sent**, but every C2 connection sends little (HTTP POSTs are a few hundred bytes, TLS about 2 KB each — roughly 100 KB in total). If 800 KB went outside, that is exfiltration.

### 5-1. The biggest outbound connections { #top-sent }

```spl
index=zeek sourcetype=zeek:conn pcap_case=20180511_NIGHT_DEW id_orig_h="10.0.14.129"
| sort - orig_bytes
| head 10
| table _time id_resp_h id_resp_p service duration orig_bytes resp_bytes
```

- `sort - orig_bytes` — largest **sent** first · `head 10` — first 10 rows.

```text
_time          id_resp_h  id_resp_p  service           duration  orig_bytes  resp_bytes
02:08:12.835   10.0.14.3  49158      dce_rpc           32.30     779560      231472
02:06:52.227   10.0.14.3  49155      krb,gssapi,dce_rpc 82.91    5859        2854
02:06:52.489   10.0.14.3  445        gssapi,smb,krb    35.61     4342        1558
02:07:30.743   10.0.14.3  445        gssapi,smb,krb    141.35    4187        1306
02:22:49.204   10.0.14.3  445        gssapi,smb,krb    14.88     3853        1200
02:37:49.223   10.0.14.3  445        gssapi,smb,krb    14.86     3853        1200
02:07:49.183   10.0.14.3  445        gssapi,smb,krb    14.90     3694        948
02:21:29.442   10.0.14.3  389        ldap_tcp,krb,gssapi 0.24    3530        3835
02:06:58.781   10.0.14.3  389        krb,gssapi,ldap_tcp 0.03    2934        472
02:06:58.771   10.0.14.3  389        ldap_tcp,krb,gssapi 0.04    2765        3169
```

**Reading:**

- **One connection is almost all of it:** 779,560 bytes to the **DC** (10.0.14.3:49158, DCE/RPC). Everything else is a few KB of normal domain traffic (SMB 445, LDAP 389, Kerberos).
- So **no large upload went outside** — an important conclusion for the report. The only data sent out besides C2 traffic is the two small encrypted POSTs in [3-6](#exfil).
- But this connection is not normal either: it starts at **02:08:12.835**, 0.6 s after the MSIE 7.0 POST to `/mlu/forum.php` (02:08:12.248), and the logon-time RPC connection (02:06:52) sent only 5.8 KB. Find out **which RPC functions** were called.

### 5-2. DCE/RPC in one minute { #dcerpc }

DCE/RPC is how Windows **calls functions on another computer**. A client first **binds** to an **interface (UUID)** — which service to use — then calls an **operation (opnum)** — which function.

| Interface | Service |
|---|---|
| `epmapper` | "Which port is service X on?" (port 135) |
| `netlogon` | Logon handling, secure channel to the DC |
| `samr` | Account management |
| `lsarpc` | Security policy, SID ↔ name |
| `drsuapi` | Active Directory replication and name translation |

The arguments can be encrypted (Kerberos — hence `krb,gssapi` in `service`), but **interface and operation names are visible**, so Zeek logs them.

### 5-3. Which functions were called { #dce-rpc-log }

```spl
index=zeek sourcetype=zeek:dce_rpc pcap_case=20180511_NIGHT_DEW
| stats count min(_time) as first by id_resp_p named_pipe endpoint operation
| convert ctime(first)
| sort first
```

- `named_pipe` — pipe name over SMB; for a direct high port it shows the port · `endpoint` — interface · `operation` — function called · `count`, `first` — how often and when first.

```text
id_resp_p  named_pipe  endpoint  operation                    count  first
135        135         epmapper  ept_map                      4      05/11/2018 02:06:52.151891
49158      49158       netlogon  NetrServerReqChallenge       1      05/11/2018 02:06:52.152403
49158      49158       netlogon  NetrServerAuthenticate3      1      05/11/2018 02:06:52.153549
49158      49158       netlogon  NetrLogonGetCapabilities     1      05/11/2018 02:06:52.1553
49158      49158       netlogon  NetrLogonGetDomainInfo       1      05/11/2018 02:06:52.155301
49155      49155       drsuapi   DRSBind                      2      05/11/2018 02:06:52.257323
49155      49155       drsuapi   DRSCrackNames                4      05/11/2018 02:06:52.257826
49155      49155       drsuapi   DRSUnbind                    2      05/11/2018 02:06:52.258333
49158      49158       netlogon  NetrLogonSamLogonWithFlags   1522   05/11/2018 02:08:12.836886
49155      49155       lsarpc    LsarLookupSids3              1      05/11/2018 02:08:27.138847
```

**Reading:**

- **Normal (02:06:52, logon):** `ept_map` (find the port), `NetrServerReqChallenge` / `NetrServerAuthenticate3` / `GetCapabilities` / `GetDomainInfo` (the PC sets up its **secure channel** with the DC — every domain PC does this at start-up), `DRSBind` / `DRSCrackNames` / `DRSUnbind` (name format translation, common at logon). Once each, at logon time.
- **Not normal: `NetrLogonSamLogonWithFlags` × 1,522 from 02:08:12.836.** This asks the DC **"is this account and password correct?"** When someone logs on to the PC with NTLM, the PC cannot decide itself and asks the DC. Normally that happens a few times. Here it is **1,522 times in 32 seconds — about 47 per second**. No person types that fast: a program is **guessing passwords** (brute force).
- 1,522 × ~512 bytes ≈ **780 KB** — exactly the big connection. The 948 KB question is answered.
- **The timing ties it to the malware:** it starts 0.6 s after the second component's POST to `/mlu/forum.php`. Some credential-stealing malware carries a built-in password list and tries it against Windows accounts; the family is left **unconfirmed** here.
- `LsarLookupSids3` once at 02:08:27 (SID → name) falls inside the guessing window — possibly the same program checking account names. Note only.

!!! question "Question: Arkime gave two results with nothing useful — why?"
    Arkime does not decode **which DCE/RPC function** was called. Zeek has a dedicated DCE/RPC analyzer that logs every interface and operation name. This is exactly the kind of case where **Splunk (Zeek logs) is the better tool**.

    Arkime is still useful for the session itself: `tags == 20180511_NIGHT_DEW && port.dst == 49158` shows 1,529 / 1,526 packets and 779,560 / 231,472 data bytes, confirming the size.

!!! question "Question: why are there so many PSH flags in this session?"
    **PSH (Push)** means "this message ends here — hand it to the application now, do not wait for more". It is set on the **last packet of each message**.

    This session: 1,529 + 1,526 = **3,055 packets**, **3,046 with PSH**. Almost every packet has PSH; only SYN, SYN-ACK, FIN and a few empty ACKs do not.

    Why: each message fits in **one packet**. 779,560 B ÷ 1,522 ≈ **512 B per request**; 231,472 B ÷ 1,522 ≈ **152 B per reply**. One packet can hold 1,400+ bytes, so each request and each reply is a single packet that also ends a message → 1,522 requests + 1,522 replies ≈ 3,044 PSH. Almost identical sizes every time = **the same function called again and again**.

    Only 5 ACKs: the DC carries its "got it" (ACK) **inside its reply packet**, so empty ACK-only packets are rarely needed.

    Compare the `wansaiful[.]com` download: 203 packets from the server, 151 with PSH. A large file arrives in many full-size packets and PSH marks only the end of each chunk.

    | Pattern | Meaning |
    |---|---|
    | **PSH ≈ total packets** | Many small messages back and forth: repeated requests (like this brute force), beacons, remote shell commands |
    | **Few PSH, many packets** | Bulk transfer in one direction: download or upload |

    **Payload8** shows the first 8 bytes each way: PC `05 00 0b 07 ...`, DC `05 00 0c 07 ...`. `05 00` = DCE/RPC version 5.0; the third byte is the message type — `0b` (11) **Bind** (request to use an interface), `0c` (12) **Bind Ack** (accepted). Eight bytes are enough to say "this is DCE/RPC" when the port number (49158) tells you nothing.

### 5-4. What traffic cannot show — hand it to the host operator { #host-leads }

The netlogon secure channel is encrypted: **which accounts, which passwords and whether any guess succeeded** are not visible. Host logs answer that:

- **DC Security log, Event 4776** — the DC validated NTLM credentials. Shows the account, the workstation and a result code: `0xC000006A` = wrong password, `0xC0000064` = no such account, **`0x0` = success**. Read every 4776 from CHICAGO-7FA3-PC between 02:08:12 and 02:08:45.
- **DC Event 4740** — an account was locked out (guessing can lock accounts).
- **PC Security log, Event 4625 / 4624** — failed / successful logon on the PC; **Process Name** shows which program made the attempts — the path to the malicious file.

---

## Step 6 — One Snort rule, and how to test it { #snort }

### 6-1. Which rule, and why { #rule-choice }

The single most useful rule is the **check-in POST**:

- **It survives domain and IP changes.** C2 domains change often; the body format `GUID=...&BUILD=...&INFO=...` does not.
- **It marks the start of an infection** — "this PC just registered with its C2".
- **Very few false positives.** Normal sites do not send those three names in that order.

```text
alert tcp $HOME_NET any -> $EXTERNAL_NET 80 (msg:"Malware check-in POST GUID/BUILD/INFO - Sung"; flow:to_server,established; content:"POST"; depth:4; content:"GUID="; content:"&BUILD="; distance:0; content:"&INFO="; distance:0; sid:1000001; rev:1;)
```

### 6-2. The rule, part by part { #rule-anatomy }

**Header**

- `alert` — raise an alert when it matches.
- `tcp` — TCP only.
- `$HOME_NET any -> $EXTERNAL_NET 80` — from any port inside to **port 80 outside** (HTTP). In pcapbox HOME_NET is all private ranges.

**Options (inside the brackets)**

- `msg:"..."` — the alert text; the author's name at the end is the team habit.
- `flow:to_server,established` — only data **from client to server on an established TCP connection**. Skips replies and handshake packets: faster and more precise.
- `content:"POST"; depth:4;` — the **first 4 bytes** are `POST` (`depth:4` = look only in the first 4 bytes), i.e. the first word of the HTTP request.
- `content:"GUID=";` — `GUID=` somewhere in it.
- `content:"&BUILD="; distance:0;` — `distance:0` = "search **after** the previous match", so `&BUILD=` must come after `GUID=`.
- `content:"&INFO="; distance:0;` — and `&INFO=` after `&BUILD=`. The rule fires only when the three appear **in this order**.
- `sid:1000001;` — rule number (own rules use 1000000+).
- `rev:1;` — rule version; add 1 every time you change it.

**How many alerts to expect?** 1 if only the first check-in has this body; **21** if the beacons send the same body. Check one beacon in Arkime before testing:

1. Search `tags == 20180511_NIGHT_DEW && host.http == lysedsohap.com && http.method == POST` (time range **All**).
2. Sort by **Start Time**: the 02:08:04 check-in, then `/mlu/forum.php`, `/d2/about.php`, then beacons from **02:10:15**.
3. Expand (`+`) the 02:10:15 session and scroll to the packet view. Turn on **Src** only to see just the request.
4. The **body** is below the headers after an empty line. Compare `Content-Length` with the check-in (123).
5. Do the same for the last beacon (02:48:25). Same first and last → the middle ones are the same too.

Both beacons showed the **same body** and `Content-Length: 123` → expect **21**.

### 6-3. Testing a Snort rule — a beginner's guide { #snort-test }

Four steps: **put the rule in → check the syntax → run it on the PCAP → read the alerts**.

**1. Put the rule in `/data/rules/local.rules`**

*Option A — Notepad on the host PC*

1. Explorer address bar: `\\10.50.10.60\rules` (user `analyst`, the Samba password).
2. Open `local.rules` in **Notepad**.
3. **Format → Word Wrap: off.** Otherwise a long rule looks like several lines. A rule must be **one line**.
4. Paste the rule on the last empty line and save (Ctrl+S).

*Option B — nano over SSH*

```bash
nano /data/rules/local.rules
```

- Go to the bottom, paste (right-click in PuTTY/PowerShell), **Ctrl+O** → Enter to save, **Ctrl+X** to exit.

*Check it is there:*

```bash
tail -3 /data/rules/local.rules
```

- `tail -3` shows the last three lines. The rule should be the last line, **all on one line**.

!!! warning "Curly quotes break rules"
    Copying from a web page or Word can turn `"` into `“ ”`. Snort cannot read curly quotes — retype them if something looks odd.

**2. Syntax check**

A typo stops Snort from starting at all, so **always check the syntax before running a PCAP**.

```bash
sudo snort -T -c /etc/snort/snort.conf 2>&1 | tail -5
```

- `-T` — **test mode**: read the config and rules, check them, do not look at packets.
- `-c /etc/snort/snort.conf` — which config (it `include`s `local.rules`).
- `2>&1` — Snort prints to the error stream; this sends it to the screen too.
- `| tail -5` — last five lines.

Success:

```text
        Snort successfully validated the configuration!
Snort exiting
```

Failure shows an `ERROR` line, for example:

```text
ERROR: /data/rules/local.rules(9) Unmatched quote in rule option 'msg'.
Fatal Error, Quitting..
```

`(9)` is the **line number** — check quotes, semicolons and brackets there.

**3a. Run it — the easy way: `snort-test`**

```bash
snort-test 20180511_NIGHT_DEW
```

pcapbox's helper (8-3 of the pcapbox manual): syntax check, then runs `/data/pcap/20180511_NIGHT_DEW.pcap` and counts alerts per rule. It writes nothing to Splunk or disk, so run it as often as you like.

```text
[1/2] 문법 OK
[2/2] /data/pcap/20180511_NIGHT_DEW.pcap
  개수 [gid:sid:rev] 메시지
     21 [1:1000001:1] Malware check-in POST GUID/BUILD/INFO - Sung
```

**3b. Run it — by hand, one alert per line**

```bash
mkdir -p /tmp/snortlog
sudo snort -c /etc/snort/snort.conf -r /data/pcap/20180511_NIGHT_DEW.pcap -A console -q -k none -U -y -l /tmp/snortlog
```

- `mkdir -p /tmp/snortlog` — a scratch folder (`-p` = no error if it exists).
- `-r file` — read this PCAP instead of a network card.
- `-A console` — print each alert on the screen.
- `-q` — hide the start-up banner.
- `-k none` — **turn off checksum checks**. Captured PCAPs often have wrong checksums; without this Snort may drop those packets and stay silent.
- `-U` — times in **UTC**; `-y` — include the year.
- `-l /tmp/snortlog` — where Snort writes its log files (see the errors below).

Count only:

```bash
sudo snort -c /etc/snort/snort.conf -r /data/pcap/20180511_NIGHT_DEW.pcap -A console -q -k none -U -y -l /tmp/snortlog | wc -l
```

- `| wc -l` counts output lines = alerts.

**4. Read the result**

```text
05/11/18-02:08:04.575944  [**] [1:1000001:1] Malware check-in POST GUID/BUILD/INFO - Sung [**] [Priority: 0] {TCP} 10.0.14.129:49198 -> 185.43.223.6:80
05/11/18-02:10:15.697332  [**] [1:1000001:1] Malware check-in POST GUID/BUILD/INFO - Sung [**] [Priority: 0] {TCP} 10.0.14.129:49205 -> 185.43.223.6:80
05/11/18-02:12:16.219566  [**] [1:1000001:1] Malware check-in POST GUID/BUILD/INFO - Sung [**] [Priority: 0] {TCP} 10.0.14.129:49210 -> 185.43.223.6:80
...
05/11/18-02:48:25.586602  [**] [1:1000001:1] Malware check-in POST GUID/BUILD/INFO - Sung [**] [Priority: 0] {TCP} 10.0.14.129:49287 -> 185.43.223.6:80
```

- `05/11/18-02:08:04.575944` — packet time (UTC).
- `[1:1000001:1]` — `[gid:sid:rev]`: gid 1 = normal text rule, our sid, our rev.
- The `msg` text.
- `[Priority: 0]` — no `classtype` in the rule, so 0. Ignore for now.
- `{TCP} 10.0.14.129:49198 -> 185.43.223.6:80` — protocol, source IP:port → destination IP:port.

**Checks:**

1. **21 alerts** = 1 check-in + 20 beacons. ✔
2. **First alert 02:08:04.575, port 49198** — the same session and the same millisecond as Arkime and Zeek's `http.log`. Three tools agree → strong evidence. ✔
3. **Interval ~120.5 s** (02:10:15 → 02:12:16 → 02:14:16 …) — the 2-minute beacon. ✔
4. **No false positives:** every alert goes to `185.43.223.6:80`; NCSI, ipify, wansaiful, TLS and DC traffic never matched. ✔

The rule never mentions a domain or IP, yet it caught only C2 traffic — if the attacker changes the domain, it keeps working.

**If it does not fire or the count is wrong**

1. **0 alerts:** re-run the syntax check; make sure `-k none` is there.
2. **Still 0:** cut the rule down (for example only `content:"GUID=";`). If that fires, add options back one at a time to find the culprit.
3. **Wrong count:** find the session that did not fire in Arkime and compare its body.
4. **Every change:** bump `rev:1` → `rev:2` so the report can say which version was tested.

**Errors met on pcapbox**

| Error | Cause | Fix |
|---|---|---|
| `sudo: snort: command not found` | `make install` put snort in `/usr/local/bin`; Oracle Linux `sudo` only searches its `secure_path`, which lacks `/usr/local/bin` | `sudo ln -sf /usr/local/bin/snort /usr/sbin/snort` (a shortcut where `sudo` looks; the pcapbox scripts find it too). `ls -l /usr/local/bin/snort` first — if missing, `make install` failed |
| `ERROR: log_tcpdump: Failed to open log file "/var/log/snort/snort.log.<n>": No such file or directory` | Snort also writes a packet log, and its default folder `/var/log/snort` does not exist | Add `-l /tmp/snortlog` (after `mkdir -p /tmp/snortlog`), or create the default once: `sudo mkdir -p /var/log/snort`. `snort-test` already uses its own temp folder |

---

## Timeline (2018-05-11, UTC) { #timeline }

| Time | Event |
|---|---|
| 02:06:51 | PC gets 10.0.14.129 by DHCP; faith.hoffman logs on (Kerberos); secure channel to the DC |
| 02:07:02 | Windows connectivity check (NCSI) — normal |
| 02:08:04 | `api.ipify[.]org` public IP lookup → POST `lysedsohap[.]com/4/forum.php` check-in; reply = 3 download commands |
| 02:08:05–02:08:14 | Three encrypted files from `wansaiful[.]com` (one keep-alive session) |
| 02:08:12 | POST `/mlu/forum.php` (206 B encrypted, MSIE 7.0, `Content-Encoding: binary`) — likely stolen credentials |
| 02:08:12–02:08:45 | 1,522 × `NetrLogonSamLogonWithFlags` to the DC (password guessing) |
| 02:08:14 | POST `/d2/about.php` (234 B encrypted, same program) |
| 02:10:15–02:48:25 | HTTP beacon to `lysedsohap[.]com` every ~120 s (20 times), reply `{n:}` |
| 02:10:16–02:45:46 | TLS C2 to `robwassotdint[.]ru` every ~5 min (54 sessions) |
| 02:40:18–02:42:37 | ~1.5 MB from the TLS C2 to the PC |
| 02:49:41 | Capture ends; both C2 channels still active |

---

## Copy-ready queries { #query-sheet }

Replace `<case>` with your case name. Drop `tags`/`pcap_case` on a live network.

**Arkime**

```text
tags == <case>
tags == <case> && protocols == dhcp
tags == <case> && protocols == krb5
tags == <case> && protocols == http
tags == <case> && ip.dns == [185.174.175.14, 185.43.223.6]
tags == <case> && host.http == lysedsohap.com && http.method == POST
tags == <case> && host.http == wansaiful.com
tags == <case> && http.request.content-type == application/octet-stream
tags == <case> && host == [www.victoryoutreachvallejo.com, medleysoup.com, radiantheartcoaching.com, hdmicablereviews.com]
tags == <case> && ip == 185.174.175.14
tags == <case> && port.dst == 49158
cert.hash == 86:af:39:2e:9b:42:ec:50:e2:87:f6:42:9e:f7:48:4c:48:bb:bd:95
cert.issuer.on == "Default Company Ltd" && cert.subject.on == "Default Company Ltd"
```

**Splunk (Zeek)**

```spl
index=zeek sourcetype=zeek:conn | stats count by pcap_case
index=zeek sourcetype=zeek:conn pcap_case=<case> | stats min(ts) as first max(ts) as last count as sessions | eval first=strftime(first,"%Y-%m-%d %H:%M:%S"), last=strftime(last,"%Y-%m-%d %H:%M:%S")
index=zeek sourcetype=zeek:conn pcap_case=<case> id_orig_h="10.0.14.*" | stats count as sessions sum(orig_bytes) as sent sum(resp_bytes) as received by id_orig_h | sort - sessions
index=zeek sourcetype=zeek:dhcp pcap_case=<case> | table _time client_addr assigned_addr mac host_name msg_types
index=zeek sourcetype=zeek:kerberos pcap_case=<case> | stats count by request_type client service success
index=zeek sourcetype=zeek:kerberos pcap_case=<case> client="<user>*" | table _time id_orig_h id_resp_h request_type client service success error_msg | sort _time
index=zeek sourcetype=zeek:http pcap_case=<case> | sort _time | table _time id_resp_h host method uri status_code resp_mime_types response_body_len user_agent
index=zeek sourcetype=zeek:http pcap_case=<case> method=POST | stats count sum(request_body_len) as sent_bytes values(user_agent) as user_agent by uri | sort - count
index=zeek sourcetype=zeek:dns pcap_case=<case> query IN ("<name1>","<name2>") | table _time query answers
index=zeek sourcetype=zeek:files pcap_case=<case> tx_hosts="<server ip>" | table _time tx_hosts rx_hosts mime_type seen_bytes total_bytes md5 sha1
index=zeek sourcetype=zeek:conn pcap_case=<case> id_resp_h="<c2 ip>" | sort _time | delta _time as gap | table _time id_resp_p service duration orig_bytes resp_bytes conn_state gap
index=zeek sourcetype=zeek:ssl pcap_case=<case> id_resp_h="<c2 ip>" | stats count min(_time) as first max(_time) as last by server_name version cipher established | convert ctime(first) ctime(last)
index=zeek sourcetype=zeek:conn pcap_case=<case> id_orig_h="<host ip>" | sort - orig_bytes | head 10 | table _time id_resp_h id_resp_p service duration orig_bytes resp_bytes
index=zeek sourcetype=zeek:dce_rpc pcap_case=<case> | stats count min(_time) as first by id_resp_p named_pipe endpoint operation | convert ctime(first) | sort first
```

**CyberChef**

```text
From Base64  →  XOR Brute Force (Key length 1, Crib: http)  →  then XOR (Key 7a, HEX)
```

**Snort**

```bash
sudo snort -T -c /etc/snort/snort.conf 2>&1 | tail -5
snort-test <case>
sudo snort -c /etc/snort/snort.conf -r /data/pcap/<case>.pcap -A console -q -k none -U -y -l /tmp/snortlog
```

---

## Lab notes met along the way { #lab-notes }

Problems hit while setting up pcapbox for this case, kept here because they will come back.

- **Arkime/Splunk not reachable from the host after the pcapbox manual's step 7.** The VM firewall only opens 8000/8005 in step 8-6. Open them first: `sudo firewall-cmd --permanent --add-port=8000/tcp --add-port=8005/tcp`.
- **`firewall-cmd: error: argument --add-service: not allowed with argument --add-port`.** This firewalld will not mix ports and services in one command. Two commands: `--add-port=...` then `--add-service=samba`, then `sudo firewall-cmd --reload`.
- **Arkime web password left as the manual's default.** `arkime_add_user.sh` only creates accounts; running it again does not change a password. Log in → **Settings → Password** to change your own; admins can use **Users** for others.
- **VMware NAT died whenever host-only VMnets were created** (Application log Event 1000/1001: `vmnat.exe` crash `0xc0000005`, VMs got DHCP but could not reach the NAT gateway `.2`). Cause: the lab subnets **overlapped real host networks** — the host's Wi-Fi used a /23 whose gateway was `10.10.10.1` (the VMnet2 host address), and a wired network used `172.16.0.0/16` (the VMnet3 range). Fix: move the lab to non-overlapping ranges (here `10.50.10.0/24` and `10.60.0.0/16`). Check before creating VMnets: `Get-NetIPAddress -AddressFamily IPv4` and `Get-NetRoute -DestinationPrefix 0.0.0.0/0` in PowerShell.

---

## Lessons { #lessons }

1. **Fix the clock first.** Arkime in browser time and Splunk in UTC differed by exactly 9 h 30 min. Set every tool to UTC before writing a single timeline line.
2. **Read HTTP first in an unknown PCAP.** It is cleartext and small, and it shows where the story starts.
3. **Tie events by size and time.** ipify's 14-byte reply = the 14-character `IP=`; netlogon 1,522 × 512 B = the 780 KB upload. Matching numbers prove links.
4. **Base the crib on behaviour.** Downloads followed the reply → the reply should contain `http`. Repeated chunks in Base64 hint at a short XOR key.
5. **Judge by content, not headers.** `text/plain` was an encrypted binary; the server clock was five minutes off.
6. **Two beacons, two programs.** 120 s HTTP and ~300 s TLS, different User-Agents and protocols.
7. **Answer every open question.** "Why is so much sent?" led to the password guessing that the first pass called normal DC traffic.
8. **Use the tool that sees it.** Zeek's DCE/RPC analyzer named the function; Arkime could not.
9. **Write rules on what the attacker cannot change cheaply.** The body format survives a new domain; one rule caught all 21 events with no false positives.
10. **Write down what traffic cannot tell, and where to look.** Accounts guessed → DC Event 4776; the guessing process → PC 4625/4624.
11. **Open every POST, even small ones.** 440 bytes never appears in a "largest upload" search, yet it can carry stolen passwords.

## References { #references }

- [First pass of this case — Arkime + CyberChef + 8 Snort rules](night-dew-hancitor-pony-zeus-panda-tls-c2.md)
- [Arkime search syntax](../../network/arkime/search-syntax.md) · [Analysing a PCAP with Arkime](../../network/arkime/offline-pcap-guide.md)
- [Zeek logs](../../network/zeek/index.md) · [conn.log](../../network/zeek/conn-log.md) · [files.log](../../network/zeek/files-log.md) · [ssl & x509](../../network/zeek/ssl-x509.md)
- [SPL cheat sheet](../splunk/spl-cheatsheet.md) · [Beaconing & C2](../../network/beaconing-c2.md)
- [DC, SMB and Snort rules lab](../../training/pcap-ir-labs/dc-smb-and-snort-rules.md) · [Playbook: compromised workstation](../playbooks/compromised-workstation.md) · [Playbook: account compromise](../playbooks/account-compromise.md)
- Original exercise: [malware-traffic-analysis.net — 2018-05-11 Night Dew](https://malware-traffic-analysis.net/2018/05/11/index.html)

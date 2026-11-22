---
title: Blank Clipboard — WhatsApp phishing link from webmail to a Dropbox first stage, a 17 MB ZIP download and a counter request (Arkime + Splunk)
tags:
  - blue-team
  - pcap
  - arkime
  - splunk
  - zeek
  - phishing
  - email
  - snort
  - ticket
---

# Blank Clipboard — WhatsApp phishing link to a Dropbox first stage and a 17 MB ZIP (Arkime + Splunk) { #blank-clipboard }

!!! abstract "Case summary"
    malware-traffic-analysis.net exercise **2018-09-27 "Blank Clipboard"**, worked **from zero, as if the PCAP were unknown**, on the home-lab **pcapbox** VM with **Arkime and Splunk (Zeek logs)**. The exercise gives a PCAP and **two emails** and asks one question: **which email started the infection?** No LAN information is given, so the domain, DC and user have to be found first.

    One Windows 7 PC (**Escritorio-PC, user thiago.almeida**) opens company **webmail**, and a link in a Portuguese **WhatsApp-themed phishing email** sends IE11 through a fake "Federal Prosecutor / contract" page and a redirect gate to a **file on Dropbox**. 81 seconds later a **non-browser program** downloads a **17 MB ZIP**, then a program with **no User-Agent** calls a likely **infection counter**. The PC most likely **restarts** at 01:48–01:49. The ZIP is **incomplete in the capture** (1.97 MB lost by the sensor), so it has no hash. The page ends with **one Snort rule** for the campaign's link format and a ticket in the team format.

| | |
|---|---|
| **Evidence** | `2018-09-27-traffic-analysis-exercise.pcap` — 2018-09-27 01:37:01 – 01:51:35 UTC (14 min 34 s), 188 Zeek connections; two `.eml` files |
| **Source** | [malware-traffic-analysis.net 2018-09-27 "Blank Clipboard"](https://malware-traffic-analysis.net/2018/09/27/index.html) |
| **Environment** | Closed network. pcapbox VM: Arkime v5.6.4 (tag = case name), Splunk (`index=zeek`, field `pcap_case`), Snort 2.9, tshark |
| **Case name** | `20180927_BLANKCLIPBOARD` |
| **Deliverables** | Analysis, the email that started the infection, one Snort rule, one incident ticket (txt) |
| **Related pages** | [Night Dew, second pass (same method)](night-dew-arkime-splunk-netlogon-bruteforce.md) · [Phishing red herring (email analysis)](phishing-red-herring-ek-driveby-ursnif-c2.md) · [Arkime search syntax](../../network/arkime/search-syntax.md) · [SPL cheat sheet](../splunk/spl-cheatsheet.md) · [Zeek logs](../../network/zeek/index.md) |

!!! tip "How to read this page"
    Every step has the same order: **Goal → query (Arkime and/or Splunk) → explanation → actual result → reading the result → ticket entry**. Every SPL query is explained line by line. The **Question** boxes are real questions asked while working the case, with their full answers. The **Correction** box is a place where a first reading was wrong; it is kept on purpose.

    The rule used throughout: **analyse an unknown PCAP.** Nothing is taken from the exercise's answer file; every finding comes from what the screen shows. Malware family names are therefore left **unconfirmed**.

!!! warning "The indicators on this page are real"
    Domains, IPs and URLs come from real 2018 phishing and malware traffic. Prose and tables are defanged (`hxxp`, `[.]`); code blocks keep the values as typed. **Do not visit them.** Open the emails only as text on an analysis VM.

## Answers at a glance { #answers }

| Item | Answer | Status |
|---|---|---|
| Email that started the infection | **"Conversa do WhatsApp no (221206)"**, received 2018-09-24 12:52:42 UTC — its link URL appears in the traffic **character for character** | Confirmed |
| Infected PC | **172.16.5.203, Escritorio-PC**, MAC `30:85:a9:f4:92:17` (ASUSTek), Windows 7, IE11 | Confirmed |
| User | **thiago.almeida** (domain A1-ASSOCIADOS), logged on 01:38:12 | Confirmed |
| Domain and DC | `a1-associados[.]com` (NetBIOS `A1-ASSOCIADOS`), DC **A1Associados-DC 172.16.5.5** (also the DHCP server) | Confirmed |
| Link opened | **01:40:54 UTC** from company webmail (HTTPS), no Referer | Confirmed (from webmail: strongly supported) |
| Redirect chain | `lealcontabil[.]com` lure page → `cadastro.php` → gate `54.38.137.127/index.php` → `/a/` → Dropbox `DOC1_CONTRATO_YBFTOP2078686788.zip` | Confirmed |
| Second stage | Non-browser program (UA `MSIE 7.0`) downloads `dnpland[.]com[.]my/images/z2448800.zip`, 17,066,397 B at 01:42:22 | Confirmed |
| Counter | No-User-Agent GET `serveengenharia[.]com[.]br/tmp/soares/cont1/` at 01:44:06 | Confirmed (purpose inferred) |
| Restart | PC restarts at about 01:48–01:49 | Inferred (four network signs) |
| C2 | None seen before the capture ends | Confirmed for this capture |
| Second email | Fake Serasa Experian debt notice, same sender — no traffic to its link in this capture | Confirmed for this capture |
| ZIP hash | Not available — 1,967,951 B missing in the capture | Confirmed |
| Malware family | Not confirmed | Not confirmed |

---

## Step 0 — Which exercise is this, and load it into pcapbox { #prep }

### 0-1. Finding the exercise from a screenshot { #find-exercise }

!!! question "Question: from this Arkime screenshot, which malware PCAP is it? Find it on the internet."
    The screenshot showed the capture window **2018/09/27 01:37:02 – 01:51:35 UTC**, one busy internal host **172.16.5.203**, a server **172.16.5.5** receiving Kerberos, LDAP, DCE/RPC and SMB (a DC), and a short list of external IPs.

    The date pointed to malware-traffic-analysis.net. Two pages exist for that day:

    - **2018-09-27 — Traffic analysis exercise "Blank Clipboard"**: a PCAP with one Windows host getting infected, plus **two emails**; the task is to find which email started the infection. LAN details are deliberately **not given** — you work them out yourself.
    - 2018-09-27 — "4 days of Hancitor" (a data dump, not an exercise).

    An AD environment with no given LAN details fits the **Blank Clipboard** exercise (`2018-09-27-traffic-analysis-exercise.pcap.zip`, 17.1 MB, plus `2018-09-27-traffic-analysis-exercise-both-emails.zip`). The answers are only in a separate answer PDF, so the malware name was **not** taken from anywhere — the case is analysed from the traffic.

### 0-2. Ingest { #ingest }

The method is the same as in [Night Dew, second pass](night-dew-arkime-splunk-netlogon-bruteforce.md#prep):

1. Rename the PCAP to the case name — here **`20180927_BLANKCLIPBOARD.pcap`** — and drop it into `\\10.50.10.60\incoming`.
2. Wait for `DONE case=20180927_BLANKCLIPBOARD` in `/data/logs/ingest.log`. The `START` line has the `sha256=` evidence hash for the ticket.
3. Arkime time range **All**, Splunk **All time** (2018 data).

If you forget the exact case name:

```spl
index=zeek sourcetype=zeek:conn
| stats count by pcap_case
```

- `stats count by pcap_case`: counts connections per case. Find this case's name in the list.

!!! question "Question: where is the PCAP stored? Please check the setup."
    After ingest, pcapbox keeps each case in these places:

    | What | Where |
    |---|---|
    | Original PCAP copy | `/data/pcap/<case>.pcap` → `/data/pcap/20180927_BLANKCLIPBOARD.pcap` |
    | Zeek logs | `/data/zeek/<case>/` (Splunk's `source` field shows this path) |
    | Snort alerts | `/data/snort/<case>/alert` |
    | Ingest log | `/data/logs/ingest.log` |
    | Arkime | sessions tagged `<case>` |

    Check it:

    ```bash
    ls -l /data/pcap/
    grep 20180927_BLANKCLIPBOARD /data/logs/ingest.log
    ```

    - `ls -l /data/pcap/`: lists the stored PCAPs and sizes. If the same name was dropped twice, the file has a time suffix (`..._2611...pcap`).
    - `grep ... ingest.log`: shows only this case's lines — `START` (path and `sha256=`) and `DONE`.

    If reading `/data/pcap/` gives `Permission denied`, put `sudo ` in front of the `tshark` command, then give the output files back to your account: `sudo chown -R $USER: ~/cases/20180927_BLANKCLIPBOARD/export` (`-R` = everything in the folder, `$USER:` = your user and group).

### 0-3. The clock { #utc }

Arkime's histogram labels already end in **UTC** (`2018/09/27 01:38:00 UTC`), so this time the Arkime time zone did not need fixing. (In the Night Dew case it showed browser time, 9 h 30 min off.)

---

## Step 1 — The big picture { #overview }

**Goal:** before any detail — when does the capture start and end, how many internal PCs, and who talks the most?

### 1-1. Arkime { #overview-arkime }

**Sessions** → time range **All** → search:

```text
tags == 20180927_BLANKCLIPBOARD
```

**Result** (SPIView → General):

```text
Start  2018/09/27 01:37:01   End  2018/09/27 01:51:35   (00:14:34, Bounding: Last Packet)
Protocols  tcp (114) udp (70) krb5 (48) dns (38) ldap (26) dcerpc (13) tls (11) dhcp (10) http (8) smb (7) llmnr (6) ntp (2) igmp (1)
Src IP     172.16.5.203 (178)  172.16.5.5 (7)
Dst IP     172.16.5.5 (142)  172.16.5.203 (7)  216.194.135.127 (7)  224.0.0.252 (6)  54.38.137.127 (4)
           172.16.5.255 (4)  255.255.255.255 (4)  103.6.198.141 (3)  162.125.5.1 (2)  162.125.5.6 (2)
           23.65.180.72 (1)  177.12.174.95 (1)  200.157.208.243 (1)  224.0.0.22 (1)
```

### 1-2. Splunk { #overview-splunk }

**Query ① — capture window and size**

```spl
index=zeek sourcetype=zeek:conn pcap_case=20180927_BLANKCLIPBOARD
| stats min(ts) as first max(ts) as last count as sessions
| eval first=strftime(first,"%Y-%m-%d %H:%M:%S"), last=strftime(last,"%Y-%m-%d %H:%M:%S")
```

- Line 1: this case's Zeek connection log (`conn.log`, one line per connection).
- Line 2 `stats`: one summary row — earliest `ts` as `first`, latest `ts` as `last`, number of connections as `sessions`.
- Line 3 `eval` + `strftime`: `ts` is epoch seconds; `strftime` turns it into `2018-09-27 01:37:01`. A comma lets one `eval` set two fields.

```text
first                 last                  sessions
2018-09-27 01:37:01   2018-09-27 01:50:57   188
```

**Query ② — traffic per internal PC**

```spl
index=zeek sourcetype=zeek:conn pcap_case=20180927_BLANKCLIPBOARD id_orig_h="172.16.5.*"
| stats count as sessions dc(id_resp_h) as dests sum(orig_bytes) as sent sum(resp_bytes) as received by id_orig_h
| sort - sessions
```

- Line 1 `id_orig_h="172.16.5.*"`: only connections **started** by the LAN. The LAN range was not given, so it comes from the Arkime screen. `*` = anything.
- Line 2: per internal IP — `count` (connections), `dc(id_resp_h)` (number of **different** destinations, dc = distinct count), `sum(orig_bytes)` (bytes sent), `sum(resp_bytes)` (bytes received).
- Line 3 `sort - sessions`: most connections first (`-` = descending).

```text
id_orig_h      sessions  dests  sent     received
172.16.5.203   188       12     172599   18482111
```

**Query ③ — external destinations by bytes received** (added for this case)

```spl
index=zeek sourcetype=zeek:conn pcap_case=20180927_BLANKCLIPBOARD NOT id_resp_h IN ("172.16.5.*", "224.*", "255.255.255.255")
| stats count as sessions min(ts) as first values(id_resp_p) as ports values(service) as service sum(orig_bytes) as sent sum(resp_bytes) as received by id_orig_h id_resp_h
| eval first=strftime(first,"%H:%M:%S")
| sort - received
```

- Line 1 `NOT id_resp_h IN (...)`: **drops** destinations that are the LAN, multicast (`224.*`) or broadcast. Only connections leaving the network remain.
- Line 2 `stats ... by id_orig_h id_resp_h`: one row per "who → where" pair — `min(ts)` (first connection), `values(id_resp_p)` (destination ports), `values(service)` (protocol Zeek recognised: `http`, `ssl`, `dns`), `sent` / `received`.
- Line 3: first time as `01:39:12`-style.
- Line 4 `sort - received`: the biggest download first.

```text
id_orig_h     id_resp_h        sessions  first     ports  service  sent  received
172.16.5.203  103.6.198.141    1         01:42:21  80     http     320   17066676
172.16.5.203  216.194.135.127  7         01:38:49  443    ssl      5936  1261710
172.16.5.203  162.125.5.1      2         01:40:58  443    ssl      1568  10332
172.16.5.203  162.125.5.6      2         01:41:00  443    ssl      1289  7959
172.16.5.203  54.38.137.127    4         01:40:54  80     http     1679  3753
172.16.5.203  177.12.174.95    1         01:44:06  80     http     90    208
172.16.5.203  200.157.208.243  1         01:49:13  80     http     97    179
172.16.5.203  23.65.180.72     1         01:37:07  80     http     97    179
```

### 1-3. Reading the result { #overview-reading }

**① The window matches.** Arkime 01:37:01 – 01:51:35, Zeek 01:37:01 – 01:50:57. The start is the same. The ends differ because Arkime's end is the **last packet** and Zeek's `ts` is when the **last connection started**.

**② One PC.** Only **172.16.5.203** starts connections in Zeek: 188 connections, 12 destinations, ~170 KB sent, **~18.5 MB received**. Suspect PC = **172.16.5.203**.

**③ A small mismatch: 172.16.5.5 as a source.** Arkime shows 7 sessions *from* 172.16.5.5, Zeek shows none, and Arkime's Dst IP list has `172.16.5.203 (7)`. So these 7 are **DC → PC**. The tools decide direction differently:

- **Arkime:** whoever sent the **first packet it saw** is the source.
- **Zeek:** guesses who started it from the SYN and the port numbers.

They disagree when a capture starts mid-conversation or only has UDP replies. Checked in [Step 2](#dc-to-pc).

**④ Internal vs external destinations.**

- **Internal:** `172.16.5.5` (142) with krb5, ldap, dcerpc, smb → **likely the DC**. A domain PC talking a lot to its DC is normal.
- **Broadcast / multicast (normally fine):** `172.16.5.255`, `255.255.255.255` (broadcast); `224.0.0.252` (LLMNR — Windows name lookup by multicast, matches `llmnr 6`); `224.0.0.22` (IGMP).
- **External:** `216.194.135.127` 7, `54.38.137.127` 4, `103.6.198.141` 3, `162.125.5.1` and `.6` 2 each, the rest 1 each.

**⑤ Different from Night Dew: no obvious suspect by session count.** There, two external IPs had 54 and 23 sessions. Here the busiest has 7. With a 14-minute capture, **count is not enough** — use other measures:

- **Bytes:** a single session can carry a big file.
- **Time order:** what came first.
- **Protocol:** `http 8` is cleartext — look there first.

Sorted by bytes, the suspects appear at once:

- **103.6.198.141 — 1 session, ~17 MB.** **92 %** of all bytes received in the capture. Port 80, **cleartext HTTP**.
- **216.194.135.127 — 7 TLS sessions, 1.26 MB.** Second biggest. Encrypted, but it starts (01:38:49) **before** the other suspicious traffic.

### 1-4. The eight HTTP sessions, in time order { #http-sessions }

**Arkime:**

```text
tags == 20180927_BLANKCLIPBOARD && protocols == http
```

```text
Start     Src port  Dst IP / port         Packets  Databytes / Bytes   URI
01:37:07  49183     23.65.180.72:80       9        276 / 778           www.msftncsi.com/ncsi.txt
01:40:54  49218     54.38.137.127:80      24       4,182 / 5,494       lealcontabil.com/comercio?imagens/img/tmp/a?onlinepor-email?e=whatsapp_Beckup_REG
                                                                       lealcontabil.com/favicon.ico  lealcontabil.com/comercio/cadastro.php ...
01:40:57  49220     54.38.137.127:80      15       1,250 / 2,076       54.38.137.127/index.php  54.38.137.127/a/
01:42:21  49225     103.6.198.141:80      10,000   6,535,736 / 8,061,835   dnpland.com.my/images/z2448800.zip
01:42:21  49225     103.6.198.141:80      10,000   0 / 7,888,936       (tags: incomplete-tcp out-of-order-dst acked-unseen-segment-src)
01:42:21  49225     103.6.198.141:80      283      0 / 243,608
01:44:06  49226     177.12.174.95:80      11       298 / 908           serveengenharia.com.br/tmp/soares/cont1/
01:49:13  49183     200.157.208.243:80    10       276 / 832           www.msftncsi.com/ncsi.txt
```

| Time (UTC) | Destination | What | First judgement |
|---|---|---|---|
| 01:37:07 | 23.65.180.72 | `www.msftncsi.com/ncsi.txt` | Normal (Windows internet check) |
| 01:38:49 | 216.194.135.127:443 | 7 TLS sessions, 1.26 MB | **Unknown** — check SNI |
| 01:40:54 | 54.38.137.127 | `lealcontabil.com/comercio/?...onlinepor-email?e=whatsapp_Beckup_REG`, `/cadastro.php` | **Suspicious** |
| 01:40:57 | 54.38.137.127 | `54.38.137.127/index.php`, `/a/` | **Suspicious** (IP, no domain) |
| 01:40:58 | 162.125.5.1 / .6:443 | TLS, 2 each | **Unknown** — check SNI |
| 01:42:21 | 103.6.198.141 | `dnpland.com.my/images/z2448800.zip`, ~17 MB | **Strongly suspicious** |
| 01:44:06 | 177.12.174.95 | `serveengenharia.com.br/tmp/soares/cont1/` | **Suspicious** |
| 01:49:13 | 200.157.208.243 | `www.msftncsi.com/ncsi.txt` | Looks normal — but see ⑦ |

**Reading each line:**

- **01:37:07 NCSI.** When Windows joins a network it fetches `ncsi.txt` to check "is the internet working?". Six seconds after the capture starts → the PC **has just connected**.
- **01:40:54 lealcontabil.com.** Several red flags: the URL contains `onlinepor-email` and `e=whatsapp_Beckup_REG` — the shape of a **link clicked in an email** ("Beckup" is a misspelling of "Backup"); `comercio`, `cadastro` (registration), `imagens` and `contabil` (accounting) are **Portuguese**; a path like `/comercio/?imagens/img/tmp/a?...` with several `?` is not something a normal site builds — typical of a page planted on a **hacked site**.
- **01:40:57 54.38.137.127/index.php, /a/.** Three seconds later, **the same server by IP**, no domain. People do not type IPs; the previous page probably **redirected** here.
- **01:42:21 dnpland.com.my/.../z2448800.zip.** A **ZIP** with a meaningless numeric name; `.com.my` is **Malaysia** — unrelated to the Portuguese site, typical of hacked sites used as file stores; **~17 MB** is very large for a ZIP holding one program. Padding a malicious file to dodge antivirus/sandbox size limits is a known trick — still a **hypothesis** here. About 1.5 minutes after 54.38.137.127, which fits "click → landing page → download".
- **01:44:06 serveengenharia.com.br/tmp/soares/cont1/.** Another Brazilian (`.com.br`) site, **two minutes after the ZIP**, 90 B sent / 208 B received — not a person viewing a page but a **program sending a short signal**. `cont` may be short for Portuguese *contador* (counter) → possibly an **infection counter** (hypothesis; the User-Agent in Step 3 will tell browser vs program).

### 1-5. Why the ZIP download shows as three Arkime rows { #arkime-split }

All three rows have source port **49225** — it is **one connection split in three**. Arkime starts a new session record when one session passes **10,000 packets** (`maxPackets` default). Zeek shows it as 1, Arkime as 3.

The three tags:

- `incomplete-tcp`: the TCP conversation is not complete (start or end missing).
- `out-of-order-dst`: the server's packets arrived out of order.
- `acked-unseen-segment-src`: the other side **acknowledged data the capture never saw** → **packets are missing from the capture**.

Remember this: the ZIP may be **broken** when extracted later ([Step 5](#zip)).

### 1-6. A clue: did the PC restart at 01:49? { #restart-clue }

Both NCSI sessions use **source port 49183**:

- 01:37:07 → port 49183
- up to 01:44:06 → ports climb to 49226
- 01:49:13 → back to **49183**

Windows gives each new connection the next source port (counting up from 49152). Going **back to the start** is what a **restart** often looks like. The Arkime histogram also has a **burst around 01:49** like the one at the start — a boot/logon burst. Some malware **restarts the PC** after installing, so this matters. Still a hypothesis — checked in [Step 2](#restart).

### Notes after Step 1 (not ticket lines) { #notes-1 }

- Suspect PC **172.16.5.203**, MAC `30:85:a9:f4:92:17` (Arkime DHCP Client MAC); DC candidate 172.16.5.5
- First suspicious event **01:40:54** lealcontabil.com (email-link-shaped URL)
- Key candidate **01:42:21** `z2448800.zip` (~17 MB); after-infection candidate 01:44:06 `cont1`
- Unknown: 216.194.135.127:443 (01:38:49, 1.26 MB), 162.125.5.1/.6:443 (01:40:58)
- Hypothesis: restart around 01:49

Baselining is not written into the ticket.

---

## Step 2 — Who is the PC, who is the user, what is the domain? { #identity }

**Goal:** IP, MAC, host name, user — and, because this exercise gives no LAN information, the **domain name and DC name**. Also test the restart hypothesis.

### 2-1. Arkime { #identity-arkime }

#### ① DHCP { #dhcp }

```text
tags == 20180927_BLANKCLIPBOARD && protocols == dhcp
```

SPIView → **dhcp**:

```text
Client MAC      30:85:a9:f4:92:17 (10)
Client OUI      ASUSTek COMPUTER INC. (10)
Host            escritorio-pc (4)
Transaction id  15851cd (2) 23eb50a8 (2) 40f8871 (2) 477a1e39 (2) 4b9db1a3 (2) 8c9a47ee (2) ...
Type            ACK (6) INFORM (4)
```

Sessions (sorted by Start Time):

```text
01:37:05  172.16.5.203:68 -> 255.255.255.255:67   udp dhcp
01:37:05  172.16.5.5:67   -> 172.16.5.203:68      udp dhcp
01:38:49  172.16.5.203:68 -> 255.255.255.255:67   udp dhcp
01:38:49  172.16.5.5:67   -> 172.16.5.203:68      udp dhcp
...
```

#### ② Kerberos { #kerberos }

```text
tags == 20180927_BLANKCLIPBOARD && protocols == krb5
```

SPIView → **krb5**:

```text
cname   escritorio-pc$ (8)  ESCRITORIO-PC$ (4)  thiago.almeida (4)
Realm   A1-ASSOCIADOS.COM (40)  A1-ASSOCIADOS (4)  a1-associados.com (4)
sname   krbtgt/A1-ASSOCIADOS.COM (14)  cifs/a1associados-dc.a1-associados.com (5)
        LDAP/A1Associados-DC.a1-associados.com (4)  escritorio-pc$@A1-ASSOCIADOS.COM (4)
        krbtgt/A1-ASSOCIADOS (4)  krbtgt/a1-associados.com (4)  ldap/A1Associados-DC.a1-associados.com (4)
        ESCRITORIO-PC$ (2)  escritorio-pc$ (2)  host/escritorio-pc.a1-associados.com (2)
        ldap/a1associados-dc.a1-associados.com (2)  cifs/A1Associados-DC.a1-associados.com (1)
```

#### ③ The 7 DC → PC sessions { #dc-to-pc }

```text
tags == 20180927_BLANKCLIPBOARD && ip.src == 172.16.5.5
```

```text
01:37:05  172.16.5.5:67  -> 172.16.5.203:68     udp dhcp
01:37:39  172.16.5.5:445 -> 172.16.5.203:49209  tcp  (11 packets, 0 / 604)
01:38:49  172.16.5.5:67  -> 172.16.5.203:68     udp dhcp
01:42:18  172.16.5.5:67  -> 172.16.5.203:68     udp dhcp
01:43:40  172.16.5.5:67  -> 172.16.5.203:68     udp dhcp
01:45:25  172.16.5.5:67  -> 172.16.5.203:68     udp dhcp
01:49:08  172.16.5.5:67  -> 172.16.5.203:68     udp dhcp
```

### 2-2. Splunk { #identity-splunk }

**Query ① — DHCP in time order**

```spl
index=zeek sourcetype=zeek:dhcp pcap_case=20180927_BLANKCLIPBOARD
| eval t=strftime(ts,"%H:%M:%S")
| table t client_addr server_addr assigned_addr mac host_name domain msg_types
| sort t
```

- Line 1: this case's DHCP log.
- Line 2 `eval t=strftime(ts,"%H:%M:%S")`: `ts` as hour:minute:second in a new field `t` (the date is the same everywhere).
- Line 3 `table`: only these columns —
    - `server_addr`: the DHCP server's IP (in small networks the DC is often the DHCP server too)
    - `host_name`: the PC's name
    - `domain`: the domain name the server gave → **the LAN information comes from here**
    - `msg_types`: DHCP message types (`REQUEST`, `ACK`, `INFORM` ...)
- Line 4 `sort t`: time order.

```text
t         client_addr   server_addr  assigned_addr  mac                host_name     domain             msg_types
01:37:05  172.16.5.203                              30:85:a9:f4:92:17  Escritorio-PC a1-associados.com  INFORM ACK
01:38:49  172.16.5.203                              30:85:a9:f4:92:17  Escritorio-PC a1-associados.com  INFORM ACK
01:42:18  172.16.5.203                              30:85:a9:f4:92:17  Escritorio-PC a1-associados.com  INFORM ACK
01:43:40  172.16.5.203                              30:85:a9:f4:92:17  Escritorio-PC a1-associados.com  INFORM ACK
01:45:25  172.16.5.203                              30:85:a9:f4:92:17  Escritorio-PC a1-associados.com  INFORM ACK
01:49:08  172.16.5.203                              30:85:a9:f4:92:17  Escritorio-PC a1-associados.com  INFORM ACK
```

**Query ② — Kerberos in time order**

```spl
index=zeek sourcetype=zeek:kerberos pcap_case=20180927_BLANKCLIPBOARD
| eval t=strftime(ts,"%H:%M:%S")
| table t id_orig_h id_resp_h request_type client service success error_msg
| sort t
```

- `request_type`: `AS` = getting the logon ticket (TGT); `TGS` = a ticket for one service; `AP` = presenting a ticket to the service.
- `client`: the account asking (= **cname**). `service`: the service wanted (= **sname**). `krbtgt/<domain>` gives the **AD domain name**; `cifs/<name>` and `ldap/<name>` give the **DC's name**.
- `error_msg`: why `success` is `false`. `KDC_ERR_PREAUTH_REQUIRED` is normal.

Key rows (all 172.16.5.203 → 172.16.5.5):

```text
t         request_type  client                              service                                           success  error_msg
01:37:02  AS            escritorio-pc$/A1-ASSOCIADOS.COM    krbtgt/A1-ASSOCIADOS.COM                          false    KDC_ERR_PREAUTH_REQUIRED
01:37:02  AS            escritorio-pc$/A1-ASSOCIADOS.COM    krbtgt/A1-ASSOCIADOS.COM                          true
01:37:02  TGS           ESCRITORIO-PC$/A1-ASSOCIADOS.COM    cifs/a1associados-dc.a1-associados.com            true
01:37:02  TGS           ESCRITORIO-PC$/A1-ASSOCIADOS.COM    ldap/A1Associados-DC.a1-associados.com/a1-...     true
01:37:03  TGS                                               escritorio-pc$@A1-ASSOCIADOS.COM                  false    KDC_ERR_BADOPTION
01:37:03  TGS           ESCRITORIO-PC$/A1-ASSOCIADOS.COM    escritorio-pc$@A1-ASSOCIADOS.COM                  true
01:37:03  AP            /A1-ASSOCIADOS.COM                  cifs/a1associados-dc.a1-associados.com            true
01:37:12  AS            ESCRITORIO-PC$/A1-ASSOCIADOS.COM    krbtgt/A1-ASSOCIADOS.COM                          true
01:38:12  AS            thiago.almeida/A1-ASSOCIADOS        krbtgt/A1-ASSOCIADOS                              false    KDC_ERR_PREAUTH_REQUIRED
01:38:12  AS            thiago.almeida/A1-ASSOCIADOS        krbtgt/A1-ASSOCIADOS.COM                          true
01:38:12  TGS           thiago.almeida/A1-ASSOCIADOS.COM    host/escritorio-pc.a1-associados.com              true
01:38:13  TGS           thiago.almeida/A1-ASSOCIADOS.COM    cifs/A1Associados-DC.a1-associados.com            true
01:38:13  TGS           thiago.almeida/A1-ASSOCIADOS.COM    ldap/A1Associados-DC.a1-associados.com            true
01:48:37  AP            /A1-ASSOCIADOS.COM                  cifs/A1Associados-DC.a1-associados.com            true
01:49:05  AS            escritorio-pc$/A1-ASSOCIADOS.COM    krbtgt/A1-ASSOCIADOS.COM                          false    KDC_ERR_PREAUTH_REQUIRED
01:49:05  AS            escritorio-pc$/A1-ASSOCIADOS.COM    krbtgt/A1-ASSOCIADOS.COM                          true
01:49:10  TGS           ESCRITORIO-PC$/A1-ASSOCIADOS.COM    LDAP/A1Associados-DC.a1-associados.com/a1-...     true
01:49:11  TGS                                               escritorio-pc$@A1-ASSOCIADOS.COM                  false    KDC_ERR_BADOPTION
01:49:11  TGS           ESCRITORIO-PC$/A1-ASSOCIADOS.COM    escritorio-pc$@A1-ASSOCIADOS.COM                  true
01:49:11  TGS           ESCRITORIO-PC$/A1-ASSOCIADOS.COM    cifs/a1associados-dc.a1-associados.com            true
01:49:16  TGS           ESCRITORIO-PC$/A1-ASSOCIADOS.COM    escritorio-pc$                                    true
```

### 2-3. Question: why look for DHCP at 01:37 *and* 01:49? { #restart }

!!! question "Question: you asked me to check whether DHCP appears around 01:37 and around 01:49. Why?"
    **To test the hypothesis "the PC restarted at about 01:49".**

    Step 1 showed two odd things: the 01:49:13 NCSI went **back to source port 49183**, and the histogram had a **burst around 01:49** like the start of the capture. Windows does the same things in the same order every time it starts:

    1. authenticates the **computer account** to the DC (Kerberos)
    2. gets network settings by **DHCP**
    3. checks the internet with **NCSI**
    4. the **user logs on** (Kerberos, person account)

    So if the start-of-capture sequence **repeats at 01:49**, a restart is likely. DHCP was one checkpoint.

    **Why it matters:** some malware **restarts the PC** after installing. A restart starts whatever it put in autostart (Run keys, services). If true, the timeline gains "**install → restart → persistence check**", and the host operator gets a lead.

    **But DHCP alone cannot decide it.** Splunk showed DHCP **six** times (01:37:05, 01:38:49, 01:42:18, 01:43:40, 01:45:25, 01:49:08), all **INFORM + ACK**:

    - **INFORM:** "I already have an IP — just tell me the **other settings** (DNS server, domain name, proxy)."
    - **ACK:** the server's answer.

    Getting a new IP at boot normally shows `DISCOVER → OFFER → REQUEST → ACK`. Not here — the PC has a **fixed or already-leased IP**. And Windows sends INFORM **at other times too** (proxy auto-discovery WPAD, network changes). Six INFORMs prove nothing.

    **Lesson:** do not test a hypothesis with one piece of evidence. DHCP was weak, so look at Kerberos.

    **Kerberos gives stronger evidence:**

    | Order | Start of capture | Around 01:49 |
    |---|---|---|
    | Computer account AS (`escritorio-pc$` → `krbtgt`, first PREAUTH_REQUIRED, then success) | 01:37:02 | 01:49:05 |
    | DHCP INFORM | 01:37:05 | 01:49:08 |
    | Computer asks a ticket for itself → `KDC_ERR_BADOPTION` → success | 01:37:03 | 01:49:11 |
    | NCSI (source port 49183) | 01:37:07 | 01:49:13 |
    | Person logon (`thiago.almeida` AS) | 01:38:12 | **none** until the capture ends (01:51) |

    The **computer account AS request** is the key: a computer's TGT is normally obtained **at boot** and used for 10 hours. Getting a new one 12 minutes later, followed by the same sequence, makes **a restart at 01:48–01:49 likely**. The user had not logged on again by the end of the capture.

    The network cannot **confirm** it. The host's Windows System log can — lead for the host operator:

    - **Event 1074:** a program or user **asked** for shutdown/restart — shows the **program path**. Most important.
    - **Event 6006:** the event log service stopped cleanly (normal shutdown).
    - **Event 6008:** unexpected shutdown (forced, power loss).
    - **Event 6005:** the event log service started (= boot).

    A fifth sign appeared later in `files.log` ([Step 5](#files-log)): the group policy file `GPT.INI` was read at 01:37:03, 01:38:13 and again **01:49:11**.

### 2-4. Question: what does each krb5 field mean? { #krb5-fields }

!!! question "Question: please explain each item in the krb5 category — cname, sname, realm and so on."
    **First, the Kerberos flow (the three `request_type` values):**

    1. **AS (Authentication Service):** "I am X" → the DC returns a **TGT** (entry ticket). Done first at logon.
    2. **TGS (Ticket Granting Service):** show the TGT → "give me a ticket for **this service**".
    3. **AP (Application):** hand the service ticket to the **actual service** (file share, LDAP). The account name is inside the encrypted ticket, so Zeek shows `client` as just `/A1-ASSOCIADOS.COM`. Normal.

    **cname (client name)** — the **account asking**, "who":

    - `escritorio-pc$` (8), `ESCRITORIO-PC$` (4): the **computer account** (a trailing `$` marks computer accounts). Same account in different case: Windows uses lower case (from the host name) in some requests and upper case (the AD name) in others. Kerberos names in AD are case-insensitive.
    - `thiago.almeida` (4): no `$` → a **person**. **This PC's user.**

    **sname (service name)** — the **service** the ticket is for, "where to", shaped `service/server`:

    - `krbtgt/A1-ASSOCIADOS.COM` (14), `krbtgt/A1-ASSOCIADOS` (4), `krbtgt/a1-associados.com` (4): the DC's **ticket-granting service**. Asking for it = getting a TGT = **logging on**. Three spellings of the same domain.
    - `cifs/a1associados-dc.a1-associados.com`: the DC's **file share (SMB)** — group policy (SYSVOL) and logon scripts (NETLOGON) at boot and logon.
    - `ldap/A1Associados-DC.a1-associados.com`: **directory lookups (LDAP)** — user details and the list of group policies.
    - `LDAP/A1Associados-DC.a1-associados.com/a1-associados.com`: LDAP with the domain added — "the DC **of this domain**", common in group policy processing.
    - `host/escritorio-pc.a1-associados.com`: **thiago.almeida** getting a ticket **for the PC itself** — happens when a person **logs on at the keyboard**.
    - `escritorio-pc$@A1-ASSOCIADOS.COM`, `ESCRITORIO-PC$`, `escritorio-pc$`: the **computer asking a ticket for itself** (S4U2self), used by group policy to learn a user's groups. `KDC_ERR_BADOPTION` first and success next is a **common normal pattern**.

    **Realm** — the Kerberos **domain name**:

    - `A1-ASSOCIADOS.COM` (40): the official realm (the AD DNS domain in upper case).
    - `a1-associados.com` (4): the same in lower case.
    - `A1-ASSOCIADOS` (4): the short, dot-less **NetBIOS domain name**, used when logging on as `A1-ASSOCIADOS\thiago.almeida`. That is why the 01:38:12 user AS request shows `thiago.almeida/A1-ASSOCIADOS`.

    **cname Cnt, Realm Cnt, sname Cnt** — "Cnt" = **how many different values that field had inside one session**. All `1` → one account, one realm, one service per session. The number in brackets (`(16)`, `(48)`) is how many sessions. Rarely needed, but useful for odd cases such as many account names in one session (guessing).

    **The numbers in brackets in SPIView** (`(8)`, `(14)`) are always the number of **sessions** with that value, not the number of requests.

### 2-5. Reading the result { #identity-reading }

- **PC:** `Escritorio-PC`, 172.16.5.203, MAC `30:85:a9:f4:92:17` (ASUSTek)
- **User:** `thiago.almeida` — logged on **01:38:12** (person AS request succeeded)
- **Domain:** `a1-associados.com` (NetBIOS `A1-ASSOCIADOS`)
- **DC:** `A1Associados-DC` (`a1associados-dc.a1-associados.com`) = **172.16.5.5**. It is **also the DHCP server** — the DHCP replies come from 172.16.5.5:67 in Arkime. Zeek's `server_addr` column was empty, so only Arkime showed this.

**The "DC → PC 7 sessions" question is solved:** 6 DHCP ACKs (the server's reply — the DC *is* the source) + 1 TCP 445 at 01:37:39 (the DC's SMB port; Arkime saw the **DC's packet first**, so it flipped the direction; Zeek used the port, 445 = server). **Both normal.**

**Context:** `escritorio` is Spanish/Portuguese for "office", `associados` is Portuguese for "associates", `thiago.almeida` is a Portuguese-language name → the victim looks like a **Brazilian (Portuguese-speaking) company**. That matches the **Portuguese URLs and `.com.br` sites** in Step 1: the attacker built the **lure in the victim's language**. Keep it in mind for the emails.

The first TLS to 216.194.135.127 starts **37 seconds after the logon** — a program that starts with the logon, or the first thing the user opened (mail?). SNI will tell (Step 3).

**Ticket entry (key facts only):**

```text
Infected host (suspected)
  IP address : 172.16.5.203
  MAC address: 30:85:a9:f4:92:17 (ASUSTek)
  Host name  : Escritorio-PC (escritorio-pc.a1-associados.com)
  User       : thiago.almeida
  Domain     : a1-associados.com (A1-ASSOCIADOS), DC A1Associados-DC 172.16.5.5
```

---

## Step 3 — Connecting the chain { #chain }

**Goal:** answer three open questions.

1. What are the two **encrypted** destinations (216.194.135.127, 162.125.5.x)?
2. Is **lealcontabil.com → 54.38.137.127 → ZIP download** one connected flow?
3. Were the ZIP download and the serveengenharia request made by a **person (browser) or a program**?

Four screens were used: Splunk `zeek:http`, Splunk `zeek:ssl`, Arkime TLS sessions (certificates), and Arkime HTTP sessions **expanded** (raw headers).

### 3-1. Splunk — HTTP log { #http-log }

```spl
index=zeek sourcetype=zeek:http pcap_case=20180927_BLANKCLIPBOARD
| eval t=strftime(ts,"%H:%M:%S")
| table t id_resp_h method host uri referrer status_code resp_mime_types response_body_len user_agent
| sort t
```

- Line 1: this case's HTTP log — **one line per HTTP request**.
- Line 2: `ts` as hour:minute:second.
- Line 3 `table`:
    - `method`: `GET` (fetch) / `POST` (send)
    - `host`: the website name; `uri`: the path on that site
    - `referrer`: **the page the browser was on just before**. If page A links to B, B's request carries A. **The field that joins a chain.**
    - `status_code`: `200` success, `301`/`302` "go somewhere else" (redirect), `404` not found
    - `resp_mime_types`: the real type of what came back (e.g. `application/zip`)
    - `response_body_len`: size of what came back
    - `user_agent`: the **name tag** of the program making the request
- Line 4: time order.

!!! note "Splunk trap to watch for"
    If every row of `host` shows the same value such as `pcapbox`, Zeek's `host` collided with Splunk's built-in `host` field (seen in an earlier case). Then read site names from Arkime. In this case `host` came through correctly.

**Result (10 rows):**

```text
t         id_resp_h        host                    uri                                       status  mime        body_len  user_agent
01:37:08  23.65.180.72     www.msftncsi.com        /ncsi.txt                                 200     text/plain  14        Microsoft NCSI
01:40:54  54.38.137.127    lealcontabil.com        /comercio?imagens/img/tmp/a?onlinepor-email?e=whatsapp_Beckup_REG    301  text/html  297   Mozilla/5.0 (Windows NT 6.1; WOW64; Trident/7.0; rv:11.0) like Gecko
01:40:55  54.38.137.127    lealcontabil.com        /favicon.ico                              404     text/html   209       (same)
01:40:55  54.38.137.127    lealcontabil.com        /comercio/?imagens/img/tmp/a?onlinepor-email?e=whatsapp_Beckup_REG   200  text/html  1382  (same)
01:40:56  54.38.137.127    lealcontabil.com        /comercio/cadastro.php                    302                 0         (same)
01:40:57  54.38.137.127    54.38.137.127           /a/                                       302                 0         (same)
01:40:57  54.38.137.127    54.38.137.127           /index.php                                302                 0         (same)
01:42:22  103.6.198.141    dnpland.com.my          /images/z2448800.zip                      200     (empty)     17066397  Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 6.1; WOW64; Trident/7.0; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.5.30729; .NET CLR 3.0.30729; Media Center PC 6.0; .NET4.0C; .NET4.0E)
01:44:06  177.12.174.95    serveengenharia.com.br  /tmp/soares/cont1/                        200     (empty)     72        (empty)
01:49:13  200.157.208.243  www.msftncsi.com        /ncsi.txt                                 200     text/plain  14        Microsoft NCSI
```

The `referrer` column was **empty on all 10 rows**. (`host` showing each name twice is a display quirk.)

**Reading the columns:**

**① `status_code` — a run of 301 and 302.** From 01:40:54 to 01:40:57: `301 → 200 → 302 → 302 → 302` in four seconds. Nobody clicks five links in four seconds — **the server kept sending the browser elsewhere**, so this is probably one flow. *Where* to is not in this table — it is in the response's `Location` header, visible in Arkime ([3-4](#arkime-http)). The 302 rows have `response_body_len` **0**: just "go there", no content.

**② `user_agent` — three kinds of requester.**

- **01:40:54 – 01:40:57:** `Mozilla/5.0 (Windows NT 6.1; WOW64; Trident/7.0; rv:11.0) like Gecko` → `Windows NT 6.1` = Windows 7, `Trident/7.0; rv:11.0` = **Internet Explorer 11**. A **browser** a person uses.
- **01:42:22 ZIP:** `Mozilla/4.0 (compatible; MSIE 7.0; ...)` → claims to be **IE 7**. The same PC's browser just said IE 11; a PC cannot have both. **Not the IE 11 browser** — this shape usually comes from a **program or script borrowing Windows' internet library**.
- **01:44:06 serveengenharia:** **empty**. Browsers always send a User-Agent. No name tag = **a request built by a program**.

Question 3 is answered: **the ZIP download and the serveengenharia request were made by programs, not a person.**

**③ `referrer` — empty everywhere.** Referer = "which page was I on just before". A clicked link normally carries the page it was clicked on.

- **lealcontabil.com (01:40:54) has none:** browsers **drop the Referer when going from an HTTPS page to an HTTP page**, so the click came from **an HTTPS page** — which one, Step 3-2 shows.
- **ZIP and serveengenharia have none:** the program requested the address **directly** — matches ②.

**④ `response_body_len` — sizes.** ZIP **17,066,397 B** (≈ query ③'s 17,066,676 B from 103.6.198.141 — almost the whole connection). serveengenharia **72 B** — too small for a web page.

**⑤ `resp_mime_types` — empty for the ZIP.** Zeek decides the type from the **first bytes** (magic bytes); a ZIP starts with `PK` → `application/zip`. Empty here. The session had `acked-unseen-segment-src` (missing packets), so the **start of the file may be missing or broken**. Checked in Step 5.

**⑥ Time order — `/a/` and `/index.php`.** The table shows `/a/` above `/index.php`: both are `01:40:57` **to the second**, so `sort t` could not order them. The real order (index.php 01:40:57, /a/ 01:40:58) comes from the response `Date` headers in Arkime. **When several rows share a second, do not trust the sort.**

### 3-2. Splunk — TLS log (SNI) { #ssl-log }

```spl
index=zeek sourcetype=zeek:ssl pcap_case=20180927_BLANKCLIPBOARD
| eval t=strftime(ts,"%H:%M:%S")
| table t id_resp_h id_resp_p server_name version established
| sort t
```

- `server_name`: the **SNI**. TLS encrypts the content, but the client says **which site** it wants **in clear** when the connection starts — so HTTPS still shows the site name.
- `version`: TLS version. `established`: did the handshake complete (`true`/`false`).

```text
t         id_resp_h        id_resp_p  server_name                                             version  established
01:38:49  216.194.135.127  443        webmail.a1-associados.com                               TLSv12   true
01:38:52  216.194.135.127  443        webmail.a1-associados.com                               TLSv12   true
01:38:55  216.194.135.127  443        webmail.a1-associados.com                               TLSv12   true
01:38:57  216.194.135.127  443        webmail.a1-associados.com                               TLSv12   true
01:39:31  216.194.135.127  443        webmail.a1-associados.com                               TLSv12   true
01:40:31  216.194.135.127  443        webmail.a1-associados.com                               TLSv12   true
01:40:46  216.194.135.127  443        webmail.a1-associados.com                               TLSv12   true
01:40:58  162.125.5.1      443        www.dropbox.com                                         TLSv12   true
01:40:58  162.125.5.1      443        www.dropbox.com                                         TLSv12   true
01:41:01  162.125.5.6      443        uc219cb805d84c449d20210774fc.dl.dropboxusercontent.com  TLSv12   true
01:41:01  162.125.5.6      443        uc219cb805d84c449d20210774fc.dl.dropboxusercontent.com  TLSv12   true
```

**216.194.135.127 = `webmail.a1-associados.com` — the company webmail.**

- `a1-associados.com` is the **victim's own domain** (Step 2).
- First connection **01:38:49** = **37 s after the user logged on** (01:38:12). Mail was opened right after logon.
- Last new connection **01:40:46** = **8 s before** the lealcontabil.com request (01:40:54).

This joins the Referer clue: the click came from an HTTPS page, and **the HTTPS page open at that moment was the webmail** → "**the user clicked a link in an email in webmail**". Question 1, part one.

**162.125.5.1 / .6 = Dropbox.** `www.dropbox.com` at 01:40:58 — **right after the last 302** (01:40:57–58). `....dl.dropboxusercontent.com` at 01:41:01 — Dropbox sends shared-link downloads to this `dl.` host for the **actual file**. Why Dropbox — see [3-4](#arkime-http).

### 3-3. Arkime — TLS sessions and certificates { #tls-certs }

```text
tags == 20180927_BLANKCLIPBOARD && ip.dst == [216.194.135.127, 162.125.5.1, 162.125.5.6]
```

A certificate is the server's **ID card**: `Subject CN` / `Alt Name` = the **name** on it, `Issuer CN` = **who issued** it.

```text
162.125.5.1     Alt Name: www.dropbox.com, dropbox.com, support.dropbox.com ...
                Subject CN: www.dropbox.com   Issuer CN: digicert sha2 extended validation server ca
162.125.5.6     Alt Name: *.dl.dropboxusercontent.com, dl.dropboxusercontent.com, dl.dropbox.com ...
                Subject CN: *.dl.dropboxusercontent.com   Issuer CN: digicert sha2 high assurance server ca
216.194.135.127 (first session, 01:38:49)
                Tags: cert:self-signed   Subject CN: a1-associados.com   Issuer CN: a1-associados.com
```

- **Dropbox:** names are dropbox.com, issuer is DigiCert (a well-known public CA) → the **real Dropbox**, not a fake.
- **Webmail:** subject and issuer are **the same** `a1-associados.com` → the company **made its own certificate (self-signed)**; Arkime tagged it `cert:self-signed`. Not good practice, but common in small companies — **not evidence of malice**.

Sizes (Databytes / Bytes, **both directions combined**):

```text
webmail  01:38:49-01:38:52    1,927 /   2,807
webmail  01:38:56-01:39:31  109,382 / 117,930
webmail  01:39:31-01:40:30  694,760 / 745,266   <- largest
webmail  01:40:30-01:40:39  455,789 / 487,557
webmail  01:40:46-01:41:27    4,812 /   6,070
dropbox  162.125.5.1  2 sessions  7,720 / 9,086  and  4,180 / 4,952
dropbox  162.125.5.6  2 sessions  3,635 / 4,515  and  5,613 / 6,709
```

The big webmail sessions are probably the mailbox, message list and message bodies. They are encrypted — **which message was opened cannot be seen**, so the email files themselves are needed (Step 4).

!!! note "Correction — the size of the Dropbox file"
    The first reading said "about 11 KB" for the `dl.dropboxusercontent.com` download. That was **both directions added up** (4,515 + 6,709). Bytes **received** only are in Step 1 query ③: **7,959 B** for 162.125.5.6, and that includes the TLS setup (certificate exchange, a few KB). So the file is **a few KB** — the size of a **small script or shortcut**, not a big program. Inferred from size only; the content is encrypted.

### 3-4. Arkime — HTTP sessions expanded (raw headers) { #arkime-http }

```text
tags == 20180927_BLANKCLIPBOARD && ip.dst == [54.38.137.127, 103.6.198.141, 177.12.174.95]
```

Click `+` on a session: **Source** (pink, what the PC sent) and **Destination** (purple, what the server sent) show the **raw headers** Splunk does not have — mainly **`Location:`** (where it redirected) and the **HTML body**.

**Session ① — port 49218, 01:40:54 (lealcontabil.com, 4 requests)**

Request 1 → response 1:

```text
GET /comercio?imagens/img/tmp/a?onlinepor-email?e=whatsapp_Beckup_REG HTTP/1.1
Accept: text/html, application/xhtml+xml, */*
Accept-Language: en-US
User-Agent: Mozilla/5.0 (Windows NT 6.1; WOW64; Trident/7.0; rv:11.0) like Gecko
Accept-Encoding: gzip, deflate
Host: lealcontabil.com
DNT: 1
Connection: Keep-Alive

HTTP/1.1 301 Moved Permanently
Server: Apache/2.4.6 (CentOS) PHP/5.4.16
Location: http://lealcontabil.com/comercio/?imagens/img/tmp/a?onlinepor-email?e=whatsapp_Beckup_REG
```

→ only adds a `/` after `comercio`; a meaningless move.

Request 2 → response 2 (**the lure page**):

```text
GET /comercio/?imagens/img/tmp/a?onlinepor-email?e=whatsapp_Beckup_REG HTTP/1.1

HTTP/1.1 200 OK
Server: Apache/2.4.6 (CentOS) PHP/5.4.16
Last-Modified: Wed, 16 Dec 2015 23:30:08 GMT
Content-Length: 1382

<meta name="description" content="Ministério Público Federal">
<title> LOCALIZANDO CONTRATO </title>
<meta http-equiv="refresh" content="1; url=cadastro.php">
... Baixando Arquivo... ...
```

- `Ministério Público Federal` = Brazil's **Federal Public Prosecutor's Office** — a government body is being impersonated.
- `LOCALIZANDO CONTRATO` = "**locating the contract**"; `Baixando Arquivo...` = "**downloading file...**".
- `<meta http-equiv="refresh" content="1; url=cadastro.php">` = **go to `cadastro.php` automatically after 1 second** — like a 302, but done in HTML.
- `Last-Modified` 2015 with an old `PHP/5.4.16` and a strange path → a **hacked site** with a planted page (inferred).

Request 3: `GET /favicon.ico` → `404 Not Found`. The browser looking for the tab icon. Normal.

Request 4 → response 4:

```text
GET /comercio/cadastro.php HTTP/1.1

HTTP/1.1 302 Found
Location: http://54.38.137.127/index.php
```

→ now to an **IP with no domain**.

**Session ② — port 49220, 01:40:57 (54.38.137.127, 2 requests)**

```text
GET /index.php HTTP/1.1
Host: 54.38.137.127

HTTP/1.1 302 Found
Date: Thu, 27 Sep 2018 01:40:57 GMT
Server: Apache/2.4.6 (CentOS) PHP/5.4.16
Set-Cookie: last1=0; expires=Fri, 28-Sep-2018 01:40:57 GMT
Location: a/
```

```text
GET /a/ HTTP/1.1
Cookie: last1=0
Host: 54.38.137.127

HTTP/1.1 302 Found
Date: Thu, 27 Sep 2018 01:40:58 GMT
Set-Cookie: last2=2; expires=Fri, 28-Sep-2018 01:40:58 GMT
Location: https://www.dropbox.com/s/0yggmgtymt2r0av/DOC1_CONTRATO_YBFTOP2078686788.zip?dl=1
```

- **`Set-Cookie`:** the server tells the browser "remember this"; the next request sends it back (`Cookie: last1=0`). The server uses it to recognise the visitor — count visits, or send repeat visitors / analysts somewhere else (inferred). This kind of IP-only redirect step is called a **gate**.
- **Last `Location`:** the destination — the Dropbox shared file **`DOC1_CONTRATO_YBFTOP2078686788.zip`**. `?dl=1` = "download directly, no preview". `contrato` = contract, matching the lure page. The attacker put the file on a **trusted service** that security tools rarely block.
- The `Date` headers fix the real order (index.php 01:40:57 → /a/ 01:40:58) — the [Splunk sort issue](#http-log) is solved.

This `Location` explains the Dropbox TLS at 01:40:58 and 01:41:01. **Question 2 is answered.**

**Sessions ③ ④ — ports 49217, 49219 (no data)**

```text
Databytes 0
TCP Flags: SYN 1  SYN-ACK 1  ACK 1  RST 1
```

Connected, sent nothing, closed with RST. IE **opens spare connections in advance** to load pages faster and closes unused ones. **Normal.**

**Session ⑤ — port 49225 (the ZIP)** — the three rows from [1-5](#arkime-split); headers already seen in Splunk (MSIE 7.0, no Referer, 17 MB).

**Session ⑥ — port 49226, 01:44:06 (serveengenharia.com.br)**

```text
GET /tmp/soares/cont1/ HTTP/1.1
Host: serveengenharia.com.br
Cache-Control: no-cache

HTTP/1.1 200 OK
Date: Thu, 27 Sep 2018 01:43:25 GMT
Server: Apache
Transfer-Encoding: chunked
Content-Type: text/html

<meta HTTP-EQUIV='Refresh' CONTENT='0;URL=http://www.google.com'>
```

- **Only two request headers.** Compare with IE 11, which always sends Accept, Accept-Language, User-Agent, Accept-Encoding, DNT, Connection. **Not a browser.** That is why Splunk's User-Agent was empty.
- **The reply** is one line: "go to google.com after 0 seconds". Anyone opening the URL in a browser just lands on Google — a **harmless-looking cover**.
- `cont1` (*contador*?) and a **single** short request right after the ZIP → possibly an **infection counter** (inferred).
- The `Date` (01:43:25) is 41 s behind the capture time (01:44:06): the **server's clock is slow**. Always use **capture time**.

### 3-5. Question: how do we know the Referer is empty? { #referer-empty }

!!! question "Question: you said the Referer is empty — how can I tell?"
    In two places: **Splunk's `referrer` column** and **Arkime's raw request headers**.

    **1. Splunk — the `referrer` column is blank.** In the HTTP query the `referrer` column (right of `uri`) had **no value on all 10 rows**; compare with `user_agent` next to it, which is filled. Zeek writes the `Referer:` header's value into `referrer` when it exists, and **`-` when it does not**. `-` means "no value" in Zeek logs; Splunk usually shows it as blank. (Zeek's field is `referrer` with two r's; the HTTP header is `Referer` with one — an old spelling mistake that became the standard. Same thing.)

    Blanks are easy to miss by eye — **count them**:

    ```spl
    index=zeek sourcetype=zeek:http pcap_case=20180927_BLANKCLIPBOARD
    | eval has_ref=if(isnull(referrer) OR referrer="" OR referrer="-", "no", "yes")
    | stats count by has_ref
    ```

    - Line 2 `eval has_ref=if(condition, "no", "yes")`: makes a new field. `if(condition, A, B)` gives A when true, B otherwise. Conditions: `isnull(referrer)` (no field at all), `referrer=""` (empty text), `referrer="-"` (Zeek's "none" mark kept as is). Any of them (`OR`) → `"no"`.
    - Line 3: counts `no` and `yes`.

    ```text
    has_ref   count
    no        10
    ```

    No `yes` row → **none of the 10 requests had a Referer.** To see the original line:

    ```spl
    index=zeek sourcetype=zeek:http pcap_case=20180927_BLANKCLIPBOARD
    | table _raw
    ```

    - `_raw`: the **original log line** as Splunk received it; the `referrer` position (tab-separated) shows `-`.

    **2. Arkime — no `Referer:` line in the raw request.** This is the **most direct evidence**: Splunk shows Zeek's summary, Arkime shows **exactly what the PC sent**. The first lealcontabil.com request had these 7 headers and nothing else:

    ```text
    GET /comercio?imagens/img/tmp/a?onlinepor-email?e=whatsapp_Beckup_REG HTTP/1.1
    Accept: text/html, application/xhtml+xml, */*
    Accept-Language: en-US
    User-Agent: Mozilla/5.0 (Windows NT 6.1; WOW64; Trident/7.0; rv:11.0) like Gecko
    Accept-Encoding: gzip, deflate
    Host: lealcontabil.com
    DNT: 1
    Connection: Keep-Alive
    ```

    With a Referer there would also be a line like `Referer: https://webmail.a1-associados.com/...`.

    The **HTTP box → `Request Headers`** field lists the header **names** the PC sent in that session (all requests in the session combined):

    ```text
    lealcontabil.com (port 49218)  : accept  accept-encoding  accept-language  connection  dnt  host  user-agent
    54.38.137.127    (port 49220)  : accept  accept-encoding  accept-language  connection  cookie  dnt  host  user-agent
    serveengenharia  (port 49226)  : cache-control  host
    ```

    No `referer` in any of them. Or search for it directly — prove "none" by **searching for it and getting 0**:

    ```text
    tags == 20180927_BLANKCLIPBOARD && http.request-header == referer
    ```

    - `http.request-header`: the field behind `Request Headers`. `== referer`: sessions whose header-name list contains `referer`. (If Arkime rejects the field name, type `http.request` in the search box and pick from the auto-complete list.)

    **3. Reasons a Referer can be empty**

    | Reason | Fits this capture? |
    |---|---|
    | **HTTPS page → HTTP page** (the browser drops it for security) | Yes for the first lealcontabil.com request — HTTPS webmail was open until 8 s earlier |
    | Address typed or opened from a bookmark | Nobody types a URL this long and strange |
    | Opened from a **mail program or other app** | Possible, but this PC was using webmail |
    | **A non-browser program** requested it | Yes for the ZIP (01:42:22) and serveengenharia (01:44:06) — their User-Agents were not browsers |

    **Why the redirect requests have none:** on a 301/302 the browser does **not create a new Referer**; it keeps the original or drops it. There was none at the start, so none along the chain (`/comercio/` → `cadastro.php` → `index.php` → `/a/`). IE usually sends no Referer after a `<meta http-equiv="refresh">` either.

    **How it was used:** "no Referer" alone does not prove "clicked in webmail". Three facts together — no Referer (Splunk + Arkime), HTTPS webmail in use at that moment (SNI, last session 01:40:46), the link request 8 s later — made it **likely**, and the email in Step 4 **confirmed** it.

### 3-6. Putting it together { #chain-summary }

```text
[Step 2 Kerberos]   01:38:12  thiago.almeida logs on
        | 37 s
[SNI]               01:38:49  webmail (webmail.a1-associados.com) opened
        | last webmail connection 01:40:46, 8 s later
[HTTP + Arkime ①]   01:40:54  IE11 opens lealcontabil.com link (no Referer = clicked on an HTTPS page)
                    01:40:55  lure page "Federal Prosecutor / locating contract / downloading file"
                    01:40:56  302 -> 54.38.137.127/index.php
[Arkime ②]          01:40:57  302 + cookie -> /a/
                    01:40:58  302 -> Dropbox DOC1_CONTRATO_YBFTOP2078686788.zip
[SNI + Arkime TLS]  01:41:01  small file (a few KB) from Dropbox
        | 1 min 21 s (time to open and run the file - inferred)
[HTTP]              01:42:22  program (MSIE 7.0 UA) downloads 17 MB ZIP from dnpland.com.my
[HTTP + Arkime ⑥]   01:44:06  program (no UA) calls serveengenharia.com.br/.../cont1/ (counter - inferred)
[Step 2]            01:48-49  restart (inferred)
```

**Confirmed (values on screen):** webmail in use (SNI); the redirect chain link → lure page → 54.38.137.127 → Dropbox ZIP (`Location` headers); the lure content (HTML); the 17 MB ZIP and the serveengenharia request were sent by programs, not the browser (User-Agent, header shape).

**Inferred (supported, not proven):** the link was clicked **in an email in webmail** (no Referer + 8 s gap) → checked in Step 4; the Dropbox file was a small script/shortcut (size only); running it fetched the 17 MB ZIP (time order + UA); serveengenharia is a counter (name + shape).

**Not seen in this capture:** steady C2 (beacons). The capture ends ~2 minutes after the restart; C2 may start after the next user logon, or use another channel. The ticket says only "no C2 seen in this capture".

**Ticket timeline draft:**

```text
#TIMELINE (UTC, 2018-09-27)#
01:38:12  User thiago.almeida logged on to Escritorio-PC (172.16.5.203).
01:38:49  User opened company webmail (webmail.a1-associados.com, 216.194.135.127).
01:40:54  IE11 opened a link with no Referer (likely clicked in webmail):
          hxxp://lealcontabil[.]com/comercio?imagens/img/tmp/a?onlinepor-email?e=whatsapp_Beckup_REG
          Lure page: "LOCALIZANDO CONTRATO", fake "Ministerio Publico Federal".
01:40:56  Redirect chain: /comercio/cadastro.php -> hxxp://54.38.137.127/index.php -> /a/
01:40:58  Redirect to Dropbox: hxxps://www.dropbox[.]com/s/0yggmgtymt2r0av/DOC1_CONTRATO_YBFTOP2078686788.zip?dl=1
          (small file, downloaded from dl.dropboxusercontent.com at 01:41:01)
01:42:22  Non-browser program (UA "MSIE 7.0") downloaded 17 MB ZIP:
          hxxp://dnpland[.]com.my/images/z2448800.zip (103.6.198.141)
01:44:06  Non-browser program (no User-Agent) requested:
          hxxp://serveengenharia[.]com.br/tmp/soares/cont1/ (177.12.174.95) - possible infection counter
01:48-01:49  Host likely restarted (machine logon, DHCP and NCSI repeated). Not confirmed.
No C2 traffic seen in this capture after 01:44:06.
```

URLs are **defanged** (`hxxp`, `[.]`) so a reader cannot click them by accident. In search queries and Snort rules they stay as is.

---

## Step 4 — The two emails: which one started it? { #emails }

**Goal:** answer the exercise's question. The traffic already describes the email to look for:

- **To:** thiago.almeida (or an `@a1-associados.com` address)
- **Received:** **before 01:40:54 UTC**
- **Body:** a **`lealcontabil.com/comercio...`** link, or words like "contrato", "Ministério Público Federal", "whatsapp"

!!! tip "Why traffic first, emails second"
    In the [phishing red herring case](phishing-red-herring-ek-driveby-ursnif-c2.md) the emails were read first; they created the belief "the email did it" — and the real infection was a web drive-by. **Facts from the traffic first** avoid that trap.

!!! danger "Handle the emails safely"
    The links and attachments are real. Do not double-click `.eml` files on your own PC (Outlook/Mail). Unzip and read them **as text** (`cat`, `less`) on an analysis VM such as pcapbox.

### 4-1. Commands { #email-commands }

**① Unzip**

```bash
mkdir -p ~/cases/20180927_BLANKCLIPBOARD/emails
cd ~/cases/20180927_BLANKCLIPBOARD/emails
unzip /path/to/2018-09-27-traffic-analysis-exercise-both-emails.zip
ls -l
```

- `mkdir -p`: makes the folder (with parents; no error if it exists). `cd`: go into it.
- `unzip`: extract. Replace `/path/to/` with the real location. The password is on the site's "about" page.
- `ls -l`: names and sizes.

**② Headers only (who, to whom, when, subject)**

```bash
grep -iE '^(Date|From|To|Subject|Return-Path|Message-ID|Content-Type|Content-Transfer-Encoding):' *.eml
```

- `grep`: print only matching lines. `-i`: ignore case. `-E`: extended regex, so `(A|B|C)` = A or B or C.
- `'^(Date|From|...):'`: lines that **start** (`^`) with these header names.
- `*.eml`: every `.eml` in the folder; each result line starts with the file name.

Look at: is `To:` thiago.almeida? Is `Date:` before 01:40:54 UTC? What is `Content-Transfer-Encoding:` (if `base64` or `quoted-printable`, links in ③ may be hidden or broken)?

**③ Links in the body**

```bash
grep -oiE 'https?://[^"<> ]+' *.eml | sort -u
```

- `-o`: print **only the matching part**, not the whole line.
- `https?://`: `http://` or `https://` (`?` = the `s` is optional).
- `[^"<> ]+`: any run of characters that are not a quote, `<`, `>` or a space = **to the end of the URL**.
- `sort -u`: sort and remove duplicates.

Both emails here were `Content-Transfer-Encoding: 8bit` HTML, so links were readable as text.

### 4-2. The two emails side by side { #email-compare }

| Item | Email A | Email B |
|---|---|---|
| Subject | `Conversa do WhatsApp no (221206)` | `Anotacao de Extrato De Debitos para seu CPF/CNPJ. No (778071)` |
| Meaning | "WhatsApp conversation no. (221206)" | "Debt statement record for your CPF/CNPJ" |
| From (displayed) | `WhatsApp-WEB <nwindows@communication.microsoft.com>` | `Comunicado \| Serasa Experian <atendimento@serasaexperian.com.br>` |
| Real sending server | `tghs18.portaldecontabil.com.br [145.239.135.211]` | `tghs8.portaldecontabil.com.br [145.239.31.79]` |
| To | thiago.almeida@a1-associados.com | thiago.almeida@a1-associados.com |
| Received (UTC) | **2018-09-24 12:52:42** | **2018-09-26 16:19:47** |
| Links | `bit.ly/2k5P2Kt?...`, **`lealcontabil.com/comercio?imagens/img/tmp/a?onlinepor-email?e=whatsapp_Beckup_REG`** | `consultafacilserasaexperian.com/clientes?...` |
| Attachment | none (HTML body only) | none (HTML body only) |

CPF is Brazil's personal taxpayer number, CNPJ the company number. Serasa Experian is a Brazilian **credit bureau**.

### 4-3. Reading headers — what to trust { #email-headers }

**Do not trust `From:`.** The sender can type anything. Email A says "WhatsApp" with a `microsoft.com` address — they do not even match.

**`Received:` is more reliable.** Each mail server a message passes **adds one line at the top**. So the **top `Received:`** matters most — our own server (`smtp.a1-associados.com`) wrote it, so it is hard to fake.

```text
Received: from tghs18.portaldecontabil.com.br ([145.239.135.211]) by
	smtp.a1-associados.com for thiago.almeida@a1-associados.com;
	Mon, 24 Sep 2018 12:52:42 +0000 (UTC)
```

- `from tghs18.portaldecontabil.com.br ([145.239.135.211])`: the server that **actually handed over** the mail — not WhatsApp, not Microsoft, but a Brazilian `portaldecontabil.com.br` server.
- `by smtp.a1-associados.com`: the victim's mail server received it. `for thiago.almeida@...`: the recipient.
- `+0000`: UTC.

**Time zones in `Date:`.** `Date: Mon, 24 Sep 2018 09:52:39 -0300` → `-0300` = "3 hours behind UTC" (Brazil). To get UTC, **add 3 hours**: 09:52:39 + 3 h = **12:52:39 UTC**. Arrived at our server 3 s later — consistent.

**`X-PHP-Originating-Script: 1000:javali.php`** — the most interesting header. When a **PHP program on a web server** sends mail, PHP adds this line automatically: sent by the **script `javali.php`**. Yet `X-Mailer: Microsoft Office Outlook` claims Outlook. It pretended to be Outlook but was **bulk-sent by a web-server script** — a common contradiction in spam and phishing.

### 4-4. Same attacker for both { #same-sender }

- Real sending server: same domain `portaldecontabil.com.br` (tghs18, tghs8); both IPs in `145.239.x.x`.
- Identical `X-PHP-Originating-Script: 1000:javali.php`.
- Identical `X-Mailer: Microsoft Office Outlook, Build 17.551210`.
- Both Portuguese, same recipient.

Different lures, **same sending tool, same campaign**. Email B did not cause this infection but is **another attempt by the same attacker** — worth a ticket line. Email B's body is also **padded with thousands of blank lines** (a trick to push content past filters and scanners).

### 4-5. Email A's body — the lure { #email-body }

Rough meaning of the Portuguese text:

> "Ugh, idiot! Did you think I'd never find out about this? You're wrong! I know everything!! You sent me photos of your conversations with others about me! Here's the record of your conversation. … This won't end here, OK? Goodbye."

An **emotional lure**: an angry acquaintance "has proof of your gossip" — people click **before thinking** to see which conversation.

The links:

```html
<a href="http://bit.ly/2k5P2Kt?imagens/img/tmp/a?onlinepor-email?e=whatsapp_Beckup_REG" ...>
  <img src="https://goo.gl/NFk0qQ" ...></a>

<a href="http://lealcontabil.com/comercio?imagens/img/tmp/a?onlinepor-email?e=whatsapp_Beckup_REG" ...>
  Whatsapp_Beckup_REG(656386387).zip</a>
```

- `href="..."` is **where it really goes**; the text between `<a>` and `</a>` is **what is shown**.
- The second link **looks like a file name**, `Whatsapp_Beckup_REG(656386387).zip` — "a chat backup file". It is really a web link to `lealcontabil.com`.
- The first link is an image (a `goo.gl` short link) pointing to a `bit.ly` short link — short links hide the real destination.

### 4-6. The decisive evidence — the same URL { #url-match }

```text
Email A link : http://lealcontabil.com/comercio?imagens/img/tmp/a?onlinepor-email?e=whatsapp_Beckup_REG
Traffic      : GET /comercio?imagens/img/tmp/a?onlinepor-email?e=whatsapp_Beckup_REG   Host: lealcontabil.com   (01:40:54)
```

Path, the odd `?` positions, even the misspelling `Beckup` — **identical**. A URL this long does not match by chance.

It also confirms the Step 3 inferences:

- **Why no Referer:** HTTPS webmail → HTTP link, **and** the email's HTML has `rel="noopener noreferrer"` — that tells the browser **not to send a Referer at all**. Two reasons together.
- **Which link was clicked:** no `bit.ly` request in the traffic; the PC went **straight** to `lealcontabil.com` → the **text link** `Whatsapp_Beckup_REG(...).zip`, not the image.
- **`e=whatsapp_Beckup_REG`:** the lure page was a "prosecutor contract" while the email was "WhatsApp chat". The same landing page seems to serve **several campaigns**, and this parameter tells it **which email the visitor came from** (inferred).

### 4-7. Times { #email-times }

- Email A received: **09-24 12:52 UTC**
- Email B received: 09-26 16:19 UTC
- Link opened: **09-27 01:40:54 UTC**

Email A arrived **about 2.5 days earlier**; it was clicked when the user opened webmail on the 27th. 01:40 UTC is **22:40 on 26 September** in Brazil (-03:00) — late evening. (Arrival and click times need not be close; mail can be opened days later.)

!!! question "Question: how do we know the link was clicked at 09-27 01:40:54 UTC?"
    Strictly, **01:40:54 is not the moment the mouse was clicked** — it is **when the PC sent its first request caused by that click**. A capture cannot see inside the PC, only packets on the wire, so the click time is represented by the **first request time**.

    **Three screens already showed it:**

    - **Step 3 Splunk HTTP, `t` column:** `01:40:54  54.38.137.127  lealcontabil.com  /comercio?imagens/...` — `t` is Zeek `ts`; in `http.log`, `ts` is **when that HTTP request started**. The email's exact URL first appears at **01:40:54**.
    - **Step 3 Arkime session list (port 49218):** `Start Time 2018/09/27 01:40:54` — the session's **first packet**.
    - **Step 1 Splunk query ③, `first` column:** `54.38.137.127  4  01:40:54  80  http` — `min(ts)`, the **first connection** to this server. Nothing reached it **before** 01:40:54 — this column proves "this was the first time".

    **What happens between the click and the request** (usually under a second):

    1. **DNS query:** "what is lealcontabil.com's IP?" → the DNS server (here the DC 172.16.5.5)
    2. **DNS answer:** "54.38.137.127"
    3. **TCP connection:** SYN to 54.38.137.127:80 → `conn.log` `ts`
    4. **HTTP request:** `GET /comercio?...` → `http.log` `ts`

    The **DNS query is closest to the click**. To the second they all read 01:40:54; to the **millisecond** the order shows:

    ```spl
    index=zeek sourcetype=zeek:dns pcap_case=20180927_BLANKCLIPBOARD query="*lealcontabil*"
    | eval t=strftime(ts,"%H:%M:%S.%3N")
    | table t id_orig_h id_resp_h query answers
    | sort t
    ```

    - Line 1: DNS lines whose query name contains `lealcontabil`.
    - Line 2: `%3N` = **3 digits of milliseconds** (`01:40:54.123`).
    - Line 3: `query` = name asked, `answers` = IPs returned, `id_resp_h` = the DNS server (expect 172.16.5.5).

    ```spl
    index=zeek pcap_case=20180927_BLANKCLIPBOARD (sourcetype=zeek:conn OR sourcetype=zeek:http) id_resp_h="54.38.137.127"
    | eval t=strftime(ts,"%H:%M:%S.%3N")
    | table t sourcetype id_orig_p uri
    | sort t
    ```

    - Line 1: **conn and http logs together**, destination 54.38.137.127 only.
    - Line 3: `sourcetype` says which log; `id_orig_p` is the PC's port (49218 ...); conn rows have no `uri`.

    Expected shape (milliseconds are examples):

    ```text
    t              sourcetype   id_orig_p  uri
    01:40:54.0xx   zeek:conn    49217
    01:40:54.0xx   zeek:conn    49218
    01:40:54.0xx   zeek:http    49218      /comercio?imagens/img/tmp/a?onlinepor-email?e=whatsapp_Beckup_REG
    ```

    DNS → conn (49218) → http (49218) within tens to hundreds of milliseconds → the click was **just before the DNS query**.

    **In the ticket**, write what we know: "**link opened** (first request sent)":

    ```text
    Link opened : 2018-09-27 01:40:54 UTC (first DNS/HTTP request to lealcontabil[.]com, from webmail)
    ```

    When the user first **read** the email cannot be seen on the network (webmail is HTTPS) — that is in the mail server's access log or the host's browser history → a host-operator lead.

### 4-8. Proving email B was *not* used { #negative-check }

"A's link is in the traffic" is half the proof. "**B's link is not**" makes it solid. Search for B's link and images, and A's other addresses (bit.ly, goo.gl):

**Splunk**

```spl
index=zeek pcap_case=20180927_BLANKCLIPBOARD ("consultafacilserasaexperian" OR "encontraaruja" OR "bit.ly" OR "goo.gl")
| table sourcetype _raw
```

- Line 1: no `sourcetype`, so **every Zeek log** of the case (conn, dns, http, ssl ...) is searched. `index=zeek` is still named, as the company rule requires.
- `("A" OR "B" ...)`: lines whose raw text contains any of them — `consultafacilserasaexperian` (B's link), `encontraaruja` (B's image), `bit.ly` and `goo.gl` (A's short link and image).
- Line 2: which log, and the raw line.

**Arkime**

```text
tags == 20180927_BLANKCLIPBOARD && (host == *serasa* || host == *encontraaruja* || host == *bit.ly* || host == *goo.gl*)
```

- `host`: searches **all host-name fields** at once (DNS query, HTTP Host, TLS SNI).
- `*serasa*`: anything containing `serasa`. `||` = or.

**Result: 0 in both.** So in this capture:

- Email B's link was **not opened**; its image was not loaded either (whether B was even displayed cannot be told).
- Email A's image link (`bit.ly`) was **not clicked**; its image (`goo.gl`) was **not loaded** (webmail may block external images).
- The user clicked **only the text link** `Whatsapp_Beckup_REG(656386387).zip`.

**Limit:** "not seen" is true **only within this 14-minute capture**. Email B arrived on the 26th and may have been opened before. The ticket says:

```text
Second email (Serasa Experian lure): no traffic to its link or images in this capture
(2018-09-27 01:37-01:51 UTC). Earlier clicks cannot be ruled out - check mailbox / proxy logs.
```

### 4-9. The answer { #exercise-answer }

> **The email that started the infection is "Conversa do WhatsApp no (221206)" (received 2018-09-24 12:52 UTC).** thiago.almeida clicked its link `Whatsapp_Beckup_REG(656386387).zip` in webmail at 2018-09-27 01:40:54 UTC. Email B (fake Serasa Experian) came from the same attacker but shows no activity in this capture.

!!! note "A small mismatch worth noticing"
    Email B's `Received:` line says `smtp.a1-associaods.com` — a typo (associ**ao**ds). Most likely a mistake by the exercise author, with no effect on the analysis. Noticing such details is still a good habit: in real cases they can reveal forged headers.

---

## Step 5 — The 17 MB ZIP { #zip }

**Goals:** is the ZIP **complete** (Step 1 showed packet-loss tags)? Its **hash** (IOC, and to find the same file elsewhere)? **What is inside** (names only — never run it)?

### 5-1. Splunk — Zeek files.log { #files-log }

```spl
index=zeek sourcetype=zeek:files pcap_case=20180927_BLANKCLIPBOARD
| eval t=strftime(ts,"%H:%M:%S")
| table t tx_hosts rx_hosts source mime_type seen_bytes total_bytes missing_bytes md5 sha1
| sort t
```

- Line 1: the **file records** Zeek found in the traffic — one line per file.
- Line 3 `table`:
    - `tx_hosts` / `rx_hosts`: IP that **sent** / **received** the file (download: server / PC)
    - `source`: which protocol carried it (`HTTP`, `SSL`, `SMB`)
    - `mime_type`: type from the first bytes
    - `seen_bytes`: bytes Zeek **actually saw**
    - `total_bytes`: size the server announced (HTTP `Content-Length`)
    - `missing_bytes`: **bytes missing** — the key column here
    - `md5`, `sha1`: file hashes (may be empty depending on Zeek's settings)

**Result (11 files):**

```text
t         tx_hosts         rx_hosts      source  mime_type   seen_bytes  total_bytes  missing_bytes  md5
01:37:03  172.16.5.5       172.16.5.203  SMB     text/ini    22          22           0              b20996efc49d181769db184aeea375a2
01:37:08  23.65.180.72     172.16.5.203  HTTP    text/plain  14          14           0              cd5a4d3fdd5bffc16bf959ef75cf37bc
01:38:13  172.16.5.5       172.16.5.203  SMB     text/ini    22          22           0              b20996efc49d181769db184aeea375a2
01:40:55  54.38.137.127    172.16.5.203  HTTP    text/html   209         209          0              18ffb59b61525f781cf9251045be575d
01:40:55  54.38.137.127    172.16.5.203  HTTP    text/html   1382        1382         0              6f23120907a7c8e6a884ea9cb6b0807e
01:40:55  54.38.137.127    172.16.5.203  HTTP    text/html   297         297          0              05f7e2ed44d9d45022ce1a15c44800e3
01:42:23  103.6.198.141    172.16.5.203  HTTP                15098446    17066397     1967951
01:44:07  177.12.174.95    172.16.5.203  HTTP                72                       0              a31fcd450e6b680316a04687c0ee3602
01:49:11  172.16.5.5       172.16.5.203  SMB     text/ini    22          22           0              b20996efc49d181769db184aeea375a2
01:49:13  200.157.208.243  172.16.5.203  HTTP    text/plain  14          14           0              cd5a4d3fdd5bffc16bf959ef75cf37bc
01:49:55  172.16.5.5       172.16.5.203  SMB     text/ini    22          22           0              b20996efc49d181769db184aeea375a2
```

!!! note "Why `source` shows two values on every row"
    Each row's `source` showed `/data/zeek/20180927_BLANKCLIPBOARD/files.log` **and** `HTTP` (or `SMB`). Another **field-name collision**, like `host`: Splunk's `source` = **which file the log was read from**; Zeek's `source` = **which protocol carried the file**. Same name, one column. The lower value (`HTTP`, `SMB`) is Zeek's.

**Group 1 — normal Windows activity**

- **SMB `text/ini`, 22 B, from the DC:** the group policy file **`GPT.INI`**. At **boot and logon** Windows reads it from the DC's SYSVOL share to check "has the policy changed?". Same hash all four times.
- **HTTP `text/plain`, 14 B:** NCSI's `ncsi.txt`, content "Microsoft NCSI" (14 characters). Same hash both times.

**More evidence for the restart.** `GPT.INI` was read at:

- **01:37:03** — right after the computer account logon (01:37:02) = **boot**, computer policy
- **01:38:13** — right after thiago.almeida's logon (01:38:12) = user policy
- **01:49:11** — after the computer account logon (01:49:05) = **boot again**, computer policy

The 01:37 pattern repeats at 01:49 — **another sign** on top of Kerberos, DHCP and NCSI.

**Group 2 — the lure pages (seen in Step 3)**

- 297 B (301 page), 1,382 B (**lure page**, MD5 `6f23120907a7c8e6a884ea9cb6b0807e`), 209 B (404 page), 72 B (serveengenharia reply, MD5 `a31fcd450e6b680316a04687c0ee3602`).
- Sizes equal Step 3's `response_body_len`; the 72 B MD5 equals Arkime's **Body MD5s** in Step 3 — **two tools saw the same data**.
- serveengenharia's `total_bytes` is empty because the reply used `Transfer-Encoding: chunked`: the server sends **pieces** without announcing the full size (`Content-Length`), so Zeek does not know the total. Normal.

**Group 3 — the ZIP**

- `total_bytes` **17,066,397** — what the server said it would send (`Content-Length`)
- `seen_bytes` **15,098,446** — what Zeek **actually saw**
- `missing_bytes` **1,967,951** — **missing from the capture** (~1.9 MB, ~11.5 %)

15,098,446 + 1,967,951 = **17,066,397** exactly. `md5`/`sha1` are **empty**: a file with holes has no meaningful hash, so Zeek did not write one. `mime_type` is empty too: the first bytes (`PK`) may be in the missing part.

### 5-2. Arkime — the ZIP session { #zip-arkime }

```text
tags == 20180927_BLANKCLIPBOARD && ip.dst == 103.6.198.141
```

Expand the **first** of the three rows (the one showing the URI):

```text
Time      2018/09/27 01:42:21 – 01:42:29 UTC
Src       Packets 4,248  Bytes 229,724  Databytes 320
Dst       Packets 5,752  Bytes 7,832,111  Databytes 6,535,416
Tags      20180927_BLANKCLIPBOARD  acked-unseen-segment-src  incomplete-tcp  out-of-order-dst
HTTP      GET (1)  200  dnpland.com.my  Mozilla/4.0 (compatible; MSIE 7.0; ...)
          Request Headers   accept accept-encoding connection host user-agent
          Response Headers  accept-ranges connection content-length content-type date keep-alive last-modified server upgrade
          content-type      application/zip
          server            Apache
```

- `Content-Type: application/zip` is the **server's claim**, not a check of the content (unlike Zeek's `mime_type`).
- **No `Body MD5s` field at all** — the other HTTP sessions in Step 3 had one. Arkime could not assemble the full body either. Same conclusion as Zeek.

**Did the PC get the whole file?** Most likely **yes** — what is missing is the **sensor's copy**. The tag `acked-unseen-segment-src` says so:

- `acked`: acknowledged (ACK)
- `unseen-segment`: data the capture **did not see**
- `src`: by the source (the PC)

= "**the PC said 'got it' for data the capture does not have**". The server sent it, the PC received it, the sensor in the middle dropped some packets (common when traffic peaks). The later events agree: right after the ZIP, a **program** called serveengenharia at 01:44:06 — indirect evidence the file was used.

**Lesson:** "missing in the capture" does not mean "the attack failed". **TCP ACKs show whether the receiver actually got the data.**

### 5-3. tshark — export the HTTP objects { #export }

```bash
mkdir -p ~/cases/20180927_BLANKCLIPBOARD/export
tshark -r /data/pcap/20180927_BLANKCLIPBOARD.pcap --export-objects http,$HOME/cases/20180927_BLANKCLIPBOARD/export
cd ~/cases/20180927_BLANKCLIPBOARD/export
ls -l
```

- `tshark -r file`: read the PCAP.
- `--export-objects http,folder`: save **every file carried over HTTP** into the folder.

**Result:**

```text
-rw-r--r--. 1 analyst analyst  297 'a%3fonlinepor-email%3fe=whatsapp_Beckup_REG'
-rw-r--r--. 1 analyst analyst 1382 'a%3fonlinepor-email%3fe=whatsapp_Beckup_REG(1)'
-rw-r--r--. 1 analyst analyst   72  cont1
-rw-r--r--. 1 analyst analyst  209  favicon.ico
-rw-r--r--. 1 analyst analyst   14 'ncsi(1).txt'
-rw-r--r--. 1 analyst analyst   14  ncsi.txt
```

**No `z2448800.zip`.** `--export-objects` saves only bodies it could assemble **from start to end**; with 1,967,951 B missing, it skipped the ZIP. After Zeek (`missing_bytes`) and Arkime (no Body MD5), this is the **third tool with the same result**.

| Exported name | Size | Really |
|---|---|---|
| `a%3fonlinepor-email%3fe=whatsapp_Beckup_REG` | 297 | lealcontabil.com **301 page** |
| `a%3fonlinepor-email%3fe=whatsapp_Beckup_REG(1)` | 1382 | the **lure page** "LOCALIZANDO CONTRATO" |
| `cont1` | 72 | serveengenharia **counter reply** (redirect to google.com) |
| `favicon.ico` | 209 | not an icon — the **404 page** |
| `ncsi.txt`, `ncsi(1).txt` | 14 | the two NCSI replies (01:37, 01:49) |

- tshark names files after the **last part of the URL**; `%3f` is `?` URL-encoded (awkward in file names); `(1)` is added when names repeat.
- `favicon.ico`: the **name can lie** — it comes from the request URL, the content from the server, which sent a 404 page.
- The 302 replies (cadastro.php, index.php, /a/) had 0-byte bodies — nothing to export.

Cross-check the tools:

```bash
md5sum *
```

- MD5 of every file in the folder. Compare with `files.log`: lure page (1382) `6f23120907a7c8e6a884ea9cb6b0807e`, `cont1` (72) `a31fcd450e6b680316a04687c0ee3602`. Equal → Zeek, Arkime and tshark **saw the same data**.

### 5-4. Optional — reading the ZIP's file names from single packets { #zip-names }

Not finished in this case (the ZIP was set aside), kept as a method. A ZIP writes the names of the files inside **in clear text** in two places, each with a fixed **marker**:

| Marker (hex) | Text | Where | Holds |
|---|---|---|---|
| `50 4b 03 04` | `PK..` | just before each file (from the start) | that file's name |
| `50 4b 01 02` | `PK..` | near the end (central directory) | every file's name and size |
| `50 4b 05 06` | `PK..` | the very end | number of files, where the directory is |

The ZIP's list lives at the **end**, so even a broken file can show names if the packets carrying those markers were captured:

```bash
P=/data/pcap/20180927_BLANKCLIPBOARD.pcap
tshark -r $P -Y 'ip.src==103.6.198.141 && tcp.payload contains 50:4b:03:04' -T fields -e frame.number -e tcp.seq
tshark -r $P -Y 'ip.src==103.6.198.141 && tcp.payload contains 50:4b:01:02' -T fields -e frame.number -e tcp.seq
tshark -r $P -Y 'ip.src==103.6.198.141 && tcp.payload contains 50:4b:05:06' -T fields -e frame.number -e tcp.seq
tshark -r $P -Y 'frame.number==N' -x
```

- `P=...`: store the long path in `P`; use it as `$P`.
- `-Y '...'`: a Wireshark display filter — packets **from** the ZIP server whose TCP data **contains** the 4 bytes.
- `-T fields -e frame.number -e tcp.seq`: print only the packet number and `tcp.seq` (where in the stream the data starts; tshark shows it relative, from 0).
- Expect `03 04` near `tcp.seq` ≈ 300 (after the HTTP header) and `01 02` / `05 06` near ≈ 17,066,000. Nothing → that part is in the missing 1.97 MB.
- `-x`: hex + text dump of packet `N`; the name (`xxxx.exe`, `xxxx.vbs`) appears just after `PK..` in the text column.

Never extract or run the content.

**Ticket text for the ZIP:**

```text
Second-stage download (incomplete in capture):
  URL      : hxxp://dnpland[.]com.my/images/z2448800.zip (103.6.198.141)
  Time     : 2018-09-27 01:42:22 UTC
  Size     : 17,066,397 bytes (Content-Type: application/zip)
  Capture  : 1,967,951 bytes missing (sensor packet loss; host ACKed the data).
             No reliable hash from this PCAP.
```

---

## Step 6 — One Snort rule { #snort }

### 6-1. Which rule, and why { #rule-choice }

One key rule, as in Night Dew. Here the best target is **the moment the phishing link is clicked**. Email A's two links:

```text
http://bit.ly/2k5P2Kt?imagens/img/tmp/a?onlinepor-email?e=whatsapp_Beckup_REG
http://lealcontabil.com/comercio?imagens/img/tmp/a?onlinepor-email?e=whatsapp_Beckup_REG
```

Different domains, but the tail **`/img/tmp/a?onlinepor-email?e=`** is identical — the **path format** the campaign uses. Matching it:

- **survives domain/IP changes** — the attacker swaps hacked sites, the path format likely stays;
- catches the **start of the chain** — the alert means "someone clicked the phishing link", **before** the ZIP arrives;
- has **almost no false positives** — normal sites do not build addresses with `?onlinepor-email?e=`.

### 6-2. The rule, part by part { #rule-anatomy }

```text
alert tcp $HOME_NET any -> $EXTERNAL_NET 80 (msg:"Phishing lure link clicked - onlinepor-email URI - Sung"; flow:to_server,established; content:"GET "; depth:4; content:"/img/tmp/a?onlinepor-email?e="; distance:0; sid:1000002; rev:1;)
```

**Header** (before the brackets):

- `alert`: raise an alert on a match. `tcp`: TCP only.
- `$HOME_NET any`: from **our network**, any port. `->`: direction, left to right only.
- `$EXTERNAL_NET 80`: to **outside**, port 80 (HTTP).

**Options** (inside the brackets, each ending with `;`):

- `msg:"..."`: the alert text.
- `flow:to_server,established`: only packets **to the server** on an **established** connection — a click is the PC asking the server.
- `content:"GET "; depth:4;`: the **first 4 bytes** are `GET `, the first word of an HTTP request. `depth:4` = "only look in the first 4 bytes" — fast and precise.
- `content:"/img/tmp/a?onlinepor-email?e=";`: the campaign path.
- `distance:0;`: find it **somewhere after** the previous `content` (`GET `) — keeps the order.
- `sid:1000002;`: rule number. Night Dew's rule is 1000001, so the next one. Your own rules use 1,000,000 and above.
- `rev:1;`: rule version; raise it on every change.

**Expected on this PCAP:** session ① (port 49218) had **2 requests** with this path (01:40:54 → 301, 01:40:55 → lure page) → **2 alerts**, both `172.16.5.203:49218 -> 54.38.137.127:80`. Anything else would be a false positive.

### 6-3. Testing it { #snort-test }

The full beginner's guide is in [Night Dew, second pass — testing a Snort rule](night-dew-arkime-splunk-netlogon-bruteforce.md#snort-test). The steps for this case:

**0. Check `HOME_NET` first (new for this case).** Night Dew was `10.0.14.x`; this case is `172.16.5.x`. If `HOME_NET` does not cover 172.16, **a correct rule will not fire**.

```bash
grep -E '^ipvar (HOME_NET|EXTERNAL_NET)' /etc/snort/snort.conf
```

- `'^ipvar (HOME_NET|EXTERNAL_NET)'`: lines that **start** with `ipvar HOME_NET` or `ipvar EXTERNAL_NET`.
- `ipvar HOME_NET any` → fine. `[10.0.0.0/8,172.16.0.0/12,192.168.0.0/16]` → fine. No 172.16 → add it (or use `any` while testing).

**1. Add the rule**

```bash
nano /data/rules/local.rules
tail -3 /data/rules/local.rules
```

- Paste the rule on **one line** at the bottom; **Ctrl+O**, Enter to save, **Ctrl+X** to exit. Leave sid 1000001 in place: it should give **0** on this PCAP — a free false-positive check.
- `tail -3`: the last 3 lines; the new rule must appear **whole on one line**. Watch for curly quotes (`“ ”`) from copy-paste.

**2. Syntax check and PCAP test in one go**

```bash
snort-test 20180927_BLANKCLIPBOARD
```

Expected:

```text
[1/2] syntax OK
[2/2] /data/pcap/20180927_BLANKCLIPBOARD.pcap
  count [gid:sid:rev] message
      2 [1:1000002:1] Phishing lure link clicked - onlinepor-email URI - Sung
```

**3. Each alert line (time, source, destination)**

```bash
mkdir -p /tmp/snortlog
sudo snort -c /etc/snort/snort.conf -r /data/pcap/20180927_BLANKCLIPBOARD.pcap -A console -q -k none -U -y -l /tmp/snortlog
```

- `-r`: read the PCAP. `-A console`: alerts on screen, one per line. `-q`: hide the banner.
- `-k none`: no checksum check (otherwise Snort may drop captured packets and stay silent).
- `-U -y`: UTC, with the year. `-l /tmp/snortlog`: log folder (avoids the `/var/log/snort` missing error).

Expected:

```text
09/27/18-01:40:54.xxxxxx  [**] [1:1000002:1] Phishing lure link clicked - onlinepor-email URI - Sung [**] [Priority: 0] {TCP} 172.16.5.203:49218 -> 54.38.137.127:80
09/27/18-01:40:55.xxxxxx  [**] [1:1000002:1] Phishing lure link clicked - onlinepor-email URI - Sung [**] [Priority: 0] {TCP} 172.16.5.203:49218 -> 54.38.137.127:80
```

Check: **2** alerts, at **01:40:54 and 01:40:55**, all to **54.38.137.127:80**.

!!! note "Status of this test"
    The rule test was **not run** during this case (the results were assumed good to finish the ticket). The output above is the **expected** result — run `snort-test` once and put the real count in the ticket.

**If it does not fire:**

1. **0 alerts:** check `HOME_NET` (step 0); then that the rule is one line and the quotes are straight.
2. **Still 0:** test a minimal rule with only `content:"onlinepor-email";`. If it fires, add options back one by one; raise `rev` each time.
3. **Only 1:** both requests may share one packet. The click is still caught; compare with the session in Arkime.

---

## Timeline (2018-09-27, UTC) { #timeline }

| Time | Event |
|---|---|
| 01:37:01 | Capture starts |
| 01:37:02 | PC starts: computer account logs on (Kerberos), group policy, DHCP INFORM, NCSI (01:37:07) |
| 01:38:12 | thiago.almeida logs on (Kerberos) |
| 01:38:49 | Company webmail `webmail.a1-associados[.]com` (216.194.135.127, TLS) — until 01:41:27 |
| 01:40:54 | IE11 opens email A's link (no Referer): `lealcontabil[.]com/comercio?imagens/img/tmp/a?onlinepor-email?e=whatsapp_Beckup_REG` |
| 01:40:55 | Lure page "LOCALIZANDO CONTRATO" (fake Ministério Público Federal), refresh to `cadastro.php` |
| 01:40:56–01:40:58 | `cadastro.php` → 302 → `54.38.137.127/index.php` → 302 (cookie) → `/a/` → 302 → Dropbox |
| 01:40:58–01:41:01 | Dropbox `DOC1_CONTRATO_YBFTOP2078686788.zip` (a few KB, TLS) |
| 01:42:22 | Non-browser program (MSIE 7.0 UA) downloads `dnpland[.]com[.]my/images/z2448800.zip`, 17,066,397 B |
| 01:44:06 | No-UA request `serveengenharia[.]com[.]br/tmp/soares/cont1/` (likely counter) |
| 01:48–01:49 | Likely restart: computer logon 01:49:05, DHCP 01:49:08, GPT.INI 01:49:11, NCSI 01:49:13 (port 49183 again) |
| 01:51:35 | Capture ends — no C2 seen, user not logged on again |

Email A was received 2018-09-24 12:52:42 UTC; email B 2018-09-26 16:19:47 UTC.

---

## Incident ticket { #ticket }

Written in the team's ticket format (index entry, metadata, internal/external machines, search queries, evidence, operator log, tool output). **Key findings only** — no baselining work. Operator name, operator log times, ticket links, evidence paths and the Snort result count are placeholders to replace.

[:material-download: Download the ticket as a txt file](files/180927_ESCRITORIO-PC_ticket.txt){ .md-button }

```text
--8<-- "docs/blueteam/investigations/files/180927_ESCRITORIO-PC_ticket.txt"
```

Before sending: run `snort-test` and put the count in; add the `ingest.log` SHA256; export the evidence PCAPs named in EVIDENCE LOCATIONS (Arkime → **Actions → Export PCAP** on each search).

Host-operator leads in the ticket use these Windows events: **4688** new process (with command line), **Sysmon 1** process create, **Sysmon 3** network connection, **1074** who/what asked for a restart, **6006** clean shutdown, **6008** unexpected shutdown, **6005** event log start (boot).

---

## Copy-ready queries { #query-sheet }

Replace `<case>` with your case name. Drop `tags`/`pcap_case` on a live network.

**Arkime**

```text
tags == <case>
tags == <case> && protocols == http
tags == <case> && protocols == dhcp
tags == <case> && protocols == krb5
tags == <case> && ip.src == 172.16.5.5
tags == <case> && ip.dst == [216.194.135.127, 162.125.5.1, 162.125.5.6]
tags == <case> && ip.dst == [54.38.137.127, 103.6.198.141, 177.12.174.95]
tags == <case> && ip.dst == 103.6.198.141
tags == <case> && http.request-header == referer
tags == <case> && (host == *serasa* || host == *encontraaruja* || host == *bit.ly* || host == *goo.gl*)
http.uri == *onlinepor-email*
```

**Splunk (Zeek)**

```spl
index=zeek sourcetype=zeek:conn | stats count by pcap_case
index=zeek sourcetype=zeek:conn pcap_case=<case> | stats min(ts) as first max(ts) as last count as sessions | eval first=strftime(first,"%Y-%m-%d %H:%M:%S"), last=strftime(last,"%Y-%m-%d %H:%M:%S")
index=zeek sourcetype=zeek:conn pcap_case=<case> id_orig_h="172.16.5.*" | stats count as sessions dc(id_resp_h) as dests sum(orig_bytes) as sent sum(resp_bytes) as received by id_orig_h | sort - sessions
index=zeek sourcetype=zeek:conn pcap_case=<case> NOT id_resp_h IN ("172.16.5.*", "224.*", "255.255.255.255") | stats count as sessions min(ts) as first values(id_resp_p) as ports values(service) as service sum(orig_bytes) as sent sum(resp_bytes) as received by id_orig_h id_resp_h | eval first=strftime(first,"%H:%M:%S") | sort - received
index=zeek sourcetype=zeek:dhcp pcap_case=<case> | eval t=strftime(ts,"%H:%M:%S") | table t client_addr server_addr assigned_addr mac host_name domain msg_types | sort t
index=zeek sourcetype=zeek:kerberos pcap_case=<case> | eval t=strftime(ts,"%H:%M:%S") | table t id_orig_h id_resp_h request_type client service success error_msg | sort t
index=zeek sourcetype=zeek:http pcap_case=<case> | eval t=strftime(ts,"%H:%M:%S") | table t id_resp_h method host uri referrer status_code resp_mime_types response_body_len user_agent | sort t
index=zeek sourcetype=zeek:http pcap_case=<case> | eval has_ref=if(isnull(referrer) OR referrer="" OR referrer="-", "no", "yes") | stats count by has_ref
index=zeek sourcetype=zeek:ssl pcap_case=<case> | eval t=strftime(ts,"%H:%M:%S") | table t id_resp_h id_resp_p server_name version established | sort t
index=zeek sourcetype=zeek:dns pcap_case=<case> query="*lealcontabil*" | eval t=strftime(ts,"%H:%M:%S.%3N") | table t id_orig_h id_resp_h query answers | sort t
index=zeek pcap_case=<case> (sourcetype=zeek:conn OR sourcetype=zeek:http) id_resp_h="54.38.137.127" | eval t=strftime(ts,"%H:%M:%S.%3N") | table t sourcetype id_orig_p uri | sort t
index=zeek pcap_case=<case> ("consultafacilserasaexperian" OR "encontraaruja" OR "bit.ly" OR "goo.gl") | table sourcetype _raw
index=zeek sourcetype=zeek:files pcap_case=<case> | eval t=strftime(ts,"%H:%M:%S") | table t tx_hosts rx_hosts source mime_type seen_bytes total_bytes missing_bytes md5 sha1 | sort t
```

**Email (analysis VM, text only)**

```bash
grep -iE '^(Date|From|To|Subject|Return-Path|Message-ID|Content-Type|Content-Transfer-Encoding):' *.eml
grep -oiE 'https?://[^"<> ]+' *.eml | sort -u
```

**Files**

```bash
tshark -r /data/pcap/<case>.pcap --export-objects http,$HOME/cases/<case>/export
md5sum *
tshark -r /data/pcap/<case>.pcap -Y 'ip.src==<server> && tcp.payload contains 50:4b:01:02' -T fields -e frame.number -e tcp.seq
```

**Snort**

```bash
grep -E '^ipvar (HOME_NET|EXTERNAL_NET)' /etc/snort/snort.conf
snort-test <case>
sudo snort -c /etc/snort/snort.conf -r /data/pcap/<case>.pcap -A console -q -k none -U -y -l /tmp/snortlog
```

---

## Lessons { #lessons }

1. **When counts show nothing, sort by bytes.** No external IP stood out by sessions; one session carried 92 % of the bytes.
2. **Read HTTP first.** The cleartext URLs, status codes and User-Agents told most of the story before any TLS or email.
3. **Follow `Location`.** 301/302/refresh headers turn five separate requests into one chain ending on Dropbox.
4. **Compare User-Agents on the same PC.** IE11 (`rv:11.0`) vs `MSIE 7.0` vs none = browser vs programs.
5. **An empty field is evidence too.** No Referer, no User-Agent, no Body MD5, no hash — each one meant something.
6. **SNI names encrypted destinations.** The "unknown 1.26 MB TLS" was the company webmail; that placed the click.
7. **Test a hypothesis with more than one source.** DHCP INFORM alone could not show a restart; Kerberos, NCSI ports and GPT.INI together could.
8. **Prove the negative.** Email B's link, bit.ly and goo.gl all searched → 0; "only the text link was clicked".
9. **Missing in the capture ≠ not received.** `acked-unseen-segment-src` showed the PC got the ZIP the sensor lost.
10. **Write rules on the campaign's shape, not its domains.** The link path format was shared by two different domains.

## References { #references }

- [Night Dew, second pass — the same pcapbox method](night-dew-arkime-splunk-netlogon-bruteforce.md) · [Phishing red herring — email analysis](phishing-red-herring-ek-driveby-ursnif-c2.md)
- [Arkime search syntax](../../network/arkime/search-syntax.md) · [Analysing a PCAP with Arkime](../../network/arkime/offline-pcap-guide.md)
- [Zeek logs](../../network/zeek/index.md) · [files.log](../../network/zeek/files-log.md) · [ssl & x509](../../network/zeek/ssl-x509.md)
- [SPL cheat sheet](../splunk/spl-cheatsheet.md) · [Adversary: phishing delivery](../../adversary/phishing-delivery.md) · [Playbook: compromised workstation](../playbooks/compromised-workstation.md)
- Original exercise: [malware-traffic-analysis.net — 2018-09-27 Blank Clipboard](https://malware-traffic-analysis.net/2018/09/27/index.html)

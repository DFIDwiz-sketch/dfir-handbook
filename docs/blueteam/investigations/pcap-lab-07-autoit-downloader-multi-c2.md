---
title: Webmail to an AutoIt downloader and multi-C2 traffic
tags:
  - blue-team
  - pcap
  - zeek
  - tshark
  - autoit
  - lokibot
  - c2
  - capture-loss
---

# Webmail to an AutoIt downloader and multi-C2 traffic { #lab-07 }

!!! abstract "Case summary"
    A stand-alone Windows 7 PC opened Yahoo Mail in Internet Explorer. About 45 seconds later a non-browser program downloaded `jjjj.exe`. Fourteen minutes later, an AutoIt-based program downloaded a second EXE, `zugu.exe`, checked the public IP and started talking to several C2 servers:

    - HTTP POSTs with the LokiBot-style User-Agent `Charon; Inferno`;
    - a `config.jpg` / `gate.php` panel;
    - HTTPS to a host with an expired certificate;
    - 232 rejected attempts to TCP port 5552.

    It also sent about 4 KB over encrypted SMTP to AOL. The capture lost packets, so **neither EXE can be hashed**.

| | |
|---|---|
| **Evidence** | `Phase1_PCAP_7.pcap`, 2017-11-20 23:58:00 – 2017-11-21 00:16:33 UTC (18.5 min) |
| **Environment** | Offline Linux analysis VM, Zeek 4.x, tshark, no internet |
| **Main tool** | Zeek logs + `zeek-cut`, `awk`, `grep`; tshark for TTL and DHCP options |
| **Lab guide** | [Training → PCAP IR Labs → Lab 7](../../training/pcap-ir-labs/lab-guide.md#lab-7) |

## The questions { #questions }

The host is **not** assumed to be Windows.

1. IP address of the compromised host.
2. MAC address.
3. Hostname.
4. Operating system.
5. What was downloaded, and how many files.
6. Where each file was downloaded from.
7. Did the files come from an internal or an external source?
8. Information that could help further investigation.
9. Did anything else happen after the downloads?
10. What started the downloads?
11. Explanation of the compromise.

## Answers at a glance { #answers }

| # | Answer | Status |
|---|---|---|
| 1 | **10.192.1.157** | Confirmed |
| 2 | **50:46:5d:d5:24:3b** | Confirmed |
| 3 | **WIN-D5243B** | Confirmed |
| 4 | **Windows 7** (User-Agent `Windows NT 6.1`, DHCP `MSFT 5.0`, TTL 128) | Confirmed |
| 5 | **Two 32-bit Windows EXEs**: `jjjj.exe` (3,061,200 bytes) and `zugu.exe` (5,895,226 bytes) | Confirmed |
| 6 | `http://lucrecianos.com.ar/imagen/1/2/jjjj.exe` (170.231.127.136) and `http://virtualsmsonline.site/zugu.exe` (104.31.92.140) | Confirmed |
| 7 | **External**: public IPs on the internet, fetched over HTTP | Confirmed |
| 8 | URLs, IPs, sizes, compile time, C2 hosts, User-Agents, SMTP; **no hashes** (capture loss) | See [IOCs](#iocs) |
| 9 | Second download, public IP check, C2 to four destinations, ~4 KB over SMTPS | Traffic confirmed; families and exfiltration inferred |
| 10 | Not the browser: first request had **no User-Agent**; second came from **AutoIt** | Partly confirmed |
| 11 | See the [report](#report) | — |

---

## Step 0 — Set up and generate the Zeek logs { #step-0 }

```bash
cd ~/Investigation_7
sha256sum Phase1_PCAP_7.pcap | tee pcap.sha256
mkdir zeek_full && cd zeek_full
zeek -C -r ../Phase1_PCAP_7.pcap local \
     frameworks/files/extract-all-files \
     policy/protocols/conn/mac-logging 2>/dev/null
ll
```

The options are explained in [Invoice email case, step 0](pcap-lab-06-invoice-macro-c2.md#step-0). This time, **the list of logs is already evidence**:

```text
capture_loss.log  conn.log  dhcp.log  dns.log  extract_files/  files.log  http.log
loaded_scripts.log  notice.log  packet_filter.log  pe.log  reporter.log  ssl.log
stats.log  x509.log
```

| What you see | What it tells you |
|---|---|
| no `kerberos.log`, no `smb_*.log` | No domain logons: a **stand-alone PC**, not part of Active Directory (inferred). There is no account question in this lab |
| `pe.log` | Zeek parsed at least one **Windows executable** in the traffic |
| `notice.log` | Zeek flagged something worth a look |
| `capture_loss.log` | Zeek keeps packet-loss statistics. It matters in [step 5](#capture-loss) |
| no `software.log` | This install's `local` policy does not log software versions (or found none). Read User-Agents from `http.log` instead |

---

## Step 1 — The big picture { #step-1 }

```bash
zeek-cut -u ts < conn.log | sort | sed -n '1p;$p'
zeek-cut id.orig_h < conn.log | grep -E "^10\.|^172\.|^192\.168\." | sort | uniq -c | sort -rn
zeek-cut service < conn.log | sort | uniq -c | sort -rn
```

```text
2017-11-20T23:58:00+0000
2017-11-21T00:16:33+0000

    575 10.192.1.157

    254 -
    163 dns
    119 ssl
     31 http
     10 dhcp
```

- 18.5 minutes of traffic and **one internal host**, the only candidate.
- `service` is the protocol Zeek recognised in each connection. Only DNS, TLS, HTTP and DHCP, so the downloads are not over FTP, SMB or TFTP.
- **254 connections with service `-`**: Zeek could not identify the protocol. That is usually because the connection never got far enough to show any content. They are examined in [step 7](#unknown-service).

=== "tshark alternative"

    ```bash
    tshark -r ../Phase1_PCAP_7.pcap -q -z io,phs
    ```

    `-z io,phs` prints the **Protocol Hierarchy** (Wireshark *Statistics → Protocol Hierarchy*). It also lists protocols Zeek writes no log for, such as ARP, LLMNR, NBNS, mDNS and TFTP. That is useful when the download protocol is unknown.

---

## Step 2 — IP, MAC and hostname (Q1–3) { #identity }

```bash
zeek-cut -u ts client_addr mac host_name < dhcp.log
```

```text
2017-11-20T23:58:00+0000   10.192.1.157   50:46:5d:d5:24:3b   -
2017-11-20T23:58:04+0000   10.192.1.157   50:46:5d:d5:24:3b   WIN-D5243B
2017-11-21T00:08:27+0000   10.192.1.157   50:46:5d:d5:24:3b   WIN-D5243B
2017-11-21T00:13:01+0000   10.192.1.157   50:46:5d:d5:24:3b   WIN-D5243B
2017-11-21T00:13:28+0000   10.192.1.157   50:46:5d:d5:24:3b   WIN-D5243B
2017-11-21T00:14:46+0000   10.192.1.157   50:46:5d:d5:24:3b   WIN-D5243B
2017-11-21T00:15:48+0000   10.192.1.157   50:46:5d:d5:24:3b   WIN-D5243B
```

- **10.192.1.157 · 50:46:5d:d5:24:3b · WIN-D5243B** (Q1–3, confirmed).
- The first line has no hostname: the very first DHCP message did not carry option 12. That is normal.
- `WIN-` + six characters is the shape of the random name Windows gives itself at install time. It is a hint, not proof, of the OS.

=== "tshark alternative (when DHCP has no name)"

    ```bash
    tshark -r ../Phase1_PCAP_7.pcap -Y "nbns || llmnr || mdns" \
           -T fields -e ip.src -e eth.src -e nbns.name -e dns.qry.name | sort | uniq -c
    ```

    Non-Windows hosts often send no DHCP hostname but announce themselves with NBNS, LLMNR or mDNS (`name.local`). Zeek writes no NBNS log, so tshark is the easy way here. In this capture DHCP already gave the name.

---

## Step 3 — Operating system (Q4) { #os }

### User-Agents { #user-agents }

```bash
zeek-cut user_agent < http.log | sort | uniq -c | sort -rn
```

```text
     15 Mozilla/5.0 (Windows NT 6.1; Trident/7.0; rv:11.0) like Gecko
      8 Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 6.1; Trident/7.0; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.5.30729; .NET CLR 3.0.30729; Media Center PC 6.0; .NET4.0C; .NET4.0E)
      7 Mozilla/4.08 (Charon; Inferno)
      3 Mozilla/5.0 (Windows NT 6.3; Trident/7.0; rv:11.0) like Gecko/20100101 Firefox/12.0
      2 AutoIt
      1 Microsoft NCSI
      1 -
```

| Count | User-Agent | Reading |
|---|---|---|
| 15 | IE 11, `Windows NT 6.1` | The user's real browser on **Windows 7** |
| 1 | `Microsoft NCSI` | Windows' "am I online?" check, sent only by Windows |
| 8 | `MSIE 7.0 … .NET CLR …` | IE 7 on a 2017 Windows 7 host is not plausible: a string hard-coded in a program |
| 7 | `Mozilla/4.08 (Charon; Inferno)` | Not a browser. A hard-coded string widely associated with **LokiBot** |
| 3 | `NT 6.3 … like Gecko/20100101 Firefox/12.0` | A malformed mix of IE and Firefox. It only went to an ad network ([step 4](#http-timeline)), so it is probably an ad script, not malware |
| 2 | `AutoIt` | The default User-Agent of **AutoIt**, a Windows automation language often used to build malware |
| 1 | `-` | A request with **no** User-Agent: not a browser |

!!! warning "User-Agents need context"
    The malformed Firefox string looked malicious on its own. The destinations show it was advertising traffic. Always read a User-Agent **together with where it went and when**.

### TTL and DHCP vendor class (tshark) { #ttl-vendor }

Zeek records neither the IP TTL nor the DHCP vendor class. tshark reads both directly:

```bash
tshark -r ../Phase1_PCAP_7.pcap -Y "ip.src==10.192.1.157" -T fields -e ip.ttl | sort | uniq -c
tshark -r ../Phase1_PCAP_7.pcap -Y "dhcp.option.vendor_class_id" \
       -T fields -e eth.src -e dhcp.option.vendor_class_id | sort -u
```

```text
     10 1
   6809 128

50:46:5d:d5:24:3b    MSFT 5.0
```

| Evidence | Meaning |
|---|---|
| TTL **128** on 6,809 packets | Windows' default initial TTL (Linux/macOS/Android use 64, network devices 255). Captured on the LAN, so the value is unchanged |
| TTL **1** on 10 packets | Link-local multicast such as LLMNR (224.0.0.252) or IGMP. TTL 1 keeps them inside the LAN; this says nothing about the OS |
| `MSFT 5.0` | The DHCP vendor class sent by every Windows version since 2000 |

??? note "Which packets have TTL 1?"
    ```bash
    tshark -r ../Phase1_PCAP_7.pcap -Y "ip.src==10.192.1.157 && ip.ttl==1" \
           -T fields -e ip.dst -e _ws.col.Protocol | sort | uniq -c
    ```
    `_ws.col.Protocol` is Wireshark's *Protocol* column.

**Answer 4: Windows 7.** The browser User-Agent (`NT 6.1`), the DHCP vendor class (`MSFT 5.0`) and TTL 128 all agree, and NCSI plus the `WIN-` hostname fit as well. The lack of `WOW64`/`Win64` in the IE string suggests 32-bit Windows 7 (inferred).

---

## Step 4 — The HTTP timeline (Q5, Q6, Q10) { #http-timeline }

```bash
zeek-cut -u ts id.resp_h host method uri status_code resp_mime_types user_agent < http.log
```

Condensed (dates trimmed, UTC):

```text
23:58:11  63.146.14.19     www.msftncsi.com       GET  /ncsi.txt                                    200  text/plain    Microsoft NCSI
23:58:41  131.253.33.200   www.bing.com           GET  /favicon.ico                                 200  image/png     IE 11
23:58:49  13.107.13.80     api.bing.com           GET  /qsml.aspx?query=m&...                       -    -             IE 11
23:58:49  13.107.13.80     api.bing.com           GET  /qsml.aspx?query=ma&...                      -    -             IE 11
   ...    (query=mai, mail, mail., mail.y, mail.ya ... one request per keystroke)
23:58:51  13.107.13.80     api.bing.com           GET  /qsml.aspx?query=mail.yahoo.com&...          200  application/xml  IE 11
23:58:56  162.208.20.184   geo-um.btrll.com       GET  /v1/map/68e4318f0f7098c3/...             302  -             NT 6.3 ... Firefox/12.0
23:58:56  52.84.14.115     cache.btrll.com        GET  /default/Pix-1x1.gif                         200  image/gif     NT 6.3 ... Firefox/12.0
23:59:35  170.231.127.136  lucrecianos.com.ar     GET  /imagen/1/2/jjjj.exe                         200  application/x-dosexec  -
00:13:28  104.31.92.140    virtualsmsonline.site  GET  /zugu.exe                                    200  application/x-dosexec  AutoIt
00:13:38  104.20.17.242    icanhazip.com          GET  /                                            200  text/plain    AutoIt
00:13:59  185.118.166.155  tcoolonline.mobi       POST /wp-admin/css/colors/blue/Panel/five/fre.php 404  text/plain    Mozilla/4.08 (Charon; Inferno)
00:14:04  37.48.82.212     www.harddomainname.biz GET  /wordpress/wp-admin/css/colors/blue/panel/config.jpg 200 image/jpeg MSIE 7.0 ...
00:14:06  5.255.255.55     yandex.ru              GET  /                                            302  -             MSIE 7.0 ...
00:14:07  37.48.82.212     www.harddomainname.biz POST /wordpress/wp-admin/css/colors/blue/panel/gate.php 200 -     MSIE 7.0 ...
00:15:01  ... tcoolonline.mobi POST .../fre.php (404, Charon; Inferno)
00:15:07  ... harddomainname.biz GET .../config.jpg (304), 00:15:08 POST .../gate.php (200)
00:16:08  ... harddomainname.biz GET .../config.jpg (304), POST .../gate.php (200)
00:16:29–31  ... tcoolonline.mobi POST .../fre.php x3 (404)
```

| Time | What happened | Why it matters |
|---|---|---|
| 23:58:49–51 | `api.bing.com/qsml.aspx?query=m`, `ma`, `mai`, … `mail.yahoo.com` | IE's address bar sends Bing autosuggest on **each keystroke**: the user **typed mail.yahoo.com**. Yahoo Mail itself is HTTPS, so the mail is not visible |
| 23:58:56 | `btrll.com` 302 + 1×1 GIF | Advertising pixels on the Yahoo page (BrightRoll, a Yahoo ad network) |
| **23:59:35** | **`jjjj.exe`** from `lucrecianos.com.ar`, **no User-Agent** | First executable, requested by something that is **not** a browser |
| *14-minute gap* | Only benign HTTPS (see [step 6](#ssl)) | First stage waiting or working quietly (inferred) |
| **00:13:28** | **`zugu.exe`** from `virtualsmsonline.site`, User-Agent **AutoIt** | Second executable, downloaded by an **AutoIt-based program** |
| 00:13:38 | `icanhazip.com` (AutoIt) | Public IP check |
| 00:13:59 → | POST `…/Panel/five/fre.php`, `Charon; Inferno`, about every minute | C2 #1. `fre.php` + this User-Agent is the classic **LokiBot** pattern; LokiBot panels often answer 404 on purpose |
| 00:14:04 → | GET `…/panel/config.jpg`, POST `…/panel/gate.php`, MSIE 7 UA, every ~60 s | C2 #2, a separate bot/stealer panel (family not determined) |
| 00:14:06 | `yandex.ru` (MSIE 7 UA) | Connectivity check by the same program |

=== "tshark alternative"

    ```bash
    tshark -r ../Phase1_PCAP_7.pcap -Y "http.request" -T fields \
           -e frame.time_utc -e ip.dst -e http.host -e http.request.method -e http.request.uri -e http.user_agent
    ```

    Requests only, without the response type. Zeek's single line per request/response is easier here; use tshark when long Zeek lines are hard to read.

---

## Step 5 — The downloaded files (Q5–Q8) and why there are no hashes { #files }

```bash
zeek-cut -u ts tx_hosts rx_hosts source mime_type filename seen_bytes fuid < files.log \
  | grep -v -i -E "x509|pkix"
```

`grep -v` hides lines that match: every HTTPS session puts its certificates in `files.log`, and they are not downloads. Two lines are executables:

```text
2017-11-20T23:59:36+0000  170.231.127.136  10.192.1.157  HTTP  application/x-dosexec  -  2870222  FwavXQ2AM4W84BhH44
2017-11-21T00:13:29+0000  104.31.92.140    10.192.1.157  HTTP  application/x-dosexec  -  5812128  FuT2N64AuTHxEdqVil
```

The rest are small web objects and the C2 exchanges. When `tx_hosts` is the infected PC, the "file" is a POST body the PC **sent**: 204 and 177 bytes to 185.118.166.155, 345 bytes to 37.48.82.212. One stands out: `config.jpg`, **81,393 bytes** of `image/jpeg` from the C2 panel path. It may hide configuration or data inside an image (inferred).

### PE header details { #pe }

```bash
zeek-cut -u ts id machine os compile_ts is_exe is_64bit < pe.log
```

```text
2017-11-20T23:59:36+0000  FwavXQ2AM4W84BhH44  I386  Windows 95 or NT 4.0          2017-11-20T15:10:13+0000  T  F
2017-11-21T00:13:29+0000  FuT2N64AuTHxEdqVil  I386  Windows Vista or Server 2008  2017-07-31T15:19:47+0000  T  F
```

- Both are **32-bit (`I386`) EXEs** (`is_exe T`, `is_64bit F`).
- `os` is the *minimum* Windows version the file declares, not the victim's OS.
- `jjjj.exe` was **compiled about 9 hours before it was downloaded**, a freshly built sample. Compile times can be faked, so treat this as supporting detail.

### Why MD5 and SHA1 are empty: capture loss { #capture-loss }

```bash
zeek-cut fuid mime_type md5 sha1 < files.log | grep dosexec
zeek-cut < files.log | grep dosexec        # all columns
```

```text
FwavXQ2AM4W84BhH44   application/x-dosexec   -   -
FuT2N64AuTHxEdqVil   application/x-dosexec   -   -
```

The full line for `jjjj.exe`, read against the Zeek 4 `files.log` column order:

| Field | Value | Meaning |
|---|---|---|
| `conn_uids` | `CJ9NTy1RmcRnZRVcma` | The connection that carried the file |
| `analyzers` | `EXTRACT,MD5,SHA1,PE` | Hashing **was attempted** |
| `seen_bytes` | 2,870,222 | Bytes present in the capture |
| `total_bytes` | **3,061,200** | Real size announced by the server (`Content-Length`) |
| `missing_bytes` | **190,978** | Bytes the capture never saw |
| `md5` / `sha1` | `-` | Not calculated |

`zugu.exe`: total **5,895,226**, seen 5,812,128, missing **83,098**.

A hash covers every byte, and one missing byte changes it completely. Zeek therefore **refuses to produce a wrong hash**. For the same reason, `sha256sum` on the extracted file, or on a tshark export, is **not** the real file's hash and must not be reported as one.

!!! danger "Report `total_bytes`, not `seen_bytes`"
    The file size is the **declared** size: 3,061,200 and 5,895,226 bytes. `seen_bytes` is only what the capture contained. This walkthrough first answered Q5 with `seen_bytes` and corrected it after checking `missing_bytes`.

Confirm the loss:

```bash
zeek-cut -u ts peer gaps acks percent_lost < capture_loss.log
zeek-cut uid id.resp_h missed_bytes history < conn.log | grep -E "CJ9NTy1RmcRnZRVcma|CtsW3u4avJGUQUma66"
zeek-cut fuid seen_bytes total_bytes missing_bytes < files.log | grep -E "FwavXQ2AM4W84BhH44|FuT2N64AuTHxEdqVil"
```

- `percent_lost` above 0 means the sensor missed packets.
- `missed_bytes` in `conn.log` should roughly match `missing_bytes`.
- In `history`, a `g`/`G` marks a content gap.

=== "tshark alternative"

    ```bash
    tshark -r ../Phase1_PCAP_7.pcap -Y "tcp.analysis.lost_segment || tcp.analysis.ack_lost_segment" | wc -l
    mkdir objs && tshark -r ../Phase1_PCAP_7.pcap -q --export-objects http,objs && ls -l objs/*.exe
    ```

    The first line counts packets where Wireshark noticed a missing TCP segment. The export saves files **under their URL names** (`jjjj.exe`, `zugu.exe`), which is handy. With capture loss they are incomplete, though, so do not hash them for the report.

### Q7 — internal or external? { #direction }

```bash
zeek-cut -u ts tx_hosts rx_hosts mime_type seen_bytes < files.log | grep dosexec
zeek-cut -u ts query answers < dns.log | grep -E "lucrecianos|virtualsmsonline"
```

`tx_hosts` (sender) is 170.231.127.136 and 104.31.92.140. Both are public addresses outside 10/8, 172.16/12 and 192.168/16, reached by internet domain names. `rx_hosts` is the victim, so the direction is **external → internal**. The stand-alone PC has no internal servers, and it was the only internal host starting connections.

---

## Step 6 — Zeek notices and HTTPS destinations { #ssl }

```bash
zeek-cut -u ts note msg src dst < notice.log
zeek-cut -u ts id.resp_h server_name < ssl.log | awk -F'\t' '$1 >= "2017-11-20T23:59:30+0000"'
```

**notice.log**: eleven `SSL::Invalid_Server_Cert … unable to get local issuer certificate` notices, mostly for large cloud and CDN providers such as Google (172.217.x) and Amazon (52.x, 34.x). That is **noise**: Zeek could not complete the chain for an old capture. **The last one is different**:

```text
2017-11-21T00:13:39+0000  SSL::Invalid_Server_Cert  SSL certificate validation failed with (certificate has expired)  10.192.1.157  5.189.170.24
```

**ssl.log** (`server_name` is the SNI, the hostname the client sends in clear text even though the content is encrypted):

| Time | Server | Reading |
|---|---|---|
| 23:59:41 | `ieonline.microsoft.com` | IE housekeeping, benign |
| 00:08:34 | `update.googleapis.com` | Google updater, benign |
| **00:13:39 – 00:16:08** | **`idea.bsit.pk`** (5.189.170.24), in bursts every 30–50 s | **Expired certificate**, starts right after `zugu.exe` → **HTTPS C2 #3** (inferred) |
| **00:14:14** | **`smtp.aol.com`** (152.163.0.69) | Outbound **mail submission** from a PC whose user uses webmail |

The 14-minute gap contains only benign HTTPS, so the first stage was waiting, or working without network traffic, until 00:13 (inferred).

### SMTP: how much was sent? { #smtp }

```bash
zeek-cut -u ts id.resp_h id.resp_p service duration orig_bytes resp_bytes < conn.log | grep 152.163.0.69
```

```text
2017-11-21T00:14:14+0000  152.163.0.69  465  ssl  2.435390  4380  5804
2017-11-21T00:14:16+0000  152.163.0.69  465  -    3.016734  0     0
2017-11-21T00:14:25+0000  152.163.0.69  465  -    -         -     -
```

- Port **465** is SMTPS (SMTP inside TLS from the start), so the content is not visible.
- `orig_bytes` 4,380 is what the PC **sent**. The TLS handshake takes 1–2 KB, which leaves a few KB of mail, enough for a list of stolen credentials.
- The user read mail in a browser, so a desktop-style SMTP session is out of place. **Probable exfiltration of stolen data** (inferred).

---

## Step 7 — Connections Zeek could not identify (Q9) { #unknown-service }

```bash
zeek-cut id.resp_h id.resp_p proto service conn_state < conn.log \
  | awk -F'\t' '$4=="-" {print $1, $2, $3, $5}' | sort | uniq -c | sort -rn | head -20
```

```text
    231 213.183.58.34 5552 tcp REJ
      6 64.94.116.170 443 tcp S0
      3 64.94.116.170 443 tcp RSTRH
      3 181.215.247.234 1031 tcp REJ
      2 64.12.88.133 465 tcp S0
      2 172.217.0.227 443 tcp OTH
      2 152.163.0.69 465 tcp S0
      1 213.183.58.34 5552 tcp S0
      1 131.253.33.200 80 tcp RSTR
      1 13.107.13.80 80 tcp RSTR
      1 10.192.1.157 49322 tcp OTH
      1 10.192.1.157 49304 tcp OTH
```

| `conn_state` | Meaning |
|---|---|
| `SF` | Normal open and close |
| `S0` | SYN sent, no reply |
| `REJ` | Rejected (the server answered with RST) |
| `RSTR` / `RSTRH` | The responder reset the connection |
| `OTH` | Zeek did not see the start (mid-stream) |

- **213.183.58.34:5552, 232 attempts, all refused.** A program retrying the same server and port again and again is malware trying to reach its C2. REJ means the port was closed, so the server was probably already down (inferred). **TCP 5552 is njRAT's default port** (weak inference from the port only).
- **181.215.247.234:1031** (REJ ×3) and **64.94.116.170:443** (S0/RST): more failed outbound attempts to unknown hosts, worth listing as indicators.
- **64.12.88.133:465**: two more failed SMTPS attempts (an AOL-range address, inferred).
- The `OTH` lines toward 10.192.1.157 are fragments of connections whose start was not captured. They are not inbound attacks.
- Zeek shows `service -` because these connections never carried data it could recognise.

When did the 5552 attempts start?

```bash
zeek-cut -u ts id.resp_h id.resp_p conn_state < conn.log | awk -F'\t' '$3==5552' | sed -n '1p;$p'
```

`awk -F'\t' '$3==5552'` keeps rows whose third column (destination port) is 5552; `sed -n '1p;$p'` prints the first and the last.

---

## Step 8 — What started the downloads? (Q10) { #download-tool }

| Evidence | Status |
|---|---|
| `jjjj.exe` was requested with **no User-Agent**. Browsers always send one, so a script or program fetched it. PowerShell's `Net.WebClient`, for example, sends none by default | Confirmed (no UA); tool inferred |
| `zugu.exe` and the `icanhazip.com` check carry the User-Agent **`AutoIt`** | Confirmed |
| The user opened **Yahoo Mail** about 45 seconds before the first download | Confirmed |
| `strings` on `jjjj.exe` found **no** `AutoIt` / `AU3!` markers | Not confirmed: the file may be packed, incomplete (capture loss), or may have dropped the AutoIt component |

```bash
strings -n 6 extract_files/*FwavXQ2AM4W84BhH44 | grep -i -E "autoit|AU3!" | sort | uniq -c | head
```

Conclusion: **the browser did not download the executables.** A non-browser program fetched the first one, and an **AutoIt-based program** fetched the second. A malicious email opened in Yahoo Mail is the likely starting point, but the mail is encrypted (HTTPS), so it cannot be confirmed from this capture.

---

## Timeline { #timeline }

| UTC | Event | Source |
|---|---|---|
| 2017-11-20 23:58:00 | Capture starts; DHCP for WIN-D5243B (10.192.1.157) | dhcp.log |
| 23:58:11 | Windows NCSI check | http.log |
| 23:58:49–51 | User types `mail.yahoo.com` in IE (Bing autosuggest) | http.log |
| 23:58:56 | Yahoo page ad pixels (btrll.com) | http.log |
| **23:59:35** | `jjjj.exe` downloaded from lucrecianos.com.ar, no User-Agent | http.log, files.log, pe.log |
| 23:59:41 – 00:08:34 | Only benign HTTPS (Microsoft, Google) | ssl.log |
| **00:13:28** | `zugu.exe` downloaded from virtualsmsonline.site, User-Agent AutoIt | http.log, files.log, pe.log |
| 00:13:38 | Public IP check, icanhazip.com | http.log |
| 00:13:39 → | HTTPS to idea.bsit.pk (expired certificate), in bursts | ssl.log, notice.log |
| 00:13:59 → | POST `fre.php` to tcoolonline.mobi (`Charon; Inferno`), about every minute | http.log |
| 00:14:04 → | `config.jpg` / `gate.php` on harddomainname.biz (MSIE 7 UA), every ~60 s | http.log |
| 00:14:14 | SMTPS to smtp.aol.com, ~4.4 KB sent | conn.log, ssl.log |
| during capture | 232 refused connections to 213.183.58.34:5552 | conn.log |
| 00:16:33 | Capture ends | conn.log |

## Indicators of compromise { #iocs }

| Type | Indicator | Role |
|---|---|---|
| URL | `hxxp://lucrecianos[.]com[.]ar/imagen/1/2/jjjj.exe` | First EXE (3,061,200 bytes, compiled 2017-11-20 15:10:13 UTC) |
| IP | `170.231.127[.]136` | lucrecianos.com.ar |
| URL | `hxxp://virtualsmsonline[.]site/zugu.exe` | Second EXE (5,895,226 bytes) |
| IP | `104.31.92[.]140` | virtualsmsonline.site |
| URL | `hxxp://tcoolonline[.]mobi/wp-admin/css/colors/blue/Panel/five/fre.php` | C2 #1 (LokiBot-style) |
| IP | `185.118.166[.]155` | tcoolonline.mobi |
| URL | `hxxp://www.harddomainname[.]biz/wordpress/wp-admin/css/colors/blue/panel/gate.php`, `…/config.jpg` | C2 #2 |
| IP | `37.48.82[.]212` | harddomainname.biz |
| Domain / IP | `idea.bsit[.]pk` / `5.189.170[.]24` | HTTPS C2 #3, expired certificate |
| IP:port | `213.183.58[.]34:5552` | Failed C2 (possible njRAT) |
| IP:port | `181.215.247[.]234:1031`, `64.94.116[.]170:443` | Failed outbound attempts |
| Host | `smtp.aol[.]com` (`152.163.0[.]69:465`), `64.12.88[.]133:465` | SMTPS, probable exfiltration |
| User-Agent | `AutoIt` · `Mozilla/4.08 (Charon; Inferno)` · `Mozilla/4.0 (compatible; MSIE 7.0; …)` | Malware programs |
| Hashes | Not available | Capture loss (`missing_bytes` > 0) |

## ATT&CK mapping { #attack }

| Technique | Evidence |
|---|---|
| T1566 Phishing | Downloads began right after Yahoo Mail was opened (inferred) |
| T1105 Ingress Tool Transfer | `jjjj.exe`, `zugu.exe` |
| T1059.010 Command and Scripting Interpreter: AutoHotKey & AutoIT | `AutoIt` User-Agent |
| T1016.001 Internet Connection Discovery | `icanhazip.com`, `yandex.ru` checks |
| T1071.001 Application Layer Protocol: Web Protocols | `fre.php`, `gate.php`, HTTPS C2 |
| T1571 Non-Standard Port | TCP 5552, 1031 |
| T1048.002 Exfiltration Over Asymmetric Encrypted Non-C2 Protocol | SMTPS to AOL (inferred) |

## Report (Q11) { #report }

> On 2017-11-20 at 23:59 UTC, the Windows 7 host WIN-D5243B (10.192.1.157) downloaded jjjj.exe from lucrecianos.com.ar, shortly after the user opened Yahoo Mail. At 00:13, an AutoIt-based program downloaded a second EXE, zugu.exe. The host then checked its public IP and contacted several C2 servers. One pattern matches LokiBot (not confirmed). It sent about 4 KB over encrypted SMTP to AOL, likely stolen data. It also kept trying a possible njRAT server on port 5552. The host should be isolated and rebuilt, and all saved passwords changed.

## Detection ideas { #detection }

=== "Zeek"

    ```bash
    # Non-browser User-Agents that fetch executables
    zeek-cut -u ts id.orig_h host uri user_agent resp_mime_types < http.log | grep dosexec
    # Known-bad / impossible User-Agents
    zeek-cut id.orig_h host user_agent < http.log | grep -E "AutoIt|Charon; Inferno|MSIE 7\.0" | sort | uniq -c
    # Hosts hammering one closed port (many REJ to the same destination)
    zeek-cut id.orig_h id.resp_h id.resp_p conn_state < conn.log | awk -F'\t' '$4=="REJ"' | sort | uniq -c | sort -rn | head
    # Workstations talking SMTP(S) directly
    zeek-cut -u ts id.orig_h id.resp_h id.resp_p orig_bytes < conn.log | awk -F'\t' '$4==25 || $4==465 || $4==587'
    ```

=== "Snort 2"

    ```text
    alert tcp $HOME_NET any -> $EXTERNAL_NET $HTTP_PORTS (msg:"LOCAL LokiBot-style User-Agent Charon Inferno"; flow:established,to_server; content:"Charon|3B| Inferno"; http_header; classtype:trojan-activity; sid:1000701; rev:1;)
    alert tcp $HOME_NET any -> $EXTERNAL_NET $HTTP_PORTS (msg:"LOCAL AutoIt User-Agent"; flow:established,to_server; content:"User-Agent|3A| AutoIt|0D 0A|"; http_header; classtype:policy-violation; sid:1000702; rev:1;)
    alert tcp $HOME_NET any -> $EXTERNAL_NET 5552 (msg:"LOCAL Outbound TCP 5552 (njRAT default port)"; flags:S; threshold:type both, track by_src, count 10, seconds 60; classtype:trojan-activity; sid:1000703; rev:1;)
    ```

=== "Splunk"

    ```spl
    index=zeek sourcetype=zeek:http (user_agent="AutoIt" OR user_agent="*Charon; Inferno*" OR resp_mime_types="*dosexec*")
    | table _time id.orig_h host uri user_agent resp_mime_types
    | sort _time
    ```

    Adjust index and sourcetype to your ingestion. `|3B|` and `|3A|` in the Snort rules are hex for `;` and `:`.

## Lessons learned { #lessons }

- **The log list is evidence.** No `kerberos.log` means no domain; `pe.log` means executables crossed the wire.
- **Check `missing_bytes` before hashing.** With capture loss, Zeek leaves `md5`/`sha1` empty, and hashing a carved file gives a wrong answer. Report `total_bytes` as the size and state why there is no hash.
- **Read User-Agents with their destinations.** The odd Firefox string was ad traffic; `AutoIt` and `Charon; Inferno` were malware.
- **`service -` hides the loudest signal.** 232 refused connections to one port only showed up by summarising unknown-service connections.
- **An encrypted SMTP session from a webmail user is out of place** and worth reporting as possible exfiltration, while saying the content cannot be seen.
- **tshark fills Zeek's gaps:** TTL, DHCP vendor class, protocol hierarchy, NBNS names and lost-segment counts.

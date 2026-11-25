---
title: Offline PCAP Analysis with Arkime — Beginner Guide
tags:
  - tool
  - network
  - arkime
  - pcap
  - training
---

# Offline PCAP Analysis with Arkime — Beginner Guide { #offline-pcap-guide }

!!! abstract "What this page is"
    How to answer the usual PCAP incident questions with Arkime instead of Zeek: import a capture, search it, and read the answers off the web UI. Arkime indexes the PCAP **session by session**, so you reach the same answers with **a search bar and clicks** instead of `zeek-cut | grep | awk`. Field names and `capture` options were checked against the Arkime source code (`capture/parsers/*.c`, `capture/main.c`).

The worked examples re-solve [the invoice email case](../../blueteam/investigations/pcap-lab-06-invoice-macro-c2.md) and [the webmail AutoIt case](../../blueteam/investigations/pcap-lab-07-autoit-downloader-multi-c2.md), which were first solved with Zeek.

## Arkime vs Zeek for one PCAP { #vs-zeek }

| | Zeek | Arkime |
|---|---|---|
| Output | Text logs per protocol (`conn.log`, `http.log` …) | Session index + original packets, web UI |
| How you search | `zeek-cut`, `grep`, `awk` | Search expression + clicks |
| Unit | Differs per log (connection, request, file) | One connection = one session, with its HTTP/DNS/TLS fields inside |
| Seeing packets | No (use tshark/Wireshark) | Straight from the session detail |
| Counting | <code>sort &#124; uniq -c</code> | **SPI View** lists every value of a field with its count |
| Strongest at | File extraction, hashes, exact fields, scripting | Sweeping many sessions fast, pivoting, reading raw packets |

The usual workflow: **sweep with Arkime to find the suspicious sessions**, then **export those sessions as a PCAP and finish with Zeek or tshark**.

## Step 0 — Import the PCAP { #import }

If Arkime is already installed, preparation is just **indexing the PCAP and fixing the time range**. Paths assume the default install (`/opt/arkime`).

### 1. Check the services { #services }

```bash
systemctl status arkimeviewer arkimecapture --no-pager   # web UI (viewer) and capture
curl -s http://localhost:9200/_cluster/health?pretty     # index store (OpenSearch/Elasticsearch)
```

- `arkimeviewer` is the web UI: browse to `http://<analysis-server>:8005` and log in.
- A cluster `status` of `green` or `yellow` is healthy. Single-node labs are usually `yellow`.
- Service names and the port can differ in your lab build.

### 2. Index the PCAP { #capture }

```bash
sudo /opt/arkime/bin/capture -c /opt/arkime/etc/config.ini \
     -r ~/Investigation_7/Phase1_PCAP_7.pcap -t lab7 --copy
```

| Option | Meaning |
|---|---|
| `-c` | Config file. The default is `/opt/arkime/etc/config.ini`, so it can usually be omitted |
| `-r <file>` | Read an offline PCAP file |
| `-R <dir>` | Read every `*.pcap` in a directory |
| `-t <tag>` | Tag every session from this PCAP. Later, `tags == lab7` shows only this lab |
| `--copy` | **Copy** the PCAP into Arkime's `pcapDir`. Without it Arkime remembers the original path, so moving or deleting the original breaks packet viewing |
| `-n <node>` | Node name. It must **match the viewer's** for packets to open (defaults to the hostname, so usually omitted) |
| `--flush` | Flush sessions between files when reading several |
| `--dryrun` | Test run: nothing is written |

Wait about a minute and refresh. When the PCAP name appears on the **Files** page, indexing is done.

### 3. The classic trap: the time range { #time-range }

Arkime indexes sessions at their **original packet time**. The lab PCAPs are from 2017–2018, so the default view ("last hour") shows **no sessions at all**.

1. Next to the search bar, set the time range to **All**, or type the capture's start and end.
2. Enter `tags == lab7` and press Search.
3. Sessions appear: you are ready.

The UI may show times in the browser's local zone. Reports use UTC, so set the time zone to **UTC** in Settings.

## The screens and the search language { #ui }

Five screens do the work. They share one search bar and time range, so a filter set on one carries over to the others.

| Screen | What it shows | Zeek equivalent |
|---|---|---|
| **Sessions** | Session list (time, src/dst IP and port, packets, bytes, info). The `+` in front of a row opens the **session detail** | `conn.log` + the protocol log |
| **SPI View** | Every **value and count** of a field (e.g. sessions per User-Agent) | <code>zeek-cut &lt;field&gt; &#124; sort &#124; uniq -c</code> |
| **SPI Graph** | Each value of one field **over time** | Beacon interval calculation |
| **Connections** | A graph of source → destination | Internal ↔ external relationships |
| **Help → Fields** | **Every field name** available in your version | The `#fields` header of a log |

### Reading a session detail { #session-detail }

- The top part lists protocol fields (for HTTP: Host, URI, User-Agent, status code, body MD5).
- The bottom part shows the **actual packet payload**, request and response in different colours, like Wireshark's Follow Stream.
- Click a field value → **and** / **and not** adds it to the search bar. You rarely need to type expressions by hand.

### Search basics { #search-basics }

Expressions read `field operator value`:

```text
ip.src == 10.192.1.157                       # equals
port.dst != 443                              # not equal
ip.src == 10.0.0.0/8                         # CIDR range
host.http == *.yahoo.com                     # * = wildcard
http.user-agent == "Mozilla/4.08 (Charon; Inferno)"   # quote values with spaces or brackets
port.dst == [465,587,25]                     # [ ] = any of a list
http.uri == /forum\.php/                     # / / = regular expression
ip.src == 10.192.1.157 && protocols == http  # && = and
protocols == dns || protocols == dhcp        # || = or
!(port.dst == 443)                           # ! = not
```

- Group mixed conditions with parentheses: `tags == lab7 && (port.dst == 80 || port.dst == 443)`.
- Type a few letters of a field name and the search bar **autocompletes** it.
- Prefix every search with `tags == lab7 &&` when several labs share one Arkime. The examples below leave it out for brevity.

## How to answer each question { #by-question }

Each item is **search → screen → how to read it**.

### 1. Find the candidate host { #infected-host }

```text
ip.src == 10.0.0.0/8 || ip.src == 172.16.0.0/12 || ip.src == 192.168.0.0/16
```

Open **SPI View → General → Src IP**. Sessions per internal IP appear; the internal IP that started the most connections is the first candidate. (Zeek: `zeek-cut id.orig_h < conn.log | sort | uniq -c`)

### 2. IP, MAC and hostname (DHCP) { #dhcp }

```text
protocols == dhcp
```

- **SPI View → DHCP**: `dhcp.host` (hostname), `dhcp.mac` (client MAC), `dhcp.classId` (vendor class).
- Open one session to see IP, MAC and name together.
- To cross-check the MAC another way: `ip.src == <infected-IP>`, then SPI View `mac.src`.

### 3. User account, domain and DC (Kerberos) { #kerberos }

```text
protocols == krb5
```

| Field | What it shows |
|---|---|
| `krb5.cname` | Account name. Ends in `$` = computer account; no `$` = a person |
| `krb5.realm` | The AD domain |
| `krb5.sname` | Requested service. The `<name>` in `ldap/<name>` or `cifs/<name>` is the DC |
| `ip.dst` | The server answering Kerberos = the DC's IP |

DNS confirms the DC name too: `host.dns == _ldap._tcp.dc._msdcs.*`. **No Kerberos sessions at all** usually means a stand-alone PC outside a domain (Lab 07).

### 4. Operating system { #os }

| Clue | Search / field | Reading |
|---|---|---|
| User-Agent | `ip.src == <infected-IP> && protocols == http` → SPI View `http.user-agent` | `Windows NT 6.1` = Windows 7, `NT 10.0` = Windows 10/11 |
| DHCP vendor class | `dhcp.classId` | `MSFT 5.0` = Windows |
| TTL | `ip.src == <infected-IP>` → SPI View `ttl.src` | 128 = Windows, 64 = Linux/macOS/Android |

With Zeek, TTL and the vendor class needed tshark. Arkime indexes both.

### 5. Downloaded files, URLs and sizes { #downloads }

```text
http.bodymagic == application/x-dosexec       # EXE/DLL
http.bodymagic == application/msword          # legacy .doc
http.bodymagic == *zip*                       # zip, and docx/xlsx (zip inside)
```

- `http.bodymagic` is the file type detected from the body's **content** (magic bytes), the same role as Zeek's `mime_type`.
- Full URL = `host.http` + `http.uri` in the session detail.
- **Size**: read `Content-Length` in the response headers in the packet area of the session detail. The session's byte count (`databytes.dst`) includes headers, so it differs slightly from the file size.

### 6. Hashes { #hashes }

- The HTTP section of the session detail shows the body hash `http.md5`. `http.sha256` only exists if `supportSha256=true` is set in the config.
- Reverse lookup: `http.md5 == <md5>` finds every session that received the same file.
- **Caution:** when the capture lost packets, this hash is not the real file's hash. See [limits and traps](#limits) for cases like Lab 07.

### 7. Browser or program? { #user-agent }

```text
ip.src == <infected-IP> && protocols == http
```

Look at **SPI View → HTTP**, field `http.user-agent`, for values and counts. Click a value and choose **and** to see in Sessions where that User-Agent went. Values such as `AutoIt`, `Charon; Inferno` or an ancient IE 7 are not browsers. Requests with no User-Agent at all show up in the request headers of the packet area.

### 8. Public IP { #public-ip }

```text
host.http == [api.ipify.org, icanhazip.com, checkip.amazonaws.com, ipinfo.io]
```

Open the session detail and read the **response body** in the packet area. The IP in the body is the host's public IP. There is no need to look up a file ID as with Zeek.

### 9. C2 and beaconing { #c2 }

```text
ip.src == <infected-IP> && http.method == POST
```

1. **SPI View → `host.http`**: which servers received POSTs, and how many.
2. **Sessions** sorted by start time: is the same server hit at a steady interval?
3. **SPI Graph** with field `host.http`: each server's connections drawn as bars over time. Evenly spaced bars are a beacon.

### 10. HTTPS destinations and certificates { #tls }

```text
ip.src == <infected-IP> && protocols == tls
```

- The HTTPS server name (SNI) is stored in the `host.http` field as well, so SPI View `host.http` lists the HTTPS sites visited.
- In the certificate part of the session detail, check `cert.issuer.cn` (issuer), `cert.subject.cn` and `cert.notafter` (expiry). An expiry earlier than the capture time means an **expired certificate**.
- `tls.ja3` is the TLS client fingerprint. The same value across several suspicious servers suggests the same program.

### 11. Failed connections (Zeek's S0, REJ) { #failed }

```text
ip.src == <infected-IP> && tcpflags.syn-ack == 0       # handshake never completed
ip.src == <infected-IP> && tcpflags.rst > 0            # connection reset (includes rejects)
```

SPI View `ip.dst` and `port.dst` then show how many times each destination failed. Arkime has no single `conn_state` column like Zeek, so TCP flags stand in for it.

### 12. Mail (SMTP) { #smtp }

```text
ip.src == <infected-IP> && port.dst == [25,465,587]
```

- **Plain SMTP on 25/587** exposes `email.src` (sender), `email.dst` (recipient), `email.subject` and `email.fn` (attachment names).
- **465 is TLS from the start**, so content is hidden. The amount sent is `databytes.src` in the session list.

## Worked examples: Lab 06 and Lab 07 in Arkime { #worked }

"Expected" values are the answers found with Zeek. Arkime should show the same; if it does not, check the time range (All) and the tag first. Prefix every search with `tags == lab6 &&` (or `lab7`).

### Lab 06 — invoice Word macro { #lab-06 }

Import: `sudo /opt/arkime/bin/capture -r ~/Investigation_6/Phase1_PCAP_6.pcap -t lab6 --copy`

| # | Search | Where to look | Expected |
|---|---|---|---|
| 1 | `ip.src == 172.16.0.0/12` | SPI View `ip.src` | One internal host, 172.16.1.125 |
| 2 | `protocols == dhcp` | SPI View `dhcp.host`, `dhcp.mac` | Anatoliy-PC, b8:97:fa:74:de:c0 |
| 3 | `protocols == krb5` | SPI View `krb5.cname`, `krb5.realm`, `krb5.sname`, `ip.dst` | anatoliy.demchuk, MARICHEIKA.NET, DC 172.16.1.3 (Maricheika-DC) |
| 4 | `http.bodymagic == application/msword` | Session detail | 2018-10-01 18:38:00 UTC, `pitchbocaraton.com/?82a1=APYBKsCs3LUw`, IE 11 User-Agent, `http.md5` = 41a3101af94fca79bbdb0db2a52994c0 |
| 5 | `host.http == api.ipify.org` | Session detail → response body | 31.44.188.95 |
| 6 | `http.method == POST` | SPI View `host.http`, SPI Graph | `/4/forum.php` on perranrowsin.com about every 2 minutes, plus `/mlu/forum.php` and `/d2/about.php` |
| 7 | `ip.src == 172.16.1.125 && protocols == http` | SPI View `http.user-agent` | Document via `WOW64` IE; C2 via `Win64; x64` and `MSIE 7.0` → different programs |

Two answers need more than Arkime:

- **The macro (Q7)**: export the document and inspect it with `strings` or `olevba`.
- **Subnet mask and gateway (Q9)**: not among Arkime's DHCP fields. One tshark line (`-e dhcp.option.subnet_mask -e dhcp.option.router`) is the easiest.

### Lab 07 — AutoIt downloader and multiple C2 { #lab-07 }

Import: `sudo /opt/arkime/bin/capture -r ~/Investigation_7/Phase1_PCAP_7.pcap -t lab7 --copy`

| # | Search | Where to look | Expected |
|---|---|---|---|
| 1 | `ip.src == 10.0.0.0/8` | SPI View `ip.src` | One internal host, 10.192.1.157 |
| 2 | `protocols == dhcp` | SPI View `dhcp.host`, `dhcp.mac`, `dhcp.classId` | WIN-D5243B, 50:46:5d:d5:24:3b, `MSFT 5.0` |
| 3 | `protocols == krb5` | Sessions | **None** → a stand-alone PC, no domain |
| 4 | `ip.src == 10.192.1.157` | SPI View `ttl.src`, `http.user-agent` | TTL 128, `Windows NT 6.1` → Windows 7 |
| 5 | `host.http == api.bing.com` | Sessions → `http.uri` | `query=m`, `ma` … `mail.yahoo.com`: the user typed the Yahoo Mail address |
| 6 | `http.bodymagic == application/x-dosexec` | Session detail | `jjjj.exe` (lucrecianos.com.ar, no User-Agent), `zugu.exe` (virtualsmsonline.site, `AutoIt`); response `Content-Length` 3,061,200 / 5,895,226 |
| 7 | `host.http == icanhazip.com` | Response body | Public IP check (User-Agent `AutoIt`) |
| 8 | `http.method == POST` | SPI View `host.http`, `http.user-agent` | tcoolonline.mobi (`Charon; Inferno`), harddomainname.biz (`MSIE 7.0`) |
| 9 | `protocols == tls` | SPI View `host.http`, certificate in session detail | idea.bsit.pk, `cert.notafter` earlier than the capture (expired) |
| 10 | `tcpflags.syn-ack == 0` | SPI View `ip.dst`, `port.dst` | Hundreds of failures to 213.183.58.34:5552 |
| 11 | `port.dst == 465` | Sessions `databytes.src` | A few KB to smtp.aol.com (152.163.0.69), content encrypted |

Even if Arkime shows an `http.md5` in row 6, **do not report it as the file hash**. Both files are missing bytes in this capture, so a hash of the bytes seen differs from the real file's hash (inferred: Arkime does not flag the gaps).

## Limits, traps, and handing off to Zeek/tshark { #limits }

Arkime is best at **finding**. Carving files and measuring precisely are better done with Zeek or tshark, and the bridge between them is **exporting the filtered sessions as a PCAP**.

### What Arkime alone cannot do well { #cannot }

| Task | In Arkime | Instead |
|---|---|---|
| Carve files, read macros | The body is visible in the packet area, but this is not an analysis tool | Export PCAP → Zeek `extract-all-files` or `tshark --export-objects` → `strings`, `olevba` |
| Check capture loss | Missing bytes are not flagged | Zeek `files.log` `missing_bytes`, tshark `tcp.analysis.lost_segment` |
| DHCP mask and gateway | Not an indexed field | tshark `dhcp.option.subnet_mask`, `dhcp.option.router` |
| Connection state (S0, REJ) | No single column | `tcpflags.syn-ack == 0`, `tcpflags.rst > 0`, or Zeek `conn_state` |
| Exact intervals in seconds | Eyeball in SPI Graph | Zeek `ts` + `awk` subtraction |

### Export a PCAP { #export }

1. In Sessions, narrow the list with a search, e.g. `tags == lab7 && http.bodymagic == application/x-dosexec`.
2. From the **actions menu** above the session list, choose **Export PCAP**, pick the matching sessions and name the file.
3. Analyse the small PCAP as usual:

```bash
mkdir exe_check && cd exe_check
zeek -C -r ../exported.pcap local frameworks/files/extract-all-files 2>/dev/null
zeek-cut fuid mime_type seen_bytes total_bytes missing_bytes md5 sha1 < files.log
```

**Export CSV** in the same menu saves the session list (visible columns) as a table, handy for the report timeline.

### Common beginner traps { #traps }

- **No sessions at all**: the time range is still "last hour". Switch to **All**.
- **Sessions show but packets will not open**: the original PCAP was moved after importing without `--copy`, or capture and viewer use different node names (`-n`).
- **Counts are doubled**: the same PCAP was probably imported twice. Import once, or keep imports apart by tag.
- **Another lab's sessions mixed in**: prefix every search with `tags == labN &&`.
- **Times do not match the report**: the UI uses the browser's time zone. Switch to UTC in Settings.
- **A field name does not work**: names can differ between versions. Check **Help → Fields**, or use the search bar's autocomplete.

## Search cheat sheet { #cheat-sheet }

Prefix with `tags == labN &&` and replace `<infected-IP>`.

| Goal | Search | Field to look at (SPI View) |
|---|---|---|
| Internal hosts | <code>ip.src == 10.0.0.0/8 &#124;&#124; ip.src == 172.16.0.0/12 &#124;&#124; ip.src == 192.168.0.0/16</code> | `ip.src` |
| IP · MAC · hostname | `protocols == dhcp` | `dhcp.host`, `dhcp.mac`, `dhcp.classId` |
| Account · domain · DC | `protocols == krb5` | `krb5.cname`, `krb5.realm`, `krb5.sname`, `ip.dst` |
| DC name (DNS) | `host.dns == _ldap._tcp.dc._msdcs.*` | DNS answer in the session detail |
| Operating system | `ip.src == <infected-IP>` | `ttl.src`, `http.user-agent`, `dhcp.classId` |
| Executable downloads | `http.bodymagic == application/x-dosexec` | `host.http`, `http.uri`, `http.md5` |
| Word documents | `http.bodymagic == application/msword` | `host.http`, `http.uri` |
| Archives · Office 2007+ | `http.bodymagic == *zip*` | `host.http`, `http.uri` |
| Same file elsewhere | `http.md5 == <md5>` | `ip.src`, `host.http` |
| Compare User-Agents | `ip.src == <infected-IP> && protocols == http` | `http.user-agent` |
| One User-Agent | `http.user-agent == "AutoIt"` | `host.http`, `http.uri` |
| Public IP check | `host.http == [api.ipify.org, icanhazip.com, checkip.amazonaws.com]` | Response body in the session detail |
| C2 POSTs | `ip.src == <infected-IP> && http.method == POST` | `host.http`, `http.uri` + SPI Graph |
| HTTPS destinations | `ip.src == <infected-IP> && protocols == tls` | `host.http` (SNI), `tls.ja3` |
| Certificates | `protocols == tls` | `cert.issuer.cn`, `cert.subject.cn`, `cert.notafter` |
| Failed connections | `tcpflags.syn-ack == 0` | `ip.dst`, `port.dst` |
| Reset connections | `tcpflags.rst > 0` | `ip.dst`, `port.dst` |
| Outbound mail | `port.dst == [25,465,587]` | `databytes.src`; in plain text also `email.src`, `email.dst`, `email.subject`, `email.fn` |
| Unusual ports | `ip.src == <infected-IP> && !(port.dst == [53,80,443])` | `ip.dst`, `port.dst` |

!!! note "Verified vs untested"
    Field names and `capture` options were checked against the Arkime source code, including that the TLS SNI goes into `host.http`. Menu names and positions (the actions menu with Export PCAP, the All time range), service names and port 8005 were not tested on the lab's Arkime build. If anything differs, **Help → Fields** in your viewer is the reference.

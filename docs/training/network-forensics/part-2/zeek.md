---
title: "2.8 — Zeek: Network Security Monitoring, Log Structure, jq, Community ID"
tags:
  - training
  - network-forensics
  - zeek
  - logs
---

# 2.8 — Zeek: Network Security Monitoring, Log Structure, jq, Community ID { #zeek }

!!! abstract "Scope of this lesson"
    - What network security monitoring (NSM) is and how it differs from an IDS
    - Processing pcaps with Zeek: `-r`, policies, and [Caution] the trap where checksum offloading makes whole logs disappear
    - Log file types, common fields and `http.log` fields; [Correction] the password field is empty by default
    - TSV and JSON, `zeek-cut` and `jq`: filtering, projecting, converting timestamps, handling arrays, pivoting between logs with `uid`
    - jq performance: narrow first with `grep`
    - Signatures and scripts; [Changed] from JA3 to JA4
    - Community ID: a flow identifier that works across tools, computed by hand
    - Building your own Zeek policy for investigations

!!! note "Lab environment and notation"
    **(Actual output)** came from **Zeek 9.0.1** (the official Docker image `zeek/zeek`), jq 1.7 and TShark 4.2.2 in this environment. The pcap analysed is practice traffic I generated on loopback: HTTP requests to lesson 2.5's Apache practice server (`www.lab.example`, port 8080), queries to lesson 2.6's practice DNS hierarchy, and a TLS connection to lesson 2.7's practice DoH server (`127.0.0.20`). That's why HTTP source and destination both appear as `127.0.0.1`. The Basic auth account and password are **practice values**. The jq speed comparison used a **fake dns.log of 1.5 million random lines**.

## 1. Network security monitoring and Zeek { #nsm }

**Blocking** was once the top priority. Intrusion detection systems (IDS) and intrusion prevention systems (IPS) were expected to catch and stop bad behaviour. Eventually came the realisation that prevention will fail sooner or later, and then you need investigations built on **solid evidence**.

**Network security monitoring (NSM)** grew out of that realisation. It collects evidence **before** an incident is discovered, creating an environment ready to support an investigation — a "forensically ready" environment. It turns the traditional idea of a "defensible network" into "a network prepared for the investigation that will inevitably come", in parallel with IDSes and IPSes evolving to absorb NSM features. Today's NSM concepts owe much to Richard Bejtlich's books *The Tao of Network Security Monitoring* and *The Practice of Network Security Monitoring*.

As an analogy, an IDS is a **burglar alarm** and NSM a **dashcam**. An alarm sounds when a predefined thing happens and records nothing otherwise. A dashcam keeps recording whatever happens and answers "what happened back then?" later. Where it breaks: a dashcam keeps the full video, but Zeek doesn't keep packets in full; it keeps **protocol-aware summaries** (logs). They're much smaller and easier to search, but details it didn't log simply aren't there (the "full packets versus summaries" trade-off from lesson 1.10).

**Zeek** (formerly Bro) is the flagship NSM tool.

- **Different goals.** Where a traditional IDS focuses on content monitoring and alert management, Zeek's developers prioritise **traffic visibility and application-layer understanding across many protocols**. You can add signatures (section 7), but that's not its main use in an investigator's daily work.
- **Free and open source**, with commercial support from Corelight and an active user community.
- **Live and pcap processing work the same way.** Real-time monitoring that feeds a SIEM and forensic processing of existing pcaps can share **one workflow**. Teams also deploy Zeek tactically in front of a compromised system or segment to boost visibility.
- **Extensible and scalable**: standard analysers cover much of what investigations meet, scripts add functionality, and clustered deployments have handled 100 Gb/s.
- **Layer-7 session awareness**: one log line holds **both the request and its response** (as with the query and answer on one line in lesson 2.7's `dns.log`), making analysis much easier than with repurposed tools.

Many NSM platforms use Zeek alone or as part of a larger suite; Security Onion is a popular example.

## 2. Processing a pcap with Zeek { #running-zeek }

Live configuration is out of scope here, but processing an existing pcap is easy. Give the input file with `-r` and log files appear in **the directory you ran it from**.

```text
zeek -r lab.pcap                 # base scripts only
zeek -r lab.pcap local           # plus the site policy (site/local.zeek)
zeek -r lab.pcap forensic.zeek   # a policy file of your own (section 10)
```

The name at the end is **a script (policy) to load as well**. With nothing there, only the base scripts run. In this lab's official image, `local` is `/usr/local/zeek/share/zeek/site/local.zeek`.

### 2.1 [Caution] Checksum offloading: whole logs disappear { #checksum }

I ran the practice pcap with no options.

**(Actual output)**

```text
$ zeek -r lab.pcap
warning in .../base/misc/find-checksum-offloading.zeek, line 54: Your trace file likely has
invalid TCP and UDP checksums, most likely from NIC checksum offloading.  By default, packets
with invalid checksums are discarded by Zeek unless using the -C command-line option or
toggling the 'ignore_checksums' variable. ...
$ ls
conn.log  packet_filter.log  reporter.log  weird.log
```

**No** `http.log` and **no** `dns.log`. `weird.log` recorded `bad_TCP_checksum` and `bad_UDP_checksum`. Running the same pcap again with `-C`:

```text
$ zeek -C -r lab.pcap
$ ls
conn.log  dns.log  files.log  http.log  packet_filter.log  ssl.log
```

What happened? Modern operating systems **hand checksum calculation to the network card (checksum offloading)**. When you capture on the sending machine itself, packets are saved **before** the checksum is filled in, so they look wrong. This pcap was captured on loopback, and 28 of its 94 packets were like that (checked with TShark). Zeek **discards packets with bad checksums by default**, so the packets needed for application-layer analysis vanished and the HTTP and DNS logs were never created.

**What this means for investigations:** you can't expect every forensic pcap to come from a device without offloading. When processing evidence pcaps, **use `-C` (or `ignore_checksums = T`) by default**, and always check `weird.log` and `reporter.log` before concluding "there's no HTTP in this pcap". Conversely, many checksum errors on a live sensor (fed by SPAN or a TAP) may mean genuinely damaged or crafted packets, which is a clue in itself.

## 3. Log file types and formats { #log-files }

Zeek doesn't write one unified log; it writes **dozens of log files depending on the traffic observed**. If there was no SSL/TLS in a time window, `ssl.log` and `x509.log` simply don't exist for it. Added functionality can create new logs or add fields to existing ones.

| Category | Log | Contents |
| --- | --- | --- |
| Network protocols | `conn.log` | TCP/UDP/ICMP connections (similar to NetFlow, lesson 1.10) |
| | `dns.log` | DNS activity (the same content as passive DNS, lesson 2.7) |
| | `http.log` | HTTP activity |
| | `ssl.log` | TLS negotiation (server name, version, cipher) |
| | `rdp.log`, `smtp.log`, `ssh.log` | Activity for each protocol |
| File metadata | `files.log` | File analysis (hashes, MIME type, etc.). For some protocols Zeek can extract full file content |
| | `smb_files.log` | Files moved over SMB |
| | `x509.log` | Certificate information |
| | `pe.log` | Windows executables (PE) |
| Inventories built by observation | `known_hosts.log`, `known_services.log`, `software.log` | Observed systems, services and software |
| Special cases | `signatures.log` | Signature hits (section 7) |
| | `weird.log` | Unexpected protocol observations (such as the checksum errors in 2.1) |
| | `intel.log` | Intelligence framework hits |
| | `notice.log` | Potentially concerning observations (certificate validation errors, brute force, etc.) |

!!! info "[Supplement] \"Rotates logs every hour on the hour\" is about operational sensors"
    The book says Zeek archives and compresses logs **every hour on the hour** by default. That's the default for live sensors run with ZeekControl or as a cluster. When you process a pcap with `zeek -r`, as here, there's no rotation, just one file per log (printing `Log::default_rotation_interval` in Zeek 9.0.1 gave `0 secs`). When investigating logs from an operational sensor, you'll need **several hourly files** such as `conn.20:00:00-21:00:00.log.gz` to see the full picture.

### 3.1 TSV and JSON { #tsv-json }

Tab-separated values (TSV) was historically the default, and **TSV is still the default** (in Zeek 9.0.1, `LogAscii::use_json` is `F`). But the move to JSON logging reached Zeek too, and in practice you'll meet JSON logs very often.

TSV logs carry format information in a header.

**(Actual output; part of the `http.log` header)**

```text
#separator \x09
#set_separator	,
#empty_field	(empty)
#unset_field	-
#path	http
#fields	ts	uid	id.orig_h	id.orig_p	id.resp_h	id.resp_p	trans_depth	method	host	uri	referrer	...
#types	time	string	addr	port	addr	port	count	string	string	string	string	...
```

To pull columns from TSV, use **`zeek-cut`**. It selects by **name**, not column number, so it's safe across versions with different column orders. `-d` converts timestamps to a human-readable form.

**(Actual output)**

```text
$ zeek-cut -d ts uid method host uri status_code < http.log
2026-11-05T07:36:46+0000	CpYAlK2BmtOQIQBL0c	GET	www.lab.example	/	200
2026-11-05T07:36:46+0000	CpYAlK2BmtOQIQBL0c	GET	www.lab.example	/notes.txt	200
2026-11-05T07:36:46+0000	CpYAlK2BmtOQIQBL0c	GET	www.lab.example	/report.zip	200
2026-11-05T07:36:46+0000	CqNOtq2Enp8yKk3sE8	GET	www.lab.example	/admin/	401
```

For JSON, pass `LogAscii::use_json=T`. The rest of this lesson uses JSON.

```text
zeek -C -r lab.pcap local policy/protocols/conn/community-id-logging LogAscii::use_json=T
```

## 4. Reading the fields { #fields }

JSON logs are, to an extent, **self-describing**. Learning Zeek's naming takes time, but the core is simple: some fields appear in most logs, and the rest vary by log (and can be changed by configuration).

**Common fields**

| Field | Meaning |
| --- | --- |
| `ts` | When the **first packet** of the exchange was seen; Unix epoch with microseconds |
| `uid` | The connection's unique ID. A great pivot for grouping several HTTP requests in one connection (Keep-Alive) and **crossing between log files** |
| `id` | A superfield holding the connection's four endpoint values. In JSON it's flattened into `id.orig_h` (originating address), `id.orig_p` (originating port), `id.resp_h` (responding address) and `id.resp_p` (responding port) |

`orig` (originator) is the side that **started** the connection; `resp` (responder) is the side that **answered**. It's about "who connected first", not "source and destination". For connectionless traffic like UDP, Zeek infers it from the first packet and the ports.

**`http.log` fields** (one line from the practice pcap, Actual output)

```text
$ jq 'select(.uri=="/report.zip")' http.log
{
  "ts": 1793864206.74854,
  "uid": "CAU56U3BuXGG04UEil",
  "id.orig_h": "127.0.0.1",
  "id.orig_p": 33246,
  "id.resp_h": "127.0.0.1",
  "id.resp_p": 8080,
  "trans_depth": 3,
  "method": "GET",
  "host": "www.lab.example",
  "uri": "/report.zip",
  "version": "1.1",
  "user_agent": "curl/8.5.0",
  "request_body_len": 0,
  "response_body_len": 46,
  "status_code": 200,
  "status_msg": "OK",
  "tags": [],
  "resp_fuids": [ "FMxNrn1TAZX9SSFI3f" ],
  "resp_mime_types": [ "application/zip" ]
}
```

| Field | Meaning |
| --- | --- |
| `trans_depth` | Which request/response this is within the connection. This line is **3**: the third after `/` and `/notes.txt` on the same connection |
| `method`, `host`, `uri` | Request method, `Host` header, request path |
| `referrer` | The `Referer` header. Zeek's developers chose the **correct spelling** rather than the standard's typo (`Referer`) |
| `user_agent` | The `User-Agent` header |
| `request_body_len`, `response_body_len` | **Uncompressed** body sizes sent by client and server |
| `status_code`, `status_msg` | Response code and phrase |
| `info_code`, `info_msg` | Last 1xx response seen |
| `filename` | File name from the response's `Content-Disposition` header |
| `tags` | Indicators of various attributes of the request/response |
| `username`, `password` | Basic auth username and password (see [Correction] below) |
| `proxied` | Headers that may indicate the request was proxied |
| `orig_fuids`, `resp_fuids` | Unique IDs of files in the request/response; link to `files.log` |
| `orig_mime_types`, `resp_mime_types` | MIME types of those files (determined by Zeek from the content) |

I also confirmed that `user_agent` is recorded **per request** within one connection (same `uid`): the first request said `LabBrowser/1.0`, the other two `curl/8.5.0` (I changed only the first on purpose). It's a per-request record, not per-connection.

!!! warning "[Correction] The `password` field is empty by default"
    The book introduces `password` as "the password if Basic auth is provided", but Zeek **does not log passwords by default** (`HTTP::default_capture_password` defaults to `F`, checked in Zeek 9.0.1). On the same pcap:

    **(Actual output)**

    ```text
    default:                       {"uri":"/admin/","status_code":401,"username":"jdoe","password":null}
                                   {"uri":"/admin/","status_code":200,"username":"jdoe","password":null}
    HTTP::default_capture_password=T:
                                   {"uri":"/admin/","status_code":401,"username":"jdoe","password":"wrong"}
                                   {"uri":"/admin/","status_code":200,"username":"jdoe","password":"Lab-Practice-1"}
    ```

    `username` is logged by default, and, like Apache in lesson 2.5, **even on a 401 (failure)**. Turning passwords on helps investigations (which passwords were tried in a brute force?), but, like lesson 2.5's `mod_log_forensic`, it makes **the log itself a credential-leak risk**. If you must enable it, restrict retention and access tightly. It's also why an empty `password` column in operational sensor logs doesn't mean "there was no authentication".

!!! warning "[Caution] A 200 in the server log versus \"no response\" in Zeek"
    A POST to the practice CGI was logged by Apache as `"POST /cgi-bin/search.cgi HTTP/1.1" 200 0`, yet in Zeek's `http.log` its `status_code` was **empty**, `conn.log` showed `resp_bytes` **0**, and `history` was `ShADafF` (no responder data `d`). curl also reported "Empty reply from server". The cause seems to be this practice CGI's behaviour, but I didn't pin it down (hypothesis). The point: **a 200 in a server log isn't proof that a response actually went out**, and putting network-side records (Zeek) next to server-side records (access logs) reveals differences like this.

## 5. Working with JSON logs in jq { #jq }

**jq** handles JSON data in general, not just Zeek. It has a huge feature set, but a handful of common uses go a long way in investigations. Every command in this section is **actual output** from jq 1.7 on the practice logs.

### 5.1 Pretty-printing: `.` { #jq-pretty }

The simplest use is to feed JSON on standard input and **reprint it readably**. `.` means "the whole input". Section 4's output is that, with a `select` added. For compressed logs from an operational sensor, use `zcat http.20:00:00-21:00:00.log.gz | jq '.'`. Add `-c` (compact) for one record per line.

### 5.2 Filtering and projecting: `select()` and `{ }` { #jq-select }

```text
$ jq -c 'select(.host=="portal.lab.example") | {ts, uid, "id.orig_h", "id.resp_h", host, status_code}' http.log
{"ts":1793864206.769968,"uid":"CiMdK3w2miyU2zLCc","id.orig_h":"127.0.0.1","id.resp_h":"127.0.0.1","host":"portal.lab.example","status_code":null}
```

Piece by piece:

- `select(.host=="portal.lab.example")`: pass only records whose `host` equals that value.
- `|`: hand the result on (the same idea as a shell pipe).
- `{ts, uid, "id.orig_h", …}`: build a new object with just those fields. **Names containing dots, like `id.orig_h`, must be double-quoted**; unquoted, jq reads them as "`orig_h` inside `id`".

### 5.3 Converting timestamps: `|= todate` { #jq-todate }

```text
$ jq -c 'select(.uid=="CqGnde2epFh6bIDYyf") | .ts |= todate | {ts, uid, username, status_code}' http.log
{"ts":"2026-11-05T07:36:46Z","uid":"CqGnde2epFh6bIDYyf","username":"jdoe","status_code":401}
```

`.ts |= todate` means "**replace** the `ts` field with `todate` applied to its value", converting Unix time to ISO 8601 (UTC). Jumping straight to an interesting `uid` found in another log like this is a common workflow. Note that `todate` drops the fractional seconds (microseconds); keep the original value too when precise ordering matters.

### 5.4 Arrays: `.answers` and `.answers[0]` { #jq-arrays }

```text
$ jq -c 'select(.query=="cdn.example.com" and .answers!=null) | {uid, query, answers, TTLs}' dns.log
{"uid":"CYHFhr4EQi9PFrUR84","query":"cdn.example.com","answers":["edge.example.net"],"TTLs":[300.0]}
{"uid":"CCRnDa3WxlmQ8naShe","query":"cdn.example.com","answers":["edge.example.net","198.51.100.80"],"TTLs":[300.0,30.0]}
$ jq -c 'select(.query=="cdn.example.com" and .answers!=null) | .answers[0]' dns.log | head -1
"edge.example.net"
```

`answers` and `TTLs` are **arrays**, paired by position (`edge.example.net` with 300 s, `198.51.100.80` with 30 s — lesson 2.6's CNAME and A records with independent TTLs). Appending `[0]` returns just the first element.

There are two lines for the reason learned in lesson 2.6: the first is the answer the resolver got **from the authoritative server** (CNAME only), the second the answer the resolver gave **to the client** (CNAME plus A). This pcap contains all port-53 traffic on loopback. Always check `id.orig_h` to see which side a record is from.

### 5.5 Pivoting between logs: `uid` and `fuid` { #jq-pivot }

I took the file ID for `/report.zip` from `http.log` and found that file's hashes in `files.log`.

```text
$ F=$(jq -r 'select(.uri=="/report.zip") | .resp_fuids[0]' http.log); echo $F
FMxNrn1TAZX9SSFI3f
$ jq -c --arg f "$F" 'select(.fuid==$f) | {fuid, mime_type, total_bytes, md5, sha1, source, uid}' files.log
{"fuid":"FMxNrn1TAZX9SSFI3f","mime_type":"application/zip","total_bytes":46,"md5":"f4d3fed54615b950dcd351770272d341","sha1":"3d9a0375eb63d96912bf6c316f9caa6e487c40d4","source":"HTTP","uid":"CAU56U3BuXGG04UEil"}
```

- `-r`: output strings raw, without quotes; needed when storing them in a shell variable.
- `--arg f "$F"`: pass the shell variable into jq as `$f`. Safer than pasting values into the filter text (no quoting or special-character problems).

Checking the real file on the server, `md5sum` gave **the same** `f4d3fed54615b950dcd351770272d341`. The `uid` in `files.log` is the connection the file travelled on; looking it up in `conn.log` gives the whole connection's size and state.

```text
$ jq -c 'select(.uid=="CAU56U3BuXGG04UEil") | {uid, service, duration, orig_bytes, resp_bytes, conn_state, history}' conn.log
{"uid":"CAU56U3BuXGG04UEil","service":"http","duration":0.0016560554504394531,"orig_bytes":289,"resp_bytes":4842,"conn_state":"SF","history":"ShADadFf"}
```

From `http.log` to `files.log` to `conn.log`, I linked "which request → received which file (hash) → what that connection looked like". The `conn_state` (`SF` = normal close) and `history` from lesson 1.10 read just the same here.

!!! warning "[Caution] `uid` changes every time you process"
    Processing the same pcap twice, the same connection (source port 33246) had `uid` `CAU56U3BuXGG04UEil` the first time and `CjrN3e3AePQwe77tTl` the second (actual output). A `uid` is a key that links logs **only within one processing run**. When you cite a `uid` in a report, say which run it's from (date, Zeek version, policy), and to link with other tools or other runs, use the **Community ID** in section 8.

## 6. jq performance: narrow first with grep { #jq-performance }

Doing everything in jq alone can be **much slower** than combining it with other tools. That's not unique to jq; investigators should know their tools' limits and combine them with processing time in mind.

I searched a fake `dns.log` of **1.5 million random lines** (about 31 MB gzipped) for `beacon.example.org` two ways.

**(Actual output, fake data)**

```text
$ time (zcat big_dns.log.gz | jq -c 'select(.query=="beacon.example.org") | {ts,"id.orig_h"}' | wc -l)
6
real	0m7.916s

$ time (zgrep -F '"beacon.example.org"' big_dns.log.gz | jq -c '{ts,"id.orig_h"}' | wc -l)
6
real	0m1.780s
```

Same result (6 lines), and narrowing first with `zgrep` was **about 4.4 times** faster. jq has to parse every line as JSON; `grep` just compares characters. `-F` searches for a **fixed string** rather than a regular expression, so the dots needn't be escaped, and including the double quotes avoids matching longer names such as `xbeacon.example.org`.

That doesn't mean never use `select()`. `grep` **doesn't know about fields**: it also matches the same text in the `answers` column (another name's CNAME target). So "**narrow broadly with `grep`, then filter precisely with jq's `select()`**" is a good combination. Complex conditions are hard to express accurately as regular expressions over raw JSON, and jq offers a much richer, JSON-native search syntax. Choosing per situation is the investigator's call.

!!! warning "[Caution] Online jq playgrounds and OPSEC"
    A browser-based "playground" (jqplay.org) is a nice way to learn jq, showing the command line equivalent of what you did on the web. But it means **sending case data to an uncontrolled Internet site**, a significant OPSEC risk. Never paste real logs; use practice data only, or a self-hosted offline copy built from the published source. jq's own tutorial and manual are good starting points.

## 7. Zeek signatures and scripts { #signatures-scripts }

### 7.1 Signatures { #signatures }

Signature detection isn't Zeek's main purpose, but it has a **signature engine** that can be very useful in incident response.

- Match on **packet fields** such as IP addresses, protocols, ports and packet size.
- Match on **raw traffic content** and **protocol-specific fields** such as the HTTP request URI and request/response headers.
- Evaluate files that appear in `files.log` by their **magic values** (format markers in the first bytes) or advertised MIME type.

It's not as rich in content-based detection as Snort or other pure IDSes, but combined with Zeek's broader NSM functionality it's often enough to flag important traffic during an investigation. I wrote a practice signature.

```text
signature lab-python-tool-post {
  ip-proto == tcp
  http-request /.*cgi-bin\/search\.cgi/
  http-request-header /User-Agent: python-requests/
  event "Practice: scripted POST to search.cgi"
}
```

`http-request` matches a regular expression against the request URI, `http-request-header` against request headers. **All** conditions must match. I loaded it with `-s`.

**(Actual output)**

```text
$ zeek -C -r lab.pcap -s lab.sig LogAscii::use_json=T
$ jq -c . signatures.log
{"ts":1793864206.769968,"uid":"C4K6n638HpgJwWWbpf","src_addr":"127.0.0.1","src_port":33276,"dst_addr":"127.0.0.1","dst_port":8080,"note":"Signatures::Sensitive_Signature","sig_id":"lab-python-tool-post","event_msg":"127.0.0.1: Practice: scripted POST to search.cgi","sub_msg":"python-requests/2.31.0"}
```

Both `signatures.log` and `notice.log` appeared, and `sub_msg` holds the matched header value. During an incident, a signature for the attacker's known (or suspected) behaviour lets you **re-run old pcaps** to find out when it started.

### 7.2 Scripts { #scripts }

Zeek's real power is its **scripting framework**. You attach processing to specific events (connection established, HTTP request, file seen, and so on) and store **enrichment and lookup results in logs**: looking up observed file hashes with reputation services, finding IPs whose MAC changes more often than a threshold, DNS frequency reports, TLS client fingerprints and more. This lab's `software.log` (inventory of observed software) comes from bundled scripts.

**(Actual output; part of `software.log`)**

```text
{"host":"127.0.0.1","software_type":"HTTP::BROWSER","name":"<unknown browser>","unparsed_version":"Mozilla/5.0 (X11; Linux x86_64) LabBrowser/1.0"}
{"host":"127.0.0.1","host_p":8080,"software_type":"HTTP::SERVER","name":"Apache","version.major":2,"version.minor":4,"version.minor2":58,"version.addl":"Ubuntu","unparsed_version":"Apache/2.4.58 (Ubuntu)"}
{"host":"127.0.0.1","software_type":"HTTP::BROWSER","name":"python-requests","version.major":2,"version.minor":31,"version.minor2":0,"unparsed_version":"python-requests/2.31.0"}
```

It summarised client and server software and versions from the `User-Agent` and `Server` headers, which is handy for spotting when an unfamiliar tool (`python-requests`) first appeared internally. There are also public projects that use Zeek scripts to hunt adversary behaviour retrospectively (for example BZAR, which maps Zeek logs to ATT&CK techniques).

!!! warning "[Changed] TLS fingerprints: from JA3 to JA4"
    The book introduces the **JA3** TLS client fingerprint, the **JA3S** server fingerprint and the **HASSH** SSH client fingerprint as add-on modules. Two things have changed.

    - **They're not built in.** Zeek 9.0.1's `ssl.log` had no `ja3` or `ja4` values (actual output: both `null`). You install them separately with the package manager (`zkg`).
    - **JA3 has become less useful.** Since early 2023, Chrome **randomises the order of ClientHello extensions**, so the same browser produces a different JA3 on each connection. **JA4** (FoxIO, 2023) and its family (JA4S, JA4H and others), which for example sort the extension list before hashing, have become widespread. Licence terms differ across the JA4 components, so check them before commercial use.

    **What this means for investigations:** matching JA3 values from old reports or threat intelligence against current traffic may not work for browser families. Always confirm which fingerprint method, and which version of the calculation, you're dealing with.

## 8. Community ID: a flow identifier across tools { #community-id }

### 8.1 Why it's needed { #why-community-id }

A long-standing problem in network investigations has been the lack of **a common name for one flow**. Each tool has its own ID (like Zeek's `uid`), and moving between tools meant matching addresses, ports and times by hand. And, as section 5.5 showed, Zeek's `uid` changes with every run.

**Community ID**, a standard developed by Christian Kreibich at Corelight, makes different tools assign **the same value to the same flow**. It's computed as:

```text
version + ":" + base64( sha1( seed + source_address + destination_address + protocol + 0x00 + source_port + destination_port ) )
```

- **Version**: only `1` is defined so far; the field allows future extension.
- **Seed**: defaults to 0 (2 bytes). Change it to distinguish collection domains.
- **Addresses and ports**: concatenated as bytes.
- **Protocol**: the layer-4 protocol number (TCP = 6, UDP = 17) in 1 byte, followed by a 0x00 byte.
- There are also rules ordering the addresses and ports so **both directions get the same value**, and ICMP type and code go in the port fields.

### 8.2 Computing it by hand and matching three tools { #cid-lab }

I wrote a short Python function from the specification, implementing the ordering rule as "put the smaller (address, port) first".

```python
def community_id(saddr, daddr, proto, sport, dport, seed=0):
    s = ipaddress.ip_address(saddr).packed; d = ipaddress.ip_address(daddr).packed
    if (s, sport) > (d, dport):            # order endpoints so both directions match
        s, d, sport, dport = d, s, dport, sport
    data = struct.pack("!H", seed) + s + d + struct.pack("!BB", proto, 0) + struct.pack("!HH", sport, dport)
    return "1:" + base64.b64encode(hashlib.sha1(data).digest()).decode()
```

For the practice pcap's POST connection (`127.0.0.1:33276 → 127.0.0.1:8080`, TCP), I compared three sources.

**(Actual output)**

```text
own implementation (forward)   1:agacjPK3vGloIKDtKkjCFusqawU=
own implementation (reverse)   1:agacjPK3vGloIKDtKkjCFusqawU=
own implementation (seed 1)    1:nucogqK6PevUrbNex7HDUz00Iv8=
Zeek conn.log community_id     1:agacjPK3vGloIKDtKkjCFusqawU=
TShark communityid field       1:agacjPK3vGloIKDtKkjCFusqawU=
```

All three tools produced **the same value**, reversing the direction didn't change it, and a different seed changed it completely. So you can paste an interesting connection's `community_id` from Zeek straight into Wireshark's or another tool's search and get the same flow. Arkime (formerly Moloch), mentioned in the book, also adds this value as metadata (`communityid`) at ingestion.

In TShark I enabled it like this:

```text
$ tshark -r lab.pcap --enable-protocol communityid -Y 'tcp.srcport==33276 && tcp.flags.syn==1' \
    -T fields -e ip.src -e tcp.srcport -e ip.dst -e tcp.dstport -e communityid
127.0.0.1	33276	127.0.0.1	8080	1:agacjPK3vGloIKDtKkjCFusqawU=
```

In the Wireshark GUI, enable `CommunityID` under "Analyze > Enabled Protocols"; the value appears in packet details and you can filter with `communityid == "1:…"`.

!!! info "[Changed] Zeek now ships it"
    The book says Zeek needs an **external module** for Community ID. It's now a bundled script (since Zeek 6.0). In this lab's Zeek 9.0.1, loading `policy/protocols/conn/community-id-logging` was enough to add `community_id` to `conn.log`. It's **not on by default**, though, so load it in your policy (section 10).

!!! warning "[Caution] Community ID names a 5-tuple, not a connection"
    Time isn't part of the calculation. If the same address/port combination is **reused later** (source-port reuse, long captures), different connections share a value. When you find results in another tool by Community ID, **match the times too** to confirm it's the same connection. And across points where addresses change, such as either side of a NAT device, the same communication gets different values.

## 9. The roles of IDS and NSM { #ids-nsm }

Once marketed as a threat-ending solution, the IDS has found a more fitting role as a **monitoring device tuned to the organisation's needs** without drowning administrators in alerts. It often provides the **first indication** that an attack is under way or has succeeded. NSM is a natural progression from rule-based IDS towards **more proactive continuous monitoring**, and platforms that process pcaps and live traffic the same way are especially valuable in incident response.

Both provide evidence in the form of logs. That's extremely useful for finding past activity that becomes recognisably suspicious **after** details about an attack or threat actor come to light. During an incident, you can write signatures for the attacker's known or suspected activity yourself and react quickly as their tactics change (section 7.1).

## 10. Building a Zeek policy for investigations { #forensic-policy }

The book presents two course policies, but their contents are principles worth applying in any investigation. I wrote my own policy file for this lab and ran it.

```text
# Practice policy for offline (pcap) forensic processing.
# Loads selected pieces instead of "local", so the hash lookup over DNS (detect-MHR) is not loaded.
@load frameworks/files/hash-all-files                # MD5/SHA1/SHA256 in files.log
@load protocols/conn/known-hosts                     # known_hosts.log
@load protocols/conn/known-services                  # known_services.log
@load protocols/http/software                        # software.log from HTTP headers
@load policy/protocols/conn/community-id-logging     # community_id in conn.log
redef LogAscii::use_json = T;                        # JSON logs for jq
redef ignore_checksums = T;                          # same effect as -C (offloaded checksums)
redef Site::local_nets += { 127.0.0.0/8 };           # what counts as "local" in this lab
```

Running `zeek -r lab.pcap forensic.zeek`, even without `-C`, produced `http.log`, `dns.log`, `files.log` (with SHA-256), `known_hosts.log` and others in JSON, with `community_id` in `conn.log` (actual output). By principle:

| Principle | How | Why |
| --- | --- | --- |
| JSON logs | `LogAscii::use_json = T` | Easy to handle with jq (section 5) |
| Ignore checksums | `ignore_checksums = T` or `-C` | Prevents logs vanishing on offloaded captures (section 2.1) |
| Community ID | load `community-id-logging` | Links to other tools (section 8) |
| File hashes | `hash-all-files` | Hashes in `files.log` for reputation lookups and matching other evidence |
| Define "local" | `Site::local_nets` | Some scripts (known-hosts etc.) decide inside/outside from it. **Adjust it to the environment under investigation** |
| Turn off outside lookups | don't load `local` wholesale, or remove the script | See [Caution] below |
| File extraction separately | `policy/frameworks/files/extract-all-files` only when needed | It greatly increases storage and run time |

!!! warning "[Caution] The default site policy asks the outside world about file hashes"
    This image's `local.zeek` loads `frameworks/files/detect-MHR` (checked directly). That script asks Team Cymru's Malware Hash Registry about observed file hashes **via DNS queries**. No files are sent, so general OPSEC constraints are met, but revealing which hashes you're investigating can be a problem, and in an analysis environment without Internet access the lookups fail and can slow processing. That's why the policy above picks pieces instead of loading `local` wholesale.

!!! info "[Changed] The SMB analyser is now on by default"
    The book says the SMB analyser must be enabled in the policy. Zeek 9.0.1's default script list (`base/init-default.zeek`) contains `@load base/protocols/smb` (checked directly), so SMB traffic produces `smb_files.log`, `smb_mapping.log` and so on out of the box. That metadata is invaluable in Windows-heavy environments.

## 11. How this is used in real investigations { #in-practice }

1. **Process evidence pcaps with `-C` (or `ignore_checksums`).** Look at `weird.log` and `reporter.log` first.
2. **Record the processing conditions.** Zeek version, policy file, options. A `uid` is valid only within that run.
3. **JSON logs; narrow with `grep`, filter precisely with jq.**
4. **Link logs with `uid` and `fuid`.** `http.log` → `files.log` (hashes) → `conn.log` (sizes, state).
5. **Link to other tools with Community ID plus time.**
6. **Know what empty fields mean.** An empty `password` doesn't mean no authentication; an empty `status_code` may mean no response came back.
7. **Check which scripts make outside lookups.** Build the policy to suit the analysis environment and OPSEC.
8. **Turn behaviour learned during the incident into signatures or scripts and re-run old pcaps.**

## 12. Summary { #summary }

- NSM is the "forensically ready" approach of collecting evidence before incidents, and Zeek is its flagship tool, prioritising **visibility and application-layer understanding** over alerts, and processing live traffic and pcaps the same way.
- **[Caution]** Confirmed directly: a pcap with offloaded checksums run without options produced **no `http.log` or `dns.log` at all**; with `-C` they appeared.
- Zeek writes dozens of log types depending on traffic. The default format is still TSV (select by name with `zeek-cut`), but JSON is common in practice. Hourly rotation is about operational sensors.
- Common fields `ts`, `uid`, `id.*`. In `http.log`, `trans_depth` is the sequence within a connection and `user_agent` is per request. **[Correction]** `password` is empty by default (`username` is logged even on 401), and enabling it turns the log into a credential-leak risk.
- jq: `.`, `-c`, `select()`, `{ }` (quote dotted names), `|= todate`, `[0]`, `-r`, `--arg`. I linked `http.log` → `files.log` (hash matched the real file) → `conn.log`.
- On 1.5 million lines, narrowing first with `zgrep` was about 4.4 times faster than jq alone. Filter precisely with `select()`.
- A signature caught the `python-requests` POST, and `software.log` inventoried observed software. **[Changed]** JA3/JA4 aren't built in, and JA3 became less useful after Chrome's extension-order randomisation.
- Community ID: my implementation, Zeek and TShark gave the same value, identical in both directions. **[Changed]** Zeek ships it as a bundled script. Time isn't part of it, so confirm times as well.

## Review questions { #review }

**Question 1. (Basics)** A colleague ran a pcap captured in front of a compromised server through Zeek, got only `conn.log` and no `http.log`, and reported "there was no HTTP traffic in this period". What would you check first?

??? success "Answer and explanation"
    First look at `weird.log`, `reporter.log` and Zeek's warning messages. If there's `bad_TCP_checksum` or a "checksum offloading" warning, Zeek discarded packets with bad checksums and couldn't do application-layer analysis (section 2.1's experiment lost `http.log` the same way). Re-run with `-C` (or `ignore_checksums = T`). Also check `service` and `resp_p` (80, 8080, 443…) in `conn.log`: HTTPS (443) lands in `ssl.log`, not `http.log`. And confirm the capture actually contains that server's traffic (lesson 1.11's collection points).

**Question 2. (Reading fields)** What can you tell from these three `http.log` lines (selected fields)?

```text
{"uid":"CX1","trans_depth":1,"method":"GET","host":"files.example.com","uri":"/","status_code":200,"user_agent":"Mozilla/5.0 ..."}
{"uid":"CX1","trans_depth":2,"method":"GET","host":"files.example.com","uri":"/dl/setup.msi","status_code":200,"resp_mime_types":["application/x-dosexec"]}
{"uid":"CX1","trans_depth":3,"method":"POST","host":"files.example.com","uri":"/api/report","status_code":204,"request_body_len":48211}
```

??? success "Answer and explanation"
    Three requests happened in sequence (`trans_depth` 1, 2, 3) on **one connection** (same `uid`). After the first page, `setup.msi` was downloaded, and the MIME type Zeek determined from the content is a **Windows executable** (`application/x-dosexec`) — a sign the extension (`.msi`) and real content may differ, worth noting. Then about 47 KB was POSTed on the same connection, and the server replied 204 with no body. Next: use line 2's `resp_fuids` to get the hash from `files.log`, check its reputation and find other PCs that received it. Line 3's POST content isn't in the log, so look for the pcap or `files.log` via `orig_fuids` (if extraction was on). Finally, use the `uid` in `conn.log` for the whole connection's volume and duration.

**Question 3. (Common misconception)** "The `password` column in Zeek's `http.log` is empty throughout, so there were no Basic auth attempts against this server." What's wrong?

??? success "Answer and explanation"
    Zeek **doesn't record passwords by default** (`HTTP::default_capture_password = F`, the [Correction] in section 4). Judge authentication attempts by the `username` column, which is logged even for failed attempts (401). In section 4's experiment, with defaults both attempts showed `password: null` but `username: jdoe`. And if the traffic was HTTPS there's no `http.log` at all; a form login (POST body) rather than Basic auth won't appear in `username` either.

**Question 4. (Applying jq)** From `conn.log` (JSON), you want only connections that sent more than 1 MB outbound, with a human-readable time, the source and destination addresses and the bytes sent. Write the jq command, assuming the originator is internal.

??? success "Answer and explanation"
    For example: `jq -c 'select(.orig_bytes != null and .orig_bytes > 1000000) | .ts |= todate | {ts, "id.orig_h", "id.resp_h", "id.resp_p", orig_bytes, resp_bytes, duration}' conn.log`. Points to check: ① some records have no `orig_bytes` (null), so filter those first to avoid comparison errors; ② quote dotted names like `id.orig_h`; ③ to make "outbound" precise, add the `local_orig`/`local_resp` columns to the condition (when `Site::local_nets` is set correctly in the policy), or exclude destinations in internal ranges; ④ for big files, use `zcat … | jq`; a numeric comparison like 1 MB is hard to pre-filter with `grep`, so this is a case for `select()` (section 6).

**Question 5. (Changed conditions)** You processed the same pcap with Zeek yesterday and today. Searching today's results for a `uid` from yesterday's report finds nothing. Why, and what should you have done?

??? success "Answer and explanation"
    `uid`s are generated fresh on every run (section 5.5's experiment: the same connection went from `CAU56U3…` to `CjrN3e3…`). A report should give the `uid` together with **which run** it came from (date, Zeek version, policy), and that run's logs should be preserved as evidence. To refer to the same flow independently of processing, also record the **Community ID** (the same 5-tuple gives the same value whenever and with whatever tool, section 8.2) plus **time, addresses and ports**.

**Question 6. (Community ID)** Searching Arkime for a suspicious connection's Community ID from Zeek returns **three** connections. What do you suspect, and how do you pick the right one?

??? success "Answer and explanation"
    Community ID is computed from the 5-tuple only (addresses, ports, protocol), not time, so when **the same 5-tuple is used several times**, different connections share a value (the [Caution] in section 8.2). The same source port may have been reused later, or it may be UDP traffic repeated on the same port pair for a long time. Compare Zeek's `ts` and `duration` with each result's start and end times to choose one, and match sizes (`orig_bytes`, `resp_bytes`) too. If the other two are repeated traffic between the same PC and server, that itself may be a clue such as beaconing (lesson 2.4).

**Question 7. (Common misconception)** "jq is slow, so for big logs just use `grep`." Refute this with section 6's experiment and explanation.

??? success "Answer and explanation"
    `grep` is fast (about 4.4 times in the experiment) but **doesn't know about fields**. It matches `"beacon.example.org"` even when it's in `answers` (another name's CNAME target) rather than `query`, and conditions such as numeric comparisons (bytes > 1 MB) or "records lacking this field" are hard to express. So use `grep` to **narrow candidates broadly**, then jq's `select()` to **filter precisely**. Conversely, with complex conditions and small data, jq alone is fine. Weighing accuracy against processing time is the investigator's judgement.

**Question 8. (Application)** During an incident, you learn that the attacker's tool adds `X-Session-Token: ` followed by 32 hex digits to its HTTP requests. Design a way to find this tool's traces in the last three months of pcaps with Zeek.

??? success "Answer and explanation"
    For example: ① write a signature with `http-request-header /X-Session-Token: [0-9a-f]{32}/` (same format as section 7.1), plus `ip-proto == tcp` and so on as needed; ② re-run three months of pcaps with `-C`, this signature (`-s`) and an investigation policy (JSON, Community ID); ③ use `signatures.log`'s `uid` to link `http.log` (which `host`, `uri`, `user_agent`), `conn.log` (volume, duration) and `files.log` (files exchanged); ④ scope by the list of internal addresses that matched; ⑤ treat the first match as a candidate start of the incident timeline. Over HTTPS the header isn't visible, so look separately for features visible outside the encryption, such as the tool's TLS fingerprint (JA4 etc.), server names or beaconing patterns.

**Question 9. (Interpretation)** The access log shows `"POST /upload HTTP/1.1" 200 0`, but for the same time Zeek's `http.log` has that request's `status_code` empty and `conn.log` shows `resp_bytes` 0. Which do you believe?

??? success "Answer and explanation"
    Neither is simply "wrong"; **they observe from different places**. The server log says the server program "recorded the outcome as 200"; Zeek saw that **no response bytes went out** on the network (the pattern seen directly in section 4's [Caution], where the client got "Empty reply"). The client probably received no response, while the server may well have received the request body and processed something. For an upload investigation, what matters is **whether the file ended up on the server**, so check the server's file system, application logs and error logs, and use Zeek's `request_body_len` and `files.log` (`orig_fuids`) for the amount actually sent and its hash. Record the discrepancy itself in the report.

## References { #references }

- Tools used in this environment: Zeek 9.0.1 (official Docker image `zeek/zeek`, including `zeek-cut`), jq 1.7, TShark 4.2.2 (CommunityID dissector), tcpdump, curl 8.5.0, Apache 2.4.58, Unbound 1.19.2, Python 3.13. Results obtained on 2026-11-05.
- Zeek, [documentation](https://docs.zeek.org/en/master/) (log file list; `conn.log`, `http.log`, `dns.log` and `files.log` fields; signature framework; script reference). Defaults (`LogAscii::use_json`, `HTTP::default_capture_password`, `Log::default_rotation_interval`) and the contents of `local.zeek` and `init-default.zeek` were checked inside the image.
- Corelight, [Community ID specification](https://github.com/corelight/community-id-spec).
- Wireshark, [CommunityID dissector](https://www.wireshark.org/docs/dfref/c/communityid.html).
- jq, [manual](https://jqlang.github.io/jq/manual/) and tutorial.
- FoxIO, [JA4+ repository](https://github.com/FoxIO-LLC/ja4) (the JA4 family and licensing). Chrome's ClientHello extension-order randomisation (early 2023, around Chrome 110) is summarised from published announcements and analyses.
- Team Cymru, Malware Hash Registry (the service used by Zeek's `detect-MHR` script).
- Richard Bejtlich, *The Tao of Network Security Monitoring* and *The Practice of Network Security Monitoring*.

!!! note "About this page"
    A personal study note, rewritten in my own words from several learning resources. The practice traffic, signature, policy file and Community ID code are my own, and the scenarios are hypothetical.

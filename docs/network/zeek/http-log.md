---
title: http.log
tags:
  - artifact
  - network
  - zeek
  - http
---

# Zeek `http.log`

<div class="dfir-meta" markdown>
**Category:** Network · **Source:** Zeek · **Last updated:** 2026-09-16
</div>

!!! abstract "In one sentence"
    One row per HTTP request/response pair in cleartext HTTP (and TLS-decrypted traffic if you have a decrypting proxy feeding Zeek) — method, host, URI, user agent, status, sizes, and the `fuid`s of any files that moved, which makes it the fastest place to spot payload downloads, web-shell traffic and HTTP-based C2.

## Fields

| Field | Meaning | Analyst notes |
|---|---|---|
| `ts`, `uid`, `id.*` | As in `conn.log` | One TCP `uid` can carry many requests (keep-alive) |
| `trans_depth` | Request number within the connection (1, 2, 3…) | Pipelining / keep-alive count |
| `method` | `GET`, `POST`, `HEAD`, `PUT`, `OPTIONS`, `PROPFIND`, `CONNECT`… | `PUT`/`PROPFIND` = WebDAV (payload staging), `CONNECT` = proxy tunnelling, weird casing/methods = tooling |
| `host` | `Host:` header | Compare to `id.resp_h` reverse/`dns.log`; **raw IP as Host** = suspicious; mismatch with SNI-style expectations = domain fronting |
| `uri` | Path + query string | Short random paths, `.php?cmd=`, base64 params, `/api/v1/` on odd hosts |
| `referrer` | `Referer:` header | Missing on direct malware requests; present on drive-by chains |
| `version` | `1.0` / `1.1` / `2` | `1.0` from a modern host = scripted client |
| `user_agent` | `User-Agent:` header | Golden field — see below |
| `origin` | `Origin:` header | |
| `request_body_len` / `response_body_len` | Bytes | POST with large body to unknown host = exfil; tiny periodic GETs = beacon |
| `status_code` / `status_msg` | Response code | See [HTTP status codes](../../basics/http-status-codes.md) |
| `info_code` / `info_msg` | 1xx interim | |
| `tags` | Zeek's own flags (e.g. `URI_SQLI`) | |
| `username` / `password` | From `Authorization: Basic` | **Cleartext creds** |
| `proxied` | Headers that suggest a proxy (`X-Forwarded-For`, `Via`) | Real client IP behind a proxy |
| `orig_fuids` / `resp_fuids` | File IDs uploaded / downloaded | → [`files.log`](files-log.md) |
| `orig_filenames` / `resp_filenames` | From `Content-Disposition` / URI | |
| `orig_mime_types` / `resp_mime_types` | Sniffed MIME types (by content, not header) | `application/x-dosexec` behind `image/png` = disguised EXE |
| `client_header_names` / `server_header_names` (optional policy) | Header names in order | Order & set of headers fingerprints tools (e.g. missing `Accept-Language`) |
| `cookie_vars`, `uri_vars` (optional) | Parsed variables | |

## Quick queries

=== "zeek-cut / shell"

    ```bash
    # Rare user agents (count of distinct hosts using each UA — malware UAs are used by 1 host)
    zeek-cut id.orig_h user_agent < http.log | sort -u | awk -F'\t' '{print $2}' | sort | uniq -c | sort -n | head -30

    # Executables downloaded (by sniffed MIME type), with where from
    zeek-cut -d ts id.orig_h host uri resp_mime_types resp_fuids < http.log | grep -E 'x-dosexec|x-msdownload|x-executable|x-msdos' 

    # POSTs to raw-IP hosts or to hosts never seen before (exfil / C2 check-ins)
    zeek-cut -d ts id.orig_h host uri method request_body_len < http.log | awk '$5=="POST"' | grep -E '\t[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+\t'

    # Beacon-like: same host+uri hit repeatedly by one client with small responses
    zeek-cut id.orig_h host uri response_body_len < http.log | sort | uniq -c | sort -rn | awk '$1>50' | head

    # Web shell hunting on your own web server (internal resp_h): POSTs to .php/.aspx/.jsp with 200
    zeek-cut -d ts id.orig_h uri method status_code < http.log | grep -E '\.(php|aspx?|jsp|jspx)\b' | awk '$4=="POST" && $5==200'

    # Directory brute force: one source, hundreds of 404s
    zeek-cut id.orig_h status_code < http.log | awk '$2==404' | sort | uniq -c | sort -rn | head

    # Cleartext credentials
    zeek-cut -d ts id.orig_h host username password < http.log | awk '$4!="-"'

    # Everything one connection said (pivot from conn.log uid)
    grep -F 'CHhAvVGS1DHFjwGM9' http.log | zeek-cut -d ts method host uri status_code user_agent
    ```

=== "Splunk"

    ```spl
    index=zeek sourcetype=zeek:http
    | stats dc(id.orig_h) as hosts count by user_agent
    | where hosts <= 2
    | sort count
    ```

    Counts how many *different* clients (`dc(id.orig_h)`) use each user agent. A UA used by one or two machines in the whole company is either a bespoke tool or malware — legitimate browsers are used by hundreds.

    ```spl
    index=zeek sourcetype=zeek:http resp_mime_types="application/x-dosexec"
    | table _time, id.orig_h, host, uri, response_body_len, resp_fuids
    | join type=left resp_fuids [ search index=zeek sourcetype=zeek:files | rename fuid as resp_fuids | fields resp_fuids, sha256, md5 ]
    ```

    `table` picks the columns to show. `join type=left resp_fuids [ … ]` runs a second search on `files.log`, renames its `fuid` to match, and glues the hashes onto each download row — so you go from "an EXE was downloaded" to "here is its SHA-256" in one query. (`join` is slow on big data; for large ranges use `stats … by fuid` after an `OR` search instead.)

## Analysis tips

!!! tip "User-Agent triage in three buckets"
    1. **Real browsers** — long UA, many hosts use it, consistent with the OS fleet.
    2. **Legit tools/updaters** — `Microsoft-CryptoAPI/10.0`, `Windows-Update-Agent`, `Microsoft BITS/7.8`, `Microsoft-Delivery-Optimization`, `Google Update`, `Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 6.1; …)` used by **Office**/WinHTTP. Learn these so they stop scaring you.
    3. **Everything else** — `python-requests/2.x`, `curl/…`, `Go-http-client/1.1`, `PowerShell`/`WindowsPowerShell/5.1`, `Wget`, `Java/1.8`, empty UA, UA with typos (`Mozila`), a *default* Cobalt Strike-style UA that is a real-looking IE string but pinned to `MSIE 9.0; Windows NT 6.1` on Win11 hosts. **Rare + on a workstation + to an unknown host** = pull the thread.

- **Host ≠ IP**: Zeek logs `host` from the header. `host` = `cdn.example.com` while `id.resp_h` belongs to a random VPS, or `host` blank / raw IP, is worth a look. Malware often hard-codes the IP and omits or fakes `Host`.
- **Sniffed MIME beats declared**: `resp_mime_types` is what the bytes *are*. `uri` ends in `.jpg`, `resp_mime_types` is `application/x-dosexec` → stage-2 payload disguised as an image. Also watch `text/plain` bodies that are actually PowerShell.
- **Beacon pattern**: `GET` to a fixed or rotating short `uri` every N seconds/minutes, `response_body_len` tiny (0–200) when idle, occasionally larger when tasked; `POST` with `request_body_len` growing when results are sent back. Cobalt Strike defaults: `GET /ca`, `/dpixel`, `/__utm.gif`, `/pixel.gif`, `/activity`, `/submit.php?id=…` — customised in malleable profiles but often left default in lab/cheap ops.
- **Web-shell traffic on your servers**: `POST` to a single script, `200`, `referrer -`, odd UA, request bodies of varying length, response bodies containing command output sizes. Check `files.log` for the upload that created the shell (a `PUT`/`POST` with `orig_fuids`).
- **HTTP on non-80 ports** still lands here (`service=http` by DPD). Filter `id.resp_p!=80` to find proxies, C2 on 8080/8443-plaintext, and internal tools.
- **HTTP/2 and HTTPS** are *not* here — `ssl.log` for the handshake, and for content you need decryption at a proxy or EDR-level visibility.
- **Chunked / compressed bodies**: `response_body_len` is the decompressed length Zeek saw; `resp_bytes` in `conn.log` is on-the-wire.

## Correlation

| Question | Then look at |
|---|---|
| What was the downloaded file? | `resp_fuids` → [`files.log`](files-log.md) (`sha256`, `mime_type`, `total_bytes`) → `pe.log`, `extract_files/<fuid>` |
| Did it get executed? | Host: [Prefetch](../../windows/prefetch.md), [Amcache](../../windows/amcache.md), `Zone.Identifier` `HostUrl` in [$MFT](../../windows/mft-usn.md) will contain this URL |
| Which process made the request? | Sysmon `3` matching `uid` 5-tuple/time; proxy logs with username |
| What did the name resolve from? | [`dns.log`](dns-log.md) `query`=`host` just before `ts` |
| Alerts? | Suricata HTTP rules (`eve.json` `http.hostname`, `http.url`), `notice.log` |
| Full request/response bodies | pcap: [`tshark -Y "http.request && ip.addr==…" -T fields -e http.file_data`](../wireshark-tshark.md); Arkime session view |

## References

- [Zeek docs — http.log](https://docs.zeek.org/en/master/scripts/base/protocols/http/main.zeek.html)
- [Cobalt Strike default HTTP indicators — Malleable C2 profiles reference](https://hstechdocs.helpsystems.com/manuals/cobaltstrike/current/userguide/content/topics/malleable-c2_main.htm)
- [HTTP status codes](../../basics/http-status-codes.md) · [Well-known ports](../../basics/well-known-ports.md)

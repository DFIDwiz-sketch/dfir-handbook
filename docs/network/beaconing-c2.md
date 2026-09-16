---
title: Beaconing & C2 Detection
tags:
  - concept
  - network
  - hunting
  - c2
---

# Beaconing & C2 Detection

<div class="dfir-meta" markdown>
**Category:** Network hunting · **Last updated:** 2026-09-16
</div>

!!! abstract "In one sentence"
    An implant has to phone home, and it does so in ways that are statistically different from a human: **regular timing**, **consistent sizes**, **one destination for a long time**, **odd TLS/HTTP fingerprints**, and **destinations no one else visits** — this page is the checklist and the queries for finding that in Zeek/Splunk, plus what modern C2 does to hide.

## The signals

| Signal | Why it exists | Where to measure |
|---|---|---|
| **Regular interval** (with or without jitter) | Implant sleeps N seconds between check-ins | `conn.log ts` deltas per (`orig_h`, `resp_h`, `resp_p`) |
| **Consistent payload size** when idle | "Nothing to do" is the same message every time | `orig_bytes` / `resp_bytes` variance; `http.log response_body_len` |
| **Long-lived relationship** | Same pair talks for hours/days | Count of connections per pair per day; first-seen date |
| **Rare destination** | Only the infected host(s) know the C2 | `dc(id.orig_h)` per `resp_h` / SNI / domain |
| **Low `dns.log` presence** or **new domain** | Hard-coded IP, or freshly registered domain | Conn without preceding DNS; domain age |
| **Fingerprint mismatch** | Implant's TLS/HTTP stack ≠ a browser | JA3/JA4 rarity, missing ALPN, odd UA, header order |
| **Cert oddities** | Self-signed / default / just-created | `ssl.log validation_status`, `x509.log not_valid_before` |
| **Off-hours activity** | Machines don't sleep, users do | Connections at 03:00 from a workstation whose user is asleep |
| **Long connections with low bytes** | Interactive shell / reverse tunnel kept alive | `conn.log duration` > hours, `orig_bytes` small |
| **Bytes out ≫ bytes in** | Exfil | `sum(orig_bytes)` per pair; [SRUM](../windows/srum.md) on the host |

## Interval analysis — the core technique

For each (`id.orig_h`, `id.resp_h`, `id.resp_p`) with enough connections (say ≥ 20 in a day), compute the **time between consecutive connections** and look at the distribution:

- **Perfect beacon**: all deltas ≈ 60 s → tiny standard deviation, one spike in the histogram.
- **Jittered beacon** (Cobalt Strike `sleep 60 jitter 30`): deltas uniformly spread in 42–60 s → a *box*, still bounded, still nothing like human traffic.
- **Human / browser**: deltas from milliseconds to hours, heavy tail, clustered in working hours.
- **Legit background**: NTP (exactly regular, port 123, tiny), Windows Update, AV updates, OneDrive, Teams presence — regular *and* to well-known destinations used by *many* hosts. Rare destination is what separates them.

=== "Splunk — beacon score"

    ```spl
    index=zeek sourcetype=zeek:conn local_orig=true local_resp=false
    | sort 0 id.orig_h, id.resp_h, id.resp_p, _time
    | streamstats current=f last(_time) as prev_time by id.orig_h, id.resp_h, id.resp_p
    | eval delta = _time - prev_time
    | where isnotnull(delta) AND delta > 0
    | stats count avg(delta) as avg_gap stdev(delta) as sd_gap avg(orig_bytes) as avg_up stdev(orig_bytes) as sd_up dc(uid) as conns min(_time) as first max(_time) as last by id.orig_h, id.resp_h, id.resp_p
    | where count >= 20
    | eval jitter_pct = round(100 * sd_gap / avg_gap, 1), size_var_pct = round(100 * sd_up / (avg_up+1), 1)
    | eval span_hours = round((last-first)/3600, 1)
    | where jitter_pct < 30 AND span_hours > 2
    | convert ctime(first) ctime(last)
    | sort jitter_pct
    ```

    Line by line: `sort 0 …, _time` orders every connection by pair and time (`0` = no row limit). `streamstats current=f last(_time) as prev_time by …` walks down the sorted list and, for each row, fetches the timestamp of the *previous* row in the same pair — `current=f` means "don't include the current row", so you get the previous one. `eval delta = _time - prev_time` is the gap in seconds. `stats … by pair` then summarises each pair: how many gaps, their average and standard deviation, the average/stdev of upload size, and the first/last time. `jitter_pct` is stdev divided by mean as a percentage — a perfect beacon is ~0%, Cobalt Strike with 30% jitter lands around 15–20%, browsing is well over 100%. `where jitter_pct < 30 AND span_hours > 2` keeps only regular, long-running pairs. What you see at the top: a workstation → one VPS IP:443, 1,400 connections, avg gap 61 s, jitter 3%, spanning 24 hours.

    Add rarity in the same pass:

    ```spl
    ... 
    | eventstats dc(id.orig_h) as hosts_to_dest by id.resp_h
    | where hosts_to_dest <= 3
    ```

    `eventstats` is like `stats` but keeps the original rows and appends the result as a new field — here, how many internal hosts talk to that destination at all. Beacons to a destination that only 1–3 hosts ever contact are the ones to open first.

=== "Zeek + shell (small pcap / single day)"

    ```bash
    # deltas for one pair
    zeek-cut ts id.orig_h id.resp_h id.resp_p < conn.log \
      | awk '$2=="10.0.0.25" && $3=="203.0.113.7" && $4==443 {print $1}' | sort -n \
      | awk 'NR>1{printf "%.0f\n", $1-prev} {prev=$1}' | sort -n | uniq -c | sort -rn | head
    # → "1372 60" (1,372 gaps of exactly 60 s) is a beacon; a browser gives a long messy list.

    # pairs by connection count, then eyeball the frequent ones
    zeek-cut id.orig_h id.resp_h id.resp_p < conn.log | sort | uniq -c | sort -rn | awk '$1>100' | head -30
    ```

=== "RITA (free, purpose-built)"

    ```bash
    # Import Zeek logs, then ask for beacons / long connections / DNS oddities
    rita import /data/zeek/logs/2026-09-16 case01
    rita show-beacons case01 | head -20         # score, src, dst, connections, avg bytes, interval range
    rita show-long-connections case01
    rita show-exploded-dns case01                # subdomain explosion = tunnelling
    rita show-strobes case01                     # extremely high connection counts
    ```

    RITA (Active Countermeasures) implements exactly this analysis with a 0–1 beacon score. AC-Hunter is the commercial UI.

## HTTP/TLS-level tells

- **Same URI, tiny response, forever**: `http.log` `GET /pixel.gif` every minute, `response_body_len` 0–100, `POST /submit.php?id=…` with `request_body_len` > 0 when results return.
- **User agent** used by 1 host; **HTTP/1.0** or missing `Accept-Language`/`Referer`; **`Host` header** is a raw IP or blank.
- **JA3/JA4** unique to the host (see [ssl.log](zeek/ssl-x509.md)); **no ALPN**; **SNI blank**; **self-signed / brand-new cert**; **`sni_matches_cert = F`** (fronting).
- **Cert reuse**: same `x509` fingerprint on multiple IPs over weeks.
- **Cobalt Strike / Sliver / Mythic / Havoc defaults** exist (default UA strings, default cert `Major Cobalt Strike`, default URIs `/ca`, `/dpixel`, `/__utm.gif`, `/activity`), but competent operators change them — rely on behaviour, use defaults as a bonus.

## DNS C2 & tunnelling

- Very high query rate to **one domain**, subdomains long and high-entropy, mostly `TXT`/`NULL`/`CNAME`/`MX`; total **DNS bytes** per host far above peers; answers that don't look like addresses. ([dns.log](zeek/dns-log.md))
- Clients talking DNS to **non-corporate resolvers**, or on **TCP 53**.
- `rita show-exploded-dns`; Splunk: `dc(query)` per registered domain per host.

## Other channels

| Channel | What it looks like |
|---|---|
| **ICMP tunnel** | `conn.log proto=icmp` with large `orig_bytes`, many packets, both directions; Wireshark `icmp && data.len > 64` |
| **Long-lived reverse shell / SOCKS (chisel, ngrok, ssh -R)** | `conn.log duration` in hours, `history` `ShADad…` with continuous small data, `service=ssh` on non-22 or `ssl` to a tunnelling provider (`*.ngrok.io`, `*.trycloudflare.com`, `*.serveo.net`) |
| **Cloud-service C2** (Slack, Discord, Telegram, Dropbox, GitHub, Google Drive APIs) | Destinations look legit; separate by **regular interval + one host + API endpoints** (`api.telegram.org`, `discord.com/api/webhooks`, `raw.githubusercontent.com` on a schedule) and by *which process* on the host (Sysmon 3 — a `rundll32.exe` talking to Discord is not Discord) |
| **Domain fronting / CDN** | SNI = big CDN, regular interval from one host, `sni_matches_cert=F` |
| **DoH** | TLS to DoH providers from a host that stops appearing in `dns.log` |
| **WebSockets** | `http.log status_code=101` then a single long connection |
| **QUIC/HTTP3** | UDP 443 with `service=quic` — Zeek 6+ logs `quic.log` with SNI |
| **Peer-to-peer / SMB named-pipe C2** (Cobalt Strike SMB beacon) | **No internet traffic from the victim** — internal `445` to the pivot host with `smb_files`/`dce_rpc` showing named pipes (`\\pipe\msagent_*`, `\\pipe\postex_*`, `\\pipe\MSSE-*`); the pivot host is the one beaconing out |

## Tuning out the noise

Build an allow-list **by destination + behaviour**, not by port. Things that beacon legitimately: NTP (123), Windows Update / Delivery Optimization (`*.windowsupdate.com`, `*.delivery.mp.microsoft.com`), Defender/AV cloud (`*.wdcp.microsoft.com`), Office/Teams presence (`*.office.com`, `*.teams.microsoft.com`), OneDrive/Dropbox/Google Drive sync, Chrome/Edge update, Slack, Zoom, Intune/SCCM/Jamf, EDR agents (**know your own agent's destinations**), printers, UPS/IoT to their clouds, monitoring agents (Zabbix, Nagios, Splunk UF to indexer on 9997), DNS to the resolver. Everything on that list is used by **many** hosts — so `dc(id.orig_h) <= 3` removes most of it automatically; the rest you allow-list by SNI/domain once and document.

## When you find one

1. Freeze the facts: pair, port, first seen, interval, bytes in/out, SNI/URI/JA3, cert fingerprint.
2. Pivot to `dns.log` for the name and every IP it resolved to; to `http.log`/`ssl.log` for the fingerprints; to `files.log` for anything downloaded on those `uid`s.
3. Hunt the fleet for the **same destination, same JA3, same cert, same URI pattern** — implants come in sets.
4. Go to the host: Sysmon 3 / EDR for the **process**; [Prefetch](../windows/prefetch.md) / [Amcache](../windows/amcache.md) for the binary; [SRUM](../windows/srum.md) for bytes per app; persistence keys ([Registry ASEP](../windows/registry-keys.md#autostart-persistence-asep)).
5. Decide: block at egress **after** you've collected, or you lose the beacon and the operator learns.

## References

- [Active Countermeasures — RITA](https://github.com/activecm/rita) · [Threat hunting training (free)](https://www.activecountermeasures.com/hunt-training/)
- [Cobalt Strike Malleable C2 — what operators change](https://hstechdocs.helpsystems.com/manuals/cobaltstrike/current/userguide/content/topics/malleable-c2_main.htm)
- [MITRE ATT&CK — Command and Control tactic (TA0011)](https://attack.mitre.org/tactics/TA0011/)
- [SANS FOR572 — Advanced Network Forensics](https://www.sans.org/cyber-security-courses/advanced-network-forensics-threat-hunting-incident-response/)
- Pages: [conn.log](zeek/conn-log.md) · [dns.log](zeek/dns-log.md) · [http.log](zeek/http-log.md) · [ssl.log](zeek/ssl-x509.md) · [Wireshark & tshark](wireshark-tshark.md)

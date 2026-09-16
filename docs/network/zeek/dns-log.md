---
title: dns.log
tags:
  - artifact
  - network
  - zeek
  - dns
---

# Zeek `dns.log`

<div class="dfir-meta" markdown>
**Category:** Network · **Source:** Zeek · **Last updated:** 2026-09-16
</div>

!!! abstract "In one sentence"
    One row per DNS query (with its answer, if seen) — the cheapest way to find what a host was *trying to reach*, catch DGA and tunnelling domains, and map an IP in `conn.log` back to the name the malware asked for.

## Fields

| Field | Meaning | Analyst notes |
|---|---|---|
| `ts`, `uid`, `id.*` | As in `conn.log` | Many queries can share one UDP `uid` |
| `proto` | `udp` / `tcp` | **TCP DNS** is rare on clients — large answers, zone transfers, tunnelling |
| `trans_id` | 16-bit transaction ID | Matches query ↔ response |
| `rtt` | Round-trip time | |
| `query` | Name asked for | Lower-case it before counting |
| `qclass` / `qclass_name` | Usually `1` / `C_INTERNET` | |
| `qtype` / `qtype_name` | Record type: `A`(1), `AAAA`(28), `CNAME`(5), `MX`(15), **`TXT`(16)**, `NS`(2), `PTR`(12), `SRV`(33), **`ANY`(255)**, `NULL`(10) | `TXT`, `NULL`, `CNAME`-heavy from one host → tunnelling; `ANY` → amplification / recon |
| `rcode` / `rcode_name` | Response code: `NOERROR`(0), **`NXDOMAIN`**(3), `SERVFAIL`(2), `REFUSED`(5) | NXDOMAIN bursts = DGA, typo-squats, sinkholed C2 |
| `AA`, `TC`, `RD`, `RA` | Authoritative / **Truncated** / Recursion desired / available | `TC=T` → client retries over TCP |
| `Z` | Reserved bits | Non-zero = odd client/tooling |
| `answers` | Vector of answers (IPs, CNAME targets, TXT strings) | Comma-separated in TSV |
| `TTLs` | Vector of TTLs matching `answers` | **Very low TTL** (≤ 60 s) on suspicious domains = fast-flux; extreme values = odd |
| `rejected` | Query rejected by server | |
| `saw_query` / `saw_reply` (optional) | Whether Zeek saw each side | |

## Quick queries

=== "zeek-cut / shell"

    ```bash
    # Most queried domains (strip to registered domain roughly: last two labels)
    zeek-cut query < dns.log | tr 'A-Z' 'a-z' | awk -F. 'NF>=2{print $(NF-1)"."$NF}' | sort | uniq -c | sort -rn | head -30

    # Rare domains — queried by exactly one host, once or twice (long tail is where C2 hides)
    zeek-cut id.orig_h query < dns.log | sort -u | awk '{print $2}' | sort | uniq -c | awk '$1==1' | head -50

    # NXDOMAIN storm per host (DGA)
    zeek-cut id.orig_h rcode_name < dns.log | awk '$2=="NXDOMAIN"' | sort | uniq -c | sort -rn | head

    # Long / high-entropy subdomains (tunnelling: dnscat2, iodine, Cobalt Strike DNS beacon)
    zeek-cut -d ts id.orig_h query qtype_name < dns.log | awk 'length($3)>60'
    zeek-cut query < dns.log | awk -F. '{ if (length($1)>30) print }' | sort | uniq -c | sort -rn | head

    # TXT / NULL / unusual types by host
    zeek-cut id.orig_h qtype_name < dns.log | awk '$2=="TXT"||$2=="NULL"||$2=="ANY"' | sort | uniq -c | sort -rn

    # Which name resolved to a given IP? (pivot from conn.log)
    grep -F '203.0.113.7' dns.log | zeek-cut -d ts id.orig_h query answers

    # Hosts using a resolver other than the corporate one (10.0.0.53)
    zeek-cut id.orig_h id.resp_h < dns.log | awk '$2!="10.0.0.53"' | sort | uniq -c | sort -rn

    # Volume of DNS *bytes* per host — tunnels move data, not just names
    zeek-cut id.orig_h orig_bytes < conn.log | awk '{s[$1]+=$2} END{for(h in s) print s[h], h}' | sort -rn | head
    # (run that on conn.log filtered to id.resp_p==53)
    ```

=== "Splunk"

    ```spl
    index=zeek sourcetype=zeek:dns
    | eval qlen=len(query), labels=mvcount(split(query,"."))
    | eval sub=mvindex(split(query,"."),0), sublen=len(sub)
    | where sublen > 30 OR qtype_name IN ("TXT","NULL")
    | stats count dc(query) as uniq_names sum(qlen) as total_chars by id.orig_h, id.resp_h
    | sort - uniq_names
    ```

    `len()` gives string length, `split(query,".")` breaks the name into a multivalue list of labels, `mvcount()` counts them and `mvindex(...,0)` picks the first label (the leftmost subdomain). A host sending thousands of unique 30+ character first labels to the same resolver is tunnelling data out through DNS.

    ```spl
    index=zeek sourcetype=zeek:dns rcode_name=NXDOMAIN
    | bin _time span=10m
    | stats count dc(query) as uniq by _time, id.orig_h
    | where uniq > 50
    ```

    `bin _time span=10m` rounds each event's time down to a 10-minute bucket so `stats` can count per host per 10 minutes. Fifty-plus unique names that don't exist in ten minutes is a Domain Generation Algorithm trying to find its C2.

## Analysis tips

!!! tip "DNS is the pre-crime log"
    Malware resolves a name **before** the `conn.log` row to the C2 appears. Sort `dns.log` around the first suspicious `conn.log` timestamp — the query 50 ms earlier is the C2 domain, and its `answers` are the whole IP set to block.

- **Not all DNS is on port 53.** DoH (`https` to `dns.google`, `cloudflare-dns.com`, `1.1.1.1`) and DoT (853) bypass `dns.log`. Hunt `ssl.log` SNI for known DoH providers and `conn.log` `id.resp_p=853`. A host that suddenly stops appearing in `dns.log` while still browsing has switched to DoH.
- **Baseline the resolver.** Clients should only talk to the corporate resolver; direct-to-internet 53 from a workstation is a policy violation or malware with a hard-coded resolver (`8.8.8.8` is common in Cobalt Strike DNS profiles).
- **Tunnel signatures:** very high query rate to one domain, mostly `TXT`/`NULL`/`CNAME`/`MX`, long labels with base32/base64-looking characters, tiny TTLs, `NOERROR` responses with `answers` that look like garbage, and — decisively — total DNS **bytes** far above other hosts.
- **DGA signatures:** many `NXDOMAIN`, random-looking labels of consistent length, often `.top .xyz .info .ru .cc` TLDs, then one `NOERROR` when it finally finds a live C2.
- **Fast-flux / CDN confusion:** low TTL alone is normal for CDNs (Akamai, Cloudflare). Combine with domain age / rarity before flagging.
- **PTR lookups** by a host for many internal IPs = recon (nmap `-sL`, BloodHound). **SRV** for `_ldap._tcp`, `_kerberos._tcp` = normal domain join; for `_msrcp`, `_vlmcs` etc. from odd hosts = enumeration.
- **`answers` gives you IOCs for free** — extract every IP a suspicious domain ever resolved to and search `conn.log` for direct connections to those IPs by *other* hosts that never did the lookup (hard-coded IP fallback).
- **Sinkholes / RPZ:** if your resolver rewrites bad domains to `0.0.0.0`/sinkhole IP, `dns.log` shows the infected host asking; `conn.log` shows the failed connection. Both are alerts.

## Correlation

| Question | Then look at |
|---|---|
| Did the host connect to what it resolved? | [`conn.log`](conn-log.md) `id.resp_h ∈ answers` within seconds after `ts` |
| What was fetched? | `uid` of that conn → [`http.log`](http-log.md) / [`ssl.log`](ssl-x509.md) (SNI should match `query`) |
| Which process asked? | Sysmon **22** (`QueryName`, `QueryResults`, `Image`) on the host; Windows DNS client cache (`ipconfig /displaydns`, memory) |
| Domain intel | passive DNS, WHOIS/creation date, VirusTotal, threat feeds; `ssl.log` cert reuse across domains |
| Server-side view | DNS server logs (Windows DNS debug log / analytical ETW, BIND query log) for hosts not covered by the sensor |

## References

- [Zeek docs — dns.log](https://docs.zeek.org/en/master/scripts/base/protocols/dns/main.zeek.html)
- [IANA DNS parameters (qtypes, rcodes)](https://www.iana.org/assignments/dns-parameters/dns-parameters.xhtml)
- [SANS — Detecting DNS tunneling (Farnham)](https://www.sans.org/white-papers/34152/)
- [Active Countermeasures — RITA / AC-Hunter DNS analysis](https://www.activecountermeasures.com/free-tools/rita/)

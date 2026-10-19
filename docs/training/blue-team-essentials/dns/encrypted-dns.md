---
title: "Encrypted DNS — DoT, DoH, DoQ, DNSSEC and Collection Strategy"
tags:
  - training
  - sec450
  - blue-team
  - dns
  - concept
  - doh
  - dnssec
---

# Encrypted DNS — DoT, DoH, DoQ, DNSSEC and Collection Strategy

<div class="dfir-meta" markdown>
**Course:** SANS SEC450 (2022) Book 2 · **Module:** DNS Analysis and Attacks · **Pages:** p.80–85
</div>

!!! abstract "What this page covers"
    What DoT, DoH and DNSSEC each protect, how DoH blinds the blue team and the four ways to respond, DoH as seen in Wireshark, and where to collect DNS logs in 2026 now that encryption is the default.

!!! note "Conventions"
    **[Added]** = not in the course, **[Correction]** = course error, **[Changed]** / **[Caution]** = changed since 2022 / risky if done the old way. See the [DNS overview](index.md) and the [triage sheet](triage-sheet.md).

## The future of DNS: DoT, DoH, DNSSEC (p.80–81) { #dot-doh-dnssec }

The three protect different things. DoT and DoH give **confidentiality** (no eavesdropping); DNSSEC gives **authenticity and integrity** (no forgery). They protect users — and block the blue team's view.

| | DoT | DoH | DNSSEC |
| --- | --- | --- | --- |
| How | DNS wrapped in TLS | DNS inside HTTPS | Digital signature on answers |
| Port | TCP 853 | TCP 443 (UDP 443 over HTTP/3) | 53 (ordinary DNS) |
| Protects | Confidentiality | Confidentiality | Authenticity, integrity |
| Blue-team view | Content hidden; easy to identify and block by port | Hard to tell from ordinary web traffic (only SNI and destination IP as clues) | Fully visible |
| Analogy | An envelope | A letter inside a parcel | A notarised seal |

### Key points

- DoT: a dedicated port, so "easy to block". Android "Private DNS" is DoT → 853 traffic is common on corporate Wi-Fi; control it with MDM.
- DoH: you can't block 443, so it's the standard that "wins". **[Correction] The course's "JSON encoded" is inaccurate** — standard DoH (RFC 8484) carries binary DNS as `application/dns-message`; JSON (`application/dns-json`) is a non-standard Google/Cloudflare API.
- DoH encrypts **only the PC ↔ recursive resolver leg**. Recursive → authoritative is usually plaintext, and the DoH provider sees everything → external DoH = the company can't see, the external provider can.
- DNSSEC chain of trust: root key (anchor) → the parent's **DS** (vouches for the child's key) → the domain's **DNSKEY** (public key) → the answer's **RRSIG** (signature). In `dig +dnssec` output the **`ad`** flag = validated; a signature mismatch → SERVFAIL.
- DNSSEC limits: usually validated only up to the recursive resolver (the PC trusts `ad`), **doesn't stop account takeover or record swaps** (signed with the real key), many domains are unsigned, and an attacker's own domain validates as "genuine" too (authenticity ≠ good intent).

??? question "Review Q&A"
    - What's wrong with "we'll turn on DNSSEC for our domain to stop eavesdropping on staff lookups and hijacking": ① DNSSEC doesn't encrypt, so it can't stop eavesdropping, and signing *our* domain only prevents forgery when *others* look up our domain — it has nothing to do with staff looking up other sites ② compromise the registrar account and the attacker changes DS/NS or turns DNSSEC off, so it doesn't stop hijacking (MFA, Registry Lock and change monitoring do).
    - `→ 9.9.9.9:853` = Quad9 DoT, identified and blocked by port / `→ 104.16.248.249:443 SNI cloudflare-dns.com` = Cloudflare DoH, blends with web traffic (a known provider, so SNI/IP still catch it; a self-hosted DoH server or ECH wouldn't be caught).
    - "With external DoH nobody knows" is wrong: the DoH provider sees all of it; recursive → authoritative is plaintext (though the authoritative server only sees the resolver's IP); the PC itself (EDR, browser logs) sees it; and when the site is then visited, **SNI and destination IP** reveal it (ECH hides SNI too).

!!! info "2026 view"
    - Added since the course: DoQ (RFC 9250, UDP 853) and DoH over HTTP/3 (UDP 443).
    - DDR (RFC 9462): the PC discovers that its current resolver supports encryption and upgrades to an encrypted connection to the same server → if company DNS supports DoH you get "encrypted, but the company keeps the logs" (check per-product support).
    - ODoH (RFC 9230): hides *who* asked even from the DoH provider.
    - OS-level DoH in Windows 11 (the course's "soon" has arrived).
    - [Caution] Detection or proxy rules that look only for the JSON format miss standard DoH. "DNSSEC = the DNS security solution" is a misconception.

## Responding to DoH, and DoH in Wireshark (p.82–84) { #doh-response }

With DoH, DNS becomes HTTP: ① the questions vanish from view and ② it is effectively an unauthorised external resolver. The overall direction: **block external DoH; provide internal DoH or turn it off.**

### Four responses (p.82)

| Response | What it does | What it covers | Limits |
| --- | --- | --- | --- |
| ① Decryption (course: best) | Company proxy decrypts TLS (company cert installed on PCs) | Known and self-hosted DoH alike | Cost/performance, pinned apps break, privacy/legal burden, managed PCs only |
| ② Canary domain | Company DNS returns NXDOMAIN for `use-application-dns.net` | Firefox **automatic** DoH only | Useless against manual settings, Chrome, Edge, OS DoH, malware |
| ③ Internal DoH server | The company runs a DoH server | What comes to the company server (encrypted + company logging/blocking) | External DoH still needs blocking |
| ④ Client logging | Firefox `MOZ_LOG=nsHostResolver:5` + `MOZ_LOG_FILE`, `about:networking` | That PC, that app | Hard to run permanently; for investigations |

### Wireshark (p.83–84)

- Encrypted: just `Application Data`. Clues are the destination IP (`104.16.248.249` = Cloudflare) and SNI. With an attacker-run DoH server you can't tell it's DNS, let alone which name.
- Decrypted: **TLS → HTTP/2 → DNS**, `POST /dns-query`, `content-type: application/dns-message`, and the query name is visible.
- **Transaction ID 0x0000**: the DoH standard (RFC 8484) recommends 0 for HTTP-cache friendliness → pair queries and answers by **TCP connection + HTTP/2 Stream ID**. HTTP/2 sends HEADERS and DATA frames separately.
- Home-lab exercise: set the `SSLKEYLOGFILE` environment variable → point Wireshark's TLS settings at the key-log file → filter `dns` or `http2.header.value == "application/dns-message"`. Delete the file and unset the variable afterwards. **A work PC with `SSLKEYLOGFILE` set is worth investigating.**
- Course homework: find 443 traffic to 1.1.1.1, 8.8.8.8, 9.9.9.9. Zeek: `cat ssl.log | zeek-cut id.orig_h id.resp_h server_name`.

??? question "Review Q&A"
    - The canary domain stops Firefox's default (automatic) DoH. It doesn't stop: Firefox manual DoH, Chrome and Edge (they ignore the canary), Windows 11 / macOS / iOS OS-level DoH, malware or other apps with their own DoH, DoT (853).
    - Why the DoH Transaction ID is 0: so HTTP caches see identical questions as identical requests. Pair by TCP connection + HTTP/2 Stream ID.
    - In EDR, `firefox.exe → cloudflare-dns.com:443` vs `Temp\svchelper.exe → dns.google:443` — **the second first**: not a browser, running from Temp, named to look like a system file → suspected malware doing DoH C2 lookups (Sysmon 1 and 22, parent process, subsequent connections, consider isolation). The first is a policy-violation check.

!!! info "2026 view"
    - Priorities ahead of decryption: ① pin DoH to the company server or turn it off by policy (Chrome/Edge `DnsOverHttpsMode` / `DnsOverHttpsTemplates`, Firefox `DNSOverHTTPS`, Windows Group Policy) ② internal DoH and DDR ③ block public DoH and 853 ④ use EDR to detect non-browser processes connecting to DoH ⑤ selective decryption.
    - [Caution] The canary domain is a helper, not "DoH is blocked".

## DNS Summary — where to collect DNS logs (p.85) { #summary }

The course's conclusion: filter and enrich DNS logs well and **you can catch evil from the domain name alone.** The eight-signal summary lives on the [domain signals](domain-signals.md#signals-summary) page.

### Collection considerations

- DNS is proxied → depending on where you collect, "who asked" disappears (a sensor outside the forwarder sees only the server IP).
- Network extraction (Zeek etc.) is the easiest method "for now".
- As encrypted DNS spreads → you must move to DNS server and endpoint logs.

!!! info "2026 view"
    - [Changed] The course's "future" is here: DoH, DoT, DoQ + ECH (hides SNI too) → on the network, little more than the destination IP remains.
    - Collection priority: ① company DNS server logs (Windows DNS Analytical log 256/257/258 and 260/261, BIND/Unbound query logs) ② endpoint logs (Sysmon 22 = per-process DNS, EDR) ③ Protective DNS (blocking and logging together) ④ network extraction as a supplement.
    - [Changed] Popularity lists: Alexa Top 1M shut down in 2022 → Tranco, Cisco Umbrella, Cloudflare Radar.
    - [Caution] Never conclude from one signal. Stack signals and add context (who · what · where · what next).

??? question "Review Q&A (p.85)"
    - **Excluding the top 100,000 by popularity from alerts**: upside — a big drop in alert noise. Risk — you lose abuse of popular platforms (Google Drive, GitHub, `*.workers.dev`, Discord CDN, dynamic DNS…), compromised popular domains and rank manipulation wholesale. Adjust: keep collecting logs and reduce only alerts; lower the score rather than exclude; take user-content platforms off the list and look at them by subdomain; look at non-browser lookups regardless of rank.
    - **C2 traffic is in the firewall, but there is no DNS server event 256 for it**: ① hard-coded IP (no DNS) ② the malware's own DoH (policy only covers browsers) ③ direct external 53 or 853 ④ hosts file ⑤ looked up under another name (CNAME or a different domain) ⑥ another internal DNS server that isn't logging ⑦ the lookup is outside the search window (PC cache) ⑧ Analytical log loss. Check: Sysmon 22, 3 and 11, EDR, firewall for 53/853/DoH servers, `ipconfig /displaydns`, other DNS servers' logs, widen the time range.
    - **Combining DNS server 256 with Sysmon 22**: the server log = which host IP asked what (for scoping across the company); Sysmon 22 = which program asked. Together: `C:\ProgramData\Intel\igfxsvc.exe` (Intel imitation in a non-standard location) looked up a never-seen `.top` domain → suspected malware. Next: hash, parent process, persistence; firewall connection to the response IP; **search DNS server logs for other hosts that asked the same name (scoping)**.

### 2026 collection priority in detail [Added] { #collection-priority }

**① Company DNS server logs** — the Windows DNS Server Analytical log (`Microsoft-Windows-DNSServer/Analytical`, off by default)

| Event ID | Meaning | When it fires |
| --- | --- | --- |
| 256 | Query received (QUERY_RECEIVED) | Every time a PC asks the DNS server |
| 257 | Response success (RESPONSE_SUCCESS) | An answer was returned |
| 258 | Response failure (RESPONSE_FAILURE) | NXDOMAIN, SERVFAIL, … |
| 260 | Recursive query out (RECURSE_QUERY_OUT) | Not in cache, asking outside |
| 261 | Recursive response in (RECURSE_RESPONSE_IN) | The outside answer arrived |

```
Event ID: 256
QUERY_RECEIVED: TCP=0; InterfaceIP=10.20.0.10; Source=10.20.4.57; RD=1; QNAME=x7qpz9wm.top.; QTYPE=1; XID=41377; Port=52114; Flags=256; PacketData=...
```

`TCP=0` arrived over UDP · `InterfaceIP` the DNS server IP that received it · `Source` **the client IP that asked** · `RD=1` recursion desired · `QNAME` the name asked (trailing dot = root) · `QTYPE=1` A record · `XID` transaction ID · `Port` the client's source port. Every query that passed through company DNS (tunnelling included) is here; queries that never touched company DNS are not.

**② Endpoint logs** — Sysmon Event ID 22 (DNSEvent): which program asked

```
Event ID: 22
UtcTime: 2026-10-19 02:14:07.311
ProcessId: 7412
QueryName: x7qpz9wm.top
QueryStatus: 0
QueryResults: ::ffff:185.199.xx.xx;
Image: C:\Users\jsmith\AppData\Local\Temp\svchelper.exe
```

`QueryStatus: 0` success (otherwise a Windows error code, e.g. 9003 = name does not exist) · `QueryResults` the returned addresses (`::ffff:` is IPv4 written in IPv6 form) · `Image` **the path of the program that asked**. Limit: it only captures lookups that go through the Windows DNS client, so a program's own DoH may not appear → supplement with Sysmon 3 (network connection) and EDR.

**③ Protective DNS** — resolve through a DNS service with threat intel that blocks and logs. Recommended by CISA and NSA in the US; in Australia, ASD reportedly runs a service for government entities.

**④ Network extraction (Zeek `dns.log`)** — a supplement for plaintext DNS through company resolvers and outbound-53 attempts. Field details: [Zeek dns.log](../../../network/zeek/dns-log.md).

---
title: "DNS Abuse — Unauthorised DNS, Shared Hosting, Record Tampering, Tunnelling"
tags:
  - training
  - sec450
  - blue-team
  - dns
  - technique
  - tunneling
---

# DNS Abuse — Unauthorised DNS, Shared Hosting, Record Tampering, Tunnelling

<div class="dfir-meta" markdown>
**Course:** SANS SEC450 (2022) Book 2 · **Module:** DNS Analysis and Attacks · **Pages:** p.63–73
</div>

!!! abstract "What this page covers"
    Unauthorised DNS servers that bypass company DNS and the six places they leave traces, the blocking dilemma of shared hosting, tampering with our own DNS records (domain shadowing, record swaps), and how DNS tunnelling works and how to tell it from legitimate traffic.

!!! note "Conventions"
    **[Added]** = not in the course, **[Correction]** = course error, **[Changed]** / **[Caution]** = changed since 2022 / risky if done the old way. See the [DNS overview](index.md) and the [triage sheet](triage-sheet.md).

## Unauthorised DNS servers (p.63–65) { #unauthorized-dns }

From here on the attacks use DNS itself abnormally. To dodge logging and blocking, attackers skip the company resolver.

### The attack list (p.63)

Unauthorised DNS servers / malicious sites on shared hosting / tampering with our records / DNS tunnelling / blockchain DNS / IDNs. They appear at every stage — recon (SRV, TXT), initial access (look-alikes, subdomain takeover), C2 (DGA, TXT commands, bypass DNS), exfiltration (tunnelling).

### Principle and remedy (p.64)

- A PC's DNS setting is a *request*, not enforcement. A program can build DNS packets itself and send them anywhere → the firewall is where you stop it.
- Legitimate software does it too: browser DoH, IoT and streaming devices with hard-coded DNS, some VPNs, games and dev tools → either malware or a "disobedient program or user" — investigate either way.
- Course remedy: ① allow outbound 53 only from company DNS ② make all DNS visible (server logs alone don't show bypass) ③ **alert on the blocked attempts too** ④ for DoH, TLS decryption (course).
- [Added] Instead of blocking, the firewall can intercept outbound 53 and redirect it to company DNS (hard-coded devices keep working). Log the original destination separately.

### Discussion: find the suspicious query (p.65)

Almost everything goes to company DNS (`192.168.42.2`), but packet 708 alone goes to `8.8.8.8`. External DNS use shows up in the **destination IP** field, not in the name asked (`www.google.com`). Malware does a **connectivity check** against Google and the like before contacting C2, so a perfectly ordinary name comes first → look at what happens **next**. The same log shows different attacks in different fields (name: phishing/DGA; destination: bypass; response: NXDOMAIN/dormant; type: TXT/SRV).

??? question "Review Q&A"
    - 2 a.m., three queries to `1.1.1.1`: `www.microsoft.com`, `www.google.com`, `a8kq2vx.duckdns.org` → time of day, company-DNS bypass and "connectivity check then connect" all line up. The decisive one is the last: **a random subdomain on a free dynamic DNS service** = C2 candidate. On DDNS and hosting platforms each subdomain has a different owner, so the subdomain is effectively the registration unit — an exception to "only the subdomain is random, so it's fine".
    - Why "we block outbound 53, so bypass is solved" is wrong: ① encrypted DNS (DoH 443, DoT/DoQ 853) ② **not using DNS at all, or another path**: hard-coded IPs, DNS on a non-53 port, an attacker-run DoH server ③ **tunnelling that legitimately goes through company DNS** (the question travels via the company resolver to the attacker's authoritative server → unaffected by the 53 block). Response: block 853, block known DoH, browser policy, internal DoH, alert on blocked attempts, default-deny egress, monitor company-DNS query patterns (tunnelling detection), EDR and behavioural detection.

!!! info "2026 view"
    - DoH response in **layers** rather than TLS decryption (cost/performance, breaks pinned apps, privacy/legal issues, ECH): browser policy, Firefox canary domain `use-application-dns.net` → NXDOMAIN, block known DoH servers, block 853 (TCP/UDP), offer internal DoH, endpoint logs.
    - An attacker's own DoH server isn't on any list → behavioural detection.
    - Before blocking 53, log-only for a few days to find devices that would break — and infected ones.
    - Correction: DoQ is **UDP 853**; UDP 443 is DoH over HTTP/3.

## Traces of external DNS, and blocking on shared hosting (p.66–67) { #traces-shared-hosting }

External DNS use leaves traces in six places, and any of them should lead to an alert. Shared hosting is not an attack technique but a blocking dilemma: what do you block when one IP hosts thousands of sites?

### Traces of external DNS use (p.66)

| Source | Where | Name? | Process? | Before traffic? | Notes |
| --- | --- | --- | --- | --- | --- |
| ① Firewall | Network | ✗ | ✗ | ✗ | Both allowed and denied. Outside NAT, sources collapse |
| ② Flow / network sensor | Network | Flow ✗ / Zeek ○ | ✗ | ✗ | Dest 53 + internal source + external dest + source ≠ DNS server |
| ③ Host firewall | Host | ✗ | ○ | ✗ | Windows Security Event ID 5156 (Filtering Platform permitted a connection), 5157 (blocked). Needs audit policy; 5156 is high-volume. `pfirewall.log` |
| ④ IDS | Network | Rule-dependent | ✗ | ✗ | Past alerts help date the start (infection time) |
| ⑤ Host integrity monitoring | Host | — | ○ | **○** | Watch DNS settings and hosts file |
| ⑥ EDR | Host | ○ | ○ | ✗ (○ if it records config changes) | "Any DNS that isn't company DNS" — the most comprehensive |

The two places to watch with host integrity monitoring:

- DNS server setting: `HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\{ID}\NameServer` → watch with Sysmon Event ID 13 (registry value set). If changed, every program on the host uses the attacker's DNS (e.g. DNSChanger).
- hosts file: `C:\Windows\System32\drivers\etc\hosts` → Sysmon Event ID 11 (file create) / FIM. It is consulted before DNS, so **no DNS query happens at all** and nothing appears in network or DNS logs.

### Shared hosting (p.67)

- Around $3 a month, thousands of small sites per IP (one apartment block, thousands of flats). Course example: `cuzb.com` → `91.195.240.79` → 5,857 other sites.
- **Reverse IP lookup ≠ PTR**: PTR is the single name the IP owner chose (`custip-1079.sedoparking.com`); a reverse IP lookup is every domain that passive DNS has seen pointing at the IP.
- Parking services (`sedoparking.com`) serve many unused domains from a few IPs — sometimes tied to malvertising and to waiting or abandoned attack domains.
- Course answer: business sites rarely live on shared hosting, so blocking both domain and IP is usually OK. **Better answer: before blocking, check logs for traffic volume to that IP and the related domains.**

??? question "Review Q&A"
    - A suspected-infected host with no trace at all in network logs → ⑤ host integrity: **the DNS server setting (registry) and the hosts file**. EDR helps if it records configuration changes. Other candidates: home router DNS, browser DoH or proxy settings.
    - Reverse IP lookup returns 3,000 domains: small hosting ASN + two of our hosts + all malicious domains → IP block is possible (also block the domains, set an expiry, investigate both hosts). Cloudflare ASN + 400 hosts + varied domains → don't block the IP. Block domains instead (DNS, proxy), identify which of the 400 actually went to the malicious domain via DNS/proxy/EDR, report abuse to the CDN if needed.

!!! info "2026 view"
    - "Thousands per IP" isn't only classic shared hosting (CDNs, cloud platforms). The reverse-IP count alone can't tell them apart → **check the ASN first**, then apply the course's judgement.
    - Work from home: home router DNS hijacking → force company DNS on corporate laptops anywhere (VPN or cloud Protective DNS).
    - EDR is standard now, but depending on the product, browser-native DoH may show only as an HTTPS connection, not as DNS.
    - [Caution] Six sources alerting on the same event = alert fatigue. One primary alert, the rest as enrichment; pre-register known exceptions.

## Record tampering and DNS tunnelling (p.68–70) { #tampering-tunneling }

If attackers compromise our DNS admin account, our own domain becomes their tool. DNS tunnelling uses DNS as a data channel — hard to block, but easy to find.

### Tampering with DNS records (p.68)

- **Domain shadowing**: add new subdomains under our domain (`blog.sec450.com` → attacker server). They borrow our reputation, age and TLD and pass every name-based check.
- **Record swap** (the "really bad" one): clone the VPN login page and point the `vpn.` A record at it. The captured password is passed through to the real page, the login succeeds, and nobody notices.
- With DNS control the attacker proves ownership via TXT and gets a **genuine HTTPS certificate**. Address bar (real domain) and padlock (real certificate) both look right, so user awareness rules fail.
- Difference from subdomain takeover: takeover uses the empty slot of a neglected CNAME; shadowing compromises the account and adds records directly.
- Defence (course): **MFA + change detection**. Added: keep a record inventory and alert on new records, watch crt.sh for certificates we didn't issue, alert on admin-account logins and changes.

### DNS tunnelling (p.69–70)

- Principle: DNS sends text and receives text → encode data (files, command output) in subdomains; tunnelling software on the attacker's authoritative server (iodine: IP tunnel; dnscat2: C2) decodes it and returns commands in responses (TXT, CNAME).
- "It almost always works": DNS must be able to leave from at least one place (the company resolver).
- Two paths: ① straight to the attacker's DNS (stopped by blocking outbound 53) ② **recursively through company DNS** (unaffected by the outbound 53 block).
- The outbound 53 rule is "allow only the company DNS server, deny the rest". The company resolver's recursion must stay open or the internet breaks → the firewall doesn't inspect question content, so tunnel queries pass as normal recursion. Forwarding to an upstream Protective DNS delivers them the same way (though the upstream can detect them).
- **The firewall blocks the *path*; the DNS server blocks the *destination***: detect the pattern at the company DNS server → block the registered domain (Protective DNS / RPZ) → isolate the infected host.
- Signals: subdomains padded to the length limit (253 per name, 63 per label), random/encoded strings, a flood of queries to one domain, high TXT/CNAME share, an odd process (Sysmon 22), abnormal data volume.
- It may look like hex yet not decode because it is encrypted — that doesn't affect the verdict.

??? question "Review Q&A"
    - Detecting a record swap: A-record change detection, rogue certificates on crt.sh, admin-account login monitoring, response IPs seen internally that aren't our servers.
    - Hundreds of 60-character random-subdomain TXT queries a minute → suspect tunnelling. If it went through company DNS, blocking outbound 53 won't stop it. **Check the registered domain first** (filter out legitimate AV/anti-spam lookups such as `sophosxl.net`) → reputation and age → process → other hosts.

!!! info "2026 view"
    - Low-and-slow evasion (small, slow chunks) → ML detection combining length, entropy, frequency, unique-subdomain count and data ratio (Protective DNS, NDR).
    - **Tunnelling over DoH** defeats DNS-log detection → EDR/NDR behaviour and connection patterns.
    - Bulk exfiltration has moved to legitimate cloud (Google Drive, Telegram, …); DNS tunnelling is for low-volume C2 and locked-down environments.
    - [Caution] False positives from legitimate services that use long random names (AV reputation lookups, CDNs).

## Telling tunnels apart, and a detection checklist (p.71–73) { #tunneling-triage }

"Long random name = tunnel" is wrong. Judge on two axes: **① the registered domain ② the volume**.

### Discussion: three "possible tunnelling" alerts (p.71–72)

| | Looks like | Type | Registered domain | Volume | Verdict |
| --- | --- | --- | --- | --- | --- |
| ① | Very long random name | TXT | `sophosxl.net` (Sophos AV Live Protection) | Low | Benign — technically tunnelling, for a good purpose |
| ② | Very long name with non-standard characters | **NULL** (almost never used) | `pirate.sea` (unknown; hack.lu CTF) | High | **Malicious** (iodine) |
| ③ | Random subdomain | A | `cloudfront.net` (AWS CDN) | Low | Benign |

- AV uses DNS for the same reason attackers do: DNS is open almost everywhere.
- NULL records can carry arbitrary binary, so they are iodine's default — their mere appearance is a strong signal.
- An A answer holds only 4 bytes of IP, so it is an inefficient return channel (though the query side can still exfiltrate).
- Allow-list confirmed legitimate DNS-data services by registered domain — and occasionally check that the process making the lookups really is that product.

### Detection checklist (p.73)

- A spike in **unique subdomains** under one registered domain — each name is new, so it never hits cache and always recurses → it shows up fully in both company DNS logs and the egress sensor (the opposite of "caching means you only see the first lookup").
- High query volume from one source (1 MB exfiltrated = tens of thousands of queries).
- Excess TXT, CNAME, MX, **NULL**.
- Long random subdomains + **an odd registered domain**.
- TXT responses carrying unreadable encoded data (legitimate TXT reads like `v=spf1`).
- Use of unauthorised DNS servers.
- False positives: CDNs, AV lookups, the **DNS hijacking test** (Chrome looks up a few random dot-less single words at start-up → NXDOMAIN).
- Heavy querying to an unknown or malicious registered domain may be exfiltration in progress — investigate first.

??? question "Review Q&A"
    - `4.3.2.1.zen.spamhaus.org` (mail server, on every message) = DNSBL spam-reputation lookup, reversed-IP format / `k8x2m9q4v7.data.update-svc.online` NULL, one host, 300 a minute = malicious tunnelling / `qwzxkplmrt` on several hosts just after boot, three queries, NXDOMAIN = Chrome hijacking test.
    - Clues that survive low-and-slow (A type, short names, one query per 10 minutes): the registered domain (new, no reputation, new to us), **unique subdomain count accumulated over a long period**, regular intervals (beacon), continuing when nobody is at the keyboard, the process (Sysmon 22), no other hosts going there. How: group by source host × registered domain and aggregate over **days to weeks**; check interval regularity.

!!! info "2026 view"
    - More false positives: DNS lookups by security products in general, DNSBLs (`zen.spamhaus.org`), cloud and telemetry → a documented allow list.
    - Evasion: low-and-slow, A/AAAA (AAAA answers carry 16 bytes), short names, well-reputed domains (shadowing, DDNS) → composite scoring, ML, long-term accumulation.
    - Keep allow lists narrow, by registered domain. Exclude them from the tunnelling rule only; keep them visible to every other detection.

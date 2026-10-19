---
title: "DNS Log Collection and Safe Investigation"
tags:
  - training
  - blue-team
  - dns
  - concept
  - opsec
---

# DNS Log Collection and Safe Investigation

!!! abstract "What this page covers"
    What sensor placement lets you see, how to pivot to firewall logs when the client has been lost, the OPSEC-safe order for looking things up, and the four steps of DNS detection (parse · enrich · decide · act).

!!! note "Conventions"
    **[Added]** = practical must-knows, **[Correction]** = a commonly repeated mistake, **[Changed]** / **[Caution]** = changed recently / risky if done the old way. See the [DNS overview](index.md) and the [triage sheet](triage-sheet.md).

## Checking your logs and pivoting { #visibility }

To catch an attack you first have to be able to see it. Sensor placement and log type decide what is visible and what isn't.

### Two ways attackers use DNS

| Kind | Example | What gives it away | How to catch it |
| --- | --- | --- | --- |
| Normal DNS to find a bad place | Phishing link click → ordinary A query | The name itself (blocklists, free TLD, newly registered, look-alike spelling) | Compare with lists |
| Using DNS itself abnormally | TXT commands, DNS tunnelling, NS hijack | Behaviour (TXT ratio, long/random names, NXDOMAIN spikes) | Compare with baseline |

List comparison alone misses new attacks; behaviour comparison alone misses known ones — you need both.

### Five checks on your DNS logging

- [ ] Where is the sensor? If only above the company DNS server, every client looks like the DNS server's IP
- [ ] Do you use both server logs and network extraction? Each fills the other's gaps
- [ ] Are answers (response IPs) logged? Without them the link to firewall logs is broken
- [ ] Are answers retained? That *is* your own passive DNS (which IP did that domain have back then?)
- [ ] Can you see queries that bypass company DNS — direct external resolvers, DoH?

| Setup | Visible | Not visible | Fill the gap with |
| --- | --- | --- | --- |
| Company DNS server logs only | The real client | Queries that bypass company DNS (straight to 8.8.8.8, DoH) | Egress sensor (inside NAT), block outbound 53 + alert on attempts, browser DoH policy |
| Egress network sensor only | Bypass queries (if on 53) | The real client, cache hits that never left, internal-domain queries | Collect DNS server logs, firewall pivot, endpoint logs |

- Put the egress sensor **inside** the NAT, or every client collapses into the company's public IP.
- DoH looks like ordinary HTTPS to the egress sensor and isn't caught by a port-53 block. Browser-native DoH bypasses the OS resolver and may not appear in Sysmon 22 either — policy is the reliable control.

### When the client is lost — pivot

Take the response IP from the DNS log, search firewall logs for it, and the real PC appears (using a value from one log to search another = pivoting).

- Upside: PCs hidden by caching also connect to the same IP, so they turn up too. Widen the time window by the TTL.
- Limit: with a shared IP (CDN) you get hundreds of hosts. Narrow to new connections in a tight window, use proxy logs (site name), SNI (not with ECH), endpoint logs (Sysmon, EDR) — and fundamentally, collect DNS server logs.

!!! info "2026 view"
    - DoH went from "a question" to reality: blocking 53 is not the end of it.
    - The more traffic is encrypted, the less the network shows — endpoint logs (Sysmon, EDR) become the third pillar.
    - [Caution] Auto-alerts built only on upstream logs will flag the company DNS server as "the infected host". Add an "is this IP a DNS server?" step to alert logic.
    - [Caution] Check whether your logging tool throws away the TTL field.

## Safe investigation and the detection formula { #investigation }

When you need a domain ↔ IP answer, weigh accuracy (is it the answer *from that time*?) against defensive OPSEC (does the attacker notice?). If the attack is targeted, or you aren't sure, default to quiet.

### Why your lookups must not be noticed

A direct `nslookup` travels to the attacker's authoritative server and leaves your organisation's IP (or your DNS server's IP) there. The attacker can respond by swapping infrastructure, wiping traces, going dormant, or rushing to the objective. For commodity malware this matters less — sharing even helps other defenders.

### Three-tier priority

| Tier | Method | Seen by attacker? | Answer from that time? | When |
| --- | --- | --- | --- | --- |
| 1 | Our own logs: DNS, proxy, Sysmon, EDR, firewall | No | Yes | Always first |
| 2 | External passive DNS lookup | Doesn't reach the attacker; the service may log your search | Yes (has a timeline) | When we have no logs |
| 3A | Ask an online service to do a fresh lookup | Our IP isn't left; VirusTotal publishes, CentralOps doesn't | No (today's answer) | When 1 and 2 are empty |
| 3B | Direct dig/nslookup | Our IP is left on the attacker's server | No (today's answer) | Only if not targeted |

- On the same website, "view historical records" (tier 2) and "run a new lookup" (tier 3) are different features.
- A direct lookup also creates a fresh "malicious domain lookup" in our own DNS logs, muddying which hosts are infected.

### The four detection steps

1. **Parse**: raw log → fields. "Logs are arriving" ≠ "every field you need is there" (watch for missing TTL, response code).
2. **Enrich**: ask a question of every field → host name, department, criticality, user, reputation, registration date, ASN, process. Use the time **of the incident**, not now (check DHCP).
3. **Decide**: one strong signal (exact threat-intel match) ≈ conclusive; several weak signals together (newly registered, cheap TLD, short TTL, no reputation, 3 a.m., process in Temp) = strong suspicion.
4. **Act**: faster, more accurate verdicts — designed so the system adds enrichment automatically, not an analyst by hand.

### Enrichment in four directions

Split the alert into fields and ask "what is this?" of each one: **who (host) · what (domain) · where (IP) · why / what next (context)**.

| Direction | What to add | Why |
| --- | --- | --- |
| Who (host) | Asset inventory (name, department, criticality), DHCP at incident time, logons (user) | Decides risk and who to contact |
| What (domain) | Threat-intel match, registration date (WHOIS), reputation/category, passive DNS history | Turns weak signals like TLD into strong ones |
| Where (response IP) | Threat intel, WHOIS/ASN (shared?), response code (NXDOMAIN?), TTL | On a shared IP, IP reputation weakens |
| Why / what next (context) | The process that asked (Sysmon 22), lookups in the preceding seconds (originating site), how many other hosts asked, the actual connection and bytes afterwards, time of day | Most often missed by beginners, most often decisive |

The same "host looked up a `.top` domain" alert can end in opposite conclusions:

- Scenario A: office hours, marketing PC, `chrome.exe`, news site just before, two-year-old ad domain, 30 other PCs did the same → ad traffic, close as low priority.
- Scenario B: 3 a.m., critical finance PC, `Temp\update.exe`, registered three days ago, no reputation, TTL 60 s, response IP listed as C2, six hours of traffic, the only host to ask → isolate now.

??? question "Review Q&A — \"Why not just nslookup it from my laptop?\""
    Looking up the domain from a targeted incident two weeks ago has three problems:

    1. **Noticed**: the query reaches the attacker's authoritative server with our IP (OPSEC).
    2. **Wrong**: you get today's answer. If it differs from two weeks ago, the firewall shows no connection and you wrongly conclude "safe".
    3. **Polluted**: our DNS logs gain a new "corporate PC looked up a malicious domain" line, confusing which hosts are infected.

    Instead: our DNS logs → proxy, Sysmon, EDR, firewall → external passive DNS history → (only if still nothing) a fresh lookup from a non-attributable environment, noting in the record that it is *today's* answer.

!!! info "2026 view"
    - Mature teams keep a non-attributable investigation environment as standard kit.
    - Uploading a suspicious file to VirusTotal effectively publishes it. "No uploads, hash search only" is a common rule.
    - Some long-standing lookup services have changed (e.g. RiskIQ → Microsoft Defender Threat Intelligence).
    - [Caution] Short DNS log retention empties tier 1 and pushes you to tiers 2–3. Keep at least a "domain · time · IP" summary for a long time.

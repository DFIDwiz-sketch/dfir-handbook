---
title: "Suspicious DNS Triage Sheet · Corrections · Common Confusions"
tags:
  - training
  - blue-team
  - dns
  - cheatsheet
---

# Suspicious DNS Triage Sheet · Corrections · Common Confusions

!!! abstract "What this page covers"
    A practical reference for what to check, in what order, when you are handed one DNS log line; things that are commonly stated wrongly or have changed recently; and the points that actually caused confusion during review.

!!! note "Conventions"
    **[Added]** = practical must-knows, **[Correction]** = a commonly repeated mistake, **[Changed]** / **[Caution]** = changed recently / risky if done the old way. See the [DNS overview](index.md) for the full reading order.

## Suspicious DNS triage sheet { #triage }

### 0. Before judging: can you trust the log?

- [ ] Is the client the real PC? (If the sensor is only above company DNS, every client is the DNS server IP)
- [ ] Are response IPs logged?
- [ ] Are the TTL and response-code fields intact?
- [ ] Can you see company-DNS bypass (direct external 53, DoH)?
- [ ] Is retention long enough for past incidents?

### 1. Principles

1. One strong signal, or several weak ones
2. A bad verdict is evidence; a good verdict is not
3. Does the claim match the source?
4. Read domains from the right; judge ownership by registered domain
5. Compare with baseline
6. Judge by "then", not "now"

### 2. Field by field

**A. The name asked (domain)**

| Signal | Strength | Tips / common false positives |
| --- | --- | --- |
| Exact threat-intel match | Strong | A match settles it / shared domains wrongly listed |
| Registered domain itself random | Strong–medium | Suspect DGA / decode Punycode first |
| Only the subdomain random | Usually benign | Re-judge on the registered domain / CDN, cloud. But on DDNS and hosting platforms (`duckdns.org`, `pages.dev` …) each subdomain has its own owner, so the subdomain is the registration unit → random = suspicious |
| Abnormally long, random subdomain | Medium | Suspect tunnelling. Check the registered domain first (AV lookups like `sophosxl.net` are benign). Detect at the company DNS server, then block the registered domain |
| Brand name stuffed in | Strong–medium | The registered domain isn't the brand's |
| Punycode (`xn--`) | Decode to know | Strong if it imitates a famous brand / legitimate non-English domains |
| Recently registered (7/30/90 days) | Weak–medium | New legitimate businesses |
| Old but recently woken up | Medium | Updated Date, registrar or NS change, passive-DNS gap then activity, recent first certificate |
| First time seen in our organisation | Weak | Supporting signal / new business services |
| Cheap TLD, `.zip` / `.mov` | Weak | Split with the Public Suffix List |
| Subdomain on free hosting | Weak–medium | Judge per subdomain |
| Reputation malicious / medium risk or above | Strong | Quick verdict |
| Reputation uncategorised | Weak | New or rarely visited |
| Reputation safe | Not evidence | Flip, compromise, platform, expired re-buy, cloaking |
| Abnormally long name | Weak | Exceptions exist (the Welsh village) |

A additions: a lookup of a **TLD not on the IANA list** (`.bazar`, `.emc`, `.lib`, `.eth` …) is a strong signal — even NXDOMAIN proves malware on the host. Exceptions: internal names (`.local`, `.corp`, `.lan`), typos, dot-less single words. Blockchain **gateway domains** (`eth.limo`, `ipfs.io`, `dweb.link` …) are on official TLDs, so watch or block them from a separate list. E addition: a host or program with no business reason querying blockchain node APIs, then connecting to an IP with no DNS = suspect EtherHiding.

A additions: any label starting `xn--` is an IDN → **always decode it**. Mixed scripts (Latin + Cyrillic, Greek, Cherokee …) = strong signal; decoded name resembling a famous brand or our domain = strong signal (same-script letters like `ɡ`, `ḟ` exist, so brand comparison is mandatory). Compare the Punycode second part with the brand: the missing letter = the swapped position. A natural single-script name (`한국.kr`) is usually fine.

**B. Query type (record type)**

| Pattern | Suspect | Benign when |
| --- | --- | --- |
| High TXT share from an ordinary PC | Command receipt, tunnelling | Mail servers |
| Mass MX lookups from an ordinary PC | Spambot | Mail servers |
| SRV (`_ldap`, `_kerberos`, `_gc`) in a burst | Internal recon | A few at boot/logon; MFP address-book LDAP |
| Sequential PTR over an IP range | Internal scan (nmap) | — |
| Direct CNAME-type query | A human using a lookup tool | Admin work |
| A/AAAA pairs, HTTPS (65) / SVCB (64) | Normal | Parsers that don't know 65 cause false positives |

B additions: **NULL (10)** is almost never used by legitimate software, so its appearance alone is a strong tunnelling signal (iodine's default). Judge tunnelling by **unique subdomain count and volume** per "one source × one registered domain", accumulated over days to weeks. False positives: AV lookups (`sophosxl.net`), DNSBLs (`zen.spamhaus.org`), CDNs, Chrome's hijacking test (random dot-less single word + NXDOMAIN).

**C. Response content**

| Pattern | Suspect | Tips |
| --- | --- | --- |
| NXDOMAIN spike (mostly different domains) | DGA | With random names, nearly conclusive. Dictionary DGAs leave this trace too |
| `127.0.0.1` / `0.0.0.0` | Dormant C2, sinkhole | Not harmless. A host still asking = still infected |
| Short TTL + constantly changing IPs | Fast flux | Short TTL alone can't be told from a CDN |
| Several answer IPs | Can be normal | Record and investigate all; firewall shows which was used |
| CNAME chain | Can be normal | Follow to the end; judge the final destination |

**D. Response IP**

| Add | Tips | Caution |
| --- | --- | --- |
| Threat intel | Strong if listed as C2 | On a shared IP, IP reputation weakens |
| ASN name | Claim vs source (the brand, or the brand's CDN) | Big companies distribute via CDNs |
| ASN type | A human account logging in from hosting ASN = suspicious | Residential proxies disguise it |
| Shared IP? | If shared, no IP blocking or IP pivot. "How many behind this IP?" is a reverse IP lookup (passive DNS), not PTR. Small hosting ASN → IP block possible after checking logs; CDN/cloud → never | Work at domain level |
| Location | Split by direction and protocol (ignore web; watch SSH, FTP) | An estimate. IP location ≠ attacker location |

**E. The asking host and context**

| Look at | Tips |
| --- | --- |
| Host role | Does the lookup fit the role? DHCP mapping at incident time |
| Program | Sysmon Event ID 22. `chrome.exe` vs `Temp\update.exe` |
| Time of day | Office hours vs 3 a.m. |
| Preceding seconds | Was there an originating site? Derived from an ad? |
| Number of other hosts | Only one = targeted / infected; dozens = possibly a normal service |
| What next | Actual connection, duration, bytes |
| Against baseline | Same time every day may be a scheduled task |

**F. The path**

| Pattern | Meaning |
| --- | --- |
| Ordinary PC sends 53 straight to an external resolver (found via destination IP) | Bypassing logging and blocking. Policy breach, misconfiguration or malware. Suspicious even with an ordinary name (connectivity check) |
| External DNS lookup of Google/Microsoft, then a lookup/connection elsewhere | Malware connectivity check → the next one is the real destination |
| Firewall deny on outbound 53, host-firewall Event ID 5157 | Blocked, but that host and program still need investigating |
| Outbound 853 (TCP DoT / UDP DoQ) | Bypass via encrypted DNS |
| 443 to a known public DoH server | DoH bypass. A browser = policy breach; a non-browser process (confirm in EDR) = strong malware suspicion. A work PC with `SSLKEYLOGFILE` set is also worth investigating |
| Company DNS queries stop but web browsing continues | Possibly DoH |
| DNS-shaped traffic on a non-53 port | Bypass attempt |
| PC DNS-server setting (registry `NameServer`) changed — Sysmon Event ID 13 | Caught before any traffic. Every program now uses the attacker's DNS |
| hosts file changed — Sysmon Event ID 11 / FIM | No DNS query is made, so nothing in network or DNS logs |
| Internal domain names going to external DNS | Internal information leak, misconfiguration |
| Our resolver's query source port is fixed | Vulnerable to cache poisoning |

Caution: list legitimate exceptions (IoT and streaming devices with hard-coded DNS, some VPN and dev tools) during a log-only period. Blocking outbound 53 still doesn't stop tunnelling that goes through company DNS normally (detect with the A and B patterns). For remote workers, consider home-router DNS hijacking.

### 3. Anomalies in our own domain (regular checks, change monitoring)

| Anomaly | Meaning | Response |
| --- | --- | --- |
| NS changed | Full domain takeover | Recover → lock down → ride out the TTL → check rogue certificates and intercepted mail → notify |
| MX changed | Mail interception | Revert immediately, review the account |
| External CNAME target returns NXDOMAIN | Subdomain takeover imminent | Delete the CNAME, audit them all |
| Verification TXT for services no longer used | SaaS exposure | Clean up |

Addition: anomalies when the DNS admin account is compromised

| Anomaly | Meaning | Response |
| --- | --- | --- |
| New subdomain under our domain that isn't in our inventory | Domain shadowing (riding our reputation) | Maintain a record inventory + alert on new records, review the account |
| A record for one of our services (VPN etc.) points at an unfamiliar IP | Record swap (cloned login page steals passwords) | Revert immediately, account MFA and session revocation |
| crt.sh shows a certificate for our domain we never issued | DNS control → TXT ownership proof → genuine certificate | Revoke, investigate records and account |
| Unfamiliar logins or config-change alerts on the DNS admin account | The starting point of every tampering | MFA, Registry Lock |

### 4. Triage workflow

1. Check log quality
2. Split into fields (time, host, domain, type, response, IP, TTL)
3. Strong signals first (threat intel, malicious reputation)
4. Enrich: who · what · where · why / what next
5. How many weak signals stack up?
6. Compare with common false positives
7. Confirm in OPSEC order: our logs → external passive DNS → fresh lookup from a non-attributable environment
8. Verdict and response: state what is certain as certain, and what is unknown as unknown

**Common false positives**: random CDN subdomains, A/AAAA pairs, dozens of lookups for one web page, HTTPS (65) queries, short TTLs, legitimate Punycode, MFP LDAP, TXT and MX from mail servers, impossible travel caused by VPN, the company DNS server appearing in alerts.

**Don't**: `nslookup` a suspicious domain from a corporate PC, treat PTR as proof of ownership, search `in-addr.arpa` without reversing it, block shared IPs, upload suspicious files to VirusTotal, publicly scan phishing URLs, believe "blocking overseas = blocking overseas attacks".

### 5. What makes triage harder in 2026

| Change | Effect | Response |
| --- | --- | --- |
| DoH by default | Invisible to company DNS logs and port-53 monitoring | Browser policy |
| ECH | Site name (SNI) hidden | DNS and endpoint logs gain value |
| HTTPS record `ipv4hint` | Connections without an A lookup | Revisit "connection without DNS" rules |
| Dictionary DGAs | Pass randomness checks | Combine with NXDOMAIN, age, lookup patterns |
| Free hosting platforms | Top-tier parent reputation | Judge per subdomain |
| Cloaking | Reputation services see a clean page | Mail context first |
| Aged / expired re-buys | Evade the age signal | Check recent changes, NS, reactivation |
| Residential proxies | Location and ASN look normal | Phishing-resistant MFA, managed-device conditions |
| Endpoint logs matter more | More is invisible to the network | Sysmon 22, EDR (browser-native DoH may not show in Sysmon 22) |

## Common misstatements and 2026 updates { #corrections }

None of the DNS principles are out of date. Below are only the places that are often explained wrongly or where the environment has changed.

| Kind | Common claim / older situation | 2026 |
| --- | --- | --- |
| Correction | "Linux does not cache answers by default" | `systemd-resolved` caches (`resolvectl show-cache`). macOS caches too. All three major OSes cache |
| Correction | "SPF TXT records start with spf=" | They start with `v=spf1` |
| Correction | TXT "255-character limit" | Per character-string; several strings are concatenated |
| Correction | MX rules cite RFC 974 | Superseded by RFC 5321 (same rule) |
| Correction | PTR of `8.8.4.4` = `google-public-dns-b.google.com` | As far as I know now `dns.google` (a live example of PTRs changing) |
| Correction | DoH "JSON encoded" | Standard DoH is `application/dns-message`; JSON is a non-standard API |
| New | Only the classic record types matter | HTTPS (65) and SVCB (64), RFC 9460 (Nov 2023). Very common now |
| New | SNI reveals the site name | ECH (RFC 9848 and 9849, March 2026). Name encrypted → DNS logs gain value |
| Changed | DoH is still rare | Close to a browser default. Watching port 53 alone misses it |
| Changed | SPF + DKIM | SPF + DKIM + DMARC required (Google and Yahoo 2024, Microsoft 2025) |
| Changed | Warning about the shared-IP accident | CDN growth makes IP blocking less and less suitable for web threats. Domain blocking is the default |
| Changed | Alexa Top 1M | Shut down 2022 → Tranco, Cisco Umbrella, Cloudflare Radar |
| Changed | OpenNIC resolves EmerDNS | Reportedly dropped around 2019 |
| Changed | Free TLDs .tk / .ml | Freenom stopped new registrations in 2023 |
| Added | — | Subdomain takeover (dangling CNAME) |
| Added | — | Domain/NS hijacking, orphaned DNS-provider accounts (Sitting Ducks, 2024) |
| Added | — | Attacks using legitimate services (Living off Trusted Sites) |
| Added | DNS collection = server logs + network extraction | Endpoint logs (Sysmon, EDR) rising as a third pillar |

Still valid as written: the hierarchy, delegation, caching and TTL, record meanings, many-to-many mapping, "don't trust PTR", "check before you block".

## Common confusions { #confusions }

Mix-ups that actually came up while working through review questions. Getting the terms right in exams and reports keeps an investigation pointed the right way.

| Confusion | Correct understanding |
| --- | --- |
| A record vs PTR record | **Give it a name → A; give it an IP → PTR.** A domain changed to point at `127.0.0.1` means the domain owner (attacker) changed its A record |
| How to verify a PTR result | Not another reverse lookup — **look the name up forward (A)** and see whether the original IP comes back (FCrDNS). In reports write "FCrDNS confirmed" |
| Canonical name | Not the name you asked — **the name in the answer** |
| Reversing PTR | Reverse by octet; digits inside an octet stay put. Only IPv6 reverses per character |
| SPF/DKIM pass = genuine mail? | Check which domain passed, alignment with the visible From (DMARC), and possible account compromise. Authenticated ≠ benign |
| First action on NS hijack | After an incident, first **restore NS (recover)**. MFA belongs to the next, lock-down step. The target is the **registrar account**, not the DNS server |
| Lots of queries = infected? | Dozens per web page is normal. Judge by content, pattern, process and time, not count |
| Judging the past with today's lookup | Don't. Use records from that time (our DNS logs, passive DNS) |
| `127.0.0.1` answer = harmless? | It may be dormant. A host still asking = a host still infected |
| A forwarder's destination IP = the server that knew the answer? | No — it may have asked someone else behind it. Capture location decides what you see |

Further confusions from the detection and attacks part:

| Confusion | Correct understanding |
| --- | --- |
| An egress sensor shows the client? | Only if it sits **inside** the NAT; outside, everything collapses into the company public IP |
| Blocking outbound 53 ends bypass DNS? | DoH (443) bypasses both sensor and block. Stop it with browser policy |
| Pivot window = a few seconds after the lookup? | Thanks to caching, other hosts can connect with no DNS query for the whole TTL. Widen the window by the TTL to find hidden infected hosts |
| The only problem with direct lookups is being noticed? | Noticed + **today's answer ≠ the answer then** + polluting our own logs — three problems |
| What to add when enriching | Who (host) · what (domain) · where (IP) · why / what next (context) |
| Reading the registered domain | From the right, up to the label just before the public suffix. The rest is decoration |
| "Probably" vs "certainly" | What follows from domain structure is fact — state it. Only unverified things are "probably" |
| Reputation "safe" = false positive? | Good reputation isn't evidence: flip, compromise, platform, expired domain, cloaking |
| A domain with an old creation date has had the same owner? | WHOIS/RDAP is a snapshot. Look at Updated Date, registrar/NS changes, passive-DNS gaps |
| NXDOMAIN for `.bazar` = failed, so nothing happened? | The lookup itself proves malware on the host; it may have retried another way |
| "Block every `xn--`" | Blocks legitimate multilingual sites. Mixed scripts + brand comparison instead |
| DNSSEC stops eavesdropping and hijacking? | It doesn't encrypt, and registrar compromise defeats it |

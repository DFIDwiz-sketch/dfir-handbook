---
title: "Domain Signals — TLD, Reputation, Age, Randomness, ASN, Geolocation"
tags:
  - training
  - blue-team
  - dns
  - concept
  - enrichment
---

# Domain Signals — TLD, Reputation, Age, Randomness, ASN, Geolocation

!!! abstract "What this page covers"
    Signals that estimate risk from the domain name and the response IP alone: TLDs and the Public Suffix List, the traps in domain reputation, domain age and "new to us", DGAs and randomness, ASN and geolocation, and popularity rank.

!!! note "Conventions"
    **[Added]** = practical must-knows, **[Correction]** = a commonly repeated mistake, **[Changed]** / **[Caution]** = changed recently / risky if done the old way. See the [DNS overview](index.md) and the [triage sheet](triage-sheet.md).

## TLDs and domain reputation { #tld-reputation }

TLD and reputation are weak signals from the name alone. A *bad* verdict is fairly reliable; a *good* one guarantees nothing.

### TLD

- TLD = the rightmost label. Generic (.com), country-code (.au, .tk), new generic (.top, .xyz, .zip — over 1,000 of them).
- Why attackers favour certain TLDs: free or cheap, the names they want are still available, easy look-alikes, lax abuse handling.
- What to do: block/alert on TLDs with a high malicious ratio that the business doesn't use; split TLD into its own field and watch the distribution (TLDs that spike against baseline).
- [Added] Split using the Public Suffix List. Naively cutting at the last dot turns `www.example.com.au` into a single `com.au` blob.
- [Added] Read ownership **from the right, up to the label just before the public suffix**. `login.microsoftonline.com.account-review.top` → TLD `.top`, registered domain `account-review.top`; everything in front is attacker decoration. It has nothing to do with Microsoft's login domain (`microsoftonline.com`).

### Domain reputation

- Category (what kind of site) + reputation (how risky).
- Match automatically against every log where a domain appears — DNS, proxy, mail.
- What to do: block malicious and medium-risk and above; for *Uncategorized*, block or show a splash page (make the user pause); watch hosts that frequently visit risky or uncategorised sites; don't trust it blindly.

| Verdict | Meaning |
| --- | --- |
| Malicious | Reliable — a quick win |
| Safe | Not a guarantee; judge with other signals |
| None / uncategorised | Itself a weak signal (new or barely visited) |

Ways a well-reputed domain can still be phishing:

- Classified safe, then the content is flipped to malicious.
- A compromised legitimate site (phishing page inside an old restaurant website).
- Abuse of a well-reputed platform (SharePoint, Google Drive, `pages.dev`, `netlify.app`) — domain reputation ≠ URL reputation.
- An expired, well-reputed domain re-registered to inherit its reputation.
- Cloaking: security crawlers see a clean page, targets see the phishing page.

In one line: **bad reputation is evidence; good reputation is not.** Attackers earn it (flip), steal it (compromise), borrow it (platforms), buy it (expired domains) and fake it (cloaking).

### Reputation says "safe" but a user reported phishing — checks

- [ ] The full URL, not just the domain (an odd path like `/wp-content/...` inside a good domain?)
- [ ] Open it safely: isolated environment or urlscan.io private mode. Cloaking may mean you need the exact mail link, but its token carries employee data — no public scans
- [ ] Domain info: recent owner change in WHOIS, recent IP change in passive DNS
- [ ] Impact: who clicked (proxy logs), was a password entered → if so, reset immediately and revoke sessions
- [ ] The email itself: SPF/DKIM/DMARC, sender. "An unexpected login link arrived by email" is a stronger signal than reputation

### Report wording: be certain about what is certain

What follows from domain structure is fact, not guesswork. For `login.microsoftonline.com.account-review.top`, don't write "probably not Microsoft" — write "this is not Microsoft's login site (`microsoftonline.com`)". Conversely, don't assert who owns `account-review.top` until WHOIS says so. Separating what you know from what you don't is what makes a report credible.

!!! info "2026 view"
    - The once-popular free TLDs (.tk, .ml) effectively disappeared after Freenom stopped new registrations in 2023; attackers moved to cheap new gTLDs (.top, .xyz, .shop … check current reports for rankings).
    - `.zip` and `.mov` (2023 on) are confused with file extensions; many organisations block them outright.
    - Free hosting platforms are the "new free TLD". Split by public suffix so a subdomain isn't buried under the platform's reputation.
    - Some long-standing reputation services have changed: RiskIQ → Microsoft Defender Threat Intelligence; threatcrowd reportedly discontinued; trustedsource changed with the Trellix/Skyhigh split (verify the current address). Alternatives: urlscan.io, URLhaus.
    - [Caution] Reputation lookups leave traces too — a public urlscan.io scan is visible to anyone and can expose the employee email embedded in the URL.
    - [Added] Reputation blocking now mostly happens at the DNS layer (Protective DNS) — which assumes browser policy stops DoH bypass.

## Domain age and randomness { #age-randomness }

A new domain is "one vote towards malicious"; a registered domain that is itself random is nearly always bad. Subdomains of legitimate services are random too, so judge by the registered domain.

### Domain age

- Attackers buy domains just before an attack (buy early and you get noticed; they're discarded quickly anyway; each campaign needs its own name).
- Check: `whois example.com | grep -i creation` → `Creation Date: 1995-08-14...`. A WHOIS query doesn't touch the attacker's servers, so it is quieter than a DNS lookup.
- The "new" threshold (7/30/90 days) is the organisation's choice. Shorter = more precise but misses more.
- **New to us**: old on the internet but first seen in our organisation — catches compromised old sites too. Better as a supporting signal than a standalone alert.
- Bulk processing needs automation (e.g. Mark Baggett's `domain_stats`; check its current maintenance status).

### Randomness and length

- DGA: malware computes hundreds of names a day **deterministically** (often seeded by date); the attacker registers just one. Block one and tomorrow there's another — hard to block.
- But the footprint is large: **random registered domains + NXDOMAIN spikes**.
- How randomness is judged: character-pair frequency (`freq.py`), entropy, machine learning.
- **Legitimate subdomains are random too** (`d1a2b3...cloudfront.net`, `r3---sn-...googlevideo.com`) → judge by the registered domain. Abnormally long, random subdomains suggest DNS tunnelling (see [DNS abuse](dns-abuse.md)).
- Long domains are suspicious. Exception: `llanfairpwllgwyngyllgogerychwyrndrobwllllantysiliogogogoch.co.uk`.

| Example | Naive randomness check | Real judgement |
| --- | --- | --- |
| `d3k9x7qplm2v8.cloudfront.net` | Fires (subdomain) | Registered domain `cloudfront.net` → normal on randomness. Attackers use CloudFront too, so not a "safe" guarantee |
| `xvqkplmzrtb.top` | Fires | The registered domain itself is random + cheap TLD → suspicious. Check NXDOMAIN, age, other hosts |
| `xn--80ak6aa92e.com` | Fires (Punycode) | Not random — the encoded form of non-ASCII letters. Decodes to the famous Cyrillic "apple" look-alike → *more* suspicious ([IDN](blockchain-dns-and-idn.md#idn)) |

### How domain age is faked, and how to check

WHOIS/RDAP shows **one snapshot of the current state**; there is no "owner changed on" field. An old creation date doesn't mean "same owner for a long time".

| Route | Creation date | Clue |
| --- | --- | --- |
| Fully deleted, then registered fresh (drop catch) | **Reset to the new date** → age signal works | Recent creation date |
| Bought at an expired-domain auction before deletion | Original date kept | Recent Updated Date, registrar/NS change |
| Bought from / transferred by the previous owner | Original date kept | Recent Updated Date, registrar/NS change |
| Bought early and left to age | Old | No real use for a long time → sudden recent activity |

- Caution: "a re-bought expired domain keeps its original creation date" is only half true. If it was fully deleted and re-registered, the date resets; it is kept only for pre-deletion auctions or direct purchase.
- More checks: Updated Date, registrar change, NS change history (passive DNS), a gap in A records followed by sudden activity (passive DNS), historical WHOIS services (mostly paid; owner data is redacted since 2018 but dates, registrar and NS are still useful), first certificate issuance (crt.sh), changes in web content (Wayback Machine).

!!! info "2026 view"
    - WHOIS → RDAP: structured (JSON) results. As far as I know ICANN made RDAP the official standard for gTLDs from early 2025. Owner data is mostly `REDACTED FOR PRIVACY`; creation date is usually visible.
    - "Newly Observed Domain" is now a standard security-product feature.
    - Dictionary DGAs (`summerhousetable.com`) evade character-pair checks → combine with NXDOMAIN spikes, age, lookup patterns, ML.
    - [Caution] Punycode (`xn--`) causes randomness false positives *and* is a look-alike attack vector. Decode it first.

## ASN and geolocation { #asn-geo }

Add "whose network is this (ASN)" and "which country (geolocation)" to an IP. Both are weak alone; the main use is "does the claim match the source?".

### ASN

- AS = a network run independently by one organisation; ASN = its number (the entity announcing IP blocks in BGP). E.g. AS15169 Google, AS8075 Microsoft, AS16509 Amazon, AS13335 Cloudflare, AS1221 Telstra.
- Lookup: `whois -h whois.cymru.com " -v 8.8.8.8"` → AS, BGP prefix, country, registry, AS name. Web: bgp.he.net, ipinfo.io. A downloaded database (MaxMind etc.) leaves no external trace.
- Example: `ChromeSetup.exe` from Google's ASN is natural; from another ASN (e.g. AS4134, which once topped Spamhaus's botnet list) suspect a fake installer.
- Rule idea: alert on "executable downloaded from a top-10 risky ASN".
- Limit: attackers rent cloud, so the ASN shows Amazon, Google, DigitalOcean → less useful for inbound attacks, but trends are visible.
- [Added] The ASN **type** is more useful than the name: residential / mobile / enterprise / hosting. A human account logging in from a hosting ASN is suspicious.
- [Caution] Brands also distribute through CDNs (large software vendors on Akamai, etc.). Don't conclude from "ASN isn't the brand name" alone — check whether it is that brand's CDN.

### Geolocation

- Not much use as a whole: web traffic goes everywhere, and anycast CDNs blur location → **split by direction and protocol**.
- Inbound: geo-restrict staff-only services (VPN, portals). A **travel/deployment exception process** is mandatory.
- Outbound: ignore web; pay attention to SSH, FTP etc. going to unexpected countries.
- Rarely a rule on its own — "one more vote" on something already suspicious.
- Map charts have little technical value but real value for convincing executives and budgets.
- ASN + location = a concrete picture: "a US data centre" vs "a US home".

??? question "Review Q&A"
    - `AdobeReader_Update.exe` + `adobe-update-center.top` + a small overseas VPS ASN: both the claim (Adobe) and the source mismatch. The registered domain `adobe-update-center.top` is not Adobe (a brand-stuffed look-alike), cheap TLD; also check age, reputation, new-to-us. Next: did it execute? (Sysmon Event ID 1 process creation, Event ID 11 file creation, Security 4688 new process), search by hash (no upload), isolate if executed, block the domain, check other hosts.
    - "Block all VPN logins from outside Australia": cuts a lot of noise such as brute force from overseas IPs. But it does **not** block "all malicious attempts from overseas" — attackers route through Australian residential proxies, Australian cloud regions and compromised Australian servers. Other limits: blocks travelling/deployed staff, geo-database errors block legitimate users, false sense of safety.

!!! info "2026 view"
    - **Residential proxies**: attackers rent home IPs in any country or city, so location and ASN both look normal → pair with phishing-resistant MFA (security keys, passkeys) and managed-device conditions.
    - Key cloud sign-in signals: impossible travel, hosting-ASN logins, never-seen countries. VPNs cause frequent false positives.
    - Bad-ASN rankings change over time. Block whole large-carrier ASNs with care; prefer narrow, conditional rules.
    - [Caution] Geolocation is an estimate. Country level is mostly reliable; city level is a hint. In reports write "the IP is registered to country X".
    - [Added] IP location ≠ attacker location — it is only the last hop. Attribution is a separate job.

## Eight name-only signals — summary { #signals-summary }

A well-filtered, well-enriched DNS log catches a lot of evil from the domain name alone — and that many organisations don't collect DNS logs because they wrongly think they are low-value and high-volume.

| Signal | In one line |
| --- | --- |
| TLD | Heavily abused TLDs like `.top`; TLDs not on the IANA list (blockchain) |
| Reputation | Bad reputation is evidence; good reputation is not a guarantee |
| Age | New domains + "new to us", RDAP |
| Randomness | DGA. Beware Punycode and CDN false positives |
| Length | Long subdomains = tunnelling; long registered domains = phishing |
| Rank [Added] | Not on a popularity list (Tranco etc.) → look closer. On the list ≠ safe |
| IP reputation | Response IP's ASN, residential proxies, shared hosting |
| IDN | `xn--`, mixed scripts + brand comparison |

### Rank [Added] { #rank }

- A top-sites list: on it = a common name, not on it = a rare name.
- [Changed] Alexa Top 1M shut down in May 2022 → Tranco (combines several lists to resist manipulation), Cisco Umbrella Popularity List, Cloudflare Radar.
- In a SOC it's mostly used to filter (lower the score).
- [Caution] A high rank isn't safety: popular platforms (`drive.google.com`, `github.com`, `*.workers.dev`) are attacker favourites → look at them by subdomain or URL. Rank lists can be manipulated with bot lookups.

### Walking one log line through the signals [Added] { #signal-walkthrough }

```
ts=2026-10-19T02:14:07Z  id.orig_h=10.20.4.57  query=a8f3k2.x7qpz9wm.top  qtype_name=A  rcode_name=NOERROR  answers=185.199.xx.xx  TTLs=60
```

1. **TLD**: `.top` → score up (never decisive alone)
2. **Registered domain / randomness**: by Public Suffix List, `x7qpz9wm.top` — unreadable = DGA-shaped
3. **Length**: long, ever-changing subdomains → tunnelling; a long registered domain → phishing
4. **Age**: RDAP creation date, and "first time seen in our organisation"
5. **Rank**: not on any popularity list
6. **Reputation**: bad = evidence; nothing at all may just mean nobody has reported it yet
7. **IP reputation**: ASN type of the response IP; `TTLs=60` (CDNs use it too, but it also fits fast flux)
8. **IDN**: no `xn--`

Signals only give you a reason to look further; the verdict comes after you add **who** (which host, which process) and **what next** (the actual connection, bytes, regular intervals).

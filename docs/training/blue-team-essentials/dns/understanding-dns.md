---
title: "Understanding DNS — Structure and Records"
tags:
  - training
  - blue-team
  - dns
  - concept
---

# Understanding DNS — Structure and Records

!!! abstract "What this page covers"
    The four DNS server roles and the recursive lookup path, TTL and caching, record types (A, AAAA, PTR, TXT, CNAME, MX, SRV, NS, HTTPS), the security risk attached to each (subdomain takeover, domain hijacking), and how to read DNS packets in Wireshark.

!!! note "Conventions"
    **[Added]** = practical must-knows, **[Correction]** = a commonly repeated mistake, **[Changed]** / **[Caution]** = what changed recently and what is risky if done the old way. See the [DNS overview](index.md) for the whole path and the [triage sheet](triage-sheet.md) for the per-log-line checklist.

## Ten key points { #key-points }

1. DNS only hands out the address. The real connection happens afterwards, so read DNS logs together with connection (firewall) logs.
2. Behind a forwarding server the original client IP disappears. Sensor placement decides visibility.
3. Answers are found root → TLD → authoritative server, and cached for the TTL at every step.
4. One domain can resolve to several IPs. Record all of them, investigate all of them.
5. PTR queries are written backwards in `in-addr.arpa` form. Always reverse them before reading.
6. The IP owner can put any name in a PTR. It is a hint, not evidence.
7. Domains and IPs are many-to-many and change at any time. Never judge a past incident by today's answer.
8. Before blocking a malicious domain's IP, count how many internal hosts talk to that IP. If it is shared, block the domain.
9. The canonical name in a CNAME is the name in the *answer*. An orphaned CNAME leads to subdomain takeover.
10. Lose your NS and you lose the whole domain — web, mail and certificates.

## DNS basics — four server roles and the lookup path { #servers }

DNS turns names into IPs, and in almost every investigation you end up recording "the IP + the domain that pointed to it".

### The four roles

| Role | Where / example | What it does | Caches? |
| --- | --- | --- | --- |
| Stub resolver | Your PC (Windows DNS Client) | Answers from its cache, otherwise passes the question to its configured server | Yes |
| Forwarding server | Corporate domain controller, home router | Passes unknown questions upward; never walks the tree itself | Yes |
| Recursive (caching) server | 8.8.8.8, 1.1.1.1, 9.9.9.9, ISP DNS, Pi-hole | Walks the tree from the root itself | Yes |
| Authoritative name server | ns1.google.com | Holds the master copy of its own zone | No |

The single most important point: **a forwarding server does not pass the question along — it builds a new question from its own IP.** Any log collected above the forwarder shows every client as that one server IP.

### The recursive path

1. PC → corporate forwarder → recursive server
2. Recursive → root ("."): "Don't know — ask the .com servers"
3. Recursive → .com: "Don't know — ask ns1.google.com"
4. Recursive → authoritative: the real IP
5. The answer travels back down and is cached by the recursive server, the forwarder and the PC

The recursive server does all of steps 2–4. Each server only needs to know the layer below it. If another PC in the company asks the same name within the TTL, the forwarder answers from cache and nothing goes outside — so an outside sensor sees only the **first** lookup.

### TTL

TTL is "how many seconds you may trust this answer", set by the domain owner. Higher layers are long (root NS: 6 days); real service IPs are short (google.com A: 300 s).

- Short TTLs (≤ 60 s) are common for CDNs and cloud. Attacker fast flux looks the same, so TTL only means something combined with other signals.
- The remaining TTL in `ipconfig /displaydns` lets you back-calculate when the lookup happened: original 300, remaining 187 → looked up about 113 s ago.

### Commands to see it yourself

- Windows cache: `ipconfig /displaydns`, `Get-DnsClientCache` (`Record Type 1` = A, `5` = CNAME)
- Linux cache: `resolvectl show-cache`, `resolvectl statistics`
- Lookup path: `dig +trace google.com A`

### Transport

Default is UDP 53; if the answer is too big the TC flag is set and the client retries over TCP 53. Today there is also DoH (TCP 443), DoT (TCP 853), DoQ (UDP 853) and DoH over HTTP/3 (UDP 443), so watching port 53 alone misses things. There are 13 root server names but, thanks to anycast, thousands of physical machines worldwide.

## Record types and A/AAAA { #records }

The record type is "the kind of question you ask DNS". Ask the same name for A and you get an IP; ask for MX and you get mail servers.

### Type numbers

| Type | No. | Asks for | Note |
| --- | --- | --- | --- |
| A | 1 | Name → IPv4 | Most common |
| AAAA | 28 | Name → IPv6 | Usually paired with A |
| NS | 2 | Name of the authoritative server | |
| CNAME | 5 | Alias → canonical name | |
| SOA | 6 | Zone metadata | |
| PTR | 12 | IP → name | |
| MX | 15 | Mail server | |
| TXT | 16 | Arbitrary text | |
| SRV | 33 | Service location + port | |
| SVCB | 64 | Service binding info | Relatively recent (RFC 9460, 2023) |
| HTTPS | 65 | HTTPS connection info | Relatively recent; now very common |

Some logs store only the number, so know 1, 28, 5, 12, 16 and 65 by number too.

### Five things to take from an A/AAAA exchange

- **Question** — the name asked. Repeated in the response packet for matching.
- **Answer** — the IP(s). **There can be several.** Record only the first and you may miss the IP actually connected to.
- **Transaction ID** — 16-bit ticket that pairs question and answer.
- **TTL** — cache lifetime in seconds.
- **Source/Destination IP** — the destination server did not necessarily know the answer; above a forwarder, the source may not be the real client.

### Practical points

- One page visit triggers dozens to hundreds of lookups (e.g. one visit to a large portal → 60 A + 95 AAAA). When one lookup looks suspicious, lay out the same PC's lookups a few seconds either side to find where it started.
- "40 lookups a second" alone does not mean infection. Random-string names + NXDOMAIN spikes + no originating site + 3 a.m. + an odd process, together, look like DGA.
- A and AAAA in pairs are normal.
- Cache-poisoning defence is Transaction ID **plus** source-port randomisation. A resolver with a fixed source port is a vulnerability.

### [2026] What the HTTPS record (65) changed

Example: `dig -t HTTPS cloudflare.com +short` → `1 . alpn="h3,h2" ipv4hint=104.16.132.229 ech=...`

- `alpn="h3"` lets the browser go straight to HTTP/3 (UDP 443). Watching TCP 443 only misses it.
- `ipv4hint` means a connection can happen with no A lookup at all — the "connection without DNS = suspicious" rule weakens.
- `ech=` is the ECH public key. With ECH the site name (SNI) disappears from the wire, which makes DNS logs more valuable.

## PTR — reverse lookups { #ptr }

PTR asks IP → name (a reverse phone-book lookup). Two traps: the address is written backwards, and the result cannot be trusted.

### Trap 1: it is written backwards

`nslookup 8.8.4.4` actually sends a query for `4.4.8.8.in-addr.arpa`.

- Why: DNS names get bigger to the right (`www.google.com`), IPs get bigger to the left (`8.8.4.4`), so the IP is reversed to match.
- `in-addr.arpa` is the zone reserved for reverse lookups.
- How to read it: drop the suffix and reverse the order of the four octets. Do **not** reverse digits inside an octet.
- Example: `36.129.85.203.in-addr.arpa` → `203.85.129.36`
- Common mistake: pasting it unreversed into a threat-intel site, getting a clean result for the wrong IP, and closing the case.
- IPv6 uses `ip6.arpa` and reverses each hex nibble. Don't do it by hand — use `dig -x <IP>`.

### Trap 2: don't trust it

Conclusion: don't rely on what a PTR record says.

- The **domain owner** sets A; the **IP owner** sets PTR. They can be different people.
- The IP owner can put someone else's domain in the PTR.
- Even with thousands of sites behind one IP, the PTR returns the one name the IP owner chose.
- Even Google doesn't match: `google.com` → `142.250.6.206` → PTR `lga25s72-in-f14.1e100.net`
- Cloud PTRs (`ec2-...amazonaws.com`) only tell you "somewhere in the cloud".

### FCrDNS (Forward-Confirmed reverse DNS)

1. PTR lookup on the IP → get a name
2. **Forward (A) lookup** on that name → does it return the original IP?

If it does, the domain owner has also claimed that IP — an attacker cannot change someone else's A record. Mail servers use this for spam scoring. Passing proves "same owner", not "safe".

### How to use PTR

- As a hint only: residential line? cloud? Tor? Internal PTRs are relatively trustworthy.
- Decide with WHOIS/RDAP (registered owner), ASN (network operator) and passive DNS (domains that IP has served).
- [Caution] A PTR lookup on an attacker IP goes to the attacker's DNS server and leaves a trace. Check tools for automatic reverse resolution too.
- [Caution] An internal PC doing PTR lookups in sequence (`1.5.0.10`, `2.5.0.10`, …) is internal scanning; nmap does PTR lookups by default.
- The old `8.8.4.4` → `google-public-dns-b.google.com` has, as far as I know, since become `dns.google` — a live example of PTRs changing.

## Many-to-many mapping and the IP-block accident { #many-to-many }

Domains and IPs are two separate maps kept by different people, and each changes independently at any time.

### Four rules

1. One domain → many IPs, or none. A domain owner can point at **someone else's IP** without permission.
2. Many domains → the same IP, or none. CDNs and shared hosting put thousands of sites behind one IP (one apartment block, hundreds of flats).
3. IP → any name (PTR is up to the IP owner).
4. All of the above can change at any time.

### The classic accident

`c703[.]info` (malicious) points at a Google IP → the analyst blocks that IP at the firewall → the whole company loses Google. The intel wasn't wrong; the mistake was assuming "that IP belongs only to that domain". The fix: before you block an IP or domain, check your logs first.

- `[.]` is the "defang" convention so nobody clicks by accident — use it when writing malicious domains in reports.
- A malicious domain pointing at `127.0.0.1` or `0.0.0.0` is not harmless — it may be **parked** (dormant) or sinkholed. An internal PC still looking it up is still infected.
- Investigate past incidents with **records from that time** (our DNS logs, passive DNS), not today's answer. Write "this IP as of HH:MM" in your notes.

### Checklist before blocking an IP

- [ ] How many internal hosts talk to this IP? (1–2: consider; hundreds: don't)
- [ ] Per WHOIS/ASN, is it shared infrastructure — Cloudflare, AWS, Google, Microsoft, Akamai?
- [ ] Do our DNS logs / passive DNS show other (legitimate) domains on the same IP?
- [ ] If there were several answer IPs, did you check them all — and which one was actually connected to?
- [ ] Would a domain block (DNS sinkhole / DNS firewall) be enough?
- [ ] If you block, did you set an expiry (30–90 days) and record the reason (case number, date, owner)?

!!! info "2026 view"
    - CDN growth means a malicious domain is far more likely to sit on a shared IP. For web threats, IP blocking fits less and less; domain blocking is the default.
    - With ECH, network devices struggle to tell sites on the same IP apart by name. The reliable enforcement points are the DNS layer and the endpoint (EDR).
    - Attackers use legitimate services (GitHub, Google Drive, Telegram) for C2 — *Living off Trusted Sites*. Domain and IP are both genuine, so detect on behaviour.
    - An IP block with no expiry breaks things six months later when the IP is reassigned to a partner.
    - Before feed-driven auto-blocking (SOAR), add an allow list of major cloud/CDN ranges and an automatic "how many internal hosts talk to this" check.

## TXT — a box for text { #txt }

TXT attaches arbitrary text to a domain. It is central to mail anti-spoofing and domain-ownership proof — and also a covert channel for attackers.

### Basics

- Any printable ASCII; binary is base64-encoded first.
- A name can have several TXT records.
- [Correction] The "255-character limit" applies to each quoted string. A record can hold several strings that are concatenated — that is how 400+ character DKIM keys fit.

### The three mail-authentication records

| Name | Where | What it checks | Example |
| --- | --- | --- | --- |
| SPF | TXT on the domain | May this server send mail as this domain? | `v=spf1 include:_spf.google.com ip4:203.0.113.10 -all` |
| DKIM | TXT at `<selector>._domainkey.<domain>` | Has the content been tampered with? (signature) | `v=DKIM1; k=rsa; p=MIIB...` |
| DMARC | TXT at `_dmarc.<domain>` | Policy on failure + alignment with the visible From | `v=DMARC1; p=reject; rua=mailto:...` |

- SPF terminators: `-all` reject, `~all` soft-fail, `?all` neutral, `+all` anyone (worst).
- DMARC policy: `none` report only, `quarantine` spam folder, `reject` reject. `rua` reports show who is spoofing your domain.
- [Correction] "SPF records start with spf=" is a common mistake — SPF starts with `v=spf1`.
- [Added] DMARC is just as essential. In February 2024 Google and Yahoo made SPF + DKIM + DMARC mandatory for bulk senders, and Microsoft followed for Outlook.com in 2025.

### Reading an SPF/DKIM pass

- What it means: sent from an authorised server (SPF), content unchanged (DKIM).
- Trap 1: pass **for which domain**? The attacker's `micros0ft-billing.com` passes for itself.
- Trap 2: SPF checks the envelope sender (Return-Path), which can differ from the visible From — DMARC alignment closes that gap.
- Trap 3: a compromised genuine account (BEC) passes SPF, DKIM and DMARC.
- Bottom line: authentication confirms identity, not intent.

### Domain-ownership proof

Services hand you a string to publish as TXT (`facebook-domain-verification=...`, `MS=...`, `google-site-verification=...`). [Added] These records reveal which SaaS the company uses — useful recon for tailored phishing. Remove them for services you no longer use.

### Why attackers abuse it

It can hold anything, DNS is almost always open, and mail servers make TXT lookups common enough not to stand out. An infected PC asks for the TXT of `cmd.evil-c2.xyz` and gets a base64 command back. Many TXT lookups from an ordinary (non-mail) PC are suspicious — detection is covered in [DNS abuse](dns-abuse.md).

## CNAME and subdomain takeover { #cname }

CNAME says "this name is an alias — go and ask that name instead". Neglect it and an attacker can take over a company address.

### Basics

- Ask for A and you get the CNAME plus the canonical name's A (CNAME chasing).
- **Canonical name = the name in the answer.** The name you asked is the alias. This is the most-missed exam point.
- Uses: pointing several names at one server, and today mostly handing off to external services (`shop.mycompany.com` → `mycompany.myshopify.com`).
- CNAMEs pointing at each other loop forever. In practice CDNs create 3–4-step chains, so read **the whole response chain** to see the final destination.
- Ordinary PCs rarely query type CNAME directly (they ask for A and get the CNAME as a bonus).

### Dangling CNAME → subdomain takeover

1. `promo.mycompany.com` CNAME `mycompany-event.herokuapp.com` hosts an event page.
2. After the event the Heroku app is deleted, but the CNAME stays.
3. The target now returns NXDOMAIN — "this spot is free, anyone can take it".
4. The attacker creates an app with the same name → attacker content on the genuine company address (credential phishing, malware, fake notices).

Training users to "check the domain in the address bar" does not help, because the address *is* genuine.

### When you find one

- [ ] Quickly confirm with the owning team whether the service is still in use (don't let it sit for days)
- [ ] Delete the CNAME (first choice). If still needed, re-create the target name yourself to claim the spot
- [ ] Check whether any other CNAME is already taken over (normal response, content we never made)
- [ ] Audit every CNAME pointing outside: `*.azurewebsites.net`, `*.cloudapp.azure.com`, `*.herokuapp.com`, `*.s3.amazonaws.com`, `*.github.io`, `*.myshopify.com`
- [ ] Process rule: **when retiring a service, delete the DNS record first, then the service**

Cloud providers have added protections such as TXT-based ownership checks, but I'm not certain they cover every service and setting, so cleaning up on our side is the dependable defence. Products that automate this audit are called EASM (external attack surface management).

!!! info "2026 view"
    - With cloud and SaaS everywhere, subdomain takeover is much more common than a few years ago.
    - CNAME can't be used at the zone apex (`mycompany.com`); the HTTPS/SVCB record's AliasMode fills that gap.
    - CNAME cloaking: ad/tracking vendors hide behind first-party names like `metrics.mycompany.com` that CNAME to them. "Company address" may not mean "company server".

## MX, SRV, NS { #mx-srv-ns }

Simple concepts, each with one security risk attached: MX — mail interception, SRV — internal recon, NS — full domain takeover.

### MX — mail servers

- Mail delivery in three steps: look up the recipient domain's MX → look up that name's A → SMTP to port 25 on that IP.
- The number in front is preference — **lower goes first**; equal numbers load-balance.
- MX must point at an FQDN with A/AAAA. No bare IPs, no CNAMEs.
- [Correction] The often-cited RFC 974 is superseded by RFC 5321 (same rule).
- Security clues: mass MX lookups from an ordinary PC = spambot; a phishing domain's MX shows intent (none = click-only, Gmail/Outlook = wants replies, self-hosted = infrastructure lead); a change to *our* MX = mail-interception emergency.
- [Added] For domains that never send mail: Null MX (`MX 0 .`, RFC 7505) + `v=spf1 -all` + DMARC `p=reject` stops spoofing.

### SRV — service location

- Format `_service._proto.name` (underscores separate it from host names).
- Answer: `priority weight port target`, e.g. `0 100 389 dc01.corp.local.` — it even gives you the **port**.
- Key AD queries: `_ldap._tcp.dc._msdcs.<domain>` (domain controllers), `_kerberos._tcp.<domain>` (authentication), `_gc._tcp.<domain>` (Global Catalog).
- SRV lookups should only be visible on the internal network → if they leave, your internal domain name leaks.
- Recon signals: many SRV types in a short burst, at night, from a device that never does it (printer, server), from an odd process. But an MFP may legitimately use LDAP for scan-to-email address books, so **compare to baseline**.
- MFPs and IP cameras patch slowly and have no EDR, making them attacker footholds.

### NS — the name of the server with the answers

- NS lives in two places: a **referral copy** at the parent TLD (entered at your registrar) and the **master** on the authoritative server.
- Why: you can't ask the authoritative server if you don't know who it is — the parent's copy breaks the chicken-and-egg problem.
- If the two differ: lame delegation (a cause of intermittent resolution failures).

### Domain hijacking (NS takeover)

Point NS at an attacker server and the attacker controls A, MX and TXT — and can pass TXT ownership checks to get a **genuine HTTPS certificate** in the company's name. The main route is not hacking DNS but **taking over the registrar account**. Real examples: the 2018–2019 Sea Turtle and DNSpionage campaigns against government and telco domains; in 2024 the "Sitting Ducks" pattern (hijacking domains whose DNS-provider account no longer exists) was published.

Response order after an incident:

1. **Recover**: restore NS at the registrar. If you can't log in, use the registrar's emergency contact (have it ready beforehand).
2. **Lock down**: change passwords, kill all sessions, MFA, Registry Lock, check whether the account's contact email was changed.
3. **Ride out**: for the NS TTL (e.g. 172800 s = 2 days) some resolvers still go to the attacker even after recovery.
4. **Find the damage**: check crt.sh (Certificate Transparency) for rogue certificates and revoke them; assume mail and password-reset emails during the window were intercepted and review key accounts.
5. **Notify**: tell customers, partners and staff to re-verify any requests from that window (especially bank-detail changes).

Prevention: registrar MFA, Registry Lock, change alerts on NS/MX/SPF, DNSSEC (useless on its own if the account is taken). When retiring a service, clean up DNS first. **Before an incident the first control is MFA; after an incident the first action is recovery.**

## Reading packets — DNS on the wire { #on-the-wire }

A capture mixing A, CNAME and PTR query/response pairs (client IP and transaction IDs are illustrative).

```
No. Source         Destination    Info
1   192.168.1.156  1.1.1.1        Standard query 0x1a2b A example.com
2   1.1.1.1        192.168.1.156  Standard query response 0x1a2b A example.com A 1.2.3.4 A 162.255.119.240
3   192.168.1.156  1.1.1.1        Standard query 0x3c4d CNAME mail.google.com
4   1.1.1.1        192.168.1.156  Standard query response 0x3c4d CNAME mail.google.com CNAME googlemail.l.google.com
5   192.168.1.156  1.1.1.1        Standard query 0x5e6f PTR 27.208.194.173.in-addr.arpa
6   1.1.1.1        192.168.1.156  Standard query response 0x5e6f PTR 27.208.194.173.in-addr.arpa PTR ql-in-f27.1e100.net
```

### How to read it

- `query` = question, `query response` = answer. The answer line repeats the question, then the answers.
- Same ticket (`0x...`) = one pair.
- In a response line, each type label starts one answer (three `A`s on line 2 = the question + two answers).
- Wireshark filters: `dns`, `dns.flags.response == 0` (questions only), `dns.qry.type == 12` (PTR only).

### Questions and answers

| Question | Answer | Point |
| --- | --- | --- |
| 1. Domain looked up with A | `example.com` | Right after the type label in the query |
| 2. Resolved IPs | `1.2.3.4`, `162.255.119.240` | Two — one alone is wrong. `1.2.3.4` is a placeholder → a domain owner can publish any IP |
| 3. Canonical name of Google's mail host | `googlemail.l.google.com` | Canonical = the name in the answer |
| 4. IP looked up via PTR | `173.194.208.27` | Reverse the octets |
| 5. DNS server used | `1.1.1.1` (Cloudflare) | The query destination — but the capture only shows the PC ↔ 1.1.1.1 leg |
| 6. (Bonus) Problem if this is a corporate PC | Bypassing company DNS to use an external resolver | No logs, domain blocking defeated, internal names leak. Block outbound 53 + alert on attempts. With DoH it wouldn't even look like this |

### MX → A → PTR investigation flow

The IP in question 4 came from `gmail.com` MX → `gmail-smtp-in.l.google.com` → A `173.194.208.27` → PTR `ql-in-f27.1e100.net`. Forward and reverse names differ — another "don't trust PTR" example. Use the same order (MX → A → compare with the sending IP in the headers) to check whether a phishing email's sending server is genuine.

---
title: DNS
tags:
  - training
  - sec450
  - blue-team
  - dns
---

# DNS

<div class="dfir-meta" markdown>
**Course:** SANS SEC450 (2022) Book 2 · **Modules:** Understanding DNS (p.31–50) → DNS Analysis and Attacks (p.51–85)
</div>

!!! abstract "In one line"
    Almost every attack passes through DNS at least once, and a well-filtered, well-enriched DNS log catches a surprising amount of evil from the domain name alone. In 2026, though, encrypted DNS (DoH/DoT/DoQ) and ECH mean the network shows less and less — **company DNS server logs + endpoint logs (Sysmon 22, EDR)** are now the centre of gravity.

## Reading order

| # | Page | Course | Key points |
| --- | --- | --- | --- |
| 1 | [Understanding DNS — structure and records](understanding-dns.md) | p.31–50 | Four server roles, recursion, TTL, A/AAAA/PTR/TXT/CNAME/MX/SRV/NS/HTTPS, subdomain takeover, domain hijacking, reading packets |
| 2 | [DNS log collection and safe investigation](collection-and-investigation.md) | p.51–56 | Sensor placement, pivoting to firewall logs, OPSEC-ordered lookups, the four detection steps |
| 3 | [Domain signals](domain-signals.md) | p.57–62, 85 | TLD, reputation, age, randomness (DGA), ASN, geolocation, rank |
| 4 | [DNS abuse](dns-abuse.md) | p.63–73 | Unauthorised DNS and its six traces, shared hosting, record tampering, DNS tunnelling |
| 5 | [Blockchain DNS and IDNs](blockchain-dns-and-idn.md) | p.74–79 | EmerDNS, ENS, gateways, EtherHiding, Punycode, homoglyphs, IDNs inside apps |
| 6 | [Encrypted DNS](encrypted-dns.md) | p.80–85 | DoT/DoH/DoQ/DNSSEC, responding to DoH, DoH in Wireshark, 2026 collection strategy |
| 7 | [Suspicious DNS triage sheet](triage-sheet.md) | All | Principles, per-field signals, workflow, false positives, course corrections, common confusions |

## Ten things to remember

1. DNS only hands out addresses; the connection happens separately — read DNS logs together with firewall logs.
2. A forwarding server replaces the client IP with its own. Sensor placement decides what you can see.
3. The IP owner can put any name in a PTR record. It is a hint, not evidence.
4. Domains and IPs are many-to-many and change at any time. Don't block shared (CDN) IPs — block the domain.
5. Judge ownership **from the right, by registered domain**.
6. Bad reputation is evidence; good reputation is not.
7. Lookup order: our own logs → passive DNS → (from a non-attributable environment) a fresh lookup. Never `nslookup` a suspicious domain from a corporate host.
8. Blocking outbound 53 does not stop tunnelling that rides the company resolver. The firewall blocks the *path*; the DNS server blocks the *destination*.
9. Always decode `xn--`. Mixed scripts + brand similarity.
10. Never conclude from one signal. Add **who · what · where · what next** before you judge.

## Related reference pages

- [Zeek dns.log](../../../network/zeek/dns-log.md) — field-by-field
- [Beaconing & C2 detection](../../../network/beaconing-c2.md) — regular-interval lookups and connections
- [Windows event logs](../../../windows/event-logs.md) — Sysmon and Security events

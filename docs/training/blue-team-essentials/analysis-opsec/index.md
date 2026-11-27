---
title: Analysis OPSEC
tags:
  - training
  - blue-team
  - soc
  - analysis
  - opsec
---

# Analysis OPSEC { #analysis-opsec }

!!! abstract "In one line"
    The investigation section showed how to research alerts; this section is about researching them **without tipping off the attacker**. It covers what operational security means for an analyst and why it matters far more in targeted than in opportunistic attacks, the rules for sharing and acting on intelligence (the Traffic Light Protocol and the Permissible Actions Protocol), and then the practical habits: passive sources first, knowing what each OSINT tool shares, search versus scan, the common OPSEC failures (public IOC submission, interacting with attacker infrastructure, premature blocking), unattributed connections, analysis machines and Tor.

## Reading order { #reading-order }

| # | Page | Key points |
| --- | --- | --- |
| 1 | [Analysis OPSEC — What It Is, Who It Protects, and Sharing Rules with TLP and PAP](opsec-tlp-pap.md) | OPSEC as denying the adversary knowledge of dispositions, capabilities and intentions, mapped to SOC work; targeted vs opportunistic and the tactical advantage of not being noticed; one targeted phishing link seen from the attacker's own BIND query log and web logs, field by field (corporate resolver and egress IPs, per-recipient token, Linux user agent, `HeadlessChrome` scanner) with quieter alternatives (T1583.001, T1583.002, T1608.005, T1566.002) and Sysmon 22 to catch analyst slips; personal, attacker and analyst OPSEC and the actions that leak; TLP 2.0 (CLEAR, GREEN, AMBER, AMBER+STRICT, RED) with marking rules and four invented reports handled; PAP (CLEAR/WHITE, GREEN, AMBER, RED) with a MISP-style tagged event read line by line and an action plan; TLP and PAP as independent labels and a decision flow; 2026 view (TLP 2.0 and CISA, PAP:CLEAR, Defender TI changes, anti-analysis phishing kits, AI tools and labelled data); practice questions |
| 2 | [Researching Safely — Passive Sources, Search vs Scan, Common OPSEC Failures, Unattributed Connections and Tor](passive-osint-failures.md) | Passive searching as the ideal, with a Mermaid flow; an invented passive-DNS result read column by column and a pivot on the IP to two more lookalike domains; the three questions to ask any OSINT tool (fresh scans, file sharing, revealed lookups) and testing with a canary domain whose BIND log shows the "search" resolving it; search vs scan vs file and URL submission; `sha256sum` hash-first with three outcomes and a real invoice saved from upload; failure 1 — public IOC submission and automated submission by SOAR and gateways; failure 2 — DNS lookups, probing and identifiable downloads shown in attacker web logs (`Wget`, directory listing), passive alternatives and mimicking the real client; one careful `curl` through Tor read flag by flag (`socks5h` vs `socks5` DNS leak) (T1105); unattributed lines and analysis hosts with revertible REMnux/Windows VMs; Tor layers relay by relay and what it doesn't hide (application data, DNS, unique URLs, listed exits), Tails; failure 3 — the premature block, PC1/PC2 and fallback C2 (T1008) seen in Zeek `dns.log` as TXT-based DNS C2 (T1071.004); section summary; 2026 view (urlscan visibility levels, private scanning, Defender TI, anti-analysis kits, Tor–Tails merger, automation risks); practice questions |

!!! success "Section complete"
    The analysis OPSEC section is complete. Next: **Reacting to Intrusions** — responding when an intrusion is discovered: dwell time, intrusion type, short-haul and long-haul backdoors, attacker motivation, business risk, what you know about the attacker, and choosing between watching and acting.


## Things to remember { #must-know }

1. Before any outward-facing step, ask: "Could this be targeted, and what will this action tell the attacker?"
2. In a targeted attack, the attacker not knowing that you know is an advantage worth protecting.
3. Attackers see their own DNS and web logs, and search the same public scanning sites you do.
4. Your own logs never tip anyone off — search them first.
5. TLP decides who may be told; PAP decides what may be done. Read both, set both.
6. TLP:GREEN is never public, and a source's extra limits always apply.
7. Search before you scan, hash before you upload — and test what your tools really do.
8. Interact only from an unattributed analysis machine; Tor hides your IP, not a unique URL.
9. Don't cut one C2 channel of a capable attacker before you know the others — unless harm is active.

## Related { #related }

- [Investigation Questions](../investigation/index.md) — the section before
- [Mental Models](../mental-models/index.md) — threat intelligence levels and cycles
- [Threat Intelligence](../../../threat-intel/index.md)

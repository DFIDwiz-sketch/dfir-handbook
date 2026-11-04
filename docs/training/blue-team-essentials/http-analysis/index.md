---
title: HTTP(S) Analysis & Attacks
tags:
  - training
  - blue-team
  - http
---

# HTTP(S) Analysis & Attacks { #http-analysis }

!!! abstract "In one line"
    HTTP is used in almost every stage of an attack (delivery, exploitation, installation, C2, exfiltration). Building on [HTTP fundamentals](../http/index.md), this section covers how to **judge malicious HTTP(S) traffic quickly and dig deep when needed** — from automated methods like reputation checks to header and content analysis, file extraction, anomaly hunting and HTTPS (TLS) analysis.

## Reading order { #reading-order }

| # | Page | Key content |
| --- | --- | --- |
| 1 | [Attack Stages over HTTP, Analysis Methods, URL Reputation](evil-http-and-reputation.md) | HTTP traces per kill-chain stage, choosing automated vs manual analysis, URL reputation and its traps, OPSEC and defanging, practice questions |
| 2 | [Screenshots, Sandboxes, and When to Go Manual](screenshots-sandboxes.md) | Confirming phishing with screenshots and reading results, which tools share, network-centric vs VM sandboxes and choosing one, sandbox evasion, combining weak signals manually, practice questions |

!!! info "Coming next"
    User-Agent analysis, cookies, Base64, file extraction, high-frequency GET/POST, connections to bare IPs, spotting exploit kits, HTTPS/TLS analysis.

## Things to remember { #must-know }

1. HTTP is used in almost every attack stage, and each stage looks different in logs.
2. Quick automated checks first; manual analysis when they don't give an answer.
3. No reputation result ≠ safe. Good domain ≠ safe URL.
4. Submitting to public scanners can leak information. Defang URLs in records.

## Related reference pages { #related }

- [HTTP fundamentals section](../http/index.md)
- [DNS domain signals](../dns/domain-signals.md) — judging domain age and reputation
- [Beaconing & C2 detection](../../../network/beaconing-c2.md)
- [Phishing delivery technique](../../../adversary/phishing-delivery.md)

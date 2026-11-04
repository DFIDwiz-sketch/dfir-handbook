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
| 3 | [Finding Malware through User-Agents and Cookies](user-agents-cookies.md) | Why malware is caught by its User-Agent, field-by-field breakdown and tools, frequency analysis (requests and PCs), version aging, C2 in cookies, a supply-chain case, cookie-abuse checklist, practice questions |
| 4 | [Base64 — How It Works, Recognising It, Suspicious Base64](base64.md) | Why it exists, bit-level conversion and padding, guessing file types from prefixes, decoding commands (incl. PowerShell UTF-16LE), legitimate uses (JWT, Basic auth, ViewState) vs suspicious Base64, practice questions |
| 5 | [Malicious Files on Good Sites, File Extraction, Frequent Requests, Bare-IP Connections](files-frequency-naked-ip.md) | Malware via cloud sharing, file extraction with Wireshark/tshark/Zeek and safety rules, spotting frequent regular GETs/POSTs, bare-IP connections and root POSTs, practice questions |
| 6 | [Spotting Exploit Kits, and Malicious/Suspicious/Benign Practice](exploit-kits-practice.md) | How exploit kits infect, traffic clues and how to confirm success, three practice judgements (inbound Log4Shell, dynamic-DNS redirect chain, jQuery-disguised C2), practice questions |
| 7 | [HTTPS — TLS Decryption, Working Without It, Reading Certificates](https-certificates.md) | Why encryption blinds the SOC, how TLS inspection works and its limits (pinning, privacy, root CA), what each layer shows without decryption, reading certificate fields (openssl, Zeek ssl/x509), suspicious-certificate signals, practice questions |

!!! info "Coming next"
    JA3/JA3S/JARM fingerprints (and JA4), what TLS 1.3 changes, and the module summary.

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

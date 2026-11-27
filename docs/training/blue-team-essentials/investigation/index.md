---
title: Investigation Questions
tags:
  - training
  - blue-team
  - soc
  - analysis
  - investigation
---

# Investigation Questions { #investigation }

!!! abstract "In one line"
    The structured-analysis section gave you methods for thinking; this section puts them to work on real evidence. It starts with how to begin an investigation — the four questions (what am I answering, what data would answer it, how do I get it, what does it tell me), the many network, host and alternative sources that hold the answer, when outside intelligence is needed, and how to extract the data with the right tool — then moves to interpreting it: network events layer by layer (IP and domain, ports, TLS certificates, application metadata and content), email links and phishing pages, targeted versus opportunistic attacks, and business email compromise.

## Reading order { #reading-order }

| # | Page | Key points |
| --- | --- | --- |
| 1 | [Starting an Investigation — The Question, the Data, Where It Lives and How to Get It Out](questions-and-data.md) | The Alexiou Principle as four questions and why it is decomposition; four invented alerts (credential-phishing landing page, VNC authentication failures, RAT check-in, PowerShell in a DNS TXT answer) with validation and follow-up questions (T1566.002, T1598.003, T1110.001, T1021.005, T1133, T1071.001, T1571, T1071.004, T1059.001); best data per question; every place one web connection is logged, with a Mermaid chart and `ipconfig /displaydns` read line by line; what ran, why it ran and the Windows artefacts (Prefetch, Shimcache, Amcache, MUICache, UserAssist, MRU lists, memory) with caveats; alert C confirmed by Prefetch, Amcache and a Run key (T1547.001); primary vs alternative sources table incl. 4624, 4768/4769, 4776; OSINT and closed-source intelligence, the submission catch; which console for which question and query languages; alert D end to end — Zeek `dns.log`, Sysmon 22, 4688 and 4104 field by field (T1204.002, T1027); 2026 view (identity-first evidence, less PCAP, AI-drafted queries, ATT&CK v19 split and v20); practice questions |
| 2 | [Analysing Network Events Layer by Layer — IP and Domain, Ports, TLS Certificates, Application Metadata and Content](analysing-network-events.md) | Interpreting evidence: all hypotheses, fresh eyes, try to disprove; encapsulation and why badness may show at one layer only (SSH upload, malware on trusted file sharing); five invented events; Layer 3 — attackers' own infrastructure, intel, prevalence, history, reverse/passive DNS, ASN, domain age, randomness, rank, length, subdomains; N1 SSH exfiltration read from `conn.log` and `ssh.log` with a `zeek-cut` prevalence check line by line (T1048.002); Layer 4 — ports and services, mismatches, non-standard, 4444/6667, random ports, why the destination port matters, port table; N2 IRC on port 80 (`service=irc`, `history`) (T1071); Layer 5 — SNI, suspicious/self-signed/expired certificates, JA3/JA3S and JA4 decoded, never-seen certificates, name mismatches; N3 self-signed C2 from `ssl.log`/`x509.log` (T1573.002, T1571, T1587.003); N4 SNI ≠ Host domain fronting (T1090.004) and CDN blocking; Layer 7 — metadata vs content; N5 ISO from cloud file sharing via `http.log`/`files.log` and Arkime extraction (T1566.002, T1608.001, T1204.002); five-event layer check-list; 2026 view (JA4+, TLS 1.3 and ECH (RFC 9849), free certificates and shorter lifetimes, AI scoring); practice questions |
| 3 | [Email Attacks and Assessing Links — Attachments, Lookalikes, Hacked Sites, Trusted Hosts and Shortened URLs](email-links-phishing.md) | Four email attack methods (attachments — executables, scripts, archives, password-protected archives listed with `7z l`, macro documents; links; scams; rare client/OS exploits) and reading the headers first (Return-Path, SPF for the wrong domain, DMARC fail); six invented phishing reports; the eight link tricks in a table; text ≠ target with `grep -o` on `href`s; IDN lookalikes decoded to punycode with Python; lookalike subdomains read right to left; cloned login pages and the form `action`; open redirects decoded with `urllib.parse`; hacked vs built-for-evil sites (shadowing, WordPress uploads paths, age, `Last-Modified`, historical scan snapshots, block expiry); a trusted file-sharing download proved malicious by EDR, 4688 and 4104 (T1608.001, T1204.002, T1059.007, T1105); shortener previews and `curl -sI` without `-L` read line by line; queue verdicts; 2026 view (post-macro lures, QR and ClickFix (T1204.004), AiTM, AI-written phishing, Bitly and goo.gl changes, private scans); practice questions |

!!! info "Coming next"
    Targeted vs opportunistic attacks, tracking clicks to shortened links, where a password box really goes, business email compromise detection, and a summary of the investigation questions — which closes this section.

## Things to remember { #must-know }

1. Plan before you search: write the question and the data you need in the ticket first.
2. The first question is always "is this alert valid — and what else looks like this?".
3. Choose the source that answers most definitively, not the one that is easiest to reach.
4. One connection is logged in many places; when the primary source is missing, use the others — and know their retention.
5. On the host, ask what ran, why it ran, and when it first ran.
6. Every lookup or upload to an outside service is also a disclosure.
7. Check every layer: destination, port, TLS wrapper and content — an attacker only needs one of them to lie.
8. Rare destinations deserve a look; trusted services can still carry bad content, and only the bytes prove it.

## Related { #related }

- [Structured Analysis](../structured-analysis/index.md) — the methods this section applies
- [Alert Triage](../alert-triage/index.md) · [Important Events](../important-events/index.md)
- [DNS](../dns/index.md) · [HTTP(S) Analysis & Attacks](../http-analysis/index.md) · [SMTP & Email](../email/index.md)

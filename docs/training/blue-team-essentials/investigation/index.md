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

!!! info "Coming next"
    Analysing network events layer by layer (IP and domain, ports, TLS certificates, application metadata and content), then email links and phishing, then targeted attacks and business email compromise.

## Things to remember { #must-know }

1. Plan before you search: write the question and the data you need in the ticket first.
2. The first question is always "is this alert valid — and what else looks like this?".
3. Choose the source that answers most definitively, not the one that is easiest to reach.
4. One connection is logged in many places; when the primary source is missing, use the others — and know their retention.
5. On the host, ask what ran, why it ran, and when it first ran.
6. Every lookup or upload to an outside service is also a disclosure.

## Related { #related }

- [Structured Analysis](../structured-analysis/index.md) — the methods this section applies
- [Alert Triage](../alert-triage/index.md) · [Important Events](../important-events/index.md)
- [DNS](../dns/index.md) · [HTTP(S) Analysis & Attacks](../http-analysis/index.md) · [SMTP & Email](../email/index.md)

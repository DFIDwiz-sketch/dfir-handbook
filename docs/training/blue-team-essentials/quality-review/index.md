---
title: Quality & Case Review
tags:
  - training
  - blue-team
  - soc
  - analysis
  - incident-response
---

# Quality & Case Review { #quality-review }

!!! abstract "In one line"
    The earlier sections took an alert all the way to a confirmed intrusion and a chosen response; this section is about **finishing well and getting better**. It covers why quality needs a written standard when speed is the only thing anyone sees, what good case documentation looks like, putting the kill chain back together before closing, classifying closed cases so they turn into metrics and threat intelligence, and being honest about attribution — and then the challenge-analysis techniques (premortem, structured self-critique, What If?, red team and Team A/B analysis) and how to turn them into a regular, friendly peer review that feeds new analytics, metrics and intelligence.

## Reading order { #reading-order }

| # | Page | Key points |
| --- | --- | --- |
| 1 | [Closing a Case Well — Consistent Quality, Good Documentation, Analytical Completeness, Classification and Attribution](documentation-classification.md) | Speed vs quality and why quality is invisible (seesaw table); define a standard, then measure; the seven-item closing checklist; how much detail is enough, write-as-you-go, record the query, UTC; an invented phishing-to-loader case at Wattle Ridge with a proxy log, a Zeek `http.log` line (epoch time, the proxy as client, `resp_fuids`) and event 4688 (`7zFM.exe` → `wscript.exe`, `%%1938`) read field by field, and the full case record; dropping into the kill chain and working backwards and forwards (private sandbox), completeness table mapped to ATT&CK (T1589.002, T1566.002, T1204.002, T1059.007, T1547.001, T1071.001, T1555.003); closed-case classification fields, benign true positive, the four key times calculated and defined consistently, a quarter of cases by detection source turned into decisions, tags, VERIS 4 As; attribution — Olympic Destroyer false flags, when you maybe can, internal clusters, a confidence scale, motivation and TTPs over names; 2026 view (NIST SP 800-61r3, the 2025 vendor naming mapping, Australian ransomware-payment reporting, CIRCIA status, AI-drafted summaries); practice questions |
| 2 | [Challenge Analysis and Peer Review — Premortem, Structured Self-Critique, What If?, Red Team and Team A/B, and Closing the Loop](challenge-analysis.md) | Why mental models resist change, reframing and Heuer's feedback argument; the two groups of challenge techniques; a premortem on the Wattle Ridge eviction plan with seven failure modes, warning signs and plan changes (and its limit); structured self-critique and why everyone, not one devil's advocate, critiques — a closed "scanner" case reopened after reading 4624 Logon Type 3 (NTLM), 5140 and 5145 `ReadData` field by field (T1039, T1078); What If? on the EDR console pushing a script to every endpoint, reasoned backwards with indicators and collection gaps (Kaseya VSA 2021); red team analysis vs red teaming, mirror-imaging; Team A/B on a 2.1 GB outbound Zeek `conn.log` session; operationalising reviews with a scored review form, pairing, no ranking, new vs senior analysts; what closed cases feed and the closing loop; summary of the analysis part; 2026 view (AI-closed alerts, AI as challenger, blameless reviews, NIST SP 800-61r3, automation bias); practice questions |

!!! success "Section complete"
    The quality and case review section is complete, and with it the analysis part. Next: the **continuous improvement part** — tuning and optimising alerts and analysis, automation, and keeping your skills growing.

## Things to remember { #must-know }

1. Speed is visible; quality isn't. Write down what a well-handled case looks like, then check against it.
2. Use a shared closing checklist: observables, classification, questions answered, remediation, other hosts, reproducible steps, feedback.
3. Notes should let someone else repeat your work. Record queries, not just results, and keep times in UTC.
4. Detection drops you into the middle of the kill chain. Work backwards to delivery and forwards to C2 and objectives.
5. Classify every closed case — disposition, type, key times, detection source, device type, motivation, summary — and define the times once.
6. Your own classified cases are your most relevant threat intelligence.
7. Don't claim attribution you can't defend. Track internal clusters, motivation and TTPs instead.
8. Challenge your own conclusions: premortem plans, self-critique closed cases, use What If?, red team and Team A/B when a consensus needs testing.
9. Review a random sample of every analyst's closed cases regularly — as learning, never as a ranking — and review AI-closed alerts too.
10. Closed cases feed new analytics, metrics, threat intelligence and peer review. Close the loop before you move on.

## Related { #related }

- [Reacting to Intrusions](../intrusion-response/index.md) — the section before
- [Mental Models](../mental-models/index.md) — Kill Chain, IR cycle, intelligence cycle and F3EAD
- [Structured Analysis](../structured-analysis/index.md) — hypotheses, confirmation bias and ACH
- [Investigation Questions](../investigation/index.md)
- [Threat Intelligence](../../../threat-intel/index.md)

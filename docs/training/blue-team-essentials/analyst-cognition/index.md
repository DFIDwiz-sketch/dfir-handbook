---
title: Perception & Memory
tags:
  - training
  - blue-team
  - soc
  - analysis
  - cognition
---

# Perception & Memory { #analyst-cognition }

!!! abstract "In one line"
    You've chosen the alert; now you must decide whether it's real — and this is where good analysts most often go wrong. This section explains why, using the psychology of analysis: perception as an active filter, mindsets that form fast and resist change, seeing what you expect, how the typical SOC workflow and SOC pressure push towards premature closure, and then the limits of short-term memory, how experience and long-term memory help and hurt, and the habits (decomposition, externalisation) that compensate.

## Reading order { #reading-order }

| # | Page | Key points |
| --- | --- | --- |
| 1 | [Perception and Analysis — Heuer's Argument, Mindsets, Seeing What You Expect, and Why the SOC Makes It Worse](perception.md) | Why validation goes wrong; Richards Heuer and *Psychology of Intelligence Analysis*; inherent vs deception-induced uncertainty (T1036.005, T1070.006, T1070.001, T1102); unmotivated, unconscious bias and why awareness isn't enough; perception as an active filter (mindset/mental model); mindsets form fast and resist change, assimilation strongest when ambiguous, confident, committed; the fresh-eyes effect; the ambiguous-figure and selective-attention examples; the five-step intuitive workflow and the disconfirming question; the SOC formula for premature closure; a VPN "scanner noise" case followed evidence by evidence (spraying T1110.003, MFA fatigue T1621, 4624 type 3, 4648, T1078/T1021.002); a "known false positive" 4688 pair (parent, token elevation, `SQBFAFgA` = `IEX`); eight practical countermeasures; practice questions |
| 2 | [Memory and Experience — Working Memory Limits, Decomposition and Externalisation, Assimilation, and Mental Ruts](memory-experience.md) | Sensory store, short-term and long-term memory; encoding and retrieval; 7 ± 2 and the newer ~4-chunk estimate; chunking; why relationships (n(n−1)/2) overflow working memory; decomposition and externalisation, six formats; a service-install case worked in the head and then as full case notes (7045, 4624 + 4672, 4688, Zeek conn/dns, T1543.003, T1569.002, T1036.004, T1071.001, T1133, T1078, T1021.002); the parked/dismissed list; mind map; assimilation vs mnemonics; learning `auditd` by mapping it to 4688; pros and cons of experience, mental ruts and five SOC examples; hardened mindsets and failing to re-evaluate earlier evidence; practice questions |

!!! success "Section complete"
    The perception and memory section is complete. Next: [**Mental Models**](../mental-models/index.md) — encapsulation, the OODA loop, the Kill Chain, defence in depth, NIST CSF, the incident response cycle, threat-intelligence cycles, the Diamond Model, attack trees, the Pyramid of Pain and MITRE ATT&CK — the models this section says you should collect.

## Things to remember { #must-know }

1. Validation, not triage, is where most wrong closures start.
2. Uncertainty is both natural (missing data) and planted (deception) — expect both.
3. Biases are unconscious; knowing about them doesn't remove them. Process does.
4. Perception is interpretation through a mindset; your mindset forms in seconds.
5. New evidence gets fitted into the first theory — most when data is ambiguous and you're confident and committed.
6. You see what you expect; the unexpected needs more evidence to be noticed.
7. Ask "what would show I'm wrong?", not "does it fit?".
8. Write down your hypothesis and an alternative; re-read the whole case before closing; use fresh eyes.
9. Working memory holds ~4–7 items; investigations hold hundreds of relationships. Decompose and externalise.
10. Keep a parked/dismissed list and re-check it when new facts arrive; experience builds both skill and ruts.

## Related { #related }

- [Alert Triage](../alert-triage/index.md) — choosing which alert to validate
- [Important Events](../important-events/index.md) — the events used in the worked cases
- [Threat intelligence](../../../threat-intel/index.md)

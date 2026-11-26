---
title: Structured Analysis
tags:
  - training
  - blue-team
  - soc
  - analysis
  - structured-analysis
---

# Structured Analysis { #structured-analysis }

!!! abstract "In one line"
    The perception and memory section showed why analysts get things wrong, and the mental models section filled the toolbox. This section is the fix: methods that make analysis reliable with incomplete, ambiguous data — System 1 and System 2 thinking, the "do you need more data?" question and diagnostic evidence, the four families of structured analytic techniques, structured brainstorming and hypothesis generation, the common hypothesis-evaluation mistakes and confirmation bias, Analysis of Competing Hypotheses (ACH), link analysis and the event matrix — each shown on realistic alerts and logs.

## Reading order { #reading-order }

| # | Page | Key points |
| --- | --- | --- |
| 1 | [System 1 and System 2, "Do You Need More Data?" and Structured Analytic Techniques — Putting a Check on Fast Thinking](system1-2-sat.md) | Section plan (generation, evaluation, organisation); System 1 vs System 2 compared and why the aim is to keep intuition in check, not switch it off; a System 2 trigger list; an "impossible travel" alert read field by field — sign-in logs, device ID, MFA claim in token, session-cookie replay (T1557, T1539, T1550.004, T1114.003); the mosaic approach vs medical diagnosis; diagnosticity; a PowerShell download alert with three hypotheses, an evidence table, discriminating tests, 4688 (parent `explorer.exe`, elevation type) and 4104 script block read line by line (T1059.001, T1105, T1204.004, T1036.005, T1547.001); what SATs are — decomposition and externalisation, the pilot's checklist; the four categories and where each fits in a SOC case; one case through all four; 2026 view (AI triage and automation bias, Kahneman and replication, mixed evidence on ACH); practice questions |

!!! info "Coming next"
    Hypothesis generation and confirmation bias, then Analysis of Competing Hypotheses (ACH), then link analysis and the event matrix.

## Things to remember { #must-know }

1. The fix for bias is method, not effort.
2. System 1 is fast and usually right on routine cases; keep it in check rather than switching it off.
3. Switch to System 2 on explicit triggers: high stakes, novelty, contradiction, irreversible decisions, fast certainty on a big case.
4. More data raises confidence faster than accuracy. Diagnose: list hypotheses, then run the tests that tell them apart.
5. Evidence consistent with every hypothesis has little diagnostic value — however alarming it looks.
6. Structured techniques decompose and externalise; they are a check on intuition, not proof of a conclusion.

## Related { #related }

- [Perception & Memory](../analyst-cognition/index.md) — the problems these methods fix
- [Mental Models](../mental-models/index.md) — the models these methods use
- [Alert Triage](../alert-triage/index.md) · [Important Events](../important-events/index.md)

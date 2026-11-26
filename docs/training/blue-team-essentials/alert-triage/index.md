---
title: Alert Triage
tags:
  - training
  - blue-team
  - soc
  - triage
---

# Alert Triage { #alert-triage }

!!! abstract "In one line"
    The analysis part starts here: with more alerts than analysts, which one do you open next? This section turns the network and host knowledge from earlier sections into a ranking habit — what "dangerous" means in practice, how to tell an attack that is nearly finished from one that has barely started, how to spot exfiltration, destruction, sensitive targets and targeted attackers in alert data, and how to prioritise a real queue.

## Reading order { #reading-order }

| # | Page | Key points |
| --- | --- | --- |
| 1 | [Triage and Defining "Dangerous" — Attacks Nearing Completion and Distance to the Attacker's Goal](defining-dangerous.md) | Triage as emergency-department thinking, why FIFO and vendor severity alone fail; four meanings of "dangerous" (near completion, high-value target, advanced/targeted attacker, unique/lowest count) and the damage–cost–hard-to-undo test; why you need attacker goals in advance (threat-model table); clear late-stage signs; a privileged service account's 4624 type 10 + 4672 and a 4688 for password-protected split `7z` read field by field (T1078.002, T1021.001, T1560.001); the Cyber Kill Chain stage table (attacker-side, host vs network), its linear weakness, the looping attack life cycle; a stage × asset × confidence score; an eight-alert queue linked by entity and ranked with reasons; practice questions |

!!! info "Coming next"
    Spotting data exfiltration and destruction attempts, recognising sensitive hosts, users and data, and the signs of a targeted attack; then prioritising IDS and exploit alerts, unique alerts and lower-priority alerts, with a triage summary.

## Things to remember { #must-know }

1. Triage by consequence, not arrival order; re-rank whenever new alerts arrive.
2. Dangerous = would cause damage, cost a lot or be hard to undo if it succeeds.
3. Order: near completion → high-value target → advanced/targeted → unique or lowest count.
4. Write down your attackers' likely goals in advance; "near completion" means near *those*.
5. Privileged accounts in the wrong place (4624 + 4672 on an unusual host) are a late-stage sign.
6. Place every alert on an attack model and ask how many steps are left — remembering that intrusions loop.
7. Link alerts by host, user and IP before ranking: three medium alerts can be one critical incident.
8. Severity is the rule's opinion; danger is this event on this asset in this context.

## Related { #related }

- [Important Events](../important-events/index.md) — the logon and process events triage relies on
- [Endpoint Attacks](../endpoint-attacks/index.md) — what each attack stage looks like on the host
- [Threat intelligence](../../../threat-intel/index.md)

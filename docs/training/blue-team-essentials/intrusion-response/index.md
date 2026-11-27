---
title: Reacting to Intrusions
tags:
  - training
  - blue-team
  - soc
  - analysis
  - incident-response
---

# Reacting to Intrusions { #intrusion-response }

!!! abstract "In one line"
    The earlier sections showed how to triage, investigate and research without tipping off the attacker; this section is about the moment an intrusion is **confirmed**. It covers the questions that decide how to react — how long the attacker has been inside (dwell time), what kind of intrusion it is, how many backdoors they are likely to hold (short-haul and long-haul), why they want your network, how much business risk there is right now and what you really know about them — and then how to choose a response, from "ignore" to "rebuild everything", how opportunistic and targeted attacks differ, the common response missteps, out-of-band communication and avoiding self-inflicted outages.

## Reading order { #reading-order }

| # | Page | Key points |
| --- | --- | --- |
| 1 | [Reacting to an Intrusion — Dwell Time, Intrusion Type, Short-Haul and Long-Haul Backdoors, Motivation, Business Risk and Knowledge](dwell-type-motivation.md) | Why "confirmed" is the start of a decision; one invented file-server backdoor at Wattle Ridge read field by field (T1543.003, T1071.001) and the "first seen by EDR" trap; dwell time and incremental risk with a leaning table; estimating dwell from System 7045, Security 4697, the linked 4624 Logon ID and 4698 on a jump server (T1053.005), where log retention runs out, and timestamps that are hard to fake; smash-and-grab vs persistent access with an evidence table (T1560, T1114.002, T1056.001); short-haul and long-haul backdoors in Zeek `conn.log` — a 60-second beacon and a weekly 02:00 beacon on another host (T1008) — and flushing the long-haul deliberately; identities as backup doors (T1078, T1098.001); strategic, tactical (T1199) and infrastructure motivation; business risk that overrides everything (ICS safety, Triton/TRISIS, T1486, T1490); a knowledge matrix of kill-chain stage × Pyramid-of-Pain depth (CTIM, DML); the six-question scorecard; 2026 view (M-Trends 2026 dwell figures and 22-second hand-offs, identity and edge-device persistence, ATT&CK v19 split and v20); practice questions |

!!! info "Coming next"
    **Choosing a response** — the response patterns from ignore to complete rebuild, reacting to opportunistic vs targeted attacks, common incident response missteps, out-of-band communication, common analyst response mistakes, preventing disaster, and the section summary.

## Things to remember { #must-know }

1. A confirmed intrusion starts a decision. Ask the questions before you reach for the isolate button — unless harm is active.
2. Dwell time comes from the earliest trustworthy evidence, not the first alert, and your logs may end before the attack began.
3. The longer they have been inside, the more footholds to expect, and the smaller the extra risk of a few days spent scoping.
4. Persistent attackers keep a noisy short-haul door and a quiet long-haul door. Hunt over long windows, and include accounts and cloud identities.
5. Ask what role you play for the attacker: strategic goal, tactical step or mere infrastructure.
6. Business risk overrides everything: safety systems, active theft or destruction mean act now.
7. Map what you know against the kill chain and the Pyramid of Pain; blank cells are the investigation plan.

## Related { #related }

- [Analysis OPSEC](../analysis-opsec/index.md) — the section before
- [Mental Models](../mental-models/index.md) — Kill Chain, IR cycle, Pyramid of Pain and ATT&CK
- [Endpoint Attacks](../endpoint-attacks/index.md)
- [Threat Intelligence](../../../threat-intel/index.md)

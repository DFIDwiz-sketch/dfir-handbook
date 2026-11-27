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
| 2 | [Choosing a Response — From Ignore to Rebuild, Opportunistic vs Targeted, Common Missteps, Out-of-Band Communication and Not Breaking Things](choosing-response.md) | The five response patterns (ignore, disrupt, engage, clean all, complete rebuild; Sony 2014, NotPetya and Maersk) with a cost/effectiveness/skill table and why skill is U-shaped; opportunistic playbook and a 30-day Zeek DNS sweep read command by command (`zcat`, `zeek-cut`, `grep -F -f`, `uniq -c`) incl. a host outside the sensors; infostealers that outlive the reimage; targeted playbook as a do/don't table (scope, volatile evidence, planned resets and blocks, more collection, no infrastructure contact, no public submission, quiet disruption of the goal); the seven common missteps from US-CERT and the 2020 Five Eyes advisory; out-of-band communication (attackers reading SOC mail, separate domain and accounts, Signal groups, phishing-resistant MFA) with an OOB card read line by line and discoverability; analyst mistakes and "search your logs first" — a supplier domain with 318 hosts and one hacked promo page, narrow block; the four-level "what could go wrong" ladder; the Wattle Ridge engage phase and eviction-day timeline (C2 blocks, identity backdoors, EDR isolation, `krbtgt` twice, token revocation, rebuild) and post-eviction watch on 4625 `0xC0000072`, 4724 and 4769; section summary; 2026 view (NIST SP 800-61r3, CISA, identity-first eviction, 22-second hand-offs, CISA messaging advice, AI and automated blocking); practice questions |

!!! success "Section complete"
    The reacting-to-intrusions section is complete. Next: **Quality & Case Review** — keeping consistent quality, good documentation, analytical completeness, closed-case classification and attribution, and challenge analysis (premortem, structured self-critique, What If?, red team and Team A/B).

## Things to remember { #must-know }

1. A confirmed intrusion starts a decision. Ask the questions before you reach for the isolate button — unless harm is active.
2. Dwell time comes from the earliest trustworthy evidence, not the first alert, and your logs may end before the attack began.
3. The longer they have been inside, the more footholds to expect, and the smaller the extra risk of a few days spent scoping.
4. Persistent attackers keep a noisy short-haul door and a quiet long-haul door. Hunt over long windows, and include accounts and cloud identities.
5. Ask what role you play for the attacker: strategic goal, tactical step or mere infrastructure.
6. Business risk overrides everything: safety systems, active theft or destruction mean act now.
7. Map what you know against the kill chain and the Pyramid of Pain; blank cells are the investigation plan.
8. Choose from the full range — ignore, disrupt, engage, clean all, rebuild. Engage needs the most skill.
9. Opportunistic: contain, clean, sweep everywhere. Targeted: scope, preserve, plan, then evict everything at once.
10. Move the response to an out-of-band channel once admin or identity compromise is suspected.
11. Search your logs before you block anything, and think about the worst case first.

## Related { #related }

- [Analysis OPSEC](../analysis-opsec/index.md) — the section before
- [Mental Models](../mental-models/index.md) — Kill Chain, IR cycle, Pyramid of Pain and ATT&CK
- [Endpoint Attacks](../endpoint-attacks/index.md)
- [Threat Intelligence](../../../threat-intel/index.md)

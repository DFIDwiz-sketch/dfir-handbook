---
title: Threat Intelligence
tags:
  - threat-intel
---

# Threat Intelligence

Who is behind the techniques in the [Adversary](../adversary/index.md) section. Each actor page answers three questions: **who they are** (attribution, aliases, mission), **what they have done** (major public incidents), and **how they do it** — their TTPs mapped to ATT&CK and linked to the technique pages on this site, so you can go straight from "this group uses X" to "this is how X looks in my logs".

!!! info "Public sources only"
    Everything here comes from public government advisories, MITRE ATT&CK and vendor reports. Attribution and alias mappings are vendor *assessments* and the groups overlap — treat names as labels for clusters of activity, not exact org charts.

| Page | What's in it |
|---|---|
| [North Korea (DPRK) — groups & incidents](dprk-overview.md) | The RGB-linked clusters (Lazarus, APT38/BlueNoroff, TraderTraitor, Andariel, Kimsuky, APT37, IT workers), alias table, major heists and attacks 2014 → 2025 |
| [North Korea — TTPs & hunting](dprk-ttps-hunting.md) | Their playbook phase by phase (fake recruiters, trojanised packages, supply chain, cloud pivot, macOS), ATT&CK mapping, Splunk/Zeek hunts |

## How to read a threat-intel page as a defender

1. **Skip the malware names, keep the behaviours.** Malware gets renamed every few months; "a developer ran a coding-test repo and Node.js spawned a shell" stays true for years.
2. **Map every behaviour to a technique you can see.** If you cannot point at a log source for a behaviour, that is a visibility gap — write it down.
3. **Turn the top three behaviours into hunts.** Use the [purple-team loop](../learning/purple-team-loop.md): reproduce in a lab → find the artifacts → write the query → document.

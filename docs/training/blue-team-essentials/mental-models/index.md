---
title: Mental Models
tags:
  - training
  - blue-team
  - soc
  - analysis
  - mental-models
---

# Mental Models { #mental-models }

!!! abstract "In one line"
    The previous section said the defence against perception and memory errors is many accurate mental models. This section is that toolbox: the standard models for attack, defence and threat intelligence — encapsulation and the OODA loop, the Cyber Kill Chain and campaign analysis, defence in depth, the NIST Cybersecurity Framework and the incident response cycle, threat-intelligence levels, the intelligence cycle and F3EAD, the Diamond Model, attack trees and graph thinking, threat modelling, the Pyramid of Pain and MITRE ATT&CK — with what each one is for, how it looks on real alerts and logs, and when to reach for which.

## Reading order { #reading-order }

| # | Page | Key points |
| --- | --- | --- |
| 1 | [Mental Models for Security, Encapsulation and the OODA Loop — Peeling Layers and Out-Cycling the Attacker](encapsulation-ooda.md) | Map of the standard models (general, offensive, defensive, threat intel) and the question each answers; encapsulation — evil on layers 2–7 (T1557.002, T1571), a cloud-hosted phishing download followed through Zeek conn/ssl/http/files (T1566.002, T1608.001, T1204.002), a nested attachment peeled with `unzip`, `file`, `oleobj` (email → ZIP → DOCX → OLE → EXE, T1566.001, T1027); go-to-the-bottom checklist; John Boyd's OODA loop, its two goals and ambiguity; the four stages in SOC terms and why Orient matters most; ops tempo and getting inside the attacker's loop; a slow vs fast defender loop against an attacker loop (beaconing T1071.001/T1036.005, 4624 type 10 RDP T1021.001); OODA in daily SOC work; practice questions |
| 2 | [Cyber Kill Chain, Campaigns, Defence in Depth, NIST CSF and the Incident Response Cycle — the Attack and the Defence as Models](kill-chain-did-nist-ir.md) | Lockheed Martin Kill Chain: purpose (intelligence-driven defence), seven stages with SOC evidence and ATT&CK examples, courses-of-action matrix (Detect/Deny/Disrupt/Degrade/Deceive) as a coverage map, completeness before and after a C2 beacon; campaign analysis across three phishing incidents — what changed (hashes, IPs, domains) vs what didn't (install path, C2 URI and interval, lure, targets); Prevent/Detect/Respond and the alert arithmetic of "detection without response"; NIST CSF five functions, Protect not Prevent, CSF 2.0 and Govern; PICERL walked through one intrusion (4688, Sysmon 13 Run key T1547.001, 4724 reset), surgical removal vs rebuild, lessons-learned template; how the five models fit; 2026 view (SP 800-61 Rev. 3, M-Trends 2026, identity attacks); practice questions |

!!! info "Coming next"
    Threat intelligence: the strategic, operational and tactical levels and their consumers, the intelligence cycle and F3EAD.

## Things to remember { #must-know }

1. Collect several models; each shows some aspects of a situation and hides others.
2. Evil can sit on any layer from 2 to 7; many modern attacks only show at layer 7.
3. Clear only the layers you actually inspected — and say which you couldn't see.
4. Files are layered too: keep unpacking until you reach something that isn't a container.
5. OODA: Observe, Orient, Decide, Act — a loop for acting under uncertainty against an opponent.
6. Orient is where models and context meet data; a wrong model makes speed useless.
7. Tempo wins: pre-approved playbooks shorten Decide, good context shortens Orient.
8. Fast isn't hasty — acting before you know the scope teaches the attacker.

## Related { #related }

- [Perception & Memory](../analyst-cognition/index.md) — why mental models matter
- [Alert Triage](../alert-triage/index.md) — attack-stage models in triage
- [File Analysis](../file-analysis/index.md) · [HTTP(S) Analysis](../http-analysis/index.md)
- [Threat intelligence](../../../threat-intel/index.md)

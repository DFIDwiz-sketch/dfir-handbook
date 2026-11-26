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
| 3 | [Threat Intelligence Levels, the Intelligence Cycle and F3EAD — Turning Data into Decisions and Incidents into Intelligence](threat-intel-cycles.md) | What CTI is for (advantage, not just IOC feeds); strategic, operational and tactical levels with consumers, timeframes and perishability, the optional technical level; one campaign turned into three products — a STIX 2.1 indicator read line by line with `valid_until`, a TLP:AMBER campaign brief, a board note asking for decisions; the intelligence cycle walked through a PIR (direction, collection that keeps overlap for corroboration, processing three sources about one domain, key assumptions, gaps and confidence words, dissemination per audience, feedback); why CTI is a separate team; F3EAD on a live intrusion — KQL hunt, 4688 (T1204.002, T1059.001, T1027), LNK tracker metadata linking build machines; cycles compared; 2026 view (AI-assisted CTI, TLP 2.0, CISA, ATT&CK v19/v20); practice questions |
| 4 | [The Diamond Model, Attack Trees, Graph Thinking and Threat Modelling — Connecting Incidents and Anticipating Paths](diamond-attack-trees.md) | Diamond Model: adversary, capability, infrastructure, victim; meta-features and the socio-political vs technical axes; Incident C filled in as two events from an email header and Zeek `ssl.log`; pivoting domain → IP → domains → capability → second victim with confidence per hop; activity threads and groups, and why one shared IP is not a group; F3EAD vs intelligence cycle vs Diamond and the self-licking ice-cream cone; attack trees (safe example, OR/AND nodes) and a supplier-payment-fraud tree with ATT&CK IDs and detection coverage per leaf (T1566.002, T1621, T1114.003); graph vs list thinking — paths to the CEO mailbox with 4624/4672/4724, T1003.001, T1021.002, T1078.002, cutting edges, a BloodHound Cypher query read line by line; threat modelling with adapted EFF questions, the four-question frame and STRIDE; 2026 view (identity graphs, help-desk social engineering, ATT&CK v18/v19); practice questions |
| 5 | [The Pyramid of Pain, MITRE ATT&CK and When Each Model Applies — Making the Attacker's Life Hard and Choosing the Right Lens](pyramid-attack-summary.md) | Pyramid of Pain at every level for one campaign: a one-byte change and a new SHA-256 (`sha256sum`, `cmp`), IPs and domains, network/host artefacts in a Zeek `http.log` line, a YARA rule for the tool and a Sigma rule for the behaviour (4688, T1204.002, T1059.001, T1027) read line by line, what the attacker did after each block; IOA vs IOC; Detection Maturity Levels; ATT&CK tactics, techniques, sub-techniques, procedures, domains and technique pages, a correction on Credential Access examples, Incident C mapped with evidence, a Navigator layer read line by line and a gap hunt (T1114.003); which model for triage, IR, strategy, hunting, CTI and tempo, walked through one night shift; why models matter for Orient and why all models are wrong; 2026 view (ATT&CK v18–v20, cheap infrastructure and SaaS C2, JA4+, AI-assisted mapping); practice questions |

!!! success "Section complete"
    The mental models section is complete. Next: **Structured Analysis** — System 1 and System 2 thinking, structured analytic techniques, hypothesis generation, confirmation bias, Analysis of Competing Hypotheses (ACH), link analysis and the event matrix: the techniques that make your use of these models reliable.

## Things to remember { #must-know }

1. Collect several models; each shows some aspects of a situation and hides others.
2. Evil can sit on any layer from 2 to 7; many modern attacks only show at layer 7.
3. Clear only the layers you actually inspected — and say which you couldn't see.
4. Files are layered too: keep unpacking until you reach something that isn't a container.
5. OODA: Observe, Orient, Decide, Act — a loop for acting under uncertainty against an opponent.
6. Orient is where models and context meet data; a wrong model makes speed useless.
7. Tempo wins: pre-approved playbooks shorten Decide, good context shortens Orient.
8. Fast isn't hasty — acting before you know the scope teaches the attacker.
9. The Diamond Model connects incidents: fill all four corners, pivot with stated confidence, group only on several shared features.
10. Attackers think in graphs: cut edges (tiering, reset verification), and let threat models and attack trees decide which controls come next.
11. Pyramid of Pain: block hashes, IPs and domains now, but invest detection effort in artefacts, tools and TTPs.
12. ATT&CK is the shared language for the top of the pyramid — map evidence, not guesses, and always record the version. All models are wrong; some are useful.

## Related { #related }

- [Perception & Memory](../analyst-cognition/index.md) — why mental models matter
- [Alert Triage](../alert-triage/index.md) — attack-stage models in triage
- [File Analysis](../file-analysis/index.md) · [HTTP(S) Analysis](../http-analysis/index.md)
- [Threat intelligence](../../../threat-intel/index.md)

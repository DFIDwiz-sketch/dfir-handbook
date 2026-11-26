---
title: "Triage and Defining \"Dangerous\" — Attacks Nearing Completion and Distance to the Attacker's Goal"
tags:
  - training
  - blue-team
  - soc
  - triage
  - analysis
---

# Triage and Defining "Dangerous" — Attacks Nearing Completion and Distance to the Attacker's Goal { #defining-dangerous }

!!! abstract "What this page covers"
    The first decision of every shift: **which alert do I open next?** We start with what triage is and why "oldest first" is the wrong answer, using the emergency-room picture and then turning it into SOC terms (limited analysts, many alerts, unequal consequences). Then we pin down what "**dangerous**" means in practice — four working definitions in priority order (attack near completion, high-value target, advanced or targeted attacker, rare or unique alert) and the single test behind all of them (damage, cost, difficulty to undo). We look closely at **attacks nearing completion**: why you must decide your attacker's likely goals in advance, and what the clear late-stage signs look like in real logs (exfiltration, imminent destruction, activity in protected enclaves and on locked-down hosts, odd use of highly privileged accounts — with Windows events **4624**, **4672** and **4688** read field by field). Then we **estimate distance to the goal** with two attack models: the seven-step Cyber Kill Chain (and which steps are attacker-side, host-based or network-based) and the looping attack life cycle that better matches real intrusions. Finally we triage an invented queue of eight alerts, rank them and explain every decision. Practice questions with explanations at the end.

!!! note "Labels"
    **[Supplement]** = practical material you need to know, **[Correction]** = a commonly repeated claim that is wrong or outdated, **[Changed]**/**[Caution]** = what has changed recently and what is risky to do the old way. The company (Kestrel Logistics), hostnames, accounts, domains and IPs are invented for illustration (`.example`, documentation and private IPs).

## The 8 key points { #key-points }

1. **Triage** is choosing which alert to work next when there are more alerts than analysts. It is a judgement about **consequences**, not a queue: the oldest alert is rarely the most important one.
2. Ask one question every time you pick an alert: **"Given the data I have right now, which of these situations would hurt us most if I ignored it for the next hour?"**
3. "**Dangerous**" has four working meanings, in this order: (1) an attack **close to completing** its goal; (2) an attack **aimed at something high-value** — a critical host, business process, user or data set; (3) signs of an **advanced or targeted** attacker; (4) a **unique, never-seen or lowest-count** alert.
4. Behind all four is one test: **would this cause damage, cost a lot, or be hard to undo if it succeeds?** Time and damage both end up as money.
5. You can only recognise "near completion" if you have **decided in advance what attackers want from you** (threat model, threat intelligence). Typical goals: steal data, destroy or encrypt data, reach a specific system, cause physical or operational harm.
6. Clear late-stage signs: **exfiltration**, **imminent destruction** (ransomware, wipers), activity **deep inside protected network zones**, activity on **heavily locked-down hosts**, and **highly privileged accounts used where they shouldn't be** (4624 + 4672 on an unusual host).
7. To estimate **distance to the goal**, place each alert on an attack model. The **Cyber Kill Chain** (Recon → Weaponisation → Delivery → Exploitation → Installation → C2 → Actions on Objectives) is the common reference; the later stages are the "danger area".
8. The Kill Chain is **linear**, but real intrusions **loop**: escalate privilege, recon inside, move laterally, keep persistence — again and again until the target is reached. C2 on one desktop is bad; C2 on the file server holding the crown jewels is much closer to the end.

## Why this matters in a SOC { #why }

A SOC never has spare analysts. On a normal morning the queue holds dozens or hundreds of alerts, most of them false positives or low-impact noise, and somewhere in the pile there may be one that matters more than all the others combined. If you simply take the alert at the top — the oldest one — you are betting that alerts arrive in order of importance. They don't. A port scan that arrived at 08:02 will sit above a domain admin logging on to the finance database at 08:20, and an hour spent on the scan is an hour the intruder has on the database.

Triage is what turns "a pile of alerts" into "the next most valuable thing to look at". It is also where an analyst's knowledge of the network, the hosts and the business pays off: the whole earlier part of this training (what DNS, HTTP, logons and process creation look like) is what lets you read an alert title and estimate, in a few seconds, **where the attacker is and what they could do next**.

Two failure modes this page helps you avoid:

- **Working the queue first-in, first-out (FIFO).** Fair to the alerts, unfair to the organisation.
- **Working by alert severity alone.** The "Critical" label was set by a rule writer who did not know which host, which account, or which other alerts would be involved. Severity is one input, not the answer.

## Triage: think like an emergency department { #triage }

Picture an emergency department. A patient with a sprained finger walks in two steps ahead of a patient with chest pain. Nobody thinks the finger should be seen first just because it arrived first. A triage nurse looks at each patient quickly, estimates how bad things will get if they wait, and orders the queue by **urgency and consequence**. An emergency dispatcher does the same with calls.

The SOC version has the same three ingredients:

- **Limited resources.** A handful of analysts per shift. Every alert you open is another alert you are not opening.
- **Multiple problems at once.** Alerts arrive continuously and many are unrelated.
- **Unequal consequences.** Some alerts, if real and ignored, cost nothing; some cost the company.

And the same goal: **pick the most dangerous (or most interesting) alert next.** Back to the technical reality: triage is a fast, incomplete assessment. You are not investigating yet. You are reading the alert title, the host, the user, the time, and maybe one or two enrichment fields, and making a **ranking decision** under uncertainty. The full investigation (later sections) comes after you have picked.

!!! tip "[Supplement] Triage is a loop, not a one-off"
    Re-rank every time you finish a case or a new alert arrives. A medium alert can jump to the top when a second alert lands on the same host or user. Triage decisions also go stale: what was right at 08:05 may be wrong at 08:25.

## Defining "dangerous" { #dangerous }

"Dangerous" sounds obvious until you have to rank eight alerts. Four working definitions, in the order you should apply them:

1. **Attack near completion.** The attacker looks close to doing the thing they came for — data leaving, data about to be destroyed, a target system reached. Nothing outranks this.
2. **Targeting or affecting high-value items.** If nothing is near completion, next comes anything aimed at what matters most: **critical hosts** (domain controllers, the ERP database, the OT gateway), **critical business processes** (payments, payroll, dispatch), **critical users** (domain admins, executives, finance staff who can move money, engineers with access to designs) and **sensitive data**. Example: a failed exploit attempt against a critical server, or malware on a laptop belonging to someone with access to sensitive data. These attacks may be past exploitation but not yet at their goal — they are "on track" to become definition 1.
3. **Advanced or targeted attackers.** A targeted attacker chose *you* and wants something only you have — customer data, intellectual property, engineering plans, or simply the ability to wipe everything. That intent makes them more persistent and more damaging than opportunistic malware. The problem is spotting them: no alert is titled "targeted attacker here, act now". The next page covers the tell-tale signs.
4. **Unique, never seen before, or lowest count.** When nothing else stands out, sort your alerts by how often each rule has fired and look at the **bottom** of the list. A rule that has fired once this month is far more likely to describe something new — including a real attack — than a rule that fires 4,000 times a day.

The bottom line that ties these together:

> **Dangerous = anything that would cause damage, cost a lot, or be hard to put right if it succeeds.**

Why "cost" covers everything: downtime, recovery work, legal notification, lost contracts and staff hours all become money. A ransomware outage of the dispatch system, a leak of customer records and a week of rebuilding a domain are all, in the end, large numbers on a spreadsheet. An adware pop-up on a kiosk is a very small number.

!!! info "[Correction] \"Dangerous\" is not the same as \"high severity\""
    A "High" signature alert against a server that isn't vulnerable (wrong OS, patched, attack blocked) can be harmless. A "Low" alert — say, an unusual logon — on the domain controller can be the most dangerous thing in the queue. Severity describes the *rule*; danger describes *this event, on this asset, in this context*.

## Attacks nearing completion { #nearing-completion }

### You must know the goals in advance { #goals-in-advance }

"Near completion" means near completion **of something**. You can only judge distance to a goal if you know what the goal is likely to be. That is why this step depends on work done *before* the alert: a **threat model** (what do we have that someone would want, and who would want it?) informed by **threat intelligence** (who actually attacks organisations like ours, and how?).

For our invented company, Kestrel Logistics, the threat model might say:

| Likely goal | Who wants it | What "the end" would look like |
| --- | --- | --- |
| Steal customer and shipment data | Extortion crews, competitors | Large uploads from file servers or the shipment database |
| Encrypt or wipe IT systems | Ransomware affiliates | Mass file changes, shadow copies deleted, backups targeted |
| Disrupt warehouse automation | Hacktivists, state actors in a crisis | Unusual access into the OT network, changes on HMI/PLC hosts |
| Payment fraud | Business-email-compromise crews | Mailbox rules, changes to supplier bank details |

With that table in your head, an alert stops being abstract. "7-Zip run on the shipment database server" maps directly to row 1.

### The clear signs { #clear-signs }

Some activity is so close to an attacker's goal that it should always jump the queue:

- **Data exfiltration.** Data is already leaving, or being packed up to leave. (Next page: how to spot it.)
- **Imminent destruction of data.** Ransomware or wiper behaviour: backups deleted, shadow copies removed, mass encryption starting. Minutes matter here.
- **Access to assets deep inside protected networks.** If you have segmented the network — a payments zone, an OT zone, a management network — attacker activity *inside* that zone means they have already crossed several barriers.
- **Access to highly locked-down hosts.** Systems where very few accounts are allowed to log on (domain controllers, privileged access workstations, backup servers). Any unexpected access is significant by design: the whitelist is short, so anything off it stands out.
- **Use of highly privileged accounts where they shouldn't be used.** Domain admin, enterprise admin, backup operator, cloud global admin — logging on to an ordinary workstation, at 03:00, from a host they never use.

That last sign is worth seeing in real events. When an account logs on to a Windows machine, that machine writes **4624** ("An account was successfully logged on") to its Security log. If the new session also receives sensitive privileges — which is the case for administrators — the machine writes **4672** ("Special privileges assigned to new logon") immediately after, with the same Logon ID.

```
Event ID 4624  Computer: KL-FIN-DB01.corp.kestrel.example   2026-11-24 03:12:41
  Subject:            SecurityID S-1-0-0  LogonId 0x0
  Logon Type:         10
  New Logon:          AccountName svc_backup  AccountDomain KESTREL  LogonId 0x5A3F21C
  Network Information: WorkstationName KL-WS-0412  SourceNetworkAddress 10.20.4.112
  Authentication:     LogonProcess User32  AuthenticationPackage Negotiate

Event ID 4672  Computer: KL-FIN-DB01.corp.kestrel.example   2026-11-24 03:12:41
  Subject:            AccountName svc_backup  LogonId 0x5A3F21C
  Privileges:         SeBackupPrivilege SeRestorePrivilege SeDebugPrivilege
                      SeTakeOwnershipPrivilege SeImpersonatePrivilege ...
```

Field by field:

- `Event ID 4624` on `KL-FIN-DB01` — the finance database server recorded a **successful logon to itself**. 4624 is always written on the machine being logged on to.
- `Logon Type: 10` — **RemoteInteractive**, i.e. Remote Desktop. Someone has a full desktop session on the database server ([logon types](../important-events/logins.md#logon-types)).
- `AccountName svc_backup` — a **service account** for backups. Service accounts normally run services (logon type 5) or batch jobs (type 4). A service account opening an *interactive RDP session* is already strange; at 03:12 even more so.
- `WorkstationName KL-WS-0412`, `SourceNetworkAddress 10.20.4.112` — the RDP session came **from an ordinary user workstation**. Backup administration should come from the backup server or an admin workstation, not from a desk in the logistics office.
- `LogonId 0x5A3F21C` — the session's ID. Every later event from this session (processes, file access) carries it, so you can follow what the session did.
- `Event ID 4672` with the **same LogonId** — Windows granted this session sensitive privileges. `SeBackupPrivilege`/`SeRestorePrivilege` let it read and write *any* file regardless of permissions; `SeDebugPrivilege` lets it open other processes' memory (credential theft); `SeTakeOwnershipPrivilege` lets it take over any object. In short: whoever holds this session can read the whole database server.

Why attackers care: highly privileged service accounts are a favourite target precisely because they are powerful, rarely watched, often have old passwords and are often exempt from MFA. In ATT&CK terms this is **T1078.002 Valid Accounts: Domain Accounts** used for **T1021.001 Remote Services: Remote Desktop Protocol**. On a crown-jewel server, from a user workstation, that is the "end is near" picture: privilege plus position.

If the same session then runs an archiving tool, the host writes **4688** ("A new process has been created", when process-creation auditing is on):

```
Event ID 4688  Computer: KL-FIN-DB01   2026-11-24 03:19:07
  Creator Subject:  AccountName svc_backup  LogonId 0x5A3F21C
  New Process Name: C:\ProgramData\7z\7z.exe
  Creator Process:  C:\Windows\System32\cmd.exe
  Process Command Line: 7z.exe a -pK3str3l! -v200m C:\ProgramData\x\s.7z D:\Exports\Shipments\
```

- `LogonId 0x5A3F21C` — **the same RDP session** from the 4624 above. One session, two alarming actions.
- `New Process Name C:\ProgramData\7z\7z.exe` — 7-Zip running from `ProgramData`, not from `Program Files`: copied in, not installed.
- `a` = add to archive; `-p...` = **password-protect** it (so DLP and proxies can't inspect the contents); `-v200m` = split into **200 MB volumes** (easier to upload, less likely to trip size limits); `D:\Exports\Shipments\` = the data being packed.
- ATT&CK **T1560.001 Archive Collected Data: Archive via Utility**, a classic step right before exfiltration (**TA0010**).

Put these three events together and you no longer need to guess: this is an attack one step from its goal.

## Assessing distance to the attacker's goal { #distance-to-goal }

For most alerts the picture is less clear. The habit to build: for every alert ask **"what stage of an attack does this look like?"** and therefore **"how many steps are left before the attacker gets what they want?"** Two models help.

### Model 1: the Cyber Kill Chain { #kill-chain }

The Cyber Kill Chain was published by Lockheed Martin researchers (Hutchins, Cloppert and Amin) in 2011 to describe the phases of a targeted intrusion. Seven steps:

| # | Stage | What the attacker does | Where you can see it | Side |
| --- | --- | --- | --- | --- |
| 1 | **Reconnaissance** | Research targets: staff names, exposed services, email formats | Web server logs, scans in firewall/IDS logs (often invisible: done on public sources) | Mostly attacker side |
| 2 | **Weaponisation** | Build the payload: malicious document, exploit + implant | Almost never visible to you | Attacker side |
| 3 | **Delivery** | Send it: email, web download, USB, exposed service | Email gateway, proxy, IDS | Network |
| 4 | **Exploitation** | The code runs: exploit fires or user opens the file | EDR, process creation (4688/Sysmon 1), crash logs | Host |
| 5 | **Installation** | Persistence: service, run key, scheduled task, web shell | EDR, 7045/4698, Sysmon 13 | Host |
| 6 | **Command & Control (C2)** | Implant talks to the attacker | DNS, proxy, Zeek `conn`/`ssl`/`http`, firewall | Network |
| 7 | **Actions on Objectives** | Steal, encrypt, destroy, move further | DLP, file access, large transfers, mass changes | Host + network |

Things worth noticing in that table:

- **Some stages happen mostly on the attacker's side.** Recon (much of it) and weaponisation happen on the attacker's own systems or on public sources. You have very little data and very few chances to act there.
- **Some stages are host-based, others network-based.** Exploitation and installation happen *on* a host, so host logs (EDR, process creation, service installs) are your best evidence. Delivery and C2 are *movements of data*, so network logs (email, proxy, DNS, Zeek) find them best. Knowing this tells you **which data to pull first** for an alert.
- **The "danger area" is the right-hand end.** An alert at stage 3 (a blocked phishing email) is far from the goal. An alert at stage 6–7 (an implant talking out, data moving) is close.

### The weakness: real intrusions loop { #kill-chain-weakness }

The Kill Chain is a straight line, but intrusions are not. Attackers rarely land directly on the system they want. They land on a receptionist's laptop, then need privileges, then need to find the right server, then move there, then often repeat. So C2 from a **desktop** is "stage 6", but the attacker may still be several hops from the goal; they will need *interactive control of a more important host* before they are truly "almost done". Reading the Kill Chain too literally makes every C2 alert look equally urgent.

### Model 2: the attack life cycle { #attack-lifecycle }

A second widely used model (popularised in incident-response reporting as the targeted attack life cycle) draws the middle of an intrusion as a **loop**:

```
Initial recon → Initial compromise → Establish foothold →
    ┌─> Escalate privileges → Internal recon → Move laterally → Maintain presence ─┐
    └──────────────────────────────────────────────────────────────────────────────┘
                                                        → Complete mission
```

- **Initial compromise** replaces weaponisation/delivery/exploitation/installation. It is more general — not every intrusion "installs" anything; often the attacker only needs a way to make one machine run their commands.
- **Establish foothold** = a reliable way back in (a backdoor, a stolen VPN account) to use as a base.
- **The loop** — escalate privileges, recon inside, move laterally, maintain presence — repeats on host after host. This is the part the Kill Chain hides.
- **Complete mission** is reached only after enough laps that the attacker can touch the target.

Because it shows the repetition, this model is easier for newer analysts to map real alerts to. Its downside for triage: you can't say "stage 6 of 7, therefore nearly done", because there are many "lap" stages per intrusion. You have to interpret **which lap** you are seeing: is this lateral movement *towards* the crown jewels, or just between two user laptops?

### Putting a number on distance { #distance-scoring }

**[Supplement]** Many SOCs make this explicit with a rough score. One simple version:

```
priority ≈ stage_weight × asset_weight × confidence
```

- `stage_weight` — e.g. recon 1, delivery 2, exploitation 3, installation 4, C2 5, lateral/privilege 6, collection/exfil/impact 8.
- `asset_weight` — from your asset list: ordinary workstation 1, server 2, crown jewel or privileged account 4.
- `confidence` — how likely the alert is true: 0.2 for a noisy rule, 0.9 for a high-fidelity one or one confirmed by a second alert.

The numbers are invented and the exact values don't matter. What matters is that you deliberately combine **where the attacker is**, **what they are touching** and **how sure you are**, rather than reacting to whichever factor is loudest.

## Worked example: an eight-alert queue { #worked-example }

It is 08:31 at Kestrel Logistics. You come back from a meeting to this queue, listed in arrival order:

| # | Time | Source | Alert | Host / user |
| --- | --- | --- | --- | --- |
| A1 | 08:02 | IDS | `SCAN inbound TCP port sweep` from 203.0.113.50 | DMZ range |
| A2 | 08:05 | Email gateway | Phishing URL `hxxps://kestrel-payroll.example/login` — **blocked**, sent to 40 users | 40 mailboxes |
| A3 | 08:11 | Antivirus | `Adware.BundleInstaller` **quarantined** | KL-WS-0388 (kiosk) / `kiosk` |
| A4 | 08:14 | EDR | Periodic HTTPS beacon every 60 s to `cdn-sync.example` (198.51.100.77), process `OneDriveSync.exe` in `%APPDATA%` | KL-WS-0412 / `j.moreno` |
| A5 | 08:20 | SIEM rule | Privileged service account interactive logon: `svc_backup` 4624 type 10 + 4672 | KL-FIN-DB01 from KL-WS-0412 |
| A6 | 08:22 | IDS | `WEB-APP remote code execution attempt` against KL-WEB02 from 192.0.2.14 | KL-WEB02 (public web) |
| A7 | 08:25 | EDR | `7z.exe` with password and split-volume flags | KL-FIN-DB01 / `svc_backup` |
| A8 | 08:30 | EDR | `Unsigned kernel driver loaded` — rule has fired **once** in 90 days | KL-OT-HMI03 (warehouse OT zone) |

**Step 1 — look for links before ranking.** A4, A5 and A7 share entities: A4 is on KL-WS-0412; A5 is an RDP logon *from* KL-WS-0412 to KL-FIN-DB01; A7 is on KL-FIN-DB01 under the same `svc_backup` account. That is very likely **one intrusion** seen three times: implant on a workstation (C2) → privileged lateral movement → staging data. Treat them as one case.

**Step 2 — rank.**

| Rank | Alert(s) | Definition of "dangerous" | Stage / distance | Reasoning |
| --- | --- | --- | --- | --- |
| **1** | **A5 + A7 (+ A4)** | Near completion + high-value asset + privileged account | Lateral movement done, **collection/staging** (T1560.001) — one step before exfil (TA0010) | Privilege + crown-jewel server + data being packed with a password. Open now; consider immediate containment of KL-WS-0412 and disabling `svc_backup` (with the right approvals). |
| **2** | **A8** | Unique / lowest count + protected enclave | Unknown — could be installation (driver = kernel access) in the OT zone | One firing in 90 days, inside a segmented zone where very little should change. Could be a maintenance vendor; could be a rootkit or a raw-disk driver for destruction. Needs a look soon, ideally by a second analyst while the first works rank 1. |
| 3 | A6 | Targeting a high-value item (public web app) | Exploitation **attempt** | Check whether it **succeeded**: HTTP response code and size, whether KL-WEB02 runs the targeted software, any new process from the web server process. If yes, it jumps to rank 1–2. |
| 4 | A2 | — | Delivery, **blocked** | Blocked, but 40 targeted users and a look-alike payroll domain. Quick follow-ups: did anyone click from a device not behind the gateway? Is the same lure arriving via other paths? |
| 5 | A3 | — | Installation, **cleaned** | Adware on a kiosk, quarantined. Low impact; close with a note or batch with similar alerts. |
| 6 | A1 | — | Recon, outside | Internet background noise against the DMZ. Useful as context (did 203.0.113.50 later appear in A6?), not as a case. |

**Step 3 — what FIFO would have done.** Working in arrival order, you would have spent the first half-hour on A1, A2 and A3 — scan, blocked email, quarantined adware — while `svc_backup` finished packing 200 MB volumes of shipment data on the finance database.

**Step 4 — write down why.** A one-line triage note per alert ("A6: attempt only, checking HTTP 500 response and process tree on KL-WEB02") makes the ranking reviewable and helps the next shift.

!!! tip "[Supplement] Group by entity, then rank"
    Most SIEMs and XDR tools can group alerts by host, user or IP into an "incident". Use it, but also check by hand: tools miss links when the attacker changes account (`j.moreno` → `svc_backup`) or when the link is a source address in a logon event rather than a shared hostname.

## The 2026 view { #trends }

!!! success "[2026 Current] Still valid"
    The core idea is unchanged: triage by **consequence, not arrival order**, and estimate where each alert sits in an intrusion and how close the attacker is to a goal you identified in advance. The four meanings of "dangerous" and the "damage, cost, hard to undo" test are still how experienced analysts rank. The Cyber Kill Chain remains the shared vocabulary for stages, and the looping life-cycle view is still the better picture of how intrusions actually progress. Windows **4624/4672/4688** remain the events that reveal privileged accounts used in the wrong place.

!!! info "[Changed] What has changed"
    - **Faster intrusions, less time to triage.** Mandiant's M-Trends 2026 (covering 2025 investigations) reports a global median dwell time of **14 days** (11 the year before), but also that the hand-off from an initial-access broker to the follow-on group (often ransomware) dropped from more than eight hours in 2022 to a **median of 22 seconds**: the second group's tooling is pre-staged during the first infection. A "low" initial-access alert can therefore be minutes away from "near completion".
    - **Extortion without encryption.** Many ransomware operations now steal data and extort without encrypting (or encrypt only as a second step), and recent reporting describes attackers deliberately going after **backups, identity services and hypervisors** to deny recovery. "Near completion" signs therefore include access to backup consoles and virtualisation management, not only mass encryption.
    - **Identity and cloud are now the "privileged accounts".** Global admins in the cloud tenant, SaaS admin roles, OAuth app consent and token theft are today's equivalents of "domain admin on a workstation". Late-stage signs live in identity-provider and cloud audit logs as much as in Windows events.
    - **ATT&CK has moved on.** Since v19 (April 2026) the old Defense Evasion tactic is split into **Stealth (TA0005)** and **Defense Impairment (TA0112)**, so Enterprise ATT&CK has 15 tactics; v20 (October 2026) added AI-related techniques. The IDs used on this page (T1078.002, T1021.001, T1560.001, TA0010) are unchanged.
    - **Built-in asset and risk scoring.** XDR/SIEM platforms now commonly tag critical assets and compute entity risk scores, and vendors ship **AI triage agents** that pre-sort alerts, write a first summary and propose a verdict. These help with volume, but they rank by what the tool knows; your threat model and asset knowledge still decide what "dangerous" means for your organisation.

!!! warning "[Caution] Wrong or risky to do the old way"
    - **Don't work the queue FIFO or by vendor severity alone.** Combine stage, asset and confidence, and re-rank as alerts arrive.
    - **Don't treat every Kill Chain stage-6 alert as equal.** Ask which lap of the loop you are seeing and how close that host is to the target.
    - **Don't assume a blocked or quarantined alert is finished.** A blocked email sent to 40 users, or a quarantined file, can be the visible part of a delivery that worked elsewhere.
    - **Don't accept an AI triage verdict without the evidence.** Check the events it relied on; models can mis-rank rare, high-value alerts exactly because they are rare.
    - **Don't skip the threat model.** Without written-down attacker goals, "near completion" is guesswork — and the backup server, hypervisor console or OT zone may not be on anyone's watch list.

## Practice questions { #quiz }

### Question 1

Your queue has: (a) IDS alert, outbound C2 signature from a sales laptop, 07:40; (b) "Critical" vendor alert, SQL injection attempt against your public website, 07:45; (c) SIEM alert, a Domain Admins account logged on with logon type 3 to the backup server from a help-desk PC, 07:50, followed by 4672. Rank them and explain using the definitions of "dangerous" and distance to the goal.

??? success "Answer and explanation"
    **1st: (c).** A Domain Admins account (privileged), on the **backup server** (high-value — backups are what you need to recover from ransomware, and attackers target them to deny recovery), from a help-desk PC (not an admin workstation). 4624 type 3 is a network logon (SMB, remote admin tools); 4672 confirms the session got special privileges. This is lateral movement with privilege towards a recovery-critical asset — close to the end.

    **2nd: (a).** C2 from a laptop is stage 6 of the Kill Chain, but on one ordinary laptop the attacker is probably early in the loop. It is still a likely real compromise; also check whether the help-desk PC in (c) talked to the same destination.

    **3rd: (b).** "Critical" is the rule's severity, not this event's danger. It is an **attempt** at exploitation. Check whether it succeeded (response codes and sizes, database errors, new processes from the web server); if it did, re-rank.

### Question 2

Why does judging "attack nearing completion" depend on a threat model, and give two examples of "the end is near" signs for an organisation whose main fear is ransomware.

??? success "Answer and explanation"
    "Near completion" means near **the attacker's goal**, and you can only measure distance to a goal you have identified. A threat model, informed by threat intelligence about who attacks organisations like yours, says what attackers want from you and therefore what the final steps would look like.

    For a ransomware-focused threat model, examples: shadow copies being deleted (`vssadmin delete shadows`, `wmic shadowcopy delete`, T1490 Inhibit System Recovery); access to or changes on backup servers and consoles; a privileged account logging on to many servers in a short time; mass file renames or writes; data being archived and uploaded before encryption (double extortion); access to hypervisor management.

### Question 3

A colleague says: "The Kill Chain shows C2 at step 6 of 7, so every C2 alert means the attacker is almost done." What is wrong with this, and which model better shows why?

??? success "Answer and explanation"
    The Kill Chain is **linear** and hides the fact that intrusions **loop**. An attacker with C2 on one desktop usually still needs to escalate privileges, explore the network, move laterally and keep persistence — often several times — before they can reach the target. Only interactive control of the systems that hold or reach the goal is really "almost done".

    The **attack life cycle** model shows this explicitly: initial compromise and foothold, then a repeating loop of escalate privileges → internal recon → move laterally → maintain presence, and only then complete mission. The cost is that you must interpret which lap you are on rather than read off a stage number.

## Related { #related }

- [Login events — 4624/4625 and logon types](../important-events/logins.md) · [Process creation](../important-events/process-creation.md)
- [Endpoint attacks](../endpoint-attacks/index.md) — what each stage looks like on the host
- [Endpoint defense: PAW, EDR, DLP, UEBA](../endpoint-defense/paw-edr-dlp-ueba.md)
- [Threat intelligence](../../../threat-intel/index.md) · [Adversary techniques](../../../adversary/index.md)

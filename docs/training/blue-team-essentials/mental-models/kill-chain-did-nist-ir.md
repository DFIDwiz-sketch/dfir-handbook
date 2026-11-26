---
title: "Cyber Kill Chain, Campaigns, Defence in Depth, NIST CSF and the Incident Response Cycle — the Attack and the Defence as Models"
tags:
  - training
  - blue-team
  - soc
  - analysis
  - mental-models
  - incident-response
---

# Cyber Kill Chain, Campaigns, Defence in Depth, NIST CSF and the Incident Response Cycle — the Attack and the Defence as Models { #kill-chain-did-nist-ir }

!!! abstract "What this page covers"
    Five models that every SOC conversation eventually uses, two from the attacker's side and three from the defender's. **The Cyber Kill Chain**: Lockheed Martin's seven-stage model of a targeted intrusion, why it was written ("intelligence-driven defence"), how the courses-of-action matrix turns it into a coverage map, and the habit it teaches — wherever you pick up an investigation, reconstruct what happened before and what would have happened after. **Campaign analysis**: tracking indicators and behaviours across several incidents so that what the attacker *didn't* change ties them together; a worked three-incident comparison shows how. **Defence in depth** as Prevent → Detect → Respond, and why "detection without response" is worth almost nothing (with the alert arithmetic to prove it). **The NIST Cybersecurity Framework**, in its original five functions and in CSF 2.0 with **Govern**. **The incident response cycle** (PICERL: Prepare, Identify, Contain, Eradicate, Recover, Lessons learned), walked through stage by stage on one invented intrusion with Windows events **4688**, **4724** and Sysmon **13** explained, plus a lessons-learned template. The 2026 view (NIST SP 800-61 Rev. 3, CSF 2.0, faster hand-offs, identity attacks that skip stages) and practice questions close the page.

!!! note "Labels"
    **[Supplement]** = practical material you need to know, **[Correction]** = a commonly repeated claim that is wrong or outdated, **[Changed]**/**[Caution]** = what has changed recently and what is risky to do the old way. The company (Kestrel Logistics), hostnames, accounts, domains, IPs, file names and log lines are invented for illustration (`.example`, documentation and private IPs). Frameworks and their authors are described in my own words.

## The 8 key points { #key-points }

1. **The Kill Chain describes a targeted intrusion as seven steps** — Reconnaissance, Weaponization, Delivery, Exploitation, Installation, Command and Control, Actions on Objectives — and every step has to succeed for the attacker to win. Break any link, ideally early, and the intrusion fails.
2. **Its real purpose is intelligence-driven defence:** map indicators to stages, map controls to stages, and see where you have no coverage. It is a planning and analysis tool, not just a diagram.
3. **It is also a completeness check.** If you find a C2 beacon (stage 6), a complete investigation explains stages 1–5 and estimates what stage 7 would have been — and blocks indicators from every stage, not only the one you found.
4. **Campaign analysis** lays several incidents side by side across the chain. Attackers rotate cheap indicators (hashes, IPs) but rarely change *everything*; what stays the same links the incidents and reveals how the actor works and what they want.
5. **Defence in depth = Prevent, Detect, Respond.** Prevention takes away the noise, detection catches what slips through, and response is what makes detection worth anything. More alerts than you can respond to is self-defeating.
6. **The NIST CSF** lists the capabilities a defence programme needs. CSF 1.x had five functions (Identify, Protect, Detect, Respond, Recover); **CSF 2.0 (February 2024) added Govern** and widened the scope to every organisation. Note the function is *Protect*, not "Prevent".
7. **The incident response cycle (PICERL)** is the defender's half of the Kill Chain: Prepare, Identify, Contain, Eradicate, Recover, Lessons learned. It works for any attack type and answers the new analyst's question "what do I do next?".
8. **Lessons learned closes the loop** back to Prepare. Skip it and the same incident happens again; do it quickly, while the details are fresh.

## Why this matters in a SOC { #why }

Think of a relay race. The attacker's team has seven runners, and the baton has to pass through all seven hands to reach the finish line. Trip any one runner and the race is lost. The Kill Chain is that list of runners. The defensive models are your side of the track: where your marshals stand (defence in depth), which jobs your organisation has staffed at all (NIST CSF), and the order in which your team acts once a runner is spotted (the incident response cycle).

Back to the technical reality: on a busy shift these models answer three questions that otherwise get answered badly by instinct. *How bad is it?* — how far along the chain is this alert ([alert triage](../alert-triage/defining-dangerous.md) used exactly this). *Is the investigation finished?* — have I explained every stage before and after the one I found? *What do I do next?* — where in the response cycle am I, and what does the next stage require? Teams that can't answer those three in a sentence close cases too early, contain before they scope, or never feed what they learned back into detection.

## The Cyber Kill Chain { #kill-chain }

### Where it came from and what it is for { #kill-chain-purpose }

In 2011 three Lockheed Martin analysts, Eric Hutchins, Michael Cloppert and Rohan Amin, published a paper on **intelligence-driven computer network defence**. Their problem was the long-running, well-resourced intrusions then called "advanced persistent threats" (APTs): attackers who came back again and again with new malware, so that blocking each piece of malware as it appeared was a losing game. Their answer borrowed the military idea of a "kill chain" — the steps needed to find and engage a target — and turned it around: describe the steps *the intruder* must complete, and then look for chances to stop each one.

The paper set out to do four things, and they are still the best way to understand the model:

- **Give instructions for building threat intelligence** — every indicator you collect gets a stage, so your intelligence is organised by what the attacker was doing, not by when you found it.
- **Inform defence investment** — if every control you own sits at Delivery and nothing sits at C2, you know where the next budget goes.
- **Connect and track threat groups** — indicators placed on the chain can be compared across incidents (campaign analysis, below).
- **Guide analytical completeness** — the chain is a checklist of what a full investigation should explain.

One limitation was built in from the start: the model was written for **targeted, human-operated intrusions**, where an adversary deliberately works through the steps. It fits commodity malware and insider threats less neatly (more on that in the 2026 view).

### The seven stages, with SOC evidence { #kill-chain-stages }

| # | Stage | What the attacker does | What you might see | Example ATT&CK techniques |
| --- | --- | --- | --- | --- |
| 1 | **Reconnaissance** | Research the target: staff, email formats, exposed services | Scans against your perimeter, bursts of visits to staff pages, phishing-for-information emails | T1595 Active Scanning, T1593 Search Open Websites/Domains, T1598 Phishing for Information |
| 2 | **Weaponization** | Build the payload: pair an exploit or macro with a backdoor | Almost nothing — it happens on the attacker's side. Only intelligence (malware builder artefacts, document metadata) shows it | T1587.001 Develop Capabilities: Malware, T1588 Obtain Capabilities |
| 3 | **Delivery** | Send the weapon: email, link, USB, exposed service | Email gateway logs, proxy downloads, web-server requests carrying an exploit | T1566.001/.002 Phishing, T1190 Exploit Public-Facing Application |
| 4 | **Exploitation** | Make code run: an exploit, or a user who clicks | EDR process trees (Office spawning a script host), IDS exploit signatures, crash logs | T1203 Exploitation for Client Execution, T1204.002 User Execution: Malicious File |
| 5 | **Installation** | Make it stay: backdoor, persistence | New Run keys, services, scheduled tasks, files in user-writable paths | T1547.001 Registry Run Keys, T1053.005 Scheduled Task, T1543.003 Windows Service |
| 6 | **Command and Control (C2)** | Talk to the implant and drive it by hand | Periodic beacons, rare domains, odd TLS fingerprints, DNS tunnelling | T1071.001 Web Protocols, T1071.004 DNS, T1573 Encrypted Channel |
| 7 | **Actions on Objectives** | Do what they came for: steal, encrypt, destroy, spy, move further | Archive creation, large uploads, mass file changes, new admin accounts, lateral movement | T1560.001 Archive via Utility, T1567.002 Exfiltration to Cloud Storage, T1486 Data Encrypted for Impact |

Two things are easy to miss in this table. First, **the earlier the stage, the cheaper the break.** Stopping a phishing email (stage 3) costs a quarantine; stopping an attacker at stage 7 costs an incident. Second, **stage 2 is nearly invisible to a SOC.** You will only "see" weaponization through intelligence — which is exactly why the paper paired the chain with intelligence work.

### Turning the chain into a coverage map: the courses-of-action matrix { #coa-matrix }

**[Supplement]** The original paper went one step further than the diagram that usually gets copied. It crossed the seven stages with six possible defensive actions — **Detect, Deny, Disrupt, Degrade, Deceive, Destroy** — to make a **courses-of-action matrix**. Here is a trimmed version for Kestrel Logistics, showing which control does what at each stage:

| Stage | Detect | Deny | Disrupt | Degrade | Deceive |
| --- | --- | --- | --- | --- | --- |
| Reconnaissance | Web analytics, perimeter scan alerts | Remove staff emails from public pages | — | — | Decoy staff profile with a canary address |
| Delivery | Email gateway, proxy, IDS | Block ISO/LNK/HTA attachments | Gateway link rewriting and click-time scan | Attachment size limits | — |
| Exploitation | EDR behaviour rules, IDS | Patch, block internet macros | EDR kills child process | — | — |
| Installation | EDR, Sysmon registry/task events | Application control on user-writable paths | — | — | Canary files in startup folders |
| C2 | DNS and proxy analytics, TLS fingerprints | Egress filtering, DNS sinkhole | IPS drops known C2 | Bandwidth limits on uncategorised sites | Sinkhole that records who calls |
| Actions on Objectives | DLP, file-audit events, UEBA | Least privilege, MFA on admin paths | Account disable via SOAR | Rate limits on downloads | Honey documents and honey accounts |

(The sixth action, *Destroy*, means striking the attacker's infrastructure — a job for law enforcement or the military, not a corporate SOC. It is in the paper, but you won't use it.)

Read the matrix like a gap report. An empty **Detect** cell is a stage where an attacker can work without you ever knowing. A row where only **Detect** is filled means you rely completely on a human responding in time. A healthy environment has something in most cells for most stages — that is defence in depth expressed in Kill Chain terms.

### Analytical completeness: before and after the point you found { #completeness }

The most useful daily habit the model gives you: **wherever you pick up an investigation, reconstruct the whole chain.**

Suppose this alert opens your case:

```
[NDR] Periodic beaconing to low-reputation domain        severity: high
  src=10.20.6.31 (KL-WS-0631)  dst=203.0.113.77:443  sni=update-cdn.example
  interval=300s±4%  sessions_24h=287  bytes_out_avg=812  bytes_in_avg=356
```

- `src=10.20.6.31 (KL-WS-0631)` — an ordinary finance workstation.
- `dst=203.0.113.77:443`, `sni=update-cdn.example` — HTTPS to a domain that looks like a software update service but has low reputation.
- `interval=300s±4%` — a connection every five minutes with very little jitter. People don't browse like that; programs do.
- `sessions_24h=287` — it has been running for nearly a full day (288 five-minute slots in 24 hours).
- `bytes_out_avg=812`, `bytes_in_avg=356` — small check-ins with small replies: "anything for me?" "no".

That is stage 6. A shallow analyst blocks the domain, re-images the PC and closes the case. A complete analyst asks the chain backwards and forwards:

| Stage | Question | Where to look | What Kestrel found |
| --- | --- | --- | --- |
| 5 Installation | How does it survive a reboot? | EDR, Sysmon 13, scheduled tasks | Run key launching `%APPDATA%\UpdSvc\updsvc.exe` |
| 4 Exploitation | What first ran the code? | EDR process tree, 4688 | `WINWORD.EXE` → `cmd.exe` → `updsvc.exe`, yesterday 10:02 |
| 3 Delivery | How did the file arrive? | Email gateway, proxy | Email "Revised freight invoice" with `Invoice_7731.docm`, 09:58 |
| 1–2 Recon/Weapon | Was this aimed at us? | Gateway: who else got it; document metadata | Sent to 6 finance staff by name; macro reused from an earlier incident (see campaigns) |
| 7 Objectives | What would have happened next? | EDR on this host, file-server audit, proxy uploads | Discovery commands run at 14:20; no upload yet — likely data theft from the finance share |

Now your containment covers every stage: quarantine the email for all six recipients (3), block the macro's behaviour (4), hunt the Run key and file path across the fleet (5), block the C2 domain *and* IP (6), and watch the finance share and the account for the next step (7). Blocking only stage 6 would have left five other unopened copies of the email in mailboxes.

## Campaign analysis { #campaigns }

### The idea { #campaigns-idea }

The second big idea in the paper is the **campaign**: the sum of one actor's activity against you over time. You build it by recording the indicators and behaviours of each incident *by stage*, then comparing incidents. The logic is economic. Changing an IP address or recompiling malware to get a new hash is cheap, so attackers do it constantly. Changing their email lure style, their tooling, their infrastructure registration habits, their working hours and their targets all at once is expensive, so they rarely do. **What they fail to change is what connects them.**

Once connected, the incidents tell you how this actor operates (their TTPs — tactics, techniques and procedures) and what they are interested in, and that lets you choose defences aimed at the actor rather than at yesterday's indicator. Sometimes, combined with outside intelligence, it can even support attribution — a bonus, not the goal.

### Worked example: three incidents at Kestrel { #campaign-example }

Over two months the Kestrel SOC handled three phishing incidents. Laid out by stage:

| Stage | Incident A (September) | Incident B (October) | Incident C (November) |
| --- | --- | --- | --- |
| Delivery: sender | `billing@freight-docs.example` | `accounts@cargo-invoices.example` | `ap@shipping-billing.example` |
| Delivery: lure | "Overdue freight invoice" | "Revised freight invoice" | "Freight invoice dispute" |
| Delivery: targets | 4 finance staff | 6 finance staff | 5 finance + 2 procurement |
| Exploitation: file | `Inv_2201.docm` (hash A) | `Invoice_7731.docm` (hash B) | `Statement_0412.zip` → `.lnk` (hash C) |
| Exploitation: document author metadata | `j.smith` | `j.smith` | — (LNK) |
| Installation | Run key, `%APPDATA%\UpdSvc\updsvc.exe` | Run key, `%APPDATA%\UpdSvc\updsvc.exe` | Run key, `%APPDATA%\UpdSvc\updsvc.exe` |
| C2: domain/IP | `cdn-sync.example` / 198.51.100.23 | `update-cdn.example` / 203.0.113.77 | `telemetry-cdn.example` / 192.0.2.140 |
| C2: URI and timing | `/api/v2/ping`, 300 s | `/api/v2/ping`, 300 s | `/api/v2/ping`, 300 s |
| C2: domain registration | registered 3 days earlier, same registrar | registered 2 days earlier, same registrar | registered 4 days earlier, same registrar |
| Activity hours | 09:00–17:00 UTC+3 | 09:00–17:00 UTC+3 | 09:00–17:00 UTC+3 |

Read it column by column and nothing repeats except "a phishing email". Read it **row by row** and the picture changes:

- **Changed every time:** sender domain, file hash, C2 domain and IP. These are the cheap things, and if your blocklist held only these, you would be starting from zero each month.
- **Never changed:** the freight-invoice theme, the targeting of finance, the install path and Run key, the C2 URI pattern and 300-second interval, the registration habit and the working hours.
- **Changed once, meaningfully:** the delivery file type moved from macro documents to a ZIP with an LNK in November — probably because Kestrel started blocking macros after Incident B. The actor adapted to your defence. That's an important finding in itself.

Conclusion for the record: *Incidents A, B and C are assessed as one campaign (tracked internally as KL-CAMP-01), based on identical installation path, C2 URI pattern and beacon interval, consistent targeting and lure theme, and consistent infrastructure registration. Confidence: moderate–high.* And the courses of action now target the durable parts: a detection on `/api/v2/ping` with a 300-second period to any newly registered domain, a hunt and an application-control rule for `%APPDATA%\UpdSvc\`, extra awareness for finance and procurement about freight-invoice lures, and an alert on any LNK inside a ZIP reaching finance mailboxes. None of these depend on next month's hash.

This is the same insight that the Pyramid of Pain (later in this section) puts into a picture: the indicators at the bottom are easy for the attacker to change, the behaviours at the top are not.

## Defence in depth: Prevent, Detect, Respond { #defence-in-depth }

### Three parts of one defence { #pdr }

A castle doesn't trust its outer wall alone. It has a moat, a wall, guards on the wall, a keep inside, and soldiers ready to fight anyone who gets in. **Defence in depth** is that idea for networks, and the simplest way to say it is **Prevent → Detect → Respond**, often summed up in two sayings: "prevention is ideal, detection is a must" and "detection without response has little value".

- **Prevent** — stop everything you can, as early in the chain as you can, automatically. Firewalls, email filtering, patching, application control, EDR blocking, MFA. Every attack prevented is one nobody has to analyse. Prevention also removes the noise so that detections stand out.
- **Detect** — no prevention is perfect; assume compromise will happen. Some attacker behaviours are too uncertain to block outright without breaking business (an admin tool used by both admins and attackers, say), so they become *alerts* rather than *blocks*. Detection is the safety net for what prevention will inevitably miss.
- **Respond** — act on what was detected, quickly and decisively. This is where the value of all the detection is actually realised.

You will often see this model extended with **Identify** at the front (build an environment you can see and defend) and **Recover** at the end (get back to normal in a predictable way). That extended version is very close to the NIST CSF below.

### "Detection without response" — the arithmetic { #detection-without-response }

The second saying is easy to nod along to and easy to violate. Do the numbers for a small SOC:

```
Alerts per day reaching analysts ............ 1,200
Analysts on shift (24 h, 3 shifts × 2) ...... 6 analyst-shifts/day
Effective triage time per analyst-shift ..... ~6 h = 360 min
Total triage minutes per day ................ 6 × 360 = 2,160 min
Minutes available per alert ................. 2,160 / 1,200 ≈ 1.8 min
```

- **1.8 minutes per alert** is not enough to open the process tree, check the user and look at the parent email. In practice analysts start bulk-closing, and the one real beacon is closed with the 400 false positives around it.
- Every detection that fires but can't be investigated in time has nearly zero value — and costs you analyst attention that could have gone to real alerts.

The fix is never "hire until it fits". It is to rebalance the three parts: move noisy-but-certain things into **prevention** (block them, don't alert on them), tune or remove low-value **detections**, and automate the first steps of **response** (enrichment, auto-closing known benign patterns, one-click containment). A SOC with 200 alerts a day that are all investigated well is far stronger than one with 1,200 that are skimmed.

## The NIST Cybersecurity Framework { #nist-csf }

### What it is { #nist-csf-what }

The US National Institute of Standards and Technology (NIST) first published its **Cybersecurity Framework (CSF)** in 2014. It is not a list of controls to buy; it is a high-level way to describe the **outcomes** a security programme needs, organised into **functions**. It is useful for a SOC analyst because it explains where your job sits among everyone else's, and why things outside the SOC (asset inventories, backups, governance) decide how well the SOC can work.

The original five functions, in SOC terms:

| Function | Meaning | What it means for the SOC |
| --- | --- | --- |
| **Identify** | Know what you have and what matters: assets, data, risks, dependencies | An asset inventory and criticality list so you know that `KL-FS02` holds payroll; a network built so it *can* be monitored |
| **Protect** | Safeguards that limit the chance and impact of incidents: access control, training, hardening, data security | Fewer incidents and less noise — the prevention layer |
| **Detect** | Find events and anomalies quickly | Your monitoring, alerts, hunting |
| **Respond** | Act on a detected incident to contain its impact | Triage, investigation, containment, communication |
| **Recover** | Restore capabilities and services, with *tested* plans | Backups that have actually been restored in a test, and a plan for scenarios where they wouldn't help |

**[Correction]** Many diagrams (and some training material) label the second function "Prevent". The framework's word is **Protect**. The idea is close, but in a meeting where people are quoting the framework, use its terms.

The **Identify** point deserves emphasis because SOC analysts feel it daily: if the network wasn't built to be watched — no central logs, no EDR on servers, flat networks, unknown assets — then detection and prevention are hard from day one, however good the analysts are. And the **Recover** point hides a question every team should be able to answer: *when did we last restore from backup in a test, and what scenario would our backups not cover?* (A ransomware actor who deletes the backups first is the classic one.)

The CSF describes *capabilities you should have*, not the order of events in an incident. For that, you need the incident response cycle.

### CSF 2.0 and the Govern function { #csf-2 }

**[Changed]** NIST released **CSF 2.0 on 26 February 2024**, the first major update since 2014. Two changes matter most:

- **A sixth function, Govern**, placed at the centre of the other five. It covers how the organisation sets and runs its cybersecurity strategy: risk-management strategy, roles and responsibilities, policy, oversight, and **cybersecurity supply chain risk management**. The message is that cybersecurity is an enterprise risk that senior leaders own, alongside financial and reputational risk.
- **Wider scope.** The original framework was aimed at critical infrastructure; 2.0 is explicitly for organisations of every size and sector.

For an analyst, Govern shows up as the things that decide your day without being "security tooling": who is allowed to isolate a server, which playbooks are approved, who signs off on notifying a regulator, and what you are contractually owed by your managed service providers.

## The incident response cycle (PICERL) { #ir-cycle }

### The defender's half of the Kill Chain { #ir-cycle-idea }

The CSF lists capabilities; the **incident response cycle** lists **steps in order**. You can think of it as the defender's half of the Kill Chain: the stages *you* must go through to get an attacker out. Unlike the Kill Chain, it doesn't care what kind of attack it is — opportunistic malware, a targeted intrusion, an insider, a lost laptop — the stages are the same. That is why it is so useful to newer analysts: when an incident is happening and you don't know what to do, **find where you are in the cycle and do the next stage.**

The six stages are commonly remembered as **PICERL**: **P**repare, **I**dentify, **C**ontain, **E**radicate, **R**ecover, **L**essons learned. They come from NIST's long-standing incident-handling guide (SP 800-61), whose own four-phase version grouped them slightly differently (Preparation; Detection and Analysis; Containment, Eradication and Recovery; Post-Incident Activity). The content is the same; PICERL simply gives each part its own name.

### The stages, walked through one intrusion { #ir-walkthrough }

We use the Incident B intrusion from the campaign example (KL-WS-0631, the 300-second beacon).

**1. Prepare — before anything happens.** Logging, EDR and network sensors in place; detections written; playbooks and authority decided; contact lists and out-of-band communication ready. At Kestrel, preparation is why the NDR sensor saw the beacon and why the EDR kept the process tree. Most of what makes an incident go well is decided here.

**2. Identify — from first signal to the decision to act.** This is detection and analysis: confirm it's real, work out scope, understand what the attacker is doing. It covers everything up to the first active response step. The evidence on the host:

```
Event ID 4688  Computer: KL-WS-0631  2026-10-14T10:02:11Z
  New Process Name:     C:\Windows\System32\cmd.exe
  Creator Process Name: C:\Program Files\Microsoft Office\root\Office16\WINWORD.EXE
  Process Command Line: cmd.exe /c copy %TEMP%\~tmp41.dat %APPDATA%\UpdSvc\updsvc.exe && %APPDATA%\UpdSvc\updsvc.exe
  Subject Account Name: r.patel
```

- **Event 4688** is Windows' "a new process has been created" event, written to the Security log on the machine where the process started — but only if *Audit Process Creation* is enabled, and the command line is recorded only if the separate "include command line" policy is turned on (see [process creation](../important-events/process-creation.md)). Attackers care because nearly everything they do on a host is a process; this event is often the clearest record of execution.
- `Creator Process Name ... WINWORD.EXE` → `cmd.exe` — Word starting a command shell is almost never legitimate. This is stage 4 (**T1204.002** user execution of a macro document, with the macro launching **T1059.003 Windows Command Shell**).
- `copy %TEMP%\~tmp41.dat %APPDATA%\UpdSvc\updsvc.exe` — the dropped payload is renamed to look like an updater and placed in a user-writable folder.

```
Sysmon Event ID 13  Computer: KL-WS-0631  2026-10-14T10:02:14Z
  EventType:    SetValue
  Image:        C:\Users\r.patel\AppData\Roaming\UpdSvc\updsvc.exe
  TargetObject: HKU\S-1-5-21-...-1844\Software\Microsoft\Windows\CurrentVersion\Run\UpdateService
  Details:      C:\Users\r.patel\AppData\Roaming\UpdSvc\updsvc.exe
```

- **Sysmon Event 13** ("registry value set") is written by Microsoft's free Sysmon tool when a monitored registry value changes. It is not in the default Security log, which is one reason many SOCs deploy Sysmon or rely on EDR for registry telemetry.
- `TargetObject ...\CurrentVersion\Run\UpdateService` — a value under the user's **Run** key. Windows starts whatever it points to every time the user logs in. This is stage 5, **T1547.001 Registry Run Keys / Startup Folder**, one of the oldest and still most common persistence methods because it needs no admin rights.

Identify ends when you know enough to act safely: one host, one user, one C2 domain and IP, the persistence mechanism, six recipients of the email, no sign yet of lateral movement or upload.

**3. Contain — stop the bleeding.** The first active steps to disrupt the attacker and make sure things can't get worse, usually short-term, while you plan the longer fix. At Kestrel: EDR network isolation of KL-WS-0631, block `update-cdn.example` and 203.0.113.77 at DNS and proxy, quarantine the email from all six mailboxes, reset `r.patel`'s password and revoke sessions. The password reset leaves its own trace on the domain controller:

```
Event ID 4724  Computer: KL-DC01  2026-10-15T09:31:40Z
  An attempt was made to reset an account's password.
  Subject:        Account Name: svc-soar
  Target Account: Account Name: r.patel
```

- **Event 4724** is "an attempt was made to reset an account's password" — someone with rights reset *another* account's password (as opposed to 4723, a user changing their own). It's logged on the domain controller. Here the subject is the SOAR service account, which is expected during containment. Attackers care about the same event for the opposite reason: resetting a victim's or an admin's password is a way to take over the account (**T1098 Account Manipulation**), so an unexpected 4724 by an unusual subject is worth an alert.

Containment for an opportunistic infection and for a targeted intrusion can look very different — with a capable, targeted actor you may need to scope further *before* the visible containment so they don't simply switch to another foothold (the OODA example on the [previous page](encapsulation-ooda.md#ooda-example) showed exactly that). Choosing a response is covered in its own section later.

**4. Eradicate — lock them out and keep them out.** Longer-term measures that remove the attacker's access entirely: remove the Run key and binary everywhere they exist (the fleet hunt found none beyond KL-WS-0631), or re-image the host; block the C2 URI pattern rather than just the domain; fix the gap that let it in (macros from the internet blocked by policy). How far you go depends on how much risk you are willing to accept that you missed something: **surgical removal** is faster and less disruptive, a **full rebuild** is safer when you can't be sure what the attacker changed.

**5. Recover — back to normal.** Restore what eradication disrupted: the user gets a rebuilt laptop and their data back from backup, the host leaves isolation, monitoring on that user and host is raised for a few weeks to catch anything that was missed. In larger incidents this is where servers taken offline are brought back in a controlled order.

**6. Lessons learned — feed it back to Prepare.** The stage most often skipped because everyone wants to get back to normal work, and one of the most important, because without it nothing gets harder for the next attacker. Do it soon, while people remember the small details. A minimal template, filled in:

```
Incident: KL-IR-2026-031 (KL-CAMP-01, Incident B)      Review date: 2026-10-17
What went well:
  - NDR beacon detection fired within 24 h; EDR process tree kept full history.
  - SOAR reset and session revoke took 2 minutes.
What didn't go well:
  - Beacon ran ~24 h before triage; alert sat in a medium-priority queue.
  - 5 of 6 phishing emails were still in mailboxes when found.
What we can do better:
  - Raise severity for periodic beacons to newly registered domains.
  - Auto-search and purge same-sender emails when one is confirmed malicious.
What we will do differently next time (owner, due):
  - Block internet-origin macros by policy (IT ops, 2026-10-31).
  - New detection: /api/v2/ping at fixed 300 s interval (detection eng., 2026-10-24).
  - Hunt %APPDATA%\UpdSvc\ fleet-wide weekly until campaign ends (SOC, ongoing).
```

- Four questions — what went well, what didn't, what we can do better, what we'll do differently — are the minimum. The last one must have **owners and dates**, or it is a wish list.
- Notice the first action item: blocking macros. Incident C a month later came as a ZIP with an LNK instead. The lesson learned worked — and the attacker adapted, which is exactly why the cycle has to keep turning.

## How the five models fit together { #fit }

| Model | Point of view | Main question | When you reach for it |
| --- | --- | --- | --- |
| Cyber Kill Chain | Attacker, one intrusion | How far along is this, and what came before and after? | Triage, scoping, completeness checks, coverage planning |
| Campaign analysis | Attacker, many intrusions | Is this the same actor, and what don't they change? | After the second similar incident; intelligence work |
| Defence in depth | Defender, layers | Which layer should have stopped this, and is the balance right? | Post-incident review, alert-volume problems |
| NIST CSF | Defender, whole programme | Do we have every capability we need? | Programme planning, explaining gaps to management |
| IR cycle (PICERL) | Defender, one incident | Where am I, and what's next? | During every incident |

The Kill Chain and PICERL are two halves of the same event: the attacker moves forward along their chain while you move through your cycle, and the race between them is the OODA tempo from the previous page.

## The 2026 view { #trends }

!!! success "[2026 Current] Still valid"
    All five models are still in everyday use. The Kill Chain remains the common language for "how far along is this attack?", and the before-and-after completeness habit is as important as ever. Campaign analysis — tracking what the actor doesn't change — is the basis of modern behaviour-focused detection. Prevent/Detect/Respond and the "detection without response" warning describe today's alert-fatigue problem exactly. PICERL is still the most common way responders describe their work.

!!! info "[Changed] What has changed"
    - **NIST CSF 2.0 (26 February 2024)** added **Govern** as a sixth, central function (strategy, roles, policy, oversight, supply chain risk) and widened the framework's scope to all organisations, not just critical infrastructure.
    - **NIST SP 800-61 Rev. 3 (April 2025)** superseded Rev. 2. It is now written as a **CSF 2.0 community profile**: incident response is described through the six CSF functions as part of overall risk management, rather than as the old stand-alone four-phase lifecycle. In broad terms, Govern, Identify and Protect cover preparation and improvement (including lessons learned), and Detect, Respond and Recover cover the incident itself. PICERL remains a perfectly good working model for analysts, but if you cite NIST in a report, cite Rev. 3.
    - **The chain runs faster.** Mandiant's M-Trends 2026 put the global median dwell time at **14 days** (up from 11 the year before) and found that the median time from initial access to hand-off to a second criminal group had fallen to **22 seconds**, from more than eight hours in 2022. Exploits were the top initial infection vector for the sixth year running (32%), with voice phishing second. Stages can now pass between different actors almost instantly.
    - **Identity and cloud attacks don't follow all seven stages.** A stolen session token or an abused OAuth consent can go straight from Delivery to Actions on Objectives with no malware "installation" and no classic C2. Models like the **Unified Kill Chain** (which adds stages for moving inside the network) and ATT&CK's tactic list are often used alongside the original chain for this reason.

!!! warning "[Caution] Wrong or risky to do the old way"
    - **Don't treat the Kill Chain as strictly linear or malware-only.** Real intrusions loop (recon and C2 repeat after every lateral move), skip stages, or are run by several groups in turn. Use the chain to ask questions, not to force evidence into seven boxes.
    - **Don't block only the stage you found.** Block and hunt indicators from every stage, and search for the other recipients and hosts — or you will be back next week.
    - **Don't build blocklists only from rotating indicators.** Hashes, IPs and fresh domains changed in every incident of the example; detections on the durable behaviour are what last.
    - **Don't wipe before you scope.** Re-imaging a host before you know how it was compromised and what else was touched destroys evidence and may leave other footholds. Eradication comes after Identify, not instead of it.
    - **Don't skip lessons learned, and don't leave it without owners and dates.** Without it, the cycle is a line, and the same attack works twice.

## Practice questions { #quiz }

### Question 1

You receive an EDR alert that `rundll32.exe` on a workstation is making periodic HTTPS connections to a rare domain. Which Kill Chain stage is this? List the questions you would ask for every other stage, and say what you would block or hunt for each one before closing the case.

??? success "Answer and explanation"
    Periodic connections to a rare domain from a running implant are **stage 6, Command and Control**. A complete investigation works backwards and forwards:

    - **Installation (5):** how does it persist? Check Run keys, scheduled tasks, services, startup folders (Sysmon 13, EDR, 4698/7045 if collected). Hunt the same mechanism and file path fleet-wide; remove it.
    - **Exploitation (4):** what first ran it? EDR process tree and 4688 — which parent launched `rundll32.exe` and with which DLL? Block the behaviour (e.g. Office spawning script hosts).
    - **Delivery (3):** how did it arrive — email, download, USB, exposed service? Find and remove every other copy (other recipients, other downloads).
    - **Recon/Weaponization (1–2):** was it targeted? Who else received it, were they chosen by role, does the payload match earlier incidents?
    - **Actions on Objectives (7):** what did the attacker do or plan to do — discovery, credential access, lateral movement, archive and upload? Watch the user's account and the data they can reach.
    - **C2 (6) itself:** block the domain *and* IP, and write a detection for the beacon pattern (URI, interval, TLS fingerprint) rather than just the name.

    The case is complete only when every stage is either explained or recorded as unknown, and indicators from each stage have been blocked or hunted.

### Question 2

A colleague says: "Incidents A, B and C can't be related — every hash, IP and domain is different." Using the campaign table, explain why that reasoning is wrong, which evidence links them, and what defensive changes follow from treating them as one campaign.

??? success "Answer and explanation"
    Hashes, IPs and domains are the **cheapest** things for an attacker to change, so their being different says almost nothing. Campaign analysis looks at what stayed the **same** across incidents: the identical installation path and Run key (`%APPDATA%\UpdSvc\updsvc.exe`), the same C2 URI (`/api/v2/ping`) and 300-second interval, the same freight-invoice lure theme, the same targeting of finance (and later procurement), the same domain-registration habit (registered 2–4 days before use, same registrar) and the same working hours. Together these are far more expensive to change than any single indicator, so they link the incidents with moderate–high confidence.

    Defensive changes: detections on the durable behaviour (the C2 URI and fixed interval to newly registered domains; the install path), hunting that path weekly, targeted awareness for finance and procurement, and anticipating the actor's adaptation — they already switched from macro documents to ZIP+LNK when macros were blocked, so alert on LNK files inside archives reaching those teams.

### Question 3

Put these actions from a ransomware precursor incident into PICERL order and name the stage for each: (a) restore the file server from last night's backup; (b) EDR-isolate two hosts with a Cobalt Strike-like beacon; (c) review: why did the backup alert not page anyone?; (d) confirm the beacon is real and find every host talking to the C2; (e) rebuild both hosts and remove the attacker's new admin account; (f) deploy EDR to the file servers that didn't have it. Which one is the most often skipped, and why does it matter?

??? success "Answer and explanation"
    - **(f) Prepare** — deploying EDR to unmonitored servers is preparation (it may be done *as a result* of lessons learned, which is the loop closing).
    - **(d) Identify** — confirming the alert and scoping the C2 contacts.
    - **(b) Contain** — isolating the two hosts stops the bleeding.
    - **(e) Eradicate** — rebuilding the hosts and removing the rogue admin account locks the attacker out.
    - **(a) Recover** — restoring the file server returns to normal operation.
    - **(c) Lessons learned** — reviewing why the backup alert didn't page anyone.

    Order: f → d → b → e → a → c (and c then feeds new items back into f-type preparation). **Lessons learned** is the most often skipped, because the pressure is over and everyone wants to return to normal work. It matters because it is the only stage that makes the next incident less likely or less damaging; without it, the same gap (here, an unmonitored backup alert) will be used again.

## Related { #related }

- [Encapsulation and the OODA loop](encapsulation-ooda.md) — the previous page; the tempo race between the two chains
- ["Dangerous" and distance to attacker goals](../alert-triage/defining-dangerous.md) — the Kill Chain used for triage
- [Endpoint attacks](../endpoint-attacks/index.md) · [Endpoint defence](../endpoint-defense/index.md) — what happens at each stage on a host, and the controls against it
- [Process creation events](../important-events/process-creation.md) · [Accounts, Defender and PowerShell events](../important-events/accounts-defender-powershell.md)
- [Persistence](../../../adversary/persistence.md) · [Phishing delivery](../../../adversary/phishing-delivery.md)
- [Threat intelligence](../../../threat-intel/index.md)

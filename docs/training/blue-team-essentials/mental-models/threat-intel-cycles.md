---
title: "Threat Intelligence Levels, the Intelligence Cycle and F3EAD — Turning Data into Decisions and Incidents into Intelligence"
tags:
  - training
  - blue-team
  - soc
  - analysis
  - mental-models
  - threat-intel
---

# Threat Intelligence Levels, the Intelligence Cycle and F3EAD — Turning Data into Decisions and Incidents into Intelligence { #threat-intel-cycles }

!!! abstract "What this page covers"
    The threat-intelligence family of models. First, what threat intelligence is actually for — an advantage over the attacker that comes from understanding them, not just a feed of bad IPs. Then the **three levels of threat intelligence** — **strategic**, **operational** and **tactical** — with their consumers, timeframes and how quickly they go stale, shown by turning one invented campaign into three very different products (an IOC package with expiry dates and a STIX 2.1 indicator read line by line, a campaign brief, and a one-page board note). Next, the **intelligence cycle** — Direction, Collection, Processing, Analysis, Dissemination, Feedback — walked through with a real-sounding question from a SOC manager, including why intelligence collection *keeps* duplicates that log pipelines throw away, how processing merges three sources about one domain, and what key assumptions, information gaps and confidence words look like in the finished product. Finally **F3EAD** — Find, Fix, Finish, Exploit, Analyze, Disseminate — the special-operations cycle that joins incident response and intelligence into one loop, walked through on a live intrusion with a hunting query, a **4688** event and LNK metadata explained. The 2026 view (AI-assisted CTI and its failure modes, TLP 2.0, CISA, ATT&CK changes) and practice questions close the page.

!!! note "Labels"
    **[Supplement]** = practical material you need to know, **[Correction]** = a commonly repeated claim that is wrong or outdated, **[Changed]**/**[Caution]** = what has changed recently and what is risky to do the old way. The company (Kestrel Logistics), campaign name, hostnames, accounts, domains, IPs, file names, reports and log lines are invented for illustration (`.example`, documentation and private IPs). Frameworks and their authors are described in my own words.

## The 8 key points { #key-points }

1. **The goal of threat intelligence is advantage**: knowing the attacker's tactics, techniques and procedures (TTPs) and intent well enough to make better defensive decisions than they expect. Indicator lists are a small part of it, not the whole.
2. **Three levels, three audiences.** *Tactical* — IPs, domains, hashes, host artefacts, detections — for SOC, IR and intel analysts. *Operational* — campaigns, capabilities, intent, attribution — for senior responders and SOC leadership. *Strategic* — the threat landscape, risk and investment — for executives and policymakers.
3. **The lower the level, the faster it spoils.** A C2 IP may be useless in days; a campaign's habits last months; a strategic trend lasts years. Tactical intelligence needs expiry dates.
4. **The intelligence cycle** — Direction, Collection, Processing, Analysis, Dissemination, Feedback — is how a threat-intel team turns a question into a trustworthy answer. It is the intelligence counterpart of the incident response cycle.
5. **Direction comes first.** Intelligence answers a *question* someone needs answered. Without one, a team just collects.
6. **Collection keeps overlap on purpose** (several sources saying the same thing is corroboration), while processing does the familiar log work — normalise, de-duplicate, enrich — and analysis applies structured techniques: key assumptions, information gaps, stated confidence.
7. **Undelivered intelligence is worthless**, just like detection without response. Dissemination puts the answer in the right form in the right hands; feedback says whether the question was answered.
8. **F3EAD (Find, Fix, Finish, Exploit, Analyze, Disseminate)** joins operations and intelligence so each feeds the other: intelligence points response at targets, and every incident is mined for new intelligence that comes back as detections. "Fix" means *locate*, and "Exploit" means *harvest information*, not attack.

## Why this matters in a SOC { #why }

Think of a national weather service. A farmer planning next decade's crops needs the climate trend. A logistics manager planning next week's deliveries needs the regional forecast. A cyclist leaving now needs to know whether it will rain on their street in the next hour. Same science, same data, three completely different products — and giving the cyclist a climate report, or the farmer an hourly radar map, is useless. Threat intelligence works the same way, and most of its failures in practice are giving the right information to the wrong person, or in the wrong form, or too late.

Back to the technical reality for an analyst: you are both a **consumer** and a **producer** of intelligence. You consume it every shift — enrichment that tells you a domain was seen in a campaign last week, a detection rule written from an intel report, a brief about which actors target your sector. And every case you work produces raw material for it: indicators, behaviours, timelines. If you understand the levels and cycles, you'll know what to ask your intel team for, what your case notes must contain to be useful to them, and why a feed of 400,000 IPs with no context and no expiry date makes your alert queue worse, not better.

## What threat intelligence is (and isn't) { #what-is-cti }

**Cyber threat intelligence (CTI)** is analysed information about adversaries — who they are, what they want, how they operate and what they are likely to do next — produced to support a decision. The last part is the important one. Raw data ("198.51.100.23 contacted our host") is not intelligence; information ("198.51.100.23 is C2 for a phishing campaign against freight companies") is closer; intelligence is information *analysed and put in context for a decision* ("this campaign has hit us three times, is adapting to our macro block, and is likely to try procurement next — here are the detections to deploy").

**[Correction]** A common belief among analysts is that threat intelligence *is* indicators of compromise (IOCs) — feeds of IPs, domains and hashes. Those are one product of one level. Most of the value lies in understanding behaviour and intent, which is also what lasts longest. (The Pyramid of Pain later in this section puts this into a picture.)

The threat-intelligence family of models covers three angles, all on this page except the last:

- **Levels** — who the intelligence is for (strategic, operational, tactical).
- **Process models** — how intelligence is produced (the intelligence cycle) and how it connects to operations (F3EAD).
- **Analytic models** — how to structure what you know about an intrusion (the Diamond Model, on the next page).

## The three levels of threat intelligence { #levels }

### The levels side by side { #levels-table }

| | **Tactical** | **Operational** | **Strategic** |
| --- | --- | --- | --- |
| **Consumers** | SOC analysts, incident responders, intel analysts, detection engineers | Senior responders and forensic leads, SOC managers and directors | Executives, board, policymakers, risk owners |
| **Question it answers** | What do I block, detect or hunt right now? | Who is doing this, how do they operate, what are they after, what will they do next? | What threats matter to the organisation, and where should we invest? |
| **Typical content** | IPs, domains, URLs, hashes, file paths, registry keys, detection rules, host artefacts with analysis | Campaign tracking, adversary capabilities and intent, TTPs, attribution assessments | Threat landscape, sector trends, geopolitical drivers, risk assessments, resource allocation |
| **Timeframe** | Hours to weeks | Weeks to months | Months to years |
| **Perishability** | Very high — many indicators are stale in days | Medium | Low |
| **Form** | Machine-readable feeds (STIX), rules, enrichment | Briefs, campaign reports, ATT&CK-mapped profiles | Short written assessments, briefings, no jargon |

The **operational** level is the hardest to pin down: too high-level to load into a firewall, too detailed for the board. In practice it is where the most useful thinking for a SOC happens — campaign analysis like the one on the [previous page](kill-chain-did-nist-ir.md#campaign-example) is operational intelligence.

**[Supplement]** Some organisations add a fourth level, **technical intelligence**, for the most low-level, machine-consumable data (raw indicators and malware signatures), and keep "tactical" for TTP-level information about how attacks are carried out. Both splits are in common use. When someone says "tactical intel", check which one they mean.

### Worked example: one campaign, three products { #levels-example }

Kestrel's intel analyst has the KL-CAMP-01 material from three incidents (freight-invoice phishing against finance, Run-key persistence at `%APPDATA%\UpdSvc\`, C2 to `/api/v2/ping` every 300 seconds, an adaptation from macro documents to ZIP+LNK). The same knowledge becomes three products.

**Tactical product — an IOC and detection package.** Part of it, as a STIX 2.1 indicator (STIX — Structured Threat Information Expression — is the common JSON format for sharing threat intelligence, usually transported over the TAXII protocol):

```json
{
  "type": "indicator",
  "spec_version": "2.1",
  "id": "indicator--6f1c2a8e-3b4d-4e7a-9c11-2d5e8f0a7b31",
  "created": "2026-11-20T08:00:00.000Z",
  "modified": "2026-11-20T08:00:00.000Z",
  "name": "KL-CAMP-01 C2 domain (Incident C)",
  "indicator_types": ["malicious-activity"],
  "pattern": "[domain-name:value = 'telemetry-cdn.example']",
  "pattern_type": "stix",
  "valid_from": "2026-11-20T08:00:00Z",
  "valid_until": "2026-12-20T08:00:00Z",
  "confidence": 85,
  "kill_chain_phases": [
    { "kill_chain_name": "lockheed-martin-cyber-kill-chain", "phase_name": "command-and-control" }
  ]
}
```

- `"type": "indicator"`, `"spec_version": "2.1"` — this object is a STIX 2.1 *indicator*: a pattern that, if matched, suggests malicious activity.
- `"id": "indicator--…"` — a globally unique ID, so updates and revocations can refer back to exactly this object.
- `"created"`, `"modified"` — when it was made and last changed; tools use `modified` to decide which version is newest.
- `"name"` — a human-readable label. Good names say *which* campaign and *which* incident.
- `"pattern": "[domain-name:value = 'telemetry-cdn.example']"` — the detection logic in STIX patterning language: "a domain name whose value is `telemetry-cdn.example`". Patterns can also combine conditions (an IP *and* a port, a file hash *or* a file name).
- `"valid_from"`, `"valid_until"` — **the indicator's shelf life**. After 20 December, consuming tools should stop alerting on it. This is how tactical intelligence handles perishability; an indicator with no expiry lives forever in a blocklist and eventually fires on whoever buys the domain next.
- `"confidence": 85` — how sure the producer is (0–100), so consumers can decide whether to block or only alert.
- `"kill_chain_phases"` — places the indicator on a stage of the Kill Chain. You can name any kill chain here, ATT&CK tactics included.

The package also contains the durable items, which are far more valuable than the domain: a behavioural detection for a 300-second `/api/v2/ping` beacon to a newly registered domain, a hunt for `%APPDATA%\UpdSvc\updsvc.exe`, and a rule for LNK files inside ZIP attachments reaching finance and procurement.

**Operational product — a campaign brief** for the SOC manager and IR lead:

```
KL-CAMP-01 — Campaign brief (update 3)                    TLP:AMBER
Bottom line: One actor is behind incidents A–C. It is adapting to our
defences and will likely target procurement payments next.
Activity: 3 intrusions since Sept; freight-invoice lures; finance
staff targeted by name; procurement added in Nov.
Capabilities: Custom backdoor (Run key, %APPDATA%\UpdSvc\); HTTPS C2
with fixed 300 s beacon; switched macro DOCM -> ZIP+LNK within 3 weeks
of our macro block (T1566.001, T1204.002, T1547.001, T1071.001).
Assessed intent: Financial — likely payment diversion (moderate confidence).
Gaps: No visibility of what was viewed on the finance share in Incident B.
Recommended actions: see tactical package v3; tabletop a payment-fraud
scenario with finance; extend email detections to procurement.
```

- **"Bottom line"** first — the reader may stop after one sentence.
- **Capabilities** are described as behaviours with ATT&CK IDs, so the SOC can check detection coverage against them.
- **Assessed intent** and **Gaps** are stated openly, with confidence. An operational product that hides its uncertainty is dangerous.
- **TLP:AMBER** marks how far it may be shared (the Traffic Light Protocol is covered in the Analysis OPSEC section later).

**Strategic product — a one-page note** for the executive team:

```
Freight-invoice fraud targeting Kestrel (for: Executive Committee)
A financially motivated group has tried three times since September to
compromise our finance staff by email, each time adjusting to our
defences. No money has been lost. Industry reporting shows payment-
diversion fraud against logistics firms rising this year.
Decision needed: approve a mandatory call-back check for any change to
supplier bank details (Finance), and fund EDR coverage for the remaining
14% of servers (IT) this quarter.
```

- No IPs, no ATT&CK IDs, no jargon. It says what the threat means for the business and asks for **decisions** only executives can make: a process change and a budget.

Same campaign, same analyst, three products. A strategic note full of hashes would be ignored; a tactical package without expiry dates would pollute the SIEM; an operational brief without stated gaps would mislead the IR lead.

## The intelligence cycle { #intelligence-cycle }

### What it is { #intelligence-cycle-what }

The **intelligence cycle** is the classic description of how intelligence organisations — national ones and corporate CTI teams alike — turn questions into answers. The US intelligence community describes it in roughly six steps, and the names vary a little between sources (Planning and Direction, Processing and Exploitation, Analysis and Production, Evaluation). A common security version:

**Direction → Collection → Processing → Analysis → Dissemination → Feedback** (and back to Direction).

Compare it with the incident response cycle on the previous page: both gather data, analyse it, act and feed back. The difference is the output — a response to an incident versus an intelligence product that answers a question.

### Walking the cycle with a real question { #cycle-walkthrough }

**1. Direction — decide the question.** Kestrel's SOC manager, after Incident C, asks: *"Is KL-CAMP-01 likely to go after our supplier payment process in the next three months, and would we detect it?"* The intel analyst sharpens it into a **priority intelligence requirement (PIR)** — a question specific enough that you know when it's answered:

```
PIR-07: Within the next 90 days, how likely is KL-CAMP-01 to attempt
payment diversion via procurement or accounts payable, by what
methods, and which of those methods do we currently detect?
Requester: SOC manager   Due: 2026-12-05   Consumers: SOC, IR lead, CFO
```

- `Within the next 90 days` — a time window makes the question answerable.
- `how likely … by what methods … which do we currently detect` — three parts: an estimate, a method list, a coverage check.
- `Consumers` — tells the analyst up front that some of the answer must be written for the CFO (strategic) as well as for the SOC (tactical).

Without this step, a CTI team does what many do: collects everything, reads everything, and produces nothing anyone asked for.

**2. Collection — gather what's needed to answer it.** Sources fall into internal and external:

- *Internal:* the three incident case files, email-gateway logs for all lures, EDR and proxy data, the finance team's records of suspicious calls about bank-detail changes.
- *External:* reports shared by the logistics sector's information-sharing group, vendor reports on payment-diversion fraud, public advisories from national cyber agencies, passive OSINT on the actor's domains (registration data, passive DNS — collected without touching the attacker's infrastructure; see the OPSEC section later).

**Here intelligence collection differs from log collection.** A log pipeline [de-duplicates](../log-pipeline/enrichment-normalization-storage.md) to save cost and noise. Intelligence collection deliberately keeps **overlapping** reports, because three independent sources saying the same thing is **corroboration**, and one source saying something nobody else does is a claim to treat carefully.

**3. Processing — make the data usable.** The familiar log-pipeline tasks reappear: normalise formats, index, filter, de-duplicate *within* a source, enrich. For example, three sources mention the same domain:

| Source | Raw entry | After processing |
| --- | --- | --- |
| Kestrel case KL-IR-2026-044 | `telemetry-cdn[.]example` C2, seen 2026-11-18 | `domain=telemetry-cdn.example`, `role=C2`, `first_seen=2026-11-18`, `source=internal`, `reliability=confirmed` |
| Sector sharing group report | "TELEMETRY-CDN.EXAMPLE used against two freight firms" | same domain, `victims_sector=logistics`, `count=2`, `source=ISAC`, `reliability=usually reliable` |
| Vendor blog | `hxxps://telemetry-cdn.example/api/v2/ping` | same domain, `uri=/api/v2/ping`, `source=vendor`, `reliability=fairly reliable` |

- **Normalised:** defanged notations (`[.]`, `hxxps`) restored for machine use, case folded, one field name for "domain".
- **Linked, not merged away:** three records for one domain, each keeping its source and reliability — that's what makes corroboration visible later.
- **Enriched:** the URI from the vendor report connects the domain to the `/api/v2/ping` behaviour Kestrel already detects.

**4. Analysis — answer the question.** This is where the structured analytic techniques covered in the Structured Analysis section belong — and an intel team should apply them more strictly than anyone, because others will act on its conclusions without seeing the evidence. Two habits are essential:

- **List key assumptions** — things you are treating as true without proof. *"We assume incidents A–C are one actor (moderate–high confidence). We assume the sector reports describe the same actor because the C2 URI pattern is identical."*
- **List information gaps** — what you don't know that would change the answer. *"We cannot see what was viewed on the finance share in Incident B. We have no visibility of supplier-side email compromise."*

Then state the judgement with an explicit confidence word, in a consistent vocabulary ("likely", "almost certainly", "roughly even chance") so readers don't have to guess what "may" means.

**5. Dissemination — get it to the people who need it, in a form they can use.** Intelligence nobody reads is like detection without response. For PIR-07 the analyst produces three outputs: detections and hunts for the SOC (tactical), an updated campaign brief for the IR lead (operational), and three sentences plus a decision for the CFO (strategic). The answer, in the form the CFO gets:

```
PIR-07 answer (2026-12-03): We assess it is LIKELY (roughly 60-75%)
that KL-CAMP-01 will attempt supplier payment diversion within 90 days,
most likely by emailing accounts payable with fake bank-detail changes.
We currently detect the malware route but NOT a pure email request
without attachments. Recommended: call-back verification for all
bank-detail changes, effective immediately.
```

- `LIKELY (roughly 60-75%)` — the confidence word comes with a range so the CFO and the SOC read it the same way.
- `We currently detect … but NOT …` — the coverage part of the PIR, answered honestly. The gap is the most actionable sentence in the product.

**6. Feedback — was the question answered?** The SOC manager replies that the coverage answer was exactly what was needed, but asks a follow-up: *which mailboxes in accounts payable have external forwarding rules?* That becomes a new direction, and the cycle turns again. Feedback is also how an intel team learns which of its products are actually used.

### Why threat intelligence is usually its own team { #separate-team }

Looking at the cycle, it's clear why CTI is often a separate role rather than "something the SOC does between alerts". It works at three levels at once, writes for audiences from detection engineers to the board, and must keep its analysis logically sound and its confidence honest. That is specialised work. The SOC's job is to be a good customer and a good source: ask clear questions, and write case notes that record indicators, behaviours, timelines and what was *not* seen.

## F3EAD: joining operations and intelligence { #f3ead }

### Where it came from and what's different { #f3ead-idea }

**F3EAD** — **Find, Fix, Finish, Exploit, Analyze, Disseminate** — comes from military special operations, where it was used in the 2000s to target networks of adversaries quickly: every raid was mined for information that pointed to the next target. It differs from OODA and the intelligence cycle in two ways:

1. **Intelligence must change operations.** Its purpose is action, not reports.
2. **The two cycles feed each other, not just themselves.** The operations half (Find, Fix, Finish) ends by handing material to the intelligence half (Exploit, Analyze, Disseminate), and the intelligence half ends by handing new targets back to operations.

That makes it one of the best high-level pictures of how a SOC/IR team and a CTI team should work together. The names are confusing because of their military origin, so here they are in security terms:

| Step | Military sense | Security meaning | Compare with |
| --- | --- | --- | --- |
| **Find** | Choose and locate targets | Which threats will we pursue? What will adversaries try against us? (from past incidents and intel analysis) | Direction |
| **Fix** | "Get a fix on" the target's position | Identify the adversary *on our network*: detect, hunt, confirm, scope. Not "fix the machine"! | Identify / detection |
| **Finish** | Act against the target | Incident response: contain and eradicate | Contain, Eradicate |
| **Exploit** | Exploit captured material for intelligence | Harvest *everything* useful from the response: indicators, malware, logs, timelines, attacker mistakes. Not "exploit a vulnerability"! | Collection |
| **Analyze** | Turn material into intelligence | Work out what the attacker did, what they will likely do next, and build an attacker profile | Processing, Analysis |
| **Disseminate** | Share with those who need it | Tactical, operational and strategic products back to SOC, IR, leadership — feeding new Find | Dissemination |

### Worked example: F3EAD on Incident C { #f3ead-example }

**Find.** The KL-CAMP-01 brief (update 2) said the actor would likely adapt to the macro block and add procurement as a target. The SOC therefore made "LNK or script files arriving in archives to finance and procurement" a hunting priority.

**Fix.** An analyst runs a hunting query in the EDR's search language. This example uses Kusto Query Language (KQL), as used by Microsoft Defender's advanced hunting; each line explained:

```
DeviceProcessEvents
| where Timestamp > ago(7d)
| where InitiatingProcessFileName =~ "explorer.exe"
| where FileName in~ ("powershell.exe", "cmd.exe", "mshta.exe", "wscript.exe")
| where ProcessCommandLine has_any (".lnk", "Statement", "Invoice", "-enc", "-w hidden")
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine
```

- `DeviceProcessEvents` — the table of process-start events collected by the EDR from every onboarded machine.
- `where Timestamp > ago(7d)` — only the last seven days.
- `where InitiatingProcessFileName =~ "explorer.exe"` — the parent is Explorer, which is what happens when a user double-clicks a file such as an LNK shortcut. (`=~` means "equals, ignoring case".)
- `where FileName in~ (…)` — the child is a script host or shell — what a malicious LNK typically launches.
- `where ProcessCommandLine has_any (…)` — the command line contains lure-like words or classic hiding options (`-enc` for an encoded command, `-w hidden` for a hidden window).
- `project …` — show only these columns.

The result:

```
Timestamp             DeviceName   AccountName  FileName        ProcessCommandLine
2026-11-18 08:47:12   KL-WS-0712   m.lindqvist  powershell.exe  powershell -w hidden -enc SQBFAFgAIAAo...
```

- One hit: `m.lindqvist`, a procurement officer, on KL-WS-0712. A hidden, encoded PowerShell launched by Explorer — exactly the predicted pattern. The Find step paid off: without it nobody would have been looking at procurement.

The same execution in the Windows Security log of KL-WS-0712:

```
Event ID 4688  Computer: KL-WS-0712  2026-11-18T08:47:12Z
  New Process Name:     C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe
  Creator Process Name: C:\Windows\explorer.exe
  Process Command Line: powershell -w hidden -enc SQBFAFgAIAAo...
  Subject Account Name: m.lindqvist
```

- **Event 4688** again — process created, with the creator (parent) and, if the policy is enabled, the full command line. It fires every time a process starts; attackers care because it records their execution even when the payload itself is fileless. Here it confirms **T1204.002 User Execution: Malicious File** (the LNK click) leading to **T1059.001 Command and Scripting Interpreter: PowerShell**, with the encoding being **T1027 Obfuscated Files or Information**. Decoding the Base64 (it's UTF-16LE, as PowerShell's `-enc` requires) shows a download from `telemetry-cdn.example`. Scoping finds no other hosts. The adversary is *fixed*.

**Finish.** Contain and eradicate as on the previous page: isolate KL-WS-0712, block the domain and IP, purge the email from all seven recipients, reset `m.lindqvist`'s credentials, remove the Run key and binary.

**Exploit.** Now harvest everything, not just the indicators needed to close the case. A shallow team stops at the domain and the hash. A good one collects:

- the email with full headers (sending infrastructure, the mail client string, timing);
- the ZIP and LNK files themselves;
- the decoded PowerShell and the second-stage binary;
- the full EDR timeline, including commands the attacker typed after the beacon started;
- metadata the attacker didn't mean to leave. LNK files carry information about the machine they were created on. Parsed with a free LNK parser (output trimmed and simplified):

```
$ lnkparse Statement_0412.lnk
Target:            C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe
Arguments:         -w hidden -enc SQBFAFgAIAAo...
Icon location:     C:\Windows\System32\imageres.dll,  index 2
Creation time:     2026-11-12 06:31:55 UTC
Machine ID:        desktop-r7q2k
Volume serial:     5A1C-9E03
MAC address:       00:00:5e:00:53:2a
```

- `Target` and `Arguments` — what the shortcut actually runs: PowerShell with a hidden window and an encoded command. The user saw only a document icon.
- `Icon location: imageres.dll, index 2` — the icon borrowed from a system file to look like a document.
- `Creation time` — when the LNK was built on the attacker's side: six days before delivery.
- `Machine ID: desktop-r7q2k`, `Volume serial`, `MAC address` — taken from the **attacker's build machine** (from the shortcut's tracker data). Attackers often forget to scrub these. They are a strong link between files built on the same machine.

**Analyze.** The analyst compares: the decoded PowerShell downloads the same backdoor family as incidents A and B (same install path, same `/api/v2/ping` C2), so this is KL-CAMP-01. The LNK `Machine ID` and volume serial are searched against the sector sharing group's data and match LNK files reported by another freight company — the actor uses one build machine for several victims. The lure timing (built Wednesday, sent the following Tuesday) and the jump from finance to procurement support the payment-diversion hypothesis in PIR-07.

**Disseminate.** Outputs go back to everyone who can use them, and feed the next **Find**:

- **Tactical:** new STIX indicators with expiry dates; a detection for LNK files whose tracker `Machine ID` is `desktop-r7q2k`; the KQL hunt above turned into a scheduled rule.
- **Operational:** campaign brief update 3 (shown earlier), shared with the sector group under TLP:AMBER so the other freight company can hunt too.
- **Strategic:** the CFO note asking for call-back verification on bank-detail changes.
- **New Find:** "accounts-payable mailboxes and supplier-change requests" becomes the next hunting priority — which is exactly where PIR-07's feedback had pointed.

The loop closes: the intelligence half pointed operations at procurement; the operations half produced the metadata that linked Kestrel's attacker to another victim.

## How the cycles compare { #cycles-compare }

| Model | Whose loop | Purpose | Its "collect" step | Its "act" step |
| --- | --- | --- | --- | --- |
| OODA | Anyone in a contest | Act faster and better under uncertainty | Observe | Act |
| Incident response cycle | SOC / IR | Remove an attacker and harden | Identify | Contain, Eradicate, Recover |
| Intelligence cycle | CTI team | Answer an intelligence question | Collection | Dissemination |
| F3EAD | SOC/IR and CTI together | Make operations and intelligence feed each other | Exploit | Finish (operations) and Disseminate (intelligence) |

## The 2026 view { #trends }

!!! success "[2026 Current] Still valid"
    The three levels, the intelligence cycle and F3EAD are still the standard vocabulary of CTI teams and remain the basis of CTI training and job descriptions. Priority intelligence requirements, stated confidence, key assumptions and information gaps are still the marks of a trustworthy intelligence product, and the warning that intelligence nobody uses is worthless is as true as ever. STIX 2.1 and TAXII 2.1 are still the main open standards for exchanging machine-readable intelligence.

!!! info "[Changed] What has changed"
    - **AI is now part of the cycle.** Language models are widely used to summarise long reports, extract indicators and ATT&CK techniques, and turn prose into structured STIX data — mainly speeding up Collection and Processing. Research in 2025–2026 also showed the failure modes: invented or mis-mapped techniques, mixed-up actors, and the risk of poisoned or misleading source reports being repeated confidently.
    - **Attackers use AI too**, which shifts some intelligence questions — for example, AI-written phishing lures in fluent local language and quickly regenerated tooling make lure wording and file hashes even less durable as indicators, and push analysis further up toward behaviour.
    - **Sharing labels changed.** **TLP 2.0** (August 2022) replaced TLP:WHITE with **TLP:CLEAR** and added **TLP:AMBER+STRICT** (recipient organisation only). Products still marked TLP:WHITE are using the old version.
    - **Sources moved.** In the US, US-CERT's functions now sit within **CISA**, which publishes the joint advisories many teams collect; in Australia, national advisories come from **ASD's ACSC**. Check that your collection plan points to current publishers.
    - **ATT&CK keeps changing.** ATT&CK v19 (April 2026) split the old Defense Evasion tactic into Stealth and Defense Impairment, and v20 (October 2026) added AI-related abuse techniques. Operational products mapped to ATT&CK need to state the version they used.

!!! warning "[Caution] Wrong or risky to do the old way"
    - **Don't load indicator feeds without context or expiry.** Indicators with no `valid_until` stay in blocklists forever and eventually hit shared hosting, CDNs and re-registered domains, producing false positives and blocked business.
    - **Don't count repeated reports as independent corroboration.** Many vendor and media reports copy one original source; studies of CTI reporting have found heavy overlap. Trace claims back to their origin before treating them as confirmed.
    - **Don't trust AI summaries or extractions without checking the source.** Verify every indicator and ATT&CK mapping an AI tool produces against the original report before it becomes a detection or a briefing.
    - **"Finish" is not hack-back.** In F3EAD for a SOC, Finish means containing and eradicating on *your* network. Attacking an adversary's infrastructure is illegal for private organisations in most countries.
    - **Don't skip Direction.** A CTI function without written requirements drifts into collecting everything and producing nothing the SOC or leadership asked for.

## Practice questions { #quiz }

### Question 1

For each item, say which level of threat intelligence it belongs to and who the main consumer is: (a) "Ransomware groups increasingly target logistics firms during peak season; we recommend funding offline backups"; (b) a list of 40 IPs and domains with `valid_until` dates; (c) "Actor X moved from macro documents to ZIP+LNK within three weeks of our macro block and is now targeting procurement"; (d) a detection rule for a 300-second HTTPS beacon to newly registered domains. Why does (b) need expiry dates when (a) doesn't?

??? success "Answer and explanation"
    - **(a) Strategic** — threat landscape plus an investment recommendation; for executives and risk owners.
    - **(b) Tactical** — atomic indicators; for SOC, IR and detection engineering (and tools).
    - **(c) Operational** — campaign behaviour, adaptation and likely next target; for senior responders and SOC leadership.
    - **(d) Tactical** — a detection the SOC deploys (it is built on behaviour, so it lasts much longer than the IP list, but it is still a tactical product).

    (b) needs expiry dates because tactical indicators are **highly perishable**: attackers rotate IPs and domains within days, and old ones get reassigned to innocent users. Left in a blocklist forever, they produce false positives. A strategic trend like (a) stays valid for months or years, so it ages slowly.

### Question 2

Your CISO says: "Tell me everything about ransomware." Using the intelligence cycle, explain what's wrong with this as a starting point, rewrite it as a usable requirement, and describe one thing that happens differently in Collection and one thing that must appear in Analysis.

??? success "Answer and explanation"
    "Everything about ransomware" is not answerable — there is no scope, no timeframe, no decision it supports, so the team will collect endlessly and deliver nothing specific. **Direction** must turn it into a question that defines when it's answered, e.g.: *"Which ransomware groups are most likely to target Kestrel in the next six months, through which initial access methods, and which of those methods do we currently prevent or detect? For: CISO and SOC; due in two weeks."*

    **Collection:** unlike a log pipeline, keep overlapping reports from different sources, because agreement between independent sources is corroboration (while checking they really are independent and not copies of one report). **Analysis:** list key assumptions (e.g. "we assume the sector reports reflect actors active in our region") and information gaps (e.g. "no visibility of our managed service provider's remote-access logs"), and state the judgement with a consistent confidence word. Then **Dissemination** in a form the CISO can act on, and **Feedback** to confirm the question was answered.

### Question 3

A new analyst reads the F3EAD diagram and says, "So after we *fix* the infected laptop, we *exploit* the attacker's server?" Correct both misunderstandings, then describe what the Exploit and Disseminate steps should have produced in the Incident C example and how they fed the next Find.

??? success "Answer and explanation"
    **Fix** means "get a fix on" — locate and identify the adversary on your network (detection, hunting, scoping). It has nothing to do with repairing the laptop; that happens in **Finish** (contain, eradicate). **Exploit** means exploiting the *information* gathered during the response for intelligence — like Collection in the intelligence cycle. It never means attacking the adversary's systems, which would be illegal for a company.

    In Incident C, **Exploit** gathered the email and headers, the ZIP and LNK, the decoded PowerShell and second-stage binary, the EDR timeline, and the LNK's tracker metadata (`Machine ID`, volume serial, MAC address of the attacker's build machine). **Analyze** linked it to KL-CAMP-01 and, via the build-machine metadata, to another freight victim. **Disseminate** produced tactical (expiring STIX indicators, a detection on the LNK machine ID, a scheduled hunt), operational (campaign brief update shared under TLP:AMBER) and strategic (CFO call-back verification) products. The analysis also pointed to accounts-payable mailboxes and supplier-change requests as the next likely target, which became the next **Find** — closing the loop between intelligence and operations.

## Related { #related }

- [Kill Chain, campaigns, defence in depth, NIST CSF and the IR cycle](kill-chain-did-nist-ir.md) — the previous page; campaign analysis is operational intelligence
- [Encapsulation and the OODA loop](encapsulation-ooda.md) — the other decision loop
- [Enrichment, normalisation and storage](../log-pipeline/enrichment-normalization-storage.md) — the processing tasks intelligence reuses
- [Process creation events](../important-events/process-creation.md) · [File identification](../file-analysis/file-identification.md)
- [Threat intelligence](../../../threat-intel/index.md) · [Phishing delivery](../../../adversary/phishing-delivery.md) · [PowerShell cradles](../../../adversary/powershell-cradles.md)

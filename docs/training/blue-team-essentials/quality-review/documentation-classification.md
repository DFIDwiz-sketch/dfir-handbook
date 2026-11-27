---
title: "Closing a Case Well — Consistent Quality, Good Documentation, Analytical Completeness, Classification and Attribution"
tags:
  - training
  - blue-team
  - soc
  - analysis
  - incident-response
---

# Closing a Case Well — Consistent Quality, Good Documentation, Analytical Completeness, Classification and Attribution { #documentation-classification }

!!! abstract "What this page covers"
    The earlier sections took an alert from the queue to a confirmed intrusion and a chosen response. This page is about the last step that most SOCs rush: **closing the case properly**. It starts with the tension every analyst feels — **speed versus quality** — and why quality needs a written standard and regular measurement, because unlike a growing queue, poor quality is invisible. Then what **good documentation** means in practice: a closing checklist your team agrees on, how much detail is "enough", and a full case record filled in for an invented phishing-to-loader incident at Wattle Ridge Energy, with the proxy log, Zeek `http.log` line and Windows event **4688** read field by field. Next, **analytical completeness**: dropping into the kill chain at the point of detection and working both backwards (how did it get here?) and forwards (what would it have done?), shown as a completeness table mapped to MITRE ATT&CK. Then **closed-case classification** — disposition, incident type, the key times (detect, assign, contain, remediate), detection source, device type, motivation and a short summary — and how a quarter's worth of classified cases turns into real decisions, with VERIS as a reference vocabulary. Finally, **attribution**: why most SOCs cannot reliably name a state actor, what they *can* do (recognise the same intruder coming back), and why motivation and TTPs matter more than a name.

!!! note "Labels"
    **[Supplement]** = practical material you need to know, **[Correction]** = a commonly repeated claim that is wrong or outdated, **[Changed]**/**[Caution]** = what has changed recently and what is risky to do the old way. The company (Wattle Ridge Energy, `wattleridge.example`), people, hostnames, domains, IPs, case numbers and log lines are invented for illustration (`.example`, documentation and private IPs). Frameworks, researchers, agencies, vendors and public incidents are real and described in my own words.

## The 8 key points { #key-points }

1. **Speed and quality pull against each other.** A SOC must hit a minimum of both. Speed is easy to see (the queue, the SLA clock); quality is not — so it needs a deliberate standard and regular checks.
2. **Write down what "done" means.** A shared closing checklist — observables recorded, event classified, every investigation question answered, remediation described, other hosts checked, steps reproducible, feedback given — turns "good enough" from a feeling into a test.
3. **Notes should be reproducible, not exhaustive.** Someone else (or you, in a year) should be able to follow them and repeat the work. Bigger and targeted incidents deserve more detail.
4. **Detection drops you into the middle of the story.** Work **backwards** from the detection point to delivery, and **forwards** to what the malware would have done (C2, objectives) — then put every indicator you find into threat intelligence.
5. **Classification is where metrics come from.** Disposition, incident type, key timestamps, detection source, affected device type, motivation and a short summary — collected on every case — become trends that drive tuning, investment and threat models.
6. **Your own closed cases are your best threat intelligence.** No feed knows what actually attacks *your* organisation; your classified cases do.
7. **Attribution to a named state actor is usually beyond an average SOC.** The realistic goal is to notice when **the same intruder comes back**, and to be honest about confidence.
8. **A name rarely changes the response.** Motivation, TTPs and what they were after decide how you defend next time; the name is a bonus.

## Why this matters in a SOC { #why }

Think of a hospital ward round. Doctors move quickly from bed to bed — the waiting room is full. But every patient leaves with a discharge summary: what was wrong, what was done, which tests were run, what to watch for, and when to come back. Months later, a different doctor can read that summary in two minutes and understand the case. And every year, the hospital counts its discharge summaries: which conditions were most common, how long treatment took, which tests found problems early. Without those summaries, the ward would be fast — and would never learn anything.

Back to the technical reality. A SOC that closes tickets with "malware removed, closed" is fast today and blind tomorrow. When the same sender domain shows up next month, nobody can find that it was seen before. When the board asks "is our email gateway worth the money?", nobody can answer. When the same intruder returns through a different door, nobody connects it. Closing a case well is where the [intelligence cycle](../mental-models/threat-intel-cycles.md#intelligence-cycle) gets its best raw material, where the [F3EAD](../mental-models/threat-intel-cycles.md#f3ead) **Exploit–Analyse–Disseminate** half actually happens, and where the "lessons learned" step of the [incident response cycle](../mental-models/kill-chain-did-nist-ir.md#ir-cycle) stops being a slogan. It also protects you: a well-documented case is your evidence that you did the right things, in the right order, for the right reasons.

## Keeping consistent quality { #quality }

Every SOC lives with constant pressure on **speed of analysis**. Alerts pile up, service-level agreements (SLAs) set deadlines for acknowledging and resolving them, and everyone can see the queue grow. That pressure is legitimate — a phishing click left untouched for six hours is a real risk. But pushed too far, speed eats quality: questions go unasked, other hosts go unchecked, cases are closed as "false positive" because that is faster than proving otherwise.

Picture a seesaw with **speed** on one side and **quality** on the other. There is a minimum acceptable speed and a minimum acceptable quality, and for a fixed team, pushing one up tends to push the other down. The trouble is that the two sides are not equally visible:

| | Speed | Quality |
| --- | --- | --- |
| How you notice a problem | Queue length, SLA breaches, dashboards turn red | Usually only when something goes wrong later — a missed second host, a reinfection, a repeat attacker nobody recognised |
| Who notices | Everyone, immediately | Often nobody, for months |
| Measured by default? | Yes — every ticketing system counts it | No — someone has to decide to measure it |

So quality needs two deliberate steps. **Step one: define the standard** — write down what a well-handled case looks like. **Step two: measure against it regularly** — through self-checks before closing and through peer review of a sample of closed cases (covered on the [next page](challenge-analysis.md)). Without step one, reviewers argue about taste. Without step two, the standard is a poster on the wall.

## Good documentation { #documentation }

### Make the list { #closing-checklist }

The simplest way to define "good enough" is for the team to write a **closing checklist** together — describe a well-done incident write-up, item by item. A practical starting list:

1. **Are all observables documented, and is the event classified?** Hashes, file paths, domains, IPs, URLs, accounts, email sender and subject — recorded in a structured way, not buried in a paragraph. Classification fields filled in (see [below](#classification)).
2. **Are all investigation questions sufficiently answered?** The questions you wrote at the start (see [investigation questions](../investigation/questions-and-data.md)) each have an answer — or an honest "could not determine, because...".
3. **Did you explain how the situation was remediated?** What was done, by whom, when, and how you confirmed it worked.
4. **Did you try to find every stage of the attack**, from reconnaissance to objectives? (See [analytical completeness](#completeness).)
5. **Did you make sure no other hosts have the same problem?** If others did, are the cases linked so they can be tracked together?
6. **Could someone else follow your steps** in the future and repeat the investigation?
7. **Did you feed back what you learned** — new blocks, new detections, tuning requests, a note to the email or endpoint team about the control that failed?

The list is not exhaustive, and each team should adapt it. But notice what it covers: the attacker's tactics and motivation, remediation on *this* host and *all* others, and feedback about the defensive failure to the people who can fix it.

### How much detail is enough? { #detail-level }

A good rule: notes should be **thorough enough that someone else could follow and reproduce what you did** if the same malware or situation appeared again — but not so detailed that writing them becomes painful and slows the whole SOC. "Searched proxy logs" is too little (which logs? which time range? what query? what did you find?). A screenshot of every click is too much.

Not every case needs the same depth. A blocked commodity phish with no click can be a few lines. An incident with an interactive attacker, a targeted campaign, a data-protection question or possible legal follow-up needs much more, because it is more likely to have a large impact, to be revisited, and to be read by people outside the SOC (management, legal, regulators, an external incident response firm).

**[Supplement]** Three habits make documentation both faster and better. **Write as you go**, with timestamps, rather than reconstructing at the end — memory is unreliable (see [memory and experience](../analyst-cognition/memory-experience.md)). **Record the query, not just the result**, so the search can be rerun. **State times in UTC** (or state the time zone explicitly) — mixing local time from one tool with UTC from another is one of the most common sources of wrong timelines.

### Worked example: a case record, filled in { #case-record }

On a Tuesday morning, Wattle Ridge's EDR raises an alert on finance laptop `WR-LT-0452`: an unknown executable written to the user's roaming profile and a registry Run key created for it. The EDR quarantined the file. The analyst, Mia Okafor, investigates. Here are three pieces of evidence she records, followed by the case record.

**Evidence 1 — proxy log.** She searches the web proxy for the laptop's IP in the half hour before the alert:

```text
2026-10-06T08:52:14Z 10.20.31.52 jlee GET https://files-share-docs.example/d/7Qk2 200 application/zip 48213 "Uncategorised" ALLOWED
```

Field by field:

- `2026-10-06T08:52:14Z` — the time, in UTC (the `Z` means UTC).
- `10.20.31.52` — the internal IP of `WR-LT-0452`.
- `jlee` — the authenticated proxy user, Jordan Lee from accounts payable.
- `GET https://files-share-docs.example/d/7Qk2` — the request: a short file-share-style link. Because the proxy does TLS inspection, the full URL path is visible.
- `200` — the server answered successfully.
- `application/zip` and `48213` — the response was a 48 KB zip file.
- `"Uncategorised"` — the proxy's category engine had never seen this domain. New, uncategorised domains are a classic sign of freshly registered attack infrastructure.
- `ALLOWED` — the policy let it through, because "Uncategorised" was not blocked. That is a **control gap** worth feeding back.

**Evidence 2 — Zeek `http.log`.** The download also passed the Zeek sensor. Because it was HTTPS, Zeek on its own would only see the TLS handshake; but at Wattle Ridge the sensor sits behind the TLS-inspecting proxy, so a decrypted copy is visible (some columns removed):

```text
#fields ts                  id.orig_h    id.resp_h      method host                    uri      status_code resp_mime_types  resp_fuids
1791276734.512  10.20.31.10  203.0.113.45   GET    files-share-docs.example /d/7Qk2  200         application/zip  F3kd92LmQ1
```

- `ts` — Unix epoch time; `1791276734` converts to `2026-10-06 08:52:14 UTC`, matching the proxy.
- `id.orig_h 10.20.31.10` — here the "client" is the proxy itself, not the laptop. That is why you need the proxy log to tie the request to `WR-LT-0452` and `jlee`.
- `id.resp_h 203.0.113.45` — the server's IP. Record it as an observable.
- `host` and `uri` — the same domain and path.
- `resp_mime_types application/zip` — Zeek's own file-type detection agrees it was a zip.
- `resp_fuids F3kd92LmQ1` — Zeek's file ID. You can look it up in `files.log` to get the file's hash, then compare it with what the EDR saw.

**Evidence 3 — Windows Security event 4688.** On the laptop, process-creation auditing (with command lines) is enabled:

```text
EventID:            4688
TimeCreated:        2026-10-06T08:52:41Z
Creator Process Name: C:\Program Files\7-Zip\7zFM.exe
New Process Name:   C:\Windows\System32\wscript.exe
Process Command Line: "C:\Windows\System32\WScript.exe" "C:\Users\jlee\AppData\Local\Temp\7zO1A2B\Remittance_0610.js"
Subject Account:    WATTLERIDGE\jlee
Token Elevation Type: %%1938 (Limited)
```

**Event 4688** means *"a new process has been created"*. It fires every time Windows starts a process, if the "Audit Process Creation" policy is enabled — and it only includes the command line if the separate "Include command line in process creation events" setting is turned on. Attackers care about it because it records exactly what they ran and with which arguments; that is why it is one of the most valuable events on a workstation and why attackers who gain admin rights sometimes try to clear the Security log (see [important events](../important-events/index.md)). Reading this one:

- `Creator Process Name ... 7zFM.exe` — the parent was the 7-Zip file manager: the user opened the zip.
- `New Process Name ... wscript.exe` — Windows Script Host, which runs `.js` and `.vbs` files. Finance users almost never have a reason to run script files.
- `Process Command Line` — the script `Remittance_0610.js` ran straight from 7-Zip's temporary extraction folder. This is **user execution of a malicious file** (MITRE ATT&CK T1204.002) using JavaScript (T1059.007).
- `Token Elevation Type %%1938 (Limited)` — it ran with normal user rights, not as administrator. Good news: the loader could only write to the user's own profile and user-level Run key.

Now the case record Mia writes before closing:

```text
Case:            WR-2026-0412
Title:           Phishing link -> JS dropper -> loader blocked at install (WR-LT-0452)
Analyst:         Mia Okafor          Reviewer (sample): pending
Disposition:     True positive
Incident type:   Malware (commodity loader), delivered by phishing
Detection source: EDR (behavioural: unsigned binary + Run key)
Device type:     User laptop (finance)
Motivation:      Financial / opportunistic (likely initial-access broker or infostealer)
Attribution:     None attempted; infrastructure matches no earlier case

Timeline (UTC)
  08:41:03  Email delivered to 14 finance recipients, sender accounts@remit-notice.example
  08:52:14  jlee downloads Remittance_0610.zip from files-share-docs.example (proxy, Zeek)
  08:52:41  wscript.exe runs Remittance_0610.js (4688)
  08:52:58  JS downloads svcupd.exe to %APPDATA%\Updater\ ; Run key written
  08:53:02  EDR quarantines svcupd.exe, alert raised            <- detection
  09:05:40  Alert assigned to M. Okafor                         <- assign
  09:19:55  WR-LT-0452 network-isolated via EDR                 <- contain
  13:40:10  Laptop reimaged; jlee password reset, sessions revoked <- remediate

Observables
  sender      accounts@remit-notice.example (SPF pass for remit-notice.example; lookalike)
  url         https://files-share-docs.example/d/7Qk2   ip 203.0.113.45
  file        Remittance_0610.zip  sha256 <recorded>  ; Remittance_0610.js sha256 <recorded>
  file        %APPDATA%\Updater\svcupd.exe  sha256 <recorded>
  registry    HKCU\Software\Microsoft\Windows\CurrentVersion\Run\SvcUpdater
  c2 (sandbox) api.cloud-metrics-sync.example  ip 198.51.100.77  (never seen in our logs)

Investigation questions
  Q1 How did it arrive?            Phishing email with link (answered: mail + proxy logs)
  Q2 Did the payload run?           JS ran; loader quarantined before execution (EDR)
  Q3 Were credentials exposed?      No evidence; reset and session revoke done as precaution
  Q4 Who else received/clicked?     14 received; 2 clicked (jlee, akim); akim's download blocked
                                    by browser, zip never opened -> linked case WR-2026-0413
  Q5 Any C2 from our network?       30-day DNS/proxy search for sandbox C2: no hits

Remediation      Email purged from 14 mailboxes; domains blocked at proxy and DNS;
                 laptop reimaged; password reset + token revocation for jlee.
Feedback         (1) Proxy: block "Uncategorised" for finance users (change CR-1187).
                 (2) Detection: new rule wscript/cscript child of archive tools (DET-0291).
                 (3) Email team: lookalike-domain rule for remit-* senders.
Reproduce        Queries saved in case attachments (proxy, Zeek, DNS, mail trace).

Summary
  - Commodity phishing ("remittance advice") reached 14 finance staff.
  - One user ran the JS dropper; EDR stopped the loader at install. No C2, no data loss.
  - Contained in 27 min from detection; reimaged and creds reset same day.
  - Gaps: uncategorised sites allowed; script files not blocked. Fixes raised.
```

Check it against the [closing checklist](#closing-checklist): observables are structured; it is classified; every question has an answer; remediation is described; other recipients were checked and the second case is linked; the saved queries make it reproducible; and three concrete feedback items went to the teams who can fix the gaps. The **summary** at the bottom is short on purpose: in a year, someone searching for `remit-notice.example` gets the whole story in four lines.

## Analytical completeness: putting the kill chain back together { #completeness }

One item on the checklist deserves its own section: **reassembling the attack** across the kill chain wherever possible. Detection almost never happens at the start of an attack. You **drop in** at some point along the chain, depending on which control fired:

```text
Recon -> Weaponise -> Deliver -> Exploit -> Install -> C2 -> Objectives
                                              ^
                                   EDR detection (this case)
<------- investigate backwards ---------------|------- simulate / research forwards ------->
```

An antivirus or EDR detection on a dropped file usually puts you at **Install**. From there:

- **Work backwards** — find the exploitation (here, user execution of a script), the delivery (the email and the link), and, if possible, signs of targeting or weaponisation (who received it, and why them?). Weaponisation and reconnaissance are often impossible to see directly; record that honestly rather than leaving the cells blank without explanation.
- **Work forwards** — if the malware was stopped before it ran, you still want to know what it *would* have done. Detonate the sample in a sandbox (a **private** one if the attack may be targeted — public submission can tip off the attacker, see [analysis OPSEC](../analysis-opsec/passive-osint-failures.md)), or look up existing analysis of the same hash, and record the C2 domains and IPs, persistence and behaviour it would have shown.

Why bother with stages that "didn't happen"? Because those forward-looking indicators go into your threat intelligence store. If the same infrastructure shows up next month behind a *different* sample that your EDR does **not** catch, the C2 domain you recorded today is what flags it. You are buying future detection with ten minutes of work now.

Here is the completeness table for case WR-2026-0412:

| Kill chain stage | What we found | Evidence source | ATT&CK | Status |
| --- | --- | --- | --- | --- |
| Reconnaissance | 14 finance recipients, all from the public "Contact accounts" page names | Mail trace, website | T1589.002 (email addresses) — inferred | Partly known |
| Weaponisation | JS dropper inside a zip, lure "remittance advice" | File analysis | — (attacker side) | Inferred |
| Delivery | Email with link to `files-share-docs.example` | Mail logs, proxy, Zeek | T1566.002 (spearphishing link) | Known |
| Exploitation | User opened zip and ran `.js` with `wscript.exe` | 4688, EDR | T1204.002, T1059.007 | Known |
| Installation | `svcupd.exe` in `%APPDATA%`, HKCU Run key | EDR | T1547.001 (Run keys) | Known — **detection point** |
| Command and control | `api.cloud-metrics-sync.example` over HTTPS (would have) | Private sandbox | T1071.001 (web protocols) | Known from simulation; no hits in our logs |
| Actions on objectives | Family behaviour: browser credential theft, then sells access | Sandbox, vendor write-up of same family | T1555.003 (credentials from web browsers) | Expected, did not happen |

**[Caution]** Check ATT&CK IDs against the current version before you put them in a report; techniques are sometimes renamed, split or moved between versions, and an old ID copied from a template can be wrong.

## Closed-case classification { #classification }

Classification is the step where a single case becomes **data**. It is the moment you record the facts that, collected across hundreds of cases, show your real attack trends. The best and most relevant threat intelligence you will ever have is generated inside your own organisation from the attacks you actually see — and case classification is one of the biggest contributors to it.

What should you collect? Anything that, **in aggregate**, will help you improve defences in a meaningful way. A practical core set:

| Field | Typical values | What it lets you analyse |
| --- | --- | --- |
| **Disposition** | True positive, false positive, indeterminate (plus, in many SOCs, *benign true positive*) | Alert quality per rule and per tool; how much analyst time goes to noise |
| **Incident type** | Malware, phishing, hacking/intrusion, insider, misuse, lost device, DoS... | Which threats are most common; whether your threat model matches reality |
| **Key times** | Time to detect (dwell), to assign, to contain, to remediate | Response speed; where the delay really is |
| **Initial detection source** | Firewall, AV/EDR, IDS, email gateway, user report, external notification... | Which tools actually find incidents — and which never do |
| **Device type affected** | User laptop, server, domain controller, cloud workload, OT/ICS, mobile | Which population of assets is attacked most, and where to focus |
| **Attribution / motivation** | Group or cluster name if known; financial, espionage, hacktivist, disruption | Whether the actors you planned for are the ones who show up |
| **Summary** | 3–5 bullet points, executive style | Fast understanding of an old case without reading pages of notes |

**[Supplement] Disposition, made precise.** A *true positive* is a real malicious event the alert was meant to catch. A *false positive* is an alert on something that is not what the rule was looking for. **Indeterminate** means you could not tell — often because data was missing — and it is better to say so than to guess. Many SOCs add **benign true positive**: the rule fired correctly on the behaviour it describes, but the activity was authorised (an admin running a scanner, a red team exercise). Separating it from false positives matters: a benign true positive means "the rule works, add an exception for this context"; a false positive means "the rule logic needs fixing".

**The key times, worked out.** From the WR-2026-0412 timeline:

| Measure | From → to | Value |
| --- | --- | --- |
| Time to detect (dwell) | First malicious activity on host (08:52:41 script ran) → detection (08:53:02) | about 21 seconds |
| Time to assign | Detection (08:53:02) → analyst assigned (09:05:40) | 12 min 38 s |
| Time to contain | Detection → host isolated (09:19:55) | 26 min 53 s |
| Time to remediate | Detection → reimaged and credentials reset (13:40:10) | 4 h 47 min |

Notice two choices that must be **defined once and applied consistently**: whether dwell starts at delivery (08:41), at the click (08:52:14) or at first execution (08:52:41), and whether "contain" and "remediate" are measured from detection or from assignment. Different definitions give very different numbers; mixing them makes trends meaningless. Compare this case with the Wattle Ridge file-server intrusion on [the dwell-time page](../intrusion-response/dwell-type-motivation.md), where dwell was at least 27 months — both are "dwell time", but they come from different evidence and that should be visible in the record.

**Turning a quarter of cases into decisions.** Suppose that at the end of Q3, Wattle Ridge's SOC exports the classification fields of its 38 true-positive cases and counts them by detection source:

| Initial detection source | True-positive cases | Of which, first found by this source alone |
| --- | --- | --- |
| EDR | 17 | 12 |
| Email gateway (user-reported phish button) | 9 | 9 |
| Proxy category alerts | 6 | 2 |
| Network IDS | 3 | 0 |
| External notification (partner, government) | 2 | 2 |
| Other (SIEM correlation, threat hunt) | 1 | 1 |

What can the team say from this? EDR and user reports find most real incidents. The IDS raised three true positives, but in each case another tool had already found the same incident — and the same export shows the IDS produced 410 alerts in the quarter. That doesn't automatically mean "switch off the IDS" (it may be the only visibility into OT segments, and absence of TPs might mean nobody attacked there), but it is now a question with evidence behind it. Two incidents were found only by **outsiders** — a strong signal of a visibility gap, worth investigating case by case. And the device-type field (not shown) might reveal that finance laptops appear in 40% of cases, which justifies the stricter proxy policy raised in WR-2026-0412. None of these conclusions is possible if cases are closed with "fixed".

The **summary** field isn't metadata, but it is just as important: when someone opens a ticket months or years later, a bullet-point executive summary tells them what happened without reading pages of notes. If your case management system has no field for one of these items, **tags** are a practical workaround (`detsrc:edr`, `type:malware`, `device:laptop`, `motive:financial`) — they can still be counted later.

**[Supplement] VERIS as a reference vocabulary.** For more ideas, the **Vocabulary for Event Recording and Incident Sharing (VERIS)** is a free, very detailed framework for describing incidents in a consistent way. It is organised around the "4 As": **Actor** (who — external, internal, partner, and their motive), **Action** (what they did — malware, hacking, social, misuse, physical, error, environmental), **Asset** (what was affected) and **Attribute** (how it was affected — confidentiality, integrity, availability). It is the schema behind Verizon's annual Data Breach Investigations Report. Filling in every VERIS field for every case would be far too much, but borrowing its categories keeps your own fields consistent and comparable with published statistics.

## Attribution { #attribution }

When a targeted attack is closed, should an average SOC try to say **who** did it? Can it say so with any confidence? In most cases, honestly, **no**. Attribution is extremely hard even for organisations with years of intelligence on many intrusions, and attackers deliberately make it harder: they reuse other groups' tools, rent infrastructure, write misleading strings into malware and copy others' habits. A well-known public example is the malware that disrupted the opening of the 2018 Winter Olympics ("Olympic Destroyer"), which was built with false clues pointing towards other countries' groups; researchers needed considerable effort to see through them. A typical SOC simply does not have the visibility across many victims, or the body of intelligence, needed to pin an attack on a specific actor — let alone to tell true attribution from planted deception.

**When you maybe can.** There are exceptions:

- You positively identify **unique tooling** — custom malware known to be used by only one group, confirmed by more than one indicator, not just a filename.
- A **government agency or a reputable threat intelligence vendor publishes solid research** that names the tool, the campaign's TTPs and perhaps even hashes or infrastructure matching what you found. Then you can say "our incident matches publicly reported activity attributed to X", with a reference — which is different from attributing it yourself.

**What every SOC can do.** Even without a name, you can recognise that **the same intruder has come back**. Give an unexplained but distinctive set of activity an internal cluster name — say, `WR-CLUSTER-02` — and record what defines it: the C2 domain pattern, the user agent, the scheduled-task naming habit, the working hours, the tools. If a new case shows the same combination, link it. That is exactly how the big intelligence teams work internally before (if ever) they assign a public name, and it gives you most of the defensive value.

A simple confidence scale keeps your wording honest:

| Statement in the case | What supports it | Confidence |
| --- | --- | --- |
| "Same activity cluster as WR-2026-0217 (`WR-CLUSTER-02`)" | Same rare C2 naming pattern, same scheduled-task name, same working hours, same targeted share | High — based on our own data |
| "Consistent with publicly reported activity attributed to group X" | Our hashes and C2 match a government advisory | Moderate — we rely on their attribution |
| "Probably state-sponsored" | Target was substation designs; long, quiet dwell; no monetisation | Low — this is about **motivation**, not identity |
| "Group X did this" | — | Don't write this unless you can defend it |

Should we be disappointed? Not really. The SOC's job is to keep the organisation safe. Knowing it was "Actor 1" rather than "Actor 2" rarely drives a different reaction. Most attackers — especially state-sponsored ones — go unpunished, and a private organisation is not going to indict them or take them to court. In most cases it is far more useful to understand the attacker's **motivation** (espionage on designs? money? disruption?) and their **TTPs**, and to ask how you will prevent or detect that scenario next time, whoever is behind it. Record the motivation and TTPs carefully; they validate (or correct) your threat model's assumptions about who is interested in you. Share indicators and TTPs with your national agency and sector partners — that is how the organisations that *can* attribute get the data to do it. For the analytic side of weighing attribution hypotheses, see the [ACH attribution example](../structured-analysis/ach.md#attribution).

## The 2026 view { #trends }

!!! success "[2026 Current] Still valid as-is"
    The speed-versus-quality tension, a written closing standard, reproducible notes, working backwards and forwards along the kill chain, and classifying every closed case are all standard practice. Your own classified cases remain the most relevant threat intelligence you have. VERIS is still the vocabulary behind Verizon's Data Breach Investigations Report (the 2026 edition was published in May 2026). And the advice on attribution is, if anything, more widely accepted: most organisations focus on TTPs, motivation and "same cluster again" rather than naming states.

!!! info "[Changed] What has changed"
    - **NIST SP 800-61 Rev. 3 (April 2025)** replaced Rev. 2 and frames incident response around the **CSF 2.0** functions. "Lessons learned" is no longer only a final phase; improvement is expected to feed back continuously from every incident — which is exactly what closing checklists and classification do.
    - **Vendor naming is converging a little.** In June 2025 Microsoft and CrowdStrike announced a shared mapping of their threat-actor names, later joined by Google (Mandiant) and Palo Alto Networks (Unit 42). It doesn't create one universal name, but it makes "is vendor A's group the same as vendor B's?" easier to answer. (FireEye's intelligence business is now **Mandiant**, part of Google.)
    - **Reporting obligations shape the case record.** In Australia, the Cyber Security Act 2024 has required many businesses to report **ransomware or cyber-extortion payments** to the government within 72 hours since 30 May 2025; critical infrastructure has its own incident-reporting duties. In the US, CISA's CIRCIA reporting rule for critical infrastructure was still being finalised in 2026 — I could not confirm its final date. Your case template should capture the times and facts these reports need.
    - **AI writes the first draft.** SOC copilots in the major SIEM/XDR platforms now draft incident summaries, timelines and even classification fields from the alert and investigation data. That saves time, but the analyst still owns the record.
    - **More of the attack is in identity and SaaS.** The completeness table now often has rows from sign-in logs, OAuth consent events and mailbox audit logs, not only endpoint and network data.

!!! warning "[Caution] What is wrong or risky to do the old way"
    - **Don't let an AI-generated summary become the record unchecked.** Read it against the evidence; models can invent a plausible step or a wrong time.
    - **Don't close as "false positive" because it is faster.** If you couldn't determine it, the honest disposition is *indeterminate* — and that is a data-gap finding.
    - **Don't measure dwell time from the first alert.** Use the earliest trustworthy evidence, and write down the definition you used.
    - **Don't publish or circulate a named attribution you can't defend.** Wrong attribution can cause real harm and embarrass the organisation; describe clusters, motivation and TTPs instead, and cite the source if you rely on someone else's attribution.
    - **Don't submit a possibly targeted sample to a public sandbox** to "work forwards". Use a private sandbox or a hash lookup.
    - **Don't stop at the host for credential-stealing malware.** Reset passwords, revoke sessions and tokens, and check the accounts' sign-in history before closing.

## Practice questions { #quiz }

### Question 1

Your SOC is meeting its SLAs every week, and the manager says quality must therefore be fine. Explain why that reasoning is flawed and what two steps would actually give evidence about quality.

??? success "Answer and explanation"
    Meeting SLAs only shows **speed**. Speed and quality pull against each other, and poor quality is invisible at the moment it happens — it only surfaces later as a missed second host, a reinfection or a returning attacker nobody linked. A SOC can hit every SLA precisely *because* it is cutting corners.

    The two steps: **(1) define a standard** — a written closing checklist describing what a well-handled case contains (observables, classification, every investigation question answered, remediation, other hosts checked, reproducible steps, feedback given); **(2) measure against it regularly** — analysts check their own cases before closing, and a sample of closed cases from each analyst is peer-reviewed against the same checklist.

### Question 2

EDR quarantined a dropped executable before it ran. Your colleague wants to close the case: "Blocked, nothing happened." What is missing, and why does the "forwards" part matter even though the malware never executed?

??? success "Answer and explanation"
    The detection put you at the **Install** stage. Missing are the **backwards** stages — how did the file get there (exploitation, delivery: email, link, download), who else received the same delivery, and did any of them run it? — and the **forwards** stages: what the malware would have done.

    Forwards matters because detonating the sample in a **private** sandbox (or looking up existing analysis of its hash) gives you its C2 domains and IPs and its behaviour. You search your logs for them now (in case another host was infected without detection) and put them in your threat-intelligence store. If the same infrastructure appears next month behind a different sample that EDR misses, those recorded indicators are what catch it. Then the case also needs classification, remediation notes and feedback on the control that let the delivery through.

### Question 3

A colleague's case notes say: "Attribution: APT group X (Russian state)", based on the malware's Cyrillic strings and the fact that the C2 server is in a country near Russia. How should the attribution field be rewritten, and what should the case record focus on instead?

??? success "Answer and explanation"
    That evidence is weak: language strings and server location are trivial to fake or rent, and planted false clues are a known deception technique. Unless there is uniquely identified tooling confirmed by several indicators, or a solid government/vendor report matching your indicators, the SOC cannot defend that claim.

    Rewrite it as what you can support, with a confidence level — for example: *"No attribution. Activity assigned internal cluster `WR-CLUSTER-03` (C2 naming pattern, tool set, working hours). Motivation assessed as likely espionage (low–moderate confidence) based on targeted data."* If indicators match a public advisory, say "consistent with activity publicly attributed to X by <source>". The record should focus on **motivation, TTPs (mapped to ATT&CK) and indicators**, which drive the defensive changes and let you recognise the same intruder if they return.

## Related { #related }

- [Quality & Case Review](index.md) — section overview
- [Challenge Analysis and Peer Review](challenge-analysis.md) — the next page
- [Choosing a Response](../intrusion-response/choosing-response.md) — the section before
- [Kill Chain, NIST CSF and the IR cycle](../mental-models/kill-chain-did-nist-ir.md) — analytical completeness and lessons learned
- [Threat intelligence and its cycles](../mental-models/threat-intel-cycles.md) — where closed-case data goes
- [Investigation questions and data](../investigation/questions-and-data.md) — the questions every case must answer
- [ACH](../structured-analysis/ach.md) — weighing hypotheses, including attribution
- [Important Events](../important-events/index.md) — Windows event IDs
- [Threat Intelligence](../../../threat-intel/index.md)

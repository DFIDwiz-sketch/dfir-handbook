---
title: "Analysis of Competing Hypotheses (ACH) — Scoring Evidence Against Every Explanation and Keeping the One You Can't Kill"
tags:
  - training
  - blue-team
  - soc
  - analysis
  - structured-analysis
---

# Analysis of Competing Hypotheses (ACH) — Scoring Evidence Against Every Explanation and Keeping the One You Can't Kill { #ach }

!!! abstract "What this page covers"
    The best-known structured analytic technique, built to fight the confirmation bias described on the previous page. It starts with the idea behind it — Karl Popper's view that no amount of confirming evidence proves a theory, but one solid contradiction can disprove it — and what ACH adds: mutually exclusive alternatives, a systematic look at every item of evidence, a focus on refuting instead of confirming, and an audit trail of your reasoning. Then the **seven steps** in full, each explained with the reason it exists. The core of the page is a worked case: an administrator account touching 37 servers in thirteen minutes at 02:30, with five hypotheses and eight evidence items — Windows events **4624**, **7045** and **4698**, a change calendar, a scanner schedule and the absence of a test authorisation — scored cell by cell in an **ACH matrix**, then refined, concluded, stress-tested for sensitivity and reported with the relative likelihood of every hypothesis. Next come the **tips** (unproven vs disproven hypotheses, "what should I see — and not see?", the fever problem of low-diagnostic evidence), a public **attribution example** and what it teaches about the limits of the method, and how to bring ACH's lessons into **everyday tickets** in five minutes. The 2026 view and practice questions close the page.

!!! note "Labels"
    **[Supplement]** = practical material you need to know, **[Correction]** = a commonly repeated claim that is wrong or outdated, **[Changed]**/**[Caution]** = what has changed recently and what is risky to do the old way. The company (Kestrel Logistics), hostnames, accounts, IPs, ticket numbers and log lines are invented for illustration (documentation and private IPs). Researchers, public analyses and their ideas are described in my own words.

## The 8 key points { #key-points }

1. **ACH exists to beat confirmation bias.** Instead of picking a favourite and collecting support for it, you lay out every reasonable explanation and test every item of evidence against all of them at once.
2. **It rests on falsification.** Confirming evidence can never prove a hypothesis true; inconsistent evidence can rule one out. So ACH looks for *what each hypothesis can't survive*, and keeps what is left.
3. **Hypotheses must be mutually exclusive.** If one is true the others must be false — otherwise evidence can't separate them. Include a deception or "authorised test" option when it is plausible.
4. **Evidence includes absences and assumptions.** What you would expect to see but don't is evidence. Assumptions go into the matrix too, labelled, so a reviewer can see what the conclusion leans on.
5. **Diagnosticity is the key idea.** Evidence consistent with every hypothesis has no diagnostic value and should be set aside — however alarming it looks. The matrix makes this visible in a way your working memory cannot.
6. **Count inconsistencies, not support.** The most likely hypothesis is the one with the *least* evidence against it, not the most evidence for it. A hypothesis nothing refutes must be taken as seriously as one with lots of apparent support.
7. **Check sensitivity and report all hypotheses.** Ask which single items your conclusion depends on and how much you trust them. Report the relative likelihood of every hypothesis, with the key evidence and assumptions — not just the winner.
8. **Full ACH is for big cases; its habits are for every case.** You won't build a matrix for every alert, but every analyst should list alternatives, try to disprove the leading one and name the key evidence and assumptions.

## Why this matters in a SOC { #why }

Picture a courtroom with only a prosecutor. Every witness is called to support the charge, nobody asks whether the evidence fits someone else, and the jury hears a long, convincing list of facts that "point to" the defendant. Plenty of those facts may fit three other people just as well. A real trial adds a defence whose whole job is to find the facts the prosecution's story can't explain. ACH builds that defence into your own head — for every suspect at once.

Back to the technical reality. A SOC analyst on a serious case faces exactly this: an alert title that suggests a story, a ticket note that agrees with it, and a stream of log lines that can be read in its favour. The previous page showed how to *generate* several hypotheses and how to design disconfirming tests. ACH is the formal way to *evaluate* them together: one grid, every hypothesis across the top, every item of evidence down the side, every cell judged. It is slow compared with intuition, which is why you use it in full only when the stakes or the ambiguity are high — an incident that may need executive, legal or regulatory action, a disputed root cause, an attribution question. For those cases it gives you two things intuition can't: a better chance of being right, and a written record that shows *why* you concluded what you did.

## Fighting confirmation bias with ACH { #why-ach }

### The idea behind it: falsification { #falsification }

The philosopher of science Karl Popper argued that scientific theories can never be proven true by piling up confirming observations — but they can be *falsified*. The classic illustration: seeing a thousand white swans doesn't prove "all swans are white"; seeing one black swan disproves it. A good scientist therefore designs experiments that could *disprove* a theory, and trusts the theories that survive serious attempts to kill them.

Richards Heuer, a long-serving intelligence analyst and methodologist, applied this thinking to intelligence analysis and created ACH as a step-by-step procedure, later refining it with Randolph Pherson. You can think of ACH as falsification applied to everyday analysis: instead of experiments, you use the evidence you have (and the evidence you go and collect), and instead of one theory, you test several competing ones side by side.

### What ACH adds to plain good intentions { #what-ach-adds }

Knowing about confirmation bias does not stop it — it operates below conscious awareness. ACH works because it changes the *procedure*, not just the intention:

- **It forces alternatives.** You cannot start the matrix with one column. Identifying alternative interpretations is step one, not an afterthought.
- **It focuses on refuting.** Each cell asks "is this evidence *inconsistent* with this hypothesis?" — the question confirmation bias never asks.
- **It forces a systematic review of all evidence.** Every row is judged against every column. Evidence you'd prefer to ignore gets a cell like everything else.
- **It deals with cognitive limits.** Five hypotheses × eight evidence items is forty judgements. Nobody can hold forty judgements in working memory (the memory page explained why); on paper it is easy. This is decomposition and externalisation in their purest form.
- **It leaves an audit trail.** Months later, when a lawyer, auditor, regulator or new team lead asks "why did you conclude this?", the matrix answers: these hypotheses, this evidence, these judgements, these assumptions.

## The seven steps of ACH { #steps }

Here is the full procedure. Each step comes with the reason it exists — the reasons matter more than memorising the list.

**Step 1 — Identify several mutually exclusive hypotheses.** Brainstorm as many plausible explanations as you can (the previous page's routine), then shape them so that if one is true, the others must be false. *Why mutually exclusive?* Because overlapping hypotheses share evidence, and evidence that fits both can't separate them. If deception is a realistic possibility — an attacker making activity look like an admin's, a test made to look like an attack — include it as its own hypothesis. *Why?* Because a hypothesis that isn't on the list can never win.

**Step 2 — List the evidence and arguments for and against each hypothesis.** Include facts, log lines, interviews, timing — and two things people forget. First, **absences**: things you would expect to see if a hypothesis were true but don't (no change ticket, no scanner job, no user logon). Second, **assumptions**: things you are treating as true without having checked them. *Why write assumptions down?* Because they often decide the outcome, and a reviewer needs to know which parts of the conclusion rest on fact and which on belief.

**Step 3 — Build the matrix and judge each cell.** Hypotheses go across the top, evidence down the side. For each cell, ask: is this item consistent (C, +), inconsistent (I, −) or not applicable / neutral (N/A) with this hypothesis? Strong items can be marked ++ or −−. If the honest answer is "it depends", mark the dependency in the cell — the judgement for that column now depends on it, and that must be visible. *Why work across rows (one evidence item against all hypotheses) rather than down columns?* Because judging one hypothesis at a time invites you to build its case; judging one item against all hypotheses forces the question "which of these does this item help me tell apart?"

**Step 4 — Refine the matrix.** Remove evidence with no diagnostic value — items that are consistent with every hypothesis. Merge hypotheses that turn out to be the same, split ones that hide two different explanations, add any that the evidence suggests. After any change to the hypotheses, run every evidence row again. *Why remove evidence?* Not because it is false, but because it can't help you choose; leaving it in only makes every hypothesis look "supported" and inflates confidence.

**Step 5 — Draw tentative conclusions by trying to disprove each hypothesis.** Look down each column for inconsistencies. The hypothesis with the fewest (and weakest) inconsistencies is the most likely; the ones with the most are the least likely. *Why only tentative?* The scoring is a structured judgement, not a measurement — the marks aren't precisely weighted, so close scores mean "close", not "decided".

**Step 6 — Analyse how sensitive the conclusion is to a few key items.** Was any hypothesis rejected on a single item? How reliable is that item — a direct log, a second-hand statement, an assumption? If a key item were wrong, misread or planted, would the conclusion flip? *Why?* Because a conclusion that hangs on one fragile item is weaker than its score suggests, and the reader must be told.

**Step 7 — Report the conclusions and the relative likelihood of every hypothesis.** State which is most likely, which were rejected and why, which can't yet be excluded, and which key evidence and assumptions the judgement depends on. Add what would change your mind. *Why report the losers?* Because decision-makers need to know what else is still possible, and because the next piece of evidence may revive a hypothesis you reported as "unlikely, not excluded".

**[Supplement]** Two additions many practitioners make: identify **milestones** — future observations that would show events are moving towards a different hypothesis — and re-run the matrix when significant new evidence arrives. ACH is not a one-off verdict; it is a living record of the case.

## Worked example: the admin account that touched 37 servers { #worked-example }

### The alert { #alert }

Wednesday 25 November 2026, 02:46 local time at Kestrel Logistics' Perth office (UTC+8). The identity-analytics tool raises:

```
Alert:      Anomalous admin activity — account touched unusually many hosts
Severity:   High
Account:    KESTREL\adm.jlee
Hosts:      37 distinct servers in 13 minutes (baseline: 3 per day)
Source:     KL-JMP-01 (10.10.5.20)
First/last: 2026-11-24T18:31:04Z / 2026-11-24T18:44:10Z
```

Line by line:

- `Account: KESTREL\adm.jlee` — the separate admin account of Jun Lee, a server engineer. Kestrel gives admins a second, privileged account for admin work; that makes this account a high-value target.
- `37 distinct servers in 13 minutes (baseline: 3 per day)` — the anomaly: roughly a server every 20 seconds, far above normal. Fast fan-out is typical of scripts — legitimate or malicious.
- `Source: KL-JMP-01` — the jump server, the host admins are supposed to use for server administration. Activity from here is *expected* in general, which is exactly why it's a good place for an attacker to hide.
- `First/last` in UTC: 18:31–18:44 UTC is 02:31–02:44 Perth time. Always convert before you judge "night".

### Step 1: hypotheses { #ex-hypotheses }

After a short brainstorm, the analyst shapes five mutually exclusive hypotheses:

| ID | Hypothesis |
| --- | --- |
| H1 | Jun Lee is doing legitimate, approved maintenance himself |
| H2 | An attacker is using stolen `adm.jlee` credentials for lateral movement (**T1078.002 Valid Accounts: Domain Accounts**) |
| H3 | An automated job (a scheduled task or script) on KL-JMP-01 is using saved `adm.jlee` credentials — a misconfiguration, no human involved |
| H4 | The vulnerability scanner is running an authenticated scan with `adm.jlee` as its credential |
| H5 | An authorised red-team or penetration test is using the account |

Are they mutually exclusive? H2 and H5 both mean "someone other than Jun is operating the account"; what separates them is *authorisation*. H3 and H4 are both automation, separated by *which system* runs it. That is enough to make each a distinct explanation with different consequences. What about deception — an attacker deliberately making the activity look like routine admin work? That is not a separate hypothesis here; it is how H2 would *look*, and it reminds us not to treat "looks like admin work" as evidence against H2.

### Step 2: evidence, absences and assumptions { #ex-evidence }

The analyst collects eight items in about forty minutes.

**E1 — Network logons on the 37 servers.** Windows event **4624** ("An account was successfully logged on") fires on the computer being logged *into*, for every successful logon. Its `LogonType` field says how: type 3 is *network* (SMB, remote service control, file shares), type 10 is *RemoteInteractive* (RDP). Attackers care because every reuse of stolen credentials leaves a 4624 on the target. One of the 37:

```
EventID:          4624
Computer:         KL-APP-07.kestrel.example
TargetUserName:   adm.jlee
TargetDomainName: KESTREL
LogonType:        3
AuthenticationPackageName: NTLM
IpAddress:        10.10.5.20
WorkstationName:  KL-JMP-01
TimeCreated:      2026-11-24T18:33:52Z
```

- `Computer: KL-APP-07` — the target server.
- `LogonType: 3` — a network logon, as expected for remote administration.
- `AuthenticationPackageName: NTLM` — NTLM rather than Kerberos. **[Supplement]** Within a domain, Kerberos is normally preferred; NTLM often appears when tools connect by IP address rather than hostname. It is a weak signal here: scanners, scripts and attacker tools can all produce it.
- `IpAddress` / `WorkstationName` — from the jump server.

**E2 — Service installation on each server.** Event **7045** in the System log ("A service was installed in the system", written by the Service Control Manager) fires whenever a new service is registered. Attackers care because creating a service on a remote host is a standard way to run code there with SYSTEM rights — the technique behind PsExec-style tools (**T1569.002 System Services: Service Execution**, **T1543.003 Create or Modify System Process: Windows Service**, delivered over **T1021.002 Remote Services: SMB/Windows Admin Shares**). On KL-APP-07, eleven seconds after the logon:

```
EventID:      7045
Computer:     KL-APP-07.kestrel.example
ServiceName:  XkqPbaTm
ImagePath:    %COMSPEC% /c C:\Windows\Temp\s.bat
ServiceType:  user mode service
StartType:    demand start
AccountName:  LocalSystem
TimeCreated:  2026-11-24T18:34:03Z
```

- `ServiceName: XkqPbaTm` — eight random letters. Legitimate software installs services with stable, meaningful names; random names are typical of remote-execution tooling.
- `ImagePath: %COMSPEC% /c C:\Windows\Temp\s.bat` — the "service" is really `cmd.exe /c` running a batch file from `Temp`. A real service binary is a program, not a command line wrapped around a script.
- `StartType: demand start` / `AccountName: LocalSystem` — started on request, running as SYSTEM: run once, with the highest local rights.

The same pattern — random name, `%COMSPEC%`, `Temp` batch file — appears on all 37 servers. **[Supplement]** If your audit policy includes "Security System Extension", the Security log also records event **4697** for the same service installation, which is easier to forward centrally.

**E3 — How the account got onto the jump server.** A 4624 on KL-JMP-01 itself, three minutes before the fan-out:

```
EventID:          4624
Computer:         KL-JMP-01.kestrel.example
TargetUserName:   adm.jlee
LogonType:        10
IpAddress:        10.40.7.18
WorkstationName:  KL-WS-0718
TimeCreated:      2026-11-24T18:28:11Z
```

- `LogonType: 10` — an RDP session (**T1021.001 Remote Services: Remote Desktop Protocol**): a human (or a human-driven tool) at a keyboard somewhere.
- `IpAddress: 10.40.7.18` / `WorkstationName: KL-WS-0718` — the RDP came from KL-WS-0718, a laptop in the sales team. Jun Lee's own workstation is KL-WS-0112, and admins are required to reach the jump server from the IT admin network.

**E4 — The change calendar.** The approved maintenance window for application servers is Saturday 22:00–02:00. There is no change ticket for Tuesday night or Wednesday morning.

**E5 — The scanner's configuration.** The vulnerability scanner (KL-SCAN-01, 10.10.5.40) runs authenticated scans on Sundays, from KL-SCAN-01, using a dedicated account `svc_vulnscan`. It does not use `adm.jlee` and does not run from KL-JMP-01.

**E6 — No test authorisation.** The security manager confirms there is no red-team or penetration test in progress and no rules-of-engagement document on file. *This is a statement from a person, not a log* — keep that in mind for step 6.

**E7 — No automation on the jump server.** No scheduled task references `adm.jlee`: there are no event **4698** records ("A scheduled task was created") for the account, and the task list on KL-JMP-01 contains no job that runs at 02:30. Event 4698 fires on the host where a task is registered; attackers care because scheduled tasks are a common way to persist and to run code later (**T1053.005 Scheduled Task/Job: Scheduled Task**). Its *absence* matters here because H3 predicts a task or saved-credential job.

**E8 — Credential exposure.** Two weeks ago the threat-intelligence provider reported `adm.jlee`'s username and an old password in a dump of infostealer logs. The password was reported as changed, but nobody confirmed the change.

Assumptions, written explicitly:

- **A1** — The security manager would know about any authorised test (E6 depends on this).
- **A2** — The scanner's configuration (E5) was not changed by someone without a change ticket.

### Step 3: the matrix, cell by cell { #ex-matrix }

Notation: **C** consistent, **I** inconsistent, **II** strongly inconsistent, **N/A** neutral or not applicable. Work across each row.

| Evidence | H1 Jun, maintenance | H2 Attacker, stolen creds | H3 Automated job | H4 Scanner | H5 Authorised test |
| --- | --- | --- | --- | --- | --- |
| E1 4624 type 3 from KL-JMP-01 to 37 servers | C | C | C | C | C |
| E2 7045 random-name services running `Temp\s.bat` | I | C | I | I | C |
| E3 RDP to jump server from a sales laptop | II | C | II | II | C |
| E4 no change ticket for this window | I | N/A | N/A | N/A | N/A |
| E5 scanner uses another account, host and day | N/A | N/A | N/A | II | N/A |
| E6 no test authorised (statement; relies on A1) | N/A | N/A | N/A | N/A | II |
| E7 no task or saved-credential job on KL-JMP-01 | N/A | N/A | II | N/A | N/A |
| E8 credentials seen in an infostealer dump | N/A | C | N/A | N/A | N/A |

Cell by cell, row by row:

- **E1** — every hypothesis predicts network logons from the jump server to many servers. Consistent with all five, so it has **no diagnostic value**. It is the evidence that raised the alert, and it feels important — but it can't tell the hypotheses apart.
- **E2** — H1: an engineer doing maintenance might push a script, but random-name services running a `Temp` batch file are not how Kestrel's engineers work (they use the deployment tool) — I. H2: exactly how common remote-execution tools behave — C. H3: a saved-credential job could in principle do this, but would normally use a stable, named tool — I. H4: **it depends** — some authenticated scanners do create temporary services; Kestrel's scanner is configured not to, and its services have a fixed vendor name — I, noting the dependency. H5: a red team would plausibly use the same tooling — C.
- **E3** — H1: Jun would RDP from his own admin workstation, not a sales laptop — II. H2: an attacker who compromised KL-WS-0718 and used stolen admin credentials from there fits perfectly — C. H3 and H4: automation doesn't open RDP sessions from a laptop — II. H5: a red team that compromised a sales laptop as its starting point — C.
- **E4** — only H1 predicts a change ticket; its absence is inconsistent with H1. For the others the change calendar is irrelevant — N/A. This is an *absence* used as evidence.
- **E5** — the scanner's account, host and schedule don't match: strongly inconsistent with H4, neutral for the rest.
- **E6** — strongly inconsistent with H5 — *if* A1 holds.
- **E7** — H3 predicts a task or saved-credential job; none exists — II. Another absence.
- **E8** — supports H2 (there was a credential leak) and says nothing against anyone else — C for H2, N/A elsewhere.

### Step 4: refine { #ex-refine }

E1 goes. It stays in the case record, but it is removed from the scoring because it cannot discriminate. No hypotheses need merging or splitting. One new hypothesis is briefly considered — "Jun Lee himself, from the sales laptop, doing unapproved work" — and set aside as a variant of H1 for now; E2's tooling and E3's laptop already score against it, and a quick call to Jun (step 6) will settle it.

### Step 5: tentative conclusions — count the inconsistencies { #ex-conclude }

Score I = 1 and II = 2, and *only count inconsistencies*:

| | H1 | H2 | H3 | H4 | H5 |
| --- | --- | --- | --- | --- | --- |
| Inconsistency score | 1 + 2 + 1 = **4** | **0** | 1 + 2 + 2 = **5** | 1 + 2 + 2 = **5** | **2** |

Reading it: H2 has *nothing* against it. H5 has one strong inconsistency, and it is E6. H1, H3 and H4 are each contradicted by several independent items. Notice that H2 has three C marks (E2, E3, E8) — only one more than H5 — so the number of Cs is not what made it win. Even if E8, the leak report, didn't exist, H2 would still be the only hypothesis with zero inconsistencies. In ACH, **the lack of negatives matters, not the number of positives**.

### Step 6: sensitivity — what is the conclusion hanging on? { #ex-sensitivity }

- **H5 rests on a single item, E6, which rests on an assumption, A1.** If the manager were unaware of a test (a test commissioned by the board or an external auditor, for example), H5 would score 0 like H2. The analyst checks: the CISO and the outsourced test provider both confirm no engagement is active. A1 now has two sources. H5 is rejected with higher confidence.
- **H1 rests on E2, E3 and E4.** E3 is the strongest. Could the 4624 on the jump server be wrong? The analyst cross-checks: the firewall log shows a TCP 3389 session from 10.40.7.18 to 10.10.5.20 at the same minute, and Jun Lee, reached by phone, says he was asleep and has never used KL-WS-0718. Two independent sources agree.
- **Could E2 be misleading?** If the scanner's configuration had been changed (A2), the "it depends" cell for H4 might become C. But H4 would still be refuted by E3 and E5. The conclusion does not hinge on A2.

### Step 7: the report { #ex-report }

> **Assessment (25 Nov 2026, 04:10 local).** We assess it is **highly likely** that an unauthorised actor used stolen credentials for `adm.jlee` to move laterally from sales laptop KL-WS-0718, via the jump server KL-JMP-01, to 37 servers, executing a batch file on each through remotely created services (H2). Legitimate maintenance by the account owner (H1) is **very unlikely**: there is no change ticket, the session originated from a non-admin laptop, and the owner denies the activity. An automated job (H3) and the vulnerability scanner (H4) are **very unlikely**: neither matches the observed RDP session, tooling, account or host. An authorised test (H5) is **unlikely**: the security manager, CISO and test provider all confirm no engagement; this is the main remaining uncertainty. **Key evidence:** E3 (RDP from KL-WS-0718, corroborated by firewall logs) and E2 (random-name services running `Temp\s.bat`). **Key assumptions:** A1, now corroborated. **What would change this assessment:** discovery of an authorised engagement, or evidence that the events on KL-JMP-01 were forged. **Recommended actions:** isolate KL-WS-0718 and KL-JMP-01, disable `adm.jlee` and reset its credentials, collect `s.bat` from an affected server, and scope for further use of the account.

That paragraph is what ACH buys you: a clear conclusion, honest about what was ruled out and what is still possible, with the evidence and assumptions named — a record that holds up when someone reviews it next month.

## Tips for ACH success { #tips }

**Pick unproven hypotheses; skip disproven ones.** There is a difference between a hypothesis nobody has *disproven* and one that the evidence has already *refuted*. The first belongs in the matrix, even if it seems unlikely — the authorised-test hypothesis (H5) is the classic case: usually there's no reason to suspect it, but it is rarely ruled out until you ask. The second wastes time: if the server was powered off during the activity, "someone used its console" doesn't need a column.

**Gather evidence with every hypothesis in mind.** For each hypothesis, ask: **"If this were true, what should I expect to see — and what should I expect *not* to see?"** That question produced E4, E5 and E7 above: H1 predicted a change ticket, H4 predicted the scanner's account and host, H3 predicted a scheduled task. None of those items would have been collected by an analyst looking only for evidence of an attacker.

**Count what you didn't see.** Absences are some of the most diagnostic evidence you have, because they come from asking what a hypothesis *requires*. "No change ticket", "no scanner job", "no user logon at the time" each rule things out. **[Supplement]** Before using an absence, check that you *could* have seen it: no 4698 events means nothing if task-creation auditing is switched off. "Absence of evidence" is only evidence of absence when the sensor was working.

**Focus on evidence that changes relative likelihood.** The most valuable items are strongly consistent with one hypothesis and strongly inconsistent with another. The weakest are consistent with everything. The classic analogy is a fever: if a patient insists they have a rare tropical disease, a fever is certainly *consistent* with that — but it is equally consistent with flu and almost every other illness, so it does almost nothing to support the diagnosis. In the SOC, the "fever" is often the alert itself: "PowerShell ran", "an admin logged on to many servers", "a large upload happened" fit both the benign and the malicious story. They justify an investigation; they don't decide it.

## An attribution example — and its lesson { #attribution }

ACH is often demonstrated on attribution questions, where analysts are especially prone to jumping to a favourite actor. A well-known public example came after the WannaCry ransomware outbreak of May 2017. A threat-intelligence company (Digital Shadows, since acquired by ReliaQuest) and, separately, an independent security researcher each published an ACH matrix asking who was behind it. The commercial analysis used four hypotheses:

| Hypothesis | In plain words |
| --- | --- |
| H1 | A sophisticated, financially motivated criminal group |
| H2 | An unsophisticated, financially motivated criminal actor |
| H3 | A nation-state or state-affiliated actor running a disruptive operation |
| H4 | A nation-state or state-affiliated actor aiming to embarrass the US National Security Agency, whose leaked exploit the worm used |

They marked each evidence item consistent, inconsistent or neutral, using letters rather than plus and minus signs — any notation works as long as it ranks consistently. Evidence publicly discussed at the time included the clumsy payment handling (few hard-coded payment addresses, making it hard to match payments to victims), the kill-switch that stopped the spread, the use of a leaked government exploit, and reported code overlaps with tools previously linked to a North Korea–associated group. Their result: H2, the *unsophisticated* criminal, scored best, with H4 close behind. They concluded that, at that time, the evidence was not sufficient to corroborate attribution to the North Korea–linked group and that alternative hypotheses should stay open.

Then the lesson. In December 2017 the US and UK governments publicly attributed WannaCry to North Korea, and in 2018 the US Department of Justice charged a North Korean programmer in connection with it. Was the ACH "wrong"? Not exactly — it was a fair judgement of the *evidence available to those analysts*, and they said so. Governments had evidence the public didn't. Three takeaways for a SOC:

1. **ACH is only as good as the evidence in the matrix.** It reduces bias in how you *use* evidence; it can't make up for evidence you don't have.
2. **The scoring is semi-subjective.** Two careful teams can mark the same item differently. That's why step 6 (sensitivity) and step 7 (reporting all hypotheses, with confidence) matter so much.
3. **Report "not yet excluded" honestly.** The authors kept the alternatives open rather than announcing a winner. That was the right call, even though the eventual attribution went another way.

**[Supplement]** For most SOCs, attribution to a named actor is rarely the question that matters most. "Who" usually matters less than "what did they do, what can they still do, and how do we stop it". Use ACH for attribution when a decision actually depends on it — a legal, regulatory, diplomatic or intelligence-sharing decision.

## Bringing ACH into daily work { #daily-work }

A full matrix takes time — tens of minutes for a small case, hours for a large one. Most alerts won't get one, and that's fine. But the lessons behind it apply to every ticket. The three failures to avoid:

- **Not considering other hypotheses that fit the evidence.**
- **Not trying to disprove your own theory.**
- **Not thinking carefully about which evidence actually discriminates** — and therefore which data sources to check first.

**[Supplement]** A "mini-ACH" for an ordinary ticket, five minutes, three lines:

```
Hypotheses considered: (1) admin script via deployment tool  (2) attacker using admin creds  (3) scanner
Key evidence: 4624 type 10 on KL-JMP-01 from KL-WS-0718 (non-admin laptop) – inconsistent with 1 and 3
Assumptions / what would change my mind: assumes no authorised test – confirmed with security manager 03:55
```

- Line 1 shows that alternatives were considered — and which.
- Line 2 names the *discriminating* evidence and which hypotheses it ruled out, not just "evidence of compromise".
- Line 3 states the assumption and how it was checked, or what new information would reopen the case.

When reviewing someone else's analysis (or your own, before closing), ask three questions:

1. **What other explanations did you consider?**
2. **Which key evidence shows this is the best answer — and which explanations does it rule out?**
3. **Did you make any assumptions, and did you check them?**

If an analyst can answer all three in a sentence each, most confirmation-bias errors have already been caught. When the case is high-stakes or the answers aren't clear, that is the signal to build the full matrix — which, as a bonus, becomes the audit trail.

## The 2026 view { #trends }

!!! success "[2026 Current] Still valid"
    ACH remains the best-known structured analytic technique and is still taught in intelligence-analysis and SOC analyst training. The underlying logic — mutually exclusive hypotheses, diagnosticity, counting inconsistencies, stating assumptions, reporting every hypothesis — is unchanged and directly useful in incident response and threat hunting. The worked case is current as well: credential theft by infostealers followed by valid-account lateral movement through jump hosts and remote service creation is a routine finding in 2025–2026 intrusion reports.

!!! info "[Changed] What has changed"
    - **The evidence for ACH is mixed, and that's now widely known.** A 2019 controlled study by Dhami, Belton and Mandel with 50 intelligence analysts found that analysts trained in ACH often didn't follow all its steps, that evidence it reduced confirmation bias was mixed, and that it could increase inconsistency in judgements. The practical reading: ACH is a disciplined way to organise and expose your reasoning, not a guarantee of accuracy. Its value depends on doing steps 3, 6 and 7 properly, and on peer review.
    - **AI assistants can draft a matrix in seconds.** Copilots in SIEM and EDR consoles, or general assistants, can propose hypotheses, list evidence and fill in cells. That's useful for the *quantity* step and for catching a hypothesis you forgot. But a model can mark cells confidently from patterns rather than from your evidence, and it can invent evidence. Treat its matrix as a draft from a junior colleague: check every cell against real logs, and keep the human judgement on diagnosticity and sensitivity.
    - **Calibrated likelihood words are more common.** Many teams now use a fixed scale ("almost certain", "highly likely", "likely", "roughly even chance", "unlikely" …), borrowed from intelligence standards, so that the step-7 report means the same thing to every reader.
    - **Telemetry makes absences easier to check.** With central identity logs, EDR process trees and cloud audit trails, "what should I see if this were true?" can often be answered in minutes — provided you have confirmed that the logging was actually on.

!!! warning "[Caution] Wrong or risky to do the old way"
    - **Don't add up the pluses.** The most common ACH mistake is to pick the hypothesis with the most C marks. Support from non-diagnostic evidence is cheap; only inconsistencies separate hypotheses.
    - **Don't treat the score as a probability.** "H2: 0, H5: 2" is not "H2 is 100% and H5 is 0%". The marks are judgements; report confidence in words and explain the sensitivity.
    - **Don't let the matrix delay containment.** In the worked case, isolating the laptop and disabling the account shouldn't wait for step 7. Contain on the strength of the leading hypothesis, and let ACH guide scope and conclusions in parallel.
    - **Don't hide the "it depends" cells.** An unexplained mark that silently depends on an assumption is exactly what a reviewer — or opposing counsel — will find.
    - **Don't use absences from data you don't collect.** Check the audit policy and log coverage before writing "no 4698 events" or "no logon" in the matrix.

## Practice questions { #quiz }

### Question 1

An analyst builds an ACH matrix for a suspicious outbound connection with three hypotheses. H1 (malware beacon) has six C marks and two I marks. H2 (a legitimate software update check) has two C marks and no I marks. H3 (a user browsing) has three C marks and three I marks. The analyst concludes H1 because "it has the most supporting evidence". What's wrong, and what should the conclusion and next steps be?

??? success "Answer and explanation"
    ACH ranks hypotheses by **inconsistencies, not support**. H2 has nothing against it, so it is currently the most likely; H1 has two inconsistencies that the analyst has ignored. The six C marks for H1 are probably consistent with H2 as well — if they are consistent with all hypotheses, they have no diagnostic value and should have been removed in step 4.

    Next steps: check which items are actually diagnostic; look hard at H1's two inconsistencies (how reliable are they?); run a sensitivity check on H2 (is it surviving only because little evidence has been collected about it?); and gather evidence that H2 predicts — for example, "if this is an update check, the destination should belong to the software vendor and the process should be the vendor's updater". Report the relative likelihood of all three hypotheses.

### Question 2

For each of the following, say whether it is likely to be diagnostic in an ACH matrix with H1 "legitimate admin activity" and H2 "attacker using stolen admin credentials", and why: (a) an alert stating "admin account logged on to 20 servers"; (b) a 4624 type 10 on the jump server from a non-admin workstation; (c) no change ticket for the work; (d) the admin's password appeared in an infostealer dump last month.

??? success "Answer and explanation"
    (a) **Not diagnostic** — both hypotheses predict an admin account logging on to many servers. It's the "fever": it justifies investigation but doesn't separate the hypotheses. (b) **Highly diagnostic** — legitimate admins are expected to come from admin workstations; an RDP session from a non-admin workstation is strongly inconsistent with H1 and consistent with H2. (c) **Diagnostic, as an absence** — H1 predicts a change ticket (if the organisation enforces change control), so its absence is inconsistent with H1; it is neutral for H2. Check that change control is actually followed before relying on it. (d) **Weakly diagnostic** — it is consistent with H2 but not inconsistent with H1 (a leaked password doesn't stop the admin working normally). It raises H2's plausibility and is a lead, but it can't by itself refute H1.

### Question 3

In the worked case, the authorised-test hypothesis (H5) was refuted by one item: the security manager's statement that no test was running. Explain why this needed a sensitivity check, what the check should involve, and how the final report should treat H5.

??? success "Answer and explanation"
    H5 was rejected on a **single item**, and that item is a person's statement resting on an **assumption** (A1: the manager would know about every authorised test). Step 6 asks exactly this: if that item were wrong, would the conclusion flip? Here it would — without E6, H5 has zero inconsistencies, the same as H2.

    The check: corroborate A1 from independent sources — the CISO, the procurement or legal record of test engagements, the external test provider, and any rules-of-engagement document. In the case, the CISO and the provider both confirmed no engagement.

    In the report, H5 should be named as **unlikely, not excluded**, with the evidence and the corroboration stated, and listed as the main remaining uncertainty, together with what would change the assessment (discovery of an authorised engagement). Containment should go ahead regardless — a real red team will understand, and a real attacker won't wait.

## Related { #related }

- [Hypothesis generation, evaluation mistakes and confirmation bias](hypothesis-generation.md) — previous page: generating the hypotheses ACH evaluates
- [System 1 and System 2, "Do you need more data?" and structured analytic techniques](system1-2-sat.md) — diagnosticity and the four families of techniques
- [Memory and experience](../analyst-cognition/memory-experience.md) — why decomposition and externalisation work
- [Login events](../important-events/logins.md) · [Services, tasks and USB events](../important-events/services-tasks-usb.md) — 4624, 7045, 4697 and 4698 in depth
- [PsExec and SMB](../../../adversary/psexec-smb.md) · [RDP](../../../adversary/rdp.md)

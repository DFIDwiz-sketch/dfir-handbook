---
title: "Perception and Analysis — Heuer's Argument, Mindsets, Seeing What You Expect, and Why the SOC Makes It Worse"
tags:
  - training
  - blue-team
  - soc
  - analysis
  - cognition
---

# Perception and Analysis — Heuer's Argument, Mindsets, Seeing What You Expect, and Why the SOC Makes It Worse { #perception }

!!! abstract "What this page covers"
    You've picked the most dangerous alert in the queue; now you have to decide whether it's real. This page explains why that step goes wrong far more often than it should — not because analysts lack skill, but because of **how human perception works**. We start with **Richards Heuer** and his book *Psychology of Intelligence Analysis*: who he was, why a book written for intelligence officers fits SOC work, and his three-part argument (analysis is full of uncertainty — some natural, some planted by the opponent; the brain handles uncertainty badly, and knowing about your biases doesn't fix them; structured tools help). Then **perception itself**: why it's an active filter (your *mindset* or *mental model*), why mindsets **form fast and resist change**, when that effect is strongest, why a newcomer often spots what you missed, and why **we see what we expect** — and need *more* evidence to see what we don't. Then how this collides with **the way most analysts work an alert** (pick a theory, look for support, write it up, move on) and with **the SOC environment** (ambiguous partial data + information arriving piece by piece + pressure for a quick final answer = premature closure). Two worked cases make it concrete: a VPN "scanner noise" alert that was really a compromise, followed evidence by evidence with the log lines read field by field (**4625**, **4624**, **4648**, **4688**), and a "known false positive" PowerShell alert that wasn't. Practical countermeasures, the 2026 view (AI summaries as a new anchor) and practice questions close the page.

!!! note "Labels"
    **[Supplement]** = practical material you need to know, **[Correction]** = a commonly repeated claim that is wrong or outdated, **[Changed]**/**[Caution]** = what has changed recently and what is risky to do the old way. The company (Kestrel Logistics), hostnames, accounts, domains, IPs and log lines are invented for illustration (`.example`, documentation and private IPs). Psychology findings are described in my own words.

## The 8 key points { #key-points }

1. **Validation is where good triage goes wrong.** Our brains weren't built to make high-quality decisions on incomplete information without training, and the SOC rewards speed — a bad combination.
2. **Heuer's argument in three lines:** analysis always involves uncertainty (natural gaps in what we can collect, *plus* deliberate deception by the opponent); the brain is poorly equipped for that uncertainty, and biases are **unconscious** — knowing about them is not enough; deliberate tools (awareness of your mental models, constant refinement, structured analytic techniques) are what help.
3. **Perception is active, not passive.** What you "see" is your senses *interpreted* through experience, training, culture and expectations. That interpretive filter is your **mindset** (also called mental model, analytic assumptions, bias).
4. **Mindsets form quickly and resist change.** Once you have a theory, your brain fits new evidence into it — even contradicting evidence, even when you know this happens. Small pieces of new information arriving one at a time make it worse.
5. The tendency to absorb new data into the old view is **strongest when** the information is ambiguous, you are confident in your assessment, and you are committed to it (said it out loud, wrote it down, told your manager).
6. **We perceive what we expect.** Unexpected things can be completely invisible, and recognising the unexpected needs **more and clearer** evidence than recognising the expected. Repetitive SOC work builds exactly these expectations.
7. **The typical workflow is the trap:** read the alert → form a working theory → look for evidence that fits → conclude and write up → next alert. It is the brain's natural shortcut, and it produces confident wrong answers.
8. **The SOC formula:** ambiguous, partial information **+** information discovered bit by bit **+** pressure for a quick, final judgement **=** high chance of a wrong hypothesis and **premature closure**. The fix starts with process, not willpower.

## Why this matters in a SOC { #why }

Most alerts are closed by one person, quickly, and never looked at again. If that person's first idea was wrong, nothing catches it. The cost isn't spread evenly either: a wrongly escalated false positive costs an hour; a wrongly closed true positive can cost the company. And the wrong closures are not random — they follow predictable patterns in how people perceive and remember. That's good news, because predictable errors can be designed against.

An analogy: think of the "autocorrect" on your phone. It doesn't show you exactly what you typed; it shows what it *expects* you meant, based on what it has seen before. Most of the time that's helpful and fast. Occasionally it confidently changes the one word that mattered — and because the result looks normal, you don't notice. Human perception does the same thing to evidence. This page is about knowing when your inner autocorrect is most likely to get it wrong, and what to do about it.

Back to the technical reality: in a SOC, "what your autocorrect expects" is built from hundreds of past alerts with the same name. That is exactly why the dangerous mistakes happen on the **familiar** alerts, not the exotic ones.

## Where this comes from: Richards Heuer { #heuer }

Much of modern thinking about analytic error in intelligence — and increasingly in cyber defence — goes back to **Richards J. Heuer Jr.** (1927–2018), who spent about 45 years with the CIA, in operations and later in analytic methodology. Between the late 1970s and mid-1980s he wrote a series of internal articles applying **cognitive psychology** (how the brain takes in, stores and processes information) to the analyst's job. They were collected and published openly in 1999 as ***Psychology of Intelligence Analysis***, which the CIA's Center for the Study of Intelligence still offers free online. Later, with Randolph Pherson, he wrote *Structured Analytic Techniques for Intelligence Analysis* (first edition 2010), a catalogue of practical methods — several of which appear later in this handbook.

Why does a book for intelligence officers fit SOC work so well? Because the job is the same shape: you get fragments of data, of uneven reliability, some of it planted by an adversary, and you must say what is happening and how confident you are — often under time pressure. Swap "agent report" for "EDR alert" and "foreign ministry" for "threat actor", and most of Heuer's examples translate directly.

His central practical message is that analysts must become **conscious of their own reasoning process** — notice how they reach a conclusion, not just what the conclusion is. The brain is poorly suited to this kind of work by default, but there are strategies that work, *if* you deliberately use them.

### Heuer's argument in three steps { #heuers-argument }

**1. Every analysis problem carries a lot of uncertainty.** Two kinds:

- **Inherent uncertainty** — limits of collection. You don't have logs from that host; the packet capture was rotated out; the EDR wasn't installed yet. This never goes away; it's part of the game.
- **Human-induced uncertainty from deception** — the opponent deliberately misleads you. In our world that is concrete and catalogued: renaming malware to look like a system binary (**T1036.005 Masquerading: Match Legitimate Resource Name or Location**), changing file timestamps (**T1070.006 Indicator Removal: Timestomp**), clearing logs (**T1070.001 Indicator Removal: Clear Windows Event Logs**), hiding C2 inside popular cloud services (**T1102 Web Service**), or leaving false-flag strings in code to point at another group.

**2. The brain is poorly equipped to deal with that uncertainty.** Our conclusions are shaped by **unmotivated** biases — not because we *want* a certain answer, but because of how perception and memory work — and these happen **unconsciously**. Studies Heuer cites show that even people who know about a bias still show it. Awareness is necessary but not sufficient. The way analysis usually unfolds — information arriving in small increments over time — makes it even harder to reach the best judgement.

**3. Tools for critical thinking can put us on a better path:**

- understanding the role of **perception and memory** in analysis (this page and the next),
- becoming **self-aware of our own mental models** — the assumptions we bring,
- constantly working to **refine those models** and keep an open mind,
- and using **structured analytic techniques** that force alternatives and make assumptions explicit (covered in a later section).

Put together, the goal is analysis that is as free of bias as possible and **explicit about every assumption made**.

## Perception and new information { #perception-new-info }

### Perception is an active filter { #active-filter }

We usually imagine perception as a camera: light comes in, a picture forms. It isn't. Perception is the process by which we **become aware of and interpret** what our senses pick up — and the *interpret* part is doing heavy lifting. Your past experience, training, culture, education and current expectations all shape what the incoming data means to you, and sometimes what you notice at all.

Heuer's image for this is a **lens or filter**. Everybody has one; it goes by many names — *mindset*, *mental model*, *analytic assumptions*, *biases*. It isn't a defect: without it you couldn't process anything quickly. An experienced analyst's filter is what lets them glance at a process tree and say "that's the patch agent". The danger is that the same filter can bend evidence to fit.

### Mindsets form fast and resist change { #mindsets-stick }

The second, more troublesome property: **mindsets form very quickly, and once formed they are hard to change.** After you have a theory, your brain wants to keep it. New evidence — even evidence that contradicts it — tends to be **assimilated** into the existing picture ("that's odd, but it's probably because…"). This happens even when you're consciously aware of the tendency.

Two consequences matter in practice:

- **It's hard to "see it a different way" once you've found one explanation.** You're not choosing to ignore alternatives; they simply stop occurring to you.
- **Small, incremental pieces of information can make you miss big insights.** If the clues arrive one by one, each can be explained away on its own. If they had arrived all at once, the pattern would have been obvious.

This explains a familiar experience: you've worked a problem for hours, a colleague walks over, looks for thirty seconds and says "isn't that just…?" — and they're right. It isn't that they're smarter. They saw **all the evidence at once, without a theory to defend**. You had been fed it piece by piece, and each piece was being fitted into your first hypothesis.

The research Heuer draws on found that this tendency to assimilate new data is **greatest when**:

1. the information is **more ambiguous** (and security data usually is),
2. the analyst is **more confident** that the first assessment is right (experience increases confidence),
3. the analyst is **more committed** to the established view (they've said it, written it, or acted on it).

All three describe a busy senior analyst who has already told the incident manager "it's the scanner" — exactly the person whose judgement the team trusts most.

### Two pictures, one drawing { #ambiguous-figure }

A classic illustration is an old ambiguous drawing (published in a humour magazine in 1915) that can be seen either as a **young woman looking away over her shoulder** or as an **old woman in profile looking down**. People usually see one first; once they've seen it, switching to the other takes real effort, and flipping back and forth quickly is hard even after you know both are there.

Now apply that to an investigation: the "drawing" is a set of log lines, and you **don't know a second picture exists**. Nobody tells you "there's another interpretation — keep looking". That is the normal condition of alert analysis.

### We see what we expect to see { #see-what-you-expect }

A second well-established finding: **we tend to perceive what we expect to perceive.** The famous demonstration is a selective-attention experiment from 1999 in which viewers count basketball passes in a short video. About half fail to notice a person in a gorilla suit walking through the middle of the scene — something completely obvious once you know to look. A simpler version: show people a short phrase in a triangle with one word accidentally repeated ("a bird in the the hand"). Most read it as the normal phrase and never see the duplicate.

There's an important **corollary**: we need **more, and less ambiguous, information to recognise something unexpected** than to recognise something expected. The expected interpretation gets accepted on thin evidence; the unexpected one has to fight its way in.

In alert analysis this bites hard. Many alerts really are repetitive, so you naturally build expectations: "this signature on this server is always the backup job". That's efficient — until the day it isn't, when you'll not only miss the difference but need *extra* evidence before you'll accept it. Over years, these expectations harden into the mindset through which you see every new alert. That's valuable most of the time and misleading at the worst moments.

## Perception meets typical analysis { #typical-analysis }

Now look at how most of us intuitively work an alert:

1. **Receive an alert** with some information.
2. **Read it and form a working theory** — run a few scenarios in your head and pick the one that seems most likely.
3. **Find evidence around that theory** — go to the SIEM and other sources to check whether it holds.
4. **Conclude and write it up** — once enough supporting data appears, document it, brief management if needed, take remediation actions.
5. **Move on to the next alert.**

See the problem? Every step matches the way the brain wants to work: form a mindset fast (step 2), assimilate new data to fit it (step 3), then commit publicly (step 4), which makes it even harder to change. Step 3 is the weak point. "Is there evidence for my theory?" is almost always answered yes, because most evidence is consistent with several theories. The question that actually discriminates is "**what evidence would show my theory is wrong — and did I look for it?**"

## The SOC environment vs perception { #soc-vs-perception }

Put the perception findings next to the working conditions of a SOC:

```
  Ambiguous, partial information
+ Information discovered bit by bit
+ Pressure for a quick, final judgement
= High chance of an inaccurate hypothesis and premature alert/incident closure
```

- **Ambiguous, partial information** — the alert is a fragment; logs are missing, clocks disagree, the attacker may be deceiving you. This is precisely the condition in which assimilation is strongest.
- **Incremental discovery** — you run one query, then another, then pull a file, then ask the user. Each result arrives alone and is fitted into the theory you already have. You rarely step back and look at everything together as if seeing it for the first time.
- **Pressure for a quick, final judgement** — SLAs, a long queue, metrics like mean time to close. And once you've made the call, written it up and told management, you have every incentive *not* to change it: reopening creates work and can make you look like someone who can't make up their mind.

The result is not that analysts are careless. It's that the conditions in which clear perception is **hardest** are exactly the conditions under which SOC analysis is **normally** done. Recognising that is the first step; the next page (memory) and the later sections on structured analysis give the tools.

## Worked case 1: "it's just the scanner" { #case-scanner }

A realistic story, told the way the evidence arrived. Kestrel runs a weekly external vulnerability scan from a vendor whose scanners use addresses in 198.51.100.0/24.

**09:05 — the alert.**

```
[SIEM] VPN - Multiple failed logins from single source   severity: medium
  src_ip=198.51.100.23   target=vpn.kestrel.example   failures=212 in 10 min   distinct_users=180
```

The analyst, Dana, reads it: 198.51.100.x is the scanner range, it's Tuesday, scans run on Tuesdays. **Working theory: scanner noise.** (Mindset formed in about five seconds.)

**09:12 — evidence 1.** The VPN appliance log:

```
2026-11-24T08:58:41Z vpn01 auth: user="m.okafor" src=198.51.100.23 result=FAIL reason=bad_password
2026-11-24T08:58:41Z vpn01 auth: user="t.nguyen" src=198.51.100.23 result=FAIL reason=bad_password
2026-11-24T08:58:42Z vpn01 auth: user="r.ito"    src=198.51.100.23 result=FAIL reason=bad_password
```

- `user=` — real Kestrel usernames, in a known naming format.
- `reason=bad_password` — the accounts **exist**; only the password is wrong. (A scanner testing a login page usually tries generic names like `admin` or `test`, which would show "unknown user".)
- One attempt per user, many users = **password spraying** (**T1110.003**), not a scanner's credential check.

Dana's interpretation: *"The vendor must have loaded our user list for an authenticated scan."* — the new fact is **assimilated** into the theory.

**09:20 — evidence 2.** The address is in the vendor's range, but the scan schedule says this week's scan starts at **13:00**, not 09:00. Interpretation: *"They probably started early."*

**09:31 — evidence 3.** One success:

```
2026-11-24T09:01:17Z vpn01 auth: user="s.patel" src=198.51.100.23 result=SUCCESS mfa=push_approved session=7f3a…
```

- `result=SUCCESS` — the spray found a working password for `s.patel`.
- `mfa=push_approved` — an MFA push was **approved**. Either the user approved a prompt they didn't trigger (MFA fatigue, **T1621 Multi-Factor Authentication Request Generation**), or the attacker had another way.

Interpretation: *"Scanner tested with a test account the vendor was given."* Dana checks — `s.patel` is a real finance employee, not a test account — but by now it's "probably a misconfiguration on the vendor's side, I'll email them".

**09:48 — evidence 4.** On the internal file server, a Windows logon from the VPN address pool:

```
Event ID 4624  Computer: KL-FS02
  Account Name: s.patel   Logon Type: 3
  Source Network Address: 10.250.0.41      (VPN pool)
Event ID 4648  Computer: KL-WS-VPN41
  Subject Account: s.patel
  Account Whose Credentials Were Used: svc_backup
  Target Server Name: KL-FIN-DB01
```

- **4624** (successful logon) with **Logon Type 3** — a *network* logon, e.g. connecting to a share. It fires on the machine that was logged on to (here the file server). Attackers generate it every time they touch a remote system with stolen credentials, which is why it is the backbone of lateral-movement hunting ([logins](../important-events/logins.md)).
- **4648** (logon with **explicit** credentials) — the session of `s.patel` used the credentials of a *different* account, `svc_backup`, against `KL-FIN-DB01`. It's logged on the **source** machine, so it shows where a borrowed account is being used *from*. A finance user borrowing a backup service account is not normal (**T1078 Valid Accounts**, **T1021.002 Remote Services: SMB/Windows Admin Shares**).

**10:15 — Dana is pulled into a meeting; Lee takes over the ticket.** Lee hasn't heard the scanner theory. Lee reads the whole ticket top to bottom, sees the four pieces of evidence *together*, and within two minutes says: "Spray with real usernames, one success, MFA approved, then lateral movement with a service account — this is a compromise." Lee disables `s.patel`, kills the VPN session and escalates.

What went wrong was not a lack of knowledge. Dana knew what spraying looks like. The first theory came from a strong, usually reliable cue (the IP range and the day), and every later fact was **absorbed** into it. Lee wasn't smarter — Lee simply saw all the evidence at once, with no theory to protect.

| Time | Evidence | Assimilated as… | What it actually pointed to |
| --- | --- | --- | --- |
| 09:05 | Failures from scanner range on scan day | "Scanner noise" (first theory) | Could be either — the cue is weaker than it feels |
| 09:12 | Real usernames, `bad_password` | "Vendor loaded our user list" | Password spraying |
| 09:20 | Wrong time for the scan | "They started early" | Not the scheduled scan |
| 09:31 | One success + MFA approved | "Vendor test account" | Account compromise |
| 09:48 | 4624 type 3 + 4648 to a service account | (not yet reviewed) | Lateral movement |

A **[Supplement]**: the attacker probably *chose* that address. Renting servers near a known scanning provider, or in a common cloud range, so that your mindset files the traffic as "known noise" is a simple form of the deliberate deception Heuer warns about.

## Worked case 2: the "known false positive" { #case-known-fp }

Kestrel's EDR raises `Suspicious encoded PowerShell` dozens of times a week on workstations, and it's always the software-deployment agent running an inventory script. Analysts close it in seconds. Here are two of this week's 4688 events side by side:

```
Event ID 4688  Computer: KL-WS-0310   (closed as FP, Monday)
  Creator Process Name: C:\Windows\CCM\CcmExec.exe
  New Process Name:     C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe
  Token Elevation Type: %%1936   (full token, SYSTEM)
  Process Command Line: powershell.exe -NoProfile -ExecutionPolicy Bypass -EncodedCommand JABpAG4AdgA9AEcAZQB0AC0A...

Event ID 4688  Computer: KL-WS-0377   (closed as FP, Wednesday)
  Creator Process Name: C:\Program Files\Microsoft Office\root\Office16\WINWORD.EXE
  New Process Name:     C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe
  Token Elevation Type: %%1938   (limited token, user)
  Process Command Line: powershell.exe -NoP -W Hidden -EncodedCommand SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoA...
```

- **4688** ("A new process has been created") is written to the Security log every time a process starts, if process-creation auditing is on (and the command line only if that extra policy is enabled). Attackers can't run tools without creating processes, so 4688 — or its richer cousin, Sysmon event 1 — is the foundation of host-based detection ([process creation](../important-events/process-creation.md)).
- `Creator Process Name` — the **parent**. Monday's parent is `CcmExec.exe`, the deployment agent: expected. Wednesday's parent is **`WINWORD.EXE`** — Word starting PowerShell is a classic sign of a malicious document (**T1566.001** → **T1204.002**, then **T1059.001 Command and Scripting Interpreter: PowerShell**).
- `Token Elevation Type` — `%%1936` means a full (elevated) token, here the SYSTEM agent; `%%1938` means a limited token, i.e. an ordinary user session. The agent always runs as SYSTEM; this one ran as the user.
- `Process Command Line` — Monday's flags are the agent's usual ones. Wednesday's add `-W Hidden` (hide the window) and the encoded text starts `SQBFAFgA`, which is UTF-16LE Base64 for **`IEX`** — `Invoke-Expression`, "run this string as code", typically followed by a download (`New-Object Net.WebClient…`). Monday's starts `JABpAG4AdgA9`, which decodes to `$inv=` — the inventory script's first variable.

Both were closed by the same analyst in under a minute. The second wasn't a lack of skill: the alert **name** matched the expectation ("encoded PowerShell = deployment agent"), and expectations need very little evidence to be confirmed and a lot to be overturned. The difference was in plain sight in the parent process field. The fix is not "try harder" — it's to make the expected case **specific** (an allow rule for *this parent, this account, this script hash*) so that anything else no longer looks like the familiar alert.

## What to do about it { #countermeasures }

Because these effects are unconscious, the countermeasures are **habits and process**, not good intentions. **[Supplement]** — practical versions you can use today:

- **Write the hypothesis down, with the time.** "09:06 — working theory: scanner noise." A written theory is easier to challenge than one in your head, and it reminds you it *is* a theory.
- **Write at least one alternative, and what would distinguish them.** "Alternative: password spray. Would distinguish: real usernames, success events, timing vs scan schedule." Then look for those things first.
- **Ask the disconfirming question.** Not "does the evidence fit?" but "what would I expect to see if I'm wrong, and have I looked?"
- **Re-read everything at checkpoints.** Before closing, or whenever a surprising fact appears, read the ticket top to bottom as if it were new. This recreates Lee's "fresh eyes" for yourself.
- **Use fresh eyes deliberately.** For high-impact closures, a two-minute review by someone who hasn't seen the case is cheap. Hand over the evidence, not your conclusion.
- **Make the expected case specific.** Tune "known false positives" to exact parent, account, path and hash, so a lookalike no longer *looks* like the usual alert.
- **Separate speed metrics from closure.** Time-to-*triage* (did someone look quickly?) is a good metric. Pressure on time-to-*close* rewards premature closure.
- **State confidence, not certainty.** "Likely scanner noise (moderate confidence) — pending vendor confirmation" is easier to revise than "Scanner. Closed." Making room to change your mind removes the social cost of doing so.

## The 2026 view { #trends }

!!! success "[2026 Current] Still valid"
    The psychology hasn't changed: perception is an active filter, mindsets form fast and resist change, we see what we expect, and ambiguous, incremental, time-pressured work makes all of it worse. Heuer's *Psychology of Intelligence Analysis* is still freely available from the CIA's Center for the Study of Intelligence and still widely recommended in intelligence and cyber-defence training. The countermeasures — explicit hypotheses, alternatives, disconfirming evidence, fresh-eyes review and structured techniques — are standard good practice.

!!! info "[Changed] What has changed"
    - **AI summaries are a new first impression.** Many SOC platforms now open an alert with an AI-generated summary or a proposed verdict. That summary is the first thing you read, which makes it a powerful **anchor**: it can set your mindset before you've seen the raw data. Research is early, but an exploratory 2025 study of security decision-making (21 participants) found that LLM help improved accuracy on routine items, while some participants followed wrong suggestions on harder ones and answers became more uniform — the authors warn of automation bias and reduced independent reasoning.
    - **More data, faster.** XDR and SOAR pipelines enrich alerts automatically, so the "incremental discovery" problem has partly shifted: you may get a lot of context at once, already framed by someone else's rule or model. The filter is no longer only yours.
    - **Identity-first attacks lean on expectations.** Spraying from cloud or "scanner-like" ranges, MFA-fatigue prompts and logins through legitimate VPN and SaaS services are designed to look like normal noise, which is exactly what expectation-driven perception lets through.

!!! warning "[Caution] Wrong or risky to do the old way"
    - **"I know about bias, so I'm fine" is the bias.** Awareness alone does not remove these effects; only process changes do.
    - **Don't read the AI verdict first and the data second.** Where your tools allow, look at the raw evidence (or at least the key fields) before the summary, and treat the AI verdict as one more hypothesis to test, not a conclusion.
    - **Don't let "known false positive" closures go unreviewed.** Tune them narrowly and sample them; the familiar alert is where the dangerous miss happens.
    - **Don't punish analysts for changing their minds.** A culture that treats reopening a case as failure guarantees premature closure.

## Practice questions { #quiz }

### Question 1

Explain Heuer's two kinds of uncertainty, with one SOC example of each, and why "being aware of my biases" is not enough to deal with them.

??? success "Answer and explanation"
    **Inherent uncertainty** comes from the limits of collection — for example, a host had no EDR installed, or the relevant packet capture had already been overwritten. It never fully goes away.

    **Human-induced uncertainty** comes from deliberate deception by the opponent — for example, malware named and placed to look like a system file (T1036.005), timestomped files (T1070.006), cleared logs (T1070.001), or spraying from an address range chosen to look like your vulnerability scanner.

    Awareness isn't enough because these biases are **unmotivated and unconscious**: they come from how perception and memory work, not from wanting an answer, and studies show people who know about a bias still show it. That's why Heuer recommends **tools and process** — explicit assumptions, alternatives, structured techniques — rather than relying on self-control.

### Question 2

According to the research Heuer draws on, under which three conditions is the tendency to fit new evidence into an existing view strongest? Why do all three typically describe an experienced SOC analyst?

??? success "Answer and explanation"
    The tendency is strongest when (1) the **information is ambiguous**, (2) the analyst is **confident** in the existing assessment, and (3) the analyst is **committed** to it.

    Security data is usually ambiguous (partial logs, several innocent and malicious explanations). Experience increases confidence — an analyst who has seen a signature 500 times is sure what it means. And SOC workflow creates commitment: the analyst has written the ticket, told the incident manager or closed similar cases the same way. So the most trusted analysts working the most familiar alerts are most exposed — which is why fresh-eyes review and explicit alternatives matter most there.

### Question 3

In worked case 2, both encoded-PowerShell alerts were closed as false positives. List three fields that distinguished the malicious one, explain what each meant, and suggest a change that would stop this happening again.

??? success "Answer and explanation"
    - **`Creator Process Name`** — the parent was `WINWORD.EXE`, not the deployment agent `CcmExec.exe`. Word spawning PowerShell suggests a malicious document (T1566.001 → T1204.002 → T1059.001).
    - **`Token Elevation Type`** — `%%1938` (limited user token) instead of `%%1936` (the agent's full SYSTEM token): it ran in a user session, not as the agent.
    - **`Process Command Line`** — extra `-W Hidden`, and the Base64 starts `SQBFAFgA` = UTF-16LE `IEX` (Invoke-Expression, run a string as code), not the inventory script's `$inv=`.

    The underlying problem was **expectation**: the alert name matched "always the deployment agent". The fix is to make the known-good case **specific** — suppress only this parent, this account, this script hash or command-line pattern — so anything else raises the alert as something new, and to sample closed "known FP" alerts periodically.

## Related { #related }

- [Prioritising alerts](../alert-triage/prioritising-alerts.md) — choosing the alert this page helps you validate
- [Login events (4624/4625/4648)](../important-events/logins.md) · [Process creation (4688)](../important-events/process-creation.md)
- [Base64](../http-analysis/base64.md) · [PowerShell cradles](../../../adversary/powershell-cradles.md) · [Phishing delivery](../../../adversary/phishing-delivery.md)
- [Log clearing](../../../adversary/impair-defenses-log-clearing.md) — deception that creates uncertainty

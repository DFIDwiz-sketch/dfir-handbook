---
title: "Challenge Analysis and Peer Review — Premortem, Structured Self-Critique, What If?, Red Team and Team A/B, and Closing the Loop"
tags:
  - training
  - blue-team
  - soc
  - analysis
  - incident-response
---

# Challenge Analysis and Peer Review — Premortem, Structured Self-Critique, What If?, Red Team and Team A/B, and Closing the Loop { #challenge-analysis }

!!! abstract "What this page covers"
    The [previous page](documentation-classification.md) defined what a well-closed case looks like. This page is about **checking our own thinking** — the family of structured techniques known as **challenge analysis** (also called contrarian or alternative analysis), whose whole purpose is to question a conclusion, a plan or a consensus before reality does. It explains why our mental models need deliberate challenge (they are built from everything we've seen, they quietly decide what we look for, and they change slowly), and why **feedback** is the only way analysts learn whether their judgements were right. Then five techniques, each with a worked SOC example: the **premortem** (imagine the eviction plan has failed — why?), **structured self-critique** (everyone puts on the critic's hat and questions a closed case — here, one that turns out to be wrong, with Windows events **4624**, **5140** and **5145** read field by field), **What If? analysis** (a low-probability, high-impact event worked backwards with indicators at each step), **red team analysis** (making the strongest case against the current view, and the mirror-imaging trap) and **Team A/B** (two teams, same evidence, competing explanations). Finally, how to **operationalise peer review** so it becomes part of SOC culture — with a filled-in review form — what closed cases should **feed** (analytics, metrics, intelligence, review), and a summary of the whole analysis part.

!!! note "Labels"
    **[Supplement]** = practical material you need to know, **[Correction]** = a commonly repeated claim that is wrong or outdated, **[Changed]**/**[Caution]** = what has changed recently and what is risky to do the old way. The company (Wattle Ridge Energy, `wattleridge.example`), people, hostnames, accounts, IPs, case numbers and log lines are invented for illustration (`.example`, documentation and private IPs). Frameworks, researchers, agencies and public incidents are real and described in my own words.

## The 8 key points { #key-points }

1. **Challenge analysis exists because mental models resist change.** They tell us what to look for and which evidence matters — and they quietly filter out what doesn't fit. Reframing techniques force a new point of view.
2. **Without feedback, experience doesn't make you better.** To learn, an analyst has to find out whether past judgements were right — and which combination of evidence led to them.
3. **Two targets:** your own (or your team's) analysis — **premortem**, **structured self-critique** — and a consensus or someone else's analysis — **What If?**, **red team analysis**, **Team A/B**.
4. **Premortem:** assume it is the future and your conclusion or plan has failed; list every way that could have happened. It legitimises dissent and exposes overconfidence, but doesn't tell you which problem is real or how to fix it.
5. **Structured self-critique:** everyone plays the critic and works through set questions — sources, contradictions, missing evidence, assumptions, alternatives, deception — then revisits confidence. It pinpoints specific weaknesses and is ideal after a premortem.
6. **What If?:** assume an unlikely, high-impact event has happened, reason backwards to how it unfolded, with indicators at each step and the consequences. A tactful way to tell a confident consensus it may be wrong.
7. **Red team analysis** builds the strongest case against the current view (and fights mirror-imaging); **Team A/B** gives the same evidence to two teams when opinions are already split.
8. **Make review routine and safe:** sample closed cases from every analyst regularly, score against the closing checklist, pair people to learn, and never turn it into a ranking. Closed cases feed new analytics, metrics, threat intelligence and the next round of review.

## Why this matters in a SOC { #why }

Think of how a good sports team uses match video. After every game, win or lose, the coaches sit the players down and replay key moments: "Here — why did you pass left? What did you see? What did you miss?" Nobody is fired for a bad pass; the point is that players rarely notice their own habits from the inside. Without the video, a striker who keeps making the same wrong run never finds out, because the moment is gone. And before a big match, the coach asks: "Suppose we lose on Saturday. How did it happen?" — and plans for those answers.

Back to the technical reality. Analysts are in the same position. You close a case as benign, and if you were wrong, you usually never find out — nobody comes back to tell you. Your [mental models](../mental-models/encapsulation-ooda.md) built from years of alerts are what make you fast, and they are also what make you miss the case that looks *almost* like the hundred benign ones before it (see [perception](../analyst-cognition/perception.md) and [memory and experience](../analyst-cognition/memory-experience.md)). The [structured techniques](../structured-analysis/system1-2-sat.md) earlier in this part help while you analyse; challenge analysis is the **feedback and stress test** that comes before you commit to a conclusion or a plan, and after a case is closed.

## What challenge analysis is { #what }

Challenge analysis is a category of structured analytic techniques that Richards Heuer and Randolph Pherson describe for the intelligence community. It goes by several names — contrarian, alternative, competitive or red team analysis — and they all share one goal: **to challenge an analytic consensus or the mental model behind it.** Reviews of past intelligence failures have often found the same root causes: a **failure of imagination** about alternative explanations, and a **lack of challenge** to the mental model everyone shared.

Why are mental models so powerful, and so hard to shift? They are built from the totality of what we've seen and experienced. They subconsciously tell us **what to look for**, **which evidence is important**, and **how to assemble the data** we receive into a story. That is exactly what makes them useful — and exactly why they change slowly, even when new evidence says they should. Challenge techniques use **reframing**: they trick the mind into seeing the same problem from a different point of view, which pulls you out of a mental rut.

Heuer adds a second, simpler argument. To learn from experience, you must **know the outcome** of what you did. Without regular feedback that closes the loop, an analyst cannot tell when their thinking went wrong — so they cannot learn to make better judgements. And the useful feedback is not just "right" or "wrong", but how accurate a judgement was **given the particular set of evidence that led the analyst to it**. In SOC terms: not "you closed WR-2026-0455 wrongly", but "you saw a scanner account and a scanner source IP and stopped there — the time of day and the file reads didn't fit, and here is how you could have caught that".

The techniques fall into two groups:

| Target | Technique | Core move | Best for |
| --- | --- | --- | --- |
| Your own / your group's analysis | **Premortem analysis** | "It's the future; we were wrong. How?" | Testing a conclusion or plan before acting; breaking groupthink |
| | **Structured self-critique** | Everyone plays critic, works through fixed questions | Finding *specific* weaknesses and fixing them; case review |
| A consensus / someone else's analysis | **What If? analysis** | "This unlikely event happened. How did it unfold, and then what?" | Low-probability, high-impact scenarios a consensus dismisses |
| | **Red team analysis** | Make the strongest case that the analysis is wrong; think as the adversary | Risk of mirror-imaging |
| | **Team A/B analysis** | Two teams, same evidence, independent conclusions | Opinions are already divided; sparse data |

## Premortem analysis { #premortem }

**Goal:** find the ways a conclusion or plan could fail **before** they happen, to reduce surprise — and the need for a post-mortem afterwards.

**Method:** alone or (better) in a group, imagine that it is some time in the future and you have just learned that your conclusion or plan of action went wrong. Everyone's job is to explain **how and why** it went wrong. In a group, go round the table so that everyone contributes, rather than letting the most senior or loudest voice set the tone. Then collect the reasons, look for early-warning signs for each, and adjust the plan.

Why does it work? Asking "what could go wrong?" invites people to defend the plan. Telling them "it **has** gone wrong — explain it" flips the frame: now finding flaws is the task, not an act of disloyalty. That **legitimises dissent** that might otherwise stay unspoken because of hierarchy, politics or the group's wish for a quick consensus. It is also a reliable way to expose **overconfidence**: teams that design a plan are almost always more confident in it than they should be, and being forced to list ways it failed tends to puncture that. The idea is usually credited to the psychologist Gary Klein. **[Supplement]**

### Worked example: a premortem on the eviction plan { #premortem-example }

On the [choosing-a-response page](../intrusion-response/choosing-response.md#eviction-plan), the Wattle Ridge team drew up an eviction-day plan for the long-running intrusion: block all known C2, disable `svc-backup` and the orphan VPN account, isolate three hosts, reset privileged passwords and `krbtgt`, revoke sessions, rebuild. Before approving it, the incident lead runs a 40-minute premortem: *"It is three weeks after eviction day. The attacker is back inside. Each of you, tell me why."*

Going round the table, the team produces:

| # | "It failed because..." | Early-warning sign to watch | Change to the plan |
| --- | --- | --- | --- |
| 1 | There was a fourth backdoor we never found | A new rare, regular beacon after T-0; logons from unknown sources | Extend long-window beacon hunting through eviction day; keep heightened monitoring for 60 days |
| 2 | They had stolen credentials for an account we didn't reset (e.g. a cloud admin with no MFA) | Sign-ins from new countries/ASNs on accounts outside the reset list | Review **all** privileged cloud identities, not just AD; require phishing-resistant MFA before T-0 |
| 3 | They saw the plan in our email | Attacker behaviour changes in the days before T-0 | Confirm planning only on the out-of-band channel; no tickets that name eviction day |
| 4 | The second `krbtgt` reset was forgotten | — | Put it on the timeline with an owner and a calendar reminder |
| 5 | They came back through the same jump-server vulnerability | Exploitation attempts against `WR-JMP01`'s service | Patch or remove the vulnerable service on Day 1, verify with a scan |
| 6 | A supplier with remote access was the real way in | Activity from the supplier's VPN range | Review third-party remote access before T-0 |
| 7 | We broke the historian and operations forced us to roll back changes | Operations tickets in the first hours | Agree a tested rollback with operations that keeps the blocks in place |

Seven failure modes, several of which change the plan. Notice what the premortem **didn't** do: it doesn't say which of these is most likely, and it doesn't prove any of them is real. That is its known limit — it shows *that* problems may exist, not which one matters or exactly how to fix it. For that, the next technique is a natural follow-on.

## Structured self-critique { #self-critique }

**Goal:** identify specific weaknesses in a current piece of analysis.

**Method:** everyone puts on a pretend "**evil hat**" — they take the role of a critic of the analysis — and answers a fixed set of questions from that point of view. Each person must pick apart the process, assumptions and evidence that led to the conclusion and come up with any reason it could be wrong. Topics to cover:

- Were our **key sources of evidence reliable**?
- Was **contradictory evidence** ignored?
- Do we have an explanation for **missing evidence** (something we'd expect to see but don't)?
- Were our **key assumptions** valid?
- Did we seriously **generate and consider alternative hypotheses**?
- Did the **absence of information** mislead us?
- Could **deception** have gone undetected?

Then, as a group, **reconsider the confidence level and the conclusion**. Self-critique is useful for reviewing triage decisions and investigations, it is an excellent follow-on to a premortem, and it zooms in on specific analysis problems and how to fix them.

How does it differ from **devil's advocacy**, where one person is appointed to argue the other side? It can work, but Heuer and Pherson observe that when only one person dissents, the rest of the team tends to get defensive, and the exercise becomes less productive. When **everyone** wears the critic's hat, nobody is "the enemy", and the critique is about the analysis, not the person.

### Worked example: self-critique of a closed case { #self-critique-example }

Case **WR-2026-0455** was closed on a busy Monday as *benign true positive*: a SIEM rule fired because the account `svc-scan` accessed the finance file share on `WR-FS01` from many files in a short time. The analyst's note: *"svc-scan is the vulnerability scanner's account; source 10.20.9.40 is the scanner appliance. Expected behaviour. Closed."* In the weekly review, the team applies structured self-critique. First, the evidence the analyst had:

```text
EventID: 4624   TimeCreated: 2026-10-10T23:10:07Z   Computer: WR-FS01
  Logon Type:            3
  Account Name:          svc-scan        Account Domain: WATTLERIDGE
  Source Network Address: 10.20.9.40
  Authentication Package: NTLM          Logon ID: 0x8A41F2
```

**Event 4624** means *"an account was successfully logged on"*. It fires on the machine being logged on to — here the file server — every time a logon succeeds. **Logon Type 3** is a **network logon**: someone connected over the network (SMB, for example) without an interactive desktop. Attackers care because every use of stolen credentials to touch a remote file share or run a remote tool produces one of these, with the source address and account — it is one of the main events for spotting lateral movement. `Authentication Package: NTLM` rather than Kerberos is worth noting: a domain-joined appliance would normally use Kerberos to a domain server, so NTLM can mean an IP address was used instead of a name, a non-domain client, or a tool doing its own authentication. `Logon ID 0x8A41F2` links this logon to the events that follow.

```text
EventID: 5140   TimeCreated: 2026-10-10T23:10:07Z   Computer: WR-FS01
  Account Name: svc-scan   Logon ID: 0x8A41F2
  Source Address: 10.20.9.40
  Share Name: \\*\Finance     Share Path: \??\D:\Shares\Finance
```

**Event 5140** means *"a network share object was accessed"*. It fires (when "Audit File Share" is enabled) the first time in a session that a client connects to a share — one per share per session, not per file. Attackers care because share access is how data is collected from file servers (ATT&CK **T1039**, Data from Network Shared Drive) and how tools are staged; seeing which shares an account opens is the start of scoping.

```text
EventID: 5145   TimeCreated: 2026-10-10T23:10:09Z ... 23:31:44Z (x 1,842)   Computer: WR-FS01
  Account Name: svc-scan   Logon ID: 0x8A41F2   Source Address: 10.20.9.40
  Share Name: \\*\Finance
  Relative Target Name: Payroll\2026\FY27_salary_model.xlsx   (and 1,841 others)
  Accesses: ReadData (or ListDirectory)   ReadAttributes
  Access Check Results: ReadData (or ListDirectory): Granted by D:(A;;FA;;;S-1-5-21-...-3107)
```

**Event 5145** means *"a network share object was checked to see whether the client can be granted the desired access"*. It needs "Audit Detailed File Share" and is very noisy, so many organisations only enable it on sensitive servers — which is exactly why Wattle Ridge has it on the finance server. It fires for each file or folder a client asks for, and it records **which access** was requested. Attackers care because it shows the difference between *looking at* a folder and *reading the files in it*. Here, `Relative Target Name` shows the files, `Accesses: ReadData (or ListDirectory)` on a **file** means its contents were read (on a folder the same right means listing it), and there were 1,842 of these in 21 minutes.

Now the critique, question by question:

| Question | Critic's answer | Finding |
| --- | --- | --- |
| Were key sources reliable? | The conclusion rests on "the account name is the scanner's" and "the IP is the scanner's". Both are labels, not proof — an account can be used by anyone holding its password. | Weak foundation |
| Was contradictory evidence ignored? | The scanner's scheduled window is **Tuesday 02:00–04:00**. This ran **Saturday 23:10**. | Contradiction not addressed |
| Missing evidence? | A scan should touch many hosts. No 4624s for `svc-scan` from 10.20.9.40 on any other server that night. | Expected evidence absent |
| Key assumptions valid? | "Scanners read files." Authenticated vulnerability scans check file versions and registry keys; they do not read the contents of 1,842 spreadsheets in a payroll folder. | Assumption false |
| Alternatives considered? | Only one hypothesis was written. Alternatives: misused scanner credentials; a scanner policy change; the appliance itself compromised. | Not done |
| Did absence of information mislead? | No proxy or firewall data for 10.20.9.40 was checked — so "no outbound transfer" was never established. | Gap |
| Could deception be involved? | Using a well-known service account from its usual IP is exactly how an intruder blends in (T1078 Valid Accounts). | Plausible |

**Reconsidering confidence:** the original conclusion goes from "certain" to "unsupported". The disposition is changed to **indeterminate**, the case is reopened, and the analyst checks the scanner appliance's own logs (no scan job on Saturday) and the vault where `svc-scan`'s password is stored (it was checked out on Friday by a contractor account that left the project months ago). The case becomes a true positive for credential misuse and collection from a network share — found because a closed case was reviewed. Notice also what the review was **not**: nobody said "you were careless". The finding was that the analysis relied on two labels and skipped the time-of-day check — a concrete habit to fix, which goes onto the closing checklist as "for service-account alerts, compare the activity with the service's known schedule and behaviour".

## What If? analysis { #what-if }

**Goal:** alert decision-makers to an **unlikely but high-impact** event that could happen more easily than they think.

**Method:** assume the event — strongly positive or negative — **has already happened**. Using that imagined hindsight, explain in detail how it unfolded, **reasoning backwards** from the event, and then analyse the **consequences** going forward. Develop at least one chain of events based on evidence and logic, focusing on what must happen at each stage. For each step, list the **observables or indicators** that would show things moving in that direction. And for each scenario, estimate how hard and costly recovery would be. The detail matters: it tells decision-makers what to do to prevent the outcome, and gives them a list of indicators to spot it developing.

What If? is similar to a premortem in that both imagine a future outcome. The difference: a premortem assumes **our conclusion was wrong**; What If? focuses specifically on **low-probability, high-impact events**, with an analysis of consequences. And where the premortem's main social benefit is letting group members dissent regardless of group dynamics, What If? is a **tactful way to suggest a consensus may be wrong** — you are not saying "you're mistaken", only "let's explore what it would look like if this happened". It fits best when:

- a well-ingrained mental model drives a consensus that the unlikely event **won't** happen;
- an issue is contentious and **nobody has planned** for the event actually occurring;
- there is a feeling that a legitimate possibility **isn't being given due consideration**.

### Worked example: "What if the EDR console were used against us?" { #what-if-example }

At Wattle Ridge, the consensus is that the EDR management console is "the most protected system we have". An analyst proposes a What If? session: *"Assume that next month, a malicious script was pushed through our EDR console to every endpoint. How did it happen?"* This isn't fantasy — real-world attackers have abused remote management platforms to push malware to many organisations at once (the 2021 Kaseya VSA incident is a well-known public example). Working backwards:

| Step (backwards from the event) | What must have happened | Indicators we would see | Do we collect them today? |
| --- | --- | --- | --- |
| 5. Script runs on all endpoints | EDR "live response" or script-deployment job targeting all groups | EDR audit log: new job, all hosts, outside change window; mass 4688 of the same script interpreter | Audit log: yes, but **nobody alerts on it** |
| 4. Attacker has console admin rights | Admin role assigned to a new or existing account | Console audit: role change; new API key created | Partly — API key creation not logged to SIEM |
| 3. Attacker signs in to the console | Cloud console sign-in with valid credentials and MFA satisfied | Identity provider: sign-in from new device/location; MFA prompt bursts; token from an unusual client | Yes |
| 2. Attacker obtains an EDR admin's session or credentials | Phishing of a SOC engineer, or infostealer on their home device | Infostealer detection on a SOC device; reused password in a breach | Only for corporate devices |
| 1. Attacker targets SOC staff | Reconnaissance of who runs the EDR | Recruiting posts naming the product; SOC staff profiles | — |

**Consequences going forward:** ransomware or a wiper across every endpoint at once; the SOC's main detection and response tool now hostile; recovery measured in weeks, with a rebuild of the EDR tenant itself. **Recovery difficulty: very high.**

What the session produced: three cheap changes — alert on mass script jobs and on console role changes, ship API-key events to the SIEM, and require phishing-resistant MFA plus a separate admin account for every EDR administrator — and a list of indicators to watch. The probability is still low; the plan for it no longer is zero.

## Red team analysis and Team A/B analysis { #red-team-team-ab }

### Red team analysis { #red-team }

**Goal:** get critique by making the **strongest possible case against** the current analysis or its assumptions.

**Method:** a team of experienced people role-plays the attacker and acts as devil's advocate, building the best argument that the current explanation is wrong or that an alternative is true. If no strong counter-argument can be built, that's a good sign for the original analysis; if one can, you have learned something important before acting.

Don't confuse this with **red teaming** in the penetration-testing sense (an authorised team attacking your systems). Red team *analysis* attacks the **reasoning**, not the network.

It is best used when there is a risk of **mirror-imaging** — the tendency to assume the adversary has the same motivations, cultural norms and expectations as we do. Example: a team assumes an intruder in the finance share is after money, so it looks for payment fraud and finds none, and concludes the threat is low. A red team analysis played by people who know espionage actors asks instead: *"If I wanted next year's salary model and supplier contracts for negotiation leverage, what would I do?"* — quiet reading, no fraud, long dwell. The behaviour that "doesn't fit a criminal" fits that actor perfectly. The red team should include people who have dealt with that kind of threat before and can best **put themselves in the attacker's shoes**.

### Team A/B analysis { #team-ab }

**Goal:** explore two competing explanations properly.

**Method:** give **the same evidence** to two separate analytic teams and have each produce an independent analysis and interpretation; then compare. Use it when there is already a **division of opinion** about what happened, or when an incident has very little data and more than one version of events deserves to be worked out in detail. Producing two well-argued, competing analyses helps each side understand and respect the other's view — and often shows that the disagreement rests on one or two specific pieces of evidence that can then be checked.

Example: Zeek shows `WR-HIS01` (the operations historian) sent 2.1 GB to an external IP over four hours one night.

```text
#fields ts            id.orig_h   id.resp_h      id.resp_p proto service duration   orig_bytes   resp_bytes
1791860412.03  10.20.8.40  198.51.100.120  443       tcp   ssl     14388.2    2254857011   1903382
```

- `id.orig_h 10.20.8.40` — the historian started the connection; `id.resp_h 198.51.100.120` port `443` — an external HTTPS server.
- `duration 14388.2` — about four hours in one session.
- `orig_bytes 2254857011` — about 2.1 GB **sent** by the historian; `resp_bytes 1903382` — under 2 MB came back. Heavily outbound, the shape of an upload.

**Team A** argues *exfiltration*: the host is already known to be compromised, the transfer was at night, the destination is not on the firewall allow-list. **Team B** argues *the vendor's cloud backup*: the historian's vendor announced a new cloud backup service last quarter, the size matches a monthly archive, and the TLS server name in `ssl.log` may match the vendor. Comparing the two analyses shows the disagreement comes down to two checkable facts — who owns `198.51.100.120` and the certificate it presented, and whether the change record shows the backup being enabled — rather than to opinion.

A detailed, free reference for these and the other structured techniques is the US government's *A Tradecraft Primer: Structured Analytic Techniques for Improving Intelligence Analysis* (2009), as well as Heuer and Pherson's book.

## Operationalising reviews { #operationalising }

Techniques only help if they actually happen. The way to make structured self-critique part of SOC culture is **mandatory periodic review of a random sample of closed cases from every analyst**.

- **Cadence:** weekly, fortnightly, monthly — whatever the team can sustain. Feedback is the key ingredient of growth, so it must happen at *some* fixed interval.
- **Who:** one reviewing analyst or a small group reads the case and notes what was and wasn't done.
- **What:** analytical completeness (were all attack stages and all affected hosts found?), the analytic technique (were several hypotheses considered, and is the reason for the conclusion explained?), and the [closing checklist](documentation-classification.md#closing-checklist).
- **Format:** a checklist, a spreadsheet, or an interactive discussion. You can assign points per question for a more objective measure — but as long as analysts hear back where they can improve, the goal is met.

An example review form, filled in for case WR-2026-0412 from the previous page:

| Review question | Points (0–2) | Reviewer note |
| --- | --- | --- |
| Observables recorded and structured | 2 | All present incl. sandbox-only C2 |
| Classified (disposition, type, times, source, device, motive) | 2 | Times defined clearly |
| All investigation questions answered | 2 | Q3 answered honestly as "no evidence" |
| More than one hypothesis considered | 1 | Implicit; write the alternatives down (e.g. targeted vs commodity) |
| Kill chain worked backwards and forwards | 2 | Good use of private sandbox |
| Other hosts / recipients checked and cases linked | 2 | Linked WR-2026-0413 |
| Reproducible (queries saved) | 2 | |
| Feedback raised to the right teams | 2 | Three concrete items |
| **Total** | **15 / 16** | Strong case. Suggest pairing with Tom on the self-critique habit; Mia can show her case template to new starters. |

Reviews have benefits beyond quality. **Newer analysts see how experienced analysts think** — which tools and methods they pick in which situation — and learn faster. **Patterns of weakness** across the team become visible (for example, "nobody checks identity logs on endpoint cases"), and people who need a tool or technique can be **paired** with someone who knows it well: efficient on-the-job training.

**[Caution] Keep it a learning tool.** Peer review must stay light-hearted and focused on learning. If it turns into a stressful **analyst ranking**, its problems will outweigh its benefits: people will document defensively, avoid hard cases and hide doubts. Make it clear that reviews exist only for each analyst's development and will never be used to punish anyone for what they haven't mastered yet.

**Different analysts, different reviews.** Newer analysts benefit from **more frequent** reviews, focused on whether their cases are analytically complete, whether the right tools were used and whether the reasoning process is sound. Experienced analysts who know the tools and process need fewer, but **different** reviews: more like a red team analysis that challenges their conclusions and mindset, checking that they didn't jump to conclusions from a mental rut — experience is exactly what creates those ruts.

## What closed cases feed { #closed-cases-feed }

Closing an incident is a key moment because the data it produces should **feed several other processes**:

```text
                 +--> New analytics   (lessons on how the attack worked -> new collection and detection rules)
                 |
Closed cases ----+--> Metrics         (classification fields -> investment in controls and tools)
                 |
                 +--> Threat intel    (motivation, TTPs, clusters -> the F3EAD and intelligence cycles)
                 |
                 +--> Peer review     (the library of cases that reviews sample from)
```

Before a case is truly closed, the loop should be complete:

1. **All attack steps analysed** — the kill chain reassembled as far as possible.
2. **Assumptions and reasoning documented** — not just the conclusion.
3. **Remediation complete** — on this host and on every other affected one.
4. **Metadata classification done** for metrics.
5. **Motivation and attribution** (or cluster) fed back to threat intelligence.
6. **New analytics and tuning** fed back to detection engineering.
7. **Samples taken** for periodic peer review and feedback.

The SOC is always under pressure to move on to the next thing. Taking the time to make sure analysis is complete, classified, and fed back into these processes is what makes the SOC better over months and years rather than just busier.

## Summary of the analysis part { #part-summary }

This page closes the analysis part of these notes. Looking back over it:

- **Alert triage and prioritisation** — what makes an alert dangerous (distance to the attacker's goal, exfiltration, destruction, sensitive hosts and people) and how to rank a queue. See [Alert Triage](../alert-triage/index.md).
- **Perception and memory** — why we see what we expect, why working memory is small, and why externalising and decomposing problems helps. See [Perception & Memory](../analyst-cognition/index.md).
- **Mental models** — OODA, the Kill Chain, defence in depth, NIST CSF and the IR cycle, intelligence cycles and F3EAD, the Diamond Model, attack trees, the Pyramid of Pain and ATT&CK. See [Mental Models](../mental-models/index.md).
- **Structured analysis** — System 1 and 2, hypothesis generation, confirmation bias and disconfirmation, ACH, link analysis and event matrices. See [Structured Analysis](../structured-analysis/index.md).
- **Investigation questions and tactics** — the question, the data, network and host evidence, email, links, phishing and BEC. See [Investigation Questions](../investigation/index.md).
- **Analysis OPSEC** — researching without tipping off the attacker, TLP and PAP. See [Analysis OPSEC](../analysis-opsec/index.md).
- **Reacting to intrusions** — dwell time, intrusion type, backdoors, motivation, risk, and choosing a response. See [Reacting to Intrusions](../intrusion-response/index.md).
- **Quality and case review** — closing cases well and challenging our own analysis (this section).

The common thread is to **question your own process**: look for alternatives, try to disprove your favourite hypothesis rather than confirm it, and build in feedback so you find out when you were wrong. Alongside the techniques, the part has shown many of the tricks attackers use to throw analysts off their trail. Triage, investigation and closing alerts take a long time to master; the aim was a strong start on how to think about the alerts in front of you and how to pick and finish the important ones. The next part moves on to **continuous improvement** — tuning and optimising alerts and analysis, automation, and ways to keep developing as a blue team analyst.

## The 2026 view { #trends }

!!! success "[2026 Current] Still valid as-is"
    Premortem, structured self-critique, What If?, red team analysis and Team A/B are still taught and used exactly as described; Heuer and Pherson's book is in its third edition (2020, with Pherson as lead author) and the 2009 tradecraft primer is still a common free reference. Premortems are now routine in incident response planning and tabletop exercises, and "sample closed cases for peer review" is a standard SOC quality practice. The case for feedback has only grown stronger as SOCs automate more triage.

!!! info "[Changed] What has changed"
    - **AI now closes alerts too.** Many SOCs in 2025–2026 let AI triage assistants or "agentic" SOC tools enrich, and sometimes auto-close, low-risk alerts. Those decisions need the same review as human ones: sample AI-closed alerts every period, and score them against the same checklist.
    - **AI as a challenger.** Analysts increasingly ask an AI assistant to argue the opposite case, list alternative hypotheses or run a quick premortem on a plan. That is a useful prompt for reframing — but the model only knows what you gave it and can share your blind spots.
    - **Blameless review culture** from site reliability engineering has spread into security operations: post-incident reviews focus on conditions and decisions, not on blaming individuals — the same spirit as the caution against analyst ranking.
    - **NIST SP 800-61 Rev. 3 (2025)** treats improvement as continuous across the CSF 2.0 functions rather than a single "lessons learned" meeting at the end — which is what regular case review delivers.
    - **More automation bias risk.** With AI-generated summaries and verdicts on screen, the danger of accepting a confident label (like "scanner activity") without checking is greater, which makes structured self-critique more important, not less.

!!! warning "[Caution] What is wrong or risky to do the old way"
    - **Don't use peer review scores to rank or punish analysts.** It destroys honest documentation and the learning it was meant to create.
    - **Don't review only cases that went wrong.** Random sampling finds the silent misses — closed "benign" cases like WR-2026-0455 — that nobody would ever flag.
    - **Don't let one appointed devil's advocate carry all the dissent.** Have everyone critique.
    - **Don't treat an AI's counter-argument as a red team.** Use it as a prompt, then have people who know the threat do the real challenge.
    - **Don't skip reviewing automated or AI-closed alerts** just because no human touched them.
    - **Don't let the review become a checkbox.** If every case scores full marks every week, the review questions are too easy or nobody is really reading.

## Practice questions { #quiz }

### Question 1

Your team is about to approve a containment plan everyone feels good about. Which technique would you run first, how would you phrase the starting question, and what is its main limitation — and which technique addresses that limitation?

??? success "Answer and explanation"
    Run a **premortem**. Start with: *"It's three weeks from now and the plan has failed — the attacker is back (or the business is down). Each of you, explain how it happened."* Go round the table so everyone contributes.

    It legitimises dissent and exposes overconfidence, and you can attach early-warning signs and plan changes to each failure mode. Its limitation is that it shows that problems **may** exist but doesn't tell you which one is real, which matters most, or exactly how to fix it. **Structured self-critique** is the natural follow-on: everyone plays critic and works through set questions (reliable sources, ignored contradictions, missing evidence, assumptions, alternatives, absence of information, deception) to pin down specific weaknesses and revisit confidence.

### Question 2

A closed case says: "svc-scan from the scanner IP accessed the finance share — expected scanner behaviour, benign." The file server shows 4624 Logon Type 3, one 5140 for `\\*\Finance`, and 1,842 5145 events with `ReadData` on spreadsheet files on a Saturday night. Explain what each event tells you and name two self-critique questions that should have changed the conclusion.

??? success "Answer and explanation"
    - **4624, Logon Type 3** — a successful **network** logon to the file server by `svc-scan` from the scanner's IP. It proves the credentials were used, not who used them.
    - **5140** — the account connected to the `Finance` share (once per session). It shows which share was opened.
    - **5145 with `ReadData`** on files — detailed file-share auditing showing each file requested and that its **contents were read**; 1,842 of them is bulk reading.

    Questions that should have changed the conclusion, for example: **"Was contradictory evidence ignored?"** — the scanner runs Tuesday 02:00–04:00, not Saturday 23:10. **"Were key assumptions valid?"** — vulnerability scanners check versions and settings; they don't read the contents of hundreds of payroll spreadsheets. Also **"missing evidence"** — a scan would touch many hosts, but no other server saw `svc-scan` that night — and **"deception"** — a known service account from its usual IP is how an intruder blends in (T1078). The disposition should have been indeterminate at best, and the case investigated further.

### Question 3

A colleague proposes ranking analysts by monthly peer-review score to "motivate quality". What would you recommend instead, and how should reviews differ for a new analyst and a senior one?

??? success "Answer and explanation"
    Recommend keeping reviews as a **learning tool**, explicitly not used for ranking or punishment. Ranking makes people document defensively, avoid difficult cases and hide doubts — the opposite of what review is for. Use the results to find **team-wide patterns** and to **pair** people who need a skill with someone who has it; let new analysts read senior analysts' cases.

    **New analysts:** more frequent reviews, focused on analytical completeness, whether the right tools were used and whether the reasoning process holds up. **Senior analysts:** fewer reviews, but in the style of a **red team analysis** — challenging their conclusions and mindset to check they didn't jump to an answer from a mental rut, because experience is exactly what creates those ruts.

## Related { #related }

- [Closing a Case Well](documentation-classification.md) — the previous page
- [Quality & Case Review](index.md) — section overview
- [Hypothesis generation and confirmation bias](../structured-analysis/hypothesis-generation.md)
- [ACH](../structured-analysis/ach.md) — disconfirming hypotheses
- [Memory and experience](../analyst-cognition/memory-experience.md) — mental ruts
- [Choosing a Response](../intrusion-response/choosing-response.md) — the eviction plan tested by the premortem
- [Important Events](../important-events/index.md) — Windows event IDs
- [Threat Intelligence](../../../threat-intel/index.md)

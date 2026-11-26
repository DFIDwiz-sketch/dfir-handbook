---
title: "The Pyramid of Pain, MITRE ATT&CK and When Each Model Applies — Making the Attacker's Life Hard and Choosing the Right Lens"
tags:
  - training
  - blue-team
  - soc
  - analysis
  - mental-models
  - mitre-attack
---

# The Pyramid of Pain, MITRE ATT&CK and When Each Model Applies — Making the Attacker's Life Hard and Choosing the Right Lens { #pyramid-attack-summary }

!!! abstract "What this page covers"
    The last two models of this section, and how all of them fit together. First, David Bianco's **Pyramid of Pain** — six kinds of indicator, from hash values at the bottom to tactics, techniques and procedures (TTPs) at the top, ranked by how much it hurts the attacker when you deny them — shown with one invented campaign's real-looking indicators at every level: a one-byte change that produces a completely new SHA-256, IPs and domains, a Zeek `http.log` line with network artefacts, a YARA rule for the tool and a Sigma rule for the behaviour, each read line by line, plus what the attacker does after each kind of block. Then **indicators of attack versus indicators of compromise**, and the Detection Maturity Level idea. Next, **MITRE ATT&CK**: tactics, techniques, sub-techniques and procedures, the matrices, what a technique page gives you, an invented intrusion mapped technique by technique, a Navigator layer read line by line and a coverage-gap hunt. Finally **when each model applies** — triage, incident response, defence strategy, hunting, threat intelligence and tempo — and the reminder that all models are wrong but some are useful. The 2026 view and practice questions close the page and the section.

!!! note "Labels"
    **[Supplement]** = practical material you need to know, **[Correction]** = a commonly repeated claim that is wrong or outdated, **[Changed]**/**[Caution]** = what has changed recently and what is risky to do the old way. The company (Kestrel Logistics), the campaign name, hostnames, accounts, domains, IPs, file names, rules and log lines are invented for illustration (`.example`, documentation and private IPs). Frameworks and their authors are described in my own words.

## The 8 key points { #key-points }

1. **The Pyramid of Pain ranks indicators by how much pain denying them causes the attacker.** From bottom to top: hash values (trivial to change), IP addresses (easy), domain names (simple), network and host artefacts (annoying), tools (challenging), TTPs (tough).
2. **Hashes are the weakest long-term defence.** Flip one bit and the hash is new. Block them anyway — it's cheap — but never treat a hash block as the end of an incident.
3. **IPs and domains cost the attacker a few minutes and a few dollars.** New cloud servers and new domains are cheap; blocks at these levels buy hours or days.
4. **Artefacts, tools and TTPs force the attacker back to the drawing board.** A rule on a URI pattern makes them change code; a rule on the tool makes them rebuild it; a detection on the behaviour makes them invent a new way of working. That's where your detection effort pays off longest.
5. **Indicators of attack (IOAs) describe what the attacker is *doing*; indicators of compromise (IOCs) describe what they *left behind*.** IOCs are reactive and easy to swap; IOAs catch the next intrusion too.
6. **MITRE ATT&CK is a catalogue of the top of the pyramid.** Tactics are the attacker's goals (the *why*), techniques and sub-techniques are the ways to reach them (the *how*), procedures are specific real-world examples. Each technique page lists who used it, how to mitigate it and how to detect it — a blue-team checklist.
7. **Each job has its model.** Triage: the Kill Chain or attack life cycle. Incident response: the IR cycle, then the Pyramid of Pain for what to block. Defence strategy: threat models and attack trees. Hunting and analytics: ATT&CK. Threat intelligence: the three levels, F3EAD and the Diamond Model. Tempo: OODA.
8. **All models are wrong; some are useful.** Models simplify, and simplifying drops detail. Use them as a starting skeleton, not a rule every incident must fit — the analyst's judgement is what fills the gaps.

## Why this matters in a SOC { #why }

Imagine a shoplifter who keeps coming back to your shop. Banning *his red jacket* at the door works until he changes jacket — tomorrow. Banning his car's number plate works until he takes the bus. Learning that he always works with a partner who distracts the cashier at the till while he fills a bag in the aisle behind — and training staff to spot that pattern — works on him *and* on every other shoplifter who uses the same trick, whatever they wear. The jacket is a hash; the plate is an IP; the distraction routine is a TTP.

Back to the technical reality: during an incident, the pressure is to block *something* fast, and the easiest things to block are the bottom of the pyramid — the hash from the sandbox, the C2 IP from the proxy log. Those blocks are necessary but they don't end anything. The Pyramid of Pain tells you where the lasting value is, and ATT&CK gives you the shared names for the top of the pyramid so that a detection engineer, a threat-intel report and an incident timeline all speak the same language. And knowing *which* model to pick for *which* question is what makes the whole toolbox of this section useful at 3 a.m. with an alert queue in front of you.

## The Pyramid of Pain { #pyramid }

### The model { #pyramid-model }

David Bianco, then a hunting lead at a large incident-response company, published the Pyramid of Pain in 2013 as a way to think about the best way to ruin an adversary's day once you know something about their operation. It ranks six types of indicator by how much it costs the attacker to change them once you start detecting or blocking them:

```
                 /\
                /  \        TTPs                    Tough!
               /----\
              /      \      Tools                   Challenging
             /--------\
            /          \    Network/Host Artefacts  Annoying
           /------------\
          /              \  Domain Names            Simple
         /----------------\
        /                  \ IP Addresses           Easy
       /--------------------\
      /                      \ Hash Values          Trivial
     /________________________\
```

The higher the level you can detect and deny, the more work the attacker has to do to keep going — and the longer your detection stays useful.

### Worked example: KL-CAMP-01 at every level { #pyramid-example }

Kestrel Logistics has three incidents from campaign KL-CAMP-01 (used throughout this section). Here is what the SOC knows, level by level, what a detection at that level looks like, and what the attacker did after each kind of block.

**Level 1 — hash values (trivial).** The sandbox gives the SHA-256 of the backdoor `updsvc.exe`. Why is this the bottom? A cryptographic hash changes completely when *any* bit of the file changes. A harmless demonstration with two text files that differ in one character:

```
$ printf 'build-id: 0001\n' > sample_v1.txt
$ printf 'build-id: 0002\n' > sample_v2.txt
$ sha256sum sample_v1.txt sample_v2.txt
fb23786473ab56b0e2a87ab67e0e77a156eeef58cce9a1eacc18c4e610225cb5  sample_v1.txt
466a2789bfd273ff55423c3748c40da98273e2837e60f0236a7accf1ac61ccd9  sample_v2.txt
$ cmp -l sample_v1.txt sample_v2.txt
14  61  62
```

- `printf … > sample_v1.txt` — write a one-line file; the second file differs only in the last digit.
- `sha256sum` — print each file's SHA-256 hash. The two hashes share nothing recognisable, although the files differ in one byte.
- `cmp -l` — list every byte that differs: byte `14`, octal `61` (the character `1`) versus octal `62` (`2`). One byte in, a completely new hash out.

Malware authors do the same automatically: a builder that changes a few bytes or repacks the file per victim gives every target a unique hash. In Incident B, Kestrel blocked the hash; Incident C used a binary with a different hash, built from the same code.

**Level 2 — IP addresses (easy).** C2 at 198.51.100.23. Renting a new cloud server takes minutes, and many attackers route through cloud providers, VPNs or compromised hosts anyway. After the IP block in Incident A, the backdoor moved to a new IP within a day.

**Level 3 — domain names (simple).** `telemetry-cdn.example`, `freightdocs-portal.example`. A domain costs a few dollars and minutes to register; some attackers use free subdomains of dynamic-DNS or hosting services, or legitimate cloud services. Slightly more annoying than an IP (registration, DNS setup, a certificate), but still cheap.

**Level 4 — network and host artefacts (annoying).** These are traces of *how the tool behaves* rather than *where it connects*. The Zeek `http.log` line from Incident A (before the actor switched to HTTPS everywhere):

```
ts=2026-09-22T10:05:12Z  uid=C8fQ2b  id.orig_h=10.20.6.31  id.resp_h=203.0.113.77  id.resp_p=80
method=POST  host=update-cdn.example  uri=/api/v2/ping  user_agent=Mozilla/5.0 (Windows NT 10.0; Win64; x64) UpdSvc/2.1
request_body_len=64  response_body_len=0  status_code=204
```

- `method=POST`, `uri=/api/v2/ping` — the check-in path the backdoor uses on every C2 server: a **network artefact**.
- `user_agent=… UpdSvc/2.1` — a browser-like User-Agent with the tool's own suffix appended: a classic sloppy artefact.
- `request_body_len=64`, `response_body_len=0`, `status_code=204` — a fixed 64-byte check-in answered with "204 No Content" when there is no task — the same every 300 seconds. Regular size and timing are artefacts too.

On the host, the artefacts are the install path `%APPDATA%\UpdSvc\updsvc.exe`, the Run-key value name `UpdSvc`, and a mutex (a named lock the malware creates so only one copy runs) called `Global\UpdSvcMtx`. A detection on `/api/v2/ping` plus the fixed 64-byte POST pattern caught Incident C's beacon on a brand-new domain and IP — the attacker had to change their code to escape it.

**Level 5 — tools (challenging).** A detection for the backdoor *family*, not one build. A YARA rule (YARA describes files by patterns of strings and bytes) for the invented `updsvc` family:

```
rule KL_CAMP01_UpdSvc_Backdoor
{
    meta:
        description = "Invented example: UpdSvc backdoor family used by KL-CAMP-01"
        tlp = "AMBER"
    strings:
        $uri   = "/api/v2/ping" ascii wide
        $mutex = "Global\\UpdSvcMtx" ascii wide
        $ua    = "UpdSvc/" ascii
        $cfg   = { 2C 01 00 00 40 00 00 00 }
    condition:
        uint16(0) == 0x5A4D and filesize < 2MB and 3 of them
}
```

- `rule KL_CAMP01_UpdSvc_Backdoor` — the rule name; good names say campaign and family.
- `meta:` — description and sharing label; not used for matching.
- `$uri`, `$mutex`, `$ua` — text strings from the tool; `ascii wide` matches both normal and UTF-16 encodings (Windows programs often store strings as UTF-16).
- `$cfg = { 2C 01 00 00 40 00 00 00 }` — a byte pattern: the little-endian numbers 300 (`0x12C`, the beacon interval) and 64 (`0x40`, the check-in size) stored together in the config.
- `uint16(0) == 0x5A4D` — the file starts with `MZ`, i.e. it is a Windows executable.
- `filesize < 2MB and 3 of them` — small file, and at least three of the four patterns. Requiring three means a rebuild that changes one string still matches.

Every rebuilt hash of `updsvc` still matches; to escape, the attacker must rewrite or replace the tool — real development work.

**Level 6 — TTPs (tough).** A detection for the *behaviour*, independent of tool, domain or hash. KL-CAMP-01's consistent behaviour is "a user opens an LNK from an archive, and Explorer launches a hidden, encoded script host". A Sigma rule (Sigma is a vendor-neutral format for log-based detections, converted into each SIEM's query language):

```
title: Hidden encoded PowerShell launched by Explorer (possible malicious LNK)
status: experimental
logsource:
    product: windows
    category: process_creation
detection:
    selection_parent:
        ParentImage|endswith: '\explorer.exe'
    selection_child:
        Image|endswith:
            - '\powershell.exe'
            - '\pwsh.exe'
    selection_flags:
        CommandLine|contains|all:
            - ' -w hidden'
            - ' -enc'
    condition: selection_parent and selection_child and selection_flags
tags:
    - attack.t1204.002
    - attack.t1059.001
    - attack.t1027
level: high
```

- `logsource: product: windows, category: process_creation` — run against process-start events: Windows **4688** or Sysmon Event 1. **Event 4688** ("a new process has been created") fires every time a process starts and, with command-line auditing enabled, records the full command; attackers care because it captures their execution even when the payload never touches disk.
- `selection_parent` — the parent process is Explorer, which is what happens when a user double-clicks something.
- `selection_child` — the child is PowerShell (Windows PowerShell or PowerShell 7).
- `selection_flags` with `contains|all` — the command line contains *both* a hidden-window option and an encoded command. (Real rules also handle the shortened and alternative spellings of these options; this one is kept short.)
- `condition` — all three must match.
- `tags` — the ATT&CK techniques: **T1204.002 User Execution: Malicious File**, **T1059.001 Command and Scripting Interpreter: PowerShell**, **T1027 Obfuscated Files or Information**.

This rule doesn't care about the domain, the hash or even the backdoor. It catches KL-CAMP-01's *next* tool, and any other actor who uses the same trick. To escape it, the attacker must change how they get code running — a new initial-access method, new tradecraft, retraining. That is the "tough" level.

### What the attacker did after each block { #pyramid-after-block }

| Kestrel blocked… | Level | Attacker's response | Time until the attacker was back |
| --- | --- | --- | --- |
| `updsvc.exe` hash (Incident B) | Hash | Rebuilt the binary | Next campaign wave (~3 weeks, but unrelated to the block) |
| C2 IP (Incident A) | IP | New cloud server | < 1 day |
| C2 domain (Incident A) | Domain | New domain on new IP | ~1 day |
| `/api/v2/ping` + 64-byte POST pattern | Artefact | (Not yet changed — still catching beacons) | — |
| YARA rule on the family | Tool | (Not yet changed) | — |
| Explorer → hidden encoded PowerShell | TTP | Would need new initial-access tradecraft | — |

**[Supplement]** In practice you do *both*: block the cheap indicators immediately because it's fast and stops the current intrusion, *and* invest your detection-engineering time higher up because that's what lasts. The pyramid isn't saying "don't block hashes"; it's saying "don't stop there". Higher-level detections also tend to be noisier (legitimate admins run hidden PowerShell too), so they need tuning — that's the price of durability.

### Indicators of attack vs indicators of compromise { #ioa-vs-ioc }

A more binary way to say the same thing is **indicators of compromise (IOCs)** versus **indicators of attack (IOAs)**, a distinction popularised by an EDR vendor. Think of a bank robbery: "the robber wore a red hat" is an IOC — true, but out of date the moment it's written, and useless if they wear a blue hat next time. Catching someone *casing* the bank, slipping into the staff corridor and working on the vault door are IOAs — observations of the attack *in progress*, which apply to any robber who does it the same way.

| | IOC | IOA |
| --- | --- | --- |
| Describes | Evidence left behind | Activity as it happens |
| Pyramid level | Mostly bottom (hashes, IPs, domains) | Mostly top (artefacts of behaviour, TTPs) |
| Defensive posture | Reactive: "have we seen this before?" | Proactive: "is someone doing this right now?" |
| KL-CAMP-01 example | `telemetry-cdn.example`, the hash of `updsvc.exe` | Explorer spawning hidden encoded PowerShell; a fixed-interval POST beacon to a newly registered domain |

**[Supplement]** Ryan Stillions' **Detection Maturity Level (DML)** model (2014) extends the same ladder to describe how mature an organisation's detection is: from DML-0 (no detection) through atomic indicators (1), host and network artefacts (2), tools (3), procedures (4), techniques (5) and tactics (6) up to the adversary's strategy (7) and goals (8). A SOC that only consumes IOC feeds sits at DML-1 however many feeds it buys.

## MITRE ATT&CK { #attack }

### What it is { #attack-what }

**MITRE ATT&CK** (Adversarial Tactics, Techniques, and Common Knowledge) is a public knowledge base of how real attackers behave, maintained by MITRE, a US not-for-profit that runs federally funded research centres. It is essentially a catalogue of the top of the Pyramid of Pain, and it has become the common language of detection engineering, threat intelligence and red teaming. Every defender should know it well.

Its structure:

- **Tactics** — the columns across the top: the attacker's goal at that point, the *why*. Examples: Initial Access, Execution, Persistence, Privilege Escalation, Credential Access, Discovery, Lateral Movement, Collection, Command and Control, Exfiltration, Impact. IDs look like `TA0006` (Credential Access).
- **Techniques** — the entries in each column: a way to reach that goal, the *how*. IDs look like `T1003` (OS Credential Dumping).
- **Sub-techniques** — more specific variants nested under a technique: `T1003.001` (LSASS Memory), `T1003.003` (NTDS).
- **Procedures** — specific, observed implementations: "group X used tool Y to dump LSASS by doing Z". These appear as examples on each technique page.

**[Correction]** Older material often lists "account manipulation, brute force, credential dumping and credentials in files" as examples of Credential Access. In the current matrix, **Brute Force (T1110)** and **OS Credential Dumping (T1003)** are under Credential Access, credentials in files is now a sub-technique, **Unsecured Credentials: Credentials In Files (T1552.001)**, and **Account Manipulation (T1098)** sits under Persistence and Privilege Escalation. Technique names and places move between versions — always check the live site.

The knowledge base is split into domains: **Enterprise** (Windows, Linux, macOS, plus cloud platforms — IaaS, SaaS, office suites and identity providers — network devices, containers and ESXi), **Mobile** and **ICS** (industrial control systems). Besides techniques, it has pages for **groups** (activity clusters with the techniques they used), **software** (malware and tools), **campaigns**, **mitigations** and, since version 18, **detection strategies** and analytics for each technique. MITRE also runs a user conference, ATT&CKcon, first held in 2018.

### Worked example: mapping Incident C { #attack-mapping }

Mapping an incident means writing, for each thing the attacker did, the technique it represents and the evidence for it:

| Time (UTC) | What happened | Evidence | Tactic | Technique |
| --- | --- | --- | --- | --- |
| 08:41 | ZIP with LNK emailed to procurement | Gateway log, email header | Initial Access | T1566.001 Phishing: Spearphishing Attachment |
| 08:47 | User opened the LNK | 4688: explorer.exe → powershell.exe | Execution | T1204.002 User Execution: Malicious File |
| 08:47 | Hidden, Base64-encoded PowerShell | 4688 command line `-w hidden -enc` | Execution | T1059.001 PowerShell; T1027 Obfuscated Files or Information |
| 08:47 | Second stage downloaded over HTTPS | Proxy log, Zeek `ssl.log` | Command and Control | T1105 Ingress Tool Transfer |
| 08:48 | Run key `UpdSvc` → `%APPDATA%\UpdSvc\updsvc.exe` | Sysmon 13 (registry value set) | Persistence | T1547.001 Registry Run Keys / Startup Folder |
| 08:48 → | Beacon every 300 s to `/api/v2/ping` | Zeek `ssl.log`, EDR network events | Command and Control | T1071.001 Application Layer Protocol: Web Protocols |

Three rules for good mapping:

- **Map evidence, not guesses.** "Probably used Mimikatz next" is not a row. If you didn't see it, it isn't mapped.
- **Use the most specific level you can support** — sub-technique if the evidence shows it, technique if not.
- **Write the ATT&CK version** used, because techniques and tactics move (see the 2026 view below).

### Worked example: a coverage layer and a hunt { #attack-coverage }

The **ATT&CK Navigator** is MITRE's free web tool for colouring the matrix — for example, which techniques you detect. Layers are saved as JSON. A trimmed layer, read line by line:

```json
{
  "name": "Kestrel SOC detection coverage 2026-11",
  "domain": "enterprise-attack",
  "versions": { "attack": "20", "navigator": "5.1", "layer": "4.5" },
  "techniques": [
    { "techniqueID": "T1059.001", "score": 3, "comment": "Sigma: hidden encoded PowerShell; AMSI logs" },
    { "techniqueID": "T1547.001", "score": 2, "comment": "Sysmon 13 on workstations only" },
    { "techniqueID": "T1003.001", "score": 3, "comment": "EDR LSASS access alert" },
    { "techniqueID": "T1114.003", "score": 0, "comment": "No inbox-rule audit in SIEM" }
  ],
  "gradient": { "colors": ["#ff6666", "#ffe766", "#8ec843"], "minValue": 0, "maxValue": 3 }
}
```

- `"name"` — what the layer shows and when.
- `"domain": "enterprise-attack"` — the Enterprise matrix.
- `"versions"` — the ATT&CK version the IDs refer to (and the tool and file-format versions). Without this, a layer is ambiguous after the next release.
- `"techniques"` — one entry per technique: `techniqueID`, a `score` (here 0 = no coverage to 3 = tested detection) and a `comment` explaining the score.
- `"gradient"` — colours from red (0) through yellow to green (3), so gaps jump out.

The red cell is **T1114.003 Email Forwarding Rule**, which the [attack tree on the previous page](diamond-attack-trees.md#attack-tree-example) already flagged. That's a hunting hypothesis: *"If KL-CAMP-01 has compromised an accounts-payable mailbox, it has created a rule forwarding or hiding supplier emails."* The hunter queries the mail platform's audit log for new inbox rules on AP mailboxes in the last 90 days, especially rules that forward externally or move messages containing "bank" or "invoice" to an obscure folder. Whether the hunt finds anything or not, the result is a new detection, and the cell turns green. This is the IOC-less hunting the ATT&CK matrix is good for: start from the attacker's possible techniques and your known gaps, not from an indicator.

## When each model applies { #when-each-model }

Now the toolbox is complete, here is when to reach for what:

| Situation | Question | Model |
| --- | --- | --- |
| **Triage** | Which alert is most dangerous? | Cyber Kill Chain / attack life cycle — how far along is each attack? |
| **Incident response** | What do I do next? | Incident response cycle (PICERL) |
| | What do I block, and how? | Pyramid of Pain |
| **Defence strategy / audit** | Which control are we missing? | Threat model and attack trees |
| **Hunting / analytic development** | What should we look for that we don't detect yet? | MITRE ATT&CK |
| **Threat intelligence** | What do we do with all these indicators? How do we use outside information? | Three levels, F3EAD, intelligence cycle, Diamond Model |
| **Operations tempo** | Are we fast and adaptable enough? | OODA loop |

A short walk through one night shift shows them in sequence:

1. **Triage.** The queue has a phishing-click alert, a port scan from the internet and a C2-beacon alert from KL-WS-0712. Kill Chain thinking: the beacon is the furthest along (an active, unblocked C2 channel), so it goes first — unless something suggests data is leaving right now, which would trump everything.
2. **Incident response.** An incident is declared. Preparation and Identification are done (the detection fired, scope is being checked), so the IR cycle says **contain** next: stop the bleeding by cutting C2 — a proxy or firewall block, a network or host IPS rule, or a host firewall rule via EDR isolation. The exception is a deliberate decision to watch and wait on a targeted intruder, covered later in this guide.
3. **What to block.** The Pyramid of Pain: block the hash, IP and domain now (cheap, immediate) and push the artefact, tool and behaviour detections to detection engineering (durable).
4. **Threat intelligence.** F3EAD's Exploit step: harvest the LNK metadata, the email, the timeline; the Diamond Model links this event to KL-CAMP-01.
5. **Hunting.** ATT&CK coverage shows the inbox-rule gap; tomorrow's hunt is written.
6. **Strategy.** The attack tree for payment fraud updates the manager's "which control next?" answer.
7. **Tempo.** The OODA loop is the reminder underneath it all: the side that understands the situation more accurately and adapts faster wins.

## Why mental models matter — and why they're all wrong { #why-models }

The OODA loop's *Orient* step is where your models meet the data. If the model is wrong, trying harder won't help: you'll just orient faster in the wrong direction. "If all you have is a hammer, everything looks like a nail" — an analyst who knows only the Kill Chain forces every incident into seven malware stages, including the insider who never used malware at all. This section had two goals: to give you the industry-standard models for attacks, defence and threat intelligence, so you can break problems down and write them outside your head (the decomposition and externalisation from the [memory page](../analyst-cognition/memory-experience.md)); and, through OODA, to show *why* having many models matters — in a fast-changing contest, the side that can switch to the right view fastest has the advantage.

And the final warning, from the statistician George Box: **all models are wrong, but some are useful.** We simplify because our minds are limited (bounded rationality, from the perception and memory section), and simplifying means leaving detail out. Some examples of where the models in this section strain:

- A cloud intrusion with a stolen session token and no malware has no "Installation" or "Weaponisation" in the Kill Chain sense.
- The Pyramid of Pain says hashes are weak, but a hash of a unique, hand-built tool shared quickly with partners can still be valuable for hunting in the first days.
- PICERL is drawn as a sequence, but real incidents jump back from Eradication to Identification when new scope appears.

Use the models as a skeleton and a starting path. The nuance of each incident is different, which is why analytical and critical-thinking skills — the subject of the next section — matter more than memorising any diagram.

## The 2026 view { #trends }

!!! success "[2026 Current] Still valid"
    The Pyramid of Pain is still one of the most-cited models in detection engineering and threat hunting, and its lesson — invest in behaviour, not only in atomic indicators — is the basis of modern EDR and detection-as-code practice. MITRE ATT&CK is firmly the common language: EDR and SIEM vendors tag detections with ATT&CK IDs, threat-intel reports map to it, and MITRE's evaluations of security products use it. YARA and Sigma remain the standard open formats for file and log detections. "All models are wrong, some are useful" is as true as ever.

!!! info "[Changed] What has changed"
    - **ATT&CK has changed a lot since early 2020s material.** Version 18 (October 2025) replaced the old per-technique data-source detection notes with *detection strategies* and *analytics*. Version 19 (April 2026) retired the Defense Evasion tactic and split its techniques into two new tactics, **Stealth** and **Defense Impairment**, which forces remapping of older detections and reports. Version 20 (October 2026) added techniques for abusing AI systems and more MFA-bypass and identity techniques. Cloud is now part of the Enterprise domain as platforms rather than a separate matrix.
    - **The bottom of the pyramid got even cheaper for attackers.** Automated builders, per-victim packing and AI-assisted code changes make unique hashes the norm; attackers increasingly use legitimate cloud and SaaS services for C2 and staging (ATT&CK T1102 Web Service, T1567 Exfiltration Over Web Service), so blocking "their" domain may mean blocking a service your business uses. The well-known free-domain registrar that many older examples cite stopped offering new registrations in 2023, but cheap domains and free subdomains remain easy to get.
    - **Network artefacts moved up the stack.** With almost all C2 inside TLS, artefacts such as URIs and User-Agents are often invisible without TLS inspection; TLS and HTTP client fingerprints (JA3 has largely given way to the **JA4+** family), certificate patterns and beacon timing carry more of the weight.
    - **AI-assisted mapping.** SOC copilots and CTI tools now suggest ATT&CK mappings for alerts and reports automatically. Useful, but mappings to deprecated or wrong techniques are a known failure mode — check them.

!!! warning "[Caution] Wrong or risky to do the old way"
    - **Don't stop at the bottom of the pyramid.** Closing an incident after blocking a hash and an IP practically guarantees the attacker returns undetected with a new build on a new server.
    - **Don't treat ATT&CK coverage as a score to maximise.** A green Navigator cell only means a rule exists; it says nothing about whether it fires on real variants, how noisy it is, or whether the data source is even collected. Test detections (for example with an adversary-emulation or atomic test) before marking them covered, and prioritise the techniques your threat model says matter.
    - **Don't reuse old ATT&CK mappings blindly.** Reports, rules and layers that mention Defense Evasion (TA0005) or older technique names need remapping to the current version. Always record the version you mapped against.
    - **Don't block legitimate cloud services as if they were attacker domains.** When C2 uses a SaaS platform, block the specific tenant, bucket or URL path where possible, or detect the behaviour, rather than the whole service.

## Practice questions { #quiz }

### Question 1

During an incident you have: (a) the SHA-256 of a dropper, (b) the C2 domain, (c) the fact that the beacon always POSTs 64 bytes to `/api/v2/ping` every 300 seconds, (d) a mutex name `Global\UpdSvcMtx`, (e) the observation that the attacker always gets execution by having Explorer launch hidden, encoded PowerShell from an LNK. Place each on the Pyramid of Pain, say what you would do with each today, and which one you would spend detection-engineering time on.

??? success "Answer and explanation"
    (a) **Hash value** — bottom; (b) **domain name**; (c) **network artefact**; (d) **host artefact**; (e) **TTP** — top. (A YARA rule built from several strings including (c) and (d) would be a **tool**-level detection.)

    Today: block (a) and (b) immediately — they are cheap, and stopping the current C2 matters — and sweep the environment for them. Deploy detections for (c) and (d), which will catch new builds on new servers. Spend real detection-engineering time on (e): a behavioural rule on process creation (4688 / Sysmon 1, T1204.002, T1059.001, T1027), tuned for legitimate admin use. It is the only one that also catches the attacker's next tool and other actors using the same trick.

### Question 2

A colleague shows you a Navigator layer where 80% of the matrix is green and says the SOC is "80% covered". Give three reasons this may be misleading, and describe how you would use ATT&CK to plan the next hunt instead.

??? success "Answer and explanation"
    (1) Green may mean "a rule exists", not "a rule fires on real variants" — untested detections often fail. (2) It may not reflect data-source reality: a rule for a technique is useless if those logs aren't collected on all hosts (e.g. Sysmon only on workstations). (3) Techniques aren't equal: covering many rarely used techniques while missing the few your adversaries actually use isn't 80% of the *risk*. Also, the layer may be mapped to an old ATT&CK version (e.g. still using Defense Evasion after v19).

    Better: start from the threat model and threat intelligence (which techniques do our likely adversaries use?), find those with no or weak coverage on the layer, write a hypothesis for one ("if they have an AP mailbox, they created a forwarding rule — T1114.003"), hunt in the relevant logs, and turn the result into a tested detection. Record the ATT&CK version.

### Question 3

For each situation, name the most useful model from this section and say why: (a) twelve new alerts and one analyst; (b) an incident has just been declared and the attacker's C2 is live; (c) the CISO asks which security project to fund next year; (d) the hunt team wants ideas for the next quarter; (e) the team has 300 indicators from five incidents and doesn't know what to do with them.

??? success "Answer and explanation"
    (a) **Kill Chain / attack life cycle** — rank alerts by how far along the attack is; active C2 and anything suggesting exfiltration go first. (b) **Incident response cycle**, then the **Pyramid of Pain** — the next step is containment (cut C2 by proxy, firewall, IPS or host isolation), and the pyramid tells you to block cheap indicators now and push behaviour-level detections for the long term. (c) **Threat model and attack trees** — pick the control that removes the most uncovered paths to the worst outcome. (d) **MITRE ATT&CK** — compare likely adversary techniques with current coverage and hunt the gaps. (e) **Threat-intelligence models** — the three levels (who needs what), **F3EAD** (feed them back into detection, with analysis), and the **Diamond Model** (link the incidents to find a shared actor). Throughout, the **OODA loop** reminds you that accuracy *and* speed of orientation win — and no model fits every case perfectly.

## Related { #related }

- [The Diamond Model, attack trees, graph thinking and threat modelling](diamond-attack-trees.md) — the previous page
- [Kill Chain, campaigns, defence in depth, NIST CSF and the IR cycle](kill-chain-did-nist-ir.md) · [Threat-intelligence levels and F3EAD](threat-intel-cycles.md) · [Encapsulation and the OODA loop](encapsulation-ooda.md)
- [Alert triage: defining "dangerous"](../alert-triage/defining-dangerous.md) — the Kill Chain in triage
- [Process creation events](../important-events/process-creation.md) · [Memory and experience](../analyst-cognition/memory-experience.md)
- [Threat intelligence](../../../threat-intel/index.md) · [PowerShell cradles](../../../adversary/powershell-cradles.md) · [Persistence](../../../adversary/persistence.md)

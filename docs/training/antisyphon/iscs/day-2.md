---
title: "Day 2 — Egress Traffic Analysis and Logging"
tags:
  - training
  - antisyphon
  - egress
  - beaconing
  - zeek
---

# Day 2 — Egress Traffic Analysis and Logging

<div class="dfir-meta" markdown>
**Course:** Information Security Core Skills · **Instructor:** John Strand (BHIS) · **Day 2 scope:** egress → NetFlow → Zeek → beaconing → RITA → ASN → AC-Hunter → UEBA → Deep Blue CLI → Windows logs → Sysmon
</div>

!!! abstract "Day 2 at a glance"
    If Day 1 was about *keeping attackers out*, Day 2 is about **finding the ones already in**. The focus is **outbound (egress) traffic** — the conversation an infected host has with its C2 server. You can't read the content (it's encrypted), but you can see the **behaviour** (regular interval + consistent size = a **beacon**). **Zeek** turns traffic into consistent metadata logs; **RITA / AC-Hunter** find the beacons. The second half covers **UEBA** (tying many logs together to spot departures from normal behaviour) and **log quality** — the limits of default Windows logging and its fix, **Sysmon**.

!!! note "Conventions"
    **💡 Note (added)** = my own addition beyond the lecture. **(reconstructed)** = commands the instructor only showed on screen, written out generically — match them to the actual lab handout.

---

## 1. Why "egress" traffic? { #why-egress }

When an attacker owns a host, that host keeps talking to the attacker's **C2 (command-and-control) server**. That conversation flows **outbound** (recall Day 1's reverse connection), so watching egress traffic reveals the infected internal host. In MITRE ATT&CK, C2 / common-port use / exfiltration are areas many orgs miss.

The reason they miss it is **encryption** — most traffic is TLS/SSL, so you can't read the content. Appliances can decrypt TLS in the middle, but that raises privacy / GDPR concerns.

!!! quote ""
    "It's encrypted so we can't see it" is not an acceptable excuse. You can't read the content, but you can still see the **behaviour**.

## 2. NetFlow — connection statistics { #netflow }

Even without content, you can see **who talked to whom, when, and how much**. That's **NetFlow** (connection statistics, created by Cisco):

- **Exporter** — the device sending the connection data (router / firewall)
- **Importer / Collector** — where that data is gathered
- **Analysis engine** — makes sense of the collected data

Once NetFlow became a de-facto standard, many look-alikes followed (sFlow, jFlow, NetStream …) — all different ways of handling connection statistics.

## 3. Lab — analysing Cisco ASA firewall logs by hand { #asa-lab }

John first shows **how painful it is by hand**. Assume some internal IP is compromised (here `192.168.1.6`):

```bash
sudo su -
cd /opt/firewall_log
grep 192.168.1.6 <logfile>        # (reconstructed) pull only lines with that IP
```

- `grep <string>` picks out only the lines containing a string.

The logs are ugly (John calls it "a nightmare"). You refine the data into something you can get statistics from, then use **R tools** to do the math and hunt for a **beacon**. The point: you *can* do it by hand, but it's brutal — hence Zeek / RITA.

## 4. Using AI on the logs — context is everything { #ai-log-analysis }

**① "Look for evil traffic" alone** → AI flags the **wrong things** (what looks like a port scan, Telnet, ACL-blocked traffic) and **misses the real malicious beacon**. Without **context** it tends to **hallucinate**.

**② Give it context** (internal/external IPs, addresses to exclude, completed connections only — the backdoor alternates between two external IPs) → it gets much closer but can still wrongly conclude "looks normal." The decisive clue is **timing**:

```text
1s, 1s, 1s, 1s, 1s …   (a full TCP connect/teardown every second)
```

> Unless it's a remote terminal or keep-alive, almost no legitimate service does a full TCP connect/teardown every second → **malicious beacon**.

R tools confirms it:

```text
min 1816, max 1848, mean 1829, stdev 12
```

A **standard deviation of 12** is tiny — the data size is near-constant, the hallmark of a **beacon**.

!!! tip "The key skill in the AI era"
    "Find evil" rarely works. You have to use what you've learned to **narrow the question**. Knowing how to analyse logs — and asking the right question — is the skill.

---

## 5. Zeek — consistent, and small { #zeek }

Because by-hand is painful, use **Zeek** (formerly Bro). It's fast, widely used, and its **timestamps are dead-consistent** (devices handle time in odd, inconsistent ways; Zeek doesn't).

This is a shift in thinking. Day 1's AV looked for **strings (assembly)** inside an executable — a signature. But traffic is **encrypted**, so there are no strings to match. Instead, the **behaviour in the logs** lets you actively **hunt**. This matters more over time because of **AI** — it can generate malware, new C2 methods and obfuscation, so humans must use AI to hunt traffic patterns.

**Zeek vs full PCAP**

| | Full PCAP | Zeek |
|---|---|---|
| Pro | all content, every tool supports it (most portable) | ~**1/10** the size |
| Con | **very large** | no raw packet content (metadata) |

Zeek doesn't compress packets — it turns them into **metadata**, about one-tenth the size.

!!! warning "Capture pre-NAT"
    Outside the firewall (internet side) every internal host looks like the **one firewall IP**, so you can't identify the infected host. Capture **pre-NAT (inside)** to get the **infected internal private IP**.

The Zeek logs themselves (`conn.log`, `dns.log`, `http.log`, `ssl.log` …) are written up under [Network → Zeek](../../../network/zeek/index.md).

## 6. What is beaconing? { #beaconing }

John's analogy: a child going "mom, mom, mom…" at a steady rhythm — that's a beacon. The infected host repeats "I'm here, give me orders" to C2 on a regular cadence. Analyse it three ways:

1. **Interval** — regular, like a heartbeat?
2. **Data size** — nearly the same each time (small standard deviation)?
3. **Connection timing** — complete/restart repeating at a tight cadence?

**Jitter** — a smart attacker deliberately **varies** the interval (e.g. 7s ±2s → random 5–9s). It isn't perfectly regular, but it still has **beacon characteristics** (a symmetric cluster around 7s). The interval doesn't have to be perfect — it just has to have beacon characteristics.

**Long connections** — instead of beaconing, an attacker can hold **one connection open** for a long time. John's spaghetti analogy: break one long strand (a long connection) into pieces (chopped-up connections), but add the pieces back up and you get the original day's worth. Chopping it up to hide still shows up **when you sum it**.

Full beacon / C2 detection notes: [Network → Beaconing & C2](../../../network/beaconing-c2.md).

## 7. RITA — the beacon-detection engine { #rita }

The math lives in **RITA (Real Intelligence Threat Analytics)** — a **free** BHIS tool, kept open-source via patents. It does two things: **find beacons** and **check deny lists** (compare against known-bad IPs — more in part 3).

**The math**

- **K-means clustering** — finds **patterns (consistency)** in data. Like a CAPTCHA teaching pattern recognition by repeatedly asking you to pick traffic lights / bicycles, it finds **clusters of consistent interval and size**.
- **MADM (median absolute deviation of the mean)** — similarly measures the consistency of the distribution.

**Beacon score** — each connection gets a **0–1 score**; closer to **1 = a more perfect beacon**. You also look at **connection count** (e.g. 108,000 connections at perfect intervals).

!!! warning "A beacon isn't always malware (legit beacons)"
    Regular beaconing isn't only malware — **TeamViewer** (staff may use it to bypass filters), **RDP**, **Nuance / Dragon** (had built-in remote control), **LAN Turtle** (a USB-to-Ethernet-shaped mini Linux). Not all malicious, but **all worth investigating**.

**Other things to look at** — **User-Agent strings** (how an internal system identifies itself), **MIME types** (what kind of data is moving — returns in part 3 as "MIME mismatch"), **JA3/JA4** (fingerprinting the TLS client hello; JA3 broke when browsers randomised the hello, so JA4 now).

**Long-tail analysis** — sort normal vs abnormal and the anomalies cluster in the **rare long tail**. Human traffic is messy and irregular; a **beacon is unusually consistent**, so it stands out in that tail.

### Is there a hands-on RITA lab? { #rita-lab-note }

**Day 2 has no standalone command-line RITA lab.** RITA is taught as the *engine*; the hands-on beacon analysis is done through **AC-Hunter's GUI**, which runs on it (part 3). So **RITA = the free command-line engine**, **AC-Hunter = the paid GUI on top** (a community edition exists). The beacon math in the first ASA-log lab used **R tools**, not RITA.

!!! note "💡 Note (added) — running RITA yourself"
    RITA is free, so you can run it against your home-lab Zeek logs (conceptual flow):

    ```bash
    # import Zeek logs into a RITA database
    rita import /opt/zeek/logs/2026-10-17 mydataset
    # show beacon analysis, highest score first
    rita show-beacons mydataset
    rita show-exploded-dns mydataset
    ```

    `rita import <zeek-log-dir> <name>` loads the logs; `rita show-beacons <name>` shows beacon scores (0–1) and connection counts. Recent RITA (v5+) is configured differently — check the docs. This is a supplement, separate from the actual course lab.

---

## 8. ASN — "the internet's postcode" { #asn }

John extends RITA's second job, **deny-list checking**, to the **ASN** level. An **ASN (Autonomous System Number)** identifies an organisation that manages a block of IP addresses (ISPs, cloud providers …) — in John's analogy, **the internet's postcode**. There are good neighbourhoods and bad ones.

### Lab — which neighbourhoods do bad IPs live in? { #asn-lab }

1. Download a continuously updated **bad-IP list** from GitHub.
2. Feed each IP to **Team Cymru** (an IP → ASN lookup service) to get its ASN (takes a while — lots of data).
3. **Count bad IPs per ASN and sort.**

!!! note "💡 Note (added)"
    This kind of tally is usually done on Linux with `sort | uniq -c | sort -rn` — `uniq -c` counts identical values, `sort -rn` sorts largest first. Follow the lab handout for the exact command.

The output's first column is the **bad-IP count**, the second the **ASN**:

```text
4925  Alibaba
4563  DigitalOcean
....  (several Chinese ASNs)
....  Microsoft
....  Amazon
```

Page down and the numbers **drop off fast** (a few pages in, you're at ~39). There are **roughly 80–90k ASNs** on the internet, yet most bad IPs sit in **a tiny handful of them**.

!!! tip "Key point"
    Check deny lists **by ASN, not just by IP**. How much your environment talks to "the few neighbourhoods where bad IPs concentrate" is a good clue. RITA and AC-Hunter can also be deployed inside **Security Onion**, because Security Onion already uses Zeek.

---

## 9. AC-Hunter lab — beacons from real malware { #ac-hunter-lab }

**AC-Hunter** is the GUI on top of the RITA engine. This lab needs no cloud VM — it runs **in the browser**. Log in with the demo account; the **datasets** (traffic from different malware samples) are listed top-left. Five questions and John's answers:

### ① AsyncRAT — a textbook beacon { #asyncrat }

**Q:** connection interval and dispersion for `192.168.0.136`? → John: **"almost the perfect definition of a beacon."**

- **Interval distribution:** centred on ~7s, **symmetric** from 5–9s — a **7s ±2s jitter**. A live example of "the interval doesn't have to be perfect, it just needs beacon characteristics."
- **Data-size distribution:** **tightly clustered** — nearly the same size every time.
- **Persistence:** a **flat** histogram — steady all day.

The practical point is **outliers** in the size distribution. Attackers usually just beacon and occasionally **activate** the backdoor — only then does the size jump. So a hunter can answer the CEO:

> CEO: "Were we compromised?" → **"Yes."**
> CEO: "Did they exfiltrate data?" → **"The data doesn't support it."** A large transfer would show up as a massive outlier.

### ② ZenoRAT — a backdoor that doesn't beacon { #zenorat }

**Q:** connection interval for `172.208.51.75`? → **just 4 connections** carrying **~7 MB**. Not a beacon but one connection **held open** — a [long connection](#beaconing). Attackers used to do this → got detected → moved to beaconing → beaconing got detected → **went back to holding connections open.** So watch for **both**.

### ③ dnscat2 — a DNS backdoor { #dnscat2 }

**Q:** which domain has the highest lookup count, and what are the random strings for? → dnscat2 uses **DNS queries themselves as the channel**. Under the most-queried domain sit countless **random-looking subdomains**.

Why random? **DNS caching.** If the backdoor always queried the same name, the first answer would be cached on the internal DNS server and later queries **would never reach the attacker**. A different subdomain each time means no cache hit, so every query travels **all the way to the attacker's DNS server**, carrying data in that string.

!!! note "💡 Note (added)"
    Clues in Zeek [`dns.log`](../../../network/zeek/index.md): an **abnormally high number of unique subdomains** under one domain, and subdomain labels that are **long and random (high entropy)**.

### ④ WhatTime — a name that blends in { #whattime }

**Q:** the C2's FQDN, and why use a name like that? → a little jitter, very small size dispersion, strong persistence; bucketed per hour it averages about **168 connections/hour**. The real point is the domain **`timeserversync.com`** — it sounds like time-server sync, so an admin thinks:

> "Looks legit… if I block it something might break."

It's chosen to **blend into the organisation**. A plausible name is no reason to relax.

### ⑤ FireStack2 — MIME mismatch { #firestack2 }

**Q:** what's wrong with the MIME data? → it's full of **MIME mismatches** ("mismatch between the response MIME type and the URI"). A **MIME type** is the label saying "this data is of this kind" (e.g. `image/jpeg`); when the label doesn't match the real content, suspect malware. It happened **2,868 times** — once or twice could be misconfiguration, but that consistency suggests **deliberate disguised communication**.

**RITA is free**; **AC-Hunter has a community edition**.

---

## 10. UEBA — tie many logs together and look at behaviour { #ueba }

**UEBA (User and Entity Behavior Analytics)** learns the **normal behaviour** of users and systems and flags departures from it. John is tempted to just rename the card "AI," and rates it on a par with **EDR**. In Back Doors & Breaches it costs **3 resource points** because it catches so much: social engineering, credential stuffing, compromised trust relationships, insider threat, phishing, credential harvesting.

### Why tie logs together — JPCERT's research { #jpcert }

Japan's **JPCERT** asked what **actually gets left behind** when an attacker uses LOLBins, makes registry changes or runs PsExec, tracking logs, Prefetch and registry together. The conclusion:

> **Single-log analysis doesn't tell the whole story.**

So UEBA **correlates many logs** into one story. The classic example is an **internal password spray**; what you're ultimately catching is **lateral movement**. JPCERT's **LogonTracer** draws it as a graph — the `SVC_WhiteNoise` account logging on to many IPs — using core events such as **4624** (successful logon) and **4625** (failed logon).

!!! note "💡 Note (added)"
    LogonTracer also uses **4768** (Kerberos TGT request), **4769** (service-ticket request) and **4776** (NTLM credential validation) — all "who logged on where, and how" events — and plots account↔host links as a **graph** to spot odd connections. Event IDs overall: [Windows Event IDs](../../../basics/windows-event-ids.md).

### "False positives don't exist" — detection tuning opportunities { #false-positives }

> **"False positives don't exist."**

Originally a false positive meant "a rule fired when the true condition wasn't met." Over time people started calling anything slightly unexpected a false positive and **switching the rule off**. John's fix: rename it a **"detection tuning opportunity."** If a **legitimate service account** logging on to many systems keeps firing alerts, don't disable the rule — **add an exception for that account and its characteristics.** "That is literally our job."

### How UEBA works { #how-ueba-works }

**① Stacking** — logon **+1**, logoff **−1**, set a threshold (say 6). Someone spraying thousands of hosts pushes the count **past 2,000** and an alert fires.

**② AI — learn normal, follow the downhill.** John uses a **3D topographic map**: AI always takes the **path of least resistance (downhill)**.

- "John logged into his own account" → extremely common. Lots of data says it's normal, so judging it malicious is **uphill** — it won't go there.
- "John suddenly logged on to **10 more** systems. Normal for him?" → no. The judgement starts **rolling downhill**.

As abnormal data accumulates it keeps descending until it hits a **decision threshold**: "probably malicious." AI baselines normal and, in John's words, is **"lazy"** — it just follows the easiest path. Example: **Bob normally logs on to 30–40 systems** (baseline) — so if he suddenly **pulls 3 GB?** That's "rolling downhill into a black hole."

!!! note "💡 Note (added)"
    The topographic analogy is a plain-language take on **gradient descent** and **anomaly detection**. Real UEBA products typically build per-user / per-group baselines and score how far activity departs from them (e.g. how many standard deviations).

---

## 11. Deep Blue CLI lab { #deepbluecli-lab }

**Deep Blue CLI** is a PowerShell script that reads Windows event logs (`.evtx`) and flags **attack-like patterns**. It's **not a true AI tool**, but a good stand-in for the abnormal patterns AI would look for.

```powershell
cd C:\Introlabs\DeepBlueCLI-master          # (reconstructed) lab folder
Set-ExecutionPolicy Unrestricted             # allow unsigned scripts to run
.\DeepBlue.ps1 .\evtx\new-user-security.evtx # (reconstructed) analyse a sample log
```

- `Set-ExecutionPolicy Unrestricted` — unsigned scripts don't run by default, so this loosens it for the lab. **Not recommended in production.**
- `.\DeepBlue.ps1 <evtx file>` — analyse the given event log.

### Case ① New user — same SID, different name { #case-sid }

Humans tend to **skip long numbers and strings**. Here a very long **SID** (an account's unique identifier) is **identical in two entries**, yet one username is just **`-` (a dash)** and the other is **`IEUser`** — and the **dash account was added to local Administrators**. Definitely worth investigating.

!!! note "💡 Note (added)"
    Related events: **4720** (user account created), **4732** (member added to a security-enabled local group, e.g. Administrators), **4781** (account renamed). Names can change but the SID stays, so track accounts **by SID, not name**.

### Case ② Password guessing — the admin account doesn't lock out { #case-guessing }

Guessing is normally stopped by **account lockout**, yet here there are **3,560** failed logons. The target is the **local Administrator**, which by default **doesn't lock out**. John's inference:

> "This is **probably not remote over SMB**."

By default you can't log on to the local Administrator **remotely (SMB)**, so it's more likely **RDP**, **someone at the keyboard**, or **misconfigured policy**.

!!! note "💡 Note (added)"
    Guessing looks like **4625** (failed logon) piling up on **one account**. The **logon type** in 4625 confirms John's inference directly — **10 = RDP (remote interactive)**, **3 = network (SMB etc.)**, **2 = at the keyboard (interactive)**.

### Case ③ Password spraying — one source, many accounts { #case-spray }

**One source (Josh Wright's account)** tried to log on to **lots of other accounts**.

> Guessing = failures pile up on **one account** / Spraying = failures spread across **many accounts**.

### Case ④ Obfuscated commands — where AI shines { #case-obfuscation }

Paste the log's **obfuscated PowerShell** into ChatGPT with "does this look like malware?" and it unpacks it quickly (it can read text in screenshots too).

| Obfuscation | What AI identified |
|---|---|
| String building + `IEX` | classic: concatenate pieces, run via **`Invoke-Expression`** |
| Base64 | a **Base64-encoded** command |
| A run of 0s and 1s | **binary → character decoding**, junk characters stripped then int→char → "highly suspicious" |
| Symbol-soup variable names | **legal PowerShell**, but weird variable names / brackets to make analysis painful |

!!! note "💡 Note (added)"
    For these commands to be logged you need PowerShell logging — **4104** (script-block logging) records the **actual de-obfuscated content** and is the key event here. Related: [PowerShell cradles](../../../adversary/powershell-cradles.md).

> **"This is what we should be using AI for"** — making our lives easier and understanding what's actually going on.

### Practical log-analysis tips { #log-tips }

- **AD logs are the glue** — especially for authentication. With multiple forests, clustered AD and transitive trusts, you need UEBA to make sense of them.
- **Draw the attack path**, look at **top talkers** (busiest workstations, user accounts, admin accounts), and do **time analysis** (the heat map shows logons spiking around hour 15).
- John's real workflow: Deep Blue CLI finds a **spray target** (e.g. `Bertha Schultz`) → PowerShell **extracts just that account's logs** → a very tight attempt-timing pattern appears.
- The follow-on tool **DeepWhite CLI** can analyse **Sysmon logs** too.

!!! warning ""
    **Your detection logic is only as good as the data your logs give you.**

---

## 12. Windows logging problems and Sysmon { #logging-sysmon }

### Why default Windows logs are a mess { #windows-logs }

**Security log:** there's useful material like logons, but it's buried under entries like "special privileges assigned to new logon — SYSTEM, NT AUTHORITY," so who tried to log on isn't obvious. Worse, when John changes Group Policy security settings the log says **"the SYSTEM account changed it"**, and **no log ties** John's privilege use to SYSTEM's change.

**Application log:** not "which program started" but "successfully auto-updated third-party root list," "offline down-level migration succeeded"… Paste an `ESENT` entry into AI and it explains the Extensible Storage Engine — but **you still don't know which service attached**.

> The records security actually needs — like "the user started Skype" — **aren't in the default logs.**

### 90–95% of logs are garbage — the economics of logging { #logging-economics }

In most organisations **fewer than 5%** of collected logs have a rule or alert attached. So why does everyone say "collect everything"?

> **"Because the vendors tell you to — the more you log, the more money they make,"** since most charge by volume.

Still, turn on the **core logs** — **4624/4634** (logon/logoff), object access (ACL), process creation and usage. John does advise **against enabling the Windows Firewall log** (too noisy).

!!! note "💡 Note (added)"
    **4634** is logoff, **4647** is user-initiated logoff. Pair with 4624 to compute session length.

### How hard it is to enable command-line logging { #cmdline-logging }

John reads the steps not for you to memorise but to show how absurd it is: ① enable Audit Process Creation → ② enable "Include command line in process creation events" → ③ make sure advanced audit policy isn't **overwritten** by basic audit policy → ④ increase the log size → ⑤ enable it under Administrative Templates → ⑥ enable it under Advanced Audit → Detailed Tracking → ⑦ a **third setting** to stop it being overwritten.

> "And there was much rejoicing."

**PowerShell logging** also needs settings, but at least you can script it in one go. The conclusion: "wouldn't it be nicer to do it all in seconds? → **Sysmon**."

!!! note "💡 Note (added)"
    With command-line logging on, **4688** (new process created) records the **full command line**. For PowerShell, **4104** (script block) and **4103** (module logging).

### Sysmon — "the logs you've been looking for" { #sysmon }

**Sysmon** was written by Sysinternals' **Mark Russinovich**. The irony: back in **2014** it already gave everything we wanted (which program started, **who** started it, its **network connections**, its **parent process**) — and Microsoft is only **now** starting to ship it by default in modern Windows.

**Log location:** Event Viewer → Applications and Services Logs → Microsoft → Windows → **Sysmon → Operational**

**Process-creation example — a Metasploit-built file as seen by Sysmon**

| Field | Value (example) | Meaning |
|---|---|---|
| Image | `C:\trustme.exe` | executable and **full path** |
| OriginalFileName | `ab.exe` | the **original name** embedded in the file |
| Product / Company | Apache HTTP Server / Apache | who made it |
| Hashes | (MD5 / SHA256 …) | file **hashes** |
| ParentImage | `cmd.exe` | **parent process** |

Why is **OriginalFileName `ab.exe`**? Metasploit stuffs its payload into **Apache Bench (`ab.exe`)**, a legitimate utility — so the file is named `trustme.exe` but its original name is `ab.exe` and the company is Apache.

!!! tip "A strong clue"
    **File name ≠ OriginalFileName** is itself a strong clue. An attacker can rename the file, but the original name embedded inside stays.

**Deployment and use:** push it easily via **Group Policy**, ship logs off-host with **Winlogbeat**, analysis tools such as **SOC Prime**, and **Sigma** — an open rule language you write once and **convert** to almost any SIEM. (Bonus: Exchange logging is off by default too.)

!!! note "💡 Note (added) — common Sysmon event IDs"
    **1** process create · **3** network connection · **7** image (DLL) load · **8** CreateRemoteThread (thread injected into another process) · **10** process access (e.g. LSASS access → credential-dumping clue) · **11** file create · **13** registry value set · **22** DNS query. What gets logged is set by a **config file** — many start from **SwiftOnSecurity**'s or **Olaf Hartong's (sysmon-modular)** public configs. Related: [LSASS dumping](../../../adversary/lsass-dumping.md) · [Process injection](../../../adversary/process-injection.md).

### Sysmon lab (overview) { #sysmon-lab }

The goal is to **see malware through Sysmon's eyes** — so you conclude you need to use Sysmon, build a config and roll it out. The flow mirrors Day 1's AppLocker lab: on Windows, disable real-time protection and the firewall and change the admin password; on Kali, build a test file and move it over; **install Sysmon on Windows before running it**; then run it and review the **Sysmon logs**.

!!! warning ""
    Again, **don't refresh the browser** (after the admin password changes, Guacamole fails to log back in → Destroy and restart the VM).

John deferred the walkthrough to the **start of Day 3** — the Sysmon log review (the malicious file creating a thread in LSASS while dumping hashes, and how Pass-the-Hash looks in Sysmon) continues there. The final AMA was run while playing **Back Doors & Breaches** competitively with students, so it isn't written up separately.

---

## Day 2 summary { #summary }

| Topic | Key point |
|---|---|
| Egress analysis | content is encrypted, but **behaviour** is visible |
| NetFlow / ASA logs | painful by hand; AI needs **context** to be useful |
| Zeek | consistent metadata logs (~1/10 of PCAP), capture **pre-NAT** |
| Beacons / long connections | regular interval + consistent size; jitter / chopping still shows in totals |
| RITA / AC-Hunter | beacon math (K-means), scores, investigate legit beacons too |
| ASN | bad IPs concentrate in a **few ASNs** |
| UEBA | **tie logs together** to find departures from normal; false positives are **tuning opportunities** |
| Deep Blue CLI | guessing (one account) vs spraying (many), AI for obfuscation |
| Windows logs / Sysmon | defaults are a mess, ~90% is garbage; **Sysmon** gives what you need |

!!! quote ""
    Find attackers already inside through outbound behaviour (Zeek + RITA) and correlated log behaviour (UEBA). And since detection is only as good as your logs, cut the useless logging and get the logs that matter — like Sysmon.

## References

- [Antisyphon Training](https://www.antisyphontraining.com/) · [Black Hills Information Security](https://www.blackhillsinfosec.com/)
- [RITA (GitHub)](https://github.com/activecm/rita) · [AC-Hunter](https://www.activecountermeasures.com/ac-hunter/)
- Related: [Network → Zeek](../../../network/zeek/index.md) · [Beaconing & C2](../../../network/beaconing-c2.md) · [Windows Event IDs](../../../basics/windows-event-ids.md)

---
title: "Prioritising Alerts — IDS and Exploit Alerts, Same-Stage Alerts, Unique Alerts and What Can Wait"
tags:
  - training
  - blue-team
  - soc
  - triage
  - ids
  - analysis
---

# Prioritising Alerts — IDS and Exploit Alerts, Same-Stage Alerts, Unique Alerts and What Can Wait { #prioritising-alerts }

!!! abstract "What this page covers"
    The first two pages of this section gave you the rules (dangerous = near completion, high-value target, targeted attacker, unique) and the clues (exfiltration, destruction, sensitive targets, targeted tells). This page **puts them to work on real-looking queues**. First a **seven-alert IDS queue** read only from signature names and hit counts — with a full Suricata `eve.json` alert broken down field by field, and the reasoning for each alert's rank (sinkhole callbacks, outbound TFTP, `xp_cmdshell` against an internal SQL server, a packed download, a mass-mailed executable, an internet-of-things scan). Then what to do when **every alert is at the same stage**: six questions (what does the exploit give, did it work, what happened after, what asset, where, which user) applied to four exploit alerts. Then a **six-scenario exploit discussion** — Log4Shell on a patched DMZ server, an exploit kit in a browser, Zerologon against a domain controller (with the **4742** and Netlogon events that show it), a planted USB stick (**6416**), password guessing against an external HR portal (**4625** sub-status codes) and a macro document sent to the help desk. Then **long-tail ("least frequency of occurrence") analysis** with a 90-day alert count built line by line, the **lower-priority alerts** that are mostly noise (and how to tell a misconfigured service from a brute force), and a **one-card triage checklist**. Practice questions with explanations at the end.

!!! note "Labels"
    **[Supplement]** = practical material you need to know, **[Correction]** = a commonly repeated claim that is wrong or outdated, **[Changed]**/**[Caution]** = what has changed recently and what is risky to do the old way. The company (Kestrel Logistics), hostnames, accounts, domains, IPs, signature names and log lines are invented for illustration (`.example`, documentation and private IPs). Signature names imitate the style of public IDS rulesets but are not copied from them.

## The 8 key points { #key-points }

1. **Read a signature name as a kill-chain stage.** Recon scan → early. Delivery (an attachment) → early but maybe wide. Exploit → middle. Installation / C2 / lateral movement / exfiltration → late. Late beats early.
2. **The hit count changes the meaning.** One hit on a bad domain may be a single redirect that failed; twenty-two hits on a **sinkhole** mean a host that is *really infected* and keeps calling home. One `xp_cmdshell` attempt on an internal server is serious; a thousand scan hits on a camera exploit you don't own is noise.
3. **Outbound protocols you never use are a gift.** If nothing in the company sends TFTP (or FTP, or SMB) to the internet, a hundred outbound TFTP alerts is probably data leaving — check it first.
4. **When everything is at the same stage, rank by consequence**: what does the exploit give (admin? user? crash?), did it work (patch state, what happened next), what kind of asset (internal server ≫ DMZ server ≫ ordinary laptop), where (production ≫ test), and who (admins, engineers, finance, executives, help desk).
5. **An exploit against an internal crown jewel also tells you how far the attacker already got.** Zerologon against a domain controller implies they are inside, found the DC and staged tools — the attack is near its goal.
6. **Long-tail analysis**: alerts that fire most are usually rules to tune; alerts that fire **least** — especially ones never seen before — are where new attacker behaviour shows up. Mind how the rule counts (per packet vs per connection).
7. **Usually not urgent**: external port scans, most policy violations, a few failed logins, single unauthorised-access attempts, and bare "bad IP" matches. They happen all the time, by accident, or are low fidelity. **But** "excessive" against one server needs a check — and rule out a misconfigured service before you call it brute force.
8. **The triage card**: How far has it progressed? Any exfiltration, destruction or evidence deletion? Could it be targeted? Is it unique here? Pick the alert with the worst answers, then move on to validating it carefully.

## Why this matters in a SOC { #why }

Rules are easy to agree with in a classroom. The hard part is a Monday morning with 300 alerts, seven of them in front of you, and no time to open all seven properly. You need to be able to look at a list of **signature names and counts** and, in a minute or two, say "this one first, this one second, these three can wait" — and be able to defend the choice afterwards.

Think of a mechanic listening to a car with five strange noises. They don't fix the noises in the order they heard them. A squeal from the brakes beats a rattle from the glovebox, even if the rattle is louder and started first. The mechanic knows what each noise *means* for the car. In the SOC, the "meaning" of an alert is its stage, its target and its rarity — and the skill is reading those from very little text.

This page practises that skill on three kinds of queue: a mixed IDS queue, a queue where everything is the same stage, and a queue of exploit scenarios. Then it covers two shortcuts (long-tail analysis and knowing what can safely wait) and finishes with a checklist you can use on any queue.

## Worked example 1: a seven-alert IDS queue { #ids-queue }

### First, what an IDS alert actually contains { #ids-alert-anatomy }

In a real queue you'd have the full alert, not just a title. Here is one of the seven alerts below as Suricata writes it to `eve.json` (one JSON object per line; shown pretty-printed and shortened):

```json
{
  "timestamp": "2026-11-23T08:14:07.331245+0000",
  "event_type": "alert",
  "src_ip": "10.10.0.53",
  "src_port": 53,
  "dest_ip": "10.20.4.57",
  "dest_port": 51544,
  "proto": "UDP",
  "alert": {
    "action": "allowed",
    "signature_id": 9100231,
    "rev": 3,
    "signature": "KL DNS Reply - Known Sinkhole Address",
    "category": "A Network Trojan was detected",
    "severity": 1
  },
  "dns": {
    "type": "answer",
    "rrname": "upd-check.kl-cdn.example",
    "rdata": "192.0.2.250"
  }
}
```

- `timestamp` — when the packet was seen, with time zone. Always check the zone before you compare with other logs.
- `event_type: alert` — Suricata writes many event types (`dns`, `http`, `tls`, `flow`…) into the same file; this line is a rule match.
- `src_ip 10.10.0.53`, `src_port 53` → `dest_ip 10.20.4.57`, `UDP` — this rule matches the **DNS reply**, so the packet travels *from* the internal resolver (10.10.0.53) *to* the client. The host to investigate is therefore the **destination**, 10.20.4.57 — the one that asked. Always work out which side is the client before you pivot; for reply-based rules it is the reverse of what you might expect.
- `alert.action: allowed` — the IDS only watched; nothing was blocked. (An IPS in blocking mode would say `blocked`.)
- `signature_id`, `rev` — the rule's number and version. You use them to read the rule itself, tune it, or search for every other hit.
- `signature` — the name you see in the queue. Rule authors usually start with a vendor/category prefix (`KL DNS`, `ET POLICY`…), then what was seen.
- `category`, `severity 1` — the ruleset's own classification. Severity 1 is the highest in Suricata's scheme, but remember from the first page: **severity is the rule's opinion, not this event's danger.**
- `dns.rrname`, `dns.rdata` — the domain asked for, and the answer: `192.0.2.250`, which (in our invented world) is a **sinkhole** — an address run by researchers or a registrar that took control of a malicious domain so infected machines call *it* instead of the attacker.

So the full alert already tells you a lot more than the title: which internal host, which domain, and that nothing was blocked. The exercise below uses only titles and counts on purpose, because that is often all you see at the queue level — and it is enough to make a first ranking.

### The queue { #ids-queue-table }

Seven signature names from Kestrel's IDS for the last 24 hours, with the number of hits each:

| # | Signature (invented) | Hits |
| --- | --- | --- |
| I1 | `KL DNS Query to Suspicious Dynamic-DNS Domain (*.dyn-host.example)` | 1 |
| I2 | `KL DNS Reply - Known Sinkhole Address` | 22 |
| I3 | `KL SMTP Inbound ZIP Attachment Containing .scr Executable` | 50 |
| I4 | `KL POLICY Outbound TFTP Data Transfer` | 100 |
| I5 | `KL SCAN Network Camera Firmware Exploit Probe` | 1,000 |
| I6 | `KL WEB_SERVER MSSQL xp_cmdshell Attempt in URI` | 1 |
| I7 | `KL MALWARE Packed Executable (rare packer) Download over HTTP` | 1 |

Let's go through them one by one, asking each time: *what stage is this, did it get anywhere, and how many people or systems does it touch?*

**I1 — one DNS query for a suspicious dynamic-DNS domain.** Someone's computer asked for a name that looks malicious. Two possible stories: the computer is *infected* and asking for its C2, or the user was *redirected* there (a malicious ad, a compromised site) as part of an exploit attempt. We don't know whether the site was even alive or whether anything downloaded. **One** query fits the redirect story better — infected machines usually ask repeatedly. So this is most likely delivery/exploit stage, possibly failed. Look later, and check whether the same host has other alerts. (ATT&CK if it turns out to be C2: **T1568 Dynamic Resolution** and **T1071.004 Application Layer Protocol: DNS**.)

**I2 — 22 replies pointing at a sinkhole.** At first glance it looks *less* bad than I1: the domain is now harmless, because the sinkhole doesn't send commands. But the count changes everything. Twenty-two lookups mean a program on that host keeps trying to reach its controller — that is **C2 behaviour from an infected machine**. Malware often carries a list of fallback domains, so it may soon try one that *isn't* sinkholed. **High priority**: the installation stage has already happened.

**I3 — 50 inbound emails with a ZIP containing a `.scr`.** A `.scr` is a screensaver file, which is really just a Windows executable (see [dangerous file types](../file-analysis/safe-handling-file-types.md)). This is **delivery** stage (**T1566.001 Phishing: Spearphishing Attachment**) — early, but it reached **50 people**, and each one is a possible infection. Fast to work: check the mail gateway for delivery status, pull the message from mailboxes, and if you can, analyse the file to find the domain it calls so you can search the proxy and DNS logs for anyone who already ran it. **Medium priority** — early stage but wide.

**I4 — 100 outbound TFTP transfers.** First question: does anything at Kestrel legitimately send TFTP to the internet? Almost certainly not — TFTP is a simple, unauthenticated file-copy protocol used *inside* networks for things like network-device configs and PXE boot. A hundred hits means this has been going on for a while. **What is being sent?** It could be confidential data. This is possibly **active exfiltration** (**T1048.003 Exfiltration Over Alternative Protocol: Exfiltration Over Unencrypted Non-C2 Protocol**) — **check it first.**

**I5 — 1,000 hits of a camera-firmware exploit probe.** Kestrel doesn't run that brand of network camera, and the name says *probe* — it's **reconnaissance** (**T1595.002 Active Scanning: Vulnerability Scanning**) aimed at something you don't have. Internet-wide scanners do this all day. The thousand hits come from the rule firing on every probe. **Bottom of the list.**

**I6 — one `xp_cmdshell` attempt in a web request.** `xp_cmdshell` is a built-in Microsoft SQL Server feature that lets a SQL user run **operating-system commands** — if the account they control is privileged. Seeing it inside a URI means someone is trying to push SQL through a web application into the database and from there onto the server's command line (SQL injection leading to command execution: **T1190 Exploit Public-Facing Application**, then **T1059.003 Command and Scripting Interpreter: Windows Command Shell**; enabling or abusing stored procedures for persistence is **T1505.001 Server Software Component: SQL Stored Procedures**). Now assume the target is an **internal** web server in front of the shipping database. Then someone is already inside and moving towards a server that holds sensitive data. Yes, it could be an admin doing something odd — but the potential damage is huge. **Top priority, level with I4.** If the target were a DMZ server, it would be lower (internet noise), though still worth checking whether the request got a `200` and a large response.

**I7 — one packed executable downloaded over HTTP.** A **packer** wraps an executable so it unpacks itself in memory when run — a bit like a self-extracting ZIP that stays runnable. Attackers like packers because they also **hide the code**, so `strings` and signatures see little (see [strings and packing](../file-analysis/strings.md)) — **T1027.002 Obfuscated Files or Information: Software Packing**. An executable arriving like this is the **installation** stage; if antivirus doesn't catch it, C2 follows quickly. **High priority, level with I2** — both probably mean an active infection.

### The ranking { #ids-ranking }

| Rank | Alert | Stage | Why here |
| --- | --- | --- | --- |
| 1 | I4 Outbound TFTP ×100 | Exfiltration (possible) | Protocol never used outbound; long-running; data may be leaving now |
| 1 | I6 `xp_cmdshell` ×1 (internal server) | Exploit → command execution on a sensitive server | Attacker already inside, going for data; one hit is enough |
| 3 | I2 Sinkhole replies ×22 | C2 from an infected host | Installed malware retrying; may switch to a live domain |
| 3 | I7 Packed EXE download ×1 | Installation | Likely becomes C2 soon if not caught |
| 5 | I3 `.scr` in ZIP ×50 | Delivery, wide | Early, but 50 possible infections; quick to contain |
| 6 | I1 Dynamic-DNS query ×1 | Delivery/exploit, probably failed | Single hit fits a redirect; check for related alerts |
| 7 | I5 Camera probe ×1,000 | Recon against something we don't own | Constant internet background |

Notice two things. First, the highest *count* (I5) ended up last and two *single* hits (I6, I7) ended up near the top — counts only matter together with stage. Second, I1 and I2 look like the same thing (a bad domain), but the count flipped their order. With only titles and counts we already have a defensible plan; the next step is to open I4 and I6 and *validate* them.

## When every alert is at the same stage { #same-stage }

Sometimes the queue is a pile of alerts that are all the same kind — say, eight "exploit attempt" alerts against different hosts. Stage no longer separates them, so you go back to the basic question: **if this one succeeds, how bad is it?** Six questions help:

1. **What does the exploit do if it works?** Remote admin (SYSTEM/root) access, ordinary user access, or just a crash (denial of service)? An exploit known to give remote SYSTEM with no login — the SMBv1 family behind EternalBlue is the classic example ([EternalBlue](../../../adversary/eternalblue-smbv1.md)) — goes up.
2. **Did it work?** If the target is patched against that exact vulnerability, lower it slightly: someone dangerous is attacking, but hasn't succeeded *yet*. Don't know the patch state? Look at what the host did **straight after** the attempt.
3. **Is there evidence of what comes next?** A new process, a new service, an outbound connection to a strange address, a new account — any of these right after the exploit means it probably worked.
4. **What type of asset?** An internal server is the worst case: the attacker is past the perimeter and going for valuable data. A laptop with no sensitive access is lower. An old exploit against a DMZ web server is internet background noise unless it shows signs of success.
5. **Where is it?** Even inside, subnets rank differently: production servers and manufacturing/OT ≫ test networks.
6. **Who is the user?** Admins and people with sensitive access — engineers, scientists, finance, executives, and the help desk (broad reset and admin rights) — first.

### Applying the six questions { #same-stage-example }

Four exploit alerts from the same hour:

| Alert | Target | Q1 gives | Q2/Q3 worked? | Q4–Q6 asset / place / user | Rank |
| --- | --- | --- | --- | --- | --- |
| E1 SMBv1 remote code execution attempt | KL-FIN-DB01 (10.30.8.21) | SYSTEM, no login | Patch state unknown; **outbound 443 from the server 40 s later** | Tier-0 database, production finance subnet | **1** |
| E2 Same SMBv1 exploit | KL-TEST-07 (10.70.1.7) | SYSTEM | Patched (inventory says so); nothing after | Test lab, no data | 3 |
| E3 Old web framework RCE attempt | KL-WEB02 (DMZ) | Web-service user | Response `404`, nothing after | Public web, constant probing | 4 |
| E4 Browser exploit attempt | KL-WS-0219, user `a.chen` | User-level code | EDR shows no child process | Laptop, but `a.chen` is a **payroll** officer | 2 |

E1 wins on every question: maximum access, a sign of success, the most valuable asset. E4 beats E2 only because of the user — a payroll officer can move money, so even user-level access is valuable. E2 and E3 can wait, but they aren't closed: E2 means someone inside can reach the test lab, which is worth asking about once E1 is handled.

## Worked example 2: six exploit scenarios { #exploit-scenarios }

Six descriptions, deliberately short. With only this, which one would turn into serious damage fastest?

**S1 — Log4Shell exploit string sent to a DMZ web server.** Log4Shell (CVE-2021-44228) let an attacker make a vulnerable Java logging library fetch and run code just by getting a crafted string logged — so it can mean full control of the server. But: a patch has existed since December 2021, the server is in the **perimeter network**, where you expect constant random attacks, and you hopefully patched it. **If patched, fairly low.** Check: did the server make an outbound LDAP/RMI/DNS lookup to the attacker's address right after (the tell that the lookup was triggered)?

**S2 — exploit kit against a user's browser.** An exploit kit is a web page that probes your browser and fires an exploit that fits ([exploit kits](../http-analysis/exploit-kits-practice.md)). Modern browsers run page code in a **sandbox** with restricted rights, so a single exploit usually ends with very limited access — at best the same rights as the user. Chains of several exploits can escape the sandbox, but that is rare. Users shouldn't be admins on their daily account. **Relatively low** in this list (**T1189 Drive-by Compromise**, **T1203 Exploitation for Client Execution**).

**S3 — Zerologon attempt against a domain controller.** Zerologon (CVE-2020-1472) abused a flaw in the cryptography of the Netlogon protocol so that an attacker with **network access to a DC** could set the DC's own machine-account password to empty — and from there take over the domain in minutes. **This is the clear top priority**, for two reasons: the exploit itself is devastating, and it tells you about the past — to send it, the attacker had to **already be inside**, find the domain controller, and stage tools. They're attempting to take everything. (**T1210 Exploitation of Remote Services**, followed by **T1003.006 OS Credential Dumping: DCSync** in typical use — see [DCSync](../../../adversary/dcsync.md).)

What it looks like on the DC's Security log — **4742** ("A computer account was changed"):

```
Event ID 4742  Computer: KL-DC01   2026-11-23 09:41:12
  Subject:          Security ID  ANONYMOUS LOGON
                    Account Name ANONYMOUS LOGON
  Computer Account That Was Changed:
                    Account Name KL-DC01$
  Changed Attributes:
                    Password Last Set  11/23/2026 9:41:12 AM
```

- **4742** fires on a DC whenever a computer account object is changed (when "Audit Computer Account Management" is on). Machines change their own password regularly, so 4742 by itself is normal.
- `Subject … ANONYMOUS LOGON` — the change was made by an **unauthenticated** session. A real password change is made by the computer account itself (`KL-DC01$`). Anonymous is the Zerologon fingerprint.
- `Account Name KL-DC01$` — the account changed is the **domain controller's own** machine account. If that password is reset, the DC can break its own replication — and the attacker now knows the password.
- `Password Last Set` — the attribute that changed.

Patched DCs also log Netlogon events in the **System** log when a device tries the vulnerable (non-secure) channel: **5829** (a vulnerable connection was *allowed*, during the compatibility phase) and **5827/5828** (a vulnerable connection was *denied*, for a machine or trust account). A burst of 5827 on an enforced DC means somebody tried Zerologon and was stopped — still a sign of an attacker inside.

**S4 — a planted USB stick plugged in.** Hard to predict on purpose: the damage depends on **who** plugged it in. Most employees are not administrators, so statistically it probably doesn't give dangerous privileges straight away — but plug it into an admin's machine and the story changes. (**T1091 Replication Through Removable Media**, or **T1200 Hardware Additions** for "keyboard-emulating" devices.) Windows can record **6416** ("A new external device was recognized by the system", with the device ID and class) when Plug and Play auditing is on — useful to tie the time to a user and host ([services, tasks and USB](../important-events/services-tasks-usb.md)).

**S5 — password guessing against an external HR website.** A trick entry: this isn't an exploit at all. Either the attacker gets in or doesn't — but even if they do, an HR portal doesn't give them a command line or a way to run malware directly (**T1110.001 Brute Force: Password Guessing**, or **T1110.003 Password Spraying** when one password is tried across many accounts). So it is the **least immediately dangerous** route to privilege escalation in this list. However, once in, the attacker can use what they find — bank details, org charts, who reports to whom — for tailored phishing or payroll fraud. *(See the [Caution] box below: in 2026 the answer depends on whether that portal uses your single sign-on.)*

**S6 — macro document sent to the help desk.** Similar to S2: Word runs as the user, so whatever the macro does runs with the **user's** rights — if they aren't admins, the attacker gets user-level access (**T1566.001**, then **T1204.002 User Execution: Malicious File**). **[Supplement]** But look at the *recipient*: help-desk staff often have rights to reset passwords and admin access to many workstations (see [sensitive users](exfil-destruction-sensitive.md#enrichment)). "User-level" on a help-desk account can be far more than on a warehouse clerk's. Add to that the 2022 change where Office blocks macros in files from the internet by default, and S6's real priority depends on the account and whether the macro could run at all.

**The order:** S3 clearly first. Then S6 or S4 depending on who is involved (help desk / admin). Then S2, S1 (if patched), and S5 last for immediate damage — while noting S5's later fraud risk.

## Unique alerts: long-tail analysis { #unique-alerts }

Another way to choose where to start: **the alert with the fewest hits.** The idea is simple. Whatever happens most often in your environment is, almost by definition, *normal* for it — so it's rarely the attack. Something that has **never fired before** is new, and new behaviour is where an attacker shows up: a determined intruder doing things that have never been done on your network should trigger rules that have never triggered. This is called **"least frequency of occurrence"** or **long-tail analysis**. It is an anomaly-focused technique built on the fact that alert volumes follow a **Pareto-like** distribution — a small number of signatures produce the vast majority of alerts.

Let's build the view from an export of 90 days of alerts (`alerts_90d.csv`, one alert per line, signature name in column 3):

```
$ cut -d',' -f3 alerts_90d.csv | sort | uniq -c | sort -rn | head -4
 412933 KL POLICY DNS Dynamic Update from External Network
 188201 KL SCAN Inbound TCP Port Sweep
  91544 KL INFO TLS Session Ticket Reuse
  40312 KL POLICY Cloud Storage Client Detected
$ cut -d',' -f3 alerts_90d.csv | sort | uniq -c | sort -n | head -4
      1 KL POLICY Windows PE/DLL Download from Low-Reputation Domain
      1 KL EXPLOIT Kerberos Pre-Auth Downgrade Attempt
      2 KL MALWARE Unusual Beacon Interval to New Domain
      3 KL DNS TXT Record Response Larger Than 1KB
```

- `cut -d',' -f3 alerts_90d.csv` — split each line at commas (`-d','`) and keep only the third field (`-f3`), the signature name. (Real CSVs can have commas inside quoted fields; for those, use a CSV-aware tool, but the idea is the same.)
- `sort` — puts identical names next to each other, which `uniq` needs.
- `uniq -c` — collapses each run of identical lines to one line and **prefixes the count**.
- `sort -rn` — sorts by that number, **n**umerically and **r**eversed (biggest first). `head -4` shows the top four.
- The second command uses `sort -n` (smallest first) to show the **tail**.

How to read the two ends:

- **The head** is where tuning work lives. 412,933 "DNS dynamic update from external network" alerts in 90 days isn't an attack — this kind of rule commonly fires when a DNS server or DHCP setting is misconfigured, and a quick search of the rule's documentation usually confirms it is a classic false positive. Fix the configuration or tune the rule.
- **The tail** is where you look for trouble. "Windows PE/DLL download from a low-reputation domain" is labelled *POLICY* and looks dull. But if your policy is "users don't download executables", and you investigate the one hit and find the file came from a domain with no history, this single policy alert can lead you **straight to an infection**.

!!! warning "Counting depends on the rule"
    Long-tail analysis doesn't always work cleanly, because rules count differently. Some fire **once per connection**, some on **every matching packet**, some are **thresholded** ("alert once per 60 s per source"). A single attack can therefore show as 1 hit or 4,000. Before trusting a count, know how that rule counts — and consider counting **distinct hosts** (`cut -f3,5 … | sort -u`) rather than raw hits.

## Lower-priority alerts: what can usually wait { #lower-priority }

Every environment has a steady background of alerts that are noise or accidents. They're **low fidelity**: a single condition that *could* be bad but is usually innocent. At low numbers you can't tell an advanced attacker from a mistake without a big investigation that finds nothing 99.99% of the time.

| Alert type | Why it's usually low | When it isn't |
| --- | --- | --- |
| External port scanning | The internet scans everyone, constantly | A scan from an **internal** host; a scan followed by an exploit that gets a response |
| Most policy violations | People break policy by accident all the time | A policy alert that is also rare and points at a bad domain (the long-tail example) |
| Failed logins | People mistype passwords | Clearly excessive, many accounts from one source, or **failures followed by a success** |
| Unauthorised access attempts | Someone clicks a share they can't open | Repeated, against sensitive data, by a service account |
| "Malicious IP" matches | IP lists are noisy: shared hosting, CDNs, cloud, recycled addresses | Combined with other signals (beacon pattern, new domain, odd process) |

**General rule:** if it happens **all the time** (scanning, policy), **by accident** (failed login, access denied), or rests on **low-fidelity data** (IP matches) — don't put it first.

### Excessive failed logins: misconfiguration or brute force? { #failed-logins }

The one in this list that *can* become urgent is a flood of failed logins against one server. Before calling it an attack, **rule out a misconfiguration** — it's very common. Windows logs failures as **4625** ("An account failed to log on"). Two short samples:

```
Event ID 4625  Computer: KL-APP03
  Account Name: svc_scan     Logon Type: 3
  Failure Reason: Unknown user name or bad password.
  Status: 0xC000006D   Sub Status: 0xC000006A
  Workstation Name: KL-MFP-2F   Source Network Address: 10.20.2.40
  (repeats every 300 s since 2026-11-20 14:00)

Event ID 4625  Computer: KL-RDS01
  Account Name: admin / administrator / backup / scan / test / j.moreno ...
  Logon Type: 3
  Status: 0xC000006D   Sub Status: 0xC0000064 (most) / 0xC000006A (some)
  Source Network Address: 203.0.113.61
  (3,140 events in 25 minutes, 410 distinct account names)
```

- **4625** fires on the machine where the logon was attempted, every time a logon fails. Attackers trigger it when they guess passwords; admins trigger it when they forget to update a saved password. ([logins](../important-events/logins.md) covers it in depth.)
- `Logon Type: 3` — a **network** logon (SMB, for example). Type 10 would be RDP, type 2 at the keyboard.
- `Sub Status 0xC000006A` — **the account exists, wrong password**. `0xC0000064` — **no such user**. Many `0xC0000064` = someone guessing account names.
- First sample: **one** account, **one** source (a multifunction printer `KL-MFP-2F`), a perfectly regular **every 300 seconds** since the day the `svc_scan` password was changed. That's a device with an old saved password — a misconfiguration. Fix the printer's scan-to-folder setting; and note that it can lock the account out (**4740** "A user account was locked out").
- Second sample: **hundreds of different names**, mostly non-existent, from one **external** address, thousands of attempts in minutes. That's brute force / spraying (**T1110**). Then the key question: is there a **4624** (successful logon) from 203.0.113.61 afterwards? If yes, this jumps to the top of the queue.

## The triage card { #summary }

There is no rule that works 100% of the time, but these four questions, asked in order, will rank almost any queue — and the more you use your tools and know your environment, the faster your intuition gets.

```
TRIAGE CARD — ask for each alert (or group of linked alerts)
1. How far has it progressed?          recon < delivery < exploit < install/C2 < lateral < goal
2. Exfiltration, destruction, or evidence deletion (or preparation for them)?   → jump the queue
3. Could it be targeted?               alert name, target asset, detection family, context, threat intel
4. Is it unique / unusual here?        lowest count, never seen before, rare in the world
Then: who/what is the target? (asset tier, subnet, user role)  → final order
```

- Line 1: post-exploitation is always more important than pre-exploitation.
- Line 2: actual or prepared exfiltration or destruction — and **deleting logs** (`wevtutil cl`, 1102 "The audit log was cleared"), which only happens after the attacker has done something worth hiding — goes straight to the front ([log clearing](../../../adversary/impair-defenses-log-clearing.md)).
- Line 3: targeted attackers jump the line because they adapt and persist. Threat intelligence often helps decide whether a malware family or infrastructure belongs to a targeted group.
- Line 4: listing all alerts over a long period and reading the *bottom* reveals attacks you'd otherwise overlook.

Once you've chosen the most pressing alert, the next job is **validation** — deciding whether it's real. That sounds simple, but how our perception and memory work, and how SOC pressure interacts with them, makes it easy to get wrong. That's the next section.

## The 2026 view { #trends }

!!! success "[2026 Current] Still valid"
    Reading alerts as kill-chain stages, letting counts adjust (not decide) the meaning, ranking same-stage alerts by access gained, success, asset, location and user, long-tail analysis of rare alerts, and knowing which alert types are mostly noise — all of this is still exactly how good analysts work a queue. Zerologon and Log4Shell remain in CISA's Known Exploited Vulnerabilities catalogue and still appear in scanning and in unpatched environments, so the S1/S3 reasoning still applies. The 4742 / Netlogon 5827–5829 and 4625 sub-status reading is unchanged.

!!! info "[Changed] What has changed"
    - **IDS engines and rulesets.** Talos stopped publishing rules for older Snort 2 versions in 2024 and recommends Snort 3; Emerging Threats still publishes ET Open/ET Pro for Suricata and supported Snort versions. Most network detection today is Suricata or Zeek, often inside an NDR product — the alert anatomy above (`eve.json`) is what you will usually see.
    - **Entity- and risk-based queues.** Many SIEM/XDR platforms now group alerts into incidents per host or user and add risk scores, so the "queue" is often already partly linked. Your judgement on stage, asset and user still decides the order inside that list.
    - **AI triage agents.** Vendors now sell AI "SOC agents" that read alerts and propose verdicts. Gartner (2026) predicts that by 2028 about 70% of large SOCs will pilot them for Tier 1/2 work but only about 15% will see measurable improvement without structured evaluation, and the SOC-CMM 2026 survey found only about 10% of SOCs rate the value they get from AI as excellent. Useful for enrichment and summaries; the ranking logic on this page is what you should check their output against.
    - **Macros are not the main Office route any more.** Since Microsoft began blocking internet macros by default (2022), attackers moved to LNK, ISO/IMG, HTML smuggling, OneNote and "paste this command" lures. A macro alert on its own is now less likely to run, but the *recipient* logic of S6 applies to every such lure.
    - **ATT&CK v19/v20.** Technique IDs used here are unchanged; defence-evasion techniques such as T1027 now sit under the Stealth tactic (TA0005) since v19 (April 2026).

!!! warning "[Caution] Wrong or risky to do the old way"
    - **"Password guessing on an external portal is lowest priority" is often wrong now.** If that portal signs in through your **single sign-on** or a cloud identity provider, a correct guess is a working identity for email, files and VPN. Treat spraying against SSO-backed apps as identity compromise risk, check MFA results and **successful** sign-ins from the same sources, and watch for MFA-fatigue prompts.
    - **Don't auto-close the "low-priority" classes without sampling.** Excessive failures, internal scans and rare policy alerts are exactly where real incidents hide; let automation close the bulk, but review a sample and anything with a follow-on success.
    - **Don't trust raw counts across rules.** Per-packet rules inflate, thresholded rules deflate; count distinct hosts and know your rules.
    - **"Patched, so lower" assumes your inventory is right.** Verify patch state (or the post-exploit behaviour) before you lower an exploit alert on an important server.
    - **Don't let an AI agent's verdict replace the triage card.** Check that its reasoning covers stage, target and rarity — not just the signature's severity.

## Practice questions { #quiz }

### Question 1

Rank these three and explain: (a) `KL DNS Query to Known Phishing Domain` ×1 from a laptop; (b) `KL DNS Reply - Known Sinkhole Address` ×35 from the same laptop over two hours; (c) `KL SCAN Inbound SSH Brute Force` ×6,000 against the DMZ jump host, all failed.

??? success "Answer and explanation"
    **(b) first, (a) second, (c) last.**

    - **(b)** 35 sinkhole replies over two hours = a program on the laptop keeps calling a C2 domain that has been taken over. That means **installation already happened** (C2 stage), and the malware may switch to a live fallback domain at any moment. Isolate / investigate the laptop.
    - **(a)** A single phishing-domain lookup could be the same infection's origin (a click) — check the timing against (b). On its own it's delivery stage and may have failed.
    - **(c)** Internet SSH guessing against a DMZ host is constant background, and every attempt failed. Confirm there's no successful login from those sources and leave it — unless the jump host accepts passwords at all, in which case fix that.

### Question 2

You have four exploit alerts at the same stage. Which six questions do you ask to order them, and why does an exploit against a domain controller tell you something about the *past* as well as the future?

??? success "Answer and explanation"
    The six questions: **what does the exploit give** if it works (admin, user, crash), **did it work** (patch state), **what happened right after** (new process, service, outbound connection, account), **what type of asset** (internal server, DMZ, laptop), **where** (production/OT vs test), and **who is the user** (admin, finance, engineer, executive, help desk).

    An exploit against a DC — such as Zerologon — needs network access to the DC, which is normally only possible from inside. So the attacker must already have **got in, explored the network, found the DC and staged tools**. That means several kill-chain stages have already passed: it's both a devastating exploit *and* evidence that the intrusion is far along. On the DC, check for **4742** with `ANONYMOUS LOGON` changing the DC's own `$` account, and Netlogon **5827–5829** in the System log.

### Question 3

Your long-tail view shows `KL POLICY Archive Upload to Personal Webmail` with 1 hit in 90 days, and `KL POLICY Cloud Storage Client Detected` with 40,000. A colleague says "both are just policy, skip them". What do you say, and what do you check before trusting the counts?

??? success "Answer and explanation"
    The 40,000-hit rule is a **tuning candidate** — something common and probably approved (or at least normal) is firing all the time. The **single** "archive upload to personal webmail" hit is at the long tail: rare, never seen before, and it describes a **possible exfiltration** step (archive + upload to an uncontrolled service, compare **T1567**). "Policy" in the name doesn't make it harmless; look at it first among the policy alerts — who, which file, how big, what else that host did.

    Before trusting the counts, check **how each rule counts** — per connection, per packet, or thresholded — and count **distinct hosts/users** rather than raw hits, so a single noisy machine doesn't make a rule look common.

## Related { #related }

- [Triage and defining "dangerous"](defining-dangerous.md) · [Spotting exfiltration, destruction, sensitive targets and targeted attacks](exfil-destruction-sensitive.md) — the previous pages
- [Logins (4624/4625)](../important-events/logins.md) · [Kerberos events](../important-events/kerberos.md) · [Services, tasks and USB](../important-events/services-tasks-usb.md)
- [Initial exploitation](../endpoint-attacks/initial-exploitation.md) · [Exploit kits](../http-analysis/exploit-kits-practice.md) · [Strings and packing](../file-analysis/strings.md)
- [DCSync](../../../adversary/dcsync.md) · [EternalBlue and SMBv1](../../../adversary/eternalblue-smbv1.md) · [Log clearing](../../../adversary/impair-defenses-log-clearing.md)

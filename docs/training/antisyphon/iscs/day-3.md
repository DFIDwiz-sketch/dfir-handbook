---
title: "Day 3 — EDR, Threat Emulation and Host Firewalls"
tags:
  - training
  - antisyphon
  - edr
  - sysmon
  - adversary-emulation
  - host-firewall
---

# Day 3 — EDR, Threat Emulation and Host Firewalls

<div class="dfir-meta" markdown>
**Course:** Information Security Core Skills · **Instructor:** John Strand (BHIS) · **Day 3 scope:** Sysmon lab review → Pass-the-Hash → EDR & defence in depth → threat emulation & Atomic Red Team → AI-written detections → BloodHound → gap-analysis lab → host firewalls
</div>

!!! abstract "Day 3 at a glance"
    Day 3 opens with the **Sysmon lab walkthrough** deferred from Day 2, then shows how **Pass-the-Hash** (logging in with only a hash) looks in the logs. It then argues that **EDR** is powerful but not enough on its own — overlapping controls **multiply** — and that you shouldn't trust vendor claims but **verify** with tools like **Atomic Red Team** (gap analysis). It closes with **host firewalls**: blocking workstation-to-workstation traffic to remove the whole lateral-movement category.

!!! note "Conventions"
    **💡 Note (added)** = my own addition beyond the lecture. **(reconstructed)** = something the instructor only showed on screen, written out generically. Labs that use offensive tooling are summarised by **what they demonstrate and the defensive / detection takeaways**; offensive command detail is omitted.

---

## 1. Sysmon lab walkthrough { #sysmon-lab-review }

### Lab recap { #lab-recap }

1. **Windows (victim):** disable real-time protection and the firewall, set the admin password to `password1234` (for the remote-logon part).
2. **Kali (attacker):** build a test payload `trustme.exe`, move it to the victim, wait for the callback.
3. **Install Sysmon on Windows**, then run `trustme.exe` → the attacker gets a remote session, dumps hashes and demonstrates a keylogger.

Building the file prints **"No encoder specified"** — meaning no encoding was done to evade AV, **on purpose**. The goal here isn't AV bypass; it's **reading Sysmon logs**.

John's numbers: the **payload is 354 bytes** but the **final file is ~73 KB**. That's Day 1's **stager**: the 354-byte piece just fetches the real body (the stage) from the attacker, and it's been stuffed inside a legitimate program, **Apache Bench (`ab.exe`)**, so the file is the size of that program.

### What Sysmon recorded { #sysmon-artifacts }

Event Viewer → Applications and Services Logs → Microsoft → Windows → **Sysmon → Operational**

| Sysmon event | What it showed | Meaning |
|---|---|---|
| **1** process create | `trustme.exe` ran; description Apache Bench; **OriginalFileName `ab.exe`**; run by administrator; hashes; **parent `cmd.exe`** | file name ≠ original name = a strong clue; launched directly from a command prompt |
| **22** DNS query | DNS lookups by `trustme.exe` | where it tried to call home |
| **8** CreateRemoteThread | `trustme.exe` created a remote thread in **LSASS** | **the hash-dump signal** — the moment hashes were pulled |
| **1** process create | `notepad.exe`, the Event Viewer snap-in, … | even the keylogger demo and analysis steps appear in time order |

**LSASS (Local Security Authority Subsystem Service)** handles logons and credentials and holds sensitive material such as password hashes in memory. Ordinary programs almost never create threads in it.

!!! note "💡 Note (added)"
    The classic credential-dumping detections are Sysmon **8** (remote thread into LSASS) and **10** (process access to LSASS). In event 10, the `GrantedAccess` value (e.g. `0x1010`, `0x1410`) shows whether memory-read access was requested. Detection queries: [LSASS dumping](../../../adversary/lsass-dumping.md).

---

## 2. Pass-the-Hash — logging in without the password { #pass-the-hash }

### Setup { #pth-setup }

John changes the admin password from `password1234` to a **very long one** — "uncrackable short of a quantum computer." Dumping hashes again shows the admin hash has changed.

```text
Administrator:500:aad3b435b51404eeaad3b435b51404ee:<NT hash>:::
```

- **`aad3b4…` (first part) = the LM (LAN Manager) hash.** Long obsolete and unused, so it's the **blank value** — identical for every account. Ignore it.
- **Second part = the NT hash.** Changing the password produced a completely different value.

### The key point — the hash is enough { #pth-core }

Even assuming the hash can never be cracked, the attacker can authenticate by **presenting the hash itself instead of the password**. John uses the same remote-execution approach (PsExec) as Day 1's spray lab, with the hash in place of the password, and opens a new session without knowing the password at all.

> However long and strong the password, if an attacker **gets the hash** they can log in as that user.

Day 1's NT-hash weakness — **no salt** — is why the hash effectively becomes "a key equivalent to the password."

!!! note "💡 Note (added) — the defence isn't a stronger password"
    - **Unique local admin passwords per host** — with **LAPS**, a hash taken from one PC doesn't work on another.
    - **Block lateral-movement paths** — the [host firewalls](#host-firewalls) section below (block SMB 445 between workstations).
    - **Credential protection** — Credential Guard, the Protected Users group, admin-account tiering.

    Artifacts and detection: [Pass-the-Hash](../../../adversary/pass-the-hash.md).

### What Pass-the-Hash looks like in Sysmon { #pth-in-sysmon }

The earlier attack was a **file execution** (`trustme.exe`); this remote one shows **heavily obfuscated PowerShell** authenticating, uploading and running the payload. The same attacker leaves **different log shapes depending on how they get in** — detection that only watches file execution would miss this.

!!! note "💡 Note (added) — traces of remote execution"
    - Security log **4624** — logon type **3** (network), authentication package **NTLM**
    - System log **7045** — new service installed (PsExec-style execution creates a service)
    - Sysmon **1** — PowerShell spawned by a service (parent `services.exe`) with a long encoded command line
    - PowerShell **4104** — the de-obfuscated script content

    Related: [PsExec & SMB](../../../adversary/psexec-smb.md) · [PowerShell cradles](../../../adversary/powershell-cradles.md)

### Is Metasploit used in real engagements? { #metasploit-in-practice }

Not much in professional pentests — many teams use **Cobalt Strike, Brute Ratel, Nighthawk**. But for **breadth of functionality** nothing matches Metasploit; its weakness is **team collaboration** (commercial tools are better at teamwork, AV evasion, BOF extensions).

> For an **internal team** doing day-to-day security work, Metasploit is **free** — and that's a huge advantage.

---

## 3. EDR — the most powerful control, but not one to rely on alone { #edr }

**EDR (Endpoint Detection and Response)** continuously watches process, file, network and registry activity on hosts and responds. In Back Doors & Breaches the **"Endpoint Security Protection Analysis"** card neutralises social engineering, compromised web servers, accessibility-feature abuse, logon scripts, lateral movement, privilege escalation, AD weaponisation, C2 and exfil — hence **4 resource points**. In real life EDR is also among the most expensive tools. (Moving into this section John also briefly name-checked **Velociraptor** as a tool BHIS loves.)

The problem is that many organisations now rely **almost 100% on EDR**.

> "To be completely honest with you, a lot of vendors lie" — guaranteeing they stop every attack with zero false positives.

### Defence in depth multiplies, it doesn't add { #defense-in-depth }

"We spent this much" or "we have EDR on 100,000 nodes" isn't defence in depth. Controls that **don't overlap** are merely **additive**; controls that **overlap on the same asset** are **multiplicative**.

If one host is covered by **AV/EDR + network security monitoring (Day 2's Zeek/RITA) + SIEM + UEBA**, one failing still leaves the others, and the attacker must evade **all of them at once** — the cost rises steeply.

> From nation-state work — landing on a system defended like that meant asking the command chain for permission to continue, and most of the time the answer was **"stop."** The risk of exposing very expensive TTPs was too high.

> **Make the attacker decide "this is too expensive"** — that's the goal.

Traditional deny-list AV is "pretty much garbage"; EDR finally lets you see systems **holistically**. A headline feature is the **process tree** (which process begat which), which matters again in memory analysis.

!!! note "💡 Note (added)"
    A chain like `WINWORD.EXE → cmd.exe → powershell.exe → rundll32.exe` is the classic "Word macro ran a command" phishing compromise. Sysmon event 1's `ParentImage` is the raw material for this tree; memory forensics uses the same idea (Volatility `pstree`).

### Choosing an EDR — AI is only as good as its data { #edr-ai-data }

> "We're a brand-new, scrappy EDR company with a completely proprietary AI no one has seen before." → John: **odds are it's crap**, because its training data just isn't big enough.

**CrowdStrike, Microsoft Defender (+ Sentinel) and SentinelOne** train on **billions of endpoints** and have the compute to crunch it — very hard for newcomers to match. John's recommendations: **CrowdStrike** and **Windows Defender + Sentinel** (the good tier costs money).

### Blue Spawn — an EDR stand-in for the lab { #bluespawn }

An open-source tool built by Virginia students for the **CCDC** collegiate cyber-defence competition when AV wasn't allowed in — they asked to write their own, and it worked. But its **MITRE coverage is low, so don't use it as a real EDR**. The lab's point is to learn **how you should test your EDR**.

---

## 4. Trust but verify — threat emulation { #trust-but-verify }

Don't just trust vendor marketing — but it's **not all the vendor's fault**. **Configuration** can cripple a product:

- **A rule that globally allows PowerShell everywhere** — dumb, but common
- **EDR deployed on 90% of the environment** — the remaining **10% is a big 10%**

The answer is **continuous validation of security controls** — BHIS's SOC constantly checks its detection stack is executing as expected with the coverage expected.

### Emulation vs simulation { #emulation-vs-simulation }

| | Simulation | Emulation |
|---|---|---|
| How | **a series of scripts** imitating attack behaviour | **one binary + a C2 server** behaving like real malware |
| Example | **Atomic Red Team** | Caldera agents, Metasploit, … |
| Level | entry | further down the pipeline |

John: "honestly it doesn't make that much difference — do both."

**Tools:** **Caldera** (MITRE's adversary-simulation environment — deploy agents and exercise ATT&CK techniques), **Infection Monkey**, **Atomic Red Team** (Red Canary — small per-technique tests showing what got detected; this course's main lab tool).

!!! warning "Test in alert-only, non-blocking mode"
    Caldera **publishes the AV signatures for its own binaries** to prevent abuse, so any AV nails it. And most simulation tooling reproduces attacks with **PowerShell scripts** — if your EDR blocks PowerShell outright, none of the remaining tests run. Evaluate EDR in **alerting, non-blocking** mode so you learn exactly what it detects and misses.

### Don't write detections too specifically { #signature-specificity }

Atomic Red Team shows each test's general command form and the concrete command with inputs (e.g. a `regsvr32` test). A lazy detection engineer who pastes the **entire command string** — including the full Atomic Red Team path — gets a rule that:

- fires **every** time someone runs Atomic Red Team, but
- **never** fires on a real attack or pentest, because no attacker uses that exact path.

Instead, **turn the variable parts into variables and match the invariant combination** — here, "`regsvr32` used **together with** `/s` `/u` `/i:` and `scrobj.dll`," case-insensitive.

!!! note "💡 Note (added)"
    This technique is the well-known **Squiblydoo** (MITRE **T1218.010**, Regsvr32) — using the signed `regsvr32.exe` to run a remote scriptlet. See [LOLBins](../../../adversary/lolbins.md).

### Using AI to write detections — and what humans must do { #ai-detections }

John asks free ChatGPT: "please create a Sigma alert based on the following detect." **Sigma** is the shared detection-rule language you write once and convert to many SIEMs.

```yaml
title: Suspicious Regsvr32 Scriptlet DLL Execution
status: experimental
description: Detects suspicious use of regsvr32 with scrobj.dll
references:
  - https://attack.mitre.org/techniques/T1218/010/
author: OpenAI
logsource:
  category: process_creation
  product: windows
detection:
  selection:
    Image|endswith: '\regsvr32.exe'
    CommandLine|contains|all:
      - 'scrobj'
      - '/i:'
  condition: selection
falsepositives:
  - Legitimate administrator software registration activity
level: high
```

*(reconstructed — the on-screen rule written out generically)*

- **`status: experimental`** — still being trialled.
- **`references`** — the ATT&CK technique it's based on.
- **`author: OpenAI`** — the AI credited itself, which made John laugh.
- **`logsource`** — Windows **process creation** (Sysmon 1 or Security 4688).
- **`Image|endswith: '\regsvr32.exe'`** — path **ends with** `regsvr32.exe`, so it matches wherever it's run from.
- **`CommandLine|contains|all`** — the command line contains **all** listed values.
- **`condition: selection`** — alert when the above matches.
- **`falsepositives`** — "legitimate admin software registration"; John has seen legitimate software use this same technique.

ChatGPT avoided the over-specific trap and wrote a **generalised** rule; John also had it produce **Elastic** and **LimaCharlie** versions.

**So what do humans do?** Someone answers "tune" — John: **"before we tune, we have to test."** BHIS's order:

1. **Draft** — AI or an analyst writes the rule.
2. **Back-test on historical data** — BHIS's **Detection Forge** asks "how many times would this have fired?" If it's **100,000**, you have tuning to do; rules that spew false positives make people dislike you.
3. **Tune** — bring the volume down.
4. **Test against a live attack** — fire it with **Atomic Red Team** in a sandbox and confirm it triggers.

> Test **both directions**: history ("not too noisy?") and a current attack ("does it actually fire?").

!!! note "💡 Note (added) — the back-test idea in Splunk"
    Translate the rule into SPL and run it over a past window to count hits:

    ```spl
    index=* EventCode=1 Image="*\\regsvr32.exe" CommandLine="*scrobj*" CommandLine="*/i:*"
    | timechart span=1d count
    ```

    `EventCode=1` is Sysmon process creation; `Image="*\\regsvr32.exe"` keeps paths ending in regsvr32.exe; the two `CommandLine` terms keep only command lines containing **both** `scrobj` and `/i:` (space-separated terms are ANDed). `timechart span=1d count` counts per day as a time chart — hundreds a day means the rule needs tuning.

**Nervous about running these tools?** Metasploit and Atomic Red Team **don't** run rampant through your environment — they run **specific test cases on a specific host**.

---

## 5. BloodHound — paths to Domain Admin { #bloodhound }

**BloodHound** (SpecterOps) enumerates **every path from a standard user to Domain Admin**, for free.

1. The attacker lands on my PC (I opened a bad Word doc) — they are effectively **me**.
2. In many AD environments **any user can log on to any workstation** with their domain credentials.
3. The tool authenticates to **thousands of hosts** asking "am I admin here?" — no, no, no …
4. On the **15,000th** host, it finds admin rights.

**Why that host?** An accounting PC with a flatbed scanner whose software, for some stupid reason, needs **local admin** to run. So the help desk says "everyone on this team needs the scanner — **add Domain Users to local Administrators**. Who's ever going to find out?"

> **BloodHound answers that question** — and attackers find out very quickly with automated tools.

From there the attacker escalates, grabs **domain-level credentials** for services and other accounts, and moves to Domain Admin. Defenders should run this kind of testing too — looking at **the whole AD environment** through an attacker's eyes, not just one workstation.

!!! note "💡 Note (added)"
    BloodHound's collector (SharpHound) generates **bulk LDAP queries** to domain controllers and SMB session / local-group enumeration across hosts. On the detection side look for one account making **network logons (4624, type 3) to very many hosts** in a short window, and bulk LDAP from one client (e.g. Zeek `ldap.log`). The key defence: **never put Domain Users in a local Administrators group**.

### John on commercial tools and AI { #ai-augment }

Commercial emulation tools — **Scythe, AttackIQ, XM Cyber** — are good, but many pitch themselves as **full pentest replacements** ("you don't need pentests anymore"). John sees this as the wrong way to apply AI: bolting it onto the status quo and concluding "we need fewer pentesters and SOC analysts, we save money."

> The industry was **drowning** — in vulnerabilities, detections, SIEM and log analysis. Then AI arrived — **a chance to finally get ahead of attackers**. Instead, vendors immediately saw it as **"we can save money."**

The right frame is the **80/20 rule** — tools and AI cover **80% of the vulnerabilities with 20% of the effort**, so humans focus on what humans are good at: business context and attack paths unique to that environment. **AI augments; it doesn't replace.**

> **"The attackers have a vote."** — they use the same tools, **asymmetrically** faster.

The author of a recent Windows privilege-escalation zero-day (**BlueHammer**) has released more, Linux privesc bugs are piling up, and one vendor said it found them with AI. Vulnerabilities will scale very fast; organisations need to realise **what's coming down the wire now**.

**MITRE evaluations — "everyone's a winner":** after MITRE ATT&CK Evaluations, nearly every vendor claims victory. **Josh Lemon** built his own scoring and early results showed wide variation — e.g. McAfee 268, Carbon Black 259, RSA 78 — and he also tallied each product's **misses**.

!!! note "💡 Note (added)"
    The raw MITRE ATT&CK Evaluations results are public. Reading **misses and "detections after configuration change"** in the raw data beats vendor press releases.

---

## 6. Lab — Blue Spawn + Atomic Red Team and gap analysis { #bluespawn-art-lab }

Really two labs in one: **① run set techniques with Atomic Red Team and see what Blue Spawn catches**, **② hand-reproduce a new attack that has no test yet.**

> Blue Spawn **won't detect everything — that's the point.** The goal is **gap analysis**: find where the holes are.

### Setup { #art-setup }

Blue Spawn on the right (detections stream in live), PowerShell on the left; real-time protection off.

```powershell
# (reconstructed) install the Invoke-AtomicRedTeam framework plus the atomics test library
IEX (IWR 'https://raw.githubusercontent.com/redcanaryco/invoke-atomicredteam/master/install-atomicredteam.ps1' -UseBasicParsing)
Install-AtomicRedTeam -getAtomics

# load the module
Import-Module "C:\AtomicRedTeam\invoke-atomicredteam\Invoke-AtomicRedTeam.psd1" -Force
```

- **`IWR`** (`Invoke-WebRequest`) — fetch the install script.
- **`IEX`** (`Invoke-Expression`) — run it. The same command Day 2's Deep Blue CLI flagged in obfuscated payloads — used by legitimate installers and attackers alike.
- **`Install-AtomicRedTeam -getAtomics`** — framework plus the **test definitions (atomics)**.
- **`Import-Module ... .psd1`** — load it so `Invoke-AtomicTest` is available.

Answer **"Yes to All"** to the PowerShell YAML module prompts. (One Atomic Red Team maintainer is **Carrie Roberts**, ex-BHIS and now an Antisyphon instructor.)

### Running tests { #art-tests }

```powershell
Invoke-AtomicTest T1547.004
```

- **`Invoke-AtomicTest`** — run the tests for a technique.
- **`T1547.004`** — boot/logon autostart → **Winlogon Helper DLL** (persistence via the Winlogon registry values run at logon).

!!! note "💡 Note (added) — useful flags"
    - `-ShowDetailsBrief` — list the tests for a technique
    - `-CheckPrereqs` — verify prerequisites
    - `-Cleanup` — **revert** the test's changes (always run afterwards)

| Test | Blue Spawn result | Lesson |
|---|---|---|
| **T1547.004** (Winlogon Helper DLL) | detected immediately | we **now know** this detection works |
| **T1543** (create/modify system process — services) | **8** technique detections (with the matched string) / generic "modifying a service" item: **0** | when activity doesn't match a known pattern, EDRs raise a **medium** "something happened" alert → focus on **classified, technique-specific** detections |
| registry-key test | nothing at first, then a **burst a few seconds later** | **the lag itself is part of the test** |
| command-prompt test | registry detections "raining" in | — |

**Why the lag?** It's very common:

- Many EDRs **store and forward** endpoint events; under load the pipeline stalls, then catches up.
- **WEC/WEF** and **Elastic collectors** have been seen to get overwhelmed and pause.
- **Cloud services** are worse — Microsoft logs in particular can take **up to an hour** from event to your analysis platform.

> When judging "is our detection effective?", factor in **not just whether it fires but how late it arrives**.

!!! note "💡 Note (added) — measuring ingest lag in Splunk"
    ```spl
    index=* earliest=-24h
    | eval lag_sec = _indextime - _time
    | stats avg(lag_sec) AS avg_lag max(lag_sec) AS max_lag BY sourcetype
    ```

    `_time` is when the event **happened**; `_indextime` is when Splunk **indexed** it. `eval lag_sec = _indextime - _time` makes a new field with the difference in seconds, and `stats ... BY sourcetype` tabulates average and maximum lag per data type. A `max_lag` near 3600 means that source can arrive up to an hour late.

ATT&CK technique IDs change between versions, so the course provides a **crosswalk JSON** mapping old numbers to new.

### Ad-hoc emulation — what if there's no test yet? { #adhoc-emulation }

> A new attack drops. **Atomic Red Team has no test for it.** Management wants to know *now* whether you'd detect it; CISA has issued a warning.

You need the ability to do **custom ad-hoc adversary simulation** — reproduce the behaviour by hand. John reopens a remote session on the test VM (the same steps as before, done quickly) and tries behaviours one by one:

| Behaviour tested | Blue Spawn result |
|---|---|
| **Keystroke logging** (typing into Notepad) | **not detected** — a clear failed detect |
| **Registry persistence ①** (autorun key added) | **not detected** |
| **Registry persistence ②** (a different registry method) | **detected** |

(Keystrokes weren't captured because the payload ran via the PowerShell method this time — how you run it can change results.)

> **What does our EDR detect, and what does it miss?** — now you know **where to add detections**.

!!! note "💡 Note (added) — log sources to close the gaps"
    - **Registry autorun persistence** (MITRE **T1547.001**, Run keys etc.) — watch Sysmon **13** (registry value set) for `\CurrentVersion\Run`, `\RunOnce`. [Persistence](../../../adversary/persistence.md)
    - **Keylogging** (MITRE **T1056.001**) — keyboard-hooking APIs rarely show in default logs, so it leans on EDR behavioural detection or memory analysis — a **common blind spot**.

The VM ends up "brutalised," so John **destroys the lab and restarts it** — the surest way back to clean.

---

## 7. Host firewalls and stopping lateral movement { #host-firewalls }

Locking down host-based firewalls addresses essentially the **whole Lateral Movement column** of MITRE ATT&CK. The course philosophy again:

> Don't chase individual techniques — take out **whole categories** of attack.

The core concept is **segmentation** — down to the **host level** if at all possible — and the reason is the **Pass-the-Hash** shown earlier.

### "Getting compromised is acceptable. But…" { #acceptable-compromise }

> Getting compromised is **acceptable** — it's going to happen. Like death, taxes and brushing your teeth.

What's **not** acceptable: an attacker persisting **for months**, or pivoting from one host to the **whole environment in minutes**. **Host firewalls** (or **private VLANs**) can stop that.

**How attackers spread:** a client-side exploit or drive-by compromises one host → they want **lateral movement**, not one box → preferably using **built-in Windows protocols** (PsExec, pass-the-token, Remote Desktop, Pass-the-Hash) → take over the **whole domain**.

### Treat the internal network as hostile { #hostile-internal }

Turning on host firewalls means treating the internal network as hostile — "because it is." Set internal hosts' firewalls **as you would at a coffee shop**.

> It's absolutely insane that your systems are **more secure at a Starbucks** than on their own network.

You can go further and segment **between business units** too (host firewalls plus inter-unit segmentation).

| From | To | Allowed? |
|---|---|---|
| **servers, help desk, jump hosts** | workstations | **yes** (needed for admin / support) |
| **workstations** | workstations | **no** (no reason to talk) |

Now a compromised host can't reach its peers, and you get **overlapping fields of visibility** — if AV, EDR, NSM, UEBA or SIEM fails, two or three others pick up the slack. Use your commercial AV's built-in firewall, or Windows' own **`netsh advfirewall`** ("awful, but free," and **configurable via Group Policy**).

!!! note "💡 Note (added)"
    In practice, build inbound rules in GPO under **Windows Defender Firewall with Advanced Security**. Typical ports to block between workstations: **SMB 445**, **RPC 135** (+ dynamic RPC), **NetBIOS 139**, **WinRM 5985/5986**, **RDP 3389**. "Deny all, then allow only the management / jump-host ranges" is the clean pattern.

### Lab — Nmap before and after the firewall { #firewall-lab }

Run in the new lab environment (**antilab**). Get the Windows VM's IP, then scan it from the attacker VM.

**① Firewall off**

```bash
nmap 10.10.222.41
```

- **`nmap`** — a scanner that shows which ports are open on a target.
- **`10.10.222.41`** — the lab Windows VM (varies per environment).

```text
PORT     STATE SERVICE
135/tcp  open  msrpc
139/tcp  open  netbios-ssn
445/tcp  open  microsoft-ds
3389/tcp open  ms-wbt-server
5985/tcp open  wsman
```

**135** RPC · **139** NetBIOS session · **445** SMB file sharing · **3389** Remote Desktop · **5985** WinRM

**② Firewall on, scan again**

```cmd
netsh advfirewall set allprofiles state on
```

- **`netsh advfirewall`** — command-line control of Windows Firewall.
- **`set allprofiles`** — apply to **all profiles** (domain, private, public).
- **`state on`** — enable (`state off` disables).

The **RPC ports disappear** (the lab keeps allow rules for Terminal Services and WSMan to stay connected). John: with those ports open, **lateral movement is possible** and Pass-the-Hash works very well.

**③ Confirm with Pass-the-Hash**

- **Firewall off** → the remote session succeeds; dumping the hash and re-authenticating **with the hash** also works. "It doesn't matter how strong someone's password is — if I've got your hash, I can authenticate as you."
- **Firewall on** → the same attack tries port **445** and is **dead in the water**.

> Shutting down port 445 alone **severely restricts lateral movement** from that host — specifically **Pass-the-Hash-style** movement.

!!! note "💡 Note (added)"
    With Windows Firewall auditing on, blocked connections log Security **5157** (Windows Filtering Platform blocked a connection). But as John said on Day 2, firewall logging is noisy — in practice log only **meaningful rules** (e.g. workstation-to-workstation 445/135) or watch from the network side (internal↔internal SMB in Zeek `conn.log`). Related: [Pass-the-Hash](../../../adversary/pass-the-hash.md) · [PsExec & SMB](../../../adversary/psexec-smb.md).

### Firewalls aren't the end — preparing the Responder lab { #responder-prep }

On the same network an attacker can redirect a target's traffic with **ARP cache poisoning**, **LLMNR** or **WPAD** and capture its authentication — Day 1's **Responder**. That long-dead lab is back thanks to the new environment.

- MetaCTF → **Cloud Labs** → code **`antilab`** → Submit. **Two free lab hours every week** (the first "Free Lab Friday").
- The attacker VM moved **from Kali to Ubuntu** (more flexible for Docker / honeypot labs ahead; Kali's tools install easily on it). The Windows VM is **Windows Server 2025** (AD capable; nested virtualisation and Docker planned).
- Flow: run Responder on Ubuntu on interface **`ens5`** → in Windows File Explorer browse to `\\<Linux IP>` and enter `password` (lower-case) → Responder shows the **captured credentials** → then crack them.

The walkthrough was deferred to **Day 4 morning**, and John reposted an updated handout that includes the cracking step.

!!! note "💡 Note (added)"
    The fix is Day 1's: **disable LLMNR / NBT-NS**, **enforce SMB signing**, plus this section's **workstation-to-workstation blocking**. [LLMNR & NTLM relay](../../../adversary/llmnr-ntlm-relay.md)

---

## 8. From the AMA { #ama }

- **Does the old trick of swapping a logon-screen accessibility tool (Utilman, Sticky Keys `sethc`, Magnifier) for a command prompt still work?** → **Yes** — and notably you come in as **SYSTEM**. (This is the "accessibility features" item on the EDR card.)
- **Still using Kali?** → John is "old school" and likes purpose-built Kali, but BHIS testers increasingly use a **home-grown build**.
- **What next after this course?** → the next in the cycle, **Active Defense and Cyber Deception**.
- **Go-to cyber news?** → BHIS's internal team that constantly shares news (and a Teams room), plus **Simply Cyber's (Jerry) Daily Cyber Threat Brief**.
- **Best home antivirus?** → "Believe it or not, straight-up **Windows Defender** is about as good as you'll get."

!!! note "💡 Note (added) — detecting / preventing accessibility-feature abuse"
    MITRE **T1546.008**, typically used with direct disk access (physical access, boot media).

    - Check `C:\Windows\System32\` `sethc.exe`, `utilman.exe`, `osk.exe`, `Magnify.exe` **hashes against originals** (an original name of `cmd.exe` is conclusive)
    - Watch **Image File Execution Options** for a new `Debugger` value on those binaries (Sysmon **13**)
    - **Full-disk encryption** (BitLocker) prevents offline file swaps
    - `cmd.exe` spawned as a child of `winlogon.exe` at the logon screen (Sysmon **1**) is a strong signal

---

## Day 3 summary { #summary }

| Topic | Key point |
|---|---|
| Sysmon lab review | name ≠ original name (1), DNS query (22), remote thread into LSASS (8 = hash-dump signal) |
| Pass-the-Hash | a hash is enough to log in — defend with LAPS, lateral-movement blocking, credential protection |
| EDR & defence in depth | overlapping controls **multiply**; AI is only as good as its data |
| Threat emulation | trust but verify; test in **alert-only, non-blocking** mode; don't over-specify rules |
| AI-written detections | AI drafts; humans **back-test on history and test against a live attack** |
| BloodHound | standard user → Domain Admin paths; never make Domain Users local admins |
| Atomic Red Team lab | technique-specific vs generic alerts; factor in **log lag**; gap analysis |
| Host firewalls | block workstation-to-workstation → remove the lateral-movement category |

!!! quote ""
    EDR is powerful but not enough alone — multiply the attacker's cost with overlapping controls, and keep finding and closing detection gaps with Atomic Red Team and hand-built emulation. And stop hash-fuelled lateral movement as a whole category with host firewalls that block workstation-to-workstation traffic.

## References

- [Antisyphon Training](https://www.antisyphontraining.com/) · [Black Hills Information Security](https://www.blackhillsinfosec.com/)
- [Atomic Red Team](https://github.com/redcanaryco/atomic-red-team) · [Invoke-AtomicRedTeam](https://github.com/redcanaryco/invoke-atomicredteam) · [MITRE Caldera](https://caldera.mitre.org/) · [BloodHound](https://github.com/SpecterOps/BloodHound) · [Sigma](https://github.com/SigmaHQ/sigma)
- [MITRE ATT&CK — T1550.002 Pass the Hash](https://attack.mitre.org/techniques/T1550/002/) · [T1218.010 Regsvr32](https://attack.mitre.org/techniques/T1218/010/) · [T1546.008 Accessibility Features](https://attack.mitre.org/techniques/T1546/008/)
- Related: [LSASS dumping](../../../adversary/lsass-dumping.md) · [Pass-the-Hash](../../../adversary/pass-the-hash.md) · [PsExec & SMB](../../../adversary/psexec-smb.md) · [Persistence](../../../adversary/persistence.md) · [LOLBins](../../../adversary/lolbins.md) · [LLMNR & NTLM relay](../../../adversary/llmnr-ntlm-relay.md) · [Windows Event IDs](../../../basics/windows-event-ids.md)

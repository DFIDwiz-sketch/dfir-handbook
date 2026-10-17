---
title: "Day 1 — Allow Listing and Password Attacks"
tags:
  - training
  - antisyphon
  - application-allowlisting
  - passwords
---

# Day 1 — Allow Listing and Password Attacks

<div class="dfir-meta" markdown>
**Course:** Information Security Core Skills · **Instructor:** John Strand (BHIS) · **Day 1 scope:** compliance → application allow listing → password attacks → cracking
</div>

!!! abstract "Day 1 at a glance"
    Attackers get in two broad ways — **① executing malicious code** or **② obtaining passwords**. So Day 1 covers both: (1) using **application allow listing** to enforce "only run from allowed folders" and block initial code execution (AppLocker lab), and (2) how passwords fall to **spraying, Kerberoasting, network interception and offline cracking**, and the defences. As background, it also explains why AV gets bypassed (ghostwriting, LOLBins).

!!! note "Conventions"
    **💡 Note (added)** = my own addition beyond the lecture. The offensive lab steps are summarised at a high level here; the Korean [Day 1 page](https://DFIDwiz-sketch.github.io/dfir-handbook/ko/training/antisyphon/iscs/day-1/) has the fuller command walkthrough, and the mechanics of each attack live in the **Adversary** reference section linked throughout.

---

## 1. Compliance: mapping many frameworks efficiently { #compliance }

There are a lot of compliance frameworks — SOC 2, HIPAA, NIST 800-53, NIST 800-171, CMMC, New Zealand's NZISM and more. Many organisations must meet **several at once**, and producing separate evidence for each and cross-referencing them costs a great deal of time and money.

John's answer: **map to the CIS (Center for Internet Security) Controls first, then cross-map everything else automatically**, using **CIS Navigator**.

!!! example "Example — one CIS control covers several NIST items"
    **CIS 2.1 (Establish and maintain a software inventory):** record the title, publisher, initial-use date etc. of all installed software. Select NIST in CIS Navigator and this one control maps to:

    | Framework | Mapped items |
    |---|---|
    | NIST CSF | ID.AM-2 |
    | NIST 800-171 | 3.4.10 |
    | NIST 800-53 | CM-7, CM-8, MA-3 |

    So **meeting CIS 2.1 also meets those NIST items**. John calls this a **"Rosetta Stone"** that translates between frameworks.

CIS Navigator can **export the mapping to Excel**. Mark each CIS control you meet with an `X` and you can see your status against the other frameworks at a glance.

**Two ways to use AI**

1. **Evidence + gap analysis** — feed the spreadsheet to an AI: "we meet these CIS controls; produce documentation showing NIST CSF compliance." It writes the documentation and points out gaps.
2. **Map to attack techniques** — ask "because of how we implemented the CIS controls, which attack techniques have we neutralised?" — **translating "we're compliant" into "we stop these attacks."** John credits **AuditScripts** as the first to do this mapping systematically.

!!! note "💡 Note (added)"
    CIS Controls v8 has 18 controls, split by organisational maturity into IG1 (basic) to IG3 (advanced). Before putting compliance data into an AI, check your organisation's policy on data leaving the environment, and always verify AI-generated mappings against the source.

---

## 2. Application allow listing — the concept { #allowlisting-concept }

**Application allow listing** restricts **which programs are allowed to execute** on a host. Narrow what can run and you narrow the attacker's path in. People fear it because they think every application must be registered one by one — you don't have to (see [section 4](#allowlisting-how)).

### Why deny lists fail { #why-denylist-fails }

The opposite is a **deny list** ("block the known-bad list") — the traditional AV approach. Security expert **Marcus Ranum**, in "The Six Dumbest Ideas in Computer Security," named "enumerating badness." Two reasons: ① bad programs appear far faster than good ones, and ② bad code can hide inside good programs.

John's analogy: cave people passed on **lists of dangers** as stories — "don't eat the purple mushroom with yellow stripes, you'll die." That worked because **threats didn't change**. In cyber, **today's poisonous mushroom is tomorrow's sizzling filet mignon.** Threats keep changing, so deny-list thinking doesn't work.

### The reality: getting in is easy, what comes next is hard { #initial-execution }

In John's experience, **initial code execution** is still relatively easy. What security products are now good at catching is the *next* step — privilege escalation and lateral movement. So **blocking that first execution step** is the key job of allow listing.

---

## 3. How AV gets bypassed (the theory) { #av-bypass }

John explains bypass **theory** to make the point "don't put all your eggs in the AV basket" (not to teach bypassing). That's why this course's labs run with **AV turned off** — to observe malware executing and how allow listing stops it.

### 3-1. Ghostwriting { #ghostwriting }

**Background — AI-based AV looks at assembly patterns.** Assembly sits one step above ones and zeros. Every function starts (prologue) and ends (epilogue) in a similar way, so AI-based AV / vulnerability tools use those boundaries to **group code into functions**, then check for risky patterns (e.g. the inherently vulnerable `gets` function, or code that allocates memory as read/write/execute and runs from it).

!!! note "💡 Note (added) — read/write/execute (RWX) memory"
    Normal code regions are usually read+execute, data regions read+write. Regions that are all three are rare, which makes them a **clue to injected code**. The concept John said "we'll come back to" is central to memory forensics — see [Process injection](../../../adversary/process-injection.md) and [Memory: processes & injection](../../../memory/processes-injection.md) (Volatility `malfind`).

**Core idea — same result, different method.** John asks: "How do you make 4 from two 2s without adding?" → `2 × 2 = 4`, `2 − (−2) = 4`. Same result, but represented differently in binary. Assembly also has **many ways to do the same thing**, so an operator can rewrite instructions so they still do the same work while no longer matching the "clean pattern" the AI memorised. **XOR** is a favourite building block here, because any value XORed with itself is always 0 — a predictable anchor you can pad meaningless instructions in front of without changing behaviour. This whole-binary rewriting is "ghostwriting."

**Why is AI weak against this?** AI was trained on **human-written code**, so its idea of normal is "what code usually looks like." Where it must scan huge amounts of code quickly, deliberately scrambled code makes it **lose its context cues**.

### 3-2. LOLBins (Living Off the Land Binaries) { #lolbins }

Using **legitimate programs already on Windows** to run malicious code — e.g. `rundll32.exe` pulling down and running content from the internet, or the Windows Script Host running a script. Microsoft-signed, so less suspicious. But LOLBins still need **an initial foothold (code execution)** → which is why blocking first execution matters. More: [LOLBins](../../../adversary/lolbins.md).

### 3-3. Encoders and automation { #encoders }

- **Shikata Ga Nai** — a Metasploit encoder that avoids **bad characters** which break exploits (e.g. `\x00`, read as end-of-string) while changing the code's shape.
- **Unicorn** — makes this process easy to automate.

!!! quote ""
    What bypassed AV today may not tomorrow. AV bypass is more art than science. — so defenders should **assume** AV will eventually fail and add layers that restrict execution itself, such as allow listing.

### Learning tool — Back Doors & Breaches { #bdb }

BHIS's card game [backdoorsandbreaches.com](https://www.backdoorsandbreaches.com/). Almost every technique in the course is a card; the back lists **attacks it detects, defensive tools and lab links**. E.g. the "Endpoint Security Protection Analysis" card links AppLocker, Atomic Red Team and Caldera labs. 200+ labs, and browser-based competitive play.

---

## 4. How to implement allow listing { #allowlisting-how }

| Method | What it is | Where it fits |
|---|---|---|
| ① Register every executable | Most thorough but hard to maintain | Only fixed-purpose systems: kiosks, POS, VDI |
| ② Digital signature (publisher) | "Allow only programs signed by this publisher" | Trusted software vendors |
| ③ **Path (folder) based** ⭐ | "Only run from these folders" | John's recommended start — general workstations |

Malware **usually first runs** from the Downloads folder, the Desktop, or temporary internet files. Blocking execution there alone stops most initial code execution.

### AppLocker { #applocker }

Built into Windows. Restricts execution by path, hash, certificate or publisher. The **Default Rules** are three:

1. Anything in `Program Files` → allowed
2. Anything in `Windows` → allowed
3. **Administrators** → can run anything (the **lifeline** for recovery)

Everything else (Downloads, Desktop, root of C: …) is blocked.

!!! note "💡 Note (added)"
    **Why path rules work:** standard users normally **can't write** to `Program Files` or `Windows`, so attackers can't easily drop malware there. Conversely, user-writable sub-folders (e.g. `C:\Windows\Temp`) can become bypass routes, so in practice you block those exception paths too. **Current direction:** Microsoft now recommends **App Control for Business (formerly WDAC)** over AppLocker (AppLocker is maintained but gets no new features). The concepts are the same, so AppLocker is a fine way to learn them.

---

## 5. AppLocker lab (summary) { #applocker-lab }

The lab's shape is **① infect a victim VM with a test payload → ② block that execution with AppLocker** — doing the infection first makes it clear what you're blocking.

!!! warning "Lab assumptions — don't do this in production"
    The lab **disables AV and the firewall** on the Windows VM and sets an easy admin password, in the cloud lab (MetaCTF, browser RDP via Guacamole). On the Windows VM **don't refresh the browser** (after the admin password changes, Guacamole tries the old one and fails → you must Destroy and restart the VM). **Destroy Lab** when idle to save credits.

**① The attacker side (summary).** From the Kali VM you mount the victim's hidden admin share, generate a small reverse-connection test payload with `msfvenom`, start a Metasploit listener, and when the payload runs on the victim you get an interactive session and can, for example, dump password hashes. The point for a defender is only this: **the first execution happens from a user-writable location (Downloads/Desktop/temp), and the payload calls back outbound.** The full step-by-step is on the Korean page; the mechanics of each stage are in [PsExec & SMB](../../../adversary/psexec-smb.md) and [SAM & NTDS extraction](../../../adversary/sam-ntds-extraction.md).

**② Block it with AppLocker (defensive config).** In Local Security Policy → **Application Control Policies → AppLocker → Executable Rules**:

1. Right-click → **Create Default Rules** (the three rules above).
2. **Configure Rule Enforcement** → "Enforce".
3. **Services (`services.msc`) → Application Identity → Start** — AppLocker only works when this service runs.
4. Apply the policy immediately:

```cmd
gpupdate /force
```

Now running a program from outside the allowed folders (e.g. `nc.exe` in an `Introlabs` folder) is blocked:

> This program is blocked by Group Policy. For more information, contact your system administrator.

!!! warning "Don't use 'Automatically Generate Rules'"
    That feature hashes **every program in `Program Files`**. Very thorough, but a patch or update changes the hash and the program stops running. On a normal workstation this breaks things — it only fits fully locked-down **kiosks**. The takeaway: decide the **threat model and use case first**, then pick the rule style.

**Publisher exception.** For a program that must run from Downloads (e.g. PuTTY), create a new rule with condition **Publisher** → it will run from any folder because it's signed by the trusted vendor.

---

## 6. Password spraying { #password-spray }

| Type | Method | Result |
|---|---|---|
| Password **guessing** | many passwords against one account | easily stopped by **account lockout** |
| Password **spraying** | **one password** against many accounts | each account only fails 1–2 times, so it **evades lockout** |

The attacker collects a staff list (user IDs), then sprays a password like a **season+year** (`Winter2025`) or a **local sports team + number** across every account. **Larger orgs are more at risk** — with 10,000 users, someone is bound to use a weak password. John: this gets into roughly **80% of organisations**.

This technique (MITRE ATT&CK **T1110.003**) was added at John's request — initially refused ("not a pentester technique") until BHIS showed nation-state actors using it in real cases.

!!! note "💡 Note (DFIR view) — what it looks like in logs"
    Password spraying shows in the Windows Security log as **Event ID 4625 (failed logon)** across **many accounts, 1–2 each, in a short window** — a **horizontally spreading** pattern (vs. guessing = one account failing repeatedly). A success is followed by **4624 (successful logon)** for that account; over SMB the logon type is **3 (network)**. Event IDs overall: [Windows Event IDs](../../../basics/windows-event-ids.md).

### Lab (summary) { #spray-lab }

On the victim a batch script creates ~200 accounts (simulating a known staff list); the Security log is cleared for a clean view. From Kali, Metasploit's `auxiliary/scanner/smb/smb_login` tries **one** password (`Winter2025`) across the user list; a green line marks a hit. The recovered credential is then used (via `psexec`) to get a session — **real access from a single weak password, no exploit needed**. Mechanics: [PsExec & SMB](../../../adversary/psexec-smb.md).

### Why MFA isn't a complete fix { #mfa-gap }

MFA cuts the risk but doesn't zero it. Many orgs have **hidden APIs/services** with no MFA, and attackers find the ones left out of **Conditional Access**.

!!! note "💡 Note (added)"
    A common gap is **legacy authentication** — old mail protocols (IMAP/POP3/SMTP auth) don't support MFA, so Microsoft recommends blocking legacy auth.

---

## 7. The thing that matters most: length { #password-length }

John is emphatic: **length matters most.** Each extra character adds **more than double** the combinations an attacker must crack — require 5 and they only crack all 5-char strings; require 6 and they must crack all 5s *and* all 6s.

!!! note "💡 Note (added)"
    More precisely, each character multiplies the space by the **character-set size** — ~10× for digits only, ~95× for upper+lower+digits+symbols. John's point ("length is decisive") holds.

**A 1985 standard still lingers.** John shows the US DoD 1985 password guide ("Green Book"), built on "an attacker guesses 8.5 times per minute" (a 300 bps modem). Today GPUs do **billions per second**, so that logic would say "change your password every second." Yet **PCI DSS** required only a **7-char** minimum until a few years ago.

!!! note "💡 Note (added)"
    PCI DSS 4.0 raised the minimum to 12 (mandatory from 2025). Current NIST guidance: drop forced periodic rotation, increase length, and check against breached-password lists — the opposite of 1985.

**Real constraint:** old systems (Solaris SPARC, mainframe RACF) sometimes can't handle 9+ characters — often fact, not laziness.

**Is SMS useless?** It's weak to **SIM swapping**, but John says check your **threat model** first — if you're not a nation-state target, **SMS still beats nothing** (an app or FIDO2 is better).

---

## 8. Service accounts and Kerberoasting { #kerberoasting }

**Service accounts** (used by programs like SQL / backup, not people) are often high-privileged, not locked out, with non-expiring passwords, and ignored by security — John's **"security forgets them, hackers love them."**

**Kerberoasting** (discovered by Tim Medin of Red Siege): ① any domain user can request a service ticket; ② the DC returns it **encrypted with the service account's password**; ③ the attacker takes it away and **cracks it offline**. Because step ③ is **offline**, there's **no account lockout and no failed-logon record** — a weak/simple password falls fast.

!!! note "💡 Note (DFIR view)"
    Detect via DC **Event ID 4769 (Kerberos service-ticket request)** — especially encryption type **0x17 (RC4)** tickets requested for many services by one user. Defend with **long (25+) service-account passwords** or auto-rotating **gMSA**, and enforce AES where possible. Full detection queries and artifacts: **[Kerberoasting reference](../../../adversary/kerberoasting.md)**.

---

## 9. Intercepting credentials on the network { #network-cred-theft }

With an attacker on the same network, a victim host can be tricked into **sending its credentials to the attacker**. The relevant protocols: **LLMNR, NBT-NS, mDNS** (Windows shouting "who has this name?" to the whole network when DNS fails) and **WPAD** (automatic proxy discovery).

Mistype a server name and the host shouts to the network; the attacker answers **"that's me!"**, the victim trusts it as the real server and authenticates automatically, and the attacker captures the **password hash**. **Responder** automates this (fake web/SMB/Kerberos/SQL/FTP/IMAP/POP/SMTP/DNS servers), often paired with **ARP cache poisoning**.

!!! note "💡 Note (added)"
    Defend by disabling **LLMNR and NBT-NS** via Group Policy (usually no business impact) and enforcing **SMB signing** (stops relaying the captured auth to another server). Full artifacts/detection: **[LLMNR & NTLM relay](../../../adversary/llmnr-ntlm-relay.md)**.

**Other tools:** **CredKing** (AWS Lambda rotates the source IP per request to dodge "many failures from one IP" blocks); **Evilginx** (an adversary-in-the-middle phishing proxy).

!!! note "💡 Note (added)"
    AiTM phishing like Evilginx lets the user complete MFA, then **steals the session cookie** to bypass it. Ordinary MFA struggles here; **FIDO2 / passkeys** (phishing-resistant, bound to the real site) stop it.

---

## 10. Password managers and PAM { #pwmgr-pam }

John recommends **password managers** but pick a trustworthy one. In the **LastPass** breach, some data turned out to be encrypted in **AES ECB mode** — where **identical content always yields identical ciphertext**, so even without reading values you can see **which entries reuse the same one** (revealing password reuse).

**PAM (privileged access management)** continuously **rotates** admin passwords and makes you "check them out" (Microsoft **LAPS** makes each host's local admin password unique and auto-rotated). John's worry: as these move to the cloud they become a **single point of failure** — one vault breached is game over.

!!! note "💡 Note (added)"
    The "remote-support vendor breach that led to a government agency" John referred to is understood to be the late-2024 **BeyondTrust** compromise that was used to reach the **US Treasury**.

---

## 11. Password cracking lab (summary) { #cracking-lab }

**Why GPUs are good at cracking:** graphics is the same math repeated enormously, so thousands of small cores in parallel (a GPU) beat one fast CPU. The same shape fits **bitcoin mining, password cracking and AI training** (all massive repetition of one calculation). **Hashcat** uses that GPU power.

!!! note "💡 Note (added) — hashes and cracking"
    Systems store a **hash** (an irreversible transform), not the password. Cracking therefore **hashes candidate words and compares to the stolen hash** — a match reveals the password.

The lab runs Hashcat against an **MD5** list (mode `-m 0`) and a **Windows NTLM** list (mode `-m 1000`, the kind dumped from SAM), with a dictionary attack (`-a 0`). Results print as `hash:password`; an empty right-hand side means a **blank password**.

!!! note "💡 Note (added) — the NT hash weakness"
    An NT hash is the password UTF-16LE-encoded then **MD4**-hashed. Its big weakness is **no salt** — the same password yields the same hash on every host, so precomputed tables work and hash-only logon ([Pass-the-Hash](../../../adversary/pass-the-hash.md)) becomes possible. `31d6cfe0d16ae931b73c59d7e0c089c0` is the well-known NT hash of a **blank password** — worth recognising in DFIR. Where the hashes come from: [SAM & NTDS extraction](../../../adversary/sam-ntds-extraction.md).

---

## 12. Highlights from the AMA { #ama }

- **Join InfraGard (FBI–industry info-sharing)?** → "Yes, and **volunteer to present**." Hiring decision-makers are in the room, and good talks are always in short supply.
- **AI (Anthropic Mythos) and the flood of vulnerabilities?** → initial marketing scepticism, but vendors confirmed the model **found vulnerabilities at scale**. The message: you must plan for **"how do we hold when there's no patch"** — and most of the industry isn't ready. **That's why this course matters** (hold with controls that block whole attack categories — allow listing, firewalls, logging).
- **Let AI do the patching?** → wary of handing everything to AI without human oversight.
- **Government vs private sector right now?** → **government** (the next ~18 months look unstable). Many firms are freezing junior hiring to "replace with AI," which John sees as a mistake — AI is **asymmetrically better for offence**, so you should hire people and **train them to use AI**.

!!! note "💡 Note (added)"
    For more on Mythos see Anthropic's own material ([anthropic.com/glasswing](https://www.anthropic.com/glasswing)).

---

## Day 1 summary { #summary }

| Attack | Key defence | Reference |
|---|---|---|
| Malware's first run from Downloads/Desktop | Application allow listing (AppLocker path rules) | [LOLBins](../../../adversary/lolbins.md) |
| AV bypass (ghostwriting, LOLBins) | Layered defence; don't rely on AV alone | [Process injection](../../../adversary/process-injection.md) |
| Password spraying | Long passwords, MFA everywhere, block legacy auth | [PsExec & SMB](../../../adversary/psexec-smb.md) · [Event IDs](../../../basics/windows-event-ids.md) |
| Kerberoasting | Long service-account passwords / gMSA, monitor 4769 | [Kerberoasting](../../../adversary/kerberoasting.md) |
| LLMNR/NBT-NS poisoning (Responder) | Disable those protocols, enforce SMB signing | [LLMNR & NTLM relay](../../../adversary/llmnr-ntlm-relay.md) |
| Hash cracking | Long passwords (length = cracking time) | [SAM & NTDS](../../../adversary/sam-ntds-extraction.md) · [Pass-the-Hash](../../../adversary/pass-the-hash.md) |

!!! quote ""
    Attackers get in by ① running code or ② getting passwords. So ① only let code run from allowed places (AppLocker), and ② make passwords long, MFA complete, service accounts tightly managed. And prepare for a world with no patch by holding whole attack categories with controls.

## References { #references }

- [Antisyphon Training](https://www.antisyphontraining.com/) · [Black Hills Information Security](https://www.blackhillsinfosec.com/)
- [Back Doors & Breaches](https://www.backdoorsandbreaches.com/)
- [MITRE ATT&CK — T1110.003 Password Spraying](https://attack.mitre.org/techniques/T1110/003/) · [T1558.003 Kerberoasting](https://attack.mitre.org/techniques/T1558/003/)
- Related: [Kerberoasting](../../../adversary/kerberoasting.md) · [LLMNR & NTLM relay](../../../adversary/llmnr-ntlm-relay.md) · [LOLBins](../../../adversary/lolbins.md) · [Pass-the-Hash](../../../adversary/pass-the-hash.md) · [Windows Event IDs](../../../basics/windows-event-ids.md)

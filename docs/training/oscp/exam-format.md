---
title: Exam Format & Scoring
tags:
  - oscp
---

# Exam Format & Scoring

<div class="dfir-meta" markdown>
**Section:** OSCP+ · **Source:** OffSec OSCP+ Exam Guide (checked 2026-10-23) · **Last updated:** 2026-10-23
</div>

!!! abstract "In one sentence"
    23 h 45 m of hands-on hacking in a private VPN, then 24 h to upload the report; 100 points available, 70 to pass, no bonus points since 1 November 2024 — and a flag only counts if the report proves it was taken from an interactive shell.

!!! warning "Rules change — re-read before booking"
    Everything on this page is summarised from the official [OSCP+ Exam Guide](https://help.offsec.com/hc/en-us/articles/360040165632). OffSec updates it without notice. Read the live guide again the week before the exam.

## Exam at a glance { #at-a-glance }

| Item | Value |
|---|---|
| Hands-on window | 23 h 45 m (e.g. start 09:00, VPN closes 08:45 next day) |
| Report window | 24 h after the hands-on window ends |
| Machines | 3 standalone + 1 Active Directory set of 3 machines |
| Points available | 100 |
| **Pass mark** | **70** |
| Bonus points | None (removed 1 Nov 2024) |
| Connection | Kali Linux + OpenVPN (OffSec only supports this setup) |
| Proctoring | Webcam + screen sharing for the whole hands-on window |
| Results | By email within 10 business days of submitting the report |

### Where the points come from { #points }

| Target | Points | How |
|---|---|---|
| Standalone 1 / 2 / 3 | 20 each | 10 for `local.txt` (low-privilege user) + 10 for `proof.txt` (root / Administrator) |
| AD machine #1 | 10 | Full compromise of the first host |
| AD machine #2 | 10 | Full compromise of the second host |
| AD machine #3 (Domain Controller) | 20 | Domain compromise |

For the AD set you are given a **username and password** at the start, simulating a user whose account has already been phished ("assumed breach"). The exact objectives for each machine are shown in the **exam control panel** — read them at the start.

### What makes a flag count { #flag-rules }

Getting the flag is not enough. Each one must meet all of these, or the target can score **zero**:

1. **Interactive shell.** Read the flag with `cat` (Linux) or `type` (Windows) from an interactive shell on the target. **Web shells are not valid** — a flag read through a web shell earns zero points for that target.
2. **Original location.** Read it where it lives — don't copy or move it first.
3. **Screenshot with the IP.** The same screenshot must show the flag contents **and** the target's IP address (`ip addr`, `ifconfig` or `ipconfig`).
4. **Right privilege for `proof.txt`.** Linux: a root shell. Windows: a shell as SYSTEM, Administrator, or a user in the local Administrators group.
5. **Submitted in the control panel** before the exam ends. The panel does **not** tell you whether the flag is correct.
6. **Documented in the report** well enough that a technically competent reader can repeat every step.

A proof screenshot that satisfies rules 1–4 in one frame:

=== "Linux"

    ```bash
    hostname; whoami; ip addr show | grep 'inet '; cat /root/proof.txt
    ```

    ```text title="Example output (illustrative)"
    web01
    root
        inet 127.0.0.1/8 scope host lo
        inet 192.168.120.45/24 brd 192.168.120.255 scope global ens160
    3f1c0e9b6a2d47c58e1f0a9d2b7c4e61
    ```

=== "Windows"

    ```powershell
    hostname & whoami & ipconfig | findstr IPv4 & type C:\Users\Administrator\Desktop\proof.txt
    ```

    ```text title="Example output (illustrative)"
    MS01
    nt authority\system
       IPv4 Address. . . . . . . . . . . : 10.10.120.141
    9a4e2c71d0b84f6e93c5a1f7e2d6b083
    ```

!!! tip "Grading order"
    OffSec grades machines in the order they appear in your report. Put each target in its own clearly labelled section.

## Passing combinations { #passing-combinations }

From the official guide — each line is exactly 70 points:

- 40 AD + 3 × `local.txt`
- 40 AD + 2 × `local.txt` + 1 × `proof.txt`
- 20 AD + 3 × `local.txt` + 2 × `proof.txt`
- 10 AD + 3 fully completed standalones

Reading the list the other way round shows why everyone says *"get the AD set"*:

| AD points | Standalone points needed | What that means |
|---|---|---|
| 40 | 30 | Three footholds, **or** one full box + one foothold |
| 20 | 50 | Five of the six standalone flags |
| 10 | 60 | Every standalone flag — no mistakes allowed |
| 0 | — | Cannot pass (standalones max out at 60) |

## What changed in November 2024 { #nov-2024-changes }

| | Before 1 Nov 2024 | OSCP+ exam now |
|---|---|---|
| AD set start | Had to find the initial foothold yourself — no foothold, no AD points | **Assumed breach**: domain credentials given at the start |
| AD scoring | All-or-nothing 40 | Points per machine: 10 / 10 / 20 |
| Bonus points | Up to 10 for lab reports and exercises | **None** |
| Buffer overflow | The dedicated 25-point BOF machine already ended in 2022 | Still not guaranteed — at most one step of a machine |
| Certification | OSCP (lifetime) | OSCP (lifetime) **and** OSCP+ (3 years) |

OSCP+ is kept current by passing the OSCP+ recertification exam in the six months before it expires, passing another qualifying OffSec certification, or through OffSec's CPE programme. The plain OSCP never expires.

## Exam rules to remember { #exam-rules }

### Restricted tools and techniques { #restricted }

The guide lists these as **not allowed** (quoted):

> Spoofing (IP, ARP, DNS, NBNS, etc)
>
> Commercial tools or services (Metasploit Pro, Burp Pro, etc.)
>
> Automatic exploitation tools (e.g. db_autopwn, browser_autopwn, SQLmap, SQLninja etc.)
>
> Mass vulnerability scanners (e.g. Nessus, NeXpose, OpenVAS, Canvas, Core Impact, SAINT, etc.)
>
> AI Chatbots (OffSec KAI, ChatGPT, YouChat, etc.)
>
> Features in other tools that utilize either forbidden or restricted exam limitations

Tools that do the same job as anything on the list are also out. What this means in practice:

| Want to… | Not allowed | Use instead |
|---|---|---|
| Capture NetNTLMv2 hashes | LLMNR / NBNS **poisoning** with Responder (spoofing) | Make the target connect to you — `impacket-smbserver`, a UNC path in a file or input field |
| Exploit SQL injection | sqlmap | Manual injection → [Web & initial access](web-initial-access.md#sqli) |
| Intercept web traffic | Burp Pro | Burp Suite Community, browser dev tools |
| Get help | ChatGPT, Claude, Gemini, OffSec KAI, other people | Your notes, HackTricks, GTFOBins, LOLBAS, man pages, search engines |

Explicitly allowed examples from the guide: Nmap (including NSE), Nikto, Burp Free, DirBuster. Searching the internet and Discord is fine; asking anyone for help is not.

### Metasploit — one target only { #metasploit }

- Metasploit modules (auxiliary, exploit, post) **or** a Meterpreter payload may be used against **one** target of your choice.
- Once used on a target, the choice is locked — even if it fails, you cannot move Metasploit to another machine.
- Running `check` (or anything else) against several machines to "pick" one is not allowed.
- No Metasploit pivoting (that would touch more than one target).
- **Always allowed on every target:** `msfvenom` and `exploit/multi/handler` (with a non-Meterpreter payload).
- The same limits apply to anything built on Metasploit (Armitage, Cobalt Strike, Metasploit Community).

### Exploit code in the report { #exploit-code }

- **Unmodified public exploit:** give the URL only — don't paste the code.
- **Modified exploit:** include the modified code, the original URL, the shellcode / msfvenom command if any, and **highlight and explain every change**.

### Other rules { #other-rules }

- Don't download files from the exam network unless you need them to compromise a target, and delete them afterwards.
- Machine reverts are limited (the count is in the control panel). A revert wipes everything on that machine, including your shells.
- The 23 h 45 m includes all breaks, meals and sleep — there is no pause button. Tell the proctor in chat before stepping away.
- Have a backup plan for your own failures: second internet connection (phone hotspot), a spare Kali VM snapshot.

### Ways to lose a target's points { #lose-points }

From the guide, you get **zero points for a target** if you:

- use a restricted tool or technique on it;
- use Metasploit modules or Meterpreter on more than one machine;
- don't provide `local.txt` / `proof.txt` both in the control panel **and** in an interactive-shell screenshot;
- don't document it well enough to reproduce.

## Report submission (summary) { #submission }

Details and checklist on the [Reporting](reporting.md) page.

| Item | Requirement |
|---|---|
| Format | One PDF, inside a `.7z` archive; scripts / PoCs as text inside the PDF |
| Names (case-sensitive) | `OSCP-OS-XXXXX-Exam-Report.pdf` and `OSCP-OS-XXXXX-Exam-Report.7z` (your OSID) |
| Password | None on the PDF or the archive |
| Size | Max 200 MB |
| Where / when | <https://upload.offsec.com>, within 24 h of the hands-on window ending |
| Check | Compare the MD5 shown after upload with your local file, then click **Submit File** |

## Scoring strategy { #scoring-strategy }

**Primary plan: 40 AD + 30 standalone = 70, then build a buffer.**

1. **Warm up on one standalone** (time-box about 2–3 h). The aim is to get into a working rhythm and, ideally, bank 10–20 points.
2. **Move to the AD set while still fresh.** It is the largest single block of points and it is chained — every credential found matters for the next machine.
3. **Go back to the remaining standalones** with the AD points banked. Each foothold is another 10.
4. **Aim for 80, not 70.** A buffer protects against a flag that the report fails to prove.

**Fallback: if the AD set stalls.** With 20 AD points (two machines) you need 50 from standalones; with 10 you need all 60. If the AD set has stalled for a long time (several hours with no new information), switch to the standalones, bank everything you can, then return to AD with fresh eyes.

| Situation at about hour 12 | Points so far | Next move |
|---|---|---|
| AD 40, one standalone foothold | 50 | Two more footholds, or finish one box |
| AD 20, nothing standalone | 20 | Standalones now; return to AD later |
| AD 0, two full standalones | 40 | AD — 30 more points must come from the set |

## Related pages

- [Exam-day strategy](exam-day.md) · [Reporting](reporting.md) · [Active Directory](active-directory.md) · [Methodology & habits](methodology.md)

## References

- [OffSec — OSCP+ Exam Guide](https://help.offsec.com/hc/en-us/articles/360040165632)
- [OffSec — OSCP Exam with AD Preparation](https://help.offsec.com/hc/en-us/articles/4547917816468-Offensive-Security-OSCP-Exam-with-AD-Preparation)
- [OffSec — OSCP exam change FAQ (Nov 2024)](https://help.offsec.com/hc/en-us/articles/29865898402836)
- [OffSec — PEN-200 Reporting Requirements](https://help.offsec.com/hc/en-us/articles/360046787731-PEN-200-Reporting-Requirements)

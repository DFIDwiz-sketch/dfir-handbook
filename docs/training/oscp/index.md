---
title: OSCP+
tags:
  - oscp
---

# OSCP+

<div class="dfir-meta" markdown>
**Exam:** OffSec PEN-200 → OSCP / OSCP+ · **Status:** Preparing · **Last updated:** 2026-11-03
</div>

!!! abstract "What this section is"
    Study hub for the OSCP+ exam (PEN-200). The layout follows what 2025–2026 pass and fail write-ups agree on: **get the Active Directory set solid, and hold the standalone machines with strong fundamentals.** Where a technique already has a page in this handbook, the OSCP page links to it instead of repeating it — so the attacker view here and the detection view in Adversary / Windows / Network stay connected.

!!! warning "Before the exam: check the official OSCP+ Exam Guide"
    Exam rules — banned tools, the Metasploit limit, proof requirements, report format — **change over time**. Before you sit the exam, read the current [OffSec OSCP+ Exam Guide](https://help.offsec.com/hc/en-us/articles/360040165632) yourself. The rule notes in this section are a study aid, not the authority.

!!! danger "Restricted in the exam (summary)"
    - **Automatic exploitation tools** — sqlmap, SQLninja, db_autopwn, browser_autopwn → do SQLi by hand ([Manual SQLi](web-initial-access.md#sqli)).
    - **Mass vulnerability scanners** — Nessus, OpenVAS, NeXpose, Core Impact → `nmap -sV` / NSE + `searchsploit` ([Recon](recon-enumeration.md)).
    - **Commercial tools** — Burp Suite Pro, Metasploit Pro → Burp Community, manual testing.
    - **Spoofing** — ARP / DNS / NBNS / LLMNR poisoning (Responder poisoning, mitm6, bettercap) → [coercion to your own SMB server](active-directory.md#coercion).
    - **AI / chatbots** — ChatGPT, Claude, Gemini, OffSec KAI and the like → your own notes and public references.
    - **Metasploit / Meterpreter** — one target only, no pivoting with it; `msfvenom` and `multi/handler` (non-Meterpreter) are fine everywhere ([Shells](shells-file-transfer.md)).

    Details: [Exam format › Restricted](exam-format.md#restricted) · [Metasploit](exam-format.md#metasploit).

## 1. Know the exam

<div class="grid cards" markdown>

-   :material-scale-balance:{ .lg .middle } **Exam format & scoring**

    ---

    3 standalones (60) + AD set (40), 70 to pass, no bonus points. What changed in November 2024 and the scoring combinations that pass.

    [:octicons-arrow-right-24: Exam format & scoring](exam-format.md)

-   :material-transit-connection-variant:{ .lg .middle } **Exam workflow**

    ---

    The whole exam as one pipeline: recon → foothold → stable shell → privesc → AD assumed breach → pivot → lateral movement → domain. Links every stage to its page.

    [:octicons-arrow-right-24: Exam workflow](exam-workflow.md)

</div>

## 2. Study areas

Each study-area page follows the same layout: **concept → main tools → scenarios (situation → command → what to read → next step) → common mistakes → exam tips**.

<div class="grid cards" markdown>

-   :material-radar:{ .lg .middle } **Recon & enumeration**

    ---

    nmap, NetExec, smbclient, enum4linux-ng, SNMP, NFS — find every port and everything it leaks.

    [:octicons-arrow-right-24: Recon & enumeration](recon-enumeration.md)

-   :material-web:{ .lg .middle } **Web & initial access**

    ---

    ffuf / feroxbuster / gobuster, nikto, Burp Community, searchsploit, manual SQLi, upload, LFI, client-side.

    [:octicons-arrow-right-24: Web & initial access](web-initial-access.md)

-   :material-console:{ .lg .middle } **Shells & file transfer**

    ---

    Reverse shells, msfvenom payloads, TTY upgrade, moving tools in and loot out, the one-target Metasploit rule.

    [:octicons-arrow-right-24: Shells & file transfer](shells-file-transfer.md)

-   :material-linux:{ .lg .middle } **Linux privilege escalation**

    ---

    LinPEAS, pspy, GTFOBins — sudo, SUID, capabilities, cron, credentials, NFS, kernel last.

    [:octicons-arrow-right-24: Linux privesc](privesc-linux.md)

-   :material-microsoft-windows:{ .lg .middle } **Windows privilege escalation**

    ---

    WinPEAS, PrintSpoofer / GodPotato, LOLBAS — tokens, services, tasks, AlwaysInstallElevated, stored creds.

    [:octicons-arrow-right-24: Windows privesc](privesc-windows.md)

-   :material-lock-open-variant:{ .lg .middle } **Password attacks**

    ---

    hashcat / john modes, custom wordlists, NetExec & Kerbrute spraying, hydra — and lockout math.

    [:octicons-arrow-right-24: Password attacks](password-attacks.md)

-   :material-domain:{ .lg .middle } **Active Directory**

    ---

    Top priority. Assumed breach → NetExec, BloodHound CE, Kerberoast / AS-REP, ACL abuse, Impacket lateral movement, mimikatz, DCSync.

    [:octicons-arrow-right-24: Active Directory](active-directory.md)

-   :material-tunnel:{ .lg .middle } **Pivoting & tunnelling**

    ---

    The most common failure point: reaching the internal subnet. Ligolo-ng, Chisel, SSH forwarding, proxychains.

    [:octicons-arrow-right-24: Pivoting & tunnelling](pivoting.md)

-   :material-format-list-checks:{ .lg .middle } **Methodology & habits**

    ---

    Enumeration checklist, simple things first, rabbit holes, the one-target Metasploit budget, notes.

    [:octicons-arrow-right-24: Methodology & habits](methodology.md)

-   :material-file-document-edit:{ .lg .middle } **Reporting**

    ---

    Proof screenshots that count, exam-time note structure, template, mock reports.

    [:octicons-arrow-right-24: Reporting](reporting.md)

</div>

## 3. Practice

<div class="grid cards" markdown>

-   :material-flask:{ .lg .middle } **Practice labs & machine lists**

    ---

    Challenge Labs (OSCP A/B/C), Proving Grounds Practice, LainKusanagi list, AD drills, mock exams, progress log.

    [:octicons-arrow-right-24: Practice labs](practice-labs.md)

-   :material-flask-outline:{ .lg .middle } **Lab walkthroughs**

    ---

    Full worked examples from my home lab — attack end to end, then detect it (Splunk / Zeek). First up: Kerberoasting.

    [:octicons-arrow-right-24: Lab walkthroughs](labs/index.md)

</div>

## 4. Exam day and plan

<div class="grid cards" markdown>

-   :material-timer-sand:{ .lg .middle } **Exam-day strategy**

    ---

    Booking, setup, order of attack (one standalone → AD set), breaks, point tracker.

    [:octicons-arrow-right-24: Exam-day strategy](exam-day.md)

-   :material-calendar-check:{ .lg .middle } **My study plan**

    ---

    Focus areas, weekly plan, weak-points log, mock exam results.

    [:octicons-arrow-right-24: My study plan](study-plan.md)

</div>

## Readiness checklist

- [ ] PEN-200 modules done, up to and including *Assembling the Pieces*
- [ ] Challenge Labs OSCP A, B and C cleared — and understood, not just flagged
- [ ] Proving Grounds Practice machines from the LainKusanagi list → [Practice labs](practice-labs.md)
- [ ] AD set from assumed-breach credentials to DC, without notes → [Active Directory](active-directory.md)
- [ ] Pivot into an internal subnet with Ligolo-ng from memory → [Pivoting](pivoting.md)
- [ ] Timed mock exam + full report, at least three times → [Reporting](reporting.md)
- [ ] Exam booked (slots are limited — book about a month ahead) → [Exam day](exam-day.md)

## References

- [OffSec — OSCP+ Exam Guide](https://help.offsec.com/hc/en-us/articles/360040165632)
- [OffSec — OSCP Exam with AD Preparation](https://help.offsec.com/hc/en-us/articles/4547917816468-Offensive-Security-OSCP-Exam-with-AD-Preparation)
- [netguardia — OSCP in 2026: is the new format harder?](https://netguardia.com/learning-development/certifications/oscp-in-2026-is-it-still-the-gold-standard-and-is-the-new-format-harder/)
- [Aryan — OSCP+ Exam 2026: strategy, reporting, tips](https://medium.com/@contact.aryan.here/oscp-exam-2026-strategy-reporting-tips-and-lessons-484363f29f6c)
- [Jess L — Passing OSCP+ on the 3rd attempt (2026)](https://medium.com/@onyuyu.loke/passing-oscp-at-3rd-attempts-journey-and-tips-sharing-2026-afe6d669b221)
- [The Husky Hacker — OSCP notes, lock-in and tips (Sep 2026)](https://medium.com/@TheHuskyHacker/oscp-notes-lock-in-and-tips-abc6f8895e60)

!!! info "Adding a page here"
    ```bash
    python new.py training/oscp/<name> -t concept
    ```
    New pages land at the end of the menu (the `...` in `.pages`). To put one inside **Study areas**, add it to that group in `docs/training/oscp/.pages` and `docs-ko/training/oscp/.pages`.

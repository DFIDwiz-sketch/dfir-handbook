---
title: OSCP+
tags:
  - oscp
---

# OSCP+

<div class="dfir-meta" markdown>
**Exam:** OffSec PEN-200 → OSCP / OSCP+ · **Status:** Preparing · **Last updated:** 2026-10-23
</div>

!!! abstract "What this section is"
    Study hub for the OSCP+ exam (PEN-200). The layout follows what 2025–2026 pass and fail write-ups agree on: **get the Active Directory set solid, and hold the standalone machines with strong fundamentals.** Where a technique already has a page in this handbook, the OSCP page links to it instead of repeating it — so the attacker view here and the detection view in Adversary / Windows / Network stay connected.

## 1. Know the exam

<div class="grid cards" markdown>

-   :material-scale-balance:{ .lg .middle } **Exam format & scoring**

    ---

    3 standalones (60) + AD set (40), 70 to pass, no bonus points. What changed in November 2024 and the scoring combinations that pass.

    [:octicons-arrow-right-24: Exam format & scoring](exam-format.md)

</div>

## 2. Study areas

<div class="grid cards" markdown>

-   :material-domain:{ .lg .middle } **Active Directory**

    ---

    Top priority. Assumed-breach start, enumeration, Kerberos attacks, lateral movement, domain compromise.

    [:octicons-arrow-right-24: Active Directory](active-directory.md)

-   :material-tunnel:{ .lg .middle } **Pivoting & tunnelling**

    ---

    The most common failure point: reaching the internal subnet. Ligolo-ng, Chisel, SSH forwarding, proxychains.

    [:octicons-arrow-right-24: Pivoting & tunnelling](pivoting.md)

-   :material-linux:{ .lg .middle } **Linux privilege escalation**

    ---

    sudo, SUID, capabilities, cron, credentials on the box, kernel exploits.

    [:octicons-arrow-right-24: Linux privesc](privesc-linux.md)

-   :material-microsoft-windows:{ .lg .middle } **Windows privilege escalation**

    ---

    Token privileges and potatoes, services, scheduled tasks, AlwaysInstallElevated, stored credentials.

    [:octicons-arrow-right-24: Windows privesc](privesc-windows.md)

-   :material-web:{ .lg .middle } **Web & initial access**

    ---

    Manual SQLi, upload bypasses, LFI → RCE, SSRF, CMS, fixing public exploits, client-side tricks.

    [:octicons-arrow-right-24: Web & initial access](web-initial-access.md)

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

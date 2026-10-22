---
title: Practice Labs & Machine Lists
tags:
  - oscp
---

# Practice Labs & Machine Lists

<div class="dfir-meta" markdown>
**Section:** OSCP+ · **Last updated:** 2026-10-23
</div>

!!! abstract "In one sentence"
    PEN-200 Challenge Labs first, then OffSec's own Proving Grounds machines — the boxes closest to the exam style — worked through a current machine list, with timed mock exams at the end.

!!! note "How this page is organised"
    A practice plan plus a progress log to fill in. The consistent advice from 2025–2026 write-ups: volume of machines matters, but only if you understand each one — don't just chase the flag.

## Order of practice { #order }

1. **PEN-200 course + Challenge Labs** — build the methodology on the official material.
2. **Proving Grounds Practice** — the closest thing to exam machines (OffSec-built, retired exam labs live here).
3. **A current machine list** (LainKusanagi) across PG / HTB — breadth and pattern recognition.
4. **AD-specific drills** — because the AD set is where people fail.
5. **Timed mock exams** — full dress rehearsals, including the report.

## PEN-200 & Challenge Labs { #challenge-labs }

- Work the course modules up to and including *Assembling the Pieces*.
- **OSCP A, B and C** are the three Challenge Labs with a full AD set under the assumed-breach model — the single best exam proxy. Clear them and understand them 100%; if they feel comfortable, you're close to ready.
- Secura, Medtech and Relia are good additional multi-machine labs.

## Proving Grounds Practice { #proving-grounds }

- Paid tier (~$19/month) with Windows and Linux boxes, including retired OSCP exam labs.
- OffSec builds these, so they train you in OffSec's style and rabbit-hole design — often cited as more exam-relevant than HTB.
- Most passers report doing roughly **40–70** machines across their whole prep.

## Machine lists { #machine-lists }

- **LainKusanagi's OSCP-like list** — the current favourite; filters out boxes outside PEN-200/OSCP scope and is kept updated. Community forks add difficulty ratings and a study tracker.
- **TJ Null's list** — the long-standing list, now considered somewhat dated for the current exam.
- Use a list as a spine, not a checklist to rush — a box you understood beats three you flagged with a walkthrough open.

## AD practice { #ad-practice }

The AD set is 40 points and the #1 failure area, so drill it specifically:

- Challenge Labs OSCP A/B/C (assumed-breach AD).
- HTB / dedicated AD rooms for Kerberos, lateral movement, pivoting.
- Hacker Blueprint and similar AD-focused drills come up often in pass write-ups.

Study side for every AD technique: [Active Directory](active-directory.md).

## Mock exams { #mock-exams }

Treat these like the real thing — they are where you practise the parts that aren't hacking:

- 3 standalones + 1 AD set, self-selected, in a 24-hour window.
- **Write the full report afterwards**, to the real requirements → [Reporting](reporting.md). Do this at least three times; by exam day the report should be mostly mechanical.
- Rehearse the logistics: start time, breaks, proof screenshots, point tracking.

## Walkthroughs — how to use them { #walkthroughs }

- Try the box **fully** first; only open a walkthrough once you've genuinely exhausted your own ideas.
- Afterwards, read an official writeup / IppSec video even if you passed — to pick up methodology, not just the answer.
- `ippsec.rocks` searches IppSec videos by technique/keyword — useful when stuck on a type of vuln.

## Progress log { #progress-log }

| Machine | Platform | OS | Done | Key lesson |
|---|---|---|---|---|
|  |  |  |  |  |

## Related pages

- [My study plan](study-plan.md) · [Active Directory](active-directory.md) · [Learning resources](../../learning/resources.md)

## References

- [LainKusanagi — list of OSCP-like machines](https://docs.google.com/spreadsheets/d/18weuz_Eeynr6sXFQ87Cd5F0slOj9Z6rt)
- [OffSec — Proving Grounds](https://www.offsec.com/products/proving-grounds/)
- [ippsec.rocks](https://ippsec.rocks/)

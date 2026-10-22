---
title: Exam-Day Strategy
tags:
  - oscp
---

# Exam-Day Strategy

<div class="dfir-meta" markdown>
**Window:** 23 h 45 m hands-on + 24 h report · **Last updated:** 2026-10-23
</div>

!!! abstract "In one sentence"
    Warm up on one standalone, take the 40-point AD set while still fresh, bank points early, and rest before frustration compounds into paralysis.

!!! note "How this page is organised"
    A plan for the day plus a point tracker to copy into your notes. The exam has a large psychological component — managing energy and nerves is as important as technique.

## Before the exam { #before }

- **Book early.** Slots are limited — often a month out. Pick a start time, and avoid travelling right before.
- **Choose a start time deliberately.** Your sharpest hours should overlap the first ~6 h (one standalone + the AD set). Many pick mid-morning; some prefer a night start after a nap. Not so early you're groggy, not so late burnout hits at the hard part.
- **Prepare the environment the day before:** Kali VM snapshot, tools / wordlists / scripts in place, the report template open, a second internet option (phone hotspot), backup power.

## Start and proctoring { #proctoring }

- Setup (ID check, screen share, webcam, VPN) can take up to an hour and does not eat your 23 h 45 m — but the VPN can be slow, so don't panic.
- The proctor may ask you to re-share your screen or recheck the webcam during the exam. This is normal; stay calm and carry on.
- No AI, no outside help, webcam on the whole time → [exam rules](exam-format.md#exam-rules).

## Order of attack { #order }

1. **One standalone to warm up** (~2–3 h cap). Get into the flow — full enumeration, exploit, document — and ideally bank 10–20 points. If it's fighting you, take the foothold and move on.
2. **The AD set, while fresh.** 40 chained points; a missed credential or pivot early blocks the rest, so do it with a clear head → [Active Directory](active-directory.md).
3. **Back to the remaining standalones** with AD banked, fresh eyes on anything you parked.
4. **Push past 70.** Aim for 80+ so a flaw in one report section doesn't fail you.

## Time-boxing and breaks { #breaks }

- Give each stuck lead a fixed budget; when it expires, switch targets.
- Take real breaks — eat lightly (heavy meals make you sluggish), step away, hydrate. Breakthroughs famously come after a break.
- Get up roughly once an hour. The 23 h 45 m includes sleep — a short nap can be worth more than another hour of staring.

## Point tracker { #point-tracker }

Copy this into your exam notes and keep it live:

| Target | local.txt | proof.txt | Points | Time done |
|---|---|---|---|---|
| Standalone 1 |  |  |  |  |
| Standalone 2 |  |  |  |  |
| Standalone 3 |  |  |  |  |
| AD #1 |  | — |  |  |
| AD #2 |  | — |  |  |
| AD DC |  | — |  |  |
| **Total** | | | | |

Checkpoint around the halfway mark against the [scoring strategy](exam-format.md#scoring-strategy) and decide where the next points are cheapest.

## When stuck { #stuck }

- Go back to enumeration — the thing you need is usually already on screen, unread.
- Switch to another machine; a parked problem often solves itself after time away.
- Re-read your own notes for a credential or detail you noted but didn't use.
- Don't spiral. People who pass write "I came back and got it in 20 minutes"; people who fail write "my mind went blank." The machines don't change — you do.

## After the hands-on window { #after }

- Submit every flag in the control panel **before** the VPN closes.
- Rest, then write the report in the 24-hour window → [Reporting](reporting.md). If your notes are good, this is mostly assembly.
- You cannot return to the machines, so a missing screenshot is unrecoverable — check the report against the [submission checklist](reporting.md#submission-checklist).

## Related pages

- [Exam format & scoring](exam-format.md) · [Reporting](reporting.md) · [Methodology & habits](methodology.md)

## References

- [OffSec — OSCP+ Exam Guide](https://help.offsec.com/hc/en-us/articles/360040165632)

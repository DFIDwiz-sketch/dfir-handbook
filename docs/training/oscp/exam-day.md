---
title: Exam-Day Strategy
tags:
  - oscp
---

# Exam-Day Strategy

<div class="dfir-meta" markdown>
**Window:** 23 h 45 m hands-on + 24 h report · **Sources checked / Last updated:** 2026-11-04
</div>

!!! abstract "In one sentence"
    Warm up on one standalone, work on the AD set while still fresh, document objectives as you complete them, and rest before frustration compounds into paralysis.

!!! note "How this page is organised"
    A plan for the day plus a raw-point and evidence tracker to copy into your notes. The exam has a large psychological component — managing energy and nerves is as important as technique.

!!! warning "Check the exam start time — scoring changes on 1 December 2026"
    Attempts starting **before 1 December 2026 at 08:00 GMT** require at least **70 raw points**. Attempts starting **on or after that instant** require at least **400 scaled points on a 100–500 scale**. Under scaled scoring, 70 or 80 raw points does not guarantee a pass, and 400/500 does not mean 80% raw points. Check your booked start time; no exam date is assumed here. See [scoring details](exam-format.md#scaled-scoring) and the official [Scoring FAQ](https://help.offsec.com/hc/en-us/articles/54589877508884-OSCP-Equated-Scaled-Scoring-FAQ).

## Before the exam { #before }

- **Book early.** Slots are limited — often a month out. Pick a start time, and avoid travelling right before.
- **Choose a start time deliberately.** Your sharpest hours should overlap the first ~6 h (one standalone + the AD set). Many pick mid-morning; some prefer a night start after a nap. Not so early you're groggy, not so late burnout hits at the hard part.
- **Prepare the environment the day before:** Kali VM snapshot, tools / wordlists / scripts in place, the report template open, a second internet option (phone hotspot), backup power.

## Start and proctoring { #proctoring }

- Setup (ID check, screen share, webcam, VPN) can take up to an hour and does not eat your 23 h 45 m — but the VPN can be slow, so don't panic.
- The proctor may ask you to re-share your screen or recheck the webcam during the exam. This is normal; stay calm and carry on.
- No AI, no outside help, webcam on the whole time → [exam rules](exam-format.md#exam-rules).

## Order of attack { #order }

1. **One standalone to warm up** (~2–3 h cap). Get into the flow — full enumeration, exploit, document. If it's fighting you, document any foothold and move on.
2. **The AD set, while fresh.** 40 chained points; a missed credential or pivot early blocks the rest, so do it with a clear head → [Active Directory](active-directory.md).
3. **Back to the remaining standalones** with AD banked, fresh eyes on anything you parked.
4. **Keep completing and documenting objectives.** Under scaled scoring there is no published raw-point pass target. Use remaining time on promising leads, evidence checks and rest; an estimated total is not a reason to stop. For pre-change attempts, the [70-point combinations](exam-format.md#passing-combinations) apply only if OffSec accepts the evidence; extra raw points never replace valid documentation.

## Time-boxing and breaks { #breaks }

- Give each stuck lead a fixed budget; when it expires, switch targets.
- Take real breaks — eat lightly (heavy meals make you sluggish), step away, hydrate. Breakthroughs famously come after a break.
- Get up roughly once an hour. The 23 h 45 m includes sleep — a short nap can be worth more than another hour of staring.

## Raw-point and evidence tracker { #point-tracker }

Copy this into your exam notes and keep it live. Use the control panel's objectives and raw-point values; your own total is only an estimate until grading, and cannot predict a scaled-scoring result.

| Target | local.txt | proof.txt | Est. raw points | Evidence / panel / notes | Time done |
|---|---|---|---|---|---|
| Standalone 1 |  |  |  |  |  |
| Standalone 2 |  |  |  |  |  |
| Standalone 3 |  |  |  |  |  |
| AD #1 |  | — |  |  |  |
| AD #2 |  | — |  |  |  |
| AD DC |  | — |  |  |  |
| **Total** | | | | | |

At the halfway mark, use the [scoring strategy](exam-format.md#scoring-strategy) to review unfinished objectives, missing evidence, promising leads and energy. Do not convert this tracker to a scaled score or label it a pass/fail result.

## When stuck { #stuck }

- Go back to enumeration — the thing you need is usually already on screen, unread.
- Switch to another machine; a parked problem often solves itself after time away.
- Re-read your own notes for a credential or detail you noted but didn't use.
- Don't spiral. People who pass write "I came back and got it in 20 minutes"; people who fail write "my mind went blank." The machines don't change — you do.

## After the hands-on window { #after }

- Submit every flag in the control panel **before** the VPN closes.
- Rest, then write the report in the 24-hour window → [Reporting](reporting.md). If your notes are good, this is mostly assembly.
- **Submit the report even if your estimated raw points seem low.** Under scaled scoring, raw points alone cannot tell you whether you passed; without a submitted report, you cannot pass.
- You cannot return to the machines, so a missing screenshot is unrecoverable — check the report against the [submission checklist](reporting.md#submission-checklist).
- Allow up to **15 business days** for results by email after report submission, as stated in the Scoring FAQ (previously 10; the Exam Guide's Results section still lists 10).

## Related pages

- [Exam format & scoring](exam-format.md) · [Reporting](reporting.md) · [Methodology & habits](methodology.md)

## References

- [OffSec — OSCP+ Equated Scaled Scoring FAQ](https://help.offsec.com/hc/en-us/articles/54589877508884-OSCP-Equated-Scaled-Scoring-FAQ)
- [OffSec — OSCP+ Exam Guide](https://help.offsec.com/hc/en-us/articles/360040165632)

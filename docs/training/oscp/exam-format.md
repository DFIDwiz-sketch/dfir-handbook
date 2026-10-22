---
title: Exam Format & Scoring
tags:
  - oscp
---

# Exam Format & Scoring

<div class="dfir-meta" markdown>
**Section:** OSCP+ · **Source:** OffSec OSCP+ Exam Guide · **Last updated:** 2026-10-22
</div>

!!! abstract "In one sentence"
    23 h 45 m of hands-on hacking, then 24 h to submit the report; 100 points available, 70 to pass, no bonus points since 1 November 2024.

!!! info "Skeleton page"
    Structure only for now — the headings below are the plan. Fill each section as you study.

## Exam at a glance { #at-a-glance }

| Part | Machines | Points |
|---|---|---|
| Standalone | 3 | 20 each — 10 initial access (`local.txt`) + 10 privesc (`proof.txt`) |
| Active Directory set | 3 (assumed breach: username + password given) | 10 (#1) + 10 (#2) + 20 (#3, DC) = 40 |
| **Pass mark** | | **70 / 100** |

## Passing combinations { #passing-combinations }

From the official guide:

- 40 AD + 3 × `local.txt`
- 40 AD + 2 × `local.txt` + 1 × `proof.txt`
- 20 AD + 3 × `local.txt` + 2 × `proof.txt`
- 10 AD + 3 fully completed standalones

## What changed in November 2024 { #nov-2024-changes }

- Assumed-breach AD set, partial points within the set
- Bonus points removed
- Buffer overflow no longer a guaranteed standalone
- OSCP (lifetime) + OSCP+ (3 years, renewable)

## Exam rules to remember { #exam-rules }

- No AI / LLM assistance — during the exam and the report
- Metasploit on one target only
- Restricted tools and techniques — re-read the official guide before booking
- Proctoring: webcam and screen sharing for the whole window

## Scoring strategy { #scoring-strategy }

- Which combination to aim for, and the fallback if the AD set stalls

## Related pages

- [Exam-day strategy](exam-day.md) · [Reporting](reporting.md) · [Active Directory](active-directory.md)

## References

- [OffSec — OSCP+ Exam Guide](https://help.offsec.com/hc/en-us/articles/360040165632)
- [OffSec — OSCP Exam with AD Preparation](https://help.offsec.com/hc/en-us/articles/4547917816468-Offensive-Security-OSCP-Exam-with-AD-Preparation)

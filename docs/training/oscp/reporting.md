---
title: Reporting
tags:
  - oscp
---

# Reporting

<div class="dfir-meta" markdown>
**Deadline:** 24 h after the hands-on window · **Last updated:** 2026-10-23
</div>

!!! abstract "In one sentence"
    Points only count if the report proves them — and mistakes are permanent once the VPN closes, because you cannot go back to the machines.

!!! note "How this page is organised"
    What the report must contain, how to take notes so the report is 80% written before you start, and a submission checklist. Practising the report is part of practising the exam — see [Practice labs › mock exams](practice-labs.md#mock-exams).

## What the report is for { #purpose }

A grader reads it and must be able to **reproduce every step**. If they can't follow it, or a flag isn't proven, that target scores reduced or zero points — regardless of whether you actually rooted it. Treat the exam network like a client engagement and write the report you'd hand a client.

## Proof requirements (the ones that cost points) { #proof }

- Each flag needs a screenshot showing **the flag contents and the target IP in the same frame** (`ip addr` / `ifconfig` / `ipconfig`). Two separate screenshots do not count.
- Flags must be read from an **interactive shell** with `cat` / `type`, from their original location — **web shells are not valid**.
- `proof.txt` needs the right privilege: root on Linux; SYSTEM / Administrator / local-admin on Windows.
- Submit every flag in the control panel before the exam ends **and** include the screenshot in the report.

Full detail: [Exam format › what makes a flag count](exam-format.md#flag-rules).

## Note structure during the exam { #exam-notes }

One page per machine, the same sections every time — this is literally your report draft:

```text
## Target: 192.168.x.x  (Standalone 1)
### Nmap / enumeration
### Initial access        → local.txt (screenshot: flag + IP)
### Local enumeration
### Privilege escalation   → proof.txt (screenshot: flag + IP)
### Exploit code / changes (URL, modified code, explanation)
```

Document **everything that could be relevant**, not just what worked at the time — a detail from machine 1 might unlock machine 2 an hour later, and you won't remember it unless it's written down.

## Exploit code in the report { #exploit-code }

- **Unmodified public exploit:** provide the URL only.
- **Modified exploit:** include the modified code, the original URL, the shellcode / `msfvenom` command if any, and highlight and explain **every change**.

## Template and tools { #template }

- **Official template:** [OSCP Exam Report (.docx)](https://www.offsec.com/pwk-online/OSCP-Exam-Report.docx) — you're strongly encouraged to use it.
- **During the exam:** a note tool you're fast in — Obsidian, CherryTree, Sublime. Keep screenshots organised per machine.
- **Report automation (optional):** SysReptor can speed up turning notes into the final document.

## Submission { #submission }

| Item | Requirement |
|---|---|
| Format | One PDF, archived as `.7z`; scripts / PoCs as **text inside the PDF** (no other files in the archive) |
| PDF name | `OSCP-OS-XXXXX-Exam-Report.pdf` (your OSID) |
| Archive name | `OSCP-OS-XXXXX-Exam-Report.7z` (same OSID) — **case-sensitive, must match exactly** |
| Password | None on the PDF or the archive |
| Size | Max 200 MB |
| Where / when | <https://upload.offsec.com>, within **24 h** of the hands-on window ending |
| Verify | Compare the MD5 shown after upload with your local file; re-upload if different, then click **Submit File** |

!!! warning "Upload gotcha"
    Some candidates hit a "file is not a proper format" error uploading from Windows 11 — OffSec recommends uploading from the Kali VM. A confirmation email follows a successful upload (check spam).

## Submission checklist { #submission-checklist }

- [ ] Every claimed flag has a proof screenshot (flag + IP, same frame)
- [ ] Every step reproduces from the report alone
- [ ] Modified exploits: code + original URL + explanation of changes
- [ ] Machines in clear, separate sections (grading follows report order)
- [ ] File names exactly `OSCP-OS-XXXXX-Exam-Report.pdf` / `.7z`
- [ ] No password on PDF or archive; archive ≤ 200 MB
- [ ] Uploaded to upload.offsec.com, MD5 verified, **Submit File** clicked
- [ ] Confirmation email received

## Related pages

- [Exam format & scoring](exam-format.md) · [Methodology & habits](methodology.md) · [Exam-day strategy](exam-day.md)

## References

- [OffSec — PEN-200 Reporting Requirements](https://help.offsec.com/hc/en-us/articles/360046787731-PEN-200-Reporting-Requirements)
- [OffSec — OSCP+ Exam Guide](https://help.offsec.com/hc/en-us/articles/360040165632)

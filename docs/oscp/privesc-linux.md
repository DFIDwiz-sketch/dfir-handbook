---
title: Linux Privilege Escalation
tags:
  - oscp
---

# Linux Privilege Escalation

<div class="dfir-meta" markdown>
**Exam weight:** 10 points per Linux standalone (`proof.txt`) · **Last updated:** 2026-10-22
</div>

!!! abstract "In one sentence"
    Low-privilege shell to root: enumerate first, try the common misconfigurations in order, keep kernel exploits for last.

!!! info "Skeleton page"
    Structure only for now — the headings below are the plan. Fill each section as you study.

## Shell upgrade { #shell-upgrade }

- Stable TTY before anything else

## Enumeration { #enumeration }

- linpeas — and how to read its output
- Manual commands to run every time

## sudo { #sudo }

- `sudo -l`, GTFOBins

## SUID & capabilities { #suid-capabilities }

## Cron & wildcards { #cron }

## Writable files & PATH { #writable-path }

## Credentials on the box { #credentials }

- Config files, history, SSH keys, database creds

## Internal services { #internal-services }

- Services on localhost only → port forward and attack

## Kernel exploits { #kernel }

- Choosing one safely — last resort

## Related pages

- [Linux auth & history](../linux/auth-and-history.md) · [Linux persistence](../linux/persistence.md) · [Linux logs & triage](../linux/logs-and-triage.md)
- [Linux commands](../basics/linux-commands.md)

## References

- [GTFOBins](https://gtfobins.github.io/)

---
title: Windows Privilege Escalation
tags:
  - oscp
---

# Windows Privilege Escalation

<div class="dfir-meta" markdown>
**Exam weight:** 10 points per Windows standalone (`proof.txt`) + AD-set hosts · **Last updated:** 2026-10-22
</div>

!!! abstract "In one sentence"
    Low-privilege user to Administrator / SYSTEM: run the enumeration scripts, check token privileges first, then services, tasks and stored credentials.

!!! info "Skeleton page"
    Structure only for now — the headings below are the plan. Fill each section as you study.

## Enumeration { #enumeration }

- winPEAS, PrivescCheck, SharpUp, PowerUp — what each checks

## Token privileges & potatoes { #token-privileges }

- `SeImpersonatePrivilege` → GodPotato / PrintSpoofer

## Services { #services }

- Modifiable binaries, weak registry keys, unquoted paths

## Scheduled tasks { #scheduled-tasks }

## AlwaysInstallElevated { #alwaysinstallelevated }

## DLL hijacking { #dll-hijacking }

## Stored credentials { #stored-credentials }

- GPP passwords, saved credentials, PowerShell history, files
- SAM / LSA secrets when SAM alone is not enough

## UAC { #uac }

## Kernel & missing patches { #kernel }

## Related pages

- [Token Impersonation / Potato](../adversary/token-impersonation-potato.md) · [UAC Bypass](../adversary/uac-bypass.md)
- [SAM / NTDS Extraction](../adversary/sam-ntds-extraction.md) · [LSASS Dumping](../adversary/lsass-dumping.md)
- [Registry keys](../windows/registry-keys.md) · [Event logs](../windows/event-logs.md)

## References

- [LOLBAS](https://lolbas-project.github.io/)

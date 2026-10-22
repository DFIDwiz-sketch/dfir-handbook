---
title: Windows Privilege Escalation
tags:
  - oscp
---

# Windows Privilege Escalation

<div class="dfir-meta" markdown>
**Exam weight:** 10 points per Windows standalone (`proof.txt`) + AD-set hosts · **Last updated:** 2026-10-23
</div>

!!! abstract "In one sentence"
    Low-privilege user to Administrator / SYSTEM: run the enumeration scripts, check your token privileges first, then services, scheduled tasks and stored credentials.

!!! note "How this page is organised"
    A study checklist. On Windows the fastest win is usually a service token privilege or a stored credential, so check those early. Practise on Proving Grounds Windows boxes → [Practice labs](practice-labs.md).

## 1. Enumerate { #enumeration }

```powershell
whoami /priv          # token privileges — the first thing to read
whoami /groups        # group memberships
systeminfo            # OS build, hotfixes (for missing-patch checks)
```

Then an automated script, read top-to-bottom:

```powershell
.\winPEASx64.exe              # or PrivescCheck.ps1 / SharpUp.exe audit
```

`whoami /priv` is the single most important line. If it shows `SeImpersonatePrivilege` or `SeAssignPrimaryTokenPrivilege` as **Enabled**, go straight to the potato family below.

## 2. Work the common vectors { #vectors }

| Vector | What to look for | Lead |
|---|---|---|
| **Token privileges** | `SeImpersonatePrivilege` (common on service accounts, `xp_cmdshell`, web shells) | PrintSpoofer / GodPotato → SYSTEM → [potatoes](#token-privileges) |
| **Service misconfig** | Writable service binary, weak service permissions, **unquoted service path** with a space | Replace / plant a binary the service runs as SYSTEM |
| **Scheduled tasks** | A task running as a privileged user whose script or binary you can modify | Edit the target it runs |
| **AlwaysInstallElevated** | Both registry keys set | Install a malicious MSI as SYSTEM (`msfvenom` MSI is allowed) |
| **Stored credentials** | GPP passwords, saved creds, PowerShell history, config / XML files | Reuse → [looting](active-directory.md#looting) |
| **DLL hijacking** | A privileged process loading a DLL from a writable path | Plant the DLL |
| **Unpatched kernel** | `systeminfo` + known exploit | Last resort, like Linux |

### Token privileges / potatoes { #token-privileges }

`SeImpersonatePrivilege` lets a process impersonate a token handed to it. The "potato" tools trigger a privileged service to authenticate, then impersonate SYSTEM. This is the most common standalone-box win and extremely common on SQL / IIS service accounts.

→ Defender view and the exact mechanism: [Token Impersonation / Potato](../../adversary/token-impersonation-potato.md).

## 3. Stored credentials { #stored-credentials }

Often faster than any exploit — look before you dig:

```powershell
cmdkey /list                                   # saved credentials
Get-Content (Get-PSReadlineOption).HistorySavePath   # PowerShell history
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" | findstr /i "DefaultUserName DefaultPassword"
Get-ChildItem C:\ -Include *.config,*.xml,*.ini,*.kdbx -Recurse -ErrorAction SilentlyContinue
```

When SAM alone isn't enough, LSA secrets and cached logons hold service passwords → [SAM / NTDS Extraction](../../adversary/sam-ntds-extraction.md), [LSASS Dumping](../../adversary/lsass-dumping.md).

## 4. UAC and kernel { #uac-kernel }

- If you are an **admin** but in a medium-integrity shell, that's a [UAC bypass](../../adversary/uac-bypass.md), not privilege escalation — you already have the rights, you need to elevate the token.
- Kernel / missing-patch exploits (from `systeminfo`) are the last resort, same reasoning as Linux.

## Checklist { #checklist }

- [ ] `whoami /priv` read → potato if `SeImpersonate`/`SeAssignPrimaryToken`
- [ ] winPEAS / PrivescCheck run and read
- [ ] Services checked (writable binary, unquoted path, weak perms)
- [ ] Scheduled tasks checked
- [ ] AlwaysInstallElevated keys checked
- [ ] Stored credentials searched (cmdkey, history, registry, files)
- [ ] `systeminfo` noted for missing patches (last option)

## Related pages

- [Token Impersonation / Potato](../../adversary/token-impersonation-potato.md) · [UAC Bypass](../../adversary/uac-bypass.md)
- [SAM / NTDS Extraction](../../adversary/sam-ntds-extraction.md) · [LSASS Dumping](../../adversary/lsass-dumping.md)
- [Registry keys](../../windows/registry-keys.md) · [Event logs](../../windows/event-logs.md) · [Methodology & habits](methodology.md)

## References

- [LOLBAS](https://lolbas-project.github.io/)
- [PEASS-ng (winPEAS)](https://github.com/peass-ng/PEASS-ng)

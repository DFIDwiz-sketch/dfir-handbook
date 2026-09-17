---
title: Linux Forensics
---

# Linux Forensics

Artifacts and log sources on Linux hosts — servers, containers hosts, and the occasional workstation. Start from the **question**; the mechanics are on each page.

## Question → where to look

| Question | Primary | Also check |
|---|---|---|
| **Who logged in, from where, and what did they type?** | [Auth & history](auth-and-history.md) — `auth.log`/`secure`, `wtmp`/`btmp`, shell history | journald, auditd `execve` |
| **How does the attacker survive reboot?** | [Persistence](persistence.md) — cron, systemd, SSH keys, profiles, PAM, modules | package-integrity check (`rpm -Va`/`dpkg --verify`) |
| **When was this file created/modified — was it timestomped?** | [Filesystem & timestamps](filesystem-timestamps.md) — MACB, ctime, ext4 birth | Sleuth Kit timeline, ext4 journal |
| **What ran / what's running / what's listening?** | [Logs, processes & triage](logs-and-triage.md) — `ps`, `ss`, `/proc`, auditd | deleted-but-open binaries in `/proc` |
| **What was installed and when?** | [Logs & triage](logs-and-triage.md) — `dpkg.log`/`apt history`/`yum.log` | package integrity |
| **Web server on Linux got popped** | [Web shell playbook](../playbooks/webshell-server.md) | Apache/Nginx logs, [logs & triage](logs-and-triage.md) |
| **Collect it all** | [UAC / CatScale / Velociraptor](../tools/velociraptor.md) | [Imaging](../tools/imaging-collection.md) |

## Pages

<div class="grid cards" markdown>

-   **[Auth & history](auth-and-history.md)** — auth logs, wtmp/btmp/lastlog, shell history, cross-checking tampered logs
-   **[Persistence](persistence.md)** — cron, systemd, profiles, SSH keys, PAM, LD_PRELOAD, modules; package-integrity checks
-   **[Filesystem & timestamps](filesystem-timestamps.md)** — MACB, ctime timestomp detection, hidden/setuid files, deleted-but-open, ext4 journal
-   **[Logs, processes & triage](logs-and-triage.md)** — log map, running-state snapshot, process triage, one-shot script

</div>

## How Linux differs from Windows (for the Windows-heavy analyst)

The investigative *method* is the same — timeline, pivot on keys, cross-check sources — but the artifacts differ. There's no registry (config is text files under `/etc`), no Prefetch/Amcache (execution evidence comes from **auditd**, shell history, and package logs, if any), no `$MFT` `$FILE_NAME` second timestamp set (so **ctime** is your timestomp detector instead), and logs are plain text or journald rather than EVTX. The biggest variable is **what logging was enabled**: with auditd you have Sysmon-grade execution data; without it, you're reconstructing from history files, journald, and the file system. Note the logging posture in every report.

## Order of work (live host)

1. **Snapshot volatile state first** — `ps`, `ss`, `/proc`, `lsof`, `lsmod` ([logs & triage](logs-and-triage.md)) — before it changes or a memory image reboots the box.
2. Auth story — [who got in](auth-and-history.md).
3. Persistence sweep — [where they hid](persistence.md), plus package integrity.
4. File-system timeline — [what changed, when](filesystem-timestamps.md).
5. Correlate; escalate to the matching [playbook](../playbooks/index.md) if it's more than one host.

!!! info "Adding a page here"
    `python new.py linux/<name> -t artifact` (or `-t concept`) — it appears in the sidebar automatically.

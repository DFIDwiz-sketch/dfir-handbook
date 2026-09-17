---
title: Compromised Workstation
tags:
  - playbook
  - triage
---

# Compromised Workstation — Initial Triage

<div class="dfir-meta" markdown>
**Scenario:** EDR/AV alert, suspicious process, or user report on a single endpoint · **Last updated:** 2026-09-17
</div>

!!! abstract "When to use this"
    An alert fires, a user reports something odd (pop-ups, slowness, a strange email they clicked), or you find a suspicious process on one host. This is the **first-responder** playbook: decide fast whether it's a real incident, scope it, and preserve evidence before it's lost — without tipping off an attacker who may still be watching.

## 1. Triage (first 15 minutes)

- **Confirm the alert is real** — read the actual detection (process, command line, file hash). Many EDR alerts are benign admin activity. Check the hash on VirusTotal, read the command line.
- **Identify** host, user, and the time window. Is the user's account privileged? Is the host a server, a jump box, or a normal workstation?
- **Decide: contain now or watch?** If it's clearly malicious and spreading, isolate. If it's a single dormant artifact and you want to understand scope first, **EDR-isolate** (network-contain but keep it running) rather than power off — you keep RAM and can still collect.
- **Don't alert the attacker**: avoid obvious remediation (deleting files, resetting the password) until you've scoped, if a live actor may be present.

## 2. Collect

| Priority | Source | Tool |
|---|---|---|
| 1 | **RAM** (if live actor / injected code suspected) | [WinPmem / FTK](../tools/imaging-collection.md) |
| 2 | Triage artifact set | [KAPE `!SANS_Triage`](../tools/kape.md) or [Velociraptor](../tools/velociraptor.md) |
| 3 | EDR process tree + timeline | EDR console export |

Run Targets on-host to a USB/network share; parse off-host ([collect on-host, parse off-host](../tools/kape.md)).

## 3. Analyse — the triage question order

Work the [Windows artifact map](../windows/index.md) in this order:

1. **What ran, and was it malicious?** [Prefetch](../windows/prefetch.md) (execution + files touched), [Amcache](../windows/amcache.md) (SHA-1 → intel), Sysmon 1 / [4688](../windows/event-logs.md) (command lines, parent process). Look for the suspicious parent→child ([phishing](../adversary/phishing-delivery.md), [PowerShell cradle](../adversary/powershell-cradles.md)).
2. **How did it get on the box?** [`Zone.Identifier`](../windows/mft-usn.md) download URL, [browser history], email ([phishing delivery](../adversary/phishing-delivery.md)), USB ([registry USB keys](../windows/registry-keys.md#usb-removable-devices-system)).
3. **Who ran it / who's logged on?** [Logon events 4624](../windows/event-logs.md), [UserAssist/BAM](../windows/registry-keys.md#program-execution-per-user-unless-noted).
4. **Did it persist?** [Autoruns / ASEP](../adversary/persistence.md) — services, tasks, Run keys.
5. **Did it talk out?** [Beaconing/C2](../network/beaconing-c2.md), Sysmon 3, [SRUM](../windows/srum.md) bytes per app.
6. **Did it steal creds or move?** [LSASS access](../adversary/lsass-dumping.md), [lateral movement](../adversary/psexec-smb.md) from this host.

Build a [host timeline](../splunk/security-searches.md#build-a-host-timeline-everything-about-one-machine) to see the sequence.

## 4. Contain / Eradicate

- Isolate the host (EDR-network-contain).
- If the account was used to authenticate elsewhere or credentials may have been dumped, **reset it** and check where it went ([4648/4624 hunts](../splunk/security-searches.md)).
- Remove persistence and the payload; note the hash for fleet-wide hunting.
- **Scope out**: hunt the fleet for the same hash, C2, parent/child pattern, or persistence name — one compromised workstation is rarely alone.

## 5. Recover & lessons

- Reimage rather than clean if the compromise was more than a single blocked file — you can't be sure you found everything.
- Restore the user with a fresh credential.
- Feed IOCs (hash, domain, IP, JA3) into detections; write a [detection rule](../splunk/hunting-patterns.md#making-hunts-repeatable) for the technique.
- If it turns into lateral movement or credential theft, escalate to the [lateral movement / domain playbook](lateral-domain.md).

## Useful queries

```spl
index=botsv3 sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventID=1 host=<HOST>
| eval parent=lower(replace(ParentImage,".*\\\\","")), child=lower(replace(Image,".*\\\\",""))
| table _time, parent, child, User, CommandLine
| sort 0 _time
```

The full process tree for one host, oldest first — read top to bottom to reconstruct what happened. `replace(...,".*\\\\","")` strips paths to bare filenames so the parent→child chain is easy to follow.

```spl
index=botsv3 host=<HOST> (sourcetype=WinEventLog EventCode IN (4624,4625,4648,4672,4688,7045,4698))
     OR (sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventID IN (1,3,11,22))
| eval what=coalesce(CommandLine, Process_Command_Line, TargetFilename, DestinationIp, Service_File_Name, Message)
| eval code=coalesce(EventCode, EventID)
| table _time, sourcetype, code, User, Account_Name, what
| sort 0 _time
```

A combined single-host timeline across Security and Sysmon — `coalesce` picks whichever descriptive field each event has, giving one readable "what happened" column.

## References

- [Windows forensics — artifact map](../windows/index.md) · [Security searches](../splunk/security-searches.md)
- [Adversary techniques](../adversary/index.md) · [KAPE](../tools/kape.md) · [Velociraptor](../tools/velociraptor.md)

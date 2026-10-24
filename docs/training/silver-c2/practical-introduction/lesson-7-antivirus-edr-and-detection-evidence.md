---
title: "Lesson 7 — Antivirus, EDR, and Detection Evidence"
---

# Lesson 7 — Antivirus, EDR, and Detection Evidence { #lesson-7-antivirus-edr-and-detection-evidence }

**Goal:** Distinguish detection from execution, and a detection record from a successful protective action.

## Start with an observation { #start-with-an-observation }

Imagine the file request succeeded, but the file is missing when you try to execute it and no beacon appears. Do not immediately conclude the download failed. A security product might have detected and quarantined the file after delivery. Investigate evidence for each step.

## Antivirus and EDR overlap { #antivirus-and-edr-overlap }

**AV** means antivirus. It detects threats and can perform protective actions such as blocking, quarantining, or removing them.

**EDR** means Endpoint Detection and Response. An endpoint is a device such as a PC or server. EDR helps investigate related device activity and respond to threats.

| Capability | Main perspective |
|---|---|
| Antivirus | Assess files or behavior and perform protection actions |
| EDR | Connect endpoint activity into an investigation and support response |

These are overlapping capabilities, not a strict division between “AV sees files” and “EDR sees behavior.” Microsoft Defender Antivirus also monitors process, file, and service activity while software runs. [Microsoft behavior-monitoring explanation](https://learn.microsoft.com/en-us/defender-endpoint/behavior-monitor)

## Static inspection and runtime behavior { #static-inspection-and-runtime-behavior }

**Static analysis** examines code without executing that code. Relevant evidence can include known hashes, code patterns, file structure, embedded strings, and signing information.

Therefore, a file can be detected **without the learner launching it**. A downloaded or newly saved file may be inspected before manual execution.

Runtime analysis asks what the program does: which processes it starts, where it connects, which files it accesses, and what system changes occur. Actual products combine multiple approaches, including machine learning and cloud-based analysis. A pre-execution alert does not by itself identify the exact detection mechanism. [Microsoft Defender Antivirus overview](https://learn.microsoft.com/en-us/defender-endpoint/microsoft-defender-antivirus-windows)

## A clue is not a proven detection cause { #clue-versus-proven-cause }

Go-related file characteristics or Sliver-related strings can be useful analysis clues. However, these are different statements:

- “The file contains a Sliver-related string.”
- “The security product detected the file specifically because of that string.”

The first is an observation; the second requires additional validation. Go is also used by legitimate software. A language, a filename, or one string does not by itself establish maliciousness or explain a product's decision.

## Correlate endpoint activity { #correlate-endpoint-activity }

```mermaid
flowchart LR
    A["PowerShell download"] --> B["Executable saved"]
    B --> C["New process starts"]
    C --> D["Network communication"]
    D --> E["Later file or system activity"]
```

An analyst checks whether these events involve the same computer, user, process, file, and time window. Collected activity information is called **telemetry**.

EDR can connect such evidence to alerts and investigations, but it is not guaranteed to record every action. Product capabilities and configuration affect visibility. [Microsoft EDR overview](https://learn.microsoft.com/en-us/defender-endpoint/overview-endpoint-detection-response)

## Detection, action, and outcome are separate { #detection-action-and-outcome }

Ask three questions:

1. What was detected?
2. What action was taken?
3. What was the action's outcome?

Microsoft Defender Antivirus provides useful examples:

| Event ID | Meaning | What to inspect |
|---|---|---|
| **1116** | Malware or potentially unwanted software detected | Threat name, path, detection details |
| **1117** | An action concerning a detected threat was recorded | Actual action, status, and result |

**1116 does not prove successful quarantine. Nor does the number 1117 mean “quarantine succeeded.”** Read whether the action was quarantine, removal, allowance, or another action, and inspect its reported state. Match it to the relevant file and threat. [Microsoft event reference](https://learn.microsoft.com/en-us/defender-endpoint/troubleshoot-microsoft-defender-antivirus)

## Read the events in PowerShell { #read-events-in-powershell }

Run this in **Windows PowerShell on the lab PC**, not in the Sliver console. It retrieves up to 20 matching events from the past hour:

```powershell
Get-WinEvent -FilterHashtable @{
    LogName = 'Microsoft-Windows-Windows Defender/Operational'
    Id = 1116, 1117
    StartTime = (Get-Date).AddHours(-1)
} -MaxEvents 20 | Format-List TimeCreated, Id, Message
```

| Part | Meaning |
|---|---|
| `Get-WinEvent` | Read Windows event records |
| `LogName` | Select the event log |
| `Id` | Select the event IDs |
| `StartTime` | Select the start of the time window |
| `-MaxEvents 20` | Retrieve up to 20 matching events |
| `Format-List` | Display the timestamp, ID, and message as a list |

This reads records; it does not change protection settings or restore quarantined content. Log permissions can restrict access. No matching records in this query do not prove no detection ever happened: the time window and selected IDs limit the search. [Get-WinEvent documentation](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.diagnostics/get-winevent)

The same log can be opened in Event Viewer under **Applications and Services Logs → Microsoft → Windows → Windows Defender → Operational**.

## Reconstruct a timeline { #reconstruct-a-timeline }

**Illustrative example:**

```text
10:00:00  File server logs an HTTP 200 response
10:00:02  Defender records detection of the executable
10:00:03  Defender records quarantine of that file
10:00:05  Execution attempt reports the file is missing
```

If the path, threat identifiers, and action result match, this supports “quarantine after delivery prevented this later file execution.” Events being close in time alone are not enough to prove they concern the same file.

## Review questions { #review-questions }

1. A file was downloaded but never manually executed. Can antivirus still detect it?
2. Only a matching 1116 event has been found. Does that establish successful quarantine?

??? success "Answers and reasoning"
    **1. Yes.** Inspection of hashes, code or string patterns, and other file characteristics can occur without manual execution. An observed string remains a clue, not proof that it caused the detection.

    **2. No.** It establishes a detection record. Find the related action evidence, confirm the file and threat match, and inspect the actual action and outcome. Even 1117 must be read rather than interpreted solely by its event number.

[Next: Identity, tokens, and permissions](lesson-8-identity-tokens-and-permissions.md)

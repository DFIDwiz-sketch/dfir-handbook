---
title: Splunk
---

# Splunk

SPL for incident response and threat hunting — syntax notes, reusable searches, hunting patterns and the BOTSv3 practice method. Every query here names its index and sourcetype; adapt them to your environment.

## Question → page

| Question | Page |
|---|---|
| **What does this command do? How do I write SPL?** | [SPL cheat sheet](spl-cheatsheet.md) |
| **What data is in this instance? Which fields? What time range?** | [Data discovery & time](data-discovery.md) |
| **The field I need doesn't exist / the XML isn't parsed** | [rex, field extraction & eval](rex-and-fields.md) |
| **Who logged on, what ran, how did they persist, did they move laterally?** | [Security searches by question](security-searches.md) |
| **Nothing alerted — how do I find what's unusual?** | [Hunting patterns](hunting-patterns.md) |
| **How do I work through BOTSv3 (or any CTF dataset) properly?** | [BOTSv3 investigation workflow](botsv3-workflow.md) |
| **Beaconing / C2 in Splunk** | [Beaconing & C2](../network/beaconing-c2.md) (network section, `streamstats` walkthrough) |
| **What does event ID 4xxx mean?** | [Windows Event IDs](../basics/windows-event-ids.md) |

## Pages

<div class="grid cards" markdown>

-   **[SPL cheat sheet](spl-cheatsheet.md)** — search anatomy, filtering, 40 commands with examples, reusable patterns, speed rules
-   **[Data discovery & time](data-discovery.md)** — indexes, sourcetypes, `fieldsummary`, CIM names, time modifiers, log-gap detection
-   **[rex, fields & eval](rex-and-fields.md)** — regex extraction, `spath`, `eval` functions, lookups, promoting to permanent extractions
-   **[Security searches](security-searches.md)** — logons, execution, persistence, lateral movement, network, tampering, host timeline
-   **[Hunting patterns](hunting-patterns.md)** — rare, new, spike, regular, long tail, peer outlier, sequences, drop-and-run, scoring
-   **[BOTSv3 workflow](botsv3-workflow.md)** — data map, pivot keys, investigation loop, first-look searches (no spoilers)

</div>

## House rules for SPL in this handbook

Queries are written to be pasted: `index=` and `sourcetype=` always present; comments explain each clause below the block; Windows event codes are named the first time they appear; field names follow what the Splunk Windows/Sysmon add-ons produce (`Account_Name`, `Logon_Type`, `Image`, `CommandLine`) with the CIM equivalent noted where it matters.

!!! info "Adding a page here"
    `python new.py splunk/<name> -t concept` (or `-t playbook` for a scenario write-up) — the file appears in the sidebar automatically.

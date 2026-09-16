---
title: Zeek conn.log
tags:
  - artifact
  - network
---

# Zeek conn.log

<div class="dfir-meta" markdown>
**Category:** network · **OS:** Windows 10/11 · **Last updated:** 2026-09-09
</div>

!!! abstract "In one sentence"
    What this artifact is and why an investigator cares about it.

## What it tells you

- Evidence of execution / file knowledge / user activity / persistence …
- Timestamps available and what each one means

## Location

| Item | Path / Key |
|---|---|
| File | `C:\...` |
| Registry | `HKLM\...` |
| Event log | `Microsoft-Windows-...%4Operational.evtx` |

## Structure & key fields

| Field | Meaning | Notes |
|---|---|---|
|  |  |  |

## How to collect

```powershell
# live collection example
```

```bash
# KAPE / velociraptor / offline example
```

## How to parse

=== "Tool A"

    ```bash
    tool-a -f input -o output.csv
    ```

=== "Tool B"

    ```bash
    tool-b input
    ```

## Analysis tips

!!! tip
    Where people get tricked, common false positives, anti-forensics that affects this artifact.

## Timeline / correlation

Which other artifacts to cross-check against (e.g. Prefetch ↔ Amcache ↔ Shimcache ↔ 4688).

## References

- [Link](https://)

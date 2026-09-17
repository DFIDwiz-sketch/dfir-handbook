---
title: Data Discovery & Time
tags:
  - concept
  - splunk
---

# Data Discovery & Working with Time

<div class="dfir-meta" markdown>
**Category:** Splunk · **Last updated:** 2026-09-17
</div>

!!! abstract "In one sentence"
    Before you can hunt you need to know **what data exists, under which names, with which fields, covering which time range** — this page is the ten-minute reconnaissance you run on any new Splunk instance (or a new dataset like BOTSv3), plus the time rules that stop you from searching the wrong day.

## Step 1 — What indexes and sourcetypes exist?

```spl
| eventcount summarize=false index=* | table index, count
```

`eventcount` reads index metadata only, so `index=*` here is cheap and acceptable — it lists every index and its event count without touching events.

```spl
| metadata type=sourcetypes index=botsv3
| eval first=strftime(firstTime,"%Y-%m-%d %H:%M"), last=strftime(lastTime,"%Y-%m-%d %H:%M")
| table sourcetype, totalCount, first, last
| sort - totalCount
```

`metadata` returns each sourcetype's total count and first/last event time straight from the index (instant, any time range). `strftime` converts the epoch numbers into readable dates. The `first`/`last` columns tell you the **time window you must search** — BOTSv3 data lives in August 2018, so a "last 24 hours" search returns nothing.

Faster and more flexible alternative:

```spl
| tstats count, min(_time) as first, max(_time) as last where index=botsv3 by sourcetype, host
| convert ctime(first) ctime(last)
| sort - count
```

`tstats` runs on indexed fields (`sourcetype`, `host`, `source`, `_time`) without reading raw events — use it for "how much of X per host" questions.

## Step 2 — What does one event look like?

```spl
index=botsv3 sourcetype=WinEventLog earliest=0 | head 5
```

`earliest=0` = from the beginning of the index, useful when you don't yet know the dataset's date range. Expand an event and look at the **Interesting Fields** panel on the left — those are the fields Splunk already extracted. Click a field for its top 10 values.

```spl
index=botsv3 sourcetype=WinEventLog earliest=0
| fieldsummary maxvals=10
| table field, count, distinct_count, values
| sort - count
```

`fieldsummary` gives one row per field: how many events have it, how many distinct values, and a sample of values with counts. Run this once per sourcetype and you know what you can `stats by`.

## Step 3 — The sourcetypes that matter for IR

| Sourcetype (typical name) | What | Key fields |
|---|---|---|
| `WinEventLog` / `WinEventLog:Security` / `XmlWinEventLog:Security` | Windows Security log | `EventCode`, `Account_Name`, `Logon_Type`, `Source_Network_Address`, `Logon_ID`, `New_Process_Name`, `Process_Command_Line`, `host` |
| `WinEventLog:System`, `WinEventLog:Application` | System/App logs | `EventCode`, `Service_Name`, `Service_File_Name` (7045), `Message` |
| `XmlWinEventLog:Microsoft-Windows-Sysmon/Operational` | Sysmon | `EventID` (or `EventCode`), `Image`, `CommandLine`, `ParentImage`, `ParentCommandLine`, `User`, `Hashes`, `DestinationIp`, `DestinationPort`, `TargetFilename`, `TargetObject`, `QueryName`, `ProcessGuid` |
| `XmlWinEventLog:Microsoft-Windows-PowerShell/Operational` | PowerShell script block `4104` | `ScriptBlockText`, `Path`, `EventCode` |
| `WinEventLog:Microsoft-Windows-TaskScheduler/Operational`, `…TerminalServices-LocalSessionManager/Operational` | Tasks, RDP sessions | |
| `stream:tcp`, `stream:http`, `stream:dns`, `stream:smb` | Splunk Stream (wire data in BOTS) | `src_ip`, `dest_ip`, `dest_port`, `site`, `uri_path`, `http_user_agent`, `query`, `bytes_in/out` |
| `zeek:conn`, `zeek:dns`, `zeek:http`, `zeek:ssl`, `zeek:files` (or `bro:*:json`, `corelight_*`) | Zeek | see [Network](../network/zeek/index.md) |
| `suricata` | IDS alerts | `alert.signature`, `alert.severity`, `src_ip`, `dest_ip` |
| `osquery:results`, `osquery_results` | osquery | `name`, `columns.*` |
| `aws:cloudtrail` | AWS API | `eventName`, `userIdentity.arn`, `sourceIPAddress`, `errorCode` |
| `o365:management:activity`, `ms:aad:signin`, `ms:o365:reporting:messagetrace` | M365 / Entra | `Operation`, `UserId`, `ClientIP`, `ResultStatus` |
| `linux_secure`, `syslog`, `linux_audit`, `auditd` | Linux auth/audit | `process`, `user`, `src_ip` |
| `iis`, `access_combined`, `nginx:plus:access` | Web server | `cs_uri_stem`, `sc_status`, `c_ip`, `cs_User_Agent` |
| `symantec:ep:*`, `ms:defender:atp:*`, `crowdstrike:events:sensor`, `carbonblack:*` | EDR/AV | vendor-specific |
| `pan:traffic`, `pan:threat`, `cisco:asa`, `fortigate_traffic` | Firewalls | `src`, `dest`, `dest_port`, `action`, `bytes_out` |

Run `metadata` on your own instance and keep *your* table — names vary by add-on.

!!! warning "Sysmon XML without the add-on"
    If `Image`, `CommandLine`, `EventID` are missing from a Sysmon sourcetype, the **Splunk Add-on for Sysmon** (or an equivalent props/transforms) isn't installed — Splunk sees one big XML blob. Quick fix in a lab: install the add-on. Emergency fix in a search: `| spath` or `| rex field=_raw "<Data Name='Image'>(?<Image>[^<]+)"` — see [rex & fields](rex-and-fields.md).

## Step 4 — Field names: `Account_Name` vs `user`, and CIM

The raw Windows field is `Account_Name`; the **Common Information Model (CIM)** name is `user`. Add-ons map raw → CIM at search time (via field aliases and calculated fields), so on a well-configured instance both work. When something returns nothing, check which name exists:

```spl
index=botsv3 sourcetype=WinEventLog EventCode=4624 | head 100
| stats count(Account_Name) as raw, count(user) as cim, count(src_ip) as cim_ip, count(Source_Network_Address) as raw_ip
```

Multivalue gotcha: `4624` and `4688` have **two** `Account_Name` values (Subject and Target). `Account_Name` alone gives both; use `mvindex(Account_Name, 1)` for the target, or the add-on's `user`/`src_user` split.

```spl
index=botsv3 sourcetype=WinEventLog EventCode=4624
| eval subject=mvindex(Account_Name,0), target=mvindex(Account_Name,1)
| stats count by target, Logon_Type, host
```

`mvindex(field, n)` picks the n-th value (0-based) out of a multivalue field. For `4624`, value 0 is the account that *performed* the logon (often `-` or the computer), value 1 is the account that *logged on*.

## Working with time

| Modifier | Meaning |
|---|---|
| `earliest=-24h` | Now minus 24 hours |
| `earliest=-7d@d latest=@d` | From midnight 7 days ago to last midnight (whole days) |
| `earliest=@w1` | Start of this week (Monday) |
| `earliest=-1mon@mon latest=@mon` | Last calendar month |
| `earliest=0` | Everything ever indexed (fine for lab data, never in prod) |
| `earliest="08/20/2018:00:00:00" latest="08/21/2018:00:00:00"` | Absolute, `%m/%d/%Y:%H:%M:%S` |
| `_index_earliest=-1h` | By **index** time (when Splunk received it) — finds late-arriving events |
| `\| where _time > relative_time(now(), "-1h")` | Same idea inside the pipeline |

Snap-to (`@`) units: `s m h d w mon q y`, plus `@w0`…`@w6` for a weekday (`@w1` Monday). Modifiers chain left to right: `-7d@d+9h` = 09:00 seven days ago.

**Time zone:** Splunk stores `_time` as UTC epoch and *displays* it in the **user's time zone** (Settings → Account → Time zone). Windows events already carry UTC; Zeek `ts` is UTC epoch; some app logs are local time with no zone — check `props.conf` `TZ`. In an incident report, state the zone. To display UTC regardless of your profile:

```spl
| eval utc=strftime(_time, "%Y-%m-%dT%H:%M:%SZ")
```

**`_time` vs `_indextime`:** `_time` is when the event *happened*; `_indextime` when Splunk got it. A gap (`eval lag=_indextime-_time`) shows forwarder delays or, in a compromise, hosts that stopped sending logs and then flushed a backlog.

**Grouping by time:**

```spl
| bin _time span=1h        →  then  | stats count by _time, host        (table)
| timechart span=1h count by host                                       (chart, one column per host, top 10 + OTHER)
| timechart span=1h limit=0 useother=f count by host                   (all hosts, no OTHER bucket)
```

`timechart` = `bin` + `stats` + pivot in one go, always bucketed on `_time`. `span=` auto-picks if omitted; set it explicitly for consistent reports.

**Recipes**

```spl
# Log gap detection: hosts that stopped logging (last event per host older than 2 hours)
| tstats latest(_time) as last where index=botsv3 sourcetype=WinEventLog by host
| eval age_h=round((now()-last)/3600,1)
| where age_h > 2
| convert ctime(last)
```

`tstats latest(_time)` is the newest event per host, read from the index without scanning raw data; `age_h` is how many hours ago that was.

```spl
# Business hours vs after hours
index=botsv3 sourcetype=WinEventLog EventCode=4624 Logon_Type=10
| eval hour=tonumber(strftime(_time,"%H")), dow=strftime(_time,"%a")
| eval when=if(hour>=8 AND hour<18 AND NOT dow IN ("Sat","Sun"),"business","after-hours")
| stats count by when, Account_Name
| sort when, - count
```

`strftime(_time,"%H")` gives the hour as text; `tonumber` makes it comparable; `%a` gives the weekday abbreviation; the `if` labels each logon.

```spl
# Sort a specific day's events into a clean timeline
index=botsv3 (sourcetype=WinEventLog OR sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational") host=FYODOR-L
        earliest="08/20/2018:00:00:00" latest="08/21/2018:00:00:00"
| eval what=coalesce(CommandLine, Process_Command_Line, New_Process_Name, Message)
| table _time, sourcetype, EventCode, EventID, User, Account_Name, what
| sort 0 _time
```

`coalesce` picks the first field that exists among several candidates so mixed sourcetypes share one `what` column; `sort 0 _time` orders everything chronologically without the 10 000-row cap.

## References

- [Splunk — Search time modifiers](https://docs.splunk.com/Documentation/Splunk/latest/SearchReference/SearchTimeModifiers)
- [Splunk — About the Common Information Model](https://docs.splunk.com/Documentation/CIM/latest/User/Overview)
- [Splunk Add-on for Sysmon](https://splunkbase.splunk.com/app/5709) · [Splunk Add-on for Microsoft Windows](https://splunkbase.splunk.com/app/742)
- [BOTSv3 dataset](https://github.com/splunk/botsv3)

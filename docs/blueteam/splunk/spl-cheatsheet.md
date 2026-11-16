---
title: SPL Cheat Sheet
tags:
  - tool
  - splunk
  - cheatsheet
---

# SPL Cheat Sheet

<div class="dfir-meta" markdown>
**Category:** Splunk · **Level:** foundations → intermediate · **Last updated:** 2026-09-17
</div>

!!! abstract "In one sentence"
    SPL is a pipeline: the first part **finds events** (index, sourcetype, keywords), every `|` after that **transforms** what came before — filter, compute, group, count, sort, present. Learn ~25 commands and you can do 95% of incident-response work.

## Anatomy of a search

```spl
index=botsv3 sourcetype=WinEventLog EventCode=4625 earliest=-24h latest=now
| eval user=lower(Account_Name)
| stats count by user, src_ip
| where count > 10
| sort - count
| head 20
```

Read it top to bottom: **1)** get failed-logon events (`4625`) from the last 24 hours in the `botsv3` index; **2)** make a lowercase `user` field; **3)** count events per user + source IP; **4)** keep only pairs with more than 10; **5)** biggest first; **6)** top 20. Every line receives the rows the previous line produced.

Rules of thumb: **always name the index** (`index=*` is slow and often forbidden in production); put the most selective terms first (`EventCode=4625` before free text); filter early with the search bar rather than late with `where`; use `stats` instead of `table` on large result sets.

## Search-time filtering (before the first `|`)

| Syntax | Meaning |
|---|---|
| `index=botsv3` | Which index |
| `sourcetype=WinEventLog` · `source="WinEventLog:Security"` · `host=FYODOR-L` | Metadata fields |
| `EventCode=4688` | Field = value (case-insensitive value match for strings) |
| `EventCode IN (4624, 4625, 4648)` | Any of a list |
| `user=admin*` | Wildcard (at end is fast; leading `*admin` is slow) |
| `NOT user=SYSTEM` · `user!=SYSTEM` | Exclude (`NOT field=x` also keeps events *without* the field; `field!=x` drops them) |
| `"cmd.exe /c"` | Phrase (quotes) |
| `mimikatz OR procdump` · `A AND B` (AND is implicit) | Booleans |
| `earliest=-7d@d latest=@d` | Time modifiers — `@d` snaps to midnight; `-7d@d` = midnight seven days ago |
| `earliest="09/15/2026:00:00:00"` | Absolute time |
| `src_ip=10.0.0.0/24` | CIDR works on IP fields |
| `TERM(10.0.0.5)` | Match a raw token exactly, fast, avoids segmentation surprises |
| `CASE(Mimikatz)` | Case-sensitive keyword |

## Commands — the ones you use daily

Each row: what it does, then a copy-ready example.

### Filter & shape rows

| Command | Does | Example |
|---|---|---|
| `search` | Filter again mid-pipeline (same syntax as the search bar) | <code>… &#124; search count &gt; 5 user!=svc*</code> |
| `where` | Filter with an **expression** (functions, comparisons between fields) | <code>&#124; where bytes_out &gt; 10*bytes_in AND like(dest, "10.%")</code> |
| `dedup` | Keep first event per unique value(s) | <code>&#124; dedup user, host</code> · <code>&#124; dedup 3 host sortby -_time</code> |
| `head` / `tail` | First / last N rows | <code>&#124; head 50</code> |
| `sort` | Order rows (`-` = descending; `0` = no 10k limit) | <code>&#124; sort 0 - count, +user</code> |
| `reverse` | Flip order | |
| `fields` | Keep (or `-` remove) columns — speeds things up | <code>&#124; fields _time, host, user, CommandLine</code> · <code>&#124; fields - _raw</code> |
| `table` | Show columns as a table (presentation only) | <code>&#124; table _time host user CommandLine</code> |
| `rename` | Rename fields (wildcards ok) | <code>&#124; rename Account_Name as user, "Source Network Address" as src_ip</code> |
| `regex` | Filter rows by regex on a field | <code>&#124; regex CommandLine="(?i)-enc&#124;-e\s+[A-Za-z0-9+/]{20,}"</code> |

### Compute new fields

| Command | Does | Example |
|---|---|---|
| `eval` | Create/modify a field with functions | <code>&#124; eval MB=round(bytes/1024/1024,2), user=lower(user)</code> |
| `eval` + `if` / `case` | Conditional values | <code>&#124; eval type=case(Logon_Type==10,"RDP", Logon_Type==3,"Network", true(),"Other")</code> |
| `eval` + `coalesce` | First non-null of several fields | <code>&#124; eval user=coalesce(Account_Name, user, User)</code> |
| `eval` + string funcs | `len`, `upper`, `lower`, `substr`, `replace`, `split`, `mvindex`, `trim`, `urldecode` | <code>&#124; eval domain=mvindex(split(query,"."),-2)</code> |
| `eval` + time funcs | `strftime`, `strptime`, `relative_time`, `now()` | <code>&#124; eval day=strftime(_time,"%Y-%m-%d")</code> |
| `eval` + `match` / `like` / `cidrmatch` | Pattern tests (return true/false) | <code>&#124; eval internal=if(cidrmatch("10.0.0.0/8",dest_ip),"yes","no")</code> |
| `rex` | Extract fields with regex named groups | <code>&#124; rex field=CommandLine "-enc\s+(?&lt;b64&gt;[A-Za-z0-9+/=]+)"</code> — see [rex & fields](rex-and-fields.md) |
| `rex mode=sed` | Find/replace in a field | <code>&#124; rex field=user mode=sed "s/^CORP\\\\//"</code> |
| `spath` | Pull fields out of JSON/XML | <code>&#124; spath input=_raw path=Event.EventData.Data{@Name}</code> |
| `lookup` | Enrich from a CSV/KV lookup | <code>&#124; lookup asset_inventory ip as dest_ip OUTPUT owner, criticality</code> |
| `iplocation` | GeoIP | <code>&#124; iplocation src_ip</code> |
| `fillnull` | Replace nulls | <code>&#124; fillnull value="-" user, src_ip</code> |
| `makemv` / `mvexpand` | Split a string into multivalue / one row per value | <code>&#124; makemv delim="," answers &#124; mvexpand answers</code> |
| `convert` | Convert formats (epoch → readable etc.) | <code>&#124; convert ctime(first) ctime(last)</code> |

### Group, count, summarise (the heart of SPL)

| Command | Does | Example |
|---|---|---|
| `stats` | Aggregate over all rows, optionally `by` group | <code>&#124; stats count, dc(dest) as hosts, values(CommandLine) as cmds by user</code> |
| `stats` functions | `count`, `dc` (distinct count), `sum`, `avg`, `min`, `max`, `stdev`, `median`, `perc95`, `values` (unique list), `list` (all, in order), `first`, `last`, `earliest`, `latest`, `range` | <code>&#124; stats earliest(_time) as first, latest(_time) as last, count by host</code> |
| `eventstats` | Same as `stats` but **keeps every row** and appends the result | <code>&#124; eventstats avg(count) as avg_count by user</code> |
| `streamstats` | Running/rolling calculations in row order | <code>&#124; streamstats current=f last(_time) as prev by src, dest &#124; eval gap=_time-prev</code> |
| `timechart` | Aggregate into time buckets (for charts) | <code>&#124; timechart span=1h count by EventCode</code> |
| `bin` (a.k.a. `bucket`) | Round `_time` (or numbers) into buckets, then `stats` | <code>&#124; bin _time span=10m &#124; stats count by _time, src_ip</code> |
| `chart` | 2-D pivot table | <code>&#124; chart count over user by Logon_Type</code> |
| `top` / `rare` | Most / least common values with count and percent | <code>&#124; top limit=20 Image</code> · <code>&#124; rare limit=20 parent_process</code> |
| `tstats` | **Fast** stats on indexed fields / data models / accelerated data | <code>&#124; tstats count where index=botsv3 sourcetype=WinEventLog by _time span=1h, host</code> |
| `transaction` | Group events into sessions by a field + time gap (**slow**; prefer `stats`) | <code>&#124; transaction Logon_ID maxspan=8h</code> |
| `addtotals` / `addcoltotals` | Row/column totals | |

### Combine searches

| Command | Does | Example |
|---|---|---|
| `append` | Glue results of a subsearch below | <code>&#124; append [search index=zeek sourcetype=zeek:conn …]</code> |
| `join` | SQL-style join on a field (limits: 50k rows, slow) | <code>&#124; join type=left uid [search index=zeek sourcetype=zeek:http &#124; fields uid, host, uri]</code> |
| `[ subsearch ]` in the search bar | Use one search's result as the filter for another (10k-row limit) | <code>index=botsv3 sourcetype=WinEventLog [search index=botsv3 EventCode=1102 &#124; fields host]</code> |
| `stats … by` with `OR` | The *fast* alternative to `join`: search both sourcetypes at once and `stats values()` by the shared key | <code>(sourcetype=zeek:conn OR sourcetype=zeek:http) &#124; stats values(host) as http_host, sum(orig_bytes) as up by uid</code> |
| `inputlookup` / `outputlookup` | Read / write a lookup table | <code>&#124; inputlookup known_admins.csv</code> · <code>&#124; outputlookup baseline_ua.csv</code> |
| `map` | Run a search per result row (slow, niche) | |

### Presentation & housekeeping

| Command | Does |
|---|---|
| `fieldsummary` | Per-field stats (count, distinct, top values) — first look at unknown data |
| `metadata type=sourcetypes index=botsv3` | List sourcetypes with first/last time and counts (instant) |
| <code>&#124; tstats count where index=botsv3 by sourcetype</code> | Same, faster and more flexible |
| `eventcount summarize=false index=*` | Event count per index (allowed use of `*` — metadata only) |
| `rest /services/data/indexes` | List indexes |
| `typeof`, `isnull`, `isnotnull` | Type/null checks inside `eval`/`where` |
| `format` | Turn subsearch rows into an `(a OR b OR c)` expression |
| `collect` | Write results into a summary index |

## Patterns you will reuse

**Baseline vs. today (find new things)**

```spl
index=botsv3 sourcetype=WinEventLog EventCode=4688 earliest=-30d@d latest=@d
| stats count by New_Process_Name
| eval period="baseline"
| append [ search index=botsv3 sourcetype=WinEventLog EventCode=4688 earliest=@d
           | stats count by New_Process_Name | eval period="today" ]
| stats values(period) as seen by New_Process_Name
| where mvcount(seen)=1 AND seen="today"
```

The first search lists every process name seen in the 30 days before today, labelled `baseline`; `append` adds today's list labelled `today`; `stats values(period)` merges them into one row per process with the set of labels; a process whose only label is `today` never appeared in the baseline.

**Rarity (long tail)**

```spl
index=botsv3 sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventID=1
| stats dc(host) as hosts, count by Image
| where hosts <= 2
| sort count
```

`dc(host)` counts how many *distinct* machines ran each binary; a program on one or two hosts out of the fleet is worth a look, and the rarest are at the top after `sort count` (ascending).

**Time-bucketed spike**

```spl
index=botsv3 sourcetype=WinEventLog EventCode=4625
| bin _time span=5m
| stats count, dc(Account_Name) as users by _time, Source_Network_Address
| where count > 20
```

`bin` rounds each event's time to the 5-minute bucket it falls in; `stats` then counts failures and distinct accounts per bucket per source; > 20 failures in 5 minutes from one IP is a brute force (many users = spraying).

**First/last seen**

```spl
index=botsv3 sourcetype=WinEventLog EventCode=4624 Logon_Type=10
| stats earliest(_time) as first, latest(_time) as last, count by Account_Name, Source_Network_Address, host
| convert ctime(first) ctime(last)
| sort first
```

`earliest`/`latest` return the first and last timestamp for each group; `convert ctime()` makes them readable; sorting by `first` shows when each RDP source/account pair appeared for the first time — new pairs during the incident window are the interesting rows.

## Speed & etiquette

- Name the index and sourcetype; narrow the time range; put keywords in the search bar not in `where`.
- `fields` early, `table` late. `stats` beats `transaction`; `stats … by key` beats `join`.
- `tstats` for counting on indexed fields (`host`, `source`, `sourcetype`, `_time`, and any field in an accelerated data model) — orders of magnitude faster.
- Avoid leading wildcards (`*admin`) and `index=*`.
- Save useful searches as **Reports**; put the pattern with a placeholder in this handbook.

## References

- [Splunk Search Reference — command list](https://docs.splunk.com/Documentation/Splunk/latest/SearchReference/ListOfSearchCommands)
- [Splunk Quick Reference Guide (PDF)](https://www.splunk.com/en_us/resources/splunk-quick-reference-guide.html)
- [eval functions](https://docs.splunk.com/Documentation/Splunk/latest/SearchReference/CommonEvalFunctions) · [stats functions](https://docs.splunk.com/Documentation/Splunk/latest/SearchReference/CommonStatsFunctions)
- Pages: [Data discovery](data-discovery.md) · [rex & fields](rex-and-fields.md) · [Security searches](security-searches.md) · [Hunting patterns](hunting-patterns.md)

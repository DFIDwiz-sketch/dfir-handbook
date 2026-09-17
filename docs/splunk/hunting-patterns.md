---
title: Hunting Patterns in SPL
tags:
  - concept
  - splunk
  - hunting
---

# Hunting Patterns in SPL

<div class="dfir-meta" markdown>
**Category:** Splunk · **Last updated:** 2026-09-17
</div>

!!! abstract "In one sentence"
    Detection rules look for *known bad*; hunting looks for *unusual* — and "unusual" in SPL is always one of a handful of statistical shapes: rare, new, spiking, regular, long-tailed, or outside the peer group. Learn the shapes once and you can apply them to any field in any log.

## The six shapes

| Shape | Question | Core SPL |
|---|---|---|
| **Rare** | What values occur on very few hosts / very few times? | `stats dc(host) count by X \| where dc <= 2` |
| **New** | What appeared today that never appeared in the baseline? | baseline `stats … by X` + `append` today + `where seen=="today"` (or `outputlookup` baseline) |
| **Spike** | What is far above its own normal? | `timechart` + `eventstats avg stdev` + `where value > avg + 3*stdev` |
| **Regular** | What repeats at a fixed interval? | `streamstats` gap + low `stdev(gap)/avg(gap)` |
| **Long tail** | Least common values of a noisy field | `rare` / `stats count by X \| sort count` |
| **Outlier in peer group** | Which host/user behaves unlike its peers? | `stats by entity` → `eventstats` group stats → z-score |

## 1. Rarity (least-common-value)

```spl
index=botsv3 sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventID=1
| eval proc=lower(replace(Image,".*\\\\","")), parent=lower(replace(ParentImage,".*\\\\",""))
| stats dc(host) as hosts, count, values(host) as where, earliest(_time) as first by parent, proc
| where hosts <= 2 AND count <= 5
| convert ctime(first)
| sort first
```

Group every parent→child pair, count distinct hosts. A pair that exists on ≤ 2 hosts and ran ≤ 5 times is rare in this fleet. `values(host)` names the machines so you can go straight to them. Apply the same to `http_user_agent`, `tls.ja3`, `Service_File_Name`, `TargetObject` (registry paths), `dest_port`, `query` domains.

## 2. New this period (baseline comparison)

**Inline (small data)**

```spl
index=botsv3 sourcetype=WinEventLog EventCode=4624 Logon_Type=10 earliest=-30d@d latest=-1d@d
| eval user=mvindex(Account_Name,1)
| stats count by user, host
| eval period="baseline"
| append [ search index=botsv3 sourcetype=WinEventLog EventCode=4624 Logon_Type=10 earliest=-1d@d
           | eval user=mvindex(Account_Name,1) | stats count by user, host | eval period="today" ]
| stats values(period) as seen, sum(count) as total by user, host
| where mvcount(seen)==1 AND seen=="today"
```

Two searches (30-day baseline, last day), each reduced to `user, host` pairs and labelled; `append` stacks them; `stats values(period)` per pair shows whether the pair existed in either, both, or only today. Only-today pairs = **first RDP logon of this user to this host**.

**With a lookup (production pattern)**

```spl
# nightly saved search
index=botsv3 sourcetype=WinEventLog EventCode=4624 Logon_Type=10 earliest=-1d@d latest=@d
| eval user=mvindex(Account_Name,1)
| stats min(_time) as first_seen by user, host
| inputlookup append=t rdp_baseline.csv
| stats min(first_seen) as first_seen by user, host
| outputlookup rdp_baseline.csv

# hunting search
index=botsv3 sourcetype=WinEventLog EventCode=4624 Logon_Type=10 earliest=-1d@d
| eval user=mvindex(Account_Name,1)
| lookup rdp_baseline.csv user, host OUTPUT first_seen
| where isnull(first_seen)
```

The nightly search merges today's pairs into the CSV (keeping the earliest date); the hunting search flags pairs the CSV doesn't know. Same pattern for new services, new scheduled tasks, new user agents, new destination ASNs, new parent/child pairs.

## 3. Spikes (self-baseline)

```spl
index=botsv3 sourcetype=WinEventLog EventCode=4625
| timechart span=1h count by host limit=0 useother=f
| untable _time host count
| eventstats avg(count) as avg, stdev(count) as sd by host
| eval z=round((count-avg)/if(sd=0,1,sd),1)
| where count > 20 AND z > 3
| sort - z
```

`timechart` makes one column per host, one row per hour; `untable` turns that wide table back into long rows (`_time, host, count`); `eventstats` computes each host's own average and standard deviation across all hours and writes them onto every row; `z` is how many standard deviations this hour is above that host's normal. Requiring both an absolute minimum (`count > 20`) and `z > 3` avoids alerting on 2 → 6.

Same skeleton for: bytes out per host per hour, DNS queries per host, 4688 count per host (a script storm), 5145 share accesses per user, HTTP 404s per source.

## 4. Regularity (beaconing)

```spl
index=botsv3 sourcetype=stream:tcp dest_port IN (80, 443, 8080, 8443)
| eval pair=src_ip.">".dest_ip.":".dest_port
| sort 0 pair, _time
| streamstats current=f last(_time) as prev by pair
| eval gap=_time-prev
| where gap > 0
| stats count, avg(gap) as avg_gap, stdev(gap) as sd_gap, dc(src_ip) as srcs by pair, dest_ip
| eventstats dc(pair) as pairs_to_dest by dest_ip
| eval jitter=round(100*sd_gap/avg_gap,1)
| where count >= 20 AND jitter < 25 AND pairs_to_dest <= 3
| sort jitter
```

`sort 0 pair, _time` orders connections per pair chronologically; `streamstats current=f last(_time)` fetches the previous connection's time for each row; `gap` is the interval; `stats` summarises intervals per pair; `eventstats dc(pair) by dest_ip` counts how many internal hosts talk to that destination at all (rarity); low jitter + few pairs = beacon. Full explanation on [Beaconing & C2](../network/beaconing-c2.md).

## 5. Long tail & stacking

```spl
index=botsv3 sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventID=1
| eval cmd=lower(CommandLine)
| eval cmd=replace(cmd, "[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}", "<guid>")
| eval cmd=replace(cmd, "\d+", "<n>")
| eval cmd=replace(cmd, "c:\\\\users\\\\[^\\\\]+", "c:\\users\\<user>")
| stats count, dc(host) as hosts, values(host) as where by cmd
| sort count
| head 100
```

"Stacking" = normalise, count, read from the bottom. The `replace` calls collapse GUIDs, numbers and user names so that `svchost.exe -k netsvcs -p -s Schedule` on 500 hosts becomes one line, and the odd one-off command floats to the top of the ascending sort. Do the same on `TargetObject`, `Service_File_Name`, `uri_path`, `query`.

## 6. Peer-group outliers

```spl
index=botsv3 sourcetype=stream:tcp
| stats sum(bytes_out) as out by src_ip
| eventstats median(out) as med, perc90(out) as p90, avg(out) as avg, stdev(out) as sd
| eval z=round((out-avg)/sd,1), MB=round(out/1048576,1)
| where out > p90 AND z > 2
| sort - out
```

Compare each host to the whole population: `eventstats` appends the fleet's median, 90th percentile, mean and standard deviation to every row; a host above the 90th percentile *and* more than two standard deviations from the mean is an outlier. Peer groups can be narrower: `by role` after a lookup (`workstation` vs `server`), `by department`, `by subnet`.

## 7. Sequences (A then B within N minutes)

```spl
index=botsv3 (sourcetype=WinEventLog EventCode=4720) OR (sourcetype=WinEventLog EventCode=4732)
| eval acct=coalesce(Member_Name, Account_Name)
| sort 0 host, _time
| streamstats current=f last(EventCode) as prev_code, last(_time) as prev_time by host
| where EventCode==4732 AND prev_code==4720 AND _time-prev_time < 300
| table _time, host, Subject_Account_Name, acct, Group_Name
```

`streamstats` remembers the previous event's code and time per host; a `4732` (added to local group) less than five minutes after a `4720` (user created) on the same host is the backdoor-account sequence. Prefer this to `transaction` — it scales. Other sequences: `4625`×N then `4624` (successful brute force), `5145 ADMIN$` then `7045` (PsExec), Sysmon `11` file create then `1` process create of the same path (drop-and-run), `4104` then Sysmon `3` (script then network).

## 8. Drop-and-run (join on a shared key with stats)

```spl
index=botsv3 sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" (EventID=11 OR EventID=1)
| eval path=lower(coalesce(TargetFilename, Image))
| where match(path, "\\.(exe|dll|ps1|bat|vbs|js|hta|scr)$")
| stats min(eval(if(EventID==11,_time,null()))) as dropped, min(eval(if(EventID==1,_time,null()))) as executed, values(eval(if(EventID==11,Image,null()))) as dropper, values(User) as users by host, path
| where isnotnull(dropped) AND isnotnull(executed) AND executed-dropped < 600
| eval delay_s=executed-dropped
| convert ctime(dropped) ctime(executed)
| sort dropped
```

Instead of `join`, search both event types together and use `stats` with `eval(if(...))` inside the aggregation functions: `min(eval(if(EventID==11,_time,null())))` is "earliest time among the file-create events" and the same for process-create; grouping by `host, path` lines them up. A file executed within ten minutes of being written, with the `dropper` process named, is the payload chain.

## 9. Enrich, then decide

```spl
… | lookup assets ip as src_ip OUTPUTNEW hostname, owner, role
    | lookup threat_ips ip as dest_ip OUTPUTNEW threat_name
    | iplocation dest_ip
    | eval score=0
    | eval score=score+if(isnotnull(threat_name),50,0)
    | eval score=score+if(role="server" AND Logon_Type=10,20,0)
    | eval score=score+if(match(Country,"^(?!Australia$)"),10,0)
    | where score >= 30
```

Additive scoring makes hunting output triage-able: each `eval score=score+if(...)` adds points for a condition; `where score >= 30` is your threshold. Keep the conditions in the handbook as they mature into detections.

## Making hunts repeatable

- Save each hunt as a **Report** with the search name = the question ("New RDP source→host pairs, daily").
- Put stable allow-lists in **lookups**, not in the SPL.
- When a hunt keeps finding true positives, convert it to a scheduled **Alert** (or a Sigma rule) and remove it from the manual list.
- Record in the handbook: question → SPL → expected noise → what a hit looked like.

## References

- [Splunk — streamstats / eventstats](https://docs.splunk.com/Documentation/Splunk/latest/SearchReference/Streamstats)
- [SANS — Threat Hunting with Splunk (whitepapers/webcasts)](https://www.sans.org/webcasts/)
- [Splunk Security Essentials — hunting content](https://splunkbase.splunk.com/app/3435)
- [Active Countermeasures — beacon analysis](https://www.activecountermeasures.com/)
- Pages: [SPL cheat sheet](spl-cheatsheet.md) · [Security searches](security-searches.md) · [Beaconing & C2](../network/beaconing-c2.md)

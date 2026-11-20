---
title: Log Pipeline & SIEM
tags:
  - training
  - blue-team
  - logging
  - siem
---

# Log Pipeline & SIEM { #log-pipeline }

!!! abstract "In one line"
    Between the moment a host writes an event and the moment you search for it, the event is collected, transported, parsed, possibly converted, enriched, normalised, indexed and stored — and any of those steps can add fields, change values, delay it or drop it. This section follows that journey so you can tell original data from pipeline additions, and "nothing happened" from "the pipeline lost it": collection methods, log formats and why structure matters, enrichment, field normalisation and common information models, storage and the log life cycle.

## Reading order { #reading-order }

| # | Page | Key points |
| --- | --- | --- |
| 1 | [Log Collection — the Logging Pipeline, Agents vs Agentless, Windows and Linux Collection Options](collection-methods.md) | Why analysts need the pipeline (unexplained fields, delays, empty results, `host=WEC01`); the blocks source → collection → aggregator → parsing/enrichment → indexing/storage → search/alerting and what each can add, change, delay or drop; two clocks (`@timestamp` vs `event.created`/`event.ingested`, `_time` vs `_indextime`) on a worked timeline; agent vs agentless push/pull; Windows options table; Splunk UF `inputs.conf`/`outputs.conf` (`renderXml`, blacklist, `useACK`, TLS) and NXLog XPath → JSON → TLS line by line; JSON vs syslog-text 4624 and why "Account Name:" breaks regexes; WEF/WEC with `wecutil qc`, the subscription-manager GPO, XPath subscriptions, `wecutil gr` heartbeat, Network Service and the Security channel, `Computer`/`Channel`/`EventRecordID` in forwarded events and the `host=WEC01` trap; agentless `Get-WinEvent -ComputerName`, `wevtutil gl` (`channelAccess`, `maxSize`, rollover maths), reader accounts; pipeline tampering 1102/104/1100/7036/7040/4719 (T1070.001, T1562.001/.002/.006); Linux options, rsyslog TLS + disk queue + `imjournal` line by line, `logger`/`ss` test, journald-only distributions, cron + `journalctl --cursor-file` push; SOC checklist; practice questions |
| 2 | [Log Formats and Structure — Unstructured Logs, CSV, Key-Value, JSON, CEF/LEEF, and Why Your SIEM Is Not Google](formats-structure.md) | Why parsing decides detection (no field = no alert = silent false negative); unstructured syslog lines (`dhclient`, `CRON`/`pam_unix`, `sudo`) read part by part, a named-group regex for `sudo` and four ways it breaks (optional parts, spaces, other programs, reworded messages), parse-failure tags and journal fields; CSV vs key-value vs JSON vs XML on the same record (38/78/96 bytes) with a comparison table; the inserted-column CSV shift, quoting traps, self-describing Zeek `#fields`/`#types`; key-value delimiter problems and log injection (CWE-117); nested JSON process event line by line; CEF header and extension dictionary (`rt`, `src`, `suser`, `act`, `cs1Label`) and escaping, LEEF 1.0 vs 2.0 with custom delimiter; PRI vs event severity; indexing vs full-text search on a Squid line field by field; schema-on-write vs schema-on-read; scoping `sara` → `index=proxy sara` → `index=proxy user=sara` with SPL basics, KQL/Elastic equivalents, leading wildcards and indexed fields; SOC checklist; practice questions |
| 3 | [Enrichment, Normalisation and Storage — Context, Common Information Models, Categorisation, Hot/Warm/Cold and the Log Life Cycle](enrichment-normalization-storage.md) | A bare DNS query vs the same event enriched (resolved IP, newly observed, rank, domain age, TI, host, patch status, user role) field by field; enrichment sources table; ingest-time vs search-time (point-in-time vs current) and which to use for IP-to-host vs threat intel; Splunk `lookup` explained for beginners; correlation of DHCP lease + 4624 LogonType 2 + DNS query with time windows; five names for source IP and the OR-search gap; Splunk CIM / ECS / OCSF / ASIM / UDM comparison; rename vs copy vs search-time alias with `props.conf` `FIELDALIAS`/`EVAL` line by line; value and meaning normalisation (actions, usernames, NAT, 4624 `IpAddress`); the missing-field trap; categorisation of 4624/4625 and sshd into `event.category`/`event.outcome`, OCSF Authentication 3002, tags and coverage gaps (T1110, T1078); like-with-like indexes; retention pressures (M-21-31); hot/warm/cold/frozen tiers; Splunk `indexes.conf` line by line and size-cap eviction; the log life cycle and restores; questions for your SIEM engineer with a `tstats` source-health check; whole-pipeline table; SOC checklist; practice questions |

!!! success "Section complete"
    The log pipeline & SIEM section is complete. Next: **File Analysis** — identifying files by content (`file`, magic bytes, nested files, polyglots, encodings), `strings`, safe handling of suspect files and dangerous file types (executables, scripts, Office, RTF, PDF), hashing and code signatures, and quick triage of good vs bad.

## Things to remember { #must-know }

1. The SIEM's version of an event is not the host's. Know which fields are original and which the pipeline added.
2. Every pipeline has the same jobs: collect, aggregate, parse/enrich, index/store, search/alert. Products only differ in which box does which job.
3. Alerts are scheduled searches. Their delay = collection lag + indexing lag + schedule; look back further than schedule + lag.
4. Compare event time with ingest time before drawing conclusions from timing.
5. Agents filter, buffer, compress and encrypt; agentless pulls need open ports, a reader account everywhere and can lose events to log rollover.
6. Every collection filter is a detection decision. Route low-value data to cheap storage rather than discarding it.
7. Keep Windows events as XML or JSON; syslog text loses structure.
8. WEF: Network Service needs read access to Security, and the real host is in `Computer`, not the collector's name.
9. A quiet host is not a clean host. Alert on missing heartbeats and on 1102, 104, 1100, 4719 and agent service changes.
10. Know whether each enrichment is point-in-time or current, which sources feed each normalised category, and the retention, size cap and freeze behaviour of every index you rely on.

## Related { #related }

- [Windows Logging](../windows-logging/index.md) — how events are produced and structured
- [Linux Logging](../linux-logging/index.md) — syslog, log files and the journal
- [Important Events](../important-events/index.md) — what is most worth collecting
- [Log aggregation](../../network-forensics/part-2/log-aggregation.md)

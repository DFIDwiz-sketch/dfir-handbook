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

!!! info "Coming next"
    Log formats: unstructured vs structured logs, CSV, key-value, JSON and XML, SIEM-centric formats, why structure matters for detection, and why your SIEM is not a search engine. After that: enrichment and correlation, field normalisation and common information models, categorisation, storage and the log life cycle.

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

## Related { #related }

- [Windows Logging](../windows-logging/index.md) — how events are produced and structured
- [Linux Logging](../linux-logging/index.md) — syslog, log files and the journal
- [Important Events](../important-events/index.md) — what is most worth collecting
- [Log aggregation](../../network-forensics/part-2/log-aggregation.md)

---
title: "Part 2 — Core Protocols and Log Aggregation/Analysis"
tags:
  - training
  - network-forensics
---

# Part 2 — Core Protocols and Log Aggregation/Analysis { #part-2 }

!!! abstract "What Part 2 covers"
    It starts with reading the two protocols that appear in almost every case, HTTP and DNS, through an investigator's eyes. After the parts of requests and responses, web server logs, and DNS structure and abuse (fast flux, domain generation algorithms, encrypted DNS), it turns packets into logs with Zeek and works with them in jq. Finally, it covers log aggregation that brings syslog and Windows event logs into one place, and an analysis environment built on the Elastic Stack.

## Lessons { #lessons }

All 14 lessons of Part 2 are published. Reading in order is recommended, but the lab guides (lessons 2.4, 2.9 and 2.14) can be tried right after skimming the lessons just before them.

| Lesson | Topic | Status |
| --- | --- | --- |
| [2.1](http-requests.md) | Reading HTTP requests: methods, URIs, request headers | Published |
| [2.2](http-responses.md) | Reading HTTP responses: status codes, response headers, investigative use | Published |
| [2.3](tracking-cookies-http2-http3.md) | Seeing the past through tracking cookies, and HTTP/2 and HTTP/3 | Published |
| [2.4](lab-http-profiling.md) | Lab guide: HTTP profiling | Published |
| [2.5](web-server-logs.md) | Web server logs: formats, reading them, traces of attacks | Published |
| [2.6](dns-structure.md) | DNS structure: records, messages, compression, hierarchy | Published |
| [2.7](dns-investigation.md) | DNS investigation: logs, fast flux, DGAs, encrypted DNS, punycode | Published |
| [2.8](zeek.md) | Turning packets into logs with Zeek: log structure, jq, Community ID | Published |
| [2.9](lab-dns-profiling.md) | Lab guide: DNS profiling, anomalies and scoping | Published |
| [2.10](syslog.md) | syslog: daemon and protocol, facility and severity, reading configuration | Published |
| [2.11](windows-event-logs.md) | Windows event logs and event forwarding | Published |
| [2.12](log-aggregation.md) | Log aggregation: why collect, and how to ship | Published |
| [2.13](elastic-stack-sof-elk.md) | The Elastic Stack and SOF-ELK | Published |
| [2.14](lab-log-aggregation.md) | Lab guide: log aggregation and analysis | Published |


## Wrapping up Part 2 { #wrap-up }

After Part 2 you should be able to:

- Read each part of HTTP requests and responses (methods, headers, status codes, cookies) with an investigator's eye, and know what is and isn't visible in HTTP/2 and HTTP/3 (lessons 2.1–2.3).
- Separate people from programs by header combinations, time of day and intervals, and see beyond the evidence period with advertising cookies (lesson 2.4).
- Know web server log formats and their pitfalls (reception time, size fields, escaping) and find traces of attacks (lesson 2.5).
- Understand DNS messages, compression, hierarchy and caching, and — allowing for how vantage points change what's visible — find fast flux, DGAs, tunnelling, encrypted DNS and look-alike domains (lessons 2.6–2.7 and 2.9).
- Turn pcaps into logs with Zeek, select and link them with jq, and move between tools with Community ID (lesson 2.8).
- Know the format, timestamp and transport limits of syslog and Windows event logs, and find scrubbed traces using central copies (lessons 2.10–2.12).
- Load multiple sources into the Elastic Stack (SOF-ELK), check that everything arrived and that time zones align, then tie the whole incident together from one clue (lessons 2.13–2.14).

Each lesson's outputs were produced with the tool versions stated in that lesson; changes are marked **[Changed]** and corrections **[Correction]**.

## Back to the series { #back }

[Network Forensics home](../index.md)

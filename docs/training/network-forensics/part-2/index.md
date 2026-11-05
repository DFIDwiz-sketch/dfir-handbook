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

Lessons are added one at a time, in order. Entries in the list below without a link are still being prepared. Numbering may shift slightly with length.

| Lesson | Topic | Status |
| --- | --- | --- |
| [2.1](http-requests.md) | Reading HTTP requests: methods, URIs, request headers | Published |
| [2.2](http-responses.md) | Reading HTTP responses: status codes, response headers, investigative use | Published |
| [2.3](tracking-cookies-http2-http3.md) | Seeing the past through tracking cookies, and HTTP/2 and HTTP/3 | Published |
| [2.4](lab-http-profiling.md) | Lab guide: HTTP profiling | Published |
| 2.5 | Web server logs: formats, reading them, traces of attacks | In preparation |
| 2.6 | DNS structure: records, messages, compression, hierarchy | In preparation |
| 2.7 | DNS investigation: logs, fast flux, DGAs, encrypted DNS, punycode | In preparation |
| 2.8 | Turning packets into logs with Zeek: log structure, jq, Community ID | In preparation |
| 2.9 | Lab guide: DNS profiling, anomalies and scoping | In preparation |
| 2.10 | syslog: daemon and protocol, facility and severity, reading configuration | In preparation |
| 2.11 | Windows event logs and event forwarding | In preparation |
| 2.12 | Log aggregation: why collect, and how to ship | In preparation |
| 2.13 | The Elastic Stack and SOF-ELK | In preparation |
| 2.14 | Lab guide: log aggregation and analysis | In preparation |

## Back to the series { #back }

[Network Forensics home](../index.md)

---
title: Linux Logging
tags:
  - training
  - blue-team
  - linux
  - logging
---

# Linux Logging { #linux-logging }

!!! abstract "In one line"
    Linux servers, and almost every firewall, switch and appliance, log in syslog: a short standard header plus free text, with no event IDs, labelled only by facility and severity, routed by a daemon (rsyslog, syslog-ng or journald) into files or across the network. Knowing what "syslog" really means at each layer — format, daemon, protocol — and where the logs end up on disk is what lets you tell "nothing happened" from "nothing was recorded, kept or forwarded".

## Reading order { #reading-order }

| # | Page | Key points |
| --- | --- | --- |
| 1 | [Syslog — How Linux Logging Differs, the Three Meanings of “Syslog”, Message Format, Network Transport, Daemons, Facility and Severity](syslog.md) | Linux vs Windows logging (no event IDs, free text, facility/severity, journald), "syslog" = format / daemon / protocol, RFC 3164 header field by field (no year or zone, T1110), regex extraction and why it breaks, key=value and JSON messages, `logger` forgery, T1070.002/T1562.006, RFC 5424 header with structured data; transports (UDP 514, TCP, TLS 6514 with RFC 9662, DTLS, RFC 3195/6587/5848 correction), size limits and truncation, `tcpdump` capture with `<PRI>` read line by line, why plain UDP is risky, RELP; syslogd, syslog-ng (One Identity, AxoSyslog), rsyslog, Debian 12 without rsyslog; rsyslog selectors and TLS `omfwd` with queues line by line, `rsyslogd -N1`, syslog-ng blocks; facility and severity tables, `auth` vs `authpriv`, PRI = facility × 8 + severity with worked examples, why facility and severity aren't trustworthy, SOC checklist, practice questions |

!!! info "Coming next"
    The traditional log path into `/var/log` and the common log files (`auth.log`/`secure`, `syslog`/`messages`, `kern.log`, `cron`, `wtmp`/`btmp`/`lastlog`), the systemd journal and `journalctl`, command-line logging — then a section summary.

## Things to remember { #must-know }

1. "Syslog" is three things: the message format, the daemon on the host, and the network protocol. Problems — and fixes — live in different layers.
2. The classic header has no year and no time zone, and the message is free text: parsers are regexes that break silently, and a broken parser looks like "no attacks".
3. Plain UDP 514 loses and leaks messages and accepts forgeries. Forward security logs over TLS (6514) with certificate checks and disk-backed queues.
4. PRI = facility × 8 + severity; decode with ÷ 8 and remainder. Facility and severity are the sender's claims, and authentication events are only `info`.
5. Don't assume `/var/log/auth.log` exists — Debian 12 and later are journald-only by default — and alert when a source goes silent.

## Related { #related }

- [Windows Logging](../windows-logging/index.md) — the structured, event-ID-based model to compare against
- [Linux Logs, Processes & Live Triage](../../../linux/logs-and-triage.md)
- [Linux Authentication & Shell History](../../../linux/auth-and-history.md)

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
| 2 | [Linux Log Files and the systemd Journal — the Traditional Log Path, Files Worth Collecting, journalctl, Command-Line Logging and a Section Summary](log-files-journal.md) | Traditional path program → `/dev/log` → syslog daemon → `/var/log` and a collector, CRON/PAM, NetworkManager and dhclient lines read (T1053.003); journald owning `/dev/log`, stdout capture, rsyslog via `imjournal`/`imuxsock`, no files without rsyslog; Debian vs Red Hat file map (`auth.log`/`secure`, `syslog`/`messages`, `kern.log`, `cron`, `audit.log`, `ufw.log`, Apache/Nginx, MySQL, dpkg/dnf), correction on `/var/log/audit/` paths; auth log read line by line (T1110, key fingerprint T1098.004, sudo fields, `su`, T1105/T1572), OpenSSH 9.8 `sshd-session`; UFW and Apache combined lines field by field; binary `wtmp`/`btmp`/`lastlog` with `last -F`, `wtmpdb`/`lastlog2`; logrotate, `zgrep`, `adm` group, T1070.002; the journal (persistent vs `/run/log/journal`, fields, `journald.conf`), `journalctl -u`/`--since` read line by line (stopped sensor T1562.001) and option table; trusted `_` fields exposing a `logger` forgery in `json-pretty`; forwarding options, sealing; auditd `execve` rule and SYSCALL/EXECVE records (`auid`), Sysmon for Linux XML, `logger` for scripts, Snoopy, T1070.003; section summary; SOC checklist; practice questions |

!!! success "Section complete"
    The Linux logging section is complete. Next: **Important Events** — the Windows and Linux events every analyst must know: logins (4624/4625, logon types, 4648), process creation (4688, auditd, Snoopy), firewall and object access, services and scheduled tasks, USB, account changes, Defender and PowerShell, and Kerberos.

## Things to remember { #must-know }

1. "Syslog" is three things: the message format, the daemon on the host, and the network protocol. Problems — and fixes — live in different layers.
2. The classic header has no year and no time zone, and the message is free text: parsers are regexes that break silently, and a broken parser looks like "no attacks".
3. Plain UDP 514 loses and leaks messages and accepts forgeries. Forward security logs over TLS (6514) with certificate checks and disk-backed queues.
4. PRI = facility × 8 + severity; decode with ÷ 8 and remainder. Facility and severity are the sender's claims, and authentication events are only `info`.
5. Don't assume `/var/log/auth.log` exists — Debian 12 and later are journald-only by default — and alert when a source goes silent.
6. File names differ by family (`auth.log`/`secure`, `syslog`/`messages`); `wtmp`/`btmp`/`lastlog` are binary; rotation keeps local history short. Only what has left the host is safe.
7. The journal is structured and its `_` fields (`_UID`, `_COMM`, `_EXE`, `_SYSTEMD_UNIT`) are set by journald, not the sender — they expose forged lines, but are lost if you forward only plain syslog. Make the journal persistent.
8. Built-in logs don't record commands: add auditd, Sysmon for Linux, Snoopy or EDR — and verify it's parsed. A log you can't parse is a log you can't alert on.

## Related { #related }

- [Windows Logging](../windows-logging/index.md) — the structured, event-ID-based model to compare against
- [Linux Logs, Processes & Live Triage](../../../linux/logs-and-triage.md)
- [Linux Authentication & Shell History](../../../linux/auth-and-history.md)
- [Linux Persistence](../../../linux/persistence.md)

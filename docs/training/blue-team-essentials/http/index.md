---
title: HTTP
tags:
  - training
  - blue-team
  - http
---

# HTTP { #http }

!!! abstract "In one line"
    Web pages, email, messaging and malware all ride on HTTP. Reading one request line and a handful of headers properly catches a surprising number of web shells, phishing pages and C2 beacons. In 2026, though, almost all web traffic is HTTPS, so paths, parameters and headers now come mainly from **proxy (TLS inspection), web server, WAF and EDR logs**.

## Reading order { #reading-order }

| # | Page | Key content |
| --- | --- | --- |
| 1 | [Web Servers, URLs and GET](web-servers-urls-get.md) | Order-and-delivery model, document root, web shells with Event 4688 / Sysmon 1, module backdoors, URL anatomy (`@`, `#`, `%`, `file://`), Zeek http.log, GET logging, SQL injection, path traversal, C2 beacons, practice questions |
| 2 | [POST, Other Methods and Request Headers](post-methods-headers.md) | POST and logging, malware and web-shell POSTs, CONNECT/HEAD/OPTIONS/PUT/DELETE/TRACE, Host, User-Agent, Referer, Cookie, Accept, X-Forwarded-For, header-order fingerprints, practice questions |

## Ten things to remember { #must-know }

1. A web server is file sharing. The URL path maps onto a disk path, and one file dropped into an executable folder becomes a web shell.
2. Web-shell signal: the web server process spawns `cmd.exe` / `powershell.exe` (4688, Sysmon 1).
3. Read domains right to left. In a URL, whatever follows `@` is the real destination, and anything after `#` never reaches the logs.
4. Decode `%` encoding and Base64. Wrapping is not encryption.
5. GET puts data in the address, POST puts it in the body. The address gets logged; the body usually doesn't.
6. Not in the log ≠ didn't happen. Look for host logs, WAF and full packet capture.
7. Inbound PUT + 2xx + executable file type = check for a web-shell upload first.
8. Anyone can fake User-Agent and X-Forwarded-For. Trust only values your own devices added.
9. A cookie is a login wristband. Steal it and MFA doesn't help.
10. Look at patterns (interval, order, surrounding requests), not single lines. Don't block CDN IPs — block the domain.

## Related reference pages { #related }

- [Zeek http.log](../../../network/zeek/http-log.md) — field-by-field
- [Beaconing & C2 detection](../../../network/beaconing-c2.md) — regular-interval connections
- [HTTP status codes](../../../basics/http-status-codes.md) — response codes
- [Windows event logs](../../../windows/event-logs.md) — 4688 and Sysmon events
- [Web shell / server playbook](../../../playbooks/webshell-server.md) — web-shell response flow

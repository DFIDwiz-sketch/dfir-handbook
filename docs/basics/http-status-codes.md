---
title: HTTP Status Codes
tags:
  - concept
  - basics
  - network
---

# HTTP Status Codes

<div class="dfir-meta" markdown>
**Category:** basics · **Last updated:** 2026-09-09
</div>

!!! abstract "In one sentence"
    The first digit tells you the class; in log analysis the *pattern* of codes (bursts of 401/403/404, a lonely 200 after hundreds of 404s) often matters more than any single code.

## Classes

| Class | Meaning | Analyst's read |
|---|---|---|
| 1xx | Informational | Rare in logs. `101` = WebSocket upgrade (C2 over WebSockets exists) |
| 2xx | Success | Request worked. A `200` to a weird path = the thing exists |
| 3xx | Redirection | Follow the `Location` header. Redirect chains are classic in phishing / malvertising |
| 4xx | Client error | Scanning, brute force, broken bots |
| 5xx | Server error | Crash, misconfig, or a successful exploit blowing up the app |

## The ones you will actually see

| Code | Name | DFIR notes |
|---|---|---|
| 200 | OK | Normal. Watch **response size** — a 200 with 0 bytes or an unusual fixed size can be a C2 heartbeat |
| 201 | Created | Upload succeeded (WebDAV PUT, API) |
| 204 | No Content | Common for beacon/telemetry check-ins |
| 206 | Partial Content | Range requests — media streaming, but also chunked exfil/download |
| 301 | Moved Permanently | |
| 302 | Found (temporary redirect) | Login flows, phishing redirectors, ad networks |
| 304 | Not Modified | Cached; client already had it |
| 307 / 308 | Temporary / Permanent redirect (method preserved) | |
| 400 | Bad Request | Malformed request — fuzzing, exploit attempts, broken tooling |
| 401 | Unauthorized | Auth required / failed. Bursts = credential brute force (Basic/NTLM) |
| 403 | Forbidden | Authenticated but not allowed, or WAF block. Dir-busting shows as many 403/404 |
| 404 | Not Found | Hundreds in a row from one IP = directory brute force (gobuster, dirb, feroxbuster) |
| 405 | Method Not Allowed | e.g. `PUT` to a server that does not allow it — probing for upload |
| 407 | Proxy Authentication Required | Corporate proxy. Malware that cannot do proxy auth stalls here |
| 408 | Request Timeout | |
| 413 | Payload Too Large | Upload attempt bigger than allowed |
| 418 | I'm a teapot | RFC 2324. If you see this, someone is having fun |
| 429 | Too Many Requests | Rate limiting kicked in — someone was hammering |
| 500 | Internal Server Error | App crashed. After a suspicious request → possible exploit |
| 501 | Not Implemented | |
| 502 | Bad Gateway | Reverse proxy could not reach the backend |
| 503 | Service Unavailable | Overload / maintenance / DoS |
| 504 | Gateway Timeout | |

## Patterns worth alerting on

| Pattern | Likely meaning |
|---|---|
| One source, many `404` in seconds, varied paths | Directory / file brute force |
| One source, many `401` to the same path | Password spraying / brute force |
| `200` to `/wp-login.php`, `/admin`, `/.git/`, `/.env` | Exposed sensitive resource — check what was returned |
| `PUT`/`POST` → `201` then `GET` same path → `200` | Web shell upload and first use |
| Regular-interval `GET` with identical small `200` | Beaconing (check jitter, User-Agent, URI entropy) |
| `500` immediately after a request containing `'`, `../`, `${jndi:`, `<script` | Exploit attempt that hit something |

## Looking these up quickly

=== "Zeek http.log"

    ```bash
    # status code distribution per source
    zeek-cut id.orig_h status_code < http.log | sort | uniq -c | sort -rn | head
    ```

=== "Splunk"

    ```spl
    index=web sourcetype=access_combined
    | stats count by clientip, status
    | where status>=400
    | sort - count
    ```

=== "Apache / Nginx access log"

    ```bash
    awk '{print $9}' access.log | sort | uniq -c | sort -rn
    ```

## References

- [MDN — HTTP response status codes](https://developer.mozilla.org/en-US/docs/Web/HTTP/Status)
- [RFC 9110 — HTTP Semantics](https://www.rfc-editor.org/rfc/rfc9110)

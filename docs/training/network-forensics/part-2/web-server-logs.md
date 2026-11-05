---
title: "2.5 — Web Server Logs: Formats, Reading Them, Traces of Attacks"
tags:
  - training
  - network-forensics
  - http
  - logs
---

# 2.5 — Web Server Logs: Formats, Reading Them, Traces of Attacks { #web-server-logs }

!!! abstract "Scope of this lesson"
    - Why web server logs are special in investigations: even for HTTPS, **server logs are plaintext**
    - Common formats: NCSA Common, Common+VHost, Combined, Apache `mod_log_forensic`, IIS's formats
    - Reading the fields one by one, and the pitfalls confirmed by running Apache 2.4.58: the time is when the request was **received**, so lines appear out of order; the size field means different things per distribution; the virtual-host field isn't the requested name; failed logins still record the username
    - [Correction] "W3C Extended" and "Combined" are different formats, and non-printable characters are written as `\xhh`, not `+`
    - Analysing with the shell: the source material's four commands run on real logs
    - Traces of attacks: reconnaissance, SQL injection attempts, remote administration tools

!!! note "Lab environment and notation"
    **(Actual output)** came from **Apache 2.4.58 (Ubuntu package)** installed in this environment. I created a practice virtual host (`www.lab.example`, alias `portal.lab.example`) on port 8080 and configured it to write the same requests in several log formats at once. The search CGI is a **practice script** made to return 500 deliberately when it sees a quote; there's no real database. All requests were sent with `curl` from the same computer, so the source appears as `127.0.0.1`. IIS couldn't be run here and was checked through documentation only.

## 1. Why web server logs are special { #why-server-logs }

Web server logs are as old as web servers. Their original purpose is unchanged: usage reports (how much was transferred, how many pages served) and records for fixing server and content errors. Yet in incidents involving a web server, these logs often become the most important evidence, because they record line by line everything from automated and manual **reconnaissance**, to the **attack** itself, to **the moment of compromise** (SQL injection, say), to **post-compromise operations**. With attacks using remote administration tools (RATs), every one of the attacker's commands may be recorded as a request line.

Compared with lesson 1.3's proxy logs: proxy logs record **our staff going out**, and web server logs record **outsiders coming in to our server**. The same HTTP, seen from the other side.

And web server logs have one big advantage: **HTTPS requests are recorded in plaintext too**. The web server is the TLS endpoint, so it writes the log **after** decrypting the request and knows the result **before** encrypting the response ("one end of the connection" from lesson 1.12). Even when packet sensors saw only encrypted bytes, the server log has the method, path, query and status code. Such logs are often the investigator's only window onto web activity: logs from web servers, caching proxies, and network security monitoring tools like lesson 2.8's Zeek. Those logs are all created from network communication, so what lessons 2.1–2.4 taught with packets carries straight over to log analysis.

## 2. Common formats { #formats }

There are many web server programs, but log formats converge on a few. Most servers offer standard formats as options, plus a way to define your own (templates).

| Server | Main formats |
| --- | --- |
| Apache | NCSA Common, Common+VHost, Combined, separate Referer and User-Agent logs, custom definitions via format strings, `mod_log_forensic` |
| IIS | **W3C extended format (default)**, IIS format, NCSA Common, centralised binary logging (CBL), ODBC (database) |
| nginx | `combined` (a predefined format), custom definitions via `log_format` |

nginx isn't in the source material, but it's very widely used today, so it's included. nginx's predefined `combined` format uses the same field order as Apache's Combined.

## 3. NCSA Common: the basic seven fields { #common }

The most basic format is **Common**, defined by NCSA (the US National Center for Supercomputing Applications), which created much of early web technology. As an Apache format string it's `%h %l %u %t "%r" %>s %b`. Here's a line written by the lab server.

**(Actual output)**

```text
127.0.0.1 - jdoe [05/Nov/2026:07:03:23 +0000] "GET /admin/ HTTP/1.1" 200 11
```

| Field | Format string | Value in this line | Meaning |
| --- | --- | --- | --- |
| 1 | `%h` | `127.0.0.1` | the requester's address (or host name, depending on configuration) |
| 2 | `%l` | `-` | remote user name (identd). Almost always `-` today |
| 3 | `%u` | `jdoe` | user name from HTTP authentication (Basic etc.). Form logins don't count |
| 4 | `%t` | `[05/Nov/2026:07:03:23 +0000]` | the time the request was **received**, with time zone |
| 5 | `"%r"` | `"GET /admin/ HTTP/1.1"` | the request line as-is: method, request target (including query, no host name), version |
| 6 | `%>s` | `200` | the **final** status code (after internal redirects) |
| 7 | `%b` | `11` | bytes in the response **body** (excluding headers); `-` if zero |

Missing values are filled with `-`. Like lesson 1.3's Squid logs, it can be read by field position, which suits `awk`. Now let's confirm the pitfalls hidden in these seven fields.

### 3.1 The time is "received", the lines are in "finished" order { #out-of-order }

In the lab I sent a request that takes three seconds (`/cgi-bin/slow.cgi`) first, then other requests in the meantime.

**(Actual output, surrounding lines only)**

```text
127.0.0.1 - - [05/Nov/2026:07:03:22 +0000] "GET / HTTP/1.1" 200 29
127.0.0.1 - - [05/Nov/2026:07:03:23 +0000] "GET /index.html HTTP/1.1" 200 29
...
127.0.0.1 - - [05/Nov/2026:07:03:23 +0000] "GET /.git/config HTTP/1.1" 404 277
127.0.0.1 - - [05/Nov/2026:07:03:22 +0000] "GET /cgi-bin/slow.cgi HTTP/1.1" 200 17
```

The `slow.cgi` line is **last**, yet its time, **07:03:22**, is earlier than the lines before it. `%t` is when the request was received, but the log line is written **after** the request finishes, exactly as the source material warns. Remember that lesson 1.3's Squid did the opposite and recorded **the completion time** (start = completion − elapsed). Even among "web logs", the meaning of the time differs.

**What it means for investigations:** building a timeline in line order is wrong. You must **re-sort** by the time field, and the longer a request took (large downloads, slow uploads, long-held connections), the further its line position strays from its time. Including `%D` (elapsed microseconds) in the format lets you calculate both start and end.

### 3.2 Size fields: `%b` and `%O`, and distribution defaults { #size-fields }

I also recorded the same requests in a format writing both `%b` and `%O`.

**(Actual output, some fields)**

```text
"GET / HTTP/1.1"            200  29      256
"GET /dataset.bin HTTP/1.1" 206  50000   50304
"GET /dataset.bin HTTP/1.1" 200  200000  200249
```

- `%b` (middle column) is the size of the response **body**: 29 for a 29-byte page.
- `%O` (right column) is the bytes **actually sent, including headers**, counted by `mod_logio`: 256 for the same page.
- **206 (partial content):** requesting only bytes from 150,000 onwards of a 200,000-byte file with `curl -r 150000-`, `%b` was **50,000**. As the source material says, with resumed downloads this value is not "the file size" but **the size of the part sent by that request**. Be careful when matching it against file sizes on disk.

!!! warning "[Supplement] Ubuntu's `combined` uses `%O`, not `%b`"
    The Combined format in upstream Apache documentation uses `%b` as its size field, but the `combined` predefined by this environment's Ubuntu package is `"%h %l %u %t \"%r\" %>s %O ..."`, using **`%O`** (confirmed directly in `/etc/apache2/apache2.conf`). So even logs called "combined" record the size as **body only** (29) or **including headers** (256) depending on the distribution. When you receive logs, check the server's **`LogFormat` definitions in its configuration file** before interpreting numbers. Lesson 1.2's "the configuration file is evidence" applies here too.

### 3.3 [Correction] Non-printable characters are written as `\xhh` { #escaping }

The source material says non-printable characters are in most cases replaced with `+`. Testing Apache 2.4 directly showed otherwise. I sent a User-Agent containing a tab, quotes and Korean text, and a request line containing a control character (`\x01`).

**(Actual output)**

```text
"GET /index.html HTTP/1.1" 200 256 "-" "tab\there \"quoted\" \xed\x95\x9c\xea\xb8\x80"
"GET /a\x01b HTTP/1.1" 400 489 "-" "-"
```

The tab was **escaped** as `\t`, the quotes as `\"`, the UTF-8 bytes of the Korean word "한글" as `\xed\x95\x9c\xea\xb8\x80`, and the control character as `\x01`. Apache's documentation also says non-printable characters in the request line and header values are written as `\xhh`, a safeguard against attackers injecting fake lines into logs. For investigations, remember two things. ① When searching logs for keywords, also search for **the escaped form** (a Korean User-Agent appears only as `\xed...`). ② A request line containing control characters is itself a sign it didn't come from a normal browser; this request got a 400.

## 4. Common+VHost and Combined { #vhost-combined }

### 4.1 [Caution] The virtual-host field is not "the requested name" { #vhost }

**Common+VHost** prefixes each line with the virtual host name, a format for environments running several sites on one IP (lesson 2.1, section 6.1). Ubuntu's `vhost_combined` starts with `%v:%p`. But a lab request sent with `Host: portal.lab.example` was recorded like this.

**(Actual output)**

```text
www.lab.example:80 127.0.0.1 - - [05/Nov/2026:07:03:23 +0000] "GET /index.html HTTP/1.1" 200 256 "https://search.example/" "..."
```

The requested name was `portal.lab.example`, but the log shows **`www.lab.example:80`**. `%v` is the **canonical name** (`ServerName`) of the virtual host that handled the request, and `%p` is likewise the configured canonical port, not the 8080 actually used. If a virtual host has several aliases (`ServerAlias`), this field can't tell you which name was used. If you need the name the client actually sent, include **`%{Host}i`** (the value of the `Host` request header) in the format. The `mod_log_forensic` log in section 5 kept `Host:portal.lab.example` as-is.

### 4.2 Combined: Referer and User-Agent { #combined }

Originally, Referer and User-Agent were written to **separate files**, so as not to break programs depending on the Common format. Later the **Combined** format, appending both to the end of the line, came into use as a de facto standard.

**(Actual output)**

```text
127.0.0.1 - - [05/Nov/2026:07:03:23 +0000] "GET /index.html HTTP/1.1" 200 256 "https://search.example/" "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36"
```

In investigations the two values are used like this.

- **Looking at our server:** `Referer` tells you **where a click came from** (a link posted on a suspicious forum, say), and the User-Agent tells you **the tool that crawled the site** (reconnaissance copying content to build a convincing phishing page, for example).
- **Looking at our staff (proxy side):** `Referer` links movements within one browser tab, and the User-Agent gives the list of software actually in use in the organisation (lesson 2.4).

The source material also warns that the headers in logs are the values **after modification inside the server** by features like `mod_headers`. If the server configuration rewrites headers, the log may not hold the client's original values. And dropping these two values from logs loses valuable material for investigations.

!!! warning "[Correction] \"W3C Extended\" and \"Combined\" are not the same format"
    The source material calls this format "W3C Extended/Combined" and attributes it to W3C. But they're different. **Combined** is an **NCSA-family** format (Apache's and nginx's default): NCSA Common plus Referer and User-Agent. The **W3C Extended Log File Format** is, as seen in lesson 1.5, a **different** format that declares column names in a `#Fields:` line (IIS's default, some commercial proxies). Reading one with a parser for the other misaligns the fields, so first check whether the file starts with a `#Fields:` line.

### 4.3 [Caution] Failed logins still record the username { #failed-auth }

I requested the Basic-auth-protected `/admin/` once with a valid account (`jdoe`) and once with a nonexistent one (`admin:admin`).

**(Actual output)**

```text
127.0.0.1 - jdoe [05/Nov/2026:07:03:23 +0000] "GET /admin/ HTTP/1.1" 200 11
127.0.0.1 - admin [05/Nov/2026:07:03:23 +0000] "GET /admin/ HTTP/1.1" 401 462
```

In the second line `%u` is `admin`, but the status code is **401**. So `%u` is not "the successfully authenticated user" but **the username the client sent**, recorded even on failure. The error log recorded `AH01618: user admin not found: /admin/` at the same time **(actual output)**. So don't read "`%u` says `admin`, so an administrator logged in"; always read it with the status code. Conversely, the list of `%u` values piling up with 401s is **the list of account names used in a brute-force attempt**.

## 5. Apache `mod_log_forensic`: recording every header { #mod-log-forensic }

Despite its name, `mod_log_forensic` wasn't built for digital forensics, but it records **every request header** for each request. The server is the TLS endpoint, so HTTPS requests are recorded decrypted too. Here's what it produced when enabled.

**(Actual output, the start line of one request)**

```text
+auwqO8D2TYfXTSURFaXOvAAAAAc|GET /index.html HTTP/1.1|Host:portal.lab.example|User-Agent:Mozilla/5.0 (...)|Accept:*/*|Referer:https%3a//search.example/
```

- Lines look like `+unique ID|request line|Header:value|Header:value|...`. The unique ID is a per-request value added by `mod_unique_id`.
- When processing **finishes**, a separate `-unique ID` line is written. In this lab there were 17 `+` lines and 17 `-` lines **(actual output)**. A request during which the server crashed or was cut off has a `+` but no `-`, which helps find the request that brought the server down.
- As section 4.1 noted, **the `Host` actually requested** (`portal.lab.example`) is recorded.
- Special characters within header values are percent-encoded (the `%3a` in `Referer:https%3a//...`).

!!! warning "[Caution] The forensic log records passwords too"
    The line for the `/admin/` request kept `Authorization:Basic amRvZTpTcHJpbmcyMDI2IQ==` verbatim **(actual output)**. As lesson 2.1 showed, Base64 decodes instantly, so this log effectively contains a **plaintext password** (`jdoe:Spring2026!`). Session cookies likewise. It's valuable for investigations, but the log itself is a treasure trove for an attacker. When enabling it, narrow the scope to the virtual hosts or paths needed (which, as the source material suggests, also reduces the performance and disk burden), and set strict access permissions and retention.

## 6. IIS logs { #iis }

IIS couldn't be run here; this is from documentation.

- **The W3C extended format is the default.** A `#Fields:` line selects the fields to record (`date time s-ip cs-method cs-uri-stem cs-uri-query s-port cs-username c-ip cs(User-Agent) sc-status sc-bytes cs-bytes time-taken`, etc.), and according to Microsoft's IIS 6-era documentation, times are written in **UTC**. Read the `#Fields:` line and handle columns by name, the same way as lesson 1.5's ELFF.
- **The IIS format** is a fixed, comma-separated format. The order the source material lists is: requester address, authenticated user, date (two-digit year), time, service name and instance (`W3SVC2` etc.), server name, server IP, processing time (milliseconds), bytes received, bytes sent, status code, Windows error code, method, requested resource, query. A comma follows even the last field. The IIS 6 documentation says this format uses **local time**, so align time zones whenever you mix it with W3C-format logs.
- Unlike Apache's default formats, IIS can record **bytes received (`cs-bytes`) and processing time** by default: exactly the "uploaded volume" that was missing from the logs in lesson 1.4.
- For heavily loaded servers there's also **centralised binary logging (CBL)** and **ODBC** (writing to a database such as SQL Server). Neither is readable directly and needs a query tool; Microsoft's old free **Log Parser** (reading many log formats with SQL-like queries) and its GUI **Log Parser Studio** were commonly used. The documentation also warns that ODBC logging disables the kernel-mode cache and carries a heavy performance cost.

## 7. Analysing with the shell { #shell-analysis }

Logs being text, shell tools handle them directly, even at large scale. I ran the source material's four example commands, adapted to the lab log (Ubuntu's `combined`). Field numbers are whitespace-separated positions, so in Combined format `$1` is the address, `$4` the time, `$7` the request target and `$9` the status code.

**① Addresses that requested a particular resource, by frequency**

```bash
grep '"GET /cgi-bin/search.cgi' lab_combined.log | awk '{print $1}' | sort | uniq -c | sort -nr
```

**(Actual output)** `5 127.0.0.1`

**② Resources requested by one address, by frequency**

```bash
grep '^127.0.0.1 ' lab_combined.log | awk '{print $7}' | sort | uniq -c | sort -nr | head -5
```

The trailing space in `grep '^127.0.0.1 '` excludes addresses with the same prefix, like `127.0.0.10`. In a regex `.` matches any character, so strictly `'^127\.0\.0\.1 '` is correct.

**③ Grouping by hour**

```bash
awk '{split($4,t,":"); print substr(t[1],2)" "t[2]":00"}' lab_combined.log | sort | uniq -c
```

**(Actual output)** `17 05/Nov/2026 07:00`

`$4` is `[05/Nov/2026:07:03:23`; splitting on `:` gives `t[1]` = `[05/Nov/2026` and `t[2]` = `07`, and `substr(t[1],2)` drops the leading `[`. The source material does the same with a `sed` regex, but splitting fields is easier to read. Don't forget this uses **the time zone written in the log** (`+0000`).

**④ Addresses and requests that triggered server errors**

```bash
awk '{print $9, $1, $7}' lab_combined.log | grep -E '^5[0-9]{2}' | sort | uniq -c | sort -nr
```

**(Actual output)**

```text
      1 500 127.0.0.1 /cgi-bin/search.cgi?q=orchid%27%20OR%201=1--
      1 500 127.0.0.1 /cgi-bin/search.cgi?q=orchid%27
      1 500 127.0.0.1 /cgi-bin/search.cgi?q=1%27%20UNION%20SELECT%20user,pass%20FROM%20users--
```

Such commands are endless. Knowing just `awk` and `sed`, you can pull what you need out of large logs quickly, and even build tables for spreadsheets and reports. For logs in a database (CBL, ODBC), you can collect SQL queries into a **repeatable query library**, and tools like lesson 2.13's SOF-ELK read NCSA and Combined formats directly. Remember too that if the organisation has kept logs long-term for business reasons, you can look at records from years ago.

!!! warning "[Caution] `$9` isn't always the status code"
    Splitting fields on whitespace assumes **no spaces inside the request line**. If an attacker sent a malformed request line (multiple spaces, broken quotes), the field numbers shift on that line alone. Apache escapes quotes, as section 3.3 showed, but before drawing important conclusions, re-check by **splitting on quotes** as in `awk -F'"'`, or use a parser that knows the format.

## 8. Traces of attacks in logs { #attack-traces }

The source material summarises when log evidence is especially useful. With the lab log:

**Reconnaissance.** Finding vulnerable web apps via search engines, or blindly probing paths of known vulnerable software.

**(Actual output, partial)**

```text
"GET /phpmyadmin/ HTTP/1.1" 404 ... "Mozilla/5.0 zgrab/0.x"
"GET /phpMyAdmin-2.8.0/scripts/setup.php HTTP/1.1" 404 ... "Mozilla/5.0 zgrab/0.x"
"GET /wp-login.php HTTP/1.1" 404 ...
"GET /.env HTTP/1.1" 404 ...
"GET /.git/config HTTP/1.1" 404 ...
```

As in the source material's example, probing **paths for many versions** of a particular product (`phpMyAdmin-2.8.0`, `-2.8.1`, …) in turn within seconds is the typical shape: lesson 2.2, section 3.3's "storm of 404s".

**SQL injection attempts and success.** Counting status codes together with User-Agents shows the shape.

```bash
awk -F'"' '{split($3,a," "); print a[1], $6}' lab_combined.log | sort | uniq -c | sort -nr
```

Splitting on quotes with `-F'"'`, `$3` is the ` 200 256 ` after the request line (status and size) and `$6` the User-Agent.

**(Actual output)**

```text
      5 404 Mozilla/5.0 zgrab/0.x
      5 200 Mozilla/5.0 (Windows NT 10.0; Win64; x64) ... Chrome/141.0.0.0 Safari/537.36
      3 500 sqlmap/1.8.4#stable (https://sqlmap.org)
      2 200 sqlmap/1.8.4#stable (https://sqlmap.org)
      1 401 Mozilla/5.0 (Windows NT 10.0; Win64; x64) ... Chrome/141.0.0.0 Safari/537.36
      1 206 Mozilla/5.0 (Windows NT 10.0; Win64; x64) ... Chrome/141.0.0.0 Safari/537.36
```

`sqlmap` is the default User-Agent of a well-known SQL injection tool (which can of course be changed). The three requests containing a quote (`%27`) got 500 (section 7's ④). In a real case, look here at ① whether a **200** from the same source follows the 500s, ② whether that 200 response is **unusually large** compared to normal search results (data may have poured out), ③ whether `POST`s or unfamiliar paths follow (post-compromise operations), and ④ database error messages in **the error log**. In this lab the two 200s were ordinary searches without quotes, unrelated to injection success.

**What a known-bad address accessed.** Once threat intelligence gives you an address, section 7's command ② pulls out that address's reconnaissance, attack and post-compromise activity in one go. In accidental-exposure incidents, the log also tells you immediately **who** downloaded the sensitive file, and **when**.

**Remote administration tools (RATs) and web shells.** An attacker plants a web shell on the server and sends commands via requests; if they didn't wipe the logs (or couldn't, because the logs were **collected on another server**, lesson 2.12), their commands remain request line by request line. The source material even cites an investigation that **reassembled** a malicious executable dropped on the server via SQL injection and a series of `echo` commands, from the logs alone. That's how completely data carried in query strings is preserved.

## 9. How to use this in real investigations { #in-practice }

1. **Secure the configuration files along with the logs.** `LogFormat`, `CustomLog`, IIS logging settings. You need the configuration to know what the size and time fields mean.
2. **Re-sort by time.** Line order is completion order. Check time zones too (IIS format local time, W3C format UTC).
3. **Read `%u` with the status code.** Next to a 401, it's just the name tried.
4. **Search in escaped forms too.** `\xhh`, `\"`, percent-encoding.
5. **For the requested name, look at `%{Host}i`.** `%v` is the canonical name.
6. **Treat forensic logs as sensitive.** Split analysis onto copies with authentication headers and cookies masked.
7. **Look at the flow.** Chain reconnaissance (404s), attempts (500s), success (a 200 with a large size) and follow-on operations (unfamiliar paths, POSTs) per source.

## 10. Summary { #summary }

- Web server logs record outsiders coming in to our server, and because the server is the TLS endpoint, **HTTPS requests are recorded in plaintext** too.
- Formats: NCSA Common, Common+VHost, Combined, `mod_log_forensic`, IIS's W3C extended (default), IIS, CBL and ODBC, and nginx's `combined`.
- Common's seven fields: address, identd, authenticated user, time **received**, request line, final status, body size.
- Pitfalls confirmed directly: a slow request is written **last, with an earlier time** (line order ≠ time order); `%b` for a 206 is the part sent (50,000); Ubuntu's `combined` uses `%O` including headers (256 versus 29); `%v` is the canonical name, not the requested one (a `portal` request logged as `www`); and `%u` is recorded on failed logins (401).
- **[Correction]** "W3C Extended" (`#Fields:`) and "Combined" (NCSA family) are different formats, and non-printable characters are written as `\xhh`, `\t`, `\"`, not `+`.
- `mod_log_forensic` records every header and each request's start (`+`) and end (`-`), but also **passwords and cookies**.
- Four shell commands produced counts by resource, address, hour and error, and counting status codes with User-Agents separated reconnaissance (404s) from injection attempts (500s).

## Review questions { #review }

**Question 1. (Reading fields)** Explain each field of the following Common line. What did this request most likely do on the server?

```text
192.0.2.77 - - [03/Nov/2026:02:14:09 +0900] "GET /backup/db_2026-10.sql.gz HTTP/1.1" 200 48211907
```

??? success "Answer and explanation"
    Address `192.0.2.77`, identd `-`, no authenticated user (`-`), received at 2026-11-03 02:14:09 (+09:00, i.e. 2 November 17:14:09 UTC), request line `GET /backup/db_2026-10.sql.gz HTTP/1.1`, final status 200, body 48,211,907 bytes (about 46 MB). What looks like a database backup was most likely downloaded **whole, without authentication**. Check whether the size equals the file size on disk (i.e. not a 206 resume), look at the same address's requests before and after (how did it learn this path: a directory listing, reconnaissance?), and find other addresses that downloaded the same file. Record the small-hours time and the local time zone (+0900) in the report too.

**Question 2. (Time)** Reading a web server log in line order, you built the timeline "login at 10:00:05, large download started at 10:00:07", but the download line's `%t` was 09:58:40. What happened?

??? success "Answer and explanation"
    Apache's `%t` is when the request was **received**, and the line is written **after** the request finishes (section 3.1). So this download **started at 09:58:40** and was a long request that finished only after the login line was written. In fact the download started **before** the login. If the download started independently of the login (i.e. it could be fetched without authentication), the incident's meaning changes considerably. Re-sort the timeline by `%t`, not line order, and if the format has `%D` (elapsed time), calculate and record the end time too.

**Question 3. (Changed conditions)** In one server's "combined" log, the same 29-byte page is recorded as 256, and a colleague says "the log is wrong". What do you check?

??? success "Answer and explanation"
    Check the server's **`LogFormat` definition**. Ubuntu and Debian's Apache packages define `combined` with `%O` (bytes sent including headers), while upstream Apache's Combined uses `%b` (body only) (confirmed directly in section 3.2: 29 versus 256). The log isn't wrong; it's **the same name with a different meaning**. Secure the configuration file with the evidence, and state in the report which definition applies. If you can't get the configuration, you can estimate from a constant difference equal to the response header size, but say it's an estimate.

**Question 4. (Common misconception)** "The first field of every line in the `vhost_combined` log is `shop.example.com`, so the attacker connected only under that name." What may be wrong?

??? success "Answer and explanation"
    `%v` is the **canonical name** (`ServerName`) of the virtual host that handled the request. In section 4.1's experiment, a request sent to `portal.lab.example` was logged as `www.lab.example:80`. If the virtual host has aliases, or requests matching no name were handled by the **default virtual host**, this field can't tell you the name the attacker actually used (a bare IP address, another alias, a random name). If you need the actual `Host` header, look for logs including `%{Host}i`, `mod_log_forensic`, packets (if plaintext), or the front-end equipment's logs.

**Question 5. (Interpretation)** The following two lines are one second apart. What can you tell, and what can't you?

```text
198.51.100.9 - administrator [04/Nov/2026:11:20:01 +0000] "GET /manage/ HTTP/1.1" 401 381
198.51.100.9 - administrator [04/Nov/2026:11:20:02 +0000] "GET /manage/ HTTP/1.1" 200 5120
```

??? success "Answer and explanation"
    **What you can tell:** `198.51.100.9` tried to authenticate as `administrator`, failed once (401) and succeeded one second later (200). As in section 4.3, `%u` is the name sent, so `administrator` on the 401 line is only the name tried; only the 200 line shows a **successful authentication** under that name. **What you can't:** whether the first attempt's password was wrong, or whether it was the **normal flow** of a browser requesting without credentials first, getting a 401 and resending with an account. With Basic authentication, a browser getting a 401 and popping up a login box is a common shape, so one 401 followed by a 200 may be normal. Dozens of 401s piling up before it would be brute force. Also check whether the source is that account's usual location.

**Question 6. (Corrected content)** To find requests with Korean text in the User-Agent, you ran `grep '한국'` on the log and got nothing. Why might that be, and how should you search?

??? success "Answer and explanation"
    Apache 2.4 writes non-ASCII bytes in header values escaped as `\xhh` (section 3.3: "한글" was written as `\xed\x95\x9c\xea\xb8\x80`). So the Korean text as such isn't in the log. Search for the UTF-8 bytes of "한국" (`\xed\x95\x9c\xea\xb5\xad`) in their escaped textual form. In the shell, mind the backslashes and search for a fixed string, as in `grep -F '\xed\x95\x9c\xea\xb5\xad'`. More broadly, `grep -F '\x'` pulls out every line containing escapes for decoding. Searching on the assumption that such characters become `+`, as the source material says, misses them.

**Question 7. (Application)** If you could change the log format to support web server compromise investigations, what would you add to Combined? Give a reason for each.

??? success "Answer and explanation"
    For example: ① **`%{Host}i`**: the name actually requested (section 4.1). ② **`%D`**: elapsed time (microseconds), to calculate both start and end and find slow requests (large exfiltration, time-based blind SQL injection) (section 3.1). ③ **`%I`** (bytes received, `mod_logio`): upload volume, the value missing in lessons 1.4 and 1.13. ④ **`%O` and `%b` together**: sizes with and without headers. ⑤ **times with an unambiguous time zone** (`%{%Y-%m-%dT%H:%M:%S}t` with `%{%z}t`, or standardise on UTC): easier to match with other logs. ⑥ **`%{UNIQUE_ID}e`**: a key linking the same request in `mod_log_forensic` or application logs. ⑦ With a front-end proxy, **`%a` together with `%{X-Forwarded-For}i`** (lesson 2.1, section 6.6). Whatever you add, weigh performance, disk and privacy (don't add cookies or authentication headers).

**Question 8. (Interpretation)** Counting 500 errors as in section 7's ④, one address had 40 requests containing quotes that got 500, and right after, one request from the same address to the same path got 200 with a size of 1,843,022 bytes. That search normally returns around 2 KB. What hypothesis do you form, and how do you check it?

??? success "Answer and explanation"
    **Hypothesis:** SQL injection failed repeatedly (500s) and finally **succeeded**, and that response carried a large amount of database content (nearly 900 times the usual size): the source material's "200 after 500s" shape (lesson 2.2, section 3.3). **Check:** ① the query string of that 200 request (does it contain constructs like `UNION SELECT`?), ② database error messages in the error log and the database's own logs at the same time, ③ ways to recover that response's content (packets, front-end equipment records, application logs), ④ the same address's subsequent requests (admin screens, uploads, paths that look like web shells), ⑤ other addresses using the same technique. For damage assessment (lesson 1.11, section 1), work out with the database team which tables left.

**Question 9. (Common misconception)** "`mod_log_forensic` is a forensics feature, so it's best left on on every server at all times." Explain the problem with this claim.

??? success "Answer and explanation"
    Despite its name, the module was built for debugging, and it records **every request header**, so ① the disk and performance burden is large, and ② above all, as section 5 showed, it records **Basic authentication passwords, session cookies and tokens**. If this log leaks, it's a mass credential leak in itself. That's why the source material recommends enabling it narrowly for the virtual hosts or paths needed. If it must be on, pair it with an operating procedure: strict access permissions, short retention, and analysis on copies with sensitive headers masked.

## References { #references }

- Tools used in this environment: Apache 2.4.58 (Ubuntu package; `mod_log_forensic`, `mod_unique_id`, `mod_cgid`, `mod_logio`), curl 8.5.0, GNU awk, grep, sort, uniq. Outputs were obtained on 2026-11-05.
- Apache, [mod_log_config documentation](https://httpd.apache.org/docs/2.4/mod/mod_log_config.html) (`%h %l %u %t %r %>s %b %O %D %v %p %{Host}i`, `\xhh` escaping of non-printable characters, Common and Combined format examples).
- Apache, [mod_log_forensic documentation](https://httpd.apache.org/docs/2.4/mod/mod_log_forensic.html) and [mod_logio documentation](https://httpd.apache.org/docs/2.4/mod/mod_logio.html) (`%I`, `%O`).
- Microsoft, [IIS Log File Formats](https://msdn2.microsoft.com/en-us/library/ms525807.aspx) (IIS 6 documentation, checked through search results on 2026-11-05). W3C extended format as default and in UTC, other formats in local time, the performance warning for ODBC logging.
- nginx, [ngx_http_log_module documentation](https://nginx.org/en/docs/http/ngx_http_log_module.html) (the predefined `combined` format).
- W3C, [Extended Log File Format](https://www.w3.org/TR/WD-logfile.html) (the `#Fields:` directive).

!!! note "About this page"
    A personal study note, rewritten in my own words from several learning resources. The practice server configuration and requests are my own, and the scenarios are hypothetical.

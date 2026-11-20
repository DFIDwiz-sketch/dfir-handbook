---
title: "Log Formats and Structure — Unstructured Logs, CSV, Key-Value, JSON, CEF/LEEF, and Why Your SIEM Is Not Google"
tags:
  - training
  - blue-team
  - logging
  - siem
---

# Log Formats and Structure — Unstructured Logs, CSV, Key-Value, JSON, CEF/LEEF, and Why Your SIEM Is Not Google { #formats-structure }

!!! abstract "What this page covers"
    Why the **format** of a log decides whether it can be used for detection at all. We start with the worst case, the **unstructured** "sentence" log behind a syslog header, and see why parsing it needs a regular expression for every possible message and breaks when programs share a file or developers change wording. Then the **structured** formats — **CSV**, **key-value pairs**, **JSON** (and XML) — compared on size, robustness and nesting, using the same record in each. Then the **SIEM-centric** formats **CEF** and **LEEF**, with every header field and the escaping rules read piece by piece. Finally, why structure matters inside the SIEM: parsing feeds **indexing**, indexing makes search fast, and failed parsing makes rules silently miss (false negatives). We close with how to **scope a search** — log type first, then field — and why a search box that looks like a web search engine does not behave like one. Practice questions with explanations at the end.

!!! note "Labels"
    **[Supplement]** = practical material you need to know, **[Correction]** = a commonly repeated claim that is wrong or outdated, **[Changed]**/**[Caution]** = what has changed recently and what is risky to do the old way. Hostnames, domains, accounts, IPs and file names are invented for illustration (`.example`, documentation and private IPs).

## The 8 key points { #key-points }

1. A log is only useful for detection if the SIEM can **reliably pull the key fields out of it**. Format decides how hard that is.
2. **Unstructured** logs have a predictable syslog header followed by a free-text sentence. Parsing them needs a regular expression for **every message variant** of every program, and those regexes break silently when wording changes.
3. Mixing many programs into one file (for example `/var/log/syslog`) multiplies the problem: each line can come from a different program with a different sentence shape.
4. **CSV** is the most compact, but the reader must already know the **column names and order**; add, remove or reorder a column and every field after it shifts.
5. **Key-value** pairs carry their own field names, so fields can be added, removed or shuffled without breaking parsing — a good middle ground. Watch out for spaces and delimiter characters inside values.
6. **JSON** is the most robust: named fields, data types, **nesting and arrays**. It is also the most verbose. XML has the same power and converts to JSON without losing the hierarchy. For detection data, prefer JSON when you have the choice.
7. **CEF** and **LEEF** are SIEM-oriented formats: a syslog header, a pipe-delimited header that says **which product created the event**, then key-value extensions.
8. Parsing feeds **indexing**; indexing makes searches fast. Scope every search by **log type** and by the **field** you expect the value in — `sara` alone is the slowest and least precise search you can run.

## Why format matters to an analyst { #why }

On the [collection page](collection-methods.md) we followed an event from host to SIEM. One of the boxes on that path was **parsing**: cutting a log line into named fields such as `user`, `src_ip` or `url`. Everything you do afterwards depends on that cut being right. A detection rule that says "alert when `user` is a service account logging in from a workstation" cannot fire if `user` was never extracted. A search for `src_ip=10.20.30.41` returns nothing if the parser put the IP into a field called `message`. Neither failure produces an error. You just get **no result**, which looks exactly like "nothing happened".

Think of it like a filing room. If every letter arrives in a standard form with labelled boxes (*Sender*, *Date*, *Subject*), a clerk can file thousands per hour and find any of them in seconds. If letters arrive as handwritten notes in different styles, the clerk has to read each one and guess where the sender's name is. Some will be misfiled, and a search for "everything from sender X" will quietly miss them. Log formats are the difference between the form and the handwritten note.

## Unstructured logs { #unstructured }

Most Linux and network-device logs start with a **syslog header** whose shape is known (timestamp, host, program and optional PID — see [syslog format](../linux-logging/syslog.md)). After the colon comes the **message**, and the message is whatever sentence the developer chose to write. Here are three lines that could sit next to each other in the same `/var/log/syslog` (or `auth.log`) file:

```
Nov 20 07:23:51 web-07 dhclient[75879]: bound to 10.20.40.17 -- renewal in 703 seconds.
Nov 20 08:17:59 web-07 CRON[55171]: pam_unix(cron:session): session opened for user root(uid=0) by (uid=0)
Nov 20 09:08:01 web-07 sudo:    sara : TTY=pts/2 ; PWD=/var/log ; USER=root ; COMMAND=/usr/sbin/service ssh start
```

Reading them:

- **Line 1.** Header: `Nov 20 07:23:51` (no year, no time zone), host `web-07`, program `dhclient`, PID `75879`. Message: the DHCP client received address `10.20.40.17` and will renew in 703 seconds. The IP and the number are buried in a sentence; nothing labels them.
- **Line 2.** Program `CRON`, PID `55171`. The message itself starts with *another* program's tag, `pam_unix(cron:session)`, then a sentence: a session was opened for user `root`. The user name sits after the words "for user" and is glued to `(uid=0)`.
- **Line 3.** Program `sudo`, no PID. This message is half-structured: `sara` ran a command as `root`, with `TTY`, `PWD`, `USER` and `COMMAND` separated by ` ; `. But the invoking user `sara` has no label at all — it is just the first word, padded with spaces.

Three programs, three completely different message shapes, in one file. To turn them into fields you need a separate **regular expression** (regex) per message type. For the `sudo` line it might look like this:

```
^(?<ts>\w{3}\s+\d+\s[\d:]{8})\s(?<host>\S+)\ssudo:\s+(?<user>\S+)\s:\sTTY=(?<tty>\S+)\s;\sPWD=(?<pwd>\S+)\s;\sUSER=(?<run_as>\S+)\s;\sCOMMAND=(?<command>.+)$
```

Piece by piece:

- `^(?<ts>\w{3}\s+\d+\s[\d:]{8})` — from the start of the line, capture a timestamp: three letters (`Nov`), one or more spaces, the day, a space, and eight characters of digits and colons (`09:08:01`). `(?<ts>…)` names the capture `ts`.
- `\s(?<host>\S+)` — a space, then the host name (any run of non-space characters).
- `\ssudo:\s+` — the literal program name `sudo:` followed by one or more spaces (sudo pads the user name).
- `(?<user>\S+)\s:\s` — the invoking user, then ` : `.
- `TTY=(?<tty>\S+)\s;\sPWD=(?<pwd>\S+)\s;\sUSER=(?<run_as>\S+)\s;\s` — each labelled part with its ` ; ` separator.
- `COMMAND=(?<command>.+)$` — everything to the end of the line is the command.

Applied to line 3 the result is:

| Field | Value |
| --- | --- |
| `ts` | `Nov 20 09:08:01` |
| `host` | `web-07` |
| `user` | `sara` |
| `tty` | `pts/2` |
| `pwd` | `/var/log` |
| `run_as` | `root` |
| `command` | `/usr/sbin/service ssh start` |

Now look at how easily it breaks:

1. **Optional parts.** If `sudo` is run from a cron job there is no terminal, and the line says `TTY=unknown` or drops parts; if the command was refused, the line is `sara : 3 incorrect password attempts ; TTY=pts/2 ; ...` — an extra chunk the regex does not expect, so the whole line fails to match.
2. **Spaces where you assumed none.** `PWD=(?<pwd>\S+)` fails for a directory such as `/home/sara/My Files`.
3. **Every other message.** The regex does nothing for `dhclient` or `CRON` lines. Each program — and each *kind* of message from each program — needs its own pattern. `sshd` alone writes dozens of different sentences.
4. **Version changes.** When a developer rewords a message ("session opened for user root(uid=0)" became that form in newer PAM versions; older versions wrote "session opened for user root by (uid=0)"), the old regex quietly stops matching.

The dangerous part is that a failed regex does not stop the log from arriving. The event is stored with only the raw text, and every rule that relied on `user` or `command` simply never sees a value. That is a **false negative** — the worst kind of error, because nobody notices it.

**[Supplement]** Most SIEMs tag events that could not be parsed (a default source type, a `tags: _grokparsefailure`-style marker in Elastic/Logstash pipelines, or an "unparsed" category). A quick weekly check of "what share of each source failed to parse" catches broken parsers before an investigation does. On Linux, the [systemd journal](../linux-logging/log-files-journal.md#journal) helps a little: it stores fields such as `_PID`, `_UID`, `_COMM` and `SYSLOG_IDENTIFIER` in a structured way, so collecting from the journal as JSON gives you the header fields for free — though the `MESSAGE` text is still a free sentence.

## Structured log formats { #structured }

The fix is to log in a format with a **predictable structure**, so a generic parser can cut every line correctly without knowing anything about the program. Here is the same DNS connection record in the three common shapes:

```
CSV:        10.20.30.41,198.51.100.53,55001,53,udp
Key-value:  src_ip=10.20.30.41 dest_ip=198.51.100.53 src_port=55001 dest_port=53 proto=udp
JSON:       {"src_ip":"10.20.30.41","dest_ip":"198.51.100.53","src_port":55001,"dest_port":53,"proto":"udp"}
```

Those lines are 38, 78 and 96 bytes long. Multiply by a billion events a day and the difference is real money in storage and licensing — but as we will see, the cost of a broken parser is higher.

| Format | Field names travel with the data? | Survives added/removed/reordered fields? | Nesting and lists | Size |
| --- | --- | --- | --- | --- |
| CSV / TSV | No — reader must know names and order | No — everything after the change shifts | No | Smallest |
| Key-value | Yes | Yes | No (flat only) | Medium |
| JSON | Yes | Yes | Yes | Largest |
| XML | Yes | Yes | Yes | Largest (often larger than JSON) |

### CSV (comma-separated values) { #csv }

A CSV log is just values in a fixed order. To parse it, the SIEM needs to be told: column 1 is `src_ip`, column 2 is `dest_ip`, column 3 is `src_port`, and so on. That is very efficient, and it is fragile. Suppose a firewall upgrade inserts a new `action` column after `dest_ip`:

```
Before:  10.20.30.41,198.51.100.53,55001,53,udp
After:   10.20.30.41,198.51.100.53,allow,55001,53,udp
```

With the old column list, the SIEM now reads `src_port=allow`, `dest_port=55001`, `proto=53`, and the last value has no name at all. No error is raised. A rule on `dest_port=53` stops firing; a dashboard of "top destination ports" fills with `55001`. Two more CSV traps: a value that contains a comma (a URL query string, a user agent, a file path such as `C:\Users\sara\Q1,Q2.xlsx`) must be quoted, and not every producer quotes correctly; and empty values (`10.20.30.41,,55001,...`) are easy to misread.

**[Supplement]** A useful halfway house is a CSV/TSV file that **describes itself** in a header. Zeek logs do exactly this:

```
#separator \x09
#fields	ts	uid	id.orig_h	id.orig_p	id.resp_h	id.resp_p	proto	service
#types	time	string	addr	port	addr	port	enum	string
1795164723.436	CkV1aB3xYz9	10.20.30.41	55001	198.51.100.53	53	udp	dns
```

- `#separator \x09` — fields are separated by a tab.
- `#fields` — the column names, in order, written into the file itself.
- `#types` — the data type of each column, so `id.orig_p` is read as a port, not text.
- The data line is then unambiguous. If a Zeek upgrade adds a column, the `#fields` line changes too, and a parser that reads it adapts. (Zeek can also write JSON directly, which most SOCs now prefer.)

### Key-value pairs { #key-value }

Here every value carries its name: `key=value`. Because the parser looks for names rather than positions, fields can be added, removed or shuffled without breaking anything. If the firewall adds `action=allow` anywhere in the line, the old fields are still found under their names and the new one simply appears. That is why many firewalls and proxies log this way, and why most SIEMs auto-extract `key=value` text without any configuration.

The weak spots are the **delimiters**:

```
src_ip=10.20.30.41 user=sara msg=login failed for sara reason=bad password
```

Where does `msg` end? A naive parser splits on spaces and gets `msg=login`, then nonsense words, then `reason=bad`. Well-behaved producers quote values (`msg="login failed for sara"`) or escape spaces; badly behaved ones do not. And if an attacker controls part of a value — say, a user name typed into a login form — they may be able to **inject** a fake field:

```
user=x src_ip=203.0.113.99 action=success
```

If that whole string is logged unescaped as the user name, a careless parser sees `user=x`, then a second `src_ip` and an `action=success` that the application never wrote. This is **log injection** (CWE-117, Improper Output Neutralization for Logs). It is one reason to prefer formats with strict quoting rules, such as JSON, for security-relevant data.

### JSON and XML { #json-xml }

**JSON** (JavaScript Object Notation) has the benefits of key-value pairs and adds three more: strict quoting and escaping rules (so a parser always knows where a value ends), **data types** (`55001` is a number, `"udp"` is a string, `true` is a boolean), and **nesting** — objects inside objects, and arrays (lists). Here is a short endpoint process event in JSON, written out over several lines for readability (in a log file it would be one line):

```json
{
  "@timestamp": "2026-11-20T09:08:01.512Z",
  "host": { "name": "web-07", "ip": ["10.20.40.17", "fe80::a1b2:3c4d"] },
  "user": { "name": "sara", "effective": { "name": "root" } },
  "process": {
    "executable": "/usr/sbin/service",
    "args": ["service", "ssh", "start"],
    "parent": { "name": "sudo", "pid": 81244 }
  },
  "event": { "category": ["process"], "type": ["start"] }
}
```

- `@timestamp` — full date, time, milliseconds and the `Z` (UTC) zone. Compare that with the syslog header's `Nov 20 09:08:01`.
- `host` — an **object** with a `name` and an **array** of two IP addresses. CSV and key-value cannot express "this host has two IPs" without inventing `ip1`, `ip2` columns.
- `user.name` and `user.effective.name` — nesting shows clearly that `sara` ran the command and it ran **as** `root`. The flattened field names (`user.effective.name`) are how most SIEMs let you search nested data.
- `process.args` — the command line as a list, so `ssh` is a separate element rather than part of a string you have to split.
- `event.category` / `event.type` — classification fields (from a common schema; more on that on the next page).

JSON's cost is size — every field name is repeated in every event, plus quotes and braces — but parsing it is dependable and needs no custom regex. **XML** offers the same power (Windows event logs are XML — see [event structure](../windows-logging/event-structure-channels.md)), and because both formats are hierarchical, XML converts to JSON without losing structure. That is why the collection page recommended shipping Windows events as XML or JSON rather than flattening them to syslog text.

**The rule of thumb:** for anything you want to detect on, ease and reliability of parsing beat compactness. Choose JSON (or the source's native structured format) whenever the producer offers it.

## SIEM-centric formats: CEF and LEEF { #cef-leef }

Some SIEMs defined their own formats so that every incoming event carries the same basic structure **plus a clear statement of which product produced it**. The two best known are **CEF** (Common Event Format, created for ArcSight and widely supported, including by Microsoft Sentinel) and **LEEF** (Log Event Extended Format, used by IBM QRadar). Both look the same at a glance: a syslog header, then a pipe-delimited header describing the source, then key-value extensions.

### CEF { #cef }

The CEF header is:

```
CEF:Version|Device Vendor|Device Product|Device Version|Signature ID|Name|Severity|Extension
```

An invented example from an email-security gateway:

```
<134>Nov 20 08:50:00 mailgw01.corp.example CEF:0|ExampleSec|MailShield|4.2.1|av-1007|Malicious attachment blocked|8|externalId=995 rt=Nov 20 2026 08:49:58 UTC src=203.0.113.45 dst=10.20.50.10 suser=billing@supplier.example duser=a.chen@corp.example fname=invoice_2026-11.zip fileHash=0123456789abcdef0123456789abcdef01234567 act=blocked cs1Label=policy cs1=inbound-attachments
```

Field by field:

| Part | Value | Meaning |
| --- | --- | --- |
| `<134>` | PRI 134 | facility 16 (`local0`), severity 6 (`info`): 16 × 8 + 6 = 134. This is the syslog transport's severity, not the event's. |
| `Nov 20 08:50:00 mailgw01.corp.example` | syslog header | when and from which device the message was sent |
| `CEF:0` | version | CEF format version 0 (the common one; version 1 also exists) |
| `ExampleSec` | Device Vendor | who made the product |
| `MailShield` | Device Product | which product |
| `4.2.1` | Device Version | product version — useful when a parser change coincides with an upgrade |
| `av-1007` | Signature ID | the vendor's ID for this **type** of event; the most useful field for grouping and rules |
| `Malicious attachment blocked` | Name | human-readable description of the event type |
| `8` | Severity | the vendor's severity, 0 (lowest) to 10 (highest); 7–8 is "high" |
| everything after the last `|` | Extension | space-separated `key=value` pairs |

The extension keys come from a fixed CEF dictionary, which is what makes CEF parse the same way for every vendor: `rt` (receipt time of the event), `src`/`dst` (source and destination IP), `spt`/`dpt` (ports), `suser`/`duser` (source and destination user), `fname` (file name), `fileHash`, `act` (action taken), `externalId` (the vendor's own event ID). Anything not in the dictionary goes into **custom fields** such as `cs1` with a label in `cs1Label` — here, "the policy that matched was `inbound-attachments`". Watch for those: in many products the most interesting data lives in `cs1`–`cs6`, and the label tells you what each one means in this product.

Escaping rules: in the header a literal `|` must be written `\|` and a backslash `\\`; in the extension a literal `=` must be written `\=` and a backslash `\\`. Spaces are allowed inside extension values — the parser knows a value ends where the next `key=` begins — which is exactly why an unescaped `=` in a value (for example in a URL query string) breaks CEF parsing.

### LEEF { #leef }

LEEF has the same idea with a slightly different header:

```
LEEF:2.0|Vendor|Product|Version|EventID|Delimiter|Extension
```

An invented example from a web proxy:

```
<13>Nov 20 08:52:04 proxy02.corp.example LEEF:2.0|ExampleNet|EdgeProxy|7.1|deny|^|devTime=Nov 20 2026 08:52:03^src=10.20.30.88^dst=198.51.100.80^usrName=sara^url=http://files.download.example/setup.exe^cat=Uncategorized^action=blocked
```

- `<13>` — PRI 13: facility 1 (`user`), severity 5 (`notice`).
- `LEEF:2.0` — format version 2.0. Version 1.0 has no delimiter field and always uses a **tab** between attributes.
- `ExampleNet|EdgeProxy|7.1` — vendor, product, version, just like CEF.
- `deny` — the **EventID**: the vendor's identifier for this event type. QRadar maps vendor + EventID to its own event categories.
- `^` — the **delimiter** chosen for the attributes (a 2.0 feature). A caret is used here because it will not appear in URLs, so values never need escaping.
- The attributes — `devTime` (event time on the device), `src`, `dst`, `usrName`, `url`, `cat` (category), `action` — use LEEF's predefined key names; vendors can add their own.

Why it matters to you: if your SIEM receives CEF or LEEF, the **header fields** (vendor, product, signature/event ID, severity) are always reliable, even when a vendor fills the extension sloppily. Rules keyed on `Device Product` + `Signature ID` survive message-text changes. And when an event looks wrong, the device version in the header is the first thing to compare against the last known-good event.

## Why structure is so important inside the SIEM { #why-structure }

A SIEM does not answer searches by `grep`-ing every stored byte. It could — that is called a **full-text search** — but over months of data it is painfully slow. Instead, at ingest the SIEM **parses** each event, takes the most commonly searched fields — user names, IP addresses, host names, domains, event IDs — and writes them into an **index**: a lookup structure from value to "which events contain this", like the index at the back of a book. A search on an indexed field jumps straight to the matching events.

Take a native-format Squid proxy line:

```
1795164723.436     17 10.20.30.88 TCP_MISS/503 861 GET http://updates.vendor.example/check.aspx sara HIER_NONE/- text/html
```

| Position | Value | Meaning |
| --- | --- | --- |
| 1 | `1795164723.436` | time as Unix epoch seconds with milliseconds: 2026-11-20 08:52:03.436 UTC |
| 2 | `17` | elapsed time in milliseconds the proxy spent on the request |
| 3 | `10.20.30.88` | client IP |
| 4 | `TCP_MISS/503` | cache result (`TCP_MISS` = not served from cache) / HTTP status the client received (503) |
| 5 | `861` | bytes sent to the client |
| 6 | `GET` | HTTP method |
| 7 | `http://updates.vendor.example/check.aspx` | requested URL |
| 8 | `sara` | authenticated user name (`-` when the proxy did not authenticate) |
| 9 | `HIER_NONE/-` | how the proxy fetched it (no upstream peer here) |
| 10 | `text/html` | content type of the response |

This is a **positional** format, like CSV with spaces. With a correct parser, the SIEM writes `10.20.30.88` into a source-IP index, `updates.vendor.example` into a domain/URL index, `sara` into a user index, and the whole line into storage. A later question such as "which users visited this domain this month?" is answered from the indexes in seconds. If the parser is wrong by one position — a proxy configured to log a different format, say — the "user" index fills with `HIER_NONE/-` and the user question returns garbage or nothing.

Parsing matters for **rules** even more than for searches. A rule matching `url` against a threat-intelligence list cannot match a field that does not exist. The alert does not fire, and you get a false negative. So, unless bandwidth or licence cost truly forces your hand, when a source offers a choice of output formats, pick the more structured and robust one over the more compact one.

**[Supplement]** SIEMs differ in *when* they extract fields, and it is worth knowing which kind you have:

- **Schema-on-write** (index-time extraction): fields are parsed as events arrive. Searches are fast, but a parser bug is baked into stored data and fixing it only helps new events. Elastic and most cloud SIEMs (Microsoft Sentinel tables, Chronicle UDM) work mostly this way.
- **Schema-on-read** (search-time extraction): raw text is stored and indexed by its words; named fields are extracted when you search. Splunk works mostly this way. A parser fix applies to old data immediately, but filtering on a field still means reading the candidate events to extract it.

Either way the analyst's rule is the same: know which fields are actually extracted and indexed for each source, and check parse-failure rates.

## Your SIEM is not Google { #not-google }

A SIEM search bar looks like a web search engine, so people type into it the way they would into one. Suppose `sara` might be infected and you want her proxy logs. Three ways to ask:

1. `sara`
2. proxy logs that contain `sara` anywhere
3. proxy logs where the **user** field is `sara`

In Splunk's search language (SPL) these could be written as follows. A quick primer for SPL beginners: a search is a list of conditions, separated by spaces, that an event must all meet (spaces mean AND); `index=` picks which storage bucket of data to search (SOCs usually keep one index per log type, such as `proxy`, `wineventlog` or `firewall`); `field=value` matches only when that named field has that value; and a bare word matches if it appears anywhere in the raw event text. The time range is set separately (the time picker, or `earliest=`).

```
sara
```

- A bare word, no index. Splunk searches the **default indexes** for any event whose raw text contains the term `sara` — Windows logs, firewall logs, DNS, everything. This is the most work for the SIEM and also the least precise result: it returns the file share `\\fs01\sara-backup`, the email to `sara@partner.example`, the process `sara_report.exe`.

```
index=proxy sara
```

- `index=proxy` limits the search to the proxy data. `sara` still matches **any** part of the event: the user field, but also URLs such as `http://intranet.corp.example/team/sara/` or a referrer. Faster than #1, but still searching fields where a user name makes no sense, and still giving you other people's traffic.

```
index=proxy user=sara
```

- `index=proxy` again limits the data; `user=sara` matches only events whose extracted `user` field is exactly `sara`. Smallest scope, and the answer is exactly what you meant. Results might look like:

```
_time                   src_ip        user  method  url                                             status
2026-11-20 08:52:03.436 10.20.30.88   sara  GET     http://updates.vendor.example/check.aspx        503
2026-11-20 08:52:09.102 10.20.30.88   sara  GET     http://files.download.example/setup.exe         200
```

The same principle in other SIEMs: in Microsoft Sentinel's KQL, the **table** plays the role of the index, so `CommonSecurityLog | where SourceUserName == "sara"` (one log type, one field) beats `search "sara"` (every table, every column). In Elastic, `user.name: "sara"` with the right data view beats a free-text `sara`.

**[Correction]** How much faster #3 is depends on the SIEM's architecture. In schema-on-write SIEMs, a field-scoped search uses the field's own index and the speed gain is large. In Splunk, the raw-text index finds events containing the term `sara` first and then checks the `user` field, so the big speed gain comes from `index=` (and a tight time range), while `user=sara` mostly buys **precision**. In every SIEM, the order of importance is the same: **time range, then log type, then field**.

Two more habits that follow from how indexes work:

- **Avoid leading wildcards.** `user=*sara` cannot use an index (an index is sorted by the start of each value) and forces a scan. `user=sara*` is usually fine.
- **Know which fields are indexed.** Some SIEM architectures cannot index every field of every log — the index would be larger than the data. In those systems, make sure the frequently searched fields (IPs, user names, host names, domains, hashes, event IDs) are indexed, and build searches from indexed fields first; adding a non-indexed field as the only filter sends the SIEM back to reading events one by one.

## Putting it to work in a SOC { #soc-use }

When you take on a new log source, or a search "should have" found something and did not:

1. **Format.** Is the source unstructured text, CSV, key-value, JSON, CEF/LEEF or XML? Can it be switched to a more structured output?
2. **Parser.** Which parser handles it, and what share of its events fail to parse? Look at a few raw events next to their extracted fields.
3. **Upgrades.** Did the device version (CEF/LEEF header, agent version) change around the time results changed? Did a CSV column move?
4. **Fields.** Which fields are extracted and which are indexed? Are the ones your rules depend on present in every event?
5. **Search scope.** Time range, then log type (`index=`, table, data view), then field. Bare words only for exploration.
6. **Injection.** For fields an outsider can influence (user names, URLs, user agents), does the format escape delimiters?

## The 2026 view { #trends }

!!! success "[2026 Current] Still valid"
    The ranking of formats (unstructured < CSV < key-value < JSON/XML for robustness, the reverse for size), the danger of regex-parsing free text, the fragility of positional formats, the way parsing feeds indexing and rules, and "scope by time, log type, then field" are all unchanged. CEF remains a common way for network and security appliances to send events to SIEMs, and LEEF is still QRadar's native format.

!!! info "[Changed] What has changed"
    - **JSON is now the default transport.** Agents, cloud services and EDR products overwhelmingly emit JSON, usually over HTTPS (vendor HTTP collectors, OpenTelemetry). Syslog text and CEF are now mostly for appliances and older products.
    - **Common schemas moved into the pipeline.** Elastic contributed ECS to OpenTelemetry in 2023, and the two are converging into OpenTelemetry's semantic conventions. **OCSF** (Open Cybersecurity Schema Framework), backed by AWS, Splunk and many others, reached 1.0 in 2023 and joined the Linux Foundation in 2024; AWS Security Lake stores data in OCSF. Microsoft Sentinel normalises with ASIM, Google SecOps with UDM. Covered on the next page.
    - **Collector changes.** In Microsoft Sentinel the old CEF/syslog connectors that relied on the retired Log Analytics agent (MMA) are deprecated; CEF and syslog now arrive through the Azure Monitor Agent on a Linux forwarder ("CEF via AMA"). ArcSight, where CEF was born, now belongs to OpenText; QRadar's SaaS business moved to Palo Alto Networks in 2024, while QRadar software (and LEEF) continues at IBM.
    - **Cheap tiers change search habits.** Data lakes and low-cost tiers (for example Microsoft Sentinel's data lake, generally available since 2025, and similar tiers from other vendors) store huge volumes cheaply but search more slowly and with fewer indexed fields. Scoping by time and log type matters even more there.
    - **AI-assisted parsing.** Several SIEMs and pipeline tools now offer AI-generated parsers and natural-language search. They speed up onboarding, but a generated parser is still a parser: check its extracted fields against raw events before writing rules on them.

!!! warning "[Caution] Wrong or risky to do the old way"
    - **Do not choose CSV or unstructured output just to save bytes** for security-relevant data. A shifted column is a silent false negative.
    - **Do not trust a parser after an upgrade** without checking a few raw events. Vendors change formats in minor versions.
    - **Do not treat "no results" as "it did not happen"** until you have checked the field actually exists and is populated for that source.
    - **Do not type bare words into the SIEM** for real investigations — they are slow and pull in unrelated events. Scope by time, log type, then field.
    - **Do not assume key-value or CEF values are safe** when outsiders can influence them; check how the format escapes `=`, spaces and `|`.

## Practice questions { #quiz }

### Question 1

Your firewall logs arrive as CSV: `src_ip,dest_ip,src_port,dest_port,proto`. After a weekend upgrade, the rule "alert on outbound connections to `dest_port=4444`" has not fired once, the "top destination ports" dashboard shows mostly five-digit numbers, and a new value `allow` appears in `src_port`. What happened, how do you confirm it, and what is the lasting fix?

??? success "Answer and explanation"
    **What happened:** the upgrade inserted a new column (an `action` field such as `allow`) after `dest_ip`. CSV has no field names in the data, so the SIEM still applies the old column list: `allow` is read as `src_port`, the real source port is read as `dest_port` (hence five-digit "destination ports" such as 55001), and the real destination port lands in `proto`. Nothing errored; the rule on `dest_port=4444` simply never sees 4444 in that field — a false negative.

    **Confirm it:** look at a few raw events from before and after the upgrade side by side and count the commas; check the device version in the device's own logs or release notes; check whether the parse-failure or "extra field" count for this source jumped at the upgrade time.

    **Lasting fix:** switch the firewall to a self-describing format if it offers one — key-value, JSON or CEF — so added or reordered fields cannot shift the others. If CSV is the only option, update the column list, add a monitor that alerts when the number of columns or the share of non-numeric ports changes, and re-check the parser after every upgrade. Then re-run the `dest_port=4444` hunt over the affected period using the corrected fields.

### Question 2

A gateway sends this event:

```
<134>Nov 20 10:02:11 mailgw01.corp.example CEF:0|ExampleSec|MailShield|4.2.1|av-1007|Malicious attachment blocked|8|src=203.0.113.45 duser=r.kim@corp.example fname=po_7781.docm act=blocked cs1Label=policy cs1=inbound-attachments
```

Name the vendor, product, event type ID, the vendor's severity and what PRI 134 tells you. Which header fields would you build a rule on, and why those rather than the `Name` text?

??? success "Answer and explanation"
    - Vendor `ExampleSec`, product `MailShield`, version `4.2.1`.
    - Event type (Signature ID) `av-1007`; Name "Malicious attachment blocked".
    - Vendor severity `8` on the 0–10 scale — high.
    - PRI `134` = facility 16 (`local0`) × 8 + severity 6 (`info`). That is the **syslog transport** priority, chosen by the sender's configuration; it does not describe how serious the event is. The CEF severity field does.
    - Extension: source IP `203.0.113.45`, recipient `r.kim@corp.example`, file `po_7781.docm`, action `blocked`, and a custom field whose label says it is the matching **policy**, `inbound-attachments`.

    **Rule on:** `Device Vendor` + `Device Product` + `Signature ID` (and possibly `act`). Those are fixed identifiers that every CEF parser extracts the same way. The `Name` is human-readable text the vendor can reword or translate in any release, which would silently break a rule matching on it — the same problem as regex-parsing free text.

### Question 3

During an incident a colleague runs the single word `10.20.30.88` over 90 days of all data. The search runs for many minutes and returns 2.4 million events across a dozen source types. You need the proxy requests made **from** that workstation in the last 24 hours. Write a better search, explain each part, and say why it is faster and more accurate.

??? success "Answer and explanation"
    A better search (in SPL, with the time picker set to the last 24 hours, or written inline):

    ```
    index=proxy src_ip=10.20.30.88 earliest=-24h
    ```

    - `index=proxy` — only proxy data, instead of every index. This is the biggest saving in data the SIEM has to touch.
    - `src_ip=10.20.30.88` — only events where the address is in the **source** field. The bare value also matched events where the workstation was a destination, appeared in a DHCP message, a Windows event, a firewall log, or any URL or text containing the string.
    - `earliest=-24h` — only the last 24 hours instead of 90 days; time is the first thing every SIEM uses to narrow the search.

    It is faster because each condition shrinks the data the SIEM has to read, and the field condition can use (or quickly check) an extracted, indexed field instead of scanning raw text. It is more accurate because it returns exactly what was asked: requests *from* that host, in the proxy log, in the incident window. Check first that the proxy parser really extracts `src_ip` for this source; if the field name differs (`c_ip`, `client_ip`), use the one your parser produces.

## Related { #related }

- [Log Collection](collection-methods.md) — the pipeline these formats travel through
- [Syslog](../linux-logging/syslog.md) — the header in front of most unstructured logs
- [Windows event structure](../windows-logging/event-structure-channels.md) — XML events with named fields
- [Linux log files and the journal](../linux-logging/log-files-journal.md)
- [Splunk field extraction with rex](../../../blueteam/splunk/rex-and-fields.md)
- [Splunk data discovery](../../../blueteam/splunk/data-discovery.md)

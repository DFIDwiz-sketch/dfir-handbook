---
title: rex, Field Extraction & eval
tags:
  - concept
  - splunk
  - regex
---

# `rex`, Field Extraction & `eval`

<div class="dfir-meta" markdown>
**Category:** Splunk · **Last updated:** 2026-09-17
</div>

!!! abstract "In one sentence"
    When the field you need doesn't exist, make it: `rex` pulls values out of text with a regex named group, `spath` walks JSON/XML, `eval` reshapes what you have — and once a pattern is proven in a search, promote it to a permanent extraction so nobody has to type it again.

## `rex` essentials

```spl
| rex field=<source field> "<regex with (?<name>...) groups>"
```

- Default `field=_raw`. Name each capture with `(?<fieldname>…)` — that becomes the new field.
- Regex flavour is **PCRE**. Splunk double-parses backslashes inside `"…"`: write `\\d` for `\d` when the pattern is in double quotes — or, simpler, keep patterns short and use `\d`, `\s`, `\w` which usually survive; test in the UI.
- Add `max_match=0` to capture **all** matches into a multivalue field (default 1).
- `(?i)` at the start = case-insensitive.
- `mode=sed` turns `rex` into search-and-replace: `| rex field=x mode=sed "s/old/new/g"`.

### Worked examples

**Base64-encoded PowerShell**

```spl
index=botsv3 sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventID=1 Image="*powershell.exe"
| rex field=CommandLine "(?i)-(?:e|en|enc|encodedcommand)\s+(?<b64>[A-Za-z0-9+/=]{20,})"
| where isnotnull(b64)
| eval decoded=replace(base64decode(b64),"\x00","")
| table _time, host, User, decoded
```

The regex matches any of `-e`, `-en`, `-enc`, `-encodedcommand` (case-insensitive), whitespace, then 20+ base64 characters captured as `b64`. `where isnotnull(b64)` keeps only rows where the capture succeeded. `base64decode` (Splunk 8+; older versions need a custom command) turns it back into text; the `replace` strips the UTF-16 null bytes PowerShell inserts between characters.

**Username without domain**

```spl
| rex field=User "^(?<domain>[^\\\\]+)\\\\(?<username>.+)$"
```

Captures `CORP\jsmith` into `domain=CORP`, `username=jsmith`. The four backslashes become a regex `\\` (one literal backslash) after Splunk's quote-unescaping.

**IP + port out of free text**

```spl
| rex field=Message "Source Network Address:\s+(?<src_ip>\d{1,3}(?:\.\d{1,3}){3})\s+Source Port:\s+(?<src_port>\d+)"
```

**Every IP in an event (multivalue)**

```spl
| rex max_match=0 "(?<ips>\b(?:\d{1,3}\.){3}\d{1,3}\b)"
| mvexpand ips
| search ips!=127.0.0.1 ips!=0.0.0.0
```

`max_match=0` collects all IPs into `ips`; `mvexpand` makes one row per IP so you can filter and count them.

**File name and extension from a path**

```spl
| rex field=TargetFilename "(?<fname>[^\\\\]+)$"
| rex field=fname "\.(?<ext>[^.]+)$"
```

**Domain from a URL / SNI**

```spl
| rex field=url "^(?:https?://)?(?<fqdn>[^/:]+)"
| eval domain=mvindex(split(fqdn,"."),-2).".".mvindex(split(fqdn,"."),-1)
```

`split` breaks the FQDN on dots into a multivalue list; `mvindex(...,-2)` and `-1` pick the last two labels; `.` concatenates them (`mail.evil-example.com` → `evil-example.com`). Good enough for most TLDs; `co.uk`-style needs a lookup.

**Sysmon XML without the add-on**

```spl
| rex field=_raw "<Data Name='Image'>(?<Image>[^<]+)"
| rex field=_raw "<Data Name='CommandLine'>(?<CommandLine>[^<]+)"
| rex field=_raw "<Data Name='ParentImage'>(?<ParentImage>[^<]+)"
| rex field=_raw "<EventID>(?<EventID>\d+)</EventID>"
```

Each `rex` grabs one `<Data Name='…'>value</Data>` element. Better: `spath` below, or install the add-on.

## `spath` for JSON / XML

```spl
| spath                                            # auto-extract everything (JSON) — fine for small results
| spath path=userIdentity.arn output=who           # one path, renamed
| spath path=Event.EventData.Data{@Name}           # XML attributes → multivalue
| spath input=Message path=alert.signature         # spath on a field that contains JSON
```

For Sysmon XML you'll usually pair `spath` with `mvzip`/`mvexpand` or just install the add-on — the XML shape (`<Data Name="X">value`) makes `rex` simpler than `spath` here.

## Auto-extraction that already exists

Before writing `rex`, check what Splunk already gives you: **Interesting Fields** panel; `| fieldsummary`; `key=value` pairs in raw text are extracted automatically (`user=admin` → `user`); the **Field Extractor** (Extract New Fields → highlight text → Splunk writes the regex) is the GUI way to build and save a `rex`.

## `eval` — the functions you actually use

| Need | Function |
|---|---|
| Conditional | `if(cond, a, b)` · `case(c1, v1, c2, v2, true(), default)` · `coalesce(a, b, c)` · `nullif(a, b)` |
| Strings | `lower`, `upper`, `len`, `substr(s, start, len)`, `replace(s, regex, repl)`, `trim`, `ltrim`, `rtrim`, `split(s, delim)`, `.` (concat), `urldecode`, `md5`, `sha1`, `sha256` |
| Tests | `like(s, "pat%")`, `match(s, "regex")`, `cidrmatch("10.0.0.0/8", ip)`, `isnull`, `isnotnull`, `in(field, "a","b")`, `searchmatch("user=admin*")` |
| Numbers | `round(x, 2)`, `floor`, `ceil`, `abs`, `pow`, `log`, `tonumber(s)`, `tostring(n, "commas")`, `random()` |
| Time | `now()`, `strftime(t, fmt)`, `strptime(s, fmt)`, `relative_time(t, "-1d@d")`, `time()` |
| Multivalue | `mvcount`, `mvindex(mv, i)`, `mvjoin(mv, ",")`, `mvfilter(match(mv, "x"))`, `mvdedup`, `mvappend`, `mvzip`, `split`, `mvsort` |
| Encoding | `base64decode` / `base64encode` (8.1+), `printf`, `tostring(x,"hex")` |
| Type | `typeof(x)`, `tonumber`, `tostring` |

### Small `eval` recipes

```spl
| eval user=lower(coalesce(user, Account_Name, User))                       # normalise usernames across sourcetypes
| eval is_admin=if(match(user,"(?i)admin|adm_|svc_"),1,0)
| eval logon_type_name=case(Logon_Type==2,"Interactive",Logon_Type==3,"Network",Logon_Type==10,"RemoteInteractive",Logon_Type==9,"NewCredentials",true(),"Other")
| eval internal=if(cidrmatch("10.0.0.0/8",dest_ip) OR cidrmatch("192.168.0.0/16",dest_ip) OR cidrmatch("172.16.0.0/12",dest_ip),"int","ext")
| eval MB_out=round(bytes_out/1048576,2)
| eval cmd_len=len(CommandLine), has_b64=if(match(CommandLine,"[A-Za-z0-9+/]{50,}={0,2}"),1,0)
| eval entropy_hint=len(replace(lower(query),"[aeiou0-9.-]",""))/len(query)   # crude consonant ratio for DGA-ish names
| eval day=strftime(_time,"%Y-%m-%d"), hour=strftime(_time,"%H")
| eval hash_sha256=mvindex(split(mvindex(split(Hashes,"SHA256="),1),","),0)  # Sysmon Hashes field "MD5=…,SHA256=…,IMPHASH=…"
```

The last one: `split(Hashes,"SHA256=")` cuts the string at `SHA256=`; `mvindex(...,1)` takes what follows; splitting that on `,` and taking index 0 leaves just the hash.

## Lookups — enrich and allow-list

```spl
# CSV with columns ip,owner,criticality uploaded as lookup "assets"
| lookup assets ip as dest_ip OUTPUTNEW owner, criticality

# Allow-list: drop rows whose process is in known_good.csv (column: process)
| lookup known_good process as Image OUTPUT process as known
| where isnull(known)

# Build a baseline once, reuse it
index=botsv3 sourcetype=stream:http earliest=-30d@d latest=@d | stats count by http_user_agent | outputlookup baseline_ua.csv
```

`OUTPUTNEW` only fills fields that are empty; `OUTPUT` overwrites. The allow-list trick: join against the list and keep rows where the lookup **failed** (`isnull`) — i.e. not on the list.

## Promote a `rex` to a permanent extraction

Once a `rex` works, save it so it is applied automatically at search time: **Settings → Fields → Field extractions → New**, sourcetype + the same regex (drop `field=` unless it's not `_raw`), or in `props.conf`:

```ini
[XmlWinEventLog:Microsoft-Windows-Sysmon/Operational]
EXTRACT-sysmon_image = <Data Name='Image'>(?<Image>[^<]+)
EXTRACT-sysmon_cmd   = <Data Name='CommandLine'>(?<CommandLine>[^<]+)
```

Also useful: **Field aliases** (`Account_Name` → `user`), **Calculated fields** (`eval` stored once), **Event types** (a saved search condition, e.g. `eventtype=win_failed_logon`), **Tags** (`tag=authentication`). These are how add-ons make CIM fields appear.

## Debugging extraction

- Nothing extracted? Test the regex on one event: `| head 1 | rex … | table b64` — then loosen it.
- Backslash trouble? Put the pattern in the Field Extractor GUI, or use `[\\\\]` for a literal backslash class.
- Wrong field name? Check spelling and case — field names are case-sensitive (`EventCode` ≠ `eventcode`), values usually aren't.
- Field appears in the sidebar but `stats` says null? It may exist in only some events — `| stats count(field) count` shows coverage.
- Multivalue surprises: `stats by Account_Name` splits on each value; use `mvindex` or `mvjoin` first.

## References

- [Splunk — rex command](https://docs.splunk.com/Documentation/Splunk/latest/SearchReference/Rex)
- [Splunk — About regular expressions](https://docs.splunk.com/Documentation/Splunk/latest/Knowledge/AboutSplunkregularexpressions)
- [Splunk — eval functions](https://docs.splunk.com/Documentation/Splunk/latest/SearchReference/CommonEvalFunctions)
- [regex101 (PCRE flavour) for testing](https://regex101.com/)

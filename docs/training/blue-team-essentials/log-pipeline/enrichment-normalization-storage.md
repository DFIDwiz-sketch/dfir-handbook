---
title: "Enrichment, Normalisation and Storage — Context, Common Information Models, Categorisation, Hot/Warm/Cold and the Log Life Cycle"
tags:
  - training
  - blue-team
  - logging
  - siem
---

# Enrichment, Normalisation and Storage — Context, Common Information Models, Categorisation, Hot/Warm/Cold and the Log Life Cycle { #enrichment-normalization-storage }

!!! abstract "What this page covers"
    What happens to a log **after** it has been parsed, and why each step changes what you see and what you can find. First **enrichment**: the SIEM uses fields already in the log to look up extra context (asset owner, user role, domain age, reputation, patch status) and attaches it, turning a bare DNS query into something you can triage in seconds — and the traps of stale or point-in-time context. Then **correlation**, joining one log to others (DHCP, logons) to answer "which machine, which person". Then **field normalisation** and **common information models** (Splunk CIM, Elastic ECS, OCSF, Microsoft ASIM, Google UDM): why `src_ip`, `sourceIP` and `source.ip` should be searchable as one field, the three ways it is done (rename, copy, alias at search time), and why a normalised name may not exist in the raw log. Then **categorisation**: finding "all logins by mike" without knowing 4624 or sshd wording. Finally **storage**: like-with-like indexes, per-type retention, hot/warm/cold/frozen tiers, the log life cycle, what that means for old investigations, a list of questions to ask your SIEM engineer, and a summary of the whole pipeline. Practice questions with explanations at the end.

!!! note "Labels"
    **[Supplement]** = practical material you need to know, **[Correction]** = a commonly repeated claim that is wrong or outdated, **[Changed]**/**[Caution]** = what has changed recently and what is risky to do the old way. Hostnames, domains, accounts, IPs and file names are invented for illustration (`.example`, documentation and private IPs).

## The 8 key points { #key-points }

1. **Enrichment** adds information that was not in the original log, looked up from fields that were (IP → host and owner, domain → age and rank, user → role). It is one of the biggest time savers a SIEM offers, and it only works if parsing worked.
2. Enrichment is a **snapshot**. Ingest-time enrichment records what was true when the log arrived; search-time enrichment shows what is true now. For IP-to-host and user-to-role questions in an investigation, the difference matters.
3. **Correlation** joins a log to other logs (DHCP leases, logons, DNS answers) to answer questions the single log cannot, such as which person was behind an IP at 03:12.
4. Different products name the same thing differently. **Field normalisation** maps them to one name so one search finds them all. A collection of standard names is a **common information model** (data model, schema).
5. Normalisation can rename fields at ingest, add a normalised copy next to the original, or alias at search time. Know which your SIEM does — a normalised field name may **not appear in the raw log**.
6. Normalisation also covers **values** (`allow`/`accept`/`permit` → `allowed`; `CORP\mike`/`mike@corp.example` → `mike`) and **meaning**; two fields with the same name can still mean different things across sources.
7. **Categorisation** tags events by what kind of thing happened (authentication, process start, network connection), so analysts and rules can ask "all failed logins by mike" across every source. Sources that the parser does not categorise are invisible to such searches.
8. Logs are stored **like with like**, each type with its own **retention**, and age through **hot → warm → cold → archived/frozen → deleted**. New data is fast; old data is slow, needs restoring, or is gone. Know the numbers before an incident, not during one.

## Where we are in the pipeline { #where }

On the [collection page](collection-methods.md) an event travelled from the host to the SIEM, and on the [formats page](formats-structure.md) it was cut into named fields. That cut is the foundation for everything on this page. Enrichment needs a clean `query` or `src_ip` field to look things up with; normalisation needs to know which field is the source IP before it can rename it; categorisation needs to know the event is a logon. If parsing failed, none of the later steps happen and the event sits in the SIEM as an un-enriched, un-normalised, uncategorised blob that most rules and dashboards never see.

A useful picture is a mail-sorting centre. Collection is the van that picks up letters. Parsing is reading the address block. Enrichment is the clerk stamping extra information on the envelope ("sender is a known business", "postcode is a new development"). Normalisation is rewriting every address in one standard style. Categorisation is putting a coloured sticker on it (bill, parcel, legal notice). Storage is which shelf it goes on and how long it stays before being moved to the basement or shredded. Each step makes later work faster, and each step can introduce a mistake you will only notice if you know the step exists.

## Log enrichment { #enrichment }

### What it is and why it matters { #enrichment-what }

Most log sources write the **minimum** needed to describe the event. A DNS server logs who asked, what they asked and what type of record. Here is a realistic query log line after parsing:

```json
{
  "@timestamp": "2026-11-20T03:12:44.218Z",
  "event.dataset": "dns.query",
  "source.ip": "10.0.10.3",
  "dns.question.name": "invoice-portal-secure.example",
  "dns.question.type": "A",
  "dns.response_code": "NOERROR"
}
```

Line by line: the event time; which log type this is (a DNS query); the IP that asked; the name asked for; the record type (`A` = an IPv4 address); and the result code (`NOERROR` = the name resolved). Is this bad? You cannot tell. Every one of the questions you would ask next — what did it resolve to, has anyone here seen this domain before, how old is it, is it on any blocklist, which machine is 10.0.10.3, who uses it, does that matter — needs a lookup somewhere else. If an alert fires on this event, an analyst spends ten minutes doing those lookups by hand, and does it again for the next alert, and the next.

Now the same event after the SIEM has enriched it:

```json
{
  "@timestamp": "2026-11-20T03:12:44.218Z",
  "event.dataset": "dns.query",
  "source.ip": "10.0.10.3",
  "dns.question.name": "invoice-portal-secure.example",
  "dns.question.type": "A",
  "dns.response_code": "NOERROR",
  "dns.resolved_ip": ["203.0.113.77"],
  "enrich.domain.first_seen_org": "2026-11-20T03:12:44Z",
  "enrich.domain.newly_observed": true,
  "enrich.domain.popularity_rank": null,
  "enrich.domain.registered": "2026-11-17",
  "enrich.domain.age_days": 3,
  "enrich.ti.match": false,
  "host.name": "fin-ws-014",
  "host.patch_status": "missing 2 critical updates",
  "user.name": "kyle.ward",
  "user.roles": ["Domain Admins"],
  "enrich.added_at": "2026-11-20T03:12:46Z"
}
```

The first six fields are unchanged; everything after them was added. Reading the additions:

- `dns.resolved_ip` — the answer, pulled from the matching DNS response log. Now you have an IP to check against firewall and proxy logs.
- `first_seen_org` / `newly_observed: true` — no machine in this organisation has queried this domain before this moment. Most legitimate domains are queried again and again; a first-ever query is a useful weak signal.
- `popularity_rank: null` — the domain is not in a top-sites popularity list. Unranked does not mean bad (most of the internet is unranked), but big, legitimate services usually are ranked.
- `registered` / `age_days: 3` — the domain was registered three days ago. Phishing and malware domains are often used within days of registration ([domain age](../dns/domain-signals.md#age-randomness)); attackers buy domains as part of their preparation (MITRE ATT&CK T1583.001, Acquire Infrastructure: Domains).
- `ti.match: false` — not on any threat-intelligence list the SIEM has. New domains are often not on lists yet, which is exactly why the other signals matter.
- `host.name` and `host.patch_status` — 10.0.10.3 is `fin-ws-014`, a finance workstation missing two critical updates. From an asset inventory or vulnerability scanner.
- `user.name` and `user.roles` — the person logged on there is `kyle.ward`, and he is a **domain admin**. From directory and logon data.
- `enrich.added_at` — when the enrichment was attached. **[Supplement]** Good pipelines record this, so you know how fresh the context was.

Put together: a domain admin, on an unpatched finance workstation, at 03:12, was the first person in the organisation ever to look up a three-day-old, unranked domain with a finance-themed name. Nothing in the original six fields said any of that. That is the whole point of enrichment: it turns "a DNS query happened" into a decision you can make in seconds. It is also the reason parsing matters so much — the SIEM cannot look up `dns.question.name` if it never extracted it.

### Common enrichment sources { #enrichment-sources }

| Enrichment | Looked up from | Answers | Typical source |
| --- | --- | --- | --- |
| Asset / host | IP, hostname | Which machine, which owner, how critical, what OS | CMDB, asset inventory, EDR |
| Identity | Username, IP + time | Which person, department, role, privileged or not, account enabled | Directory (AD, Entra ID), HR feed, logon events |
| Network location | IP | Internal subnet name (DMZ, server VLAN, guest Wi-Fi), site | IPAM, subnet list |
| Geolocation and ASN | External IP | Country, network owner, hosting vs residential | GeoIP / ASN database |
| Threat intelligence | IP, domain, URL, hash | Known bad? Which campaign? How confident? | TI platform, feeds |
| Domain data | Domain | Age, registrar, popularity rank, first seen here | WHOIS/RDAP, rank lists, own DNS history |
| Vulnerability | Host | Missing patches, known vulnerable software | Vulnerability scanner |
| Prevalence | Hash, process name, domain | How many machines have seen this | EDR, own log history |

### Ingest time or search time? { #enrichment-when }

There are two moments the SIEM can attach context, and they give different answers.

**Ingest-time enrichment** looks things up as the event arrives and writes the result into the stored event. Its strength is that it records **what was true at that moment**. If 10.0.10.3 belonged to `fin-ws-014` at 03:12 and DHCP gives it to a laptop at 09:00, the stored event still says `fin-ws-014`. Its weaknesses are that it can never be corrected (if the asset list was wrong that day, the event is wrong forever) and it cannot benefit from later knowledge: a domain that was added to a blocklist at 10:00 still shows `ti.match: false` on the 03:12 event.

**Search-time enrichment** looks things up when you run the search. Its strength is that it uses **current** data, so the 03:12 domain now shows as malicious. Its weakness is the opposite: if you ask "which host is 10.0.10.3?" today you get **today's** answer, which may be a different machine. For user roles, a person who was added to Domain Admins last night will appear as a domain admin on last week's events.

A rule of thumb that holds in most SOCs:

- Things that **change over time and must be historically correct** — IP-to-host, IP-to-user, user role at the time — are best done at ingest, or by correlating with time-stamped logs (DHCP, logon events) rather than with a current table.
- Things where the **latest knowledge is better** — threat intelligence, reputation — are best done at search time, or by re-scanning past data when new intelligence arrives (many SIEMs do retro-hunting of new indicators over the last N days).

**[Caution]** Always check whether an enrichment field is point-in-time or current before writing it in a report. "The host was owned by finance" is a claim about the past; if the field came from today's CMDB, say so.

### A simple search-time lookup, explained { #enrichment-spl }

Many SIEMs let you enrich in the query itself. In Splunk this is done with a **lookup**: a table (often a CSV file) the SIEM can join against. Suppose there is a lookup called `asset_inventory` with columns `ip`, `hostname`, `owner`, `criticality`. A search for the DNS event above:

```
index=dns query="invoice-portal-secure.example"
| lookup asset_inventory ip AS src_ip OUTPUT hostname owner criticality
| table _time src_ip hostname owner criticality query
```

For a complete beginner, piece by piece:

- `index=dns` — search only the index (storage area) that holds DNS logs. More on indexes [below](#storage).
- `query="invoice-portal-secure.example"` — keep only events whose `query` field is exactly that name. Field names are whatever your DNS parser creates; here the field is `query`.
- `|` — the pipe. It passes the results on the left into the command on the right, like a production line.
- `lookup asset_inventory` — the `lookup` command: for each event, look up a row in the table called `asset_inventory`.
- `ip AS src_ip` — match the table's `ip` column against the event's `src_ip` field.
- `OUTPUT hostname owner criticality` — copy those three columns from the matching row onto the event as new fields. If no row matches, the fields are simply empty.
- `table _time src_ip hostname owner criticality query` — show the results as a table with those columns, in that order. `_time` is Splunk's event time.

What the screen shows:

```
_time                    src_ip      hostname     owner        criticality  query
2026-11-20 03:12:44.218  10.0.10.3   fin-ws-014   finance-ops  high         invoice-portal-secure.example
```

Remember: this lookup is **search-time**, so `hostname` is whatever the table says **now**. If that table is refreshed daily from DHCP, an event from three weeks ago may be matched to the wrong machine.

### Correlation: joining logs to answer "who" { #correlation }

Enrichment from tables is one half; the other half is **correlation**, using other logs. The DNS event knows only an IP. Three other logs, written by three other systems, can turn that into a person:

```
# DHCP server log (lease granted)
2026-11-19 18:02:10  ASSIGN  10.0.10.3  mac=00:1a:2b:3c:4d:5e  hostname=fin-ws-014  lease=86400

# Windows Security 4624 on fin-ws-014 (interactive logon)
2026-11-20 02:58:31  EventID=4624  LogonType=2  TargetUserName=kyle.ward  TargetDomainName=CORP  WorkstationName=FIN-WS-014

# DNS query log
2026-11-20 03:12:44  client=10.0.10.3  query=invoice-portal-secure.example  type=A
```

Reading them in order: the DHCP server gave 10.0.10.3 to `fin-ws-014` at 18:02 the previous evening for 86,400 seconds (24 hours), so at 03:12 the lease is still valid. Event **4624** is Windows' "an account successfully logged on" event, written on the machine the account logged on to; **LogonType 2** means someone typed credentials at the keyboard or console (see [logons](../important-events/logins.md)). So `kyle.ward` sat down at `fin-ws-014` at 02:58. Fourteen minutes later that machine looked up the new domain. Attackers care about 4624 because it shows exactly which account was used where — and defenders care for the same reason.

Two cautions. First, correlation needs **time windows**: the right DHCP lease is the one that was valid at the event time, and the right logon is the latest one on that host before the event with no logoff in between. Second, an IP on a shared machine (terminal server, NAT gateway, proxy) maps to many users, so "the user" can be a guess. Say so in the report.

## Field normalisation and common information models { #normalization }

### The problem { #normalization-problem }

Every vendor names fields its own way. Here is the **source IP** of a connection, as five different sources write it:

```
Zeek conn.log (JSON):        "id.orig_h": "10.0.10.3"
Windows Firewall log (W3C):  src-ip 10.0.10.3
Palo Alto traffic (CSV):     ...,10.0.10.3,...          (column "Source address")
Sysmon Event ID 3:           <Data Name="SourceIp">10.0.10.3</Data>
Windows 4624:                <Data Name="IpAddress">10.0.10.3</Data>
```

All five mean "the machine where this started". To find every connection from 10.0.10.3 without normalisation you need to know all five names and write:

```
id.orig_h=10.0.10.3 OR src-ip=10.0.10.3 OR src_addr=10.0.10.3 OR SourceIp=10.0.10.3 OR IpAddress=10.0.10.3
```

That works until someone adds a sixth source and forgets to tell the analysts. Then the sixth source is silently missing from every search and every rule. That is the real cost: not typing, but **gaps nobody notices**.

**Field normalisation** solves this by mapping each source's field to one agreed name. The set of agreed names (and agreed meanings and value formats) is called a **common information model**, common event model, data model or schema depending on the product. After normalisation the search is just:

```
source.ip=10.0.10.3        (or src=10.0.10.3, src_endpoint.ip=..., depending on the model)
```

### The common models you will meet { #models }

| Model | Used by | Source IP | User | Notes |
| --- | --- | --- | --- | --- |
| Splunk CIM (Common Information Model) | Splunk, Splunk ES | `src` | `user` | Organised as data models (Authentication, Network Traffic, Endpoint…), mostly applied at search time |
| ECS (Elastic Common Schema) | Elastic, many shippers | `source.ip` | `user.name` | Dotted, nested names; being merged into OpenTelemetry semantic conventions |
| OCSF (Open Cybersecurity Schema Framework) | AWS Security Lake and many vendors | `src_endpoint.ip` | `user.name` / `actor.user.name` | Vendor-neutral, organised by event class with numeric IDs |
| ASIM (Advanced Security Information Model) | Microsoft Sentinel | `SrcIpAddr` | `TargetUsername` / `ActorUsername` | Mostly query-time parsers (functions like `_Im_Authentication`) |
| UDM (Unified Data Model) | Google Security Operations | `principal.ip` | `principal.user.userid` / `target.user.userid` | Uses principal / target / src / observer nouns |

You do not need to memorise all five. You need to know **which one your SIEM uses**, where its field list is documented, and that a field like `src` in your SIEM may have been `id.orig_h` in the raw log.

### Three ways it is done { #normalization-how }

**1. Rename at ingest.** The pipeline renames `id.orig_h` to `source.ip` before storing. Searches are simple and fast. The original name is gone, so people looking at raw Zeek documentation may be confused, and if the mapping was wrong, the stored data is wrong.

**2. Copy at ingest.** The pipeline keeps `id.orig_h` and adds `source.ip` with the same value. Both names work. Costs a little more storage. This is common in ECS-style pipelines that also keep the original event in a field such as `event.original`.

**3. Alias at search time.** Nothing is changed in storage. When you search, the SIEM translates `src` into `id.orig_h` for Zeek data, `src-ip` for firewall data, and so on. Splunk field aliases and Sentinel's ASIM parser functions work this way. The raw data stays untouched and mappings can be fixed later, but searches are a bit slower and depend on the mapping being installed for that source.

A Splunk example of option 3, so you can recognise it (this goes in a configuration file called `props.conf`, normally maintained by the SIEM engineer):

```
[zeek:conn]
FIELDALIAS-cim_src  = "id.orig_h" AS src
FIELDALIAS-cim_dest = "id.resp_h" AS dest
EVAL-action = if(conn_state IN ("REJ","S0"), "blocked", "allowed")
```

Line by line: `[zeek:conn]` — these settings apply to events whose source type (Splunk's label for a log format) is `zeek:conn`. `FIELDALIAS-cim_src = "id.orig_h" AS src` — whenever someone searches this data, also make the value of `id.orig_h` available as `src`. The text after `FIELDALIAS-` is just a name for the setting. The second line does the same for destination. `EVAL-action = ...` — compute a new field `action` at search time: if Zeek's connection state is `REJ` (rejected) or `S0` (no reply), call it `blocked`, otherwise `allowed`. That is **value** normalisation, the next topic. (Real mappings are more careful than this; `S0` can also mean a dropped packet rather than a block.)

### Values and meanings, not just names { #normalization-values }

**[Supplement]** Renaming fields is only half the job. The **values** also need a common form:

- Firewall actions: `allow`, `accept`, `permit`, `pass`, `ALLOWED`, `1` → `allowed`.
- Usernames: `CORP\kyle.ward`, `kyle.ward@corp.example`, `KYLE.WARD` → `kyle.ward`, with the domain kept in its own field.
- Protocols: `6`, `tcp`, `TCP` → `tcp`.
- Times: local time strings, epoch seconds, ISO 8601 with zone → one standard (UTC, ISO 8601).

Without this, `action=allowed` finds one vendor's events and misses the rest, and `user=kyle.ward` misses every event that wrote `CORP\kyle.ward`.

And **meanings** can still differ under the same name. Behind a NAT gateway, the firewall's `src` is the gateway's address, not the workstation's. In event 4624, `IpAddress` is the machine the logon came **from**, but for a local console logon it is `-` or `127.0.0.1`. An analyst who treats every `source.ip` as "the attacker's machine" will draw wrong conclusions. When something looks odd, open the raw event (`event.original`, `_raw`) and check what the source itself meant.

### The trap: a field that is not in the raw log { #normalization-trap }

You find `source.ip` in the SIEM, then go to the raw Zeek file on the sensor and search for `source.ip`. Nothing. The field never existed there; the SIEM made it. The same happens in reverse: a colleague tells you to search `SourceIp` because "that's what Sysmon calls it", and in your SIEM it returns nothing because it was renamed at ingest. When a field name seems to be missing, the first suspect is normalisation. Your SIEM's data-model documentation, or a side-by-side look at `_raw`/`event.original` and the parsed fields, settles it in a minute.

## Categorisation { #categorisation }

### The problem { #categorisation-problem }

You need every login attempt by `mike` across the organisation. Without categorisation, you need to know what a login looks like in every source:

```
# Windows: success and failure events
index=windows (EventCode=4624 OR EventCode=4625) TargetUserName=mike

# Linux sshd: two different sentences
index=linux process=sshd ("Accepted password for mike" OR "Failed password for mike" OR "Accepted publickey for mike")

# Cloud identity provider sign-in logs, VPN, web applications, network devices ... each with its own wording
```

**4624** is a successful logon and **4625** a failed one; both are written by the machine that checked the password. Attackers generate floods of 4625 when guessing passwords (T1110, Brute Force) and a single quiet 4624 when they use stolen credentials (T1078, Valid Accounts). The Linux lines come from the SSH server's free-text messages. A junior analyst may know none of this, and even a senior one will forget the VPN.

### What categorisation does { #categorisation-what }

The parser attaches a **category** to every event it understands, describing what kind of thing happened, plus a few standard fields for the outcome. After that, one search works:

```
tag=authentication user=mike
```

In Splunk CIM, `tag=authentication` marks events that belong to the Authentication data model, and `action` is normalised to `success` or `failure`. Here is how a single failed SSH login looks after categorisation in an ECS-style SIEM, next to the raw line it came from:

```
Nov 20 03:20:07 web-07 sshd[48211]: Failed password for mike from 198.51.100.23 port 51544 ssh2
```

```json
{
  "event.original": "Nov 20 03:20:07 web-07 sshd[48211]: Failed password for mike from 198.51.100.23 port 51544 ssh2",
  "event.category": ["authentication"],
  "event.type": ["start"],
  "event.outcome": "failure",
  "user.name": "mike",
  "source.ip": "198.51.100.23",
  "source.port": 51544,
  "host.name": "web-07",
  "process.name": "sshd",
  "process.pid": 48211
}
```

Line by line: `event.original` keeps the raw line, so you can always check the source; `event.category: authentication` says what kind of event it is; `event.type: start` says it was an attempt to begin a session; `event.outcome: failure` is the result; the remaining fields are the normalised user, source, host and process. A Windows 4625 for `mike` would produce exactly the same `event.category`, `event.type` and `event.outcome`, with `user.name: mike` — so a search for `event.category:authentication AND event.outcome:failure AND user.name:mike` finds both, without anyone needing to know either format.

In OCSF the same idea uses numbered classes: the **Authentication** class (`class_uid` 3002, in the Identity & Access Management category) with an `activity_id` of 1 for logon and a `status_id` of 1 or 2 for success or failure. Sentinel's ASIM uses an `_Im_Authentication` parser with `EventResult` set to `Success` or `Failure`.

### When the SIEM cannot categorise: tags { #tags }

Some SIEMs categorise little out of the box. The simple fallback is **tagging**: a rule in the pipeline (or a saved search definition) that adds the word `login` to every event matching known login patterns. As long as everyone knows the tag exists, `tag=login user=mike` does the job. The weakness is the same as with normalisation: the tag only covers the patterns someone wrote. A new VPN appliance whose logins nobody tagged is invisible to every tag-based search and rule.

**[Caution]** Before trusting a category-based search, ask: which sources feed this category? Splunk's CIM, for example, lets you check which source types populate the Authentication data model. If the VPN is not in the list, "no failed logins by mike" means "no failed logins by mike **in the sources we categorised**".

## Log storage { #storage }

### Like with like { #storage-indexes }

The last step is writing the event somewhere it can be found again. Whatever the database underneath, most SIEMs **store similar logs together**: one place for firewall logs, one for Windows, one for proxy, one for IDS. Splunk calls these places **indexes**, Elastic uses indices or **data streams**, Sentinel uses **tables**. Settings that apply to a whole log type — parsing, access control, retention — are often attached at this level.

For you as a searcher, this means you should **name the storage area** in your search: `index=proxy`, `index=windows`, a specific Sentinel table, an Elastic data view. You can leave it out, but then the SIEM searches every storage area, which is slow and returns noise from log types you did not want. (We saw the same idea from the field side on the [formats page](formats-structure.md#not-google).)

### Retention: how long each type is kept { #retention }

Storage is finite, so each log type gets a **retention period**. One organisation might keep firewall logs for 30 days (huge volume, moderate value), DNS and proxy for 90 days, Windows security and authentication logs for a year, and legal or audit trails for seven years. These numbers come from three pressures: **compliance** (some regulations and government policies specify minimums — for example, US federal agencies' logging policy M-21-31 sets 12 months in active storage and 18 more in cold storage for many log types), **investigation needs**, and **cost**.

**[Supplement]** The investigation need is easy to underestimate. Intrusions are often discovered weeks or months after they began. If proxy logs are kept for 30 days and the first beacon was 45 days ago, the start of the story is gone. When retention is set, ask "if we find a compromise today, how far back do we need to look?" — not just "how much disk do we have?".

### Hot, warm, cold, frozen { #tiers }

Most SIEMs move data through **storage tiers** as it ages, trading search speed for cost:

| Tier | Typical hardware | Search speed | Typical age |
| --- | --- | --- | --- |
| Hot | Fast SSD, being written to | Fastest | Hours to days |
| Warm | SSD or fast disk, read-only | Fast | Days to weeks |
| Cold | Cheaper disk or object storage | Slower | Weeks to months |
| Frozen / archive | Object storage, tape, offline | Slow, or not searchable until restored | Months to years |
| Deleted | — | Gone | After retention ends |

Product names vary: Splunk moves data in "buckets" through hot → warm → cold → frozen, where frozen means **deleted by default** unless an archive location is configured (archived buckets must be "thawed" to search again); Elastic's index lifecycle management moves indices through hot → warm → cold → frozen → delete, with frozen data searched from snapshots in object storage; cloud SIEMs offer an analytics tier plus cheaper lake or archive tiers with longer retention and slower, more limited queries.

Here is a Splunk index definition, the kind of file your SIEM engineer maintains, so you can read it:

```
[proxy]
homePath   = $SPLUNK_DB/proxy/db
coldPath   = $SPLUNK_DB/proxy/colddb
thawedPath = $SPLUNK_DB/proxy/thaweddb
frozenTimePeriodInSecs = 7776000
maxTotalDataSizeMB = 500000
coldToFrozenDir = /archive/splunk/proxy
```

- `[proxy]` — the index name. This is what `index=proxy` refers to.
- `homePath` — where hot and warm data live (usually fast disk).
- `coldPath` — where cold data lives (often slower, bigger disk).
- `thawedPath` — where archived data is put back if someone restores it.
- `frozenTimePeriodInSecs = 7776000` — data older than 7,776,000 seconds leaves the index. 7,776,000 ÷ 86,400 seconds per day = **90 days**.
- `maxTotalDataSizeMB = 500000` — the index may not grow beyond about 500 GB. If it does, the **oldest** data is frozen early, even if it is younger than 90 days.
- `coldToFrozenDir` — instead of deleting frozen data, copy it to this archive directory. Without this line, frozen means deleted.

**[Caution]** The size limit is the one people forget. A noisy week — a scanning worm, a misconfigured application, or an attacker deliberately flooding logs — can push the index past its size cap and quietly evict data that the time-based policy promised to keep. "We keep 90 days" is only true if the size cap is large enough for the busiest 90 days.

### The log life cycle { #life-cycle }

Logs follow a natural life cycle, and storage tiers are built around it:

1. **Written** — the event is created and ingested.
2. **New** — fresh data, used every day for alerting, triage, hunting and incident response. Lives on hot storage.
3. **Ageing** — days to months old; searched less and less. Moves to warm, then cold.
4. **Old** — very unlikely to be needed except for compliance or a long-running investigation. Archived, possibly offline.
5. **Deleted** — retention has ended.

What this means in practice:

- Searches over the last day or week are fast. Searches that reach back months are slower, may time out, or may skip data that is in a tier your search does not cover.
- Archived data often has to be **restored** (rehydrated, thawed, reloaded) before you can search it. That can take hours and sometimes needs a ticket to another team. If you will need old data in an incident, ask for the restore early.
- "No results" for a period older than the hot/warm window may mean "not searched", not "did not happen". Check the time range your SIEM actually covered.

A worked example: you learn today (20 November) that a vendor's software update was trojanised from 2 August. With the policy above, proxy logs from August are frozen; if the archive directory exists, they can be thawed, otherwise they are gone. Windows security logs kept for a year are still searchable, though from cold storage and slowly. EDR telemetry kept for 30 days covers none of the start. That one sentence — "we need August" — is why knowing these numbers before an incident matters.

## Questions for your SIEM engineer { #questions }

You may not choose these settings, but you live with their consequences. A missing log because the agent never collected it looks identical to an attack that never happened. Get answers to these and keep them in your team wiki.

**Data collection**

- Which systems do we collect from: all servers and workstations, or only some? Which cloud services?
- Which channels or files are collected from each type of system (Security only, or Sysmon, PowerShell, Defender, task scheduler too)?
- What filters are applied, where, and where are those configurations kept?

**Data use**

- Which common information model does our SIEM use, and where is its field list?
- Which sources feed each category or data model (Authentication, Network Traffic, Endpoint)?
- Which fields are indexed for fast search (product dependent)? Which enrichments exist, and are they ingest-time or search-time?

**Data storage**

- What is the retention for each log type, and are there size caps that can cut it short?
- How long is data hot/warm (fast) vs cold/archive (slow or needs restoring), and how do I request a restore?

**[Supplement]** You can answer some of these yourself. In Splunk, this search lists what is actually arriving:

```
| tstats count latest(_time) AS last_seen WHERE index=* BY index sourcetype
| eval last_seen=strftime(last_seen, "%Y-%m-%d %H:%M")
| sort index sourcetype
```

- `| tstats ...` — a fast command that reads only index metadata instead of whole events. It must start with a pipe because it is a generating command (it creates results rather than filtering them).
- `count latest(_time) AS last_seen` — for each group, count the events and find the newest event time, naming it `last_seen`.
- `WHERE index=*` — across all indexes you are allowed to see (respecting the time picker).
- `BY index sourcetype` — one row per index and source type.
- `eval last_seen=strftime(...)` — `eval` creates or changes a field; `strftime` turns the epoch number into a readable date.
- `sort index sourcetype` — order the rows.

Output:

```
index     sourcetype              count      last_seen
dns       zeek:dns                18233412   2026-11-20 09:41
linux     linux_secure              912337   2026-11-20 09:41
proxy     squid:access            40117200   2026-11-20 09:41
windows   XmlWinEventLog:Security 25441090   2026-11-20 09:40
windows   XmlWinEventLog:Sysmon      1842   2026-11-12 22:05
```

The last row is the kind of thing this check exists to find: run over the last 30 days, Sysmon has only a few thousand events and the newest is from eight days ago, while every other source is current. Sysmon data stopped arriving on 12 November, and every Sysmon-based rule has been blind since then. (`tstats` only returns rows for data that exists in the time range, so a source that stopped before the range starts simply disappears from the list — run it over a window long enough to include the last time each source was seen.)

## The whole pipeline in one view { #summary }

```
Log generated → Collect → Parse → Normalise → Enrich → Index → Store → Search / Alert
```

| Stage | What you should know | How it fails silently |
| --- | --- | --- |
| Collect | Agent or agentless, which hosts, which channels, which filters | Host or channel not collected; filter drops what you need; agent stopped |
| Parse | Format, parser, fields extracted | Field not extracted; columns shifted after an upgrade |
| Normalise | Model in use, field names, value mapping, which sources are mapped | New source not mapped; same name, different meaning |
| Enrich | What is added, from where, when (ingest/search time) | Stale table; point-in-time vs current confusion |
| Index | Which fields are indexed, how to scope searches | Slow or timed-out searches on non-indexed fields |
| Store | Retention and tiers per type, size caps, restore process | Data aged out or frozen; search did not cover the tier |

The goal is not to become the SIEM engineer. It is to be able to say, for any log you are chasing, what happened to it at each step — so that when it is not where you expect, you know where to look next rather than concluding nothing happened.

## Putting it to work in a SOC { #soc-use }

When you triage an alert, hunt, or a search returns nothing:

1. **Raw vs added.** Which fields came from the source and which were added by enrichment or normalisation? Open the raw event when it matters.
2. **Time of truth.** Is each enrichment point-in-time or current? For IP-to-host and IP-to-user, confirm with DHCP and logon events from the time of the event.
3. **Model.** Search with the normalised fields, but know the raw names for each source you rely on.
4. **Coverage.** Does every relevant source feed the category or data model you are searching? If not, add a raw search for the missing ones.
5. **Storage.** Name the index/table. Check that your time range is inside the searchable tiers; ask for restores early.
6. **Health.** Check that each source is still arriving (latest event time per source) before trusting "no results".

## The 2026 view { #trends }

!!! success "[2026 Current] Still valid"
    Everything on this page still holds: enrichment is still one of the biggest value-adds of a SIEM, ingest-time vs search-time is still the key question for historical accuracy, normalisation and categorisation are still what let one search and one rule cover many sources, and hot/warm/cold tiers with per-type retention are still how SIEMs control cost. The questions for your SIEM engineer have not changed.

!!! info "[Changed] What has changed"
    - **Open schemas.** OCSF reached 1.0 in 2023 and joined the Linux Foundation in late 2024; it keeps publishing 1.x releases and is used natively by AWS Security Lake and supported by many security vendors. Elastic contributed ECS to OpenTelemetry in 2023 and the two are being converged into OpenTelemetry semantic conventions. Splunk CIM, Microsoft ASIM and Google UDM remain the product models. Expect to translate between at least two of these in your career.
    - **Normalisation moved earlier in the pipeline.** Security data pipeline products (and the SIEMs' own pipeline features) now commonly route, filter, enrich and convert to a schema such as OCSF or ECS **before** data reaches the SIEM, often sending full-fidelity copies to cheap storage and a reduced copy to the SIEM. That makes the "what happened to my log on the way" question even more important.
    - **Cheap lake tiers.** Cloud SIEMs now pair an expensive analytics tier with a much cheaper data-lake tier. Microsoft Sentinel's data lake became generally available in 2025 with long retention (up to 12 years); other vendors offer similar lake, federated-search or archive tiers. Data in these tiers is usually searchable without restoring, but with slower queries, fewer features and sometimes per-query cost — and detection rules may not run on it.
    - **AI-assisted enrichment and summaries.** Many SIEM and SOAR products now add AI-generated alert summaries and enrichment. Treat these like any other enrichment: know where the information came from, and verify it against the raw events before acting on it.

!!! warning "[Caution] Things that are wrong or risky to do the old way"
    - **Do not treat current lookup tables as history.** Using today's DHCP or CMDB table to say which machine had an IP last month can name the wrong host — and the wrong person.
    - **Do not assume a category search covers every source.** Check which sources feed it; new and cloud sources are the usual gaps.
    - **Do not drop low-value data at the pipeline to save SIEM cost without keeping it somewhere.** Route it to a lake or archive tier instead; you cannot enrich or search what was thrown away.
    - **Do not trust "we keep 90 days" without checking size caps** and what happens at freeze (archive or delete).
    - **Do not report "no activity" for a period you could not actually search** (frozen, archived, or outside the lake query's range). Say what was searched.

## Practice questions { #quiz }

### Question 1

An alert shows a connection from `10.0.10.3` to a known-bad IP on 3 November. Your SIEM's search-time lookup says 10.0.10.3 is `hr-lt-201`, owned by an HR employee. You are asked to quarantine that laptop. What should you check first, and why?

??? success "Answer and explanation"
    Check whether the IP-to-host mapping is **point-in-time** or **current**. A search-time lookup uses today's table, so it tells you who has 10.0.10.3 **now**, not on 3 November. DHCP leases change daily, so the machine that made the connection may be a completely different host.

    Confirm with time-stamped evidence from 3 November: the DHCP server's lease log for 10.0.10.3 valid at the connection time (lease granted before it, not yet expired or released), and ideally a 4624 logon on that machine shortly before. If your pipeline does ingest-time host enrichment, the `host.name` stored on the original event is also good evidence. Only then quarantine — otherwise you might isolate an innocent HR laptop while the real infected machine keeps running. In the report, note where the mapping came from.

### Question 2

A colleague runs `tag=authentication action=failure user=svc_backup` over the last 7 days and finds nothing, so they write "no failed logins for the service account". The account is also used to log in to a new VPN appliance added last month and to Linux servers over SSH. What is wrong with the conclusion, and how do you check it?

??? success "Answer and explanation"
    The search only finds events from sources whose parsers **categorise** them as authentication and normalise `action` and `user`. A VPN appliance added last month may not be mapped to the Authentication model at all, so its failures are invisible to this search. The Linux sshd events are probably mapped, but only if the add-on/parser for that source is installed and the `user` value is normalised the same way.

    Check coverage: list which source types feed the Authentication data model (or category) and see whether the VPN is there. Run a raw search on the VPN index for `svc_backup` and its failure wording, and confirm that sshd failures (`Failed password for svc_backup` / `Invalid user`) are categorised. The correct conclusion until then is "no failed logins **in the categorised sources** (list them)". Then ask the SIEM engineer to map the VPN source.

### Question 3

Your Splunk proxy index has `frozenTimePeriodInSecs = 7776000`, `maxTotalDataSizeMB = 300000` and no `coldToFrozenDir`. Normal volume is 2.5 GB per day. Last month, a misconfigured application tripled proxy volume for 30 days. What retention do you really have, and what happens to the oldest data?

??? success "Answer and explanation"
    `7776000` seconds = 90 days of intended retention. At normal volume, 90 days is about 225 GB, under the 300 GB cap, so normally you do have 90 days.

    During the bad month, 30 days were about 7.5 GB per day = 225 GB. Add the other 60 days at normal volume (150 GB) and the 90-day window would need about 375 GB — over the 300 GB cap. Splunk freezes the **oldest** buckets to stay under the cap, so you lose roughly the oldest 75 GB, around 30 days of normal-volume data: effective retention drops to about 60 days (the exact figure depends on compression and bucket sizes).

    Because there is no `coldToFrozenDir`, frozen means **deleted** — there is no archive to thaw. Fixes: raise the cap to fit the busiest 90 days, add an archive location, alert when an index nears its cap, and fix or filter the noisy source. And remember: an attacker who can generate log volume can use the same effect to push evidence out.

## Related { #related }

- [Log collection](collection-methods.md) — how events reach the SIEM
- [Log formats and structure](formats-structure.md) — parsing, indexing and scoping searches
- [Logons: 4624, 4625, 4648](../important-events/logins.md) — the authentication events behind categorisation
- [Domain age and reputation signals](../dns/domain-signals.md) — what domain enrichment is based on
- [Splunk data discovery](../../../blueteam/splunk/data-discovery.md)
- [Log aggregation](../../network-forensics/part-2/log-aggregation.md)

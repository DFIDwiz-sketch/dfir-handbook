---
title: "Log Collection — the Logging Pipeline, Agents vs Agentless, Windows and Linux Collection Options"
tags:
  - training
  - blue-team
  - logging
  - siem
  - windows
  - linux
---

# Log Collection — the Logging Pipeline, Agents vs Agentless, Windows and Linux Collection Options { #collection-methods }

!!! abstract "What this page covers"
    Why an analyst who never builds a SIEM still has to understand how logs get into it, and the stages every log passes through on the way: source → collection → aggregator → parsing/enrichment → indexing and storage → search, reporting and alerting — with what each stage can add, change, delay or silently drop. Then the two ways logs leave a host (an **agent**, or **agentless** push/pull), and the concrete options on Windows (SIEM vendor agents, Windows Event Forwarding, third-party agents, PowerShell/WMI/RPC pulls) and Linux (the built-in syslog daemon, vendor and third-party agents, scripts). Every configuration sample is read line by line, along with the events and time fields that tell you when the pipeline itself is broken or has been tampered with. Practice questions with explanations at the end.

!!! note "Labels"
    **[Supplement]** = practical material you need to know, **[Correction]** = a commonly repeated claim that is wrong or outdated, **[Changed]**/**[Caution]** = what has changed recently and what is risky to do the old way. Hostnames, domains, accounts, IPs and file names are invented for illustration (`.example`, documentation and private IPs).

## The 8 key points { #key-points }

1. The event you see in the SIEM is **not** the event the host wrote. On the way it may be **converted, filtered, parsed, renamed, enriched and delayed**. Knowing which parts are original and which were added later is what keeps an investigation honest.
2. The pipeline has the same functional blocks in every product: **log sources → collection → aggregator → parsing/enrichment → indexing/storage → search/reporting and alerting**. Products differ in which box does which job, not in the jobs.
3. An **aggregator** exists to accept huge volumes, in many formats, from many devices, at high speed — and to clean, parse, filter and standardise before storage. Big or spread-out environments run several.
4. **Alerting is just searching on a schedule.** An alert can never be faster than collection lag + indexing lag + the search schedule.
5. Logs leave a host in one of two ways: an **agent** (a dedicated, always-running process) or **agentless** (something logs in and **pulls**, or a scheduled script **pushes**). Agents are usually preferred because they **filter, buffer, compress and encrypt**.
6. On Windows the options are: **SIEM vendor agents**, the built-in **Windows Event Forwarding (WEF)**, **third-party agents**, and **agentless** pulls via PowerShell, WMI or RPC. Keep Windows events structured (XML or **JSON**) — converting them to syslog text throws structure away.
7. WEF moves native XML events from many hosts into the **Forwarded Events** channel of a collector server, where **one** agent ships them on. The original host name stays in the event's `Computer` field — make sure the SIEM uses it.
8. On Linux the built-in **rsyslog/syslog-ng** daemon is the usual agent; forwarding can be one line, but a reliable setup needs TCP/TLS, a disk queue and a "this host went silent" alert.

## Why an analyst must understand the pipeline { #why }

In many organisations, someone else builds the SIEM. The analyst just opens a search bar and types. That works until the day a search returns something that doesn't make sense:

- A field called `src_country` says `RU` — but there is no such field in a Windows event. Who wrote it, and from which IP?
- A logon at "09:14" appears in the SIEM at 09:31. Did the attacker manipulate time, or was the pipeline slow?
- A domain controller shows no 4769 events at all yesterday. Did nobody use Kerberos, did the DC stop logging, or did a filter on the collector drop them?
- Every forwarded event says `host=WEC01`. Did one server really log on to the whole network?

Each of these has an answer **inside the pipeline**, not inside the attack. Think of a parcel sent through a courier network. The sender packs a box (the host writes an event). A van picks it up (collection), it goes to a sorting hub (aggregator) where staff weigh it, stick on barcodes and sometimes repack it (parsing, enrichment, format conversion), then to a warehouse with a catalogue (indexing and storage), and finally a clerk can find it by searching the catalogue (search) or a rule says "call me when a box from this sender arrives" (alerting). When the box arrives late, damaged or with extra labels, you need to know which step did it. The label "Fragile — handled by Hub 3" was not written by the sender.

Back to the technical reality: as an analyst, you need to be able to say for any field **"this came from the source"** or **"this was added by the pipeline"**, and for any gap **"no data because nothing happened"** versus **"no data because the pipeline lost it"**. Without that, it's easy to draw a wrong conclusion, and easy to miss chances to make the logs better (a missing field that could be extracted, a channel nobody collects).

## The logging pipeline, box by box { #pipeline }

```
 Log sources          Collection         Aggregator(s)            Storage / index          Use
+-------------+     +-----------+     +------------------+     +------------------+     +--------------+
| Windows     | --> | agent     | --> | accept at speed  | --> | parse (if not    | --> | search       |
| Linux       |     | WEF       |     | parse / clean    |     |  done yet)       |     | dashboards   |
| firewalls   |     | syslog    |     | enrich / filter  |     | index            |     | reports      |
| cloud APIs  |     | scripts   |     | buffer / route   |     | store (hot/cold) |     | alerts =     |
+-------------+     +-----------+     +------------------+     +------------------+     | scheduled    |
                                                                                        | searches     |
                                                                                        +--------------+
```

- **Log sources.** Everything that writes events: the Windows Event Log service, syslog daemons, applications, network devices, cloud services. How these produce logs is covered in [Windows Logging](../windows-logging/index.md) and [Linux Logging](../linux-logging/index.md).
- **Collection.** Something must move each event off the host. This is the first step that can **change the event** (format conversion, for example XML to JSON) or **drop it** (a filter rule). It is covered in detail below.
- **Aggregator.** The receiving tier. Its first job is simply to **take in events fast** — tens of thousands per second, from thousands of devices, in many formats (syslog over UDP and TCP, agent protocols, HTTP). Then, depending on the product, it may **parse** (split text into fields), **clean** (fix timestamps, drop junk), **enrich** (add geo-IP, asset owner, threat-intel tags), **filter** (discard noisy events) and **route** (security events to the SIEM, debug logs to cheap storage), and finally output in a more standard format. There may be several aggregators: to handle more volume, or one per region or site so logs don't cross slow links in raw form.
- **Indexing and storage.** The heavy lifter. If the aggregator didn't parse and enrich, this tier does. It writes events to permanent storage **and** builds an index — a database-like structure that maps values to events, the way a book's index maps words to pages — so that a search for `TargetUserName=svc-backup` over 90 days returns in seconds instead of scanning every byte.
- **Search, reporting and alerting.** Analysts search; dashboards and reports are saved searches drawn as charts; **alerts are saved searches that run on a schedule and take an action** (create a ticket, notify) when they return results. They usually run on the storage tier, because they are data searches too.

### What each box can do to your event { #what-changes }

| Stage | Can add | Can change | Can delay | Can drop |
| --- | --- | --- | --- | --- |
| Collection | Agent metadata (agent name/version, collector host) | Format (XML → JSON or text), rendered message text | Batching, polling interval | Channel not configured, event ID filter, permissions |
| Aggregator | Geo-IP, asset/owner, threat-intel tags, normalised field names | Timestamps (time zone fixes), field names, truncation of long values | Queues, back-pressure | Filters, parse failures sent to a "dead letter" place, UDP overload |
| Indexing/storage | Index time, extracted fields | Field types (string vs number) | Indexing backlog | Licence/volume caps, retention expiry |
| Search/alerting | Calculated fields, lookups | — | Schedule (e.g. every 15 min) | Search time window too short for the lag |

### Two clocks on every event { #two-clocks }

Each event in a SIEM normally carries at least two times: **when it happened on the host** and **when the SIEM received or indexed it**. In Elastic Common Schema (ECS) these are `@timestamp` (event time) with `event.created` (when the agent/pipeline first saw it) and `event.ingested` (when it reached the central store); in Splunk they are `_time` and `_indextime`. A worked example of one failed logon:

```
09:14:02.311  WS-HR-0231 writes 4625 (TimeCreated SystemTime="2026-11-20T09:14:02.311Z")
09:14:05      agent sends a batch (batch interval 3 s)
09:14:06      aggregator AGG01 receives, parses, adds geo and asset owner
09:14:09      indexer writes it            -> event.ingested = 2026-11-20T09:14:09Z
09:20:00      brute-force rule runs (every 5 min, looks back 10 min) -> alert
```

Reading it line by line: the **event time** (09:14:02) comes from the host's `TimeCreated` field and is what you put in your timeline. The 3-second agent batch and the 3-second index delay are normal. The **alert** fires at 09:20 because the rule runs every five minutes — nothing was "missed"; that is the design. If instead `event.ingested` were 11:47 for a 09:14 event, the host was probably offline or its agent was queuing — important when you ask "when could we first have known?". And if event time is **later** than ingest time, the host clock is wrong. Always check the gap between the two clocks before drawing conclusions from timing.

<strong>[Supplement]</strong> Two practical rules follow. First, a scheduled rule must look back **further than its schedule plus the normal lag**, or events that arrive late fall between two runs and are never evaluated. Second, a laptop that was off the network for a weekend uploads Saturday's events on Monday: time-based searches on **ingest time** find them, searches on **event time** for "the last hour" do not.

## Getting logs off the endpoint: agent vs agentless { #agent-vs-agentless }

```
                 +---------------------+
   pushed by --> |                     |
   an agent      |                     |
                 |   Log aggregator    |
   pushed by --> |                     |
   a script      |                     |
                 |                     |
   pulled by <-- |  (logs in remotely) |
   a tool        +---------------------+
```

**Agent.** A separate process that runs all the time in the background with one job: reliably pick up logs and send them over the network. It can come from the operating system, from the SIEM vendor, or from a third party. Why agents are usually preferred:

- **Many sources at once** — event channels, text files, the journal — configured in one place.
- **Filtering by content** before anything crosses the network.
- **Buffering**: if the aggregator is down, events queue in memory or on disk and are sent later instead of lost.
- **Compression and encryption** on the wire.
- **Health**: most send a heartbeat, so a silent agent is noticeable.

Here we count anything that is a constantly running process dedicated to log shipping as an agent — even if it ships with the OS.

**Agentless.** Used when an agent can't or mustn't be installed (appliances, legacy systems, "no more agents" policies, systems owned by another team). Two shapes:

- **Pull**: a collector **logs in remotely** on a schedule and reads the logs (PowerShell remoting or RPC on Windows, SSH on Linux, or a cloud service's API).
- **Push**: a **scheduled script on the host** reads new logs and sends them out (for example a cron job or scheduled task posting to an HTTP endpoint).

An analogy: an agent is a full-time post clerk who sits in the building, sorts outgoing mail all day and keeps it in a locked bag if the van is late. Agentless pull is a courier who drops by every few hours with a master key and grabs whatever is in the out-tray; agentless push is someone in the office who, every hour, carries a pile to the post office themselves. Both can work — but if the out-tray overflows between visits, letters are lost, and the courier's master key is a juicy thing to steal.

Whichever method you use, it is **the first step that can change the log** (format conversion) or **filter it out**. That's why "how is this source collected?" is the first question when something looks odd.

## Windows log collection options { #windows }

| Option | Examples | Strengths | Weak points |
| --- | --- | --- | --- |
| SIEM vendor agent | Splunk Universal Forwarder, Elastic Agent / Winlogbeat, QRadar WinCollect, LogRhythm System Monitor, Microsoft's Azure Monitor Agent | Works with its SIEM out of the box, fast setup, central management, field parsing ready-made | One more agent on every machine; tied to one vendor |
| Built-in: Windows Event Forwarding (WEF) | Built into Windows; collector role = Windows Event Collector (WEC) | Present on every host, controlled by Group Policy, push or pull, Kerberos-encrypted, compressed, native XML | More moving parts to set up (GPO, WinRM, subscriptions, permissions); still needs an agent on the collector |
| Third-party agent | NXLog, Fluentd/Fluent Bit, Snare | Flexible filtering and output formats, many destinations | Another product to maintain and secure |
| Agentless | PowerShell (`Get-WinEvent`), WMI, MSRPC (remote event log) | Quick to start, nothing to install | Scales poorly, needs firewall openings and remote-read accounts, can miss events if the log rolls over between pulls |

### Vendor and third-party agents { #win-agents }

These agents make three things easy: **choosing channels** (Security, System, Sysmon, PowerShell…), **filtering** by event ID or content, and **output format**. A Splunk Universal Forwarder, for example, is configured with two short text files. `inputs.conf` says what to read:

```ini
[WinEventLog://Security]
disabled = 0
renderXml = true
blacklist = 5156,5158

[WinEventLog://Microsoft-Windows-Sysmon/Operational]
disabled = 0
renderXml = true
```

- `[WinEventLog://Security]` — a stanza (section) that reads the **Security** event channel through the Windows event API.
- `disabled = 0` — the input is on (`1` would switch it off — a quick way for someone to silently stop collection).
- `renderXml = true` — send the event as its **original XML**, rather than the "classic" multi-line text rendering. XML keeps every `EventData` field with its name.
- `blacklist = 5156,5158` — do **not** send these event IDs (Windows Filtering Platform allowed connection and bind). They are very noisy; dropping them saves licence and storage, but it also means no host-level connection records in the SIEM. Every filter is a detection decision — write it down.
- The second stanza does the same for the Sysmon channel.

`outputs.conf` says where to send:

```ini
[tcpout]
defaultGroup = soc_indexers

[tcpout:soc_indexers]
server = 198.51.100.21:9997, 198.51.100.22:9997
useACK = true
clientCert = $SPLUNK_HOME\etc\auth\soc\client.pem
sslVerifyServerCert = true
```

- `defaultGroup = soc_indexers` — send everything to the group named below.
- `server = …:9997, …:9997` — two receivers; the forwarder **load-balances** between them and fails over if one is down. Port 9997 is the conventional receiving port.
- `useACK = true` — **indexer acknowledgement**: the forwarder keeps each block until the receiver confirms it was written. Without it, data in flight during a crash can be lost silently.
- `clientCert` / `sslVerifyServerCert = true` — TLS with a client certificate, and the forwarder checks the receiver's certificate, so a fake receiver can't harvest your logs.

A third-party agent such as NXLog looks different but does the same jobs. This one reads two channels, converts to **JSON** and sends over TLS:

```xml
<Extension _json>
    Module  xm_json
</Extension>

<Input eventlog>
    Module  im_msvistalog
    <QueryXML>
        <QueryList>
            <Query Id="0">
                <Select Path="Security">*</Select>
                <Select Path="Microsoft-Windows-Sysmon/Operational">*</Select>
            </Query>
        </QueryList>
    </QueryXML>
</Input>

<Output siem>
    Module  om_ssl
    Host    agg01.corp.example
    Port    6514
    CAFile  C:\Program Files\nxlog\cert\soc-ca.pem
    Exec    to_json();
</Output>

<Route r1>
    Path    eventlog => siem
</Route>
```

- `<Extension _json>` / `xm_json` — load the JSON module.
- `<Input eventlog>` / `im_msvistalog` — the input module for the modern Windows Event Log API (Vista and later).
- `<QueryXML>` — an **XPath query** in the same `QueryList` syntax as Event Viewer custom views and WEF subscriptions. `<Select Path="Security">*</Select>` means "all events from the Security channel". You could narrow it, e.g. `*[System[(EventID=4624 or EventID=4625)]]`.
- `<Output siem>` / `om_ssl` — send over TLS to `agg01.corp.example` port 6514, trusting only the SOC's CA file. (Exact directive names differ a little between NXLog editions and versions.)
- `Exec to_json();` — turn each event's fields into one JSON object per line.
- `<Route r1>` — connect the input to the output.

### Why JSON, not syslog text { #json-not-syslog }

Windows events are already **structured**: XML with named fields, and sometimes nested data and lists. The safest conversions keep that structure. Compare the same 4624 after two different agent settings.

Converted to **JSON** (shortened):

```json
{"EventTime":"2026-11-20T09:12:44.517Z","Hostname":"WS-HR-0231.corp.example","Channel":"Security","EventID":4624,"TargetUserName":"j.park","TargetDomainName":"CORP","LogonType":"3","IpAddress":"10.20.30.52","LogonProcessName":"NtLmSsp ","AuthenticationPackageName":"NTLM","WorkstationName":"LT-FIN-0419"}
```

Every field keeps its name. A SIEM can parse this with zero custom work, and `LogonType`, `IpAddress` and `AuthenticationPackageName` are searchable immediately.

Converted to **syslog text** (a "message" rendering, one long line, wrapped here):

```
<13>Nov 20 09:12:44 WS-HR-0231 MSWinEventLog 1 Security 88213 Fri Nov 20 09:12:44 2026 4624
Microsoft-Windows-Security-Auditing N/A N/A Success Audit WS-HR-0231 Logon An account was
successfully logged on. Subject: Security ID: S-1-0-0 Account Name: - Account Domain: - Logon
ID: 0x0 Logon Information: Logon Type: 3 ... New Logon: Security ID: S-1-5-21-...-1107 Account
Name: j.park Account Domain: CORP ... Network Information: Workstation Name: LT-FIN-0419 Source
Network Address: 10.20.30.52 ...
```

- `<13>` is the syslog PRI (facility 1 = user, severity 5 = notice) — see [facility and severity](../linux-logging/syslog.md#facility-severity). Not very meaningful for a Windows event.
- The header gives host and time, but the time has **no year in the header and no time zone**, and the milliseconds are gone.
- The body is the **rendered description**: field names and values now sit in a sentence. Worse, "Account Name:" appears **twice** — once for Subject, once for New Logon — so a simple `Account Name: (\S+)` regex grabs `-` from the Subject block instead of `j.park`.
- Descriptions are language-specific: a host with a different display language produces different text.

So the rule is: **keep Windows events as XML or JSON**. Turning them into free text means writing fragile regular expressions to get back what you already had.

### Windows Event Forwarding (WEF) { #wef }

WEF is the log forwarding built into Windows. Source machines send events in **native XML** to a server acting as a **Windows Event Collector (WEC)**. On the collector, all received events land in the **Forwarded Events** channel (`ForwardedEvents`), and a single agent on that server ships them to the SIEM.

```
  WS-HR-0231 ─┐
  WS-HR-0232 ─┤  WinRM (HTTP 5985, Kerberos-encrypted)      +--------------------+     +------+
  SRV-APP-07 ─┼──────────────────────────────────────────►  | WEC01              | --> | SIEM |
  DC01       ─┘  events selected by a subscription (XPath)  | "Forwarded Events" |     +------+
                                                            | + one agent        |
                                                            +--------------------+
```

Why organisations choose it: it is **already on every Windows host**, configured entirely by **Group Policy**, works **push** (source-initiated, the usual choice) or **pull** (collector-initiated), and traffic is **compressed and encrypted** (in a domain, WinRM over HTTP 5985 is encrypted with Kerberos; HTTPS on 5986 is used for non-domain machines). It is the answer when the security team isn't allowed "another agent on every machine": only the collectors need one.

A minimal source-initiated setup:

```
C:\> wecutil qc
```

- On the collector `WEC01`: `wecutil qc` ("quick config") sets the **Windows Event Collector service** (`Wecsvc`) to start automatically and prepares WinRM. It asks for confirmation (`Y`), then returns to the prompt.

Then a Group Policy for the sources, at *Computer Configuration → Administrative Templates → Windows Components → Event Forwarding → Configure target Subscription Manager*:

```
Server=http://WEC01.corp.example:5985/wsman/SubscriptionManager/WEC,Refresh=60
```

- `Server=http://WEC01.corp.example:5985/wsman/SubscriptionManager/WEC` — the WinRM address of the collector's subscription manager. It says `http`, but in a domain the payload is still encrypted by Kerberos.
- `Refresh=60` — every 60 seconds the source checks the collector for new or changed subscriptions.

The **subscription** on the collector (created in Event Viewer → Subscriptions, or with `wecutil cs subscription.xml`) holds an XPath query of what to send, for example:

```xml
<QueryList>
  <Query Id="0" Path="Security">
    <Select Path="Security">*[System[(EventID=4624 or EventID=4625 or EventID=4688 or EventID=4720 or EventID=4732)]]</Select>
    <Select Path="Microsoft-Windows-PowerShell/Operational">*[System[(EventID=4104)]]</Select>
  </Query>
</QueryList>
```

Each `<Select>` picks a channel and an XPath filter on the `System` part of the event (the fields covered in [event structure](../windows-logging/event-structure-channels.md)). Only matching events leave the source. The subscription also chooses a **delivery mode**: batching events to save bandwidth or sending them within about 30 seconds to minimise latency — another source of the "two clocks" gap above.

Checking that sources are actually reporting:

```
C:\> wecutil gr SOC-Baseline
Subscription: SOC-Baseline
	RunTimeStatus: Active
	LastError: 0
	EventSources:
		WS-HR-0231.corp.example
			RunTimeStatus: Active
			LastError: 0
			LastHeartbeatTime: 2026-11-20T09:15:31.000
		SRV-APP-0007.corp.example
			RunTimeStatus: Inactive
			LastError: 0
			LastHeartbeatTime: 2026-11-17T22:03:10.000
```

- `wecutil gr <name>` — "get runtime status" of the subscription `SOC-Baseline`.
- `WS-HR-0231 … Active`, heartbeat a minute ago — fine.
- `SRV-APP-0007 … Inactive`, last heartbeat **three days ago** — that server has stopped forwarding. It may be decommissioned, broken, or someone may have stopped WinRM or changed its policy. Whatever the cause, **nothing from that host has reached the SIEM for three days**, and an investigation that relies on it would see "no activity" that means nothing.

<strong>[Supplement]</strong> The most common WEF mistake: on the sources, forwarding runs as the **Network Service** account, which by default **cannot read the Security channel**. Everything else arrives, Security silently doesn't. The fix is to grant it read access (for example adding Network Service, `S-1-5-20`, to the Security channel's access list, or to the *Event Log Readers* group, by Group Policy). Always test that a 4624 from a source really appears in Forwarded Events.

What a forwarded event looks like on the collector (System part, shortened):

```xml
<System>
  <Provider Name="Microsoft-Windows-Security-Auditing" Guid="{54849625-5478-4994-a5ba-3e3b0328c30d}" />
  <EventID>4625</EventID>
  <TimeCreated SystemTime="2026-11-20T09:14:02.3110000Z" />
  <EventRecordID>1932277</EventRecordID>
  <Channel>Security</Channel>
  <Computer>WS-HR-0231.corp.example</Computer>
</System>
```

- `Channel` is still **Security** — the original channel — even though the event now sits in the collector's Forwarded Events log.
- `Computer` is still **WS-HR-0231** — the machine that wrote it.
- `EventRecordID` is the record number **on the source**, so gaps in it per host can reveal lost or deleted events.

<strong>[Caution]</strong> The agent on the collector reads all these events from **one** machine. Depending on the agent and its add-on settings, the SIEM's `host` field may be filled with the **collector's** name (`WEC01`) instead of the `Computer` field. Then every logon on the network appears to "happen on WEC01". Check that your SIEM sets the host from `Computer` for forwarded events, and when in doubt, search on that field directly.

### Agentless collection on Windows { #win-agentless }

The lightest option: a collector pulls events using built-in remote interfaces — **PowerShell** (`Get-WinEvent -ComputerName`, or PowerShell remoting), **WMI**, or the remote event log interface over **MSRPC**. Nothing to install, so it is fast to start. An example of a scheduled pull:

```powershell
$since = (Get-Date).AddHours(-1)
Get-WinEvent -ComputerName SRV-APP-0007 -FilterHashtable @{
    LogName   = 'Security'
    Id        = 4624, 4625, 4672
    StartTime = $since
} | Select-Object TimeCreated, Id, MachineName, @{n='Xml';e={$_.ToXml()}} |
    ConvertTo-Json -Compress | Out-File \\SRV-LOG-01\drop\SRV-APP-0007.json
```

- Line 1: `$since` = one hour ago — the window this run will collect.
- Line 2: `Get-WinEvent -ComputerName SRV-APP-0007` reads the event log of a **remote** machine (over RPC; the target's "Remote Event Log Management" firewall rule must allow it, and the account must be in *Event Log Readers* or be an admin there).
- Lines 3–6: `-FilterHashtable` is evaluated on the remote side, so only matching events cross the network: Security channel, IDs 4624/4625/4672, newer than `$since`.
- Line 7: keep time, ID, host name and the full XML of each event.
- Line 8: turn it into compact JSON and write it to a share where an aggregator picks it up.

Why it is "lesser used" and must be designed carefully:

1. **It doesn't scale.** One collector polling 5,000 machines every hour is slow, and every unreachable machine is a gap.
2. **It needs openings.** Firewall rules for RPC/WinRM from the collector to everything, and an **account that can read logs everywhere**. That account is a high-value target: if it is a domain admin "because it was easier", stealing its password (often stored in the script or a scheduled task) gives the attacker the whole domain. Use a dedicated account with only *Event Log Readers* rights.
3. **Rollover between pulls loses data.** Event logs are fixed-size files that overwrite the oldest events when full. Check the size:

```
C:\> wevtutil gl Security
name: Security
enabled: true
type: Admin
owningPublisher:
isolation: Custom
channelAccess: O:BAG:SYD:(A;;0xf0005;;;SY)(A;;0x5;;;BA)(A;;0x1;;;S-1-5-32-573)
logging:
  logFileName: %SystemRoot%\System32\Winevt\Logs\Security.evtx
  retention: false
  autoBackup: false
  maxSize: 20971520
publishing:
  fileMax: 1
```

- `wevtutil gl Security` — "get log" configuration for the Security channel.
- `channelAccess` — who may read: `SY` (SYSTEM), `BA` (Builtin Administrators) and `S-1-5-32-573` (*Event Log Readers*), written in SDDL. This is the list you edit for the WEF Network Service problem above.
- `retention: false` — when full, **overwrite** the oldest events (the default). `true` would stop logging when full instead, which is worse.
- `maxSize: 20971520` — **20 MB**. Rough maths: at an average of about 1 KB per event on disk, that is roughly 20,000 events. A busy server writing 100 security events per second fills it in about **3–4 minutes**. Pulling once an hour would miss almost everything. Larger log sizes help, but frequent collection (or an agent) is the real fix.

4. **Old tools disappear.** Scripts built on the `wmic` command-line tool break on current Windows 11, where it has been removed; WMI itself remains through PowerShell's CIM cmdlets — see [Changed](#trends).

### Watching the pipeline itself { #tamper }

Attackers know the logs are being shipped. Disrupting collection is a standard defence-evasion step, so a SOC should treat **collection health as a detection source**:

| Signal | What it means | ATT&CK |
| --- | --- | --- |
| Security **1102** "The audit log was cleared" | Someone (the `SubjectUserName` in the event) cleared the Security log | T1070.001 Clear Windows Event Logs |
| System **104** "The … log file was cleared" | Another channel (System, Application, …) was cleared | T1070.001 |
| Security **1100** "The event logging service has shut down" | Event Log service stopped — on a normal shutdown, or because someone stopped it | T1562.002 Disable Windows Event Logging |
| System **7036**/**7040** for the agent's service ("stopped", start type changed to disabled) | The log agent was stopped or disabled | T1562.001 Disable or Modify Tools |
| Agent heartbeat missing / WEF source `Inactive` / no events from a host for N minutes | Host off, network broken, agent killed or forwarding rule removed | T1562.006 Indicator Blocking |
| `auditpol` change (Security **4719** "System audit policy was changed") | Audit categories switched off at the source | T1562.002 |

Event 1102 deserves one more line: it is written **after** the clear, into the freshly emptied log, so the local log shows almost nothing but 1102. If the pipeline worked, the SIEM still holds everything up to the clear — the strongest argument for collecting quickly and centrally.

## Linux log collection options { #linux }

The choices look like the Windows ones, with one big difference: on Linux the **built-in syslog daemon is by far the most common agent**.

1. **Built-in syslog daemon as the agent** — **rsyslog**, **syslog-ng** (or old **syslogd**). Already installed on most distributions, flexible filtering and output formats.
2. **SIEM vendor or third-party agents** — Elastic Agent/Filebeat, Splunk Universal Forwarder, NXLog, Fluentd/Fluent Bit, Apache NiFi and others; useful for application files, the journal's structured fields, or when you want one agent family everywhere.
3. **Agentless** — scripts that push, or a collector that logs in (SSH) and pulls.

Why the syslog daemon wins on Linux: forwarding is **one line** in a configuration file, while WEF needs collectors, subscriptions, WinRM and Group Policy. The simplest forwarding rule (covered on the [syslog page](../linux-logging/syslog.md#rsyslog-config)) is:

```
*.*  @@192.0.2.10:514
```

- `*.*` — every facility, every severity.
- `@@` — over **TCP** (a single `@` would be UDP).
- `192.0.2.10:514` — the aggregator and port.

That gets logs moving. It is **not** a good final setup: no encryption, and if the aggregator is down the daemon's in-memory buffer eventually fills and messages are lost. rsyslog and syslog-ng are capable agents — they can filter, convert formats, chain to other instances and queue to disk — so it is worth checking how your distribution's default is configured. A more reliable rsyslog forwarding action, in a file such as `/etc/rsyslog.d/60-siem.conf`:

```
global(DefaultNetstreamDriverCAFile="/etc/ssl/soc/soc-ca.pem")

module(load="imjournal" StateFile="imjournal.state")

action(type="omfwd" target="agg01.corp.example" port="6514" protocol="tcp"
       StreamDriver="gtls" StreamDriverMode="1"
       StreamDriverAuthMode="x509/name" StreamDriverPermittedPeers="agg01.corp.example"
       queue.type="LinkedList" queue.filename="fwd_agg01"
       queue.maxDiskSpace="1g" queue.saveOnShutdown="on"
       action.resumeRetryCount="-1")
```

- `global(DefaultNetstreamDriverCAFile=…)` — the CA certificate used to check the aggregator's TLS certificate.
- `module(load="imjournal" …)` — read messages from the **systemd journal** (on systems where rsyslog is fed from the journal rather than the `/dev/log` socket); `StateFile` remembers the position, so a restart continues where it left off instead of re-sending or skipping. See [the systemd journal](../linux-logging/log-files-journal.md#journal).
- `action(type="omfwd" …)` — the forwarding output: to `agg01.corp.example`, port **6514** (syslog over TLS), over TCP.
- `StreamDriver="gtls" StreamDriverMode="1"` — use the GnuTLS driver and require TLS.
- `StreamDriverAuthMode="x509/name" StreamDriverPermittedPeers=…` — accept only a server whose certificate name is `agg01.corp.example`. Without this, TLS encrypts but doesn't prove who you're talking to.
- `queue.type="LinkedList" queue.filename="fwd_agg01"` — give this action its own queue; because a filename is set, it becomes **disk-assisted**: when memory fills, messages spill to disk.
- `queue.maxDiskSpace="1g"` — up to 1 GB on disk while the aggregator is unreachable.
- `queue.saveOnShutdown="on"` — keep queued messages across a restart.
- `action.resumeRetryCount="-1"` — retry forever instead of giving up and discarding.

Test it end to end:

```
$ logger -p auth.notice -t soc-test "pipeline test 4c1e"
$ ss -tnp | grep 6514
ESTAB 0 0 10.20.40.15:48212 198.51.100.30:6514 users:(("rsyslogd",pid=812,fd=11))
```

- `logger -p auth.notice -t soc-test "…"` — write a test message with facility `auth`, severity `notice`, tag `soc-test`, and a unique string to search for in the SIEM.
- `ss -tnp | grep 6514` — list TCP sockets with their process; the output shows an **established** connection from this host (`10.20.40.15`) to the aggregator on 6514, owned by `rsyslogd`. If the SIEM shows `pipeline test 4c1e` within seconds, collection works for `auth` messages.

<strong>[Caution]</strong> Distributions differ. Some current ones (Debian 12 and later, for example) don't install rsyslog by default, so only the journal exists until you add a syslog daemon or an agent that reads the journal. "We forward syslog from all Linux servers" can quietly exclude every new server.

### Agentless on Linux, and why scripts drift { #linux-agentless }

A push script scheduled with cron is the typical agentless setup:

```
*/5 * * * * root journalctl -u ssh -u sshd --cursor-file=/var/lib/soc/ssh.cursor -o json | curl -sS --cacert /etc/ssl/soc/soc-ca.pem -H @/etc/soc/ingest-header --data-binary @- https://agg01.corp.example:8443/ingest
```

- `*/5 * * * * root` — cron: every 5 minutes, as root.
- `journalctl -u ssh -u sshd` — journal entries for the SSH service (the unit is `ssh` on some distributions, `sshd` on others; listing both covers both).
- `--cursor-file=/var/lib/soc/ssh.cursor` — start after the position saved last time, and save the new position. This avoids the classic script bug: with "the last 5 minutes" (`--since "5 min ago"`), a delayed cron run leaves a **gap** and an early one sends **duplicates**.
- `-o json` — one JSON object per entry, keeping the journal's fields.
- `curl … --data-binary @-` — send the output (read from standard input) to the ingest endpoint over HTTPS, checking the server certificate with the SOC CA; the auth header is read from a root-only file instead of being typed into the crontab.

Pulls over SSH from a collector have the same weaknesses as on Windows: a collection account with access to every host (protect its key), firewall openings, and gaps if a file rotates between pulls (see [log rotation](../linux-logging/log-files-journal.md#rotation)).

## Putting it to work in a SOC { #soc-use }

When a source looks wrong or empty, walk the pipeline from the start:

1. **Source:** is the event generated at all (audit policy, channel enabled, daemon installed)?
2. **Collection:** which method collects this host — vendor agent, WEF, syslog daemon, script? Is the channel or file in its configuration? Any event-ID or content filter? Permissions (Network Service and Security)?
3. **Transport:** is the agent connected (heartbeat, `wecutil gr`, `ss`)? UDP or TCP/TLS? Is anything queued?
4. **Aggregator/parsing:** did the event arrive but fail to parse (look for "unparsed" or default source types)? Which fields were **added** here?
5. **Storage/search:** is the time gap between event time and ingest time normal? Is the search window wide enough? Is it beyond retention?
6. **Tamper:** any 1102/104/1100/4719, agent service stop, or a host that went silent right after a suspicious event?

## The 2026 view { #trends }

!!! success "[2026 Current] Still valid"
    The pipeline blocks (collection, aggregation, parsing/enrichment, indexing/storage, search/alerting), the agent vs agentless choice and its trade-offs, Windows Event Forwarding with the Forwarded Events channel, rsyslog/syslog-ng as the usual Linux agent, and "keep Windows events as XML or JSON, not syslog text" all hold exactly. Alerts are still scheduled or streaming searches, so lag still matters, and collection tampering (clearing logs, stopping agents) is still a standard attacker step.

!!! info "[Changed] What has changed"
    - **The agent landscape moved.** Elastic now steers users to the Fleet-managed **Elastic Agent** with integrations rather than separate Beats (Winlogbeat still exists). Microsoft retired the legacy Log Analytics agent (MMA) in August 2024; the **Azure Monitor Agent** with data collection rules (which use XPath filters) is the path into Microsoft Sentinel. Vendors also merged and changed hands: Splunk is part of Cisco, IBM sold its QRadar SaaS business to Palo Alto Networks (customers are being offered moves to Cortex XSIAM, while QRadar software and WinCollect continue at IBM), LogRhythm merged with Exabeam, and McAfee's SIEM line went to Trellix. Expect the vendor names in older diagrams to be out of date.
    - **A "pipeline layer" is now common.** Between sources and SIEM, many SOCs run a telemetry pipeline (Cribl, the OpenTelemetry Collector, Fluent Bit, or vendor pipeline products) to filter, reshape and route data — often sending full-fidelity data to cheap storage or a data lake and only selected data to the expensive SIEM. That is one more box that can change or drop your events.
    - **Agentless is no longer "lesser used".** Cloud and SaaS logs (identity provider sign-ins, Microsoft 365 audit, AWS CloudTrail, Google Workspace) are collected almost entirely by **API pulls or cloud-native streaming**, with their own delays and their own retention limits. EDR products also stream their telemetry to the vendor's cloud, and the SIEM receives it through an API or connector.
    - **Sysmon is becoming part of Windows.** Microsoft is shipping Sysmon as a built-in, optional Windows feature (documented on Microsoft Learn); it still has to be switched on, given a configuration, and collected like any other channel. Availability depends on the Windows build — check yours.
    - **`wmic` is gone** from current Windows 11 releases (removed starting with 25H2). WMI itself remains; agentless scripts must use PowerShell CIM cmdlets instead.
    - **Schemas and formats.** JSON over HTTPS (vendor HTTP collectors, OpenTelemetry) is now a normal transport next to syslog, and common schemas such as ECS and OCSF are increasingly applied in the pipeline — covered on the next pages.

!!! warning "[Caution] Wrong or risky to do the old way"
    - **Don't convert Windows events to syslog text** to "standardise". Ship XML or JSON.
    - **Don't filter away what you can't get back** just to save licence cost. Route low-value events to cheap storage instead of discarding them, and document every filter as a detection decision.
    - **Don't run agentless collection with a domain admin account** or leave its password in a script. Use a least-privilege reader account and protect it as a Tier 0-style secret.
    - **Don't trust UDP or unacknowledged transport for security logs.** Use TCP/TLS (or the agent's encrypted protocol) with acknowledgement and disk buffering.
    - **Don't assume WEF delivers the Security log** until you've seen a 4624 arrive; Network Service needs read access.
    - **Don't assume a quiet host is a clean host.** Alert on missing heartbeats and on 1102/104/1100/4719 and agent-service changes.

## Practice questions { #quiz }

### Question 1

After a new Windows Event Collector is deployed, a colleague searches the SIEM for yesterday's 4625 failures and reports: "All 3,400 failed logons happened on `WEC01`. That server is under attack!" What is the more likely explanation, and how do you confirm it? Also: why might 4625 events be present from some sources but **no Security events at all** from others?

??? success "Answer and explanation"
    **More likely explanation:** `WEC01` is the **collector**. Events from many machines arrive in its Forwarded Events channel and one agent ships them, so the SIEM's `host` field was filled with the **collector's** name instead of the original machine. The events were not written on WEC01.

    **How to confirm:** look at the raw event. In the XML `System` section, `<Computer>` holds the real source (e.g. `WS-HR-0231.corp.example`) and `<Channel>` still says `Security`. Group the 3,400 events by the `Computer` field — they will spread across many hosts. Then fix the SIEM/agent setting so that `host` comes from `Computer` for forwarded events.

    **Why some sources send no Security events:** on the sources, WEF runs as **Network Service**, which can't read the Security channel by default. Other channels (System, PowerShell) still forward, so it looks like WEF works. The fix is to grant Network Service (`S-1-5-20`) read access on the Security channel (or add it to *Event Log Readers*) by Group Policy, then confirm with `wecutil gr` and a test logon. Also check that the subscription's XPath actually selects those IDs.

### Question 2

A server team refuses agents. They propose an agentless script that pulls the Security log from their 40 servers **every 6 hours** with a service account that is a member of Domain Admins. `wevtutil gl Security` on a busy server shows `maxSize: 20971520` and `retention: false`. List the problems and what you'd propose instead.

??? success "Answer and explanation"
    **Problems:**

    1. **Rollover gaps.** `maxSize: 20971520` is 20 MB and `retention: false` means oldest events are overwritten. At roughly 1 KB per event, that's about 20,000 events. A busy server can write that in minutes, so a pull every 6 hours collects only the last few minutes and **loses the rest** — you'd have holes exactly where an investigation needs data.
    2. **Detection delay.** Even when nothing is lost, an event could reach the SIEM up to 6 hours late; any alert on it is late too.
    3. **Dangerous account.** A Domain Admin credential used from a script (and likely stored in it or in a scheduled task) is a gift to an attacker: stealing it means owning the domain. Reading logs only needs *Event Log Readers*.
    4. **Openings and scale.** Remote RPC/WinRM from the collector to every server must be allowed, and any server unreachable at pull time becomes a gap.

    **Proposal:** use **Windows Event Forwarding** — it's built into Windows, so it isn't "another agent" — with subscriptions for the needed events and minimised latency delivery, to a collector that has the only agent. Increase the Security log size anyway. If agentless must stay: pull every few minutes, a least-privilege reader account, a larger log, and monitoring of `EventRecordID` gaps per host.

### Question 3

At 02:10 the SIEM receives a 4624 type 10 (RDP) logon to `SRV-APP-0007` from an unusual source. After 02:12, nothing more arrives from that server. The next morning a colleague says, "No events after 02:12, so the attacker must have logged off." What would you check, and what events or signs on the server or in the pipeline would change that conclusion?

??? success "Answer and explanation"
    "No events" is not proof of "no activity". The silence right after a suspicious logon is itself suspicious. Check:

    - **Pipeline health first:** the agent's heartbeat, or `wecutil gr` for that source (is it `Inactive` since 02:12?), the agent service status, and whether other hosts on the same collector were still arriving (to rule out a collector outage).
    - **Tamper events** — locally on the server, and in the SIEM for the moments before the silence: **1102** (Security log cleared, with who did it), **104** (another channel cleared), **1100** (Event Log service shut down), **4719** (audit policy changed), **7036/7040** for the agent's service stopping or being disabled. These map to T1070.001, T1562.002 and T1562.001.
    - **Other sources** that the attacker on the host can't silence: firewall and network logs (Zeek `conn.log`) for traffic from that server after 02:12, EDR telemetry (sent through a separate channel), domain controller events such as 4769 service ticket requests made by that machine.

    If the agent stopped or the log was cleared at 02:12, the right conclusion is the opposite: the attacker likely **blinded collection** and kept working. Isolate the server and treat the post-02:12 period as unknown.

## Related { #related }

- [Windows Logging](../windows-logging/index.md) — how events are produced, channels and the XML structure the pipeline carries
- [Syslog](../linux-logging/syslog.md) · [Linux log files and the journal](../linux-logging/log-files-journal.md)
- [Important Events](../important-events/index.md) — the events most worth collecting
- [Windows Event Logs (EVTX)](../../../windows/event-logs.md)
- [Log aggregation](../../network-forensics/part-2/log-aggregation.md)
- [Splunk data discovery](../../../blueteam/splunk/data-discovery.md)

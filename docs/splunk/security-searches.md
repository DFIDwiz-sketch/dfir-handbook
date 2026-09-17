---
title: Security Searches by Question
tags:
  - playbook
  - splunk
  - windows
  - network
---

# Security Searches by Question

<div class="dfir-meta" markdown>
**Category:** Splunk · **Data:** Windows Security, Sysmon, PowerShell, Zeek/Stream · **Last updated:** 2026-09-17
</div>

!!! abstract "In one sentence"
    The searches you run during an incident, grouped by the question you are answering, each with a plain-English breakdown of what the SPL does and what the event codes mean — swap `index=botsv3` and the sourcetype names for your environment's.

Conventions: `SEC` = `index=botsv3 sourcetype=WinEventLog` (Security log; use `source="WinEventLog:Security"` if System/Application share the sourcetype), `SYSMON` = `index=botsv3 sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational"`, `PS` = `index=botsv3 sourcetype="XmlWinEventLog:Microsoft-Windows-PowerShell/Operational"`. Event ID meanings: [Windows Event IDs](../basics/windows-event-ids.md).

## Who logged on, from where?

**Successful logons by type and source**

```spl
index=botsv3 sourcetype=WinEventLog EventCode=4624
| eval user=mvindex(Account_Name,1)
| eval type=case(Logon_Type==2,"2 Interactive",Logon_Type==3,"3 Network",Logon_Type==4,"4 Batch",Logon_Type==5,"5 Service",Logon_Type==7,"7 Unlock",Logon_Type==9,"9 NewCredentials",Logon_Type==10,"10 RDP",Logon_Type==11,"11 Cached",true(),Logon_Type)
| stats count, earliest(_time) as first, latest(_time) as last by host, user, type, Source_Network_Address
| convert ctime(first) ctime(last)
| sort host, - count
```

`4624` = a logon succeeded. `Account_Name` has two values (subject, target); `mvindex(...,1)` takes the account that logged on. `case` turns the numeric `Logon_Type` into a label — type 3 (network: SMB/WinRM/PsExec), 10 (RDP) and 9 (`runas /netonly`, pass-the-hash tooling) are the ones to read carefully. `stats` gives one row per host/user/type/source with first and last time.

**Failed logons — brute force and spraying**

```spl
index=botsv3 sourcetype=WinEventLog EventCode=4625
| bin _time span=10m
| stats count, dc(Account_Name) as users, values(Sub_Status) as substatus by _time, Source_Network_Address, host
| where count >= 10
| eval pattern=if(users >= 5, "spraying (many users)", "brute force (few users)")
| sort - count
```

`4625` = logon failed. Bucketing to 10 minutes and counting per source IP finds bursts; `dc(Account_Name)` (distinct accounts) separates spraying (one password, many users) from brute force (one user, many passwords). `Sub_Status` explains why: `0xC000006A` wrong password, `0xC0000064` user doesn't exist (spraying a wordlist), `0xC0000234` locked out, `0xC0000072` disabled account.

**Explicit credentials / lateral movement source side**

```spl
index=botsv3 sourcetype=WinEventLog EventCode=4648
| stats count, values(Target_Server_Name) as targets, values(Process_Name) as procs by host, Subject_Account_Name, Account_Name
| where mvcount(targets) > 3
```

`4648` = a logon was attempted with **explicit** credentials (`runas`, scheduled task creds, tools that supply a username/password/hash). It's logged on the **source** machine, so `host` is where the attacker is, `targets` is where they went. One account reaching many servers in a short window is lateral movement.

**RDP sessions with source IP**

```spl
index=botsv3 sourcetype=WinEventLog (EventCode=4624 Logon_Type=10) OR EventCode=4778 OR EventCode=4779 OR (sourcetype="WinEventLog:Microsoft-Windows-TerminalServices-LocalSessionManager/Operational" EventCode IN (21,24,25))
| eval src=coalesce(Source_Network_Address, Client_Address, Source_Network_Address)
| eval user=coalesce(mvindex(Account_Name,1), Account_Name, User)
| table _time, host, EventCode, user, src
| sort 0 _time
```

`4624/10` = RDP logon; `4778/4779` = RDP session reconnected/disconnected (with client name/IP); LocalSessionManager `21` = session logon succeeded, `24` disconnect, `25` reconnect. `coalesce` merges the differently-named IP fields into one `src` column so the timeline reads cleanly.

**Admin logons**

```spl
index=botsv3 sourcetype=WinEventLog EventCode=4672
| stats count by host, Account_Name
| sort - count
```

`4672` = special privileges assigned at logon — effectively "an admin-level account logged on". Pair it with the `4624` that has the same `Logon_ID`.

## What ran?

**Process creation with command lines (Security 4688)**

```spl
index=botsv3 sourcetype=WinEventLog EventCode=4688
| eval user=mvindex(Account_Name,0)
| stats count by host, user, New_Process_Name, Process_Command_Line, Creator_Process_Name
| sort - count
```

`4688` = new process created. `Process_Command_Line` is only present if "Include command line in process creation events" is enabled by policy; `Creator_Process_Name` (parent) exists on Win10+/2016+.

**Sysmon process tree — suspicious parents**

```spl
index=botsv3 sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventID=1
| eval parent=lower(replace(ParentImage,".*\\\\","")), child=lower(replace(Image,".*\\\\",""))
| search (parent IN ("winword.exe","excel.exe","powerpnt.exe","outlook.exe","acrord32.exe","msedge.exe","chrome.exe") AND child IN ("cmd.exe","powershell.exe","wscript.exe","cscript.exe","mshta.exe","rundll32.exe","regsvr32.exe","certutil.exe","bitsadmin.exe","msiexec.exe"))
   OR (parent="wmiprvse.exe" AND child IN ("cmd.exe","powershell.exe"))
   OR (parent="services.exe" AND child IN ("cmd.exe","powershell.exe"))
   OR (parent IN ("w3wp.exe","httpd.exe","tomcat*.exe") AND child IN ("cmd.exe","powershell.exe","whoami.exe"))
| table _time, host, User, parent, child, CommandLine
```

Sysmon `1` = process create with full parent/child and hashes. `replace(ParentImage,".*\\\\","")` strips the path, leaving the file name. The `search` lists classic bad parent→child pairs: Office spawning a shell (macro), WMI provider host spawning a shell (remote WMI exec), `services.exe` spawning a shell (PsExec-style service), a web server spawning a shell (web shell).

**LOLBins & suspicious command lines**

```spl
index=botsv3 sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventID=1
| where match(CommandLine, "(?i)(-enc|-encodedcommand|frombase64string|iex\s*\(|invoke-expression|downloadstring|downloadfile|net\.webclient|invoke-webrequest|certutil.*-urlcache|certutil.*-decode|bitsadmin.*transfer|mshta.*http|regsvr32.*/i:http|rundll32.*javascript|vssadmin.*delete|wbadmin.*delete|bcdedit.*recoveryenabled|wevtutil\s+cl|schtasks.*/create|sc\s+create|reg\s+add.*\\run|whoami|net\s+(user|group|localgroup)|nltest|dsquery|adfind|mimikatz|sekurlsa|procdump.*lsass|comsvcs.*minidump|ntdsutil|esentutl.*ntds)")
| stats count, values(CommandLine) as cmds, earliest(_time) as first by host, User, Image
| convert ctime(first)
| sort first
```

One long case-insensitive regex covers download cradles, encoded PowerShell, LOLBin downloaders, shadow-copy/backup deletion (ransomware prep), log clearing, persistence commands, discovery commands and credential dumping. `values(CommandLine)` collects every matching command per host/user/binary so you read them in one row.

**PowerShell script blocks**

```spl
index=botsv3 sourcetype="XmlWinEventLog:Microsoft-Windows-PowerShell/Operational" EventCode=4104
| where len(ScriptBlockText) > 500 OR match(ScriptBlockText,"(?i)frombase64string|invoke-mimikatz|amsi|bypass|-nop|hidden|downloadstring|reflection\.assembly|virtualalloc|kernel32")
| stats count, min(_time) as first, values(Path) as paths by host, ScriptBlockText
| convert ctime(first)
| sort first
```

`4104` = the actual decoded script text, even for `-enc` payloads — it's the single best PowerShell artifact. Long blocks and the keyword set (AMSI bypass, reflection, memory allocation, download cradles) surface offensive tooling.

**Renamed / out-of-place binaries (Sysmon)**

```spl
index=botsv3 sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventID=1
| eval fname=lower(replace(Image,".*\\\\","")), orig=lower(OriginalFileName)
| where isnotnull(orig) AND orig!="?" AND fname!=orig AND NOT (fname="powershell.exe" AND orig="powershell.exe")
| stats count by host, Image, OriginalFileName, CommandLine
```

Sysmon records the PE header's `OriginalFileName`. If the file on disk is `svchost.exe` but the header says `mimikatz.exe`, the attacker renamed it. Also useful: `Image` under `\Users\Public\`, `\ProgramData\`, `\Windows\Temp\`, `\AppData\Local\Temp\`, `\PerfLogs\`.

## How do they persist?

**New services**

```spl
index=botsv3 sourcetype="WinEventLog:System" EventCode=7045
| table _time, host, Service_Name, Service_File_Name, Service_Type, Service_Start_Type, Account_Name
| sort 0 _time
```

System `7045` = a service was installed. `PSEXESVC` = PsExec; random 8-char names with `%COMSPEC% /b /c start /b /min powershell -nop -w hidden -enc` = Cobalt Strike/Metasploit service payloads; a service whose binary sits in a user folder is persistence.

**Scheduled tasks**

```spl
index=botsv3 sourcetype=WinEventLog EventCode IN (4698, 4702)
| rex field=Task_Content "<Command>(?<cmd>[^<]+)</Command>"
| rex field=Task_Content "<Arguments>(?<args>[^<]+)</Arguments>"
| table _time, host, Subject_Account_Name, Task_Name, cmd, args
```

`4698` = task created, `4702` = task updated (requires audit policy). The task XML lives in `Task_Content`; `rex` pulls the command and arguments out of it.

**Registry run keys & other ASEPs (Sysmon)**

```spl
index=botsv3 sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventID IN (12, 13, 14)
| where match(TargetObject, "(?i)\\\\CurrentVersion\\\\Run|\\\\RunOnce|\\\\Winlogon\\\\(Shell|Userinit)|\\\\Image File Execution Options|\\\\Services\\\\[^\\\\]+\\\\ImagePath|\\\\AppInit_DLLs|\\\\Command Processor\\\\AutoRun|\\\\Environment\\\\UserInitMprLogonScript|\\\\Classes\\\\CLSID\\\\[^\\\\]+\\\\InprocServer32|\\\\Policies\\\\Explorer\\\\Run|\\\\Active Setup")
| table _time, host, User, Image, EventID, TargetObject, Details
```

Sysmon `12` = key created/deleted, `13` = value set, `14` = key/value renamed. `TargetObject` is the registry path; `Details` the value written. The regex lists the autostart locations from the [Registry keys](../windows/registry-keys.md#autostart-persistence-asep) page.

**WMI persistence**

```spl
index=botsv3 (sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventID IN (19,20,21)) OR (sourcetype="WinEventLog:Microsoft-Windows-WMI-Activity/Operational" EventCode=5861)
| table _time, host, sourcetype, EventID, EventCode, User, EventNamespace, Name, Query, Destination, Consumer, Filter, Message
```

Sysmon `19/20/21` = WMI event filter / consumer / binding created — all three together = persistence. WMI-Activity `5861` is the OS's own record of a new permanent consumer.

**New local users and group changes**

```spl
index=botsv3 sourcetype=WinEventLog EventCode IN (4720, 4722, 4724, 4728, 4732, 4756)
| eval action=case(EventCode==4720,"user created",EventCode==4722,"user enabled",EventCode==4724,"password reset",EventCode==4728,"added to global group",EventCode==4732,"added to local group",EventCode==4756,"added to universal group")
| table _time, host, Subject_Account_Name, action, Account_Name, Member_Name, Group_Name
| sort 0 _time
```

`4720` create, `4722` enable, `4724` admin password reset, `4728/4732/4756` member added to a security group (global/local/universal). A `4720` followed within seconds by `4732` into `Administrators` is textbook backdoor account creation.

## Lateral movement (target side)

**PsExec / SMB admin share pattern**

```spl
index=botsv3 (sourcetype=WinEventLog EventCode IN (4624, 5140, 5145)) OR (sourcetype="WinEventLog:System" EventCode=7045)
| eval share=coalesce(Share_Name, Relative_Target_Name)
| where EventCode!=4624 OR Logon_Type=3
| eval src=coalesce(Source_Network_Address, Source_Address)
| stats values(EventCode) as codes, values(share) as shares, values(Service_Name) as services, values(Account_Name) as accounts, min(_time) as first, max(_time) as last by host, src
| where match(mvjoin(codes,","),"5140|5145") AND match(mvjoin(codes,","),"7045")
| convert ctime(first) ctime(last)
```

The PsExec chain on the **target**: `4624 type 3` (network logon) → `5140/5145` (share `ADMIN$`/`IPC$` accessed, file `PSEXESVC.exe` written) → `7045` (service installed). Grouping everything by target host and source IP, then requiring both a share-access code and a service-install code in the same group, finds the chain even without knowing the tool's name.

**WMI / WinRM remote execution**

```spl
index=botsv3 sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventID=1 (ParentImage="*\\wmiprvse.exe" OR ParentImage="*\\wsmprovhost.exe")
| table _time, host, User, ParentImage, Image, CommandLine
```

On the target, remote WMI runs children under `wmiprvse.exe`; PowerShell Remoting runs them under `wsmprovhost.exe`. Neither should normally spawn `cmd`/`powershell`.

**Pass-the-hash indicators**

```spl
index=botsv3 sourcetype=WinEventLog EventCode=4624 Logon_Type=9 Logon_Process=seclogo Authentication_Package=Negotiate
| table _time, host, Account_Name, Logon_ID, Process_Name
```

Mimikatz `sekurlsa::pth` and similar create a `4624` with **Logon Type 9** (NewCredentials), logon process `seclogo`, package `Negotiate` on the *attacker's* machine. On the *target*, PtH looks like a normal type 3 NTLM logon — so also hunt `4624 Logon_Type=3 Authentication_Package=NTLM` from workstation-to-workstation in a Kerberos domain.

**Kerberoasting (on DCs)**

```spl
index=botsv3 sourcetype=WinEventLog EventCode=4769 Ticket_Encryption_Type=0x17 Failure_Code=0x0
| where NOT match(Service_Name, "\\$$|krbtgt")
| bin _time span=10m
| stats dc(Service_Name) as spns, values(Service_Name) as services by _time, Account_Name, Client_Address
| where spns >= 5
```

`4769` = service ticket requested. Encryption type `0x17` = RC4 — what cracking tools request. Excluding computer accounts (`$`) and `krbtgt`, one user requesting five or more distinct SPNs in ten minutes is Kerberoasting.

## Network side (Zeek / Stream in Splunk)

**Beacon candidates** — see [Beaconing & C2](../network/beaconing-c2.md) for the full `streamstats` version.

**Rare user agents**

```spl
index=botsv3 sourcetype=stream:http
| stats dc(src_ip) as hosts, count, values(site) as sites by http_user_agent
| where hosts <= 2
| sort count
```

`dc(src_ip)` = how many clients use each UA; one or two = bespoke tool or malware; `values(site)` shows where it goes.

**Executable downloads**

```spl
index=botsv3 sourcetype=stream:http (http_content_type="application/x-msdownload" OR http_content_type="application/x-dosexec" OR uri_path="*.exe" OR uri_path="*.dll" OR uri_path="*.ps1")
| table _time, src_ip, dest_ip, site, uri_path, http_user_agent, bytes_in
```

**DNS oddities**

```spl
index=botsv3 sourcetype=stream:dns record_type=A
| eval qlen=len(query), first=mvindex(split(query,"."),0)
| where qlen > 50 OR len(first) > 30 OR record_type IN ("TXT","NULL")
| stats count, dc(query) as uniq by src_ip, dest_ip
| sort - uniq
```

**Large uploads**

```spl
index=botsv3 sourcetype=stream:tcp
| stats sum(bytes_out) as out, sum(bytes_in) as in by src_ip, dest_ip, dest_port
| eval out_MB=round(out/1048576,1), ratio=round(out/(in+1),1)
| where out_MB > 50 AND ratio > 5
| sort - out_MB
```

`ratio` = bytes sent divided by bytes received; a client sending 5× more than it receives, in the tens of megabytes, is uploading.

## Log tampering

```spl
index=botsv3 (sourcetype=WinEventLog EventCode IN (1102, 4719, 4616)) OR (sourcetype="WinEventLog:System" EventCode=104)
| eval what=case(EventCode==1102,"Security log cleared",EventCode==104,"Event log cleared",EventCode==4719,"Audit policy changed",EventCode==4616,"System time changed")
| table _time, host, what, Account_Name, Subject_Account_Name, Message
| sort 0 _time
```

`1102` = Security log cleared (records who), `104` = any other log cleared, `4719` = audit policy changed (logging turned off before the action), `4616` = system time changed (timeline confusion). Also check for hosts whose log volume drops to zero — [Data discovery → log gap detection](data-discovery.md#working-with-time).

## Build a host timeline (everything about one machine)

```spl
index=botsv3 host=FYODOR-L earliest="08/20/2018:00:00:00" latest="08/21/2018:00:00:00"
  (sourcetype=WinEventLog EventCode IN (4624,4625,4648,4672,4688,4698,4720,4732,7045,1102))
  OR (sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventID IN (1,3,11,12,13,22))
  OR (sourcetype="XmlWinEventLog:Microsoft-Windows-PowerShell/Operational" EventCode=4104)
| eval code=coalesce(EventCode, EventID)
| eval who=coalesce(User, mvindex(Account_Name,1), Account_Name)
| eval what=coalesce(CommandLine, Process_Command_Line, ScriptBlockText, TargetFilename, TargetObject, QueryName, DestinationIp." :".DestinationPort, Service_File_Name, Task_Name, Message)
| eval what=substr(what,1,300)
| table _time, sourcetype, code, who, what
| sort 0 _time
```

One search, three sourcetypes, a handful of event codes; `coalesce` picks the most descriptive field each event has and `substr` trims it so the table stays readable. This is the table you paste into a report timeline.

## References

- [Windows Event IDs](../basics/windows-event-ids.md) · [Registry keys — ASEP](../windows/registry-keys.md#autostart-persistence-asep)
- [Splunk Security Essentials (free app — hundreds of searches with explanations)](https://splunkbase.splunk.com/app/3435)
- [Sigma rules — convert to SPL with sigma-cli / uncoder.io](https://github.com/SigmaHQ/sigma)
- [JPCERT Tool Analysis Result Sheet — what each attack tool logs](https://jpcertcc.github.io/ToolAnalysisResultSheet/)

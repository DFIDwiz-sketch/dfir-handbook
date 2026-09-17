---
title: Web Shell & Server Compromise
tags:
  - playbook
  - webshell
  - initial-access
---

# Web Shell & Server Compromise

<div class="dfir-meta" markdown>
**Scenario:** Web server compromised — web shell, exploited app, or attacker command execution via a web service · **Last updated:** 2026-09-17
</div>

!!! abstract "When to use this"
    An internet-facing (or internal) web server is behaving oddly: an unfamiliar script in the web root, the web-server process (`w3wp.exe`, `httpd`, `tomcat`, `php-fpm`) spawning shells, or an exploit alert on the app. Web shells are a common **initial access** and **persistence** foothold — a small script that turns an HTTP request into command execution on the server.

## 1. Triage (first 15 minutes)

- Confirm: is there a **web shell** on disk (a script in the web root the developers didn't put there), and/or is the **web-server process spawning child processes** (cmd/powershell/sh)?
- Identify the server role and exposure (internet-facing? what app/CMS/version?). A known-vulnerable app + a new script = exploited.
- Preserve the web shell file and the relevant **web-server access logs** before anything is cleaned — the access log ties requests to the shell and to the attacker's IP.
- If actively being used, network-isolate the server (keep it running for RAM/artifacts).

## 2. Collect

| Source | What | Where |
|---|---|---|
| Web server access/error logs | Requests to the shell, attacker IP, exploit attempts | IIS (`%SystemDrive%\inetpub\logs\LogFiles`), Apache/Nginx (`/var/log/…`), Tomcat |
| The web shell file(s) | The payload itself | Web root; hash it, read it |
| Host triage | Execution, persistence, lateral movement from the server | [KAPE](../tools/kape.md) / [Velociraptor](../tools/velociraptor.md) (Linux artifacts too) |
| [$MFT / $UsnJrnl](../windows/mft-usn.md) | When the shell was written (and by what) | File creation time = upload time |
| Network | The exploit request + any follow-on C2/lateral | [Zeek http.log](../network/zeek/http-log.md) / [Arkime](../network/arkime/index.md) |
| App/DB logs | SQLi, auth bypass, admin actions | Application-specific |

## 3. Analyse

- **Find the shell**: web-server process spawning a shell is the loudest signal ([suspicious parents](../adversary/wmi-winrm.md) — `w3wp.exe`/`httpd`/`tomcat`→`cmd`/`powershell`/`sh`/`whoami`). On disk, a recently created script in the web root with suspicious content (`eval`, `system(`, `exec(`, `passthru(`, `Runtime.exec`, base64 blobs). Hash it and search the fleet — attackers drop the same shell on multiple servers.
- **When and how it got there**: [`$MFT`/`$UsnJrnl`](../windows/mft-usn.md) creation time of the shell = the upload moment; correlate with the **access log** entry (a `PUT`/`POST` to that path, or an exploit request just before). This gives the **initial-access vector** (upload feature, deserialization, RCE, path traversal, stolen creds).
- **What the attacker did through it**: the access log shows every request to the shell — `POST` bodies (if logged) or the follow-on child processes ([Sysmon 1](../splunk/security-searches.md#what-ran)) reveal the commands: `whoami`, `net user`, downloading tools, [dumping creds](../adversary/lsass-dumping.md), [moving laterally](../adversary/psexec-smb.md).
- **Attacker IP & scope**: the source IP(s) hitting the shell → search for other paths they touched, other servers, and pre-compromise recon (`404` scanning). One shell often implies more.
- **Persistence beyond the shell**: check for [services/tasks/Run keys](../adversary/persistence.md), new web-app admin accounts, modified app config, and additional shells (attackers plant backups).

## 4. Contain / Eradicate

- Remove **all** web shells (find every one — they plant spares) and any attacker-added accounts, tasks, services.
- **Patch or disable the vulnerable app/feature** that allowed the upload/RCE — removing the shell without closing the vector just invites re-compromise.
- Rotate any credentials/secrets the server held (app service accounts, DB creds, API keys, machine keys) — assume they were read.
- If the attacker moved off the server, pivot to [lateral movement / domain](lateral-domain.md).
- Block the attacker IP; consider WAF rules for the exploit.

## 5. Recover & lessons

- Rebuild the server from clean media if the compromise went beyond a single removed file — you can't be certain you found every shell/backdoor on a web server.
- Restore the app patched, with rotated secrets, behind a WAF, with reduced web-root write permissions (the web process shouldn't be able to write executable scripts into its own root).
- Harden: least-privilege app pools, disable script execution in upload directories, file-integrity monitoring on the web root, Sysmon rule for web-server processes spawning shells, and continuous access-log monitoring for shell-like request patterns.

## Useful queries

```spl
index=botsv3 sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventID=1
| eval parent=lower(replace(ParentImage,".*\\\\",""))
| where parent IN ("w3wp.exe","httpd.exe","nginx.exe","php-cgi.exe","php-fpm","tomcat*.exe","java.exe","sqlservr.exe")
    AND match(lower(Image),"cmd\.exe|powershell|whoami|net1?\.exe|cscript|wscript|bitsadmin|certutil|/bin/(ba)?sh")
| table _time, host, parent, Image, CommandLine, User
| sort 0 _time
```

Sysmon `1` = process create. A web-server or app process spawning a shell or discovery command is the defining web-shell signal — legitimate web apps almost never do this. `parent` is stripped to the bare filename for the comparison.

```spl
index=<your_web_index> sourcetype=iis
| stats count, values(c_ip) as src, values(cs_method) as methods, min(_time) as first, max(_time) as last by cs_uri_stem
| where match(cs_uri_stem,"(?i)\.(aspx?|php|jsp|jspx)$") AND match(mvjoin(methods,","),"POST")
| where count < 50
| convert ctime(first) ctime(last)
| sort first
```

Web-server access logs grouped by requested page. A script endpoint that receives `POST` requests from few sources and is rarely hit (low `count`) — especially one whose filename isn't part of the app — is a candidate web shell; `first`/`last` bound when it was active and `src` gives the attacker IP. Adapt field names (`cs_uri_stem`, `c_ip`, `cs_method`) to your log source via [data discovery](../splunk/data-discovery.md).

## References

- [MITRE ATT&CK — Server Software Component: Web Shell (T1505.003)](https://attack.mitre.org/techniques/T1505/003/)
- [CISA — Web shell detection & prevention](https://www.cisa.gov/) · [NSA/ASD web shell guidance](https://www.cisa.gov/resources-tools/resources/detect-and-prevent-web-shell-malware)
- Pages: [Phishing/initial access](../adversary/phishing-delivery.md) · [Persistence](../adversary/persistence.md) · [LSASS dumping](../adversary/lsass-dumping.md) · [Zeek http.log](../network/zeek/http-log.md) · [MFT/USN](../windows/mft-usn.md)

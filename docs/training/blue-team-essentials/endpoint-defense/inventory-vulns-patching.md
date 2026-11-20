---
title: "Inventory, Vulnerability Scanning, Patching and Exploit Protection — Stopping the Attack Before It Lands"
tags:
  - training
  - blue-team
  - endpoint
  - vulnerability-management
  - hardening
---

# Inventory, Vulnerability Scanning, Patching and Exploit Protection — Stopping the Attack Before It Lands { #inventory-vulns-patching }

!!! abstract "What this page covers"
    Why one layer of endpoint defence is never enough, and how the common endpoint controls line up against the attack stages (exploitation, installation, command and control, actions on objective). Then the first and cheapest layer — stopping exploitation: knowing what software you actually run (inventory systems and network scanning, with an Nmap scan read line by line), finding out when it becomes vulnerable (unauthenticated vs authenticated vulnerability scanning and how to prioritise the results), patching it fast (OS, server and client software, emergency patches), and catching the exploits patching misses with anti-exploitation tools — from the retired EMET to today's exploit protection, controlled folder access, network protection and attack surface reduction (ASR) rules, with the commands and Defender events (1121–1126) a SOC reads. Practice questions with explanations at the end.

!!! note "Labels"
    **[Supplement]** = practical material you need to know, **[Correction]** = a commonly repeated claim that is wrong or outdated, **[Changed]**/**[Caution]** = what has changed recently and what is risky to do the old way. Hostnames, domains, accounts, IPs and file names are invented for illustration (`.example`, documentation and private IPs).

## The 8 key points { #key-points }

1. **One layer is never enough.** Each endpoint control covers a different attack stage; together they give *defence in depth* — every layer either stops the attacker or at least slows them down and makes noise.
2. Line the controls up against the kill chain: **exploitation** → inventory, scanning, patching, anti-exploitation; **installation** → hardening, antivirus, file integrity monitoring, privileged access workstations, application control; **C2** → host firewall, host IDS/IPS; **actions on objective** → auditing, behaviour analytics, encryption, logging, DLP.
3. **You can't protect what you don't know you have.** Software inventory (agents or log-ins that list installed software) and network scanning (what is actually listening) see different things — use both.
4. A scanner like **Nmap** does far more than "is the port open": it grabs service banners, guesses the OS and runs scripts (anonymous FTP, SMB host details). Attackers use the very same scans — that is why you want to see your network their way first.
5. **Vulnerability scanning must be continuous**: a server that is safe today can be exploitable tomorrow. **Unauthenticated** scans only see what the network reveals; **authenticated** scans log in and know exactly which versions are installed.
6. Patching is the **number one way to prevent exploitation** — operating system, server software *and* client software (browsers, PDF readers, Office). Decide in advance how bad a vulnerability must be to justify an emergency outage.
7. Patching never catches everything, so **anti-exploitation** tools try to break the exploit itself — and, just as important, **log that an exploit was attempted**, which gives the SOC an early, high-quality alert.
8. On Windows, EMET is gone; its successors are built into Windows and Microsoft Defender: **exploit protection**, **controlled folder access** (anti-ransomware), **network protection** (block bad destinations for every app) and **ASR rules** (e.g. stop Office from spawning child processes). Their block/audit events go to the Defender operational log and should reach the SIEM.

## Defence in depth along the kill chain { #defence-in-depth }

Think of airport security. There is a check at the booking stage (is this person on a watch list?), a document check at the counter, a scanner for bags and people, a locked cockpit door, and an air marshal on board. None of them is perfect. Each one catches some threats the others miss, and a person who wants to cause harm has to get past *all* of them. Each extra check also takes time and creates a chance to be noticed.

Endpoint defence works the same way. Earlier pages followed the attacker across the host: [initial exploitation](../endpoint-attacks/initial-exploitation.md), then [execution, persistence and discovery](../endpoint-attacks/execution-persistence-discovery.md), [privilege escalation](../endpoint-attacks/privilege-escalation.md), [credential dumping](../endpoint-attacks/credential-dumping-mimikatz.md) and [lateral movement and exfiltration](../endpoint-attacks/lateral-collection-exfil.md). This section walks the same road from the defender's side and asks, at every stage, "what can stop or reveal this?"

| Attack stage | What the attacker needs | Endpoint controls that answer it |
| --- | --- | --- |
| Exploitation | A vulnerable program the exploit can reach | Software inventory, network scanning, vulnerability scanning, patching, anti-exploitation |
| Installation (persistence) | To write and run their own code and make it survive a reboot | Hardening, antivirus/EDR, file integrity monitoring, privileged access workstations (PAWs), application control |
| Command and control | A network path out to their server | Host firewall, host intrusion detection/prevention (HIDS/HIPS) |
| Actions on objective | To reach, collect and move data or damage systems | Auditing, user and entity behaviour analytics (UEBA), encryption, logging, data loss prevention (DLP) |

Two ideas sit behind this table.

- **The earlier you stop it, the cheaper it is.** Stopping an exploit before the first byte of attacker code runs costs one alert. Finding the same attacker three weeks later, after they have dumped credentials and touched forty machines, costs an incident response.
- **Prevention and detection are both outputs.** A good control either blocks the step, or records it so the SOC sees it — ideally both. A control that blocks silently is better than nothing, but a control that blocks *and* logs turns the attacker's failed attempt into your earliest warning.

This page covers the first row: preventing exploitation. The next pages cover the other rows.

## Step 1 — know your software { #inventory }

An exploit needs a target: a specific vulnerable version of a specific program, running somewhere the attacker can reach. If you don't know that `SRV-APP-0007` still runs an old Java application server, you won't patch it, you won't watch it and you won't notice when it starts spawning shells. Inventory is the foundation for everything else on this page.

There are two complementary ways to build that list.

### Inventory systems — the list from the inside { #inventory-systems }

An **inventory system** asks each machine what is installed — through an installed agent (endpoint management, EDR, configuration management tools) or by logging in periodically — and stores the answer in a central database you can query ("which hosts have 7-Zip older than version X?").

The weakness is in *how* the machine is asked. Most tools read the operating system's list of installed programs. Software that never registered itself there — a portable `.exe` copied into a user's Downloads folder, a tool unzipped into `C:\Tools`, a Python package installed with `pip`, a container image — may simply not appear. The list is only as good as its enumeration method.

Here is what a basic Windows check looks like, the way many tools do it under the hood:

```powershell
$paths = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*',
         'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*'
Get-ItemProperty $paths |
  Where-Object DisplayName |
  Select-Object DisplayName, DisplayVersion, Publisher, InstallDate |
  Sort-Object DisplayName
```

Line by line:

- Line 1–2 — the two registry locations where installers register programs: the normal 64-bit list and the `WOW6432Node` list for 32-bit programs on 64-bit Windows. Checking only one of them misses half the software.
- `Get-ItemProperty $paths` — reads every entry under those keys.
- `Where-Object DisplayName` — drops entries with no display name (updates and internal components).
- `Select-Object …` — keeps the useful columns; `Sort-Object` sorts by name.

```
DisplayName                       DisplayVersion   Publisher               InstallDate
-----------                       --------------   ---------               -----------
7-Zip 19.00 (x64)                 19.00            Igor Pavlov             20210314
Google Chrome                     131.0.6778.86    Google LLC              20261102
Microsoft 365 Apps for enterprise 16.0.18129.20158 Microsoft Corporation   20261110
Notepad++ (64-bit x64)            8.1.9            Notepad++ Team          20220119
```

Reading it as an analyst: Chrome and Microsoft 365 were updated this month, which suggests automatic updates work. `7-Zip 19.00` from 2021 and `Notepad++ 8.1.9` from 2022 have clearly never been updated — exactly the kind of forgotten client software attackers target with booby-trapped files. Note that the user's portable tools in `%USERPROFILE%\Downloads` are not in this list at all.

On Linux the package manager is the inventory:

```
$ dpkg-query -W -f='${Package} ${Version}\n' openssh-server openssl sudo
openssh-server 1:9.6p1-3ubuntu13.5
openssl 3.0.13-0ubuntu3.4
sudo 1.9.15p5-3ubuntu5
```

- `dpkg-query -W` lists installed Debian/Ubuntu packages; `-f` sets the output format (package name and version). On Red Hat-family systems the equivalent is `rpm -qa`.
- Distributions **backport** security fixes: `3.0.13-0ubuntu3.4` may contain fixes for bugs that upstream only fixed in a later 3.x release. Comparing the upstream number alone gives false positives — one reason good scanners understand distribution package versions.

**[Caution]** Avoid `Get-CimInstance Win32_Product` (or the old `wmic product`) for inventory. Querying that class makes Windows Installer *re-check and potentially repair every MSI-installed program*, which is slow, noisy in the Application log and can change installations. Read the Uninstall registry keys or use your management tool instead.

### Network scanning — the list from the outside { #network-scanning }

The second view asks a different question: **what does this machine actually expose to the network?** Instead of trusting the machine's own list, you connect to it the way an attacker would. This catches listening services that the inventory missed — the "temporary" web server a developer started, a management interface on a forgotten appliance, the printer with Telnet open.

Scanning can be **active** (send probes and see what answers) or **passive** (listen to existing traffic — for example Zeek or a network sensor noticing that `10.20.0.88` answers on TCP 8080). Passive discovery is used where active probing is risky or not allowed — fragile industrial and medical devices are the classic case, because some of them crash when scanned.

**Nmap** is the best-known active scanner and a good illustration of what this tool category does. A defender's service and OS scan of a small server subnet:

```
$ sudo nmap -sS -sV -O --script "ftp-anon,smb-os-discovery" -p 21,22,80,445,3389,8080 10.20.0.0/24 -oA scans/srv-2026-11-19
```

Taking it apart:

- `sudo` — raw-packet scans and OS detection need root.
- `-sS` — **SYN scan** ("half-open"): send a SYN, and an answering SYN/ACK means the port is open. Nmap then resets the connection instead of finishing the handshake.
- `-sV` — **version detection**: after a port is found open, connect and read or provoke the service's **banner** to identify the product and version.
- `-O` — **OS detection**: guess the operating system from small differences in how its TCP/IP stack answers (TTLs, window sizes, option ordering). It is a heuristic guess, not a certainty.
- `--script "ftp-anon,smb-os-discovery"` — run two **NSE scripts** (Nmap Scripting Engine): `ftp-anon` tries an anonymous FTP login and lists what is visible; `smb-os-discovery` asks an SMB server for its name, domain and OS.
- `-p 21,22,80,445,3389,8080` — only these ports (a full `-p-` scan covers all 65,535).
- `10.20.0.0/24` — the targets: 256 addresses.
- `-oA scans/srv-2026-11-19` — save the results in all three formats (normal, XML, grepable) so they can be imported and compared with last month.

Part of the output:

```
Nmap scan report for srv-ftp-02.corp.victim.example (10.20.0.31)
Host is up (0.00041s latency).
PORT     STATE  SERVICE       VERSION
21/tcp   open   ftp           vsftpd 3.0.3
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
|_-rw-r--r--    1 0        0          48213 Oct 02 09:14 payroll-export.csv
22/tcp   open   ssh           OpenSSH 8.2p1 Ubuntu 4ubuntu0.5 (Ubuntu Linux; protocol 2.0)
80/tcp   closed http
445/tcp  closed microsoft-ds
3389/tcp closed ms-wbt-server
8080/tcp open   http          Apache Tomcat 9.0.31
Device type: general purpose
Running: Linux 4.X|5.X
OS details: Linux 4.15 - 5.15

Nmap scan report for srv-app-0007.corp.victim.example (10.20.0.37)
PORT     STATE SERVICE       VERSION
445/tcp  open  microsoft-ds  Microsoft Windows Server 2012 R2 microsoft-ds
3389/tcp open  ms-wbt-server Microsoft Terminal Services
Host script results:
| smb-os-discovery:
|   OS: Windows Server 2012 R2 Standard 9600 (Windows Server 2012 R2 Standard 6.3)
|   Computer name: SRV-APP-0007
|   Domain name: corp.victim.example
|_  System time: 2026-11-19T10:02:44+10:00
```

Reading it line by line:

- `Nmap scan report for srv-ftp-02… (10.20.0.31)` — reverse DNS name and IP. `Host is up` — it answered.
- `21/tcp open ftp vsftpd 3.0.3` — FTP is open and the banner identifies the product and version.
- `ftp-anon: Anonymous FTP login allowed (FTP code 230)` — the script logged in **without credentials**. The next line shows a file anyone on the network can download: `payroll-export.csv`. That is a finding before any vulnerability is even considered.
- `22/tcp … OpenSSH 8.2p1 Ubuntu 4ubuntu0.5` — the version string includes the Ubuntu package revision, which also tells you roughly which Ubuntu release this is (20.04).
- `closed` — the host answered with a reset: nothing listens there. (`filtered` would mean no answer at all, usually a firewall.)
- `8080/tcp open http Apache Tomcat 9.0.31` — an application server on a non-standard port, and an old version. Was it in the inventory? Is anyone patching it?
- `Device type / Running / OS details` — the OS *guess*; useful, but confirm it.
- For `srv-app-0007`: `445 … Windows Server 2012 R2`. The `smb-os-discovery` script got the exact OS build, computer name and domain — **without logging in**. Windows Server 2012 R2 left extended support in October 2023; unless it is enrolled in paid Extended Security Updates, it gets no security patches. This is a host that must be upgraded, isolated or covered with compensating controls.

Combining both views: the inventory system tells you what is *installed*; the scan tells you what is *exposed*. A program installed but not listening is still exploitable through malicious files (client-side). A port listening with nothing in the inventory is a blind spot. Together they give you the **attack surface** — the set of things an attacker could try — so you can shrink it (remove what isn't needed) and protect the rest.

**[Supplement]** Attackers run the same scans from their first foothold — ATT&CK **T1046 Network Service Discovery** (inside the network) and **T1595 Active Scanning** (from outside, before the attack). That gives the SOC two reasons to know its own scanners: authorised scans should come from known scanner hosts at known times (so you can exclude them), and *any other* host suddenly touching hundreds of IP/port pairs is worth an alert. Only scan networks you are authorised to scan, and tell the SOC before you do.

## Step 2 — continuous vulnerability scanning { #vuln-scanning }

Knowing that `srv-ftp-02` runs Tomcat 9.0.31 is half the job. The other half is knowing **when that version becomes dangerous**. Vulnerabilities are published every day, and exploit code often follows within days. A server that was fully patched on Monday can be the most exposed machine in the company by Thursday, without anyone touching it.

A **vulnerability scanner** automates this. It keeps a database of every host and its software, compares versions against a constantly updated list of known vulnerabilities (CVEs), and shows where the risk is. Think of it as a building inspector who comes back every week with an updated list of known-faulty parts, rather than once when the building was finished.

### Unauthenticated vs authenticated scans { #scan-types }

| | Unauthenticated scan | Authenticated (credentialed) scan |
| --- | --- | --- |
| How | Probes over the network like Nmap: banners, protocol behaviour, a few safe checks | Logs in (SSH, Windows admin/SMB/WinRM, or a local agent) and reads installed packages, file versions, registry, patch level, configuration |
| Sees | Only what services reveal about themselves | What is really installed, including client software that never listens on a port |
| Accuracy | Limited: many services hide or fake their versions; backported fixes cause false positives | High: exact versions and installed patches |
| Typical use | Attacker's-eye view of an internet-facing range | Internal hosts — the scan you rely on for patch decisions |

Here is the same server through both lenses, as a scanner report might show it:

```
Host: 10.20.0.31 (srv-ftp-02)                Scan: unauthenticated  2026-11-19 02:10Z
  [Medium] Anonymous FTP enabled                         port 21
  [Info]   SSH server detected: OpenSSH 8.2p1            port 22
  [Info]   HTTP server: Apache Tomcat (version hidden)   port 8080

Host: 10.20.0.31 (srv-ftp-02)                Scan: authenticated    2026-11-19 03:40Z
  [Critical] Apache Tomcat 9.0.31 < 9.0.98 multiple RCE  /opt/tomcat/lib/catalina.jar
  [High]     openssl 1.1.1f-1ubuntu2.16 outdated         package
  [High]     sudo 1.8.31-1ubuntu1.2 privilege escalation package
  [Medium]   Anonymous FTP enabled                       port 21
  [Medium]   Kernel 5.4.0-150 reboot pending (patch installed, not active)
```

- Unauthenticated: the scanner found anonymous FTP and saw OpenSSH, but Tomcat was configured to hide its version, so it could only say "Tomcat, version unknown". No critical findings — a dangerously comforting result.
- Authenticated: logged in over SSH, it read the actual Tomcat library file and the package database. Now the **critical remote code execution** risk is visible, plus local privilege escalation (`sudo`), which matters once an attacker is in.
- `reboot pending` — the patch is installed but the old kernel is still running. Only an authenticated check can see this, and it is a common reason "patched" systems are still exploitable.

### Turning results into decisions { #prioritise }

A large network produces thousands of findings. Patching can never happen instantly with 100% coverage, so the value of the scanner is in **sorting**:

- **By severity of the vulnerability** — how bad is it? (CVSS score, but see [below](#trends) for why the score alone is a poor guide.)
- **By likelihood of attack** — is it being exploited right now? Is there public exploit code?
- **By asset criticality** — a domain controller, an internet-facing VPN or a payroll server matters more than a lab PC.
- **By group** — business unit, OS, owner, compliance scope — so each team gets its own list.

A typical "top of the list" view:

```
Rank  CVE (example)      Host            Exposure         Asset tier  Exploited in wild  Action
1     CVE-2026-0xxxx     vpn-gw-01       Internet         Tier 0      Yes (KEV)          Patch today (emergency)
2     CVE-2026-1xxxx     srv-ftp-02      Internal 8080    Tier 2      Public PoC         Patch this week
3     CVE-2025-4xxxx     450 laptops     Client (PDF)     Tier 3      No                 Normal monthly cycle
```

Tracking the count for one vulnerability over time ("how many hosts still have it?") is the burn-down chart management asks for during a high-profile vulnerability — and the list of the last stragglers is what the SOC should watch most closely.

**[Supplement]** For the SOC, the vulnerability database is an **investigation tool**, not just a patching tool. When an IDS alert says "exploit attempt for CVE-X against 10.20.0.31", the first question is "is 10.20.0.31 actually vulnerable to CVE-X?" An attempt against a patched host is noise; the same attempt against a host the scanner flagged last night is an incident.

## Step 3 — patching { #patching }

Patching is the **single most effective way to prevent exploitation**: an exploit for a bug that no longer exists does nothing. The CIS Critical Security Controls have long ranked knowing your software and continuous vulnerability management near the top of their list. (In the older v7 numbering, software inventory was #2 and continuous vulnerability management #3; in the current v8/v8.1 list they are Control 2 *Inventory and Control of Software Assets* and Control 7 *Continuous Vulnerability Management*, with Control 1 *Inventory and Control of Enterprise Assets* still first.)

"Continuous" means having the ability to react quickly when the news breaks that version X of product Y has a critical vulnerability — not just in a monthly cycle. That covers three groups of software, and all three matter:

- **Operating systems** — Windows, Linux kernels, macOS, firmware on network devices. These often need **reboots**, which means planned outages for servers.
- **Server software** — web servers, databases, VPN gateways, mail servers: the targets of [service-side exploits](../endpoint-attacks/initial-exploitation.md#service-side).
- **Client software** — browsers, PDF readers, Office, archive tools, chat apps: the targets of [client-side exploits](../endpoint-attacks/initial-exploitation.md#client-side). This group is easy to forget because it never shows up in a port scan — the 2021-era 7-Zip in the inventory example above is a typical case.

### Setting the bar in advance { #emergency-bar }

Vendors regularly ship **out-of-band (emergency)** patches outside their normal schedule when a bug is being exploited. The worst time to decide whether a patch justifies taking down a production server is at 2 a.m. while it is happening. Agree beforehand, in writing, what level of risk allows the security team to force an outage — for example: "internet-facing, remote code execution, and exploited in the wild or public exploit available → patch or mitigate within 48 hours, even if it means downtime". If your organisation follows Australia's Essential Eight, its patching requirements (for example 48 hours for internet-facing services when the vulnerability is critical or a working exploit exists, at the higher maturity levels) already give you such a bar.

The long-term goal is **automated patch management** for both the OS and third-party applications, so that "patch quickly" no longer requires heroic manual effort or painful outages.

### Checking that a patch really landed { #verify-patch }

"We pushed the patch" and "every host is patched" are different statements. A few quick checks:

```powershell
Get-HotFix | Sort-Object InstalledOn -Descending | Select-Object -First 3
```

```
Source        Description      HotFixID      InstalledBy           InstalledOn
------        -----------      --------      -----------           -----------
LT-FIN-0412   Security Update  KB50xxxxx     NT AUTHORITY\SYSTEM   11/12/2026 12:00:00 AM
LT-FIN-0412   Update           KB50yyyyy     NT AUTHORITY\SYSTEM   11/12/2026 12:00:00 AM
LT-FIN-0412   Security Update  KB50zzzzz     NT AUTHORITY\SYSTEM   10/15/2026 12:00:00 AM
```

- `Get-HotFix` lists Windows updates recorded through the OS's Quick Fix Engineering list. `InstalledBy NT AUTHORITY\SYSTEM` is normal for Windows Update.
- It does **not** show third-party application updates, and on modern Windows cumulative updates it may not show every component — so treat it as a quick check, not a full inventory.

The **System** event log also records Windows Update results from the source `Microsoft-Windows-WindowsUpdateClient`: event **19** = an update installed successfully, **20** = an installation failed, **43** = an installation started. A host that logs repeated 20s for the same update is quietly falling behind. And for Linux:

```
$ apt list --upgradable 2>/dev/null | grep -i security
openssl/noble-security 3.0.13-0ubuntu3.5 amd64 [upgradable from: 3.0.13-0ubuntu3.4]
$ [ -f /var/run/reboot-required ] && cat /var/run/reboot-required
*** System restart required ***
```

- `apt list --upgradable` lists packages with a newer version available; filtering for `security` shows those from the security pocket.
- `/var/run/reboot-required` exists on Ubuntu/Debian when an installed update (often a kernel or core library) needs a reboot to take effect. Installed-but-not-active is the same trap as the scanner's "reboot pending" above.

## Step 4 — anti-exploitation: when patching isn't enough { #anti-exploitation }

### The problem patching can't solve { #why-anti-exploit }

Picture it: a user receives an email with `Invoice_7731.pdf`, downloads it and opens it. The PDF contains an exploit for the PDF reader. Two questions:

1. **Will it work?** Only if the reader is vulnerable. If it is a *zero-day* (no patch exists yet), or the reader is one of the forgotten unpatched copies, the answer is yes.
2. **How will you know it happened?** Without extra tooling, possibly not at all — the user sees a blank document, and the first sign may be C2 traffic days later.

Malicious files arrive by email, web downloads, USB sticks and chat. Patching and scanning can't get ahead of every one of them, especially zero-days. **Anti-exploitation** tools address this by making the *exploit technique* fail, whatever the specific bug is. Exploitation is the first stage of the attack that happens on the host itself, so it is the earliest point where the endpoint can break the chain — and early is cheap.

### How exploit mitigations work { #how-mitigations-work }

Go back to the building analogy. Patching fixes a specific broken lock. Anti-exploitation is more like making the building *structurally* harder to break into: bars on all windows, doors that only open outward, walls that set off an alarm if drilled. A burglar with a brand-new trick for one particular lock still hits the bars.

Technically, most memory-corruption exploits follow a few standard moves — overwrite memory with attacker data, then redirect execution into it or into existing code chunks. Mitigations target those moves:

| Mitigation | What it blocks (simplified) |
| --- | --- |
| DEP (Data Execution Prevention) | Running code from memory meant only for data (stack, heap) |
| ASLR (Address Space Layout Randomization), mandatory/bottom-up | Knowing where code and libraries are in memory, which exploits rely on |
| CFG (Control Flow Guard) | Indirect calls jumping to addresses that are not valid function starts |
| SEHOP | Overwriting the exception handler chain to hijack execution |
| Export/Import address filtering, caller checks, ROP mitigations | Calling sensitive functions (e.g. making memory executable) from attacker-built code chains |
| Child process blocking, code-integrity guard, blocking remote/low-integrity image loads | The payload stage: launching `cmd.exe`, loading unsigned DLLs |

The big extra benefit: these tools *recognise* a buffer overflow or ASLR bypass when they stop it, so they can **write a log entry saying an exploit was attempted**. That converts a silent attack into an alert the SOC receives within seconds — a very high-quality one, because normal software almost never triggers these mitigations.

### From EMET to Exploit Guard to today { #emet-exploit-guard }

Microsoft's first widely used tool here was **EMET** (Enhanced Mitigation Experience Toolkit), a free add-on that could force these mitigations onto older programs that weren't built with them, on Windows up to 8.1 / Server 2012 R2. EMET reached end of life in July 2018 and must not be used today. Its replacement was built into Windows 10 as **Windows Defender Exploit Guard**, a set of four controls. The "Exploit Guard" brand name has since faded — the features now live in Windows Security and Microsoft Defender for Endpoint under *exploit protection* and *attack surface reduction* — but the four components are the same.

**1. Exploit protection** — the direct successor to EMET's mitigations. System-wide defaults plus per-program overrides, each in *on* or *audit* mode. You can read a program's settings:

```powershell
Get-ProcessMitigation -Name AcroRd32.exe
```

```
ProcessName                     : AcroRd32.exe
DEP:
    Enable                      : ON
ASLR:
    ForceRelocateImages         : ON
    BottomUp                    : ON
    HighEntropy                 : ON
ControlFlowGuard:
    Enable                      : ON
ChildProcess:
    DisallowChildProcessCreation: ON
    Audit                       : OFF
ImageLoad:
    BlockRemoteImageLoads       : ON
    BlockLowLabelImageLoads     : ON
```

- `Get-ProcessMitigation -Name` shows the mitigations applied to a program by name (`-System` shows the system-wide defaults).
- `DEP Enable ON`, `ASLR ForceRelocateImages ON` — the classic memory protections are forced for this program even if it wasn't compiled with them ("mandatory ASLR").
- `ChildProcess DisallowChildProcessCreation ON` — the PDF reader may not start other programs. An exploit that succeeds in memory and then tries to launch `powershell.exe` is stopped at the payload stage.
- `ImageLoad BlockRemoteImageLoads` — no loading DLLs from network shares, a common exploit trick.
- Blocked mitigations are logged in `Microsoft-Windows-Security-Mitigations/UserMode` and `…/KernelMode` (Event Viewer → Applications and Services Logs → Microsoft → Windows → Security-Mitigations). Add those channels to log collection — they are low volume and high value.

Test before enforcing: some older applications crash under forced mitigations, which is why *audit* mode exists.

**2. Controlled folder access** — Microsoft's anti-ransomware control. You mark folders as *protected* (Documents, Pictures, Desktop by default, plus your own like a finance share), and only programs on an allow list (Microsoft's trusted-app list plus ones you add) may change files there. Ransomware running as the user tries to overwrite `C:\Users\m.lee\Documents\budget.xlsx` and is refused. (ATT&CK **T1486 Data Encrypted for Impact** is the technique it targets.)

```powershell
Set-MpPreference -EnableControlledFolderAccess Enabled        # or AuditMode
Add-MpPreference -ControlledFolderAccessProtectedFolders 'D:\FinanceShare'
```

A block appears in the Defender log as event **1123**:

```
Log Name:  Microsoft-Windows-Windows Defender/Operational
Event ID:  1123
Controlled Folder Access blocked C:\Users\m.lee\AppData\Local\Temp\svch0st.exe from making changes to the folder C:\Users\m.lee\Documents\
 Detection time: 2026-11-19T04:12:07.331Z
 User: CORP\m.lee
 Path: C:\Users\m.lee\Documents\budget.xlsx
 Process Name: C:\Users\m.lee\AppData\Local\Temp\svch0st.exe
```

- `Event ID 1123` = a controlled folder access **block** (`1124` = the same in audit mode, `1127`/`1128` = blocked/audited writes to protected disk sectors).
- `Process Name …\Temp\svch0st.exe` — a misspelled `svchost` running from Temp trying to write a document. Legitimate programs blocked here are usually line-of-business apps that need allow-listing; this is not one of them. Dozens of 1123s from one process across different files in seconds is ransomware behaviour — isolate the host.

**3. Network protection** — extends Microsoft's SmartScreen reputation checks (normally only in Edge) to **every application's** outbound connections. If any process — a script, an unknown `.exe`, a third-party browser — tries to reach a domain or IP with a known-bad or low reputation, the connection is blocked. Events: **1126** = blocked, **1125** = audited. It is an extra C2 and phishing-site brake, not a replacement for a proxy.

**4. Attack surface reduction (ASR) rules** — rules that block the behaviours typical of malware delivered through Office documents, email and scripts. Each rule has a GUID and a mode (`0` off, `1` block, `2` audit, `6` warn). Some well-known rules:

| ASR rule (name) | Blocks |
| --- | --- |
| Block all Office applications from creating child processes | `WINWORD.EXE` → `powershell.exe` / `cmd.exe` |
| Block Office applications from creating executable content | A macro writing `update.exe` to disk |
| Block executable content from email client and webmail | Running `.exe`/scripts straight from Outlook attachments |
| Block JavaScript or VBScript from launching downloaded executable content | Script droppers |
| Block execution of potentially obfuscated scripts | Heavily obfuscated PowerShell/JS |
| Block credential stealing from the Windows local security authority subsystem | Opening `lsass.exe` for memory reads ([credential dumping](../endpoint-attacks/credential-dumping-mimikatz.md)) |
| Block persistence through WMI event subscription | WMI-based persistence |

Checking what is configured on a host:

```powershell
Get-MpPreference | Select-Object -ExpandProperty AttackSurfaceReductionRules_Ids
Get-MpPreference | Select-Object -ExpandProperty AttackSurfaceReductionRules_Actions
```

```
d4f940ab-401b-4efc-aadc-ad5f3c50688a
9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2
be9ba2d9-53ea-4cdc-84e5-9b1eeee46550
1
2
1
```

- The first command prints the rule GUIDs that are configured; the second prints the matching actions **in the same order**. So: Office child processes = `1` (block), LSASS credential stealing = `2` (audit only), email executable content = `1` (block).
- Reading them together matters: a rule that is only in audit mode logs but does not protect.

The event a SOC should love — an ASR block, Defender event **1121**:

```
Log Name:  Microsoft-Windows-Windows Defender/Operational
Event ID:  1121
Microsoft Defender Exploit Guard has blocked an operation that is not allowed by your IT administrator.
 ID: D4F940AB-401B-4EFC-AADC-AD5F3C50688A
 Detection time: 2026-11-19T01:22:41.508Z
 User: CORP\m.lee
 Path: C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe
 Process Name: C:\Program Files\Microsoft Office\root\Office16\WINWORD.EXE
 Target Commandline: powershell.exe -nop -w hidden -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBi...
```

Field by field:

- `Event ID 1121` = an ASR rule **blocked** something (`1122` = the rule is in audit mode and *would* have blocked it).
- The message still says "Exploit Guard" — the old name lives on in event text.
- `ID D4F940AB-…` = the rule GUID: *Block all Office applications from creating child processes*.
- `Process Name …\WINWORD.EXE` — the parent that tried to act. `Path …\powershell.exe` — what it tried to start.
- `Target Commandline … -nop -w hidden -enc …` — PowerShell with no profile, a hidden window and a Base64-encoded command: classic macro-dropper behaviour (ATT&CK **T1204.002 Malicious File** leading to **T1059.001 PowerShell**).
- The exploit or macro *ran* inside Word, but the next stage was stopped. So: find the document (which file did `m.lee` open at 01:22?), check whether other users received it, and check whether anything else from that document succeeded — for example a different technique that no rule covered.

**Licensing — and its 2026 reality.** Originally exploit protection and controlled folder access came with all Windows 10 editions, network protection needed Enterprise E3, and ASR (with central management and reporting in what was then Defender ATP) needed E5. Today the features run on Windows 10/11 Pro and Enterprise with Microsoft Defender Antivirus as the active antivirus (many depend on real-time and cloud protection). Microsoft supports ASR with E3, but full central reporting, alerting and advanced hunting need Microsoft Defender for Endpoint (Plan 2 / E5). Without that, collect the Defender operational log yourself so 1121–1126 still reach the SIEM. If a third-party antivirus is the primary AV, Defender is in passive mode and these features generally do not enforce — check, don't assume.

## Putting it together — what a SOC takes from this layer { #soc-use }

- **Scan schedules and scanner IPs** — know them, exclude them, alert on everything else that looks like a scan.
- **Vulnerability data in the SIEM** — enrich IDS/EDR alerts with "is this host vulnerable to this CVE?".
- **Unpatched outliers** — the hosts that keep failing updates (event 20, scanner "reboot pending") are where attackers succeed; give them extra monitoring.
- **Anti-exploitation events** — route Security-Mitigations events and Defender 1121/1123/1126 (block) as alerts; review 1122/1124/1125 (audit) to tune before switching to block.
- **The question to ask on every exploit alert:** was it blocked, and was it the *only* thing that happened? A blocked child process means the first stage ran.

## The 2026 view { #trends }

!!! success "[2026 Current] Still valid"
    Defence in depth along the attack stages, "you can't protect what you don't know you have", combining inventory with network scans, authenticated over unauthenticated scanning, patching as the most effective control against exploitation (OS, server *and* client), deciding the emergency-patch bar in advance, and anti-exploitation that both blocks and logs — all of this is exactly as described. Nmap's SYN scan, version detection, OS guessing and NSE scripts work the way shown, and the four Exploit Guard components still exist with the same Defender event IDs (1121–1128).

!!! info "[Changed] What has changed"
    - **Names and packaging.** EMET has been unsupported since 2018. "Windows Defender Exploit Guard" is now just exploit protection, controlled folder access, network protection and ASR rules inside Microsoft Defender Antivirus / Defender for Endpoint; ASR has grown well beyond the original rules (e.g. LSASS credential theft, WMI persistence, vulnerable signed drivers, webshell creation on servers) and has a *warn* mode. ASR is supported with E3, with full reporting through Defender for Endpoint.
    - **CIS Controls numbering.** The "Top 20" (v7) became 18 controls in v8 (2021) and v8.1 (2024): software inventory is Control 2, continuous vulnerability management is Control 7.
    - **Prioritisation moved beyond CVSS.** CVSS v4.0 (2023) exists, but teams now combine severity with *likelihood*: CISA's Known Exploited Vulnerabilities (KEV) catalogue, EPSS exploit-probability scores and asset exposure. "Patch everything rated 9.0+" is no longer considered a good strategy on its own.
    - **Time-to-exploit collapsed.** Industry analyses (for example Google/Mandiant's time-to-exploit studies) found the average gap between disclosure and exploitation fell from about a month a few years ago to around five days for vulnerabilities exploited in 2023, with a large share exploited as zero-days. Monthly-only patching is too slow for internet-facing systems.
    - **Edge devices are the top target.** VPN gateways, firewalls, file-transfer appliances and other edge devices have been among the most exploited products since 2023. They often can't run EDR or anti-exploitation tools, so inventory, fast patching and log forwarding from them matter even more.
    - **Fewer reboots.** Hotpatching (security updates without a restart) is available for Windows 11 Enterprise 24H2 and Windows Server 2025 (via Azure Arc subscription), and services like Windows Autopatch automate rollout — removing some of the outage argument against fast patching.
    - **Exposure management.** Inventory, vulnerability and attack-surface data are increasingly merged into "exposure management" / external attack surface management (EASM) products that keep scanning from the internet side continuously.

!!! warning "[Caution] Wrong or risky to do the old way"
    - **Don't deploy EMET** or rely on legacy guides that reference it — it is unsupported and incompatible with current Windows.
    - **Don't trust an unauthenticated scan's "no critical findings".** Hidden banners and client software make it blind. Use credentialed scans or agents for patch decisions.
    - **Don't treat "patch installed" as "patched"** until the reboot happened and a re-scan confirms it.
    - **Don't use `Win32_Product` / `wmic product` for inventory** — it triggers MSI repair checks across the machine. (`wmic` itself is being removed from Windows.)
    - **Don't leave ASR rules in audit mode forever.** Audit is for tuning; a rule in audit protects nothing. Also check that Defender is actually the active AV — in passive mode the rules don't enforce.
    - **Don't run aggressive active scans against fragile OT/medical devices** without the owners' agreement; use passive discovery there.
    - **Don't forget out-of-support systems.** A host like Windows Server 2012 R2 without Extended Security Updates gets no patches at all — it needs upgrading or isolation, not a ticket in the monthly cycle.

## Practice questions { #quiz }

### Question 1

The asset team says "Our inventory system has 100% coverage, so we don't need network scanning." Give two concrete examples of what the inventory could miss that a network scan would find — and one example of the opposite.

??? success "Answer and explanation"
    **What inventory can miss (but a scan finds):**

    1. Software that never registered with the OS — a portable web server or a developer tool started from a Downloads folder, a Python or Java service unpacked into a folder, a container publishing a port. It isn't in the Uninstall list, but it **listens** on the network.
    2. Devices with no agent at all — appliances, printers, IP cameras, a forgotten test VM, a contractor's laptop. The inventory system doesn't know they exist; a scan finds the IP answering on TCP 80/23/8080.

    (Also: a service that *is* in the inventory but is configured dangerously, like anonymous FTP — only probing it shows that.)

    **The opposite (inventory finds, scan misses):** client software that never listens on a port — an outdated PDF reader, archive tool or browser. Port scans can't see it, yet it is the target of client-side exploits via malicious files. That's why the two views are combined: installed vs exposed = the attack surface.

### Question 2

The IDS alerts: "Apache Tomcat RCE exploit attempt" from `198.51.100.23` to `10.20.0.31:8080`. Last night's unauthenticated scan of `10.20.0.31` showed no critical findings. The authenticated scan from the same night shows Tomcat 9.0.31 with critical RCE vulnerabilities and "kernel reboot pending". What does each scan tell you, how urgent is this alert, and what do you check next?

??? success "Answer and explanation"
    **The scans:** the unauthenticated scan couldn't read Tomcat's hidden version, so its "no critical findings" means "couldn't tell", not "safe". The authenticated scan read the real version from disk: the host **is vulnerable** to the kind of exploit being attempted. "Reboot pending" adds that even the patches that were installed aren't active.

    **Urgency:** high. An exploit attempt against a host *confirmed vulnerable* to it is a probable compromise, not noise. (The same alert against a patched host would be low priority.)

    **Next checks:**

    1. On `srv-ftp-02`: did the Tomcat process (`java`) spawn anything — `sh`, `bash`, `curl`, `wget` — around the alert time (process logs / auditd / EDR)? New files in the webapps directory (webshell)? Outbound connections from the host?
    2. Web/Tomcat access logs for requests from `198.51.100.23` and the HTTP status codes.
    3. Contain if there are signs of success; in any case patch Tomcat (emergency bar: reachable, RCE, exploit in use) and reboot.
    4. Check whether the same source hit other hosts, and whether other hosts run the same vulnerable version.

### Question 3

You find these on a finance laptop within one minute. Explain each event, what was stopped, and whether the incident is over.

```
01:22:41  Defender 1121  ID D4F940AB-401B-4EFC-AADC-AD5F3C50688A  Process: WINWORD.EXE  Path: powershell.exe  Cmd: powershell -nop -w hidden -enc ...
01:22:43  Defender 1122  ID 9E6C4E1F-7D60-472F-BA1A-A39EF669E4B2  Process: C:\Users\Public\rdr.exe  Path: lsass.exe
01:22:50  Defender 1123  Process: C:\Users\Public\rdr.exe  Folder: C:\Users\m.lee\Documents\
```

??? success "Answer and explanation"
    **1121 (block)** — the ASR rule *Block all Office applications from creating child processes* stopped Word from launching hidden, encoded PowerShell. A malicious document was opened and its macro/exploit ran.

    **1122 (audit)** — the rule *Block credential stealing from LSASS* is only in **audit** mode. `C:\Users\Public\rdr.exe` opened `lsass.exe` and the rule **did not stop it** — it only logged that it would have. Credential theft may have succeeded.

    **1123 (block)** — controlled folder access stopped the same `rdr.exe` from changing files in Documents: ransomware-like behaviour was blocked.

    **Not over — it's serious.** The PowerShell stage was blocked, yet `rdr.exe` exists and runs, so the document found **another way** to drop and start an executable (or a second stage arrived differently). It then tried to read LSASS (allowed) and encrypt files (blocked). Isolate the laptop, collect the document and `rdr.exe`, find how `rdr.exe` got there (process creation logs, Sysmon 11 file creation), treat every credential cached on that laptop as stolen and reset them, look for those accounts being used elsewhere, and switch the LSASS rule from audit to block after tuning. Lesson: audit-mode rules give visibility, not protection.

## Related { #related }

- [Endpoint Attacks](../endpoint-attacks/index.md) — the attack stages this section defends against
- [Initial Exploitation](../endpoint-attacks/initial-exploitation.md) · [Credential Dumping and Mimikatz](../endpoint-attacks/credential-dumping-mimikatz.md)
- [Phishing delivery](../../../adversary/phishing-delivery.md) · [EternalBlue and SMBv1](../../../adversary/eternalblue-smbv1.md) · [PrintNightmare](../../../adversary/printnightmare.md)
- [Hardening by Windows version](../../../adversary/hardening-by-version.md)
- [Windows Event IDs](../../../basics/windows-event-ids.md) · [Well-known ports](../../../basics/well-known-ports.md)

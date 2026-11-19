---
title: "DHCP — Protocols to Watch, Turning an IP into a Device, Finding Rogue Devices, DORA Step by Step"
tags:
  - training
  - blue-team
  - network
  - dhcp
---

# DHCP — Protocols to Watch, Turning an IP into a Device, Finding Rogue Devices, DORA Step by Step { #dhcp }

!!! abstract "What this page covers"
    Why the protocols an analyst must know after DNS, HTTP and email (DHCP, SMB, SSH, RDP/VNC, PowerShell remoting, FTP, ICMP and remote administration tools) are grouped together, starting with DHCP. Why DHCP is the first step in turning an IP in an alert into "which device, whose device", why the time matters, how DHCP logs find rogue devices (hostname conventions, the MAC address OUI) and where that breaks down, and the four steps of getting an address (DORA) packet by packet. Reading the Windows DHCP audit log and Zeek `dhcp.log` field by field, and attacks such as rogue DHCP servers. Practice questions with explanations at the end.

!!! note "Labels"
    **[Supplement]** = practical material you need to know, **[Correction]** = a commonly repeated claim that is wrong or outdated, **[Changed]**/**[Caution]** = what has changed recently and what is risky to do the old way. Hostnames, domains, IPs and MACs are invented for illustration (`.example`, documentation and private IPs).

## The 8 key points { #key-points }

1. Beyond DNS, HTTP and SMTP, attackers use other protocols to **move laterally** and to **exfiltrate data**: SMB, SSH, RDP/VNC, PowerShell remoting, FTP, ICMP and **any remote access or administration tool**.
2. DHCP is less an attack channel than the record that tells an analyst **"which device had this IP at that time"**.
3. Investigation is a chain of **IP → device name (hostname) and MAC → user**, and the DHCP log is the first link.
4. An IP is leased, so its owner changes. You must find **the device that held the IP at the time of the alert**.
5. DHCP servers usually log the **hostname, the assigned IP and the MAC address**, so they act as an attendance register for the network.
6. Rogue devices can be found by **hostname conventions** (does it match the company scheme, is it a router or Raspberry Pi default name) and the **MAC OUI** (first 3 bytes = manufacturer).
7. But hostname and MAC are **self-reported by the device** and can be faked. Accidentally connected devices are caught easily; a prepared attacker can slip through. Today **MAC randomisation** on phones and laptops also undermines OUI checks.
8. An address is obtained in four steps: **Discover → Offer → Request → Acknowledge (DORA)** over UDP **67 (server) and 68 (client)**, starting from source `0.0.0.0` to the broadcast `255.255.255.255`.

## The protocols in this group { #additional-protocols }

DNS, HTTP and email were the attack's **entrance and phone line**: in through a phishing email, malware over HTTP, C2 over DNS or HTTPS. Once an attacker has a foothold on one machine, the job changes. They **move sideways** to other servers, gain admin rights, and finally **move data out**. The protocols they use for that are mostly the ordinary ones administrators use every day.

| Protocol | Normal use | Why attackers like it | Page |
| --- | --- | --- | --- |
| DHCP | Handing out IPs | Not an attack path so much as **the investigation's anchor**. Rogue DHCP servers, rogue devices | This page |
| SMB | Windows file and printer sharing | Remote execution (PsExec-style), file copy, ransomware spread, credential capture | SMB page |
| SSH | Remote shell, file transfer | One outbound SSH session can build a **tunnel back in** | SSH, RDP and VNC page |
| RDP/VNC | Remote desktop | Driving the screen with a stolen account, internet-exposed RDP | SSH, RDP and VNC page |
| PowerShell remoting | Remote administration (WinRM) | Running commands on another PC without dropping files | PowerShell remoting, FTP and ICMP page |
| FTP / ICMP | File transfer / ping | Plaintext exfiltration, data hidden in ICMP (tunnelling) | PowerShell remoting, FTP and ICMP page |
| Any remote admin tool | Remote support and management | Legitimate software, rarely blocked by antivirus | Remote tools page |

The core idea: **don't ask "is this protocol good or bad?" but "is it normal for this protocol to be used on this device, to this peer, at this time?"** RDP from an admin workstation to a server is routine; RDP from one finance PC to another finance PC is suspicious. To make that call you first need to know who an IP is, which is why this group starts with DHCP.

## Why DHCP matters to analysts { #why-dhcp }

### Turning the IP in an alert into "who" { #ip-to-owner }

IDS alerts, firewall logs and proxy logs mostly identify devices only by **IP address**. But response is about people and devices. "Isolate 10.20.30.41" is not an action; "isolate J. Kim's finance laptop `LT-FIN-0412`" is. The chain looks like this:

```
 Alert: src=10.20.30.41          (IDS / firewall / proxy)
        │  DHCP lease log at the alert time
        ▼
 Host: LT-FIN-0412  MAC 3c:52:82:aa:41:07
        │  asset inventory / EDR / AD computer object
        ▼
 Device owner: finance team, assigned to j.kim
        │  logon events (4624 on the host, 4768 on the DC)
        ▼
 User at that time: VICTIM\j.kim
```

Think of a **hotel room number**. A noise complaint from room 1203 doesn't tell you who "the person in 1203" is. You need the front desk's **check-in record** to know who stayed there at that time, and yesterday's guest in 1203 may be someone else today. The IP is the room number; the DHCP lease record is the check-in record.

Technically: DHCP lends an IP **only for a set period (the lease time)**. A laptop joins the meeting-room Wi-Fi, leaves, and the next day joins on another floor with a different IP. An expired IP goes to another device. So **looking up "the device using this IP now" can catch the wrong person.** Always find the lease that covers the alert time.

### The rest of the chain — 4624 and 4768 { #logon-events }

<strong>[Supplement]</strong> DHCP only takes you from IP to device. Device to person comes from logon records. Two events do most of the work:

- **Windows event 4624 (An account was successfully logged on).** Written to that PC's Security log every time someone logs on to it. The `Logon Type` field gives the method: 2 = interactive at the keyboard, 3 = network (file shares etc.), 10 = RDP, 11 = cached credentials. `Source Network Address` holds the peer IP. For attackers, logging on to another PC with a stolen account leaves this event, so it is the first event to check for lateral movement.
- **Windows event 4768 (A Kerberos authentication ticket (TGT) was requested).** Written on the domain controller. When a user logs on to a domain PC, it first gets an "entry pass" (TGT) from the DC, and this event records **the account name and the `Client Address` (requesting IP)** together. So DC logs alone can tell you "the user logging on from that IP at that time". For attackers, AS-REP roasting and password guessing surface here (with failures showing as 4771 and similar).

In short: **DHCP (IP → device) + 4768/4624 (IP/device → user)** go together. With EDR, the console often makes this link for you, but for devices without EDR (printers, personal devices, the attacker's own box) the DHCP record is often the only clue.

## What the logs look like { #logs }

### Windows DHCP server audit log { #windows-audit-log }

The Windows DHCP server keeps an audit log by default as daily text files under `%windir%\System32\dhcp\`, named by **weekday**: `DhcpSrvLog-Mon.log`, `DhcpSrvLog-Tue.log` and so on. Each weekday's file is overwritten the following week, so **by default only about a week is kept.** To find "that IP three weeks ago" during an incident, the logs must already have been shipped to a SIEM.

The file is comma-separated. A table explaining the IDs comes first, then the records.

```
ID,Date,Time,Description,IP Address,Host Name,MAC Address,User Name,TransactionID,QResult,Probationtime,CorrelationID,Dhcid,VendorClass(Hex),VendorClass(ASCII),UserClass(Hex),UserClass(ASCII),RelayAgentInformation,DnsRegError
10,11/18/26,08:52:13,Assign,10.20.30.41,LT-FIN-0412.corp.victim.example,3C5282AA4107,,2817346601,0,,,,0x4D53465420352E30,MSFT 5.0,,,0x0104000A0114,0
30,11/18/26,08:52:13,DNS Update Request,10.20.30.41,LT-FIN-0412.corp.victim.example,,,0,6,,,,,,,,,0
32,11/18/26,08:52:13,DNS Update Successful,10.20.30.41,LT-FIN-0412.corp.victim.example,,,0,6,,,,,,,,,0
11,11/18/26,12:52:20,Renew,10.20.30.41,LT-FIN-0412.corp.victim.example,3C5282AA4107,,1093882716,0,,,,0x4D53465420352E30,MSFT 5.0,,,,0
10,11/18/26,13:07:45,Assign,10.20.30.77,raspberrypi,B827EB5C19A0,,3301928811,0,,,,0x64686370636420392E342E31,dhcpcd 9.4.1,,,0x0104000A0114,0
12,11/18/26,17:31:02,Release,10.20.30.41,LT-FIN-0412.corp.victim.example,3C5282AA4107,,3920118373,0,,,,,,,,,0
```

The header line, field by field:

- `ID` — what happened. Common ones: **10 = new lease (Assign)**, **11 = renewal (Renew)**, **12 = release**, 13 = the IP is already in use on the network (conflict), 14 = the address pool is exhausted, 15 = lease denied, 16 = lease deleted, 17 = lease expired, 30/31/32 = DNS update request/failure/success. Others cover start/stop and authorisation.
- `Date`, `Time` — the server's **local time**, not UTC. Check the time zone when correlating with other logs.
- `Description` — text for the ID.
- `IP Address` — the leased IP.
- `Host Name` — **the name the client reported itself** (DHCP option 12 or 81). Domain-joined Windows PCs usually show an FQDN (`LT-FIN-0412.corp.victim.example`).
- `MAC Address` — 12 hex digits with no separators. `3C5282AA4107` = `3c:52:82:aa:41:07`.
- `User Name` — almost always empty. **This is not a record of user names.**
- `TransactionID` — ties one exchange together (the packet's `xid`). Useful for finding the same exchange in a packet capture.
- `QResult` — the result from NAP, a long-retired quarantine feature. Usually meaningless now.
- `VendorClass(Hex)`, `VendorClass(ASCII)` — DHCP option 60, the device saying what kind of DHCP client it is. `MSFT 5.0` = Windows, `dhcpcd 9.4.1` = many Linux systems (including Raspberry Pi OS), `android-dhcp-…` = older Android.
- `RelayAgentInformation` — DHCP option 82, added by the relaying switch or router. Depending on configuration it can say **which switch and which port** the request came from — gold when locating a rogue device physically.
- `DnsRegError` — DNS registration error code (0 = fine).

Now the records:

1. **08:52:13, ID 10** — `LT-FIN-0412` received `10.20.30.41`. Vendor class `MSFT 5.0` means Windows, and the name matches the company scheme (`LT-<dept>-<number>`).
2. **ID 30, 32** — the DHCP server registered `LT-FIN-0412 → 10.20.30.41` in DNS on the PC's behalf. DNS can therefore also map IP to name, but DNS only shows **the current value**, so for a past time the DHCP record is more accurate.
3. **12:52:20, ID 11** — renewal four hours later. With an 8-hour lease this is normal: clients renew at the halfway point (see T1 in the DORA section).
4. **13:07:45, ID 10** — hostname `raspberrypi`, MAC `B8:27:EB:…`, vendor class `dhcpcd`. `raspberrypi` is Raspberry Pi OS's default hostname and `B8:27:EB` is an OUI registered to the Raspberry Pi Foundation. A name outside the scheme + a manufacturer the company doesn't buy + a Linux client: **top of the list to investigate.** Use the relay information (`0x0104000A0114`) with the network team to find the switch port.
5. **17:31:02, ID 12** — `LT-FIN-0412` released its IP (shut down at the end of the day). An alert for `10.20.30.41` after this time may be **a different device**.

<strong>[Supplement]</strong> Current leases can also be viewed with PowerShell:

```powershell
Get-DhcpServerv4Lease -ComputerName dhcp01.corp.victim.example -ScopeId 10.20.30.0 |
    Where-Object { $_.IPAddress -eq '10.20.30.77' } |
    Select-Object IPAddress, ClientId, HostName, AddressState, LeaseExpiryTime
```

- Line 1: `Get-DhcpServerv4Lease` — gets the IPv4 leases in one scope (`-ScopeId`, here the `10.20.30.0` range) on a DHCP server (`-ComputerName`). The trailing `|` passes the results to the next command.
- Line 2: `Where-Object` — keeps only the lease for `10.20.30.77`.
- Line 3: `Select-Object` — picks the fields to show. `ClientId` is normally the MAC.

```
IPAddress    ClientId          HostName     AddressState LeaseExpiryTime
---------    --------          --------     ------------ ---------------
10.20.30.77  b8-27-eb-5c-19-a0 raspberrypi  Active       11/19/2026 9:07:45 PM
```

This shows **only leases that are live right now.** "Who had it back then" needs the audit log (or the copy in your SIEM).

### Zeek `dhcp.log` { #zeek-dhcp-log }

If a network sensor runs Zeek, it records DHCP conversations regardless of the server product. Zeek **collapses the four DORA packets into one line**.

```
$ zeek-cut -d ts client_addr server_addr mac host_name client_fqdn assigned_addr lease_time msg_types < dhcp.log
2026-11-18T13:07:45+0000  10.20.30.77  10.20.0.5  b8:27:eb:5c:19:a0  raspberrypi  -  10.20.30.77  28800.000000  DISCOVER,OFFER,REQUEST,ACK
2026-11-18T13:42:10+0000  -            192.168.8.1  b8:27:eb:5c:19:a0  raspberrypi  -  192.168.8.103  43200.000000  DISCOVER,OFFER,REQUEST,ACK
```

The command:

- `zeek-cut` — extracts chosen fields from a Zeek log. `-d` turns Unix-epoch timestamps into readable dates.
- The names after it — the fields to extract. `< dhcp.log` feeds the file in.

The fields:

- `ts` — time of the first packet.
- `client_addr` — the IP the client **already had**. Empty (`-`) when obtaining a first address.
- `server_addr` — the DHCP server that answered. **A value not on your list of DHCP servers is an alert.**
- `mac`, `host_name`, `client_fqdn` — the self-reported MAC and names (options 12 and 81).
- `assigned_addr` — the IP finally assigned.
- `lease_time` — lease length in seconds. 28800 = 8 hours.
- `msg_types` — the message types in this conversation. `DISCOVER,OFFER,REQUEST,ACK` is a normal DORA; a renewal shows just `REQUEST,ACK`.

The second line matters. 35 minutes later the same Raspberry Pi got `192.168.8.103` from **a server never seen before, `192.168.8.1`**, outside our address plan (`10.20.x.x`). That strongly suggests someone **plugged in a home Wi-Fi router that is now acting as a DHCP server** (small routers commonly use `192.168.x.1`). A rogue DHCP server like this can hand other staff PCs the wrong gateway and DNS, which is dangerous (see the attacks section).

<strong>[Supplement]</strong> For packet captures, use the Wireshark/tshark filter `dhcp` (very old versions: `bootp`). A host-identification walkthrough is in [Identifying hosts](../../pcap-ir-labs/host-identification.md#ip-mac-hostname).

## Finding rogue devices with DHCP { #rogue-devices }

A classic scenario: an attacker walks into the building (or poses as a cleaner or visitor), plugs a small device into a meeting-room wall port, and leaves. A small computer such as a Raspberry Pi that opens an outbound connection gives the attacker remote access from inside. The control that stops this up front is **Network Access Control (NAC)**, typically 802.1X port authentication. Where there is no NAC, or it has gaps, you must **notice after the fact**, and since the first thing most devices do is request an address over DHCP, the DHCP log sees them first. The same checks catch staff accidentally plugging in a home router or personal device.

### Clue 1 — the hostname { #hostname }

Corporate devices usually follow a **naming scheme**, for example `LT-<dept>-<number>` (laptops), `WS-<floor>-<number>` (desktops), `SRV-…` (servers). That allows two checks:

- **Allow list:** review anything that doesn't match the scheme. For example the regex `^(LT|WS|SRV)-[A-Z]{2,4}-\d{4}(\.corp\.victim\.example)?$` — pass if it matches, review if not.
  - `^` and `$` — the whole name must match (nothing before or after).
  - `(LT|WS|SRV)` — starts with one of these three.
  - `[A-Z]{2,4}` — 2 to 4 capital letters (department code).
  - `\d{4}` — four digits.
  - `(\.corp\.victim\.example)?` — the domain suffix is optional.
- **Deny list:** look for **default names** that shouldn't exist in the company: `raspberrypi`, `kali`, `ubuntu`, `DESKTOP-` followed by random characters (a fresh Windows build nobody renamed), default names containing a router vendor, and personal-device names such as `android-…`, `iPhone` or `Galaxy-…`.

The allow list is stricter but generates false positives because of exceptions (printers, meeting-room kit, door controllers and other IoT). In practice use both and keep the exceptions on a managed list.

### Clue 2 — the MAC address OUI { #oui }

A MAC address is **6 bytes (48 bits)**, usually written like `b8:27:eb:5c:19:a0`. The first 3 bytes (`b8:27:eb`) are the **OUI (Organizationally Unique Identifier)**, a number the IEEE assigns to a manufacturer; the last 3 are a serial the manufacturer picks per device. It's like **the manufacturer code at the start of a car's VIN**.

```
 b8 : 27 : eb : 5c : 19 : a0
 └─── OUI ───┘  └─ device ─┘
 maker (IEEE)   serial chosen by maker
```

Checks you can run:

- **Allow list:** if all company laptops are from vendor A, review a non-A OUI on the corporate wired network. Note that a laptop's MAC may carry the OUI of the **network chip maker** (e.g. Intel, Realtek) or of a **docking station or USB Ethernet adapter**, so build the list from your real assets' MACs.
- **Deny list:** OUIs of small single-board computers, consumer routers and IoT vendors the company doesn't use.

Look OUIs up in the IEEE's public registry or the manufacturer database Wireshark publishes (its OUI lookup tool and `manuf` file). Wireshark also shows the vendor in place of the MAC prefix (e.g. `Raspberr_5c:19:a0`).

<strong>[Supplement]</strong> Two things you must know when reading OUIs:

1. **The "locally administered" bit.** If the second-lowest bit of the first byte is 1, the MAC was **generated by software**, not assigned by a manufacturer. Easy check: if **the second hex character is `2`, `6`, `A` or `E`**, it's locally administered (e.g. `da:a1:19:…`, `4a:…`, `f6:…`). Such MACs have no OUI, so a vendor lookup is meaningless. Phone privacy MACs, virtual machines and some VPN or container interfaces look like this.
2. **OUIs aren't always 3 bytes.** Besides large blocks (MA-L, 24 bits = 3 bytes), the IEEE sells smaller blocks (MA-M, 28 bits; MA-S, 36 bits), so the first 3 bytes may cover a block shared by several small vendors. Check that your lookup tool handles this.

### The limit — these values are self-reported { #limits }

The hostname and MAC are **values the client writes into its own DHCP packets**. The server records them as given and verifies nothing — like an email's `From:`. So:

- A prepared attacker can learn the naming scheme (by listening to other PCs' DHCP requests, or reading a printer label), use a plausible name like `LT-FIN-0419`, and set a MAC with the company laptop vendor's OUI. They can even **clone the name and MAC of a real device**.
- On the other hand, a home router a staff member plugged in by mistake, or a Raspberry Pi left on defaults, keeps its name and MAC and is **caught easily**.

So DHCP-based detection isn't a perfect gatekeeper; it's **a cheap, wide first net**. For what slips through, also look at:

- **The same name or MAC in two places at once.** A clone and the real device seen at the same time on different switch ports or IPs is a strong signal.
- **A name that doesn't match its other traits.** A Windows-style name with a `dhcpcd` (Linux) vendor class, or an **option list (option 55, Parameter Request List)** in a non-Windows order. Each OS requests a characteristic set of options, and inferring the OS from it is called **DHCP fingerprinting**.
- **Devices not in the asset inventory or EDR.** Seen in DHCP but with no EDR agent and no asset record: review.
- **Switch-side records.** Port link up/down, 802.1X failures and option 82 relay information give you the physical location.

## How DHCP works — DORA in four steps { #dora }

Now the protocol itself. DHCP (Dynamic Host Configuration Protocol) lets **devices without a static IP get one automatically**, along with the subnet mask, default gateway (router), DNS servers, domain name and lease time. It runs over UDP: **server port 67, client port 68**.

The starting problem: a device that has just booted **has no IP and doesn't know where the DHCP server is.** So it begins by shouting a **broadcast**: "anyone who can hear this, please answer." Like walking into a new office and calling out "is the person who assigns desks here?"

```
 Client (no IP yet)                               DHCP server 10.20.0.5
   MAC 3c:52:82:aa:41:07

 1. DISCOVER  0.0.0.0:68  ───────────────────▶  255.255.255.255:67   "Any DHCP server out there?"
 2. OFFER     10.20.30.41:68 ◀───────────────  10.20.0.5:67          "You can have 10.20.30.41"
 3. REQUEST   0.0.0.0:68  ───────────────────▶  255.255.255.255:67   "I'll take 10.20.30.41 from 10.20.0.5"
 4. ACK       10.20.30.41:68 ◀───────────────  10.20.0.5:67          "Confirmed, 8 hours"
```

Step by step:

1. **Discover.** The client has no IP yet, so the source is `0.0.0.0`, port 68. The destination is **the broadcast to the whole local network, `255.255.255.255`**, port 67, and the Ethernet destination is `ff:ff:ff:ff:ff:ff` (everyone). The packet carries the client's MAC (the `chaddr` field), hostname (option 12), vendor class (option 60) and the settings it wants (option 55). If it had an IP before, it may ask for it again (option 50).
2. **Offer.** The DHCP server(s) on that network reply "how about this address?" from the server IP, port 67. The offer carries the proposed IP (the `yiaddr` field), lease time (option 51), subnet mask (option 1), router (option 3), DNS servers (option 6) and server identifier (option 54). Depending on the client, it is **unicast to the offered IP** (at the Ethernet level, to the client's MAC) or **broadcast**. Since the client has no IP yet, delivery relies on the MAC address, not IP routing.
3. **Request.** The client picks one offer (usually the first to arrive) and says "I'll use this address from this server". The confusing part: **this request is broadcast too** (`0.0.0.0` → `255.255.255.255`). Two reasons: the client still has no confirmed IP so must use `0.0.0.0`, and **every server that made an offer needs to hear it** so the ones not chosen can withdraw their offers and return the addresses to the pool. The server identifier (option 54) names the chosen server.
4. **Acknowledge (ACK).** The chosen server confirms, and the client uses the IP for the lease time. Many clients first check with ARP whether anyone already uses the IP and send a **DHCPDECLINE** if so (ID 13 in the Windows audit log relates to such conflicts).

<strong>[Supplement]</strong> Beyond DORA, these make the logs easier to read:

- **Renewal.** At **half the lease (T1)** the client sends a **unicast** `REQUEST` directly to its server; an `ACK` extends the lease (audit log ID 11, Zeek `msg_types=REQUEST,ACK`). If that server doesn't answer, from **87.5% (T2)** the client broadcasts to any server. So a healthy device leaves renewal records at regular intervals all day.
- **NAK.** The server refuses ("you can't have that address"), common when a laptop moves to another network and asks for its old address. The client starts again from Discover.
- **RELEASE.** The client hands the address back (`ipconfig /release`, and some clean shutdowns). Audit log ID 12.
- **INFORM.** The client already has an IP and only wants settings (DNS etc.).
- **Relay.** Broadcasts don't cross routers, yet companies have a network per floor and only one or two DHCP servers in the data centre. So each network's router or L3 switch runs a **DHCP relay** (`ip helper-address` on Cisco kit) that picks up the broadcast and unicasts it to the server. The relay's address goes in the `giaddr` field so the server knows which network to serve, and option 82 can add switch and port information.
- DHCP inherited its packet format from the older BOOTP, hence field names like `ciaddr` (client's current IP), `yiaddr` ("your" IP, to be assigned), `siaddr`, `giaddr` and `chaddr` (client MAC), and the old Wireshark filter name `bootp`.

## Attacks on DHCP { #dhcp-attacks }

<strong>[Supplement]</strong> DHCP has no authentication at all; clients trust the first answer they hear. Anyone on the same network (the same broadcast domain) can therefore try:

- **Rogue DHCP server.** Answer before the real server and hand out **the attacker's machine as gateway or DNS server**, so the victim's traffic or DNS queries pass through the attacker (man-in-the-middle). As in the home-router example, it also happens by accident. Detection: a `server_addr` in Zeek `dhcp.log` or an option 54 not on the approved server list; clients receiving an unexpected range, gateway or DNS. Prevention: **DHCP snooping** on switches, which only passes Offers/ACKs arriving from the port the real server is on. Windows DHCP servers in Active Directory must be "authorised" in AD to run, but that **does nothing against a rogue server on another OS.**
- **DHCP starvation.** Flood Discovers from changing fake MACs until the server's pool is leased out. Legitimate devices get no address (audit log ID 14, pool exhausted), and a rogue server answers instead. Detection: hundreds of never-seen MACs in a short time, a surge of MACs with the locally administered bit. Prevention: limit MACs per port (port security), rate-limit DHCP.
- **Getting in via IPv6.** Windows has IPv6 enabled by default and waits for DHCPv6 answers. Even on a company network that doesn't use IPv6, an attacker pretending to be a DHCPv6 server can make PCs accept them as **the IPv6 DNS server**. The technique is commonly called mitm6 after the tool, and is followed by NTLM relay to capture credentials ([LLMNR and NTLM relay](../../../adversary/llmnr-ntlm-relay.md)). **IPv4 DHCP logs don't show this attack at all.**
- **Route injection that bypasses VPN (TunnelVision, CVE-2024-3661, disclosed 2024).** DHCP option 121 (classless static routes) can push routes such as "send this range via this gateway". Being more specific than the VPN's routes, they win, so traffic leaves **outside the VPN even while it's connected**. The attacker needs to control or spoof the DHCP server on the same network (café or hotel Wi-Fi, for example). Android, which doesn't implement option 121, wasn't affected; mitigations are the VPN product's kill switch, firewall rules or network isolation features.

## When a SOC uses DHCP logs { #soc-use }

- **Enriching every IP-based alert.** Have the SIEM attach the DHCP lease for the alert time automatically, showing "IP + hostname + MAC". It saves analysts manual lookups and stays correct when IPs are reused later.
- **New-device alerts.** Never-seen MACs, hostnames outside the scheme, deny-listed OUIs, never-seen DHCP servers.
- **Scoping an incident.** You need to know which networks and IPs an infected laptop moved through that day (laptops use several IPs a day) to find every other log recorded under those IPs.
- **Checking retention.** The default audit log overwrites by weekday, so about a week. Incidents are often discovered weeks later, so **SIEM collection is essential.** If DHCP is spread across cloud-managed wireless, firewall-built-in DHCP and branch routers, collect all of them.

## The 2026 view { #trends }

!!! success "[2026 Current] Still valid"
    The four DORA steps, UDP 67/68, the broadcast start, the lease concept, using DHCP logs to link IP to device, finding suspicious devices by hostname, MAC and OUI, and the limit of that (self-reported values) are unchanged. So is the fact that DHCP has no authentication and anyone on the same network can interfere.

!!! info "[Changed] What has changed"
    - **MAC randomisation is now the default.** iOS/iPadOS (from 14) and Android (from 10) use a different random MAC per Wi-Fi network by default, and Apple later added a "rotating" mode that changes it periodically. Windows offers a random hardware address option too. So on wireless networks **many devices can't be identified by OUI, and one phone can look like several devices.** For company devices, use MDM to enforce fixed MACs on the corporate network, and identify devices by authentication (802.1X) results instead.
    - **IP-to-device mapping has moved towards EDR and NAC.** EDR agents report their own IP changes, and NAC and wireless controllers log the authenticated account with MAC and IP. DHCP logs are still needed, but their value has shifted to **finding devices without EDR (IoT, personal devices, attacker kit)**.
    - **Remote and cloud work weakens "an IP inside the company network".** Home laptops use the home router's DHCP and never appear in company DHCP logs; track them through VPN/ZTNA connection records and EDR.
    - **New DHCP attacks keep appearing.** TunnelVision (2024, VPN bypass via option 121) is the prominent one, and IPv6-based man-in-the-middle (DHCPv6, router advertisements) remains a penetration-testing staple.
    - **IPv6 SLAAC devices may not appear in DHCP logs.** On IPv6 networks devices can build their own address from router advertisements (SLAAC), so address-to-device mapping must be supplemented from router and switch neighbour (NDP) tables.

!!! warning "[Caution] Wrong or risky to do the old way"
    - **Don't investigate "the device using that IP now".** Always find the lease at the alert time, and align time zones (server local time vs UTC).
    - **Don't decide "company device or not" from the OUI alone.** Random MACs, cloned MACs and network-chip or dock vendor OUIs are all mixed in. Check the locally administered bit first.
    - **Don't use current DNS lookups (including reverse lookups) instead of historical records.** DNS only shows the present.
    - **Don't assume AD authorisation protects against rogue DHCP servers.** DHCP snooping on switches is the real defence.
    - **Don't declare "no new devices" from IPv4 DHCP logs alone.** IPv6 and statically configured devices (an attacker can just set an IP without DHCP) never appear in DHCP. Compare with ARP, switch MAC tables and NAC records.

## Practice questions { #quiz }

### Question 1

On 18 November at 14:20 (server local time), the IDS alerted on C2 traffic leaving `10.20.30.41`. The next morning an analyst runs `Get-DhcpServerv4Lease` and finds `10.20.30.41` is now used by `WS-HR-0107`, and plans to isolate `WS-HR-0107`. Using the audit log example above, explain why this is risky and give the right order of steps.

??? success "Answer and explanation"
    **Why it's risky:** `Get-DhcpServerv4Lease` shows **only leases that are live now**. IPs are leased, so owners change. In the audit log example, `10.20.30.41` went to `LT-FIN-0412` at 08:52, was renewed at 12:52 and **released at 17:31**. At the alert time of 14:20, `LT-FIN-0412` held it; the next day it passed to `WS-HR-0107`. Isolating the current owner **isolates the wrong PC and misses the infected one.**

    **The right order:**

    1. Find the lease covering the alert time (check time zones: if the IDS logs UTC, convert to server local time) in the audit log or SIEM → `LT-FIN-0412`, MAC `3C5282AA4107`
    2. Confirm the device in the asset inventory and EDR, and identify the user at that time from 4768 on the DC (TGT request, `Client Address`) or 4624 on the PC
    3. Find the IP `LT-FIN-0412` uses now (it may differ) and isolate it, and search logs under the other IPs that device used that day

### Question 2

For each of these two Zeek `dhcp.log` lines, say what is suspicious and what to check. The company's DHCP servers are `10.20.0.5` and `10.20.0.6`, and laptops are named `LT-<dept>-<4 digits>`.

```
ts=2026-11-18T09:14:02Z client_addr=- server_addr=10.20.0.5 mac=da:3f:91:07:c2:5e host_name=LT-FIN-0412 assigned_addr=10.20.40.18 msg_types=DISCOVER,OFFER,REQUEST,ACK
ts=2026-11-18T09:20:11Z client_addr=- server_addr=10.20.44.200 mac=3c:52:82:19:aa:02 host_name=LT-ENG-0233 assigned_addr=10.20.44.150 msg_types=DISCOVER,OFFER,REQUEST,ACK
```

??? success "Answer and explanation"
    **First line:** the name `LT-FIN-0412` fits the scheme, but in the MAC `da:3f:…` the second character is `a` → **a locally administered address** (software-generated). A company laptop normally has no reason to use a random MAC on the corporate wired network, and above all the real `LT-FIN-0412` had MAC `3c:52:82:aa:41:07`. Check: whether the real `LT-FIN-0412` was somewhere else (another IP or port) at the same time — if so, suspect **name cloning** — whether EDR shows the laptop's adapter settings changed, and the physical port from option 82 or switch records.

    **Second line:** name and MAC look ordinary, but **`server_addr=10.20.44.200` is not an approved DHCP server.** Something on that network is acting as a DHCP server (an accidentally connected router, a device with a server role enabled, or an attacker's rogue server). Check: the gateway (option 3) and DNS (option 6) in the ACK — if they point to an attacker's device, it's man-in-the-middle — the MAC and switch port of `10.20.44.200`, and whether other clients on that network got addresses from it. As prevention, review DHCP snooping on that switch.

### Question 3

A colleague says, "we catch every new device with DHCP logs, so nothing has been secretly plugged in." Give at least three reasons this is wrong and suggest what to add.

??? success "Answer and explanation"
    **Why it's wrong:**

    1. **Hostname and MAC are self-reported**, so a device can pose with a scheme-compliant name and the company laptop vendor's OUI (or a cloned real MAC).
    2. **No DHCP, no record.** An attacker can watch the network's range and set a static IP. IPv6 SLAAC addresses may not appear in DHCP logs either.
    3. **MAC randomisation** makes legitimate devices look new each time, flooding "new MAC" alerts and burying the real ones.
    4. (Bonus) The default audit log keeps **only about a week**, and if DHCP runs in several places (wireless controllers, firewalls, branch routers) you may be seeing only part of it.

    **What to add:** **NAC such as 802.1X to authenticate the connection itself**; compare switch MAC tables and ARP records with DHCP to find "devices that appeared without DHCP"; reconcile against the asset inventory and EDR list; detect the same name or MAC appearing twice at once; use DHCP fingerprinting (options 55 and 60) to check that name and OS agree; keep all DHCP sources in the SIEM long term.

---
title: "Kerberos Events — How AS and TGS Work, 4768 TGT Requests, 4769/4770 Service Tickets, and Spotting Kerberos in 4624"
tags:
  - training
  - blue-team
  - windows
  - logging
  - kerberos
  - active-directory
---

# Kerberos Events — 4768, 4769/4770 and Kerberos in 4624 { #kerberos }

!!! abstract "What this page covers"
    The default way a Windows domain proves who you are, and the trail it leaves. Why Kerberos exists and the three parties involved (client, service, and the **Key Distribution Center** on the domain controller, with its **Authentication Service** and **Ticket Granting Service**); the six steps of a Kerberos logon, from the password-derived key to the **ticket-granting ticket (TGT)** to a **service ticket** to the final logon, and what each step writes to which log; **4768** (TGT requested) read field by field, including result codes, ticket options, encryption type and pre-authentication type; the related **4771** and **4772**; **4769** (service ticket requested) and **4770** (renewed) read field by field, including the noisy `0x20` failures; how to tell from a **4624** on the target whether Kerberos or NTLM was used (`AuthenticationPackageName`, `LogonProcessName`, `LmPackageName`, `KeyLength`) and how to tie it back to the DC with the `LogonGuid`; what Kerberoasting, AS-REP roasting, forged tickets and pass-the-ticket look like in these events; how to keep learning important events; SOC checklist, the 2026 view and practice questions.

!!! note "Labels"
    **[Supplement]** = practical material you need to know, **[Correction]** = a commonly repeated claim that is wrong or outdated, **[Changed]**/**[Caution]** = what has changed recently and what is risky to do the old way. Domains, hosts, accounts, SIDs, GUIDs and IPs are invented examples (`corp.example`, documentation and private IPs).

## The 8 key points { #key-points }

1. **Kerberos** is the default authentication protocol in an Active Directory domain. Windows uses it whenever it can (a domain account, a target named by a name the domain knows) and falls back to **NTLM** otherwise.
2. Three parties: the **client** (the user's computer), the **service** (file share, web app, SQL server…), and the **KDC** — which on Windows is every **domain controller**. The KDC runs two services: the **Authentication Service (AS)**, which checks who you are and hands out a **TGT**, and the **Ticket Granting Service (TGS)**, which swaps a TGT for a **service ticket** for one specific service.
3. The log trail of one logon is split across machines: **4768** on the DC (TGT), **4769** on the DC (service ticket, one per service), **4624** on the target server (the actual logon). 4770 (renewal) is rare and looks like a 4769.
4. These DC events come from the *Account Logon* category: *Audit Kerberos Authentication Service* (4768, 4771, 4772) and *Audit Kerberos Service Ticket Operations* (4769, 4770, 4773). They are written **only on domain controllers** — collect them from **every** DC.
5. **4768** answers "which account asked for a TGT, from which IP, and did it work?" `Result Code 0x0` = success; anything else is a failure you can look up (`0x6` unknown user, `0x12` account disabled/locked/expired). A wrong password usually becomes **4771** with `0x18` instead.
6. **4769** adds **which service** (`ServiceName`, e.g. `FS-02$`). Pivot from it to the 4624 on that server a moment later. Ignore the flood of `0x20` failures (expired ticket, harmless).
7. The **encryption type** fields are where many attacks show: `0x12`/`0x11` = AES (normal), `0x17` = RC4 (legacy — and the signature of **Kerberoasting**, T1558.003, when it appears for user-run services). `Pre-Authentication Type 0` on a 4768 = no pre-authentication — the prerequisite for **AS-REP roasting** (T1558.004).
8. On the target, `AuthenticationPackageName` in 4624 says `Kerberos`, `NTLM` or `Negotiate`. Kerberos logons show `LmPackageName` `-` and `KeyLength` `0`; NTLM shows `NTLM V1`/`NTLM V2` and usually `128`. `Negotiate` means "look at the other two fields to see which won".

## Why Kerberos, and why you must read its logs { #why }

Think of a large music festival. You don't show your passport at every stage, bar and tent. You show it **once**, at the main gate; the gate checks it against the guest list and snaps a **wristband** on you. Now, when you want to go into the VIP tent, you show your wristband at a small booth, and the booth gives you a **paper ticket for that one tent**, valid tonight only. The tent bouncer never sees your passport — he only checks that the ticket was printed by the festival's own booth and is meant for his tent.

That is Kerberos:

- the passport is your **password** (or rather a key derived from it),
- the main gate is the **Authentication Service** on the DC,
- the wristband is the **ticket-granting ticket (TGT)**,
- the booth is the **Ticket Granting Service**, also on the DC,
- the paper ticket is the **service ticket**,
- the bouncer is the **service** (the file server, for example).

Back to the technical reality. In a domain, thousands of services need to know who you are. Sending the password (or a hash of it) to each one would expose it everywhere, and every server would need to ask the DC each time. Kerberos solves both problems: your password-derived key is used **once**, against the DC, and from then on you carry tickets that are encrypted with keys only the DC and the right service know. The service can check a ticket **without contacting the DC at all**.

For the SOC, this means the most important "who logged on to what, from where" questions are answered in **two places**: the DC (who asked for which tickets, from which IP) and the target (who actually logged on). Most of the analyst's daily work on identity — a suspicious logon, a compromised account, lateral movement — ends up in these events. And many of the best-known Active Directory attacks (Kerberoasting, AS-REP roasting, golden and silver tickets, pass-the-ticket) are attacks **on Kerberos itself**; you can only spot them if you know what normal Kerberos events look like.

The attacker side is in [Credential dumping and Mimikatz](../endpoint-attacks/credential-dumping-mimikatz.md) and [Lateral movement, collection and exfiltration](../endpoint-attacks/lateral-collection-exfil.md); the logon side in [Login events](logins.md).

## The cast and the props { #cast }

| Who / what | What it is | Where it lives |
| --- | --- | --- |
| **Client** | The device the user sits at, which wants to reach a service | Workstation, e.g. `WS-031` |
| **Service** | What the user ultimately wants: SMB share, IIS site, SQL server, Exchange… Identified by a **service principal name (SPN)** such as `cifs/FS-02.corp.example` | Member server, e.g. `FS-02` |
| **KDC** | Key Distribution Center: knows the long-term key of **every** account in the domain, runs AS and TGS | Every domain controller (`kdc` service, `lsass.exe`) |
| `krbtgt` **account** | A special, disabled account whose key encrypts and signs **every TGT** in the domain. RID **502** | Active Directory |
| **Long-term key** | A key derived from the account's password (for RC4 it is the same as the NT hash; for AES it is derived with the account name as salt). The client and the KDC both have it — the password itself is never sent | Client memory after you type it; AD database on the DC |
| **TGT** | Proof you already authenticated; encrypted with the `krbtgt` key, so only a DC can read it. Default lifetime **10 hours**, renewable up to **7 days** | Client memory (in `lsass.exe`) |
| **Service ticket** | Proof for **one** service; encrypted with **that service account's** key, so only that service (and the DC) can read it | Client memory, then handed to the service |

[Supplement] A service ticket is encrypted with the key of the **account that runs the service**. For most services that is the **computer account** (`FS-02$`), whose password is long and random and changes every 30 days. But when a service runs as a **user account** (for example `svc_sql`) with an SPN registered on it, the ticket is encrypted with a key derived from a human-chosen password. That is the weakness Kerberoasting exploits (see below).

## Kerberos step by step { #steps }

Here is user `j.park` on workstation `WS-031` (`10.20.7.31`) logging on in the morning and then opening `\\FS-02\projects`. The cryptographic details are simplified; the point is what happens and what each step logs.

```text
   WS-031 (client)                   DC-01 (KDC)                     FS-02 (service)
        |                         [AS]        [TGS]                         |
   1    |--- AS-REQ (user, time   -->|                                      |
        |    encrypted with key)     |                                      |
   2    |<-- AS-REP (TGT) -----------|      -> 4768 on DC-01                |
        |                                                                   |
   3    |--- TGS-REQ (TGT + "cifs/FS-02") -->|                              |
   4    |<-- TGS-REP (service ticket) -------|  -> 4769 on DC-01            |
        |                                                                   |
   5    |--- AP-REQ (service ticket) ---------------------------------------->|
   6    |<-- access granted -------------------------------------------------|  -> 4624 on FS-02
```

Line by line:

1. **AS-REQ.** When `j.park` types the password at logon, `WS-031` derives the long-term key and sends the AS a request: "I am `j.park`, give me a TGT". To prove it knows the key, it encrypts the **current timestamp** with it. This proof is called **pre-authentication**. The DC has the same key (from AD), decrypts the timestamp and checks it is within **5 minutes** of its own clock.
2. **AS-REP.** If that works, the AS returns a **TGT** (encrypted with the `krbtgt` key — the client can't read it, just carry it) plus a session key the client can read. The DC writes **4768**. If pre-authentication failed (wrong password) it writes **4771** instead.
3. **TGS-REQ.** Later, `j.park` opens `\\FS-02\projects`. The client sends the TGT to the TGS with the name of the service it wants: `cifs/FS-02.corp.example`.
4. **TGS-REP.** The TGS checks the TGT (only the DC can decrypt it), looks up which account owns that SPN (`FS-02$`), and returns a **service ticket** encrypted with `FS-02$`'s key. The DC writes **4769**. Note: the DC does **not** check whether `j.park` is allowed to read the share — that is the server's job.
5. **AP-REQ.** The client hands the service ticket to `FS-02` inside the SMB session setup.
6. **Access.** `FS-02` decrypts the ticket with its own key, reads who the user is and which groups they are in (the **PAC**, privilege attribute certificate, inside the ticket), and logs them on. `FS-02` writes **4624** (logon type 3, `AuthenticationPackageName` `Kerberos`). Then normal file permissions decide what they can read.

Two things follow from this that matter for investigations:

- **The DC never sees step 5 and 6.** A service ticket used at 09:00 might have been requested at 08:00. And if an attacker **forges** a service ticket (a "silver ticket"), there is no 4769 at all — only the 4624 on the target.
- **The target never sees the password.** That's why the 4624 on `FS-02` can't tell you whether the password was typed correctly 1 minute or 9 hours ago. For that you go back to the 4768 on the DC.

[Supplement] The one-to-one mapping to events: AS exchange → 4768/4771/4772; TGS exchange → 4769/4770/4773; client-server exchange → 4624/4625 on the target (and 4634 on logoff). A TGT is requested at logon (and again when it expires); a service ticket once per service per ticket lifetime — not per file you open.

## Turning on and finding the events { #config }

```text
C:\> auditpol /get /subcategory:"Kerberos Authentication Service","Kerberos Service Ticket Operations"
System audit policy
Category/Subcategory                      Setting
Account Logon
  Kerberos Service Ticket Operations      Success and Failure
  Kerberos Authentication Service         Success and Failure
```

Line by line:

- `auditpol /get` — show the current effective audit policy (run elevated, **on a domain controller**).
- `/subcategory:"...","..."` — only these two subcategories.
- `Account Logon` — the category. "Account logon" means **checking credentials** (done by the DC for domain accounts), as opposed to "Logon/Logoff", which is **creating a session** on the machine being accessed (4624). A common beginner confusion: the 4768 on the DC and the 4624 on the server are two different things happening on two different machines.
- `Kerberos Service Ticket Operations` — produces 4769, 4770, 4773.
- `Kerberos Authentication Service` — produces 4768, 4771, 4772.

On member servers and workstations these subcategories produce nothing, because they aren't KDCs. Default DC policy logs at least successes; confirm failures are on too, since many attack signals are failures. Volume is high: in a 10,000-user domain, 4769 alone can be millions of events a day. Plan storage, but don't filter at collection — filter in queries.

## Event 4768: a Kerberos authentication ticket (TGT) was requested { #4768 }

### A complete event { #4768-sample }

```xml
<System>
  <Provider Name="Microsoft-Windows-Security-Auditing" Guid="{54849625-5478-4994-a5ba-3e3b0328c30d}" />
  <EventID>4768</EventID>
  <Task>14339</Task>
  <Keywords>0x8020000000000000</Keywords>
  <TimeCreated SystemTime="2026-11-20T22:02:11.4417263Z" />
  <Channel>Security</Channel>
  <Computer>DC-01.corp.example</Computer>
</System>
<EventData>
  <Data Name="TargetUserName">j.park</Data>
  <Data Name="TargetDomainName">CORP.EXAMPLE</Data>
  <Data Name="TargetSid">S-1-5-21-1004336348-1177238915-682003330-1187</Data>
  <Data Name="ServiceName">krbtgt</Data>
  <Data Name="ServiceSid">S-1-5-21-1004336348-1177238915-682003330-502</Data>
  <Data Name="TicketOptions">0x40810010</Data>
  <Data Name="Status">0x0</Data>
  <Data Name="TicketEncryptionType">0x12</Data>
  <Data Name="PreAuthType">2</Data>
  <Data Name="IpAddress">::ffff:10.20.7.31</Data>
  <Data Name="IpPort">51544</Data>
  <Data Name="CertIssuerName"></Data>
  <Data Name="CertSerialNumber"></Data>
  <Data Name="CertThumbprint"></Data>
</EventData>
```

The Event Viewer "General" tab shows the same thing as text: *Account Information* (Account Name, Supplied Realm Name, User ID), *Service Information* (Service Name, Service ID), *Network Information* (Client Address, Client Port), *Additional Information* (Ticket Options, Result Code, Ticket Encryption Type, Pre-Authentication Type) and *Certificate Information*. The XML names above are what your SIEM will usually see.

### Field by field { #4768-fields }

- `EventID` `4768`, `Task` `14339` — "A Kerberos authentication ticket (TGT) was requested", subcategory *Kerberos Authentication Service*.
- `Keywords` `0x8020000000000000` — Audit Success. A 4768 with `0x8010000000000000` (Audit Failure) is a failed request; read `Status`.
- `Computer` `DC-01.corp.example` — the **DC that answered**. The user's computer is in `IpAddress`, not here.
- `TargetUserName` `j.park` — "Account Name": the account asking for the TGT. A name ending in `$` (`WS-031$`) is a **computer account**; computers get TGTs too, at boot and periodically, so most 4768s in a domain are computers. Filter them in queries, don't drop them.
- `TargetDomainName` `CORP.EXAMPLE` — "Supplied Realm Name": the Kerberos realm (the DNS domain name in capitals) the client asked for. If a client asks with a typo or the short NetBIOS name you may see `CORP` here — still the same domain.
- `TargetSid` — "User ID": the account's SID. Empty or `S-1-0-0` (NULL SID) on failures where the account doesn't exist.
- `ServiceName` `krbtgt`, `ServiceSid` `...-502` — the "service" being asked for is the **TGT service itself**, and `krbtgt` (RID 502) is the account behind it. In 4768 this is always `krbtgt`; it's how the event says "this was a request for a TGT".
- `TicketOptions` `0x40810010` — a 32-bit set of flags requested by the client, numbered from the **left** (bit 0 = the highest bit). `0x40810010` = bit 1 **forwardable** (`0x40000000`) + bit 8 **renewable** (`0x00800000`) + bit 15 **canonicalize** (`0x00010000`) + bit 27 **renewable-ok** (`0x00000010`). This exact value is what normal Windows clients send — so it's a baseline. An unusual value repeated from one host (for example tools that send `0x50800000`, which adds **proxiable**) is worth a second look, though it's a weak signal on its own.
- `Status` `0x0` — "Result Code". `0x0` = success. Common failures:

| Code | Name | What it usually means |
| --- | --- | --- |
| `0x6` | `KDC_ERR_C_PRINCIPAL_UNKNOWN` | Username doesn't exist. Many of these from one IP = **username guessing / enumeration** (T1087.002 / T1110) |
| `0x12` | `KDC_ERR_CLIENT_REVOKED` | Account disabled, expired or **locked out** — a spray hitting lock-out, or someone using a leaver's account |
| `0x17` | `KDC_ERR_KEY_EXPIRED` | Password expired — usually harmless |
| `0x18` | `KDC_ERR_PREAUTH_FAILED` | Wrong password. Normally logged as **4771**, not 4768 |
| `0x25` | `KRB_AP_ERR_SKEW` | Client clock more than 5 minutes off — a misconfigured device, or a tool on a foreign machine |
| `0xE` | `KDC_ERR_ETYPE_NOSUPP` | No common encryption type — legacy device, or an account with no AES keys under an AES-only policy |

- `TicketEncryptionType` `0x12` — the encryption used **for the issued ticket**. `0x12` = AES256, `0x11` = AES128 (both normal), `0x17` = RC4-HMAC (legacy), `0x1`/`0x3` = DES (should never appear; removed in current Windows), `0xffffffff` = failure (no ticket issued). In a modern domain nearly everything is `0x12`. A user account suddenly getting `0x17` TGTs from a workstation that normally gets `0x12` can mean a tool requested RC4 on purpose — for example "overpass-the-hash", which uses a stolen NT hash (which **is** the RC4 key) to get a TGT (T1550.002).
- `PreAuthType` `2` — how the client proved itself. `2` = **encrypted timestamp** with the password key (the normal password logon). `15`/`16`/`17` = **PKINIT**, certificate-based (smart card, Windows Hello for Business, or a certificate) — then the `Cert*` fields are filled. `0` = **no pre-authentication**: the account has *Do not require Kerberos preauthentication* set, so the DC handed out an encrypted reply to anyone who asked. That's the setting **AS-REP roasting** (T1558.004) hunts for. `-` appears on failures.
- `IpAddress` `::ffff:10.20.7.31` — "Client Address". The `::ffff:` prefix is an **IPv4-mapped IPv6 address**: the DC listens on IPv6 and IPv4 together, so an IPv4 client is written this way. Strip it when you join with other logs. `::1` means the request came from the DC itself.
- `IpPort` `51544` — the client's source port, a random high port; useful only to match a packet capture. `0` is common when the request came from the DC itself.
- `CertIssuerName`, `CertSerialNumber`, `CertThumbprint` — filled only for certificate logons (PKINIT). A certificate logon for a privileged account from a certificate nobody recognises is a classic sign of **AD Certificate Services abuse** (see [AD CS abuse](../../../adversary/adcs-abuse.md)).

### What 4768 is good for { #4768-use }

- **"Which user was on which IP?"** The 4768 of a human account ties the account to the IP at morning logon. If DHCP logs give you the hostname for that IP, you now know which machine they used. That also answers the reverse question: "who was on `10.20.7.31` at 09:00?"
- **Account from an unusual place.** A TGT for `j.park` from a server subnet, a VPN pool they never use, or two different IPs at the same time.
- **Accounts that should never authenticate.** Disabled, leaver, break-glass or honey accounts: keep a list and alert on any 4768 (success or failure).
- **Names that don't follow your naming standard** (`administrator`, `admin`, `test`, `root`, names with spaces) in failed 4768s with `0x6` — someone is guessing.
- **Group and count.** Count by account, by IP, by result code. One IP with hundreds of `0x6` and `0x12` across many names = spraying or enumeration. One account with requests from 20 IPs = possibly shared or stolen credentials.

[Supplement] **4771** "Kerberos pre-authentication failed" is the event for a **wrong password** in Kerberos: `Status` `0x18`, with the account and client IP. It has a `PreAuthType` field too. Many 4771 `0x18` against **many accounts** from one IP, each tried once or twice, is password spraying (T1110.003) — on the DC you see all attempts in one place. **4772** is a rare failure to issue a TGT. NTLM validation by the DC logs **4776** instead. Both are introduced in [Login events](logins.md#4625).

## Event 4769: a Kerberos service ticket was requested { #4769 }

### A complete event { #4769-sample }

A few seconds after the 4768, `j.park` opens the share on `FS-02`:

```xml
<System>
  <EventID>4769</EventID>
  <Task>14337</Task>
  <Keywords>0x8020000000000000</Keywords>
  <TimeCreated SystemTime="2026-11-20T22:02:15.0921884Z" />
  <Channel>Security</Channel>
  <Computer>DC-01.corp.example</Computer>
</System>
<EventData>
  <Data Name="TargetUserName">j.park@CORP.EXAMPLE</Data>
  <Data Name="TargetDomainName">CORP.EXAMPLE</Data>
  <Data Name="ServiceName">FS-02$</Data>
  <Data Name="ServiceSid">S-1-5-21-1004336348-1177238915-682003330-1310</Data>
  <Data Name="TicketOptions">0x40810000</Data>
  <Data Name="TicketEncryptionType">0x12</Data>
  <Data Name="IpAddress">::ffff:10.20.7.31</Data>
  <Data Name="IpPort">51551</Data>
  <Data Name="Status">0x0</Data>
  <Data Name="LogonGuid">{6c3e9f12-08ab-4d7e-b1d4-2f7a90c5e811}</Data>
  <Data Name="TransmittedServices">-</Data>
</EventData>
```

### Field by field { #4769-fields }

- `EventID` `4769`, `Task` `14337` — "A Kerberos service ticket was requested", subcategory *Kerberos Service Ticket Operations*.
- `Computer` — again, the DC that issued the ticket.
- `TargetUserName` `j.park@CORP.EXAMPLE` — the account the ticket is **for**, written in `user@REALM` form (unlike 4768). Computer accounts look like `WS-031$@CORP.EXAMPLE`.
- `TargetDomainName` — the realm.
- `ServiceName` `FS-02$` — the **account that owns the requested service**. Here it's the computer account of the file server, so the user was going to `FS-02` (SMB, or any other service running as the computer). Microsoft documents this field as optional, so it can occasionally be empty; `ServiceSid` is the reliable one. Three patterns to recognise:
    - ends in `$` → a computer (most common, normal);
    - `krbtgt` → the client is using its TGT to get a **TGT renewal** or a referral, normal;
    - a **user account** like `svc_sql` → a service running under a user account. Normal in itself, but these are the Kerberoasting targets.
- `ServiceSid` — the SID of that account. Event Viewer turns it into a name like `CORP\FS-02$` when it can.
- `TicketOptions` `0x40810000` — forwardable, renewable, canonicalize: the normal Windows value for service tickets. (`0x60810010` would add **forwarded** and renewable-ok; you'll see it when a ticket was requested with a forwarded TGT, for example through delegation.)
- `TicketEncryptionType` `0x12` — the encryption of **the service ticket**, which depends on what the **service account** supports. Same code table as 4768. **`0x17` (RC4) for a user service account is the key Kerberoasting signal** (see below).
- `IpAddress` / `IpPort` — the client. Same `::ffff:` rule.
- `Status` `0x0` — "Failure Code". `0x0` success. `0x20` (`KRB_AP_ERR_TKT_EXPIRED`) means the TGT presented had expired; Windows clients then fetch a fresh one. Microsoft itself notes these show up in large numbers and have essentially no security value — filter them out of dashboards. Other useful ones: `0x7` (`KDC_ERR_S_PRINCIPAL_UNKNOWN`, the SPN doesn't exist — typos, stale config, or someone **scanning for SPNs**), `0x1F` (integrity check failed — a damaged or **tampered ticket**), `0xE` (no common encryption type).
- `LogonGuid` `{6c3e9f12-...}` — a GUID that also appears as `LogonGuid` in the **4624 on the target**. This is how you join the DC's view and the server's view exactly, instead of guessing by time and IP.
- `TransmittedServices` `-` — "Transited Services": filled only when **delegation** (S4U / constrained delegation) is used, listing the services that requested on the user's behalf. Unexpected values here (a web server asking for tickets to the DC on behalf of admins) deserve a look.

### Reading it as a sentence { #4769-read }

"At 22:02:15 UTC, user `j.park` from `10.20.7.31` asked `DC-01` for a ticket to a service run by `FS-02$`, got it (`0x0`), and the ticket is AES256-encrypted." Next pivot: on `FS-02`, a 4624 with `TargetUserName` `j.park`, `IpAddress` `10.20.7.31`, logon type 3, `AuthenticationPackageName` `Kerberos`, and the same `LogonGuid` — within seconds.

### Event 4770: a Kerberos service ticket was renewed { #4770 }

**4770** is written when a client renews a ticket whose *renewable* flag is set, instead of asking for a new one. It carries almost the same fields as 4769 (account, service, ticket options, encryption type, client address) without a status code, so analyse it the same way. In practice it is rare compared to 4769, and many renewals concern the TGT itself (`ServiceName` `krbtgt`). **4773** is a failed service-ticket request in older documentation; on current systems failures are 4769 with Audit Failure.

### What 4769 is good for { #4769-use }

- **Lateral movement map.** "Which servers did this account get tickets for?" Group 4769 by `TargetUserName` → list of `ServiceName`. A help desk account suddenly getting tickets for `DC-01$`, `BACKUP-01$` and twenty servers in ten minutes is exploring or spreading.
- **Rare service for this user.** First-ever ticket to a sensitive server (domain controllers, backup, hypervisor management, PKI) for an account.
- **Volume.** One account asking for tickets to **many different services in a short time** — especially user-account services with RC4 — is the shape of Kerberoasting.
- **Anomalies in the extra fields.** Unusual ticket options, unexpected `TransmittedServices`, RC4 where AES is normal, failures with `0x1F`.

## Spotting Kerberos in 4624 on the target { #4624-kerberos }

Not every logon uses Kerberos. If the client connects by **IP address** instead of a name (`\\10.20.5.12\share`), if the account is **local** to the target, if the DC can't be reached, or if a tool **forces NTLM** (for example pass-the-hash), Windows uses NTLM. The 4624 on the target tells you which one was used. Two 4624s on `FS-02` for the same user, side by side:

```xml
<!-- Logon A -->
<Data Name="TargetUserName">j.park</Data>
<Data Name="TargetDomainName">CORP</Data>
<Data Name="LogonType">3</Data>
<Data Name="LogonProcessName">Kerberos</Data>
<Data Name="AuthenticationPackageName">Kerberos</Data>
<Data Name="WorkstationName">-</Data>
<Data Name="LogonGuid">{6C3E9F12-08AB-4D7E-B1D4-2F7A90C5E811}</Data>
<Data Name="LmPackageName">-</Data>
<Data Name="KeyLength">0</Data>
<Data Name="IpAddress">10.20.7.31</Data>

<!-- Logon B -->
<Data Name="TargetUserName">j.park</Data>
<Data Name="TargetDomainName">CORP</Data>
<Data Name="LogonType">3</Data>
<Data Name="LogonProcessName">NtLmSsp</Data>
<Data Name="AuthenticationPackageName">NTLM</Data>
<Data Name="WorkstationName">WS-118</Data>
<Data Name="LogonGuid">{00000000-0000-0000-0000-000000000000}</Data>
<Data Name="LmPackageName">NTLM V2</Data>
<Data Name="KeyLength">128</Data>
<Data Name="IpAddress">10.20.7.118</Data>
```

Line by line, comparing A and B:

- `LogonType` `3` in both — network logon, as for any share access.
- `LogonProcessName` — `Kerberos` in A, `NtLmSsp` (the NTLM security support provider) in B.
- `AuthenticationPackageName` — the direct answer: `Kerberos` vs `NTLM`.
- `WorkstationName` — `-` in A: Kerberos doesn't send a workstation name. NTLM does, so B shows `WS-118` — but that name is supplied by the client and can be anything; trust `IpAddress` more.
- `LogonGuid` — a real GUID in A that **matches the `LogonGuid` of the 4769** on the DC (case aside). All zeros in B: NTLM has no ticket, so nothing to match.
- `LmPackageName` — `-` in A: there's no NTLM version for Kerberos, so this field is **never filled** for Kerberos. In B, `NTLM V2` (normal for NTLM). `NTLM V1` or `LM` would be a weakness worth reporting: those are legacy protocols that are easy to crack or relay and shouldn't be in use anywhere.
- `KeyLength` — `0` in A: the field is about the NTLM session key, so it is **always 0 for Kerberos**. `128` in B, normal for NTLMv2. Caution: `0` is **also** possible for NTLM (for example anonymous logons or when no session key is negotiated), so `KeyLength 0` alone doesn't prove Kerberos — combine it with `LmPackageName`.

And when the package says **`Negotiate`**? That's typical for interactive and RDP logons (types 2, 10, 11), where the logon process (`User32`, `Advapi`) asks the Negotiate package to **pick** Kerberos if possible, NTLM otherwise. Then:

| `AuthenticationPackageName` | `LmPackageName` | `KeyLength` | Conclusion |
| --- | --- | --- | --- |
| `Kerberos` | `-` | `0` | Kerberos |
| `NTLM` | `NTLM V2` / `NTLM V1` / `LM` | usually `128` (can be `0`) | NTLM (version as named) |
| `Negotiate` | `-` | `0` | Kerberos won the negotiation |
| `Negotiate` | `NTLM V2` etc. | `128` | NTLM won |

**Logon B is the suspicious one** in a domain where Kerberos should work: the same user, NTLM, from a different machine (`10.20.7.118`) than their usual one. That's the shape of **pass-the-hash** (T1550.002): an attacker with the NT hash can only use NTLM, because a hash is not a ticket. It isn't proof — some apps and IP-based connections use NTLM legitimately — but it's a good hunting pivot. More in [Login events](logins.md#4624-fields) and [Pass-the-Hash](../../../adversary/pass-the-hash.md).

[Supplement] If you join 4769 (DC) and 4624 (target) by `LogonGuid`, you can find **4624 Kerberos logons with no matching 4769**. Since a real service ticket always comes from a DC, a Kerberos logon whose ticket no DC remembers issuing may be a **forged service ticket** ("silver ticket", T1558.002). Caveats: tickets can be used long after being issued, logs roll over, and you need 4769 from **every** DC. Treat it as a hunting lead, not an alert.

## Attacks you'll see in these events { #attacks }

This is the level a defender needs: what the attack is, why it works, and what it leaves. Not how to run it.

| Technique (ATT&CK) | What the attacker does | Where it shows |
| --- | --- | --- |
| **Kerberoasting** (T1558.003) | Any domain user asks for service tickets for services that run as **user accounts**, takes them away and guesses the service account's password offline. Asking for a ticket is normal, so it can't be blocked — only spotted | **4769**: one account, many different user-account `ServiceName`s in minutes, often `TicketEncryptionType` **`0x17`** (RC4 is much faster to crack, so tools ask for it) |
| **AS-REP roasting** (T1558.004) | For accounts with pre-authentication disabled, anyone can request an AS-REP and crack part of it offline | **4768** with `PreAuthType` **`0`**, often `0x17`, from a host that's not the account's own. Better still: find and fix those accounts (`userAccountControl` flag `DONT_REQ_PREAUTH`) |
| **Password spraying** (T1110.003) | A few common passwords against many accounts | Many **4771** `0x18` and **4768** `0x6`/`0x12` from one IP across many accounts |
| **Overpass-the-hash** (T1550.002) | Uses a stolen NT hash as the RC4 key to get a real TGT | **4768** with `0x17` for an account that normally gets `0x12`, from an unusual IP |
| **Pass-the-ticket** (T1550.003) | Steals a ticket from one machine's memory and uses it on another | 4769/4624 for the account from an IP that never got a 4768 for it |
| **Golden ticket** (T1558.001) | With the `krbtgt` key (from a DC compromise or DCSync), forges TGTs for anyone with any groups | **4769** for an account **without** a preceding 4768, odd lifetimes, account names that don't exist or don't match their SID; the real fix is rotating `krbtgt` twice |
| **Silver ticket** (T1558.002) | With a service account's key, forges service tickets for that one service | **4624** Kerberos on the target with **no 4769** on any DC |

Detailed walk-throughs: [Kerberoasting](../../../adversary/kerberoasting.md), [AS-REP roasting](../../../adversary/asrep-roasting.md), [Golden and Silver tickets](../../../adversary/golden-silver-tickets.md), [DCSync](../../../adversary/dcsync.md).

[Correction] "Kerberoasting needs admin rights." It doesn't. **Any authenticated domain user** can request a service ticket for any SPN — that's how Kerberos is meant to work. The defence is long random passwords (or group-managed service accounts, gMSA) on service accounts, AES-only encryption, and detection on the 4769 pattern.

## Quick hunting with PowerShell { #hunting }

On a DC, list service tickets issued with RC4 in the last day, excluding computer accounts and `krbtgt`:

```powershell
Get-WinEvent -FilterHashtable @{ LogName='Security'; Id=4769; StartTime=(Get-Date).AddDays(-1) } |
  ForEach-Object { $x = [xml]$_.ToXml(); $d = @{}
    $x.Event.EventData.Data | ForEach-Object { $d[$_.Name] = $_.'#text' }
    [pscustomobject]@{ Time=$_.TimeCreated; User=$d.TargetUserName; Service=$d.ServiceName
                       Enc=$d.TicketEncryptionType; Status=$d.Status; From=$d.IpAddress } } |
  Where-Object { $_.Enc -eq '0x17' -and $_.Service -notlike '*$' -and $_.Service -ne 'krbtgt' -and $_.Status -eq '0x0' } |
  Group-Object User | Sort-Object Count -Descending | Select-Object Count, Name
```

Line by line:

- `Get-WinEvent -FilterHashtable @{ ... }` — read the Security log, filtered inside the event log service: only ID 4769 from the last 24 hours.
- `ForEach-Object { $x = [xml]$_.ToXml(); $d = @{}` — for each event, turn it into XML and prepare an empty table `$d`.
- `$x.Event.EventData.Data | ForEach-Object { $d[$_.Name] = $_.'#text' }` — copy every `<Data Name="...">value</Data>` into `$d`, so we can write `$d.ServiceName` instead of counting positions.
- `[pscustomobject]@{ ... }` — build one tidy row with the fields we care about.
- `Where-Object { ... }` — keep only rows with RC4 (`0x17`), a service name **not** ending in `$` (not a computer), not `krbtgt`, and successful.
- `Group-Object User | Sort-Object Count -Descending` — count per requesting user, biggest first.
- `Select-Object Count, Name` — show just the count and the user.

What the output looks like:

```text
Count Name
----- ----
   23 a.lim@CORP.EXAMPLE
    2 backup.agent@CORP.EXAMPLE
    1 j.park@CORP.EXAMPLE
```

`a.lim` received 23 RC4 tickets for user-account services in a day — far more than anyone else. Next: list **which** services (`$_.Group | Select Service, From` for that user), check the source IP, and ask whether `a.lim` has any reason to touch those services. In a SIEM, the same logic becomes a scheduled search with a threshold and a baseline per user. On a busy DC this script is slow — it's for a quick look, not for production detection.

## Keep learning important events { #keep-learning }

This section covered the events that come up most often, but there are hundreds more, and no shortcut to knowing them. What works:

1. **Understand the attack first.** Read red team write-ups, threat reports and ATT&CK technique pages to know **what** attackers do and **in what order**.
2. **Then map each action to its trace.** For each technique ask: which audit subcategory would record it, on which machine, with which event ID and fields? The [Windows Event IDs](../../../basics/windows-event-ids.md) page and Microsoft's per-event documentation are good references, as are public community cheat sheets and encyclopedias of Windows security events and government guidance on which events to collect.
3. **Reproduce it in a lab.** Run the technique against a test domain with full auditing and Sysmon on, and look at what appears. Your own lab events teach more than any table, and you'll learn which fields are filled in **your** Windows version.
4. **Keep it current.** New Windows versions add fields and events (the Kerberos encryption changes below are an example) and new techniques appear every year. Schedule regular time for it.

## Putting it to work in a SOC { #soc-use }

- **Collect** 4768, 4769, 4770, 4771, 4772, 4776 (and the System log `Kdcsvc` events) from **every** domain controller; 4624/4625 from every server and workstation. Check `auditpol` on the DCs for success **and** failure.
- **Baseline** encryption types: in a healthy 2026 domain, nearly all tickets are `0x12`. Keep a list of the few systems that still need RC4, and treat everything else as an exception to investigate.
- **Alert, high confidence:** 4768 or 4769 for disabled, leaver or honey accounts; 4768 with `PreAuthType 0` (then fix the account); one account requesting RC4 tickets for many user-account services (Kerberoasting); `0x1F` failures; certificate logons (`PreAuthType` 16/17) for admin accounts from unknown certificates; any `0x1`/`0x3` (DES).
- **Hunt, then tune:** `0x6`/`0x12`/`0x18` failures by source IP (spraying and enumeration); 4769 to DCs and other tier-0 servers by non-admin accounts; NTLM 4624 where Kerberos is expected; Kerberos 4624 without a 4769 (silver tickets); 4769 without a 4768 for the account from that IP (golden ticket / pass-the-ticket).
- **Filter in queries, not at collection:** computer accounts (`$`), `0x20` failures, `krbtgt` renewals.
- **Join** DC and target with `LogonGuid`, and IP to host with DHCP/DNS logs. Remember the `::ffff:` prefix and that DC event times are UTC in XML.

## The 2026 view { #trends }

!!! success "[2026 Current] Still valid as is"
    Kerberos is still the default authentication protocol for Active Directory, and 4768, 4769, 4770 and 4771 still have the same meaning and core fields on Windows Server 2025. Reading the account, client IP, service, result code, encryption type and pre-authentication type is exactly how analysts work today. Telling Kerberos from NTLM in 4624 with `AuthenticationPackageName`, `LmPackageName` and `KeyLength` still works. Kerberoasting, AS-REP roasting, golden/silver tickets and pass-the-ticket remain common in real intrusions, and the event patterns above remain the classic way to catch them.

!!! info "[Changed] What has changed"
    - **RC4 is being turned off.** After announcing the move "beyond RC4" in December 2025, Microsoft started a phased change with the January 2026 updates (CVE-2026-20833): an audit phase that writes new `Kdcsvc` events (IDs **201–209** in the DC's **System** log) when RC4 would be used by default, then an enforcement phase in which DCs assume **AES-only** for accounts that don't explicitly allow RC4 (rolling out from April 2026, with the manual rollback option removed in the July 2026 updates). In a patched domain, `0x17` tickets should become rare — which makes every remaining one more meaningful. Check your DCs' System log for those events before assuming RC4 is gone.
    - **More fields in 4768/4769.** Recent updates for Windows Server 2019, 2022 and 2025 added encryption detail to these events (such as the account's supported encryption types, which keys exist, and the session encryption type) to help find RC4 dependencies. Field names and layout vary by build; check a real event from your DCs before writing parsers.
    - **DES** is no longer supported in current Windows Server and Windows 11 Kerberos; any DES ticket type is now a misconfiguration or an attack.
    - **NTLM is on its way out** (NTLMv1 removed in Windows 11 24H2 / Server 2025, a staged plan to disable NTLM by default), so NTLM 4624s in a domain are increasingly the exception you should explain.
    - **Identity moved partly to the cloud.** In hybrid environments much authentication happens in Microsoft Entra ID (sign-in logs, not 4768), and Windows Hello for Business and Entra Kerberos change what TGT requests look like (more certificate/PKINIT and cloud-issued tickets). Identity-focused tools such as Microsoft Defender for Identity read these same DC events and network traffic to detect the attacks in this page automatically — but you still need to read the raw events to verify an alert.

!!! warning "[Caution] Wrong or risky if done the old way"
    - **Don't collect from one DC.** Each DC logs only the tickets it issued; a client can go to any of them.
    - **Don't drop `$` accounts at collection.** Filter them in queries; computer-account tickets matter in some attacks (for example relay and delegation abuse).
    - **Don't treat `KeyLength 0` alone as proof of Kerberos.** Combine it with `AuthenticationPackageName` and `LmPackageName`.
    - **Don't alert on 4769 `0x20`.** It's expired-ticket noise.
    - **Don't assume a successful Kerberos logon means a legitimate one.** Forged and stolen tickets produce perfectly normal-looking 4624s; the evidence is in what's **missing** or **inconsistent** on the DC side.
    - **Don't keep allowing RC4 "just in case".** Find the systems that need it (the new `Kdcsvc` events and 4768/4769 fields help), fix them, and let enforcement happen.

## Practice questions { #quiz }

### Question 1

On `DC-02` you see, within four minutes, 31 successful **4769** events where `TargetUserName` = `m.cho@CORP.EXAMPLE`, `IpAddress` = `::ffff:10.20.9.44`, `TicketEncryptionType` = `0x17`, and `ServiceName` is a different value each time: `svc_sql`, `svc_backup`, `svc_iis`, `svc_report`… `m.cho` is in the finance team. What is likely happening, why does the encryption type matter, and what do you do?

??? success "Answer and explanation"
    This is the shape of **Kerberoasting** (T1558.003). `m.cho` (or something using `m.cho`'s session on `10.20.9.44`) asked for service tickets for **many services that run as user accounts** (no `$` at the end) in a few minutes. Each ticket is encrypted with a key derived from that service account's password, so it can be taken away and cracked offline. A finance user has no reason to access 31 back-end services, let alone in four minutes.

    `0x17` (RC4) matters because RC4 tickets are far faster to crack than AES, so attack tools ask for RC4 on purpose. In a domain that normally issues `0x12`, a burst of RC4 tickets for user-account services is a strong signal. **Next:** identify the process on `10.20.9.44` (4688/Sysmon/EDR around that time), isolate the host if it's confirmed, reset the passwords of **every service account** in the list to long random values (or move them to gMSA), check those accounts for logons from unusual places afterwards, and make those services AES-only. Also check `DC-01` and the other DCs — the same activity may be split across them.

### Question 2

On server `APP-07` there are two 4624 type 3 logons for `CORP\svc_deploy`. Logon 1: `AuthenticationPackageName` `Negotiate`, `LmPackageName` `-`, `KeyLength` `0`. Logon 2: `AuthenticationPackageName` `NTLM`, `LmPackageName` `NTLM V1`, `KeyLength` `0`, `WorkstationName` `BUILD01`, `IpAddress` `10.20.30.77`. Which protocol did each logon use, and what is worth reporting?

??? success "Answer and explanation"
    **Logon 1 = Kerberos.** The package is `Negotiate`, so you look at the other fields: `LmPackageName` `-` (no NTLM version) and `KeyLength` `0` both point to Kerberos winning the negotiation. You could confirm by finding a 4769 on a DC with the same `LogonGuid`.

    **Logon 2 = NTLM, version 1.** `AuthenticationPackageName` says `NTLM` directly. `KeyLength` `0` doesn't mean Kerberos here — it shows no NTLM session key was established, which is possible with NTLM — that's exactly why you don't use `KeyLength` alone. **Worth reporting:** `NTLM V1` is a legacy, weak protocol (easy to crack and relay) that shouldn't be used anywhere, and current Windows has removed it. Find what on `10.20.30.77` (don't trust the `BUILD01` name — the client supplied it) is still using NTLMv1, fix or isolate it, and check whether it's legitimate at all: a service account logging on with NTLMv1 from an unexpected host may also be a downgrade attempt to capture a crackable response.

### Question 3

On `DC-01` you find a successful **4768** for `old.admin` (an account HR says belongs to someone who left last year) with `PreAuthType` `0`, `TicketEncryptionType` `0x17`, `IpAddress` `::ffff:192.0.2.80` — an address outside your internal ranges, coming in through a misconfigured VPN pool. There's no 4771 or any other failure before it. Explain each detail, and say what the attacker gained.

??? success "Answer and explanation"
    - **The account should not exist or be enabled** — a leaver's account that still works is a gift to attackers, and any 4768 for it should alert on its own.
    - **`PreAuthType 0`** means the account has *Do not require Kerberos preauthentication* set, so the DC answered **without any proof** of the password. That explains why there are no failures: nothing was checked. This is the **AS-REP roasting** pattern (T1558.004): the reply contains data encrypted with the account's password key, which the requester can crack offline.
    - **`0x17` (RC4)** — the requester asked for RC4, the fastest to crack. A modern Windows client would use AES.
    - **`192.0.2.80`** — not one of your workstations: someone outside your normal client population is querying the DC directly.

    **What the attacker gained:** not yet a working logon — they got an encrypted blob that they can try to crack offline, and if `old.admin`'s password was weak, they'll soon have it. **Next:** disable `old.admin` now, reset its password, clear the `DONT_REQ_PREAUTH` flag on it **and search for every other account with that flag**, block or fix the VPN pool, look for any later 4768/4769/4624 for `old.admin` (with pre-auth 2, meaning they cracked it), and review what that account had access to.

## Related { #related }

- [Important Events](index.md) — this section's overview
- [Login events](logins.md) — 4624/4625 fields, logon types, 4771/4776 on the DC
- [Account, Defender and PowerShell events](accounts-defender-powershell.md) — account changes an attacker makes after getting credentials
- [Credential dumping and Mimikatz](../endpoint-attacks/credential-dumping-mimikatz.md) — where stolen hashes and tickets come from
- [Lateral movement, collection and exfiltration](../endpoint-attacks/lateral-collection-exfil.md) — what attackers do with them
- [Windows event structure and channels](../windows-logging/event-structure-channels.md) — reading XML and the Security channel
- [Kerberoasting](../../../adversary/kerberoasting.md), [AS-REP roasting](../../../adversary/asrep-roasting.md), [Golden and Silver tickets](../../../adversary/golden-silver-tickets.md), [Pass-the-Hash](../../../adversary/pass-the-hash.md), [AD CS abuse](../../../adversary/adcs-abuse.md)
- [Windows Event IDs](../../../basics/windows-event-ids.md)

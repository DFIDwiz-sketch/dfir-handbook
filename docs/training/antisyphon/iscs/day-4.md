---
title: "Day 4 — Responder, Internet Allow Listing and Vulnerability Management (in progress)"
tags:
  - training
  - antisyphon
  - ntlm-relay
  - internet-allowlisting
  - vulnerability-management
---

# Day 4 — Responder, Internet Allow Listing and Vulnerability Management

<div class="dfir-meta" markdown>
**Course:** Information Security Core Skills · **Instructor:** John Strand (BHIS) · **Day 4 so far:** Responder lab walkthrough → NTLM cracking, relay and signing → internet allow listing → vulnerability management → Nessus report lab
</div>

!!! abstract "Day 4 at a glance (parts 1–2)"
    Day 4 opens with the **Responder lab** set up on Day 3. An attacker on the same network redirects traffic, captures the **NTLMv2 challenge/response**, then cracks it offline or **relays** it — hence host-to-host blocking, disabling LLMNR and **SMB signing**. Next, exploiting the attacker habit of **using brand-new domains briefly and burning them**: simply **blocking "Uncategorized"** in your web filter gives you de-facto **internet allow listing**. Finally, **vulnerability management** in the AI era — bump CVSS up a level, don't ignore lows and informationals, and **group by vulnerability rather than by host** — plus the **Nessus report lab**.

!!! info "This page is in progress"
    **Parts 1–2** are written up. Parts 3–4 (web application security and the ZAP lab, AD hardening and the Ping Castle lab, wrap-up) will follow.

!!! note "Conventions"
    **💡 Note (added)** = my own addition beyond the lecture. **(reconstructed)** = something the instructor only described or showed on screen, written out generically. Answers to questions that came up while studying are collected as **"Deep dive"** sub-sections. Labs that use offensive tooling are summarised by what they demonstrate and the defensive / detection takeaways.

---

## 1. Responder lab walkthrough { #responder-lab }

### Why Ubuntu instead of Kali { #why-ubuntu }

In most classes Kali is used for Metasploit, Nmap and password cracking. Upcoming labs involve **Docker containers** and **honeypot technologies**, so the environment moved to Ubuntu, where more tools install easily. The new environment also shows the **Linux IP at the top of the screen**, so no more running `ifconfig` again and again.

### Poisoning doesn't work in the cloud — so the lab emulates it { #cloud-limitation }

Responder starts poisoners for **LLMNR, NBT-NS and mDNS** (Day 1 — Windows shouting "who has this name?" to the network when DNS fails). These **don't work in AWS**, which isolates **Layer 2** between VMs, so the lab has Windows **browse straight to the Linux box** instead.

> If you're on a network with an adversary, all they've got to do is **reroute your traffic** — and that's easy with ARP cache poisoning or LLMNR.

Responder's servers — **HTTP, HTTPS, SMB, Kerberos** and more — are all primed to steal credentials (**WPAD** is off for this lab).

> **Segmentation would stop an attack like this** — but we very rarely see organisations with that segmentation.

### The capture { #capture }

Type `\\<Linux IP>` into Windows File Explorer and hit Enter — Responder immediately captures the **administrator** authentication. If the user re-types credentials, you get them again. What you see is **NTLMv2**:

- **username**
- **challenge** — a random value from the server
- **response** — computed from the password hash and the challenge

> The challenge is sent in the clear and the response is sent in the clear, which kind of defeats the purpose. If we intercept that traffic on the same network, we can **crack** it.

!!! note "💡 Note (added) — a little more precisely"
    The lecture said "16-byte challenge" and "reverse the authentication." In NTLMv2 the **server challenge is 8 bytes**, and the response is an HMAC-MD5 keyed with the NT hash — it can't be reversed. The attacker instead **tries candidate passwords offline against the captured challenge/response** until one reproduces it. So Day 1's conclusion holds: **weak passwords fall, long strong ones survive**.

### Cracking — Hashcat mode 5600 { #hashcat-5600 }

In the password-cracking directory, edit the lab file so its **IP matches the captured value** (it differs per environment), then run Hashcat with **mode 5600** — **NetNTLMv2**. It's slow to start inside nested virtualisation, but the output shows the **admin account, the challenge, the hash within it, and the cracked password** at the end. The other passwords aren't in the wordlist, so John stops there.

| Hashcat mode | Value | Where it comes from |
|---|---|---|
| **`-m 0`** | MD5 | web databases, etc. |
| **`-m 1000`** | NT hash | SAM, NTDS.dit, LSASS memory — used for Pass-the-Hash |
| **`-m 5600`** | NetNTLMv2 | a challenge/response captured on the wire — what Responder catches |

The same "Windows password" needs a different mode **depending on where the value came from**.

### Relay instead of crack — ntlmrelayx { #ntlmrelayx }

**ntlmrelayx** doesn't crack the captured authentication — it **relays it to other systems** and authenticates there. The takeaway mirrors Day 3:

> That's why **these firewalls are important.** We don't want **host-to-host communication** on a network where somebody can just jump right over.

**Would Sysmon catch this?**

> Sysmon wouldn't see the cracking — that happens on the attacker's machine. It would see **the network connection from the victim back to the attacker**, and not much else.

!!! note "💡 Note (added) — watching from the network side"
    - **LLMNR (UDP 5355) / NBT-NS (UDP 137) responses** coming from an ordinary **workstation IP** rather than a DNS server
    - A workstation attempting **SMB (445) authentication to another workstation or an unfamiliar IP** (Zeek `smb_mapping.log`, `ntlm.log`)
    - On the victim, Sysmon **3** (network connection) from the `System` process to port 445 on an unexpected internal IP

    Defences: **disable LLMNR / NBT-NS**, **require SMB signing** (stops relay), **block workstation-to-workstation traffic**, and **block outbound SMB 445** to the internet. More: [LLMNR & NTLM relay](../../../adversary/llmnr-ntlm-relay.md)

### Deep dive ① What can be done with a captured value — crack vs relay vs Pass-the-Hash { #deep-dive-relay }

*An added explanation, not from the lecture.*

NTLM is a question-and-answer scheme. The server sends a random **question (challenge)**; the client uses its **NT hash as the key** to compute an **answer (response)**.

- The **NT hash** is a **fixed key** derived from the password. Whoever holds it can answer **any** challenge — log in any time, to any server, repeatedly → **Pass-the-Hash**.
- A **NetNTLMv2** value is a **one-time answer to one specific challenge**. Next time the server asks a **different question**, so a recorded answer is useless → no reuse, **offline cracking only**.
- **Relay** doesn't store anything for later — the attacker **sits between victim and real server and forwards question and answer in real time**.

```text
Victim PC              Attacker (ntlmrelayx)           Real server (e.g. file server)
    │                         │                                │
    │── ① I want to auth ───▶│                                │
    │                         │── ② I want to auth (as victim) ─▶│
    │                         │◀──────── ③ challenge ───────────│
    │◀── ④ same challenge ───│                                │
    │  (victim computes the answer with its NT hash)           │
    │── ⑤ response ─────────▶│                                │
    │                         │──────── ⑥ same response ──────▶│
    │                         │◀──── ⑦ authenticated! ─────────│
                    (the attacker now has a session as the victim)
```

Because the real server's challenge is passed to the victim, the victim answers **exactly that challenge** — the answer the server is waiting for. The attacker gets a session as the victim **without knowing the password or the NT hash**, which is why relay works **however strong the password is**.

| | What the attacker holds | What they can do |
|---|---|---|
| **Pass-the-Hash** | NT hash (fixed key) | log in any time, to any server, repeatedly |
| **Captured NetNTLMv2** | a one-time answer | no reuse → offline cracking only |
| **NTLM relay** | nothing stored (live forwarding) | log in elsewhere **only at the moment** the victim authenticates |

**Relay constraints:** ① it must be **live**; ② the victim account needs **rights on the target** for it to matter; ③ reflecting back to the same host is blocked by long-standing patches.

**In the logs (DFIR view):** a successful relay leaves **4624** (successful logon) on the **target**, logon type **3** (network), auth package **NTLM**. The tell is that **account and source don't match** — the account is the victim (e.g. `CORP\alice`) but `IpAddress` is the **attacker's host**, and `WorkstationName` doesn't match that IP.

### Deep dive ② How SMB signing stops relay { #deep-dive-smb-signing }

*An added explanation, not from the lecture.*

Think of a **bank counter**:

- **Relay = passing someone else's ID check.** The attacker forwards the teller's questions to the real customer and the customer's answers back, and **passes the counter as the customer**.
- **SMB signing = requiring the customer's personal seal on every withdrawal slip after that.** Every request after logon (open a file, run a command …) must carry **a seal only the real user can produce**.
- **The attacker has no seal.** Authentication succeeds, but **the very first request is rejected**. They got to the counter but can't get anything done.

**Watch out: it must be "required," not just "enabled."**

- **Enabled:** "you may seal or not." → the attacker says "no seal, thanks" and it's accepted → **doesn't stop relay**
- **Required:** "no seal, no service." → **stops relay**

Recent Windows (Windows 11 24H2, Windows Server 2025) is moving to **SMB signing required by default**, but older versions or modified configurations may still not require it — check your actual settings.

### Deep dive ③ Does signing require the NT hash? { #deep-dive-signing-key }

*An added explanation, not from the lecture.*

**With NTLM logons, effectively yes.** (What's commonly called the "NTLM hash" is properly the **NT hash**.)

1. While answering the challenge, the client also
2. mixes the **NT hash with values from this challenge/response** to derive a **session key** for this conversation only.
3. Signatures are made with that **session key**, which itself is **never sent over the network**.

**So how does the file server know it?** It doesn't have users' NT hashes, so it **asks the domain controller**. The DC validates the answer, derives the session key and passes it to the file server over the **Netlogon secure channel**. Only the **client, the DC and the file server** know the key — the forwarding attacker doesn't. (With **Kerberos**, signing uses the **session key inside the Kerberos ticket** instead of the NT hash — same principle.)

**The key consequence — if the attacker already has the hash, it's different.** An attacker who **already holds the NT hash** can derive the session key and **sign requests themselves**. So **Pass-the-Hash is not stopped by SMB signing.**

| Attack | Does the attacker know the NT hash? | Stopped by SMB signing (required)? |
|---|---|---|
| **NTLM relay** | no (just forwarding) | **yes** |
| **Pass-the-Hash** | yes (stolen) | **no** |
| **Cracking captured NetNTLMv2** | once cracked, they know the password | **no**, after cracking |

So each needs its own defence: **SMB signing for relay**; **Day 3's LAPS, workstation-to-workstation blocking and Credential Guard for Pass-the-Hash** ([Pass-the-Hash](../../../adversary/pass-the-hash.md)); **Day 1's long, strong passwords against cracking**.

### Labs coming up later today { #upcoming-labs }

- **Web testing lab** — attack a deliberately vulnerable little web app (Damn Small Vulnerable Web App) with **ZAP (Zed Attack Proxy)** (part 3)
- **Ping Castle lab** — no VM needed; just **analyse a Ping Castle report** on a website (part 4)

---

## 2. Internet allow listing { #internet-allowlisting }

Very similar to Day 1's application allow listing: **highly effective**, but people avoid it fearing they'd have to allow-list every site the company uses.

> You don't have to. It's actually easy with **simple settings on the web proxy** your users go out through.

It shuts down a large part of **initial compromise** and **C2**, and complements Day 2's RITA / AC-Hunter nicely.

### Why deny-listing fails { #why-not-denylist }

> The internet is big. Really big. You wouldn't believe just how vastly, mind-bogglingly huge it is. Most of it is worthless and evil.

### How attackers use domains { #attacker-domains }

**① Buy, use, refund.** A domain costs about **$4.99** at GoDaddy and similar, and under ICANN rules there's a **refund window of a week or two**. Attackers buy, attack, and **get their money back** — "if they ain't nothing, they ain't frugal."

**② Compromise someone else and use their domain.** John demonstrates with **Shodan** (a search engine for internet-exposed devices):

- Search **MongoDB** → **93,624** exposed databases, many **end-of-life** and unpatched
- With an enterprise licence (expensive) you can search for **vulnerable or already-compromised systems**
- In Shodan Images, port **5900 (VNC)** → live screens; tag **ICS** → **industrial control systems open with no authentication**

**Why only briefly?** Not just money — attack domains are usually **"burnt"** (deny-listed) within **a week or two**.

### Pentesters do it differently — pre-categorised domains { #pentester-domains }

Pentesters like BHIS use a tool that **buys expired domains and sorts them by URL and risk rating (SimilarWeb, ACR scores)** (the tool's name isn't clear in the auto-captions). Because these domains were used before, expired and came back on sale, security vendors have already given them **legitimate categories** — brokerage/trading, government/legal (e.g. an Oregon City Parks .org), entertainment, technology/internet. The goal is **bypassing domain filtering**.

> Attackers rarely do this — they **buy brand-new domains**. That difference is the key to the defence below.

### Allow the sites, remove the ads { #ads }

Most people visit **only a handful of sites** a day. The exceptions are the click-on-everything crowd and heavy news readers — on sites like Yahoo, **ads that look like news stories** sit among the content, and some people click them. But they're rare.

> Allow-list the sites people want — even Yahoo — but **remove the ads** with something like Ghostery or AdBlock Plus **across the whole environment**. Your exposure ends up far lower than with a deny-list approach.

Deny-listing loses because vendors like Cisco or Fortinet **lag** — there's a gap between a site going live and attacking, and it reaching the critical mass where vendors block it.

### The key move — block "Uncategorized" { #block-uncategorized }

Web filters list categories (adware, alcohol, anonymizers, porn, gambling …). Companies block the obvious ones but **ignore "Uncategorized" in the bottom-right corner**.

> Blocking it gives you **de-facto allow listing of known sites without a lot of work**.

Attackers use **brand-new domains**, so your firewall / proxy vendor has **never seen them**.

> If Cisco has never seen that domain before, do you really want your users going there? That seems like a bad idea.

!!! note "💡 Note (added)"
    Many proxies and DNS filters now have a separate **"Newly Registered Domains (NRD)"** category (e.g. registered within 30 days). Blocking it alongside "Uncategorized" effectively filters the domains attackers just bought.

### Three allow-listing approaches { #allowlist-approaches }

- **① Allow-list every site individually** — "dumb most of the time"
- **② Allow-list by category** — as above (including blocking Uncategorized)
- **③ Let users allow-list their own sites** — possible with **Pi-hole**: an unseen domain triggers an **"Are you sure you want to go?"** prompt

> That makes it very hard to get **C2 out of the environment** — C2 malware **doesn't have hands** to click the button.

### Legitimate sites still infect — through ads { #malvertising }

Even with allow listing, compromise can come via **legitimate sites** — news, Facebook, movie sites, adult sites — and it's **almost always through advertisements**.

> The initial compromise server **usually isn't the C2 server** — one server delivers the exploit, a separate one does command and control.

So even if delivery gets through, you get another chance to block the **outbound C2**. Category filtering can also be done with DNS-based filters like **OpenDNS**.

!!! note "💡 Note (added) — finding never-before-seen domains in Splunk"
    ```spl
    index=zeek sourcetype=zeek_dns earliest=-30d
    | stats earliest(_time) AS first_seen count BY query
    | where first_seen > relative_time(now(), "-1d")
    | sort - count
    ```

    - **`index=zeek sourcetype=zeek_dns earliest=-30d`** — the last 30 days of Zeek DNS logs (adjust index / sourcetype).
    - **`stats earliest(_time) AS first_seen count BY query`** — per domain (`query`), when it **first appeared** (`first_seen`) and **how often** it was looked up.
    - **`where first_seen > relative_time(now(), "-1d")`** — keep only domains first seen **in the last 24 hours** — "absent for 30 days, new today."
    - **`sort - count`** — most-queried first.

    ```text
    query                         first_seen   count
    timeserversync.com            1729555200   168
    cdn-update-check.net          1729560000    42
    ```

    A brand-new domain queried **regularly and often** (like Day 2's WhatTime at 168/hour) is worth suspecting as C2.

### John on DNS over HTTPS (DoH) { #doh }

**DoH** sends name lookups over **encrypted HTTPS** — good for privacy. But John is uneasy:

- Even for people in dangerous countries, he recommends **a VPN** instead.
- Many DoH vendors wear a veneer of civil-rights help while **harvesting DNS data for ads** — "kind of sketchy."
- **Don't use DoH in a corporate setting:**

> DNS is unencrypted, so it lets us **see where people are going**, and that gives us some level of protection. With DoH we **lose that visibility**.

!!! note "💡 Note (added)"
    Typically you **disable browsers' built-in DoH** via Group Policy and block outbound 443 to well-known public DoH resolvers (e.g. `1.1.1.1`, `8.8.8.8`, `dns.google`) so clients **use internal DNS only** — which also keeps Day 2's DNS-based detection (e.g. spotting dnscat2-style backdoors) working.

---

## 3. Vulnerability management { #vulnerability-management }

### Unchanged for ten years { #unchanged }

> Run a vulnerability scanner → it finds external-facing vulnerabilities → you get a report. Very, very simple.

Some companies are moving to **credentialed scans** (give the scanner an account and inventory every installed application), but many teams get **completely overwhelmed by the data**. And in the AI era, **reported vulnerabilities, new CVEs and exploits will skyrocket**, so people have to stay in the loop.

### "Fix only highs and criticals" is broken { #broken-prioritization }

Ignoring **mediums, lows**, or anything **without a public exploit** causes problems in the AI era: anyone with a bit of skill, AI tools, time and tokens can **pull working exploits** out of those vulnerabilities.

> What was a medium before is probably becoming a high.

**John's proposal — bump every CVSS score up by at least one:** 6.5 → **7.5**, 8.5 → **9.5**, 9.5 → expect an exploit very quickly.

| CVSS score | Severity |
|---|---|
| 0.1 – 3.9 | Low |
| 4.0 – 6.9 | Medium |
| 7.0 – 8.9 | High |
| 9.0 – 10.0 | Critical |

On "we won't patch until there's an active exploit":

> By the time that exploit hits, **it's too late.**

Exploits and worms used to spread **indiscriminately** and give defenders **some time**; now even a targeted attack or pentest can do **targeted exploit development with AI** relatively quickly.

!!! note "💡 Note (added) — what to use alongside CVSS"
    - **CISA KEV** — vulnerabilities confirmed as exploited in the wild
    - **EPSS** — the **probability** of exploitation in the next 30 days

    Both help, but both rise only **after signals accumulate**, so they can lag in an era of AI-accelerated exploitation. Use KEV / EPSS to set the front of the queue — and don't ignore what's below.

### The bigger problem — ignored lows and informationals { #lows-and-infos }

> The bigger problem is that **lows and informationals** probably shouldn't have been ignored anyway.

Imagine a server farm with **1,000 Telnet servers** (it happens with legacy tech). The scan shows each one's **banner**:

```text
login
login
login
mushroom
mushroom
login
router
login
...
```

*(reconstructed — John's spoken example)*

Most say `login`, but the **one that says `router`** is a **Telnet server requiring no authentication at all** — a huge, glaring vulnerability. Because a banner can be **any string**, the scanner can't tell "just a login banner" from "potentially a huge vulnerability," so it files it as **Informational**.

> Even before the age of AI, we were already dealing with a mass of **lows and informationals being missed** — and the vast majority of organisations **just ignore them**.

### Deep dive ④ Why is a `router` banner dangerous? { #deep-dive-router-banner }

*An added explanation, not from the lecture.*

The danger isn't the **word** `router` — it's that **a device command prompt appeared without any login request**. A normal Telnet server asks who you are first:

```text
$ telnet 10.1.0.1
Connected to 10.1.0.1.

User Access Verification

Username:
```

The `router` one most likely looks like this:

```text
$ telnet 10.1.0.9
Connected to 10.1.0.9.

Router>
```

`Router>` is the **"enter a command" prompt you normally only see after logging in**. Cisco devices default to the hostname `Router`, so the prompt reads `Router>`. You're **inside the router the moment you connect** — like opening the front door and finding yourself straight in the plant room.

A router is the network's **intersection**: from it an attacker can read the config to **map the network**, change routes to **redirect traffic to themselves** (the same effect as Responder), **edit ACLs to open blocked paths**, and use it as a **foothold** into other segments. And Telnet is **unencrypted**, so even legitimate logins send passwords in the clear.

`mushroom` illustrates that **banners can be any text** — you can't tell from the words whether a login prompt follows. A scanner just **records the first line**; it doesn't understand whether that's a login prompt or an already-logged-in command prompt. It takes a human reading it.

### Group by vulnerability, not by host { #group-by-vuln }

Looking host by host — **1,000 IPs × ~25 vulns each = 25,000 issues** — feels impossible. John says that approach is **almost always incorrect**.

> You don't actually have 25,000 vulnerabilities. You usually have **a couple hundred vulnerabilities repeating** again and again across systems.

Flip the question — ❌ "what vulnerabilities does this host have?" → ⭕ "**which hosts have this vulnerability?**" Now you chase **a couple hundred**, and you can use **automation — Microsoft patching, Ansible scripts** — to push the same fix to many systems **in parallel**.

!!! note "💡 Note (added) — \"group by vulnerability\" in Splunk"
    Suppose Nessus results were exported to CSV and uploaded to Splunk as a **lookup file** `nessus_scan.csv` (columns such as `Plugin ID`, `Name`, `Risk`, `Host`, `Port`, `Plugin Output`).

    ```spl
    | inputlookup nessus_scan.csv
    | stats dc(Host) AS host_count values(Host) AS hosts BY "Plugin ID" Name Risk
    | sort - host_count
    ```

    - **`| inputlookup nessus_scan.csv`** — load the uploaded CSV instead of searching an index (note the leading `|`).
    - **`stats ... BY "Plugin ID" Name Risk`** — group by vulnerability. Field names with **spaces** go in double quotes.
        - **`dc(Host) AS host_count`** — `dc` is **distinct count** — how many **different hosts** have it.
        - **`values(Host) AS hosts`** — the **list** of those hosts.
    - **`sort - host_count`** — most-affected first.

    ```text
    Plugin ID  Name                              Risk    host_count  hosts
    42263      Unencrypted Telnet Server         Medium  1000        10.1.0.1, 10.1.0.2, ...
    57608      SMB Signing not required          Medium   812        10.2.0.5, 10.2.0.6, ...
    ...        Web Server Office File Inventory  None      14        10.3.1.20, ...
    ```

    *(illustrative numbers)* 25,000 rows become **a few hundred**, with "fix once, solve hundreds of hosts" at the top. **"SMB Signing not required"** ties straight to [Deep dive ②](#deep-dive-smb-signing) — Nessus rates it Medium, but it means 812 hosts are open to relay. In Nessus CSVs, informationals have `Risk` = **`None`** — **don't filter them out**.

    To surface **rare values** like the banners (Day 2's long-tail analysis):

    ```spl
    | inputlookup nessus_scan.csv
    | search "Plugin ID"=42263
    | stats count BY "Plugin Output"
    | sort count
    ```

    - **`search "Plugin ID"=42263`** — Telnet-server findings only.
    - **`stats count BY "Plugin Output"`** — count identical banner outputs.
    - **`sort count`** — **smallest first** (no `-` means ascending).

    ```text
    Plugin Output        count
    router                   1
    mushroom                 2
    login                  997
    ```

    The lone `router` at the top is the **unauthenticated Telnet server**.

**Vulnerability scanning covers a narrow slice.** In MITRE ATT&CK it's mostly **Exploit Public-Facing Application** and **External Remote Services** — most of the matrix and **post-exploitation lateral-movement opportunities** stay invisible. Hence tools like Day 3's BloodHound and part 4's Ping Castle.

---

## 4. Nessus report lab — an Easter-egg hunt { #nessus-lab }

In the Windows VM's `IntroLabs` folder is a **Nessus report** (older, but the concepts hold). The task is an Easter-egg hunt for **lows and mediums people ignore that absolutely should be fixed**; John's explanations are at the bottom of the report.

### ① Office File Inventory (Low) { #office-file-inventory }

`Ctrl+F` **"office"** → a **Low** finding listing **Office documents on the web server**.

> This is a low finding we end up with a lot — and **we use it to gain access to systems.**

People put silly things on web servers — **`passwords.doc`**, an **install guide** walking through setup **step by step**.

### ② Backup files (.bak) { #backup-files }

Search **`.bak`** → the site's page index shows things like:

```text
/admin/
/admin/backup/backup.bak
/admin/telnet
```

Many sites take **regular backups** saved as `.001`, `.002` or `.bak` in the same folder, and those often contain **server-side includes** with **user IDs and passwords**. Another site exposes **`sourcecode.tar`**.

!!! note "💡 Note (added) — why backup files are dangerous"
    A web server **executes** `config.php` and returns only the output, so its DB password stays hidden. But `config.php.bak` isn't treated as executable — it's **served as plain text**, exposing **source code and the DB password**. Keep backups out of the web root, and block serving extensions like `.bak`, `.old`, `.tar`, `.zip`.

### ③ config term (Telnet) { #config-term }

Finally, the Telnet case from earlier:

```text
Welcome to the configure terminal.
Please authenticate.
Please authenticate.

Router(config)#
```

*(reconstructed — the report's exact wording may differ)*

It keeps saying "please authenticate," but ultimately **configuration mode is just sitting there**, and anyone who connects can change the configuration.

### Deep dive ⑤ Why does `config term` appear after "please authenticate"? { #deep-dive-config-term }

*An added explanation, not from the lecture.*

> The **"Please authenticate" text isn't an authentication check — it's just a printed notice.**

Devices have two separate settings:

- **Banner** — a **notice** shown on connect; any text at all.
- **Login** — the setting that actually **asks for and checks credentials**.

This device has a banner saying "please authenticate" but **no login configured**. It's a door with a **"show ID to enter" sign** that **isn't locked**.

`config term` is Cisco's **`configure terminal`** — the command that enters **configuration mode**.

| Prompt | Level | What you can do |
|---|---|---|
| `Router>` | user EXEC | view some status |
| `Router#` | privileged EXEC | view everything and enter config mode |
| `Router(config)#` | **global configuration** | **change any device setting** |

So this is **worse than Deep dive ④'s `Router>`** — not only no authentication, but **straight into full-privilege configuration**.

**Why it happens:** no authentication on the remote-access (VTY) lines (`no login`); remote sessions configured to land directly at **privilege level 15**; loosened for testing and **never reverted**; an old device **nobody reviews**.

**Defence:** **disable Telnet, allow SSH only** (`transport input ssh`), **require login** on remote access (AAA or local accounts), and restrict management access to **management IPs** with an ACL. When auditing, collect the **banners of every host with port 23 open and review the rare ones first** to spot anything that isn't a `login` prompt.

### What this lab is getting at { #nessus-takeaway }

> You can't just look at highs and criticals — **you've got to look at lows and informationals.** And to do that effectively, **sort by plugin ID and vulnerability ID**.

That's a standard vulnerability-assessment scan — **fundamentally different** from testing **web applications, mobile apps and APIs**, which is where part 3 picks up.

---

That's Day 4 parts 1–2. One-line summary:

> **An attacker on your network captures NTLMv2 and cracks or relays it — the answer is host-to-host blocking, disabling LLMNR and required SMB signing, while stolen-hash Pass-the-Hash needs separate defences. Attackers burn brand-new domains, so blocking "Uncategorized" and removing ads gives de-facto internet allow listing. For vulnerabilities, bump CVSS up a level, look at lows and informationals, and group by vulnerability so automation can fix them at scale.**

Next (parts 3–4, to be added): **web application security** and the **ZAP lab**, **AD hardening** (BloodHound, PlumHound, Mimikatz) and the **Ping Castle lab**, wrap-up.

## References

- [Antisyphon Training](https://www.antisyphontraining.com/) · [Black Hills Information Security](https://www.blackhillsinfosec.com/)
- [Responder](https://github.com/lgandx/Responder) · [Impacket (ntlmrelayx)](https://github.com/fortra/impacket) · [Hashcat example hashes (mode numbers)](https://hashcat.net/wiki/doku.php?id=example_hashes)
- [Microsoft — SMB signing](https://learn.microsoft.com/windows-server/storage/file-server/smb-signing) · [CISA KEV](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) · [FIRST EPSS](https://www.first.org/epss/) · [FIRST CVSS](https://www.first.org/cvss/)
- [MITRE ATT&CK — T1557.001 LLMNR/NBT-NS Poisoning and SMB Relay](https://attack.mitre.org/techniques/T1557/001/)
- Related: [LLMNR & NTLM relay](../../../adversary/llmnr-ntlm-relay.md) · [Pass-the-Hash](../../../adversary/pass-the-hash.md) · [SAM & NTDS extraction](../../../adversary/sam-ntds-extraction.md) · [Zeek](../../../network/zeek/index.md) · [Well-known ports](../../../basics/well-known-ports.md)

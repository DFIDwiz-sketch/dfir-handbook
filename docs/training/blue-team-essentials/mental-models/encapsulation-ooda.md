---
title: "Mental Models for Security, Encapsulation and the OODA Loop — Peeling Layers and Out-Cycling the Attacker"
tags:
  - training
  - blue-team
  - soc
  - analysis
  - mental-models
---

# Mental Models for Security, Encapsulation and the OODA Loop — Peeling Layers and Out-Cycling the Attacker { #encapsulation-ooda }

!!! abstract "What this page covers"
    The previous section ended with a prescription: collect many accurate mental models. This section is that collection. We start with a **map of the standard security models** — general, offensive, defensive and threat-intelligence — and what each one is for. Then the first two general models. **Encapsulation**: attacks live in layers, both in network traffic (link, IP, transport, session, application) and in files (an email containing a ZIP containing a document containing an executable), and something that looks innocent at the top layer can be malicious further down. We follow one phishing download through Zeek `conn`, `ssl`, `http` and `files` logs to show which layer finally reveals it, then peel a nested attachment apart command by command (`unzip`, `file`, `oleobj`) with the output at each step. **The OODA loop** (Observe, Orient, Decide, Act): John Boyd's model for acting under uncertainty and winning head-to-head contests, what each stage means in a SOC, why **Orient** decides everything, and what it means to get "inside" an attacker's loop. A worked intrusion shows defender and attacker loops side by side, minute by minute, including a **4624** logon type 10 and the moment the defender's slow Decide lets the attacker re-orient. The 2026 view (Encrypted Client Hello, QUIC, 29-minute breakout times, AI on both sides of the loop) and practice questions close the page.

!!! note "Labels"
    **[Supplement]** = practical material you need to know, **[Correction]** = a commonly repeated claim that is wrong or outdated, **[Changed]**/**[Caution]** = what has changed recently and what is risky to do the old way. The company (Kestrel Logistics), hostnames, accounts, domains, IPs, file names and log lines are invented for illustration (`.example`, documentation and private IPs). Frameworks and their authors are described in my own words.

## The 8 key points { #key-points }

1. **Attack details change constantly; good high-level models don't.** Models of attack, defence and intelligence give you a stable frame to hang new information on — exactly what the memory page said speeds up learning and analysis.
2. **Four families:** *general* (encapsulation, OODA), *offensive* (Kill Chain, campaigns, attack trees, graph thinking, ATT&CK), *defensive* (defence in depth, NIST CSF, incident response cycle, Pyramid of Pain, threat modelling) and *threat intelligence* (levels of intelligence, intelligence cycle, F3EAD, Diamond Model). Each answers a different question.
3. **Encapsulation:** data is wrapped in layers. Evil can sit on any network layer from 2 to 7, and many modern attacks are **only visible at layer 7** — the IP, port and domain all look normal.
4. **You need visibility at every layer**, which for HTTPS often means TLS inspection or endpoint telemetry. Without it, a malicious download from a reputable cloud service is just "HTTPS to a trusted site".
5. **Files have layers too:** email → ZIP → Office document → embedded executable. Scanning only the outer layer can miss everything. Recursively take it apart until you reach the bottom.
6. **OODA = Observe, Orient, Decide, Act** — John Boyd's model for acting under uncertainty and winning competitive encounters. Perfect information never comes; the side that cycles faster and adapts its picture faster wins.
7. **Orient is the heart of the loop.** It's where new observations meet your mental models and context to form a picture of reality. A wrong or stale model breaks everything downstream, however fast you are.
8. **Tempo wins.** Running your loop several times inside one of the attacker's — being "inside their loop" — is the goal of a SOC's detection and response speed. Pre-decided playbooks shorten Decide; good models shorten Orient.

## Why this matters in a SOC { #why }

A carpenter doesn't own one tool. They own a box of them and, more importantly, know which one fits which job. Mental models are the analyst's toolbox. When an alert lands, the right model tells you what to ask next: encapsulation says "what's inside this?", the Kill Chain says "how far along is this?", the Pyramid of Pain says "which indicator will actually hurt them if I block it?", OODA says "how fast do I need to move, and what will the attacker do when I do?".

Back to the technical reality: almost every bad call in alert analysis comes either from looking at the wrong layer (the IP was clean, so the session was clean) or from moving at the wrong tempo (too slowly to stop lateral movement, or so fast that the attacker noticed and changed tactics before the scope was known). The two models on this page target exactly those two failures.

## A map of the models { #model-map }

Here are the standard models this section covers, grouped by what they're for:

| Family | Model | The question it answers |
| --- | --- | --- |
| General | **Encapsulation** (network and file layers) | What is really inside this traffic or file? |
| General | **OODA loop** | How do I act under uncertainty — and faster than my opponent? |
| Offensive | **Cyber Kill Chain** | Which stage is this attack at, and how far from its goal? |
| Offensive | **Campaigns, indicators, actions** | Is this one event, or part of a larger pattern by the same actor? |
| Offensive | **Attack trees / graph thinking** | Which paths can an attacker take to reach this target? |
| Offensive | **MITRE ATT&CK** | Which specific technique is this, and what usually comes before and after? |
| Defensive | **Defence in depth** | Which layers of defence should stop this, and which failed? |
| Defensive | **NIST Cybersecurity Framework** | Are we covering every function of a security programme? |
| Defensive | **Incident response cycle** | Which phase of response are we in, and what's next? |
| Defensive | **Pyramid of Pain** (and detection maturity) | Which indicators are worth detecting and blocking? |
| Defensive | **Threat modelling** | What could go wrong with this system, and what do we do about it? |
| Threat intel | **Levels of intelligence** (strategic, operational, tactical) | Who needs this information, and in what form? |
| Threat intel | **Intelligence cycle** and **F3EAD** | How do we turn data into intelligence, and intelligence into action? |
| Threat intel | **Diamond Model** | Who did this, with what, against whom, using which infrastructure? |

None of these is "the right one". Each highlights some aspects of a situation and hides others, which is why you want several. The rest of this page covers the two general models; the following pages take the others in turn.

## Encapsulation: attacks live in layers { #encapsulation }

### The idea { #encapsulation-idea }

Think of a Russian nesting doll — a *matryoshka*. The outer doll is painted cheerfully. You only find what's inside by opening it, and the next one, and the next. Network traffic and files are built the same way: each layer wraps the one inside, and each layer's "paint" can look perfectly normal.

In networking, **encapsulation** is the literal mechanism: application data (say, an HTTP request) is wrapped in a TLS record, then in a TCP segment, then in an IP packet, then in an Ethernet frame. Each layer adds its own header and knows nothing about what it carries. For an analyst the consequence is simple: **each layer can hide or reveal something different**, and a decision based on one layer only tells you about that layer.

### Evil on every layer { #evil-per-layer }

| Layer | What you see there | Example of malicious activity visible at this layer |
| --- | --- | --- |
| 2 — Link | MAC addresses, ARP, VLANs | ARP spoofing to sit in the middle of traffic (**T1557.002 Adversary-in-the-Middle: ARP Cache Poisoning**); a rogue device on the network |
| 3 — Network | Source/destination IP | Connection to a known-bad IP; internal host talking to an address it never has before |
| 4 — Transport | Ports, TCP flags, connection length, bytes | Port scanning; C2 on an odd port (**T1571 Non-Standard Port**); a long-lived connection sending more than it receives |
| 5/6 — Session/presentation (TLS) | Certificates, SNI, TLS fingerprints | Self-signed or freshly issued certificate on a "bank" domain; a TLS client fingerprint matching a known malware family ([HTTPS certificates](../http-analysis/https-certificates.md), [TLS fingerprints](../http-analysis/tls-fingerprints-tls13.md)) |
| 7 — Application | HTTP methods, URIs, headers, file content, DNS queries, SMB commands | A ZIP containing an executable downloaded from a trusted site; a script in a POST body; data hidden in DNS queries |

Note the last row. For a growing share of modern attacks, **layer 7 is the only layer where the attack is visible** — because attackers deliberately use legitimate infrastructure for the lower layers.

### Worked example: a malicious download from a trusted cloud service { #encapsulation-example }

A user at Kestrel receives an email: "Your invoice is ready — view it here." The link goes to a file on a major, reputable cloud file-sharing service (here, `files.cloudshare.example`). The user clicks. Let's see what each layer of the logs tells us.

**Layer 3/4 — Zeek `conn.log`:**

```
#fields ts  uid  id.orig_h  id.orig_p  id.resp_h  id.resp_p  proto  service  duration  orig_bytes  resp_bytes  conn_state
1795521601.2  Cq81  10.20.4.57  52844  198.51.100.40  443  tcp  ssl  2.91  1288  412877  SF
```

- `id.orig_h=10.20.4.57` — the user's workstation, KL-WS-0457.
- `id.resp_h=198.51.100.40`, `id.resp_p=443` — an address belonging to the cloud provider's huge, shared range; port 443 is ordinary HTTPS. Reputation feeds rate the address **clean**, because thousands of legitimate customers use it.
- `resp_bytes=412877` — about 400 KB came back. A file download, but nothing tells us what kind.
- Verdict from this layer: **normal**.

**Layer 5/6 — Zeek `ssl.log`:**

```
#fields ts  uid  id.orig_h  id.resp_h  version  server_name  subject  issuer  validation_status
1795521601.2  Cq81  10.20.4.57  198.51.100.40  TLSv13  files.cloudshare.example  -  -  -
```

- `version=TLSv13` — TLS 1.3, so the server certificate is encrypted in the handshake and Zeek can't read `subject` and `issuer` (shown as `-`).
- `server_name=files.cloudshare.example` — the SNI (the name the client asked for) is a well-known, trusted service. Domain reputation: **clean**.
- Verdict from this layer: **normal**.

**Layer 7 — only because Kestrel's proxy performs TLS inspection** (decrypts, inspects and re-encrypts), Zeek on the inside of the proxy sees the HTTP:

```
#fields ts  uid  id.orig_h  method  host  uri  status_code  resp_mime_types  user_agent
1795521601.4  Cq81  10.20.4.57  GET  files.cloudshare.example  /s/9fK2/Invoice_4471.zip?dl=1  200  application/zip  Mozilla/5.0 (Windows NT 10.0; Win64; x64) ...
```

```
#fields ts  fuid  uid  source  mime_type  filename  total_bytes  extracted
1795521601.6  FhA2  Cq81  HTTP  application/zip  Invoice_4471.zip  412610  extract-FhA2.zip
```

- `uri=/s/9fK2/Invoice_4471.zip?dl=1` — a shared link with "direct download" forced.
- `resp_mime_types=application/zip` — Zeek identified the content as a ZIP from its magic bytes, not from the name.
- `files.log` `extracted=extract-FhA2.zip` — Zeek saved a copy for analysis. **Now** we have something to look at, and opening it (next section) shows an executable inside.

So the attack was invisible at layers 3, 4 and 5 and only appeared at layer 7. This is the shape of **T1566.002 Phishing: Spearphishing Link** with the payload hosted on a legitimate service (**T1608.001 Stage Capabilities: Upload Malware**), leading to **T1204.002 User Execution: Malicious File**. Without TLS inspection, the remaining options are endpoint telemetry (EDR sees the browser write `Invoice_4471.zip` to disk and sees what is extracted and run) and email-gateway link analysis.

### Files are layered too { #file-layers }

Now the same lure, but with the file attached to the email instead of linked. The email gateway sees a ZIP. Antivirus scans the ZIP and finds nothing obviously bad. Do we stop there? No — peel it. ([Nested files](../file-analysis/file-identification.md#nested-files) covers the theory; here's the routine.)

**Layer 1 — the email.** A fragment of the MIME structure:

```
Content-Type: application/zip; name="Invoice_4471.zip"
Content-Disposition: attachment; filename="Invoice_4471.zip"
Content-Transfer-Encoding: base64
```

- `Content-Type: application/zip` — the sender's claim about the attachment type.
- `Content-Transfer-Encoding: base64` — the file is Base64-encoded inside the email; the gateway decodes it before scanning.

**Layer 2 — the ZIP.** In an isolated analysis VM:

```
$ unzip -l Invoice_4471.zip
Archive:  Invoice_4471.zip
  Length      Date    Time    Name
---------  ---------- -----   ----
   409984  2026-11-23 22:14   Invoice_4471.docx
---------                     -------
   409984                     1 file
```

- `unzip -l` *lists* the contents without extracting.
- One file, `Invoice_4471.docx`, about 400 KB — very large for a one-page invoice. Suspicious already.

**Layer 3 — the Word document.** A `.docx` is itself a ZIP of XML files, so it can be listed the same way:

```
$ unzip -o -q Invoice_4471.zip -d stage1
$ unzip -l stage1/Invoice_4471.docx | grep -v xml
Archive:  stage1/Invoice_4471.docx
  Length      Date    Time    Name
   398848  1980-01-01 00:00   word/embeddings/oleObject1.bin
     4286  1980-01-01 00:00   word/media/image1.emf
```

- `unzip -o -q … -d stage1` — extract quietly into a folder called `stage1`.
- `grep -v xml` — hide the normal XML parts so the unusual ones stand out.
- `word/embeddings/oleObject1.bin` — an **embedded OLE object**, almost 390 KB: nearly the whole document. A legitimate invoice has no reason to embed anything.
- `word/media/image1.emf` — the icon the user sees in the document (often a fake "PDF" or "click to view" picture to click on).

**Layer 4 — the OLE object.**

```
$ unzip -o -q stage1/Invoice_4471.docx -d stage2
$ file stage2/word/embeddings/oleObject1.bin
stage2/word/embeddings/oleObject1.bin: Composite Document File V2 Document, Cannot read section info
$ oleobj stage2/word/embeddings/oleObject1.bin
...
Parsing OLE Package
Filename = "Invoice_details.exe"
...
saving to file oleObject1.bin_Invoice_details.exe
```

- `file` — recognises the OLE "compound file" container format (the old Office binary format), but can't tell you what's inside.
- `oleobj` (from the free `oletools` suite) — parses the OLE **Package** object, which is how Office embeds an arbitrary file, and extracts it. The embedded file is named `Invoice_details.exe`. (Output trimmed.)

**Layer 5 — the bottom.**

```
$ file oleObject1.bin_Invoice_details.exe
oleObject1.bin_Invoice_details.exe: PE32 executable (GUI) Intel 80386, for MS Windows
$ sha256sum oleObject1.bin_Invoice_details.exe
<64-hex-digit hash>  oleObject1.bin_Invoice_details.exe
```

- `PE32 executable (GUI)` — a Windows program. The user would see an icon in the document, double-click it, and Office would offer to run the embedded program.
- `sha256sum` — the hash to search in your EDR and threat-intel platforms, and to block ([hashing](../file-analysis/hashing-signatures.md)).

Five layers: email → ZIP → DOCX → OLE package → EXE. Each one looks harmless to a check that only looks at its own layer. This chain maps to **T1566.001 Phishing: Spearphishing Attachment** → **T1204.002 User Execution: Malicious File**, with the nesting itself acting as **T1027 Obfuscated Files or Information**.

### The lesson: go all the way to the bottom { #to-the-bottom }

Just because a file or network transaction looks innocent on the surface doesn't mean it is. In many cases you have to **take the data apart recursively** before you can be confident nothing malicious is happening. **[Supplement]** — a practical checklist:

- **For network events:** which layers do I actually have? If I only have layers 3–4 (NetFlow, firewall), I can only clear layers 3–4. Say so in the ticket ("no layer 7 visibility; cannot exclude malicious content").
- **For cloud and CDN destinations:** IP and domain reputation is almost meaningless. Ask what was transferred, not where it went.
- **For files:** keep unpacking — archives, disk images (ISO/IMG/VHD), Office containers, embedded objects, scripts inside HTML — until you reach something that is *not* a container. Automate it: sandboxes and tools such as `binwalk` or a recursive extractor do this, but check that they actually descended every layer.
- **For password-protected archives:** the password is usually in the email body. That's the attacker deliberately blocking the gateway from opening a layer.
- **Record the layers in the case notes,** e.g. `email → ZIP → DOCX → OLE → EXE (sha256 …)`, so the next analyst knows what was checked.

## The OODA loop { #ooda }

### Where it comes from { #ooda-origins }

**John Boyd** (1927–1997) was a US Air Force fighter pilot and instructor, famous for being able to win a simulated dogfight from a position of disadvantage in under forty seconds. Out of that experience he developed theories of air combat in the 1960s and, later, a broader theory of conflict presented in long briefings through the late 1970s and 1980s. The **OODA loop** — **Observe, Orient, Decide, Act** — is the best-known part of it.

Boyd's insight was that a pilot with a technically inferior aircraft and imperfect information could still win by **cycling through decisions faster** and adapting to the changing situation faster than the opponent. Each pilot is constantly running the loop in their head; the one who completes it quicker — sees, makes sense, chooses and acts while the other is still making sense — gains the upper hand.

Two goals sit at the core of the model, and both fit SOC work closely:

1. **A general method for dealing with uncertainty** — a learning system that keeps updating its picture as reality changes.
2. **A strategy for winning head-to-head competitions** — and incident response is exactly that: an intelligent opponent adapting to what you do.

A central theme in writing about Boyd is that **ambiguity isn't something to fear or wait out — it's the normal condition**. You will never have complete and perfect information. The winner isn't the side that eliminates uncertainty; it's the side that acts well *despite* it and keeps adjusting.

What the model warns against is the tendency covered in the previous section: people don't update their mental models fast enough as circumstances change. A stale picture leads to bad choices, and bad choices lose the contest.

### The four stages, in SOC terms { #ooda-stages }

| Stage | General meaning | In security operations |
| --- | --- | --- |
| **Observe** | Take in new information about the environment | Collect network and host security monitoring data: logs, alerts, packets, files, EDR telemetry, user reports |
| **Orient** | Combine observations with mental models and context to form a picture of reality | Combine what the attacker is doing with network and user context, threat intel and attack models into a picture of the attack in progress and its likely goal |
| **Decide** | Choose a course of action, treating it as a hypothesis | Decide how to disrupt the attacker so that you gain the advantage in the next round: contain, block, observe longer, collect more |
| **Act** | Carry it out, and feed the result back into Observe | Isolate the host, disable the account, block the domain, deploy a detection — then watch what happens |

**Orient is the most important stage.** It's where new information is filtered through everything the last two pages discussed: perception, memory, mindsets and mental models. It's where you pick which model describes the situation, and the quality of that choice depends on **how many good models you have** and how willing you are to drop one that no longer fits. If Orient is wrong, a fast Decide and Act just get you to the wrong place sooner. Boyd drew Orient as the stage that shapes all the others — it influences what you choose to observe next as well as what you decide.

**Decide** is best thought of as choosing a hypothesis to test, not a final answer. **Act** is the test, and its result — did the beaconing stop? did a new one start somewhere else? — becomes the next Observe.

### Ops tempo: getting inside the attacker's loop { #ops-tempo }

The key property of OODA is **speed relative to the opponent**. If you can complete several loops in the time the attacker completes one — sometimes described as being "inside" their loop — you're very likely to win: every time they act, you've already seen it, made sense of it and responded, and their picture of the situation is out of date before they can use it.

That maps directly onto a SOC's **operations tempo**: how fast it can prevent, detect and respond, and how fast it can learn from each iteration. Concretely:

- **Faster Observe:** good collection and alerting, low ingestion delay, alerts reaching a human (or automation) in minutes, not hours.
- **Faster Orient:** analysts with good models and context ready to hand — asset criticality, user roles, baseline behaviour, threat intel.
- **Faster Decide:** decisions made **in advance** — playbooks and pre-approved actions ("analysts may isolate a workstation with confirmed C2 without approval"). Waiting for a manager at 03:00 is a slow Decide.
- **Faster Act:** EDR isolation, account disable and blocks that take one click or an automated SOAR step.

And the reverse: the attacker is running their own loop against you. Their Observe is watching whether their beacon still answers, whether their account still works; their Orient is deciding whether they've been noticed.

### Worked example: two loops, one intrusion { #ooda-example }

An attacker has phished a Kestrel user and has a beacon on workstation KL-WS-0219. Here's the next ninety minutes as two loops.

**Defender loop 1 (slow).**

```
[EDR] Beaconing behaviour: periodic HTTPS to rare domain   severity: medium
  host=KL-WS-0219  process=C:\Users\a.cho\AppData\Local\Temp\onenote_sync.exe
  dest=cdn-telemetry.example (203.0.113.51)  interval≈60s  first_seen=09:12Z
```

- **Observe (09:14):** the alert arrives — a process in a user's `Temp` folder contacting a rare domain about every 60 seconds (**T1071.001**, **T1036.005** for the fake "OneNote" name).
- **Orient (09:14–09:50):** the alert waits in the queue for 25 minutes; the analyst then spends 11 minutes deciding whether it's an update agent.
- **Decide (09:50–10:20):** the analyst wants to isolate the host but policy needs a manager's approval; the manager is in a meeting.
- **Act (10:20):** KL-WS-0219 is isolated.

**Attacker loop, running at the same time.**

- **09:20 Observe/Orient:** the beacon gives the attacker a shell. They enumerate the domain and find `a.cho` is in a group that can RDP to a file server.
- **09:41 Decide/Act:** they RDP from KL-WS-0219 to KL-FS02 with `a.cho`'s credentials. On KL-FS02 the Security log records:

```
Event ID 4624  Computer: KL-FS02  2026-11-24T09:41:07Z
  Account Name: a.cho   Logon Type: 10
  Source Network Address: 10.20.2.19   Logon Process: User32
```

- **4624** with **Logon Type 10** (*RemoteInteractive*) — an RDP (Remote Desktop) logon. It fires on the machine being logged on to. Attackers care because RDP gives them a full interactive desktop on the target using credentials they already have (**T1021.001 Remote Services: Remote Desktop Protocol**). A finance user starting an RDP session to a file server from her workstation is unusual; type 10 logons to servers from non-admin accounts are a good hunting lead ([logins](../important-events/logins.md)).
- **09:55 Act:** they drop a second, quieter implant on KL-FS02 that calls out every 4 hours through a different domain.
- **10:21 Observe:** the beacon from KL-WS-0219 stops answering. **Orient:** "they've found the workstation". **Decide/Act:** switch to the implant on KL-FS02 and go quiet.

The defender completed **one** loop while the attacker completed **three**. When the workstation was isolated, the attacker had already moved, and the isolation itself told them they'd been seen.

**Defender loop, the fast version.** Same alert, a SOC with a better tempo:

- **Observe (09:14):** beaconing alert scored high automatically because the binary is in `Temp`, unsigned and rare.
- **Orient (09:14–09:20):** the analyst uses the [memory page's](../analyst-cognition/memory-experience.md#case-notes) case-notes habit: entity list, timeline; checks EDR for the process tree (spawned from `ONENOTE.EXE` after an email attachment opened at 09:10) — confirmed C2.
- **Decide (09:20):** playbook says "confirmed C2 on a workstation → analyst may isolate immediately, then scope." No waiting.
- **Act (09:21):** KL-WS-0219 isolated, `a.cho` sessions revoked and password reset.
- **Observe again (09:22–09:40):** search for `cdn-telemetry.example` and the binary's hash across the fleet; check `a.cho`'s logons in the last 24 hours. Nothing beyond KL-WS-0219.

At 09:41 the attacker's RDP attempt fails, because the credentials are already reset and the source host is isolated. The defender was **inside the attacker's loop**: the attacker's picture ("I have a working foothold and valid credentials") was out of date before they could act on it.

!!! tip "Fast is not the same as hasty"
    Speed applies to the *whole* loop, including Orient. Acting before you understand the scope — blocking one domain while three other implants exist — just teaches the attacker that you're watching and makes them harder to find. Later sections on reacting to intrusions deal with when to act and when to watch; OODA's lesson is to make each loop *quick and well-oriented*, not to skip Orient.

### Where OODA helps in daily SOC work { #ooda-daily }

- **During an incident:** say the stage out loud in a bridge call. "We're still orienting — we don't know scope yet" stops premature action; "we've oriented, we need a decision" stops endless analysis.
- **For tempo metrics:** time-to-detect is Observe; time-to-triage and time-to-scope are Orient; time-to-approval is Decide; time-to-contain is Act. Measuring each shows where your loop is slow.
- **For playbooks:** every decision you can make in advance is time removed from Decide in the middle of the night.
- **For thinking about the attacker:** deception, living-off-the-land and blending into normal traffic all target *your* Observe and Orient. Encapsulation is one of their best tools for that.

## The 2026 view { #trends }

!!! success "[2026 Current] Still valid"
    Encapsulation and OODA are as relevant as ever. Attackers still stage payloads on reputable cloud services and nest them inside containers, and layer-7 or endpoint visibility is still what reveals them. OODA remains widely used in military, business and incident-response thinking, and "getting inside the adversary's loop" is a common way to frame SOC detection and response speed.

!!! info "[Changed] What has changed"
    - **Less is visible on the wire.** TLS 1.3 encrypts the server certificate, QUIC (HTTP/3) carries web traffic over UDP 443, and **Encrypted Client Hello** (ECH) — published as **RFC 9849** in March 2026 and already supported by major browsers and some CDNs — can hide the SNI as well. Layers 5–7 increasingly require TLS inspection or **endpoint telemetry**; EDR has become the main source of "layer 7" truth for many SOCs.
    - **Containers shifted after macro blocking.** Since Office began blocking internet macros by default in 2022, nesting moved to ISO/IMG/VHD images, LNK files, OneNote and HTML smuggling (**T1027.006**), often to sidestep Mark-of-the-Web (**T1553.005**). The peel-every-layer habit matters more, not less.
    - **The attacker's loop got faster.** One 2026 industry threat report put average eCrime breakout time (initial access to lateral movement) at **29 minutes**, with the fastest at **27 seconds**, and reported a sharp rise in attacks by AI-enabled adversaries. A Decide stage that waits for a meeting to end is no longer survivable.
    - **AI is entering both loops.** Defenders use AI triage and SOAR to shorten Observe and Orient; attackers use AI to speed up reconnaissance, phishing and tooling. ATT&CK v20 (October 2026) added techniques for AI-related abuse, and ATT&CK v19 (April 2026) split the old Defense Evasion tactic into Stealth and Defense Impairment.

!!! warning "[Caution] Wrong or risky to do the old way"
    - **"The IP and domain are clean" is not a verdict** for cloud-hosted or CDN-fronted destinations. Clear only the layers you actually inspected, and say which ones you couldn't.
    - **Don't rely on TLS inspection alone.** Certificate pinning, QUIC, ECH, privacy exclusions (banking, health) and legal limits leave gaps; plan for endpoint visibility too, and make sure inspection is lawful and approved where you operate.
    - **Don't automate Act without Orient.** Auto-blocking on a single weak signal can break business services or tip off an attacker before scope is known. Automate the parts of the loop where the model is reliable.
    - **Don't trust one-layer scanning of attachments.** A clean result on an outer archive means only that the archive is clean. Make sure your sandbox or gateway actually recursed into every layer, including password-protected ones.

## Practice questions { #quiz }

### Question 1

In the cloud-download example, list what each of layers 3/4, 5/6 and 7 told the analyst, and explain why only layer 7 revealed the attack. What could the SOC use if it had no TLS inspection?

??? success "Answer and explanation"
    - **Layers 3/4 (`conn.log`):** an HTTPS connection on port 443 to an address in a large cloud provider's shared range, about 400 KB downloaded. IP reputation clean — everything normal.
    - **Layers 5/6 (`ssl.log`):** TLS 1.3 (certificate not visible), SNI `files.cloudshare.example`, a well-known trusted service. Domain reputation clean — normal.
    - **Layer 7 (`http.log`, `files.log` via TLS inspection):** a direct download of `Invoice_4471.zip`, MIME type `application/zip`, extracted for analysis — and it contained an executable.

    Only layer 7 revealed it because the attacker deliberately used **legitimate infrastructure** for every lower layer; the malicious part was the *content*. Without TLS inspection: **endpoint telemetry** (EDR seeing the file written, extracted and executed), **email-gateway link analysis** or URL detonation, and the cloud service's own abuse reporting.

### Question 2

Explain what each OODA stage means in a SOC and why Orient is considered the most important. In the slow defender loop of the worked example, which stage cost the most time, and how did the fast version fix it?

??? success "Answer and explanation"
    **Observe** — collect monitoring data (logs, alerts, packets, files, EDR). **Orient** — combine observations with mental models and context (assets, users, threat intel, attack models) into a picture of the attack and its goal. **Decide** — choose a course of action as a hypothesis (contain, block, observe, collect). **Act** — carry it out and feed the result back into Observe.

    **Orient** matters most because it's where your models and context turn data into understanding, and it shapes what you observe and decide next. A wrong or stale model makes a fast Decide and Act useless — or harmful.

    In the slow loop, the biggest delays were the 25 minutes in the queue plus 11 minutes of uncertain orienting (about 36 minutes), and then **Decide** — 30 minutes waiting for manager approval. The fast version shortened Orient with automatic scoring and a structured case-notes habit, and removed the Decide delay with a **pre-approved playbook** allowing immediate isolation of a workstation with confirmed C2. That put the defender inside the attacker's loop.

### Question 3

An email gateway reports "attachment scanned: clean" for `Statement.zip`. A colleague wants to close the alert. Describe how you'd apply encapsulation thinking, including at least three commands or checks and what you'd expect each to show if the file were malicious.

??? success "Answer and explanation"
    "Clean" only means the outer layer passed whatever check the gateway applied. Peel it, in an isolated analysis environment:

    1. `unzip -l Statement.zip` — list contents. Suspicious: an Office document, disk image (ISO/IMG), LNK, script (`.js`, `.vbs`, `.hta`), HTML file or another archive; a password-protected archive (password in the email body) is a red flag on its own.
    2. Extract and run `file` on each item — check the real type from magic bytes. Suspicious: a "PDF" that is actually a PE executable, a "DOCX" that is a ZIP with odd parts.
    3. For Office files, `unzip -l` the document and look for `word/embeddings/` or `vbaProject.bin`; use `oleobj`/`olevba` (oletools) to extract embedded objects or macros. Suspicious: an embedded OLE Package containing an `.exe` or script.
    4. Hash the final non-container files (`sha256sum`) and search EDR and threat intel; check whether any user opened them.

    Record the chain in the case (`email → ZIP → … → final file + hash`) and only close it once you've reached the bottom layer.

## Related { #related }

- [Memory and experience](../analyst-cognition/memory-experience.md) — why we collect mental models in the first place
- [File identification and nested files](../file-analysis/file-identification.md#nested-files) · [Hashing and signatures](../file-analysis/hashing-signatures.md) · [Dangerous file types](../file-analysis/safe-handling-file-types.md)
- [HTTPS certificates and TLS decryption](../http-analysis/https-certificates.md) · [TLS fingerprints and TLS 1.3](../http-analysis/tls-fingerprints-tls13.md)
- [Defining "dangerous"](../alert-triage/defining-dangerous.md) — attack-stage models used in triage
- [Phishing delivery](../../../adversary/phishing-delivery.md) · [RDP](../../../adversary/rdp.md)

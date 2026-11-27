---
title: "Choosing a Response — From Ignore to Rebuild, Opportunistic vs Targeted, Common Missteps, Out-of-Band Communication and Not Breaking Things"
tags:
  - training
  - blue-team
  - soc
  - incident-response
  - analysis
---

# Choosing a Response — From Ignore to Rebuild, Opportunistic vs Targeted, Common Missteps, Out-of-Band Communication and Not Breaking Things { #choosing-response }

!!! abstract "What this page covers"
    The [previous page](dwell-type-motivation.md) asked the questions; this page turns the answers into action. First, the **range of responses** — **Ignore**, **Disrupt**, **Engage** (watch and learn), **Clean all** and **Nuke from orbit** (rebuild everything) — and how cost, effectiveness and the skill they demand change along that range (the middle option is the hardest). Then the two very different playbooks: **reacting to opportunistic attacks** (contain, clean, then sweep the whole network for the same indicators — shown with a Zeek log search broken down command by command) and **reacting to targeted attacks** (scope carefully, preserve volatile evidence, plan resets and blocks, collect more, never touch their infrastructure or submit samples publicly, and quietly disrupt their goal). Next, the **common missteps** that national incident response teams keep seeing, and why each one helps the attacker; **out-of-band communication**, for when the attacker may be reading your email; and the **analyst's own mistakes** — blocking a partner, a critical service or the alert queue — with a "search your logs before you block" example worked through, and a ladder of what could go wrong. An eviction-day plan for the Wattle Ridge intrusion, with Windows events **4625**, **4724** and **4769** to watch afterwards, and the section summary close the page.

!!! note "Labels"
    **[Supplement]** = practical material you need to know, **[Correction]** = a commonly repeated claim that is wrong or outdated, **[Changed]**/**[Caution]** = what has changed recently and what is risky to do the old way. The company (Wattle Ridge Energy, `wattleridge.example`), people, hostnames, domains, IPs and log lines are invented for illustration (`.example`, documentation and private IPs). Frameworks, researchers, agencies and public incidents are real and described in my own words.

## The 8 key points { #key-points }

1. **There is a spectrum of responses**, not just "block it": ignore, disrupt, engage, clean all, rebuild everything. The answers to the previous page's questions point you to one.
2. **The middle is the hardest.** Ignoring and rebuilding need little security skill; **engaging** — watching a live adversary, learning their tools and planning an eviction — demands the most from a SOC.
3. **Opportunistic infections are usually one-host problems:** contain, clean (reimage is safest), then **sweep the whole network** for the same indicators, because if one machine caught it, others may have too.
4. **Targeted attacks need special handling:** scope first, preserve volatile evidence, plan resets and blocks together, increase collection, stay off their infrastructure, keep samples out of public services, and slow them down without tipping them off.
5. **Mitigating too early is the classic misstep.** National incident response teams list it first, alongside touching attacker infrastructure, early blocks and early password resets, losing logs, and talking over the compromised network.
6. **Assume your own channels are being read** once an incident is serious. Set up **out-of-band communication** before you need it, with separate accounts and strong MFA — and remember those messages can be discoverable.
7. **Search your logs before you block anything.** One retroactive search tells you whether that "malicious" domain or hash is used by half the company.
8. **Think about the worst case before you act**, get buy-in when critical services or VIPs are involved, keep recovery steps where everyone can find them, and own your mistakes.

## Why this matters in a SOC { #why }

Think of a hospital emergency department. Not every patient gets surgery. A scraped knee gets a plaster and goes home (ignore, more or less). A simple fracture gets set straight away (disrupt). A patient with confusing, changing symptoms is admitted and watched closely while tests come back, with the team ready to act the moment something gets worse (engage). Sepsis may need the whole system treated at once (clean all). And very occasionally, the only option is a transplant (rebuild). Choosing the wrong level hurts the patient either way: operating on a scraped knee causes harm, and sending the confusing case home with painkillers misses the real problem.

Back to the technical reality. A SOC that only knows one response — usually "isolate and reimage" — handles 95% of its incidents well and the most dangerous 5% badly. A SOC that over-thinks everything wastes days on adware. This page gives you the menu, the reasoning for each choice, and the safety checks that stop a correct decision from turning into an outage of your own making. It is also where the incident response cycle's **Contain**, **Eradicate** and **Recover** stages become concrete; see the [incident response cycle](../mental-models/kill-chain-did-nist-ir.md#ir-cycle).

## Choosing a response: the five patterns { #patterns }

Once the evidence shows an intrusion and you have worked through the factors on the previous page, the response patterns described in Frode Hommedal's attacker-eviction work form a spectrum from "do nothing" to "start again from scratch". Some fit single opportunistic infections; others are for advanced attackers who have been inside for a long time.

**1. Ignore.** Do nothing (beyond recording it). Some opportunistic findings — adware, a "potentially unwanted program" that injects ads into a browser — may pose so little threat that addressing them isn't worth the time. This is a deliberate, documented decision, not neglect: you note why it was low risk.

**2. Disrupt.** Whack-a-mole: rebuild the infected asset immediately. Most opportunistic threats are handled this way, because they don't move laterally or spread through the environment. Rebuild the machine, and the problem is gone.

**3. Engage.** Watch and learn. Leave the affected hosts online for a while, investigate indicators on them and on other machines, and work out how the whole campaign fits together — the tools, the communication methods, the accounts. Once you understand it deeply, sweep everything at once to cut the attacker off. Meanwhile, wherever you can do it **without tipping your hand**, take tactical steps to prevent further damage or escalation.

**4. Clean all.** Less watching, more mass cleaning: reimage or rebuild every asset that might be affected. It is heavier-handed but needs less defensive skill, because you don't need to learn the attacker's TTPs in detail when you are rebuilding everything they could have touched.

**5. Nuke from orbit (complete rebuild).** Start from scratch — nothing in the environment can be trusted. Reserved for the worst compromises or for business-destroying attacks. Public examples of organisations that had to (or were forced to) rebuild on this scale include the 2014 Sony Pictures attack and the 2017 NotPetya outbreak, after which the shipping company Maersk publicly described reinstalling tens of thousands of computers and thousands of servers in a matter of days.

### Cost, effectiveness and skill { #cost-skill }

| Pattern | Direct cost | Effectiveness at removing the attacker | Security skill needed | Typical fit |
| --- | --- | --- | --- | --- |
| Ignore | Lowest | None | Low | Adware, PUPs, harmless noise |
| Disrupt | Low | High for single-host commodity malware; low against a spread-out attacker | Low | Opportunistic, single host |
| Engage | Medium (people and time) | High, if done well | **Highest** | Targeted, long dwell, strategic attacker, risk under control |
| Clean all | High | High, if the scope is right | Medium | Widespread compromise when you can't (or won't) map every TTP |
| Complete rebuild | Highest | Highest — a new environment | Low to medium (but huge project effort) | Total loss of trust, destructive attacks |

Two things stand out. **Cost** generally rises down the list, and so does **effectiveness** — the last option leaves the attacker nothing to come back to. But **skill** is U-shaped: doing nothing and rebuilding machines take little from a blue team, while the middle option — fighting a live adversary in your own network — takes the most advanced capabilities a SOC has. That is why "engage" is not the default; a team without the visibility and people to do it well may be safer choosing "clean all".

## Reacting to opportunistic attacks { #opportunistic }

Opportunistic attacks — spam bots, DDoS "zombies", click-fraud malware, crypto-miners, many banking trojans — are usually single-host pieces of malware, not built to spread across the network or give an attacker interactive control. Once that one machine is cleaned, the incident is normally over. The steps:

1. **Identify the infection and contain the host** so the user can't lose sensitive data and the malware can't do more damage (EDR network isolation, or pulling it off the network).
2. **Clean it.** Reimaging is the safest way to remove malware; antivirus or manual removal is possible but less certain.
3. **Collect its indicators** — every domain and IP it contacted, every file it dropped, its hashes, its persistence location.
4. **Search the whole network for those indicators.** Assume that if one machine picked it up, others may have too — even though those copies probably have nothing to do with each other.
5. **Clean every machine that shows signs of infection.**

### Worked example: sweeping for one infection's indicators { #sweep-example }

Wattle Ridge's EDR quarantines a click-fraud trojan on laptop `WR-LT-0417`. The analyst extracts its network indicators into a file, `iocs.txt`:

```text
adclick-relay.example
cdn-promo-stats.example
198.51.100.203
```

Then searches 30 days of Zeek DNS logs on the log server:

```console
$ zcat /data/zeek/2026-1[01]-*/dns.*.log.gz \
    | zeek-cut ts id.orig_h query answers \
    | grep -F -f iocs.txt \
    | awk '{print $2}' | sort | uniq -c | sort -rn
     412 10.20.6.88
      97 10.20.5.31
```

Line by line:

- `zcat /data/zeek/2026-1[01]-*/dns.*.log.gz` — decompress and print every DNS log from October and November (`1[01]` matches `10` and `11`). `zcat` reads gzip files without unpacking them to disk.
- `zeek-cut ts id.orig_h query answers` — keep only four columns: timestamp, the internal host that asked, the name it asked for, and the answers. Zeek logs have many columns; `zeek-cut` selects by name.
- `grep -F -f iocs.txt` — keep only lines containing any indicator in the file. `-F` treats them as fixed strings (so the dots in domain names aren't regex wildcards), and `-f` reads the patterns from the file. Matching the IP in the `answers` column catches *other* domain names that resolve to the same server.
- `awk '{print $2}'` — print just the second column, the internal host IP.
- `sort | uniq -c | sort -rn` — count how many matching lookups each host made, biggest first.

The output says two more hosts — `10.20.6.88` (412 lookups) and `10.20.5.31` (97) — have been resolving the same click-fraud domains. Notice that the original laptop isn't in the list: it was on a hotel network, outside the Zeek sensors, when it was infected. That is a reminder to search **every** source you have (EDR, proxy, firewall, DNS resolver logs), not just one. The analyst opens tickets for both hosts, they are reimaged, and the indicators are added to the DNS block list — this is an opportunistic, commodity threat, so blocking it does no OPSEC harm.

**[Caution]** In 2026, "opportunistic" does not always mean "finished when the laptop is clean". **Infostealer** malware is opportunistic too, but what it steals — saved passwords, browser session cookies, VPN and cloud tokens — keeps working after the laptop is rebuilt, and is often sold to other criminals. For any infection that could have touched credentials, the clean-up includes resetting passwords, **revoking sessions and tokens**, and checking those accounts for unusual sign-ins.

## Reacting to targeted attacks { #targeted }

Targeted attacks are a different situation altogether. The attacker's goals and techniques mean the reaction must be far more careful, so that it doesn't reveal unnecessary information to them. Once there is a real possibility the attack is targeted:

| Do / Don't | What it means | Why |
| --- | --- | --- |
| **Scope the intrusion carefully before reacting** | Find every host, account, backdoor and C2 path you can (the knowledge matrix from the previous page) | Partial clean-ups tell the attacker what you know and leave them a way back |
| **Preserve volatile evidence** | Capture memory, running processes and live network connections *before* rebooting, isolating or reimaging | Some malware lives only in memory; a reboot destroys the evidence of what it was and where it talked |
| **Carefully plan password resets and IOC blocking** | Do them together, at a planned time, as part of the eviction | Early, piecemeal resets or blocks warn the attacker and push them onto other credentials and channels |
| **Enable more data collection if possible** | Extra logging (command-line process auditing, Sysmon, PowerShell script-block logging), longer retention, packet capture at key choke points, EDR on hosts that lack it | You need to see their other footholds and how they react |
| **Do NOT contact adversary infrastructure** | No lookups, scans or browsing of their domains and IPs from attributable systems | It shows them they are being investigated (see [analysis OPSEC](../analysis-opsec/index.md)) |
| **Do NOT submit samples to public sandboxes** | Hash lookups only; private analysis | Public submissions alert the attacker and may expose your data |
| **DO try to disrupt their goal without tipping them off** | Quietly move or protect what they are after; make actions look like ordinary IT behaviour | Limits damage while you prepare the real response |

What does "disrupt quietly" look like? At Wattle Ridge, the attacker reads substation design files every month. The team moves the most sensitive current drawings to a share the compromised `svc-backup` account cannot reach, leaving older, less valuable files in place, and tightens a firewall rule between the historian and the control network in a change window that already had maintenance scheduled. Nothing about it looks like a security response; it simply makes the prize harder to reach.

## Common missteps in incident response { #missteps }

Is "watch and learn" really accepted best practice, or just a clever idea? Government incident response teams agree with it. A presentation by US-CERT (now part of CISA) on responding to major incidents, and later a joint 2020 advisory from the cyber security agencies of the US, Australia, Canada, New Zealand and the UK on uncovering and remediating malicious activity, list the mistakes they see most often. Paraphrased:

1. **Mitigating affected systems before responders can protect and recover data** — at the top of the list. Wiping or rebuilding destroys the evidence you need and tells the attacker to change tactics.
2. **Touching adversary infrastructure** — pinging, looking up or browsing their domains and IPs. It tips them off.
3. **Pre-emptively blocking adversary infrastructure** — they notice, and move to infrastructure you don't know about.
4. **Pre-emptive credential resets** — before you know every compromised account and how they got the credentials, a reset warns them, and they may simply harvest the new passwords.
5. **Failing to preserve or collect the log data** that would show how they got in and moved.
6. **Communicating over the same network** where the incident response is being run — the attacker may be listening.
7. **Fixing only the symptom, not the root cause** — removing the malware but not the vulnerability, the stolen credential or the misconfiguration that let them in, so they come straight back.

Notice that almost every item is a version of "doing something too early or too visibly". Targeted attacks require special, careful handling and the discipline to resist the instinct to react immediately — except, as always, when business risk demands it.

## When things go bad: out-of-band communication { #out-of-band }

One tactic advanced attackers use again and again is **monitoring the security team itself**. If they can read the SOC's email and chat, they stay one step ahead of the recovery: they know which hosts you've found, when the eviction is planned and which accounts will be reset. This is not a far-fetched scenario. It has been reported across many incidents and sectors, and it can take very little: an account with administrative rights on desktops — help desk or domain admin — can usually log on to the security team's machines too. That is one strong argument for keeping security team infrastructure **completely separate from the corporate Windows domain**: if no accounts are shared, this attack becomes much harder.

Once an incident becomes serious enough (domain admin compromise is the usual threshold), it is wise to **assume your in-network communication is being monitored**, whether or not you have direct evidence. The answer is **out-of-band communication** (OOB): a way for responders and management to talk that is **completely independent of the organisation's accounts, credentials and infrastructure**, set up and tested **before** an incident.

It can be elaborate — a separate email system or a separate collaboration tenant — or simple: everyone installs an end-to-end encrypted messenger such as Signal on their mobile phones and joins a team group (handy for out-of-hours coordination anyway). Whatever you choose:

- **Separate credentials**, never the corporate SSO, and **MFA turned on** — ideally phishing-resistant (passkeys or security keys). You don't want attackers breaking into that channel too.
- **Include management.** Executives will want updates on any large incident and have their own coordination to do (legal, regulators, communications).
- **Keep an offline contact sheet** — phone numbers for the team, management, legal, your incident response retainer and key suppliers — on paper or in a device not tied to the corporate network.
- **Test it** in exercises, so the first time you use it isn't during a crisis.

An example OOB card for Wattle Ridge:

```text
WATTLE RIDGE — OUT-OF-BAND INCIDENT COMMS (review quarterly)
Trigger:      Declared Sev-1, or any suspected identity/admin compromise
Primary:      Signal group "WR-IR-Core" (SOC leads, IR manager, CISO)
              Signal group "WR-IR-Exec" (CISO, COO, General Counsel, Comms lead)
Accounts:     Personal-device Signal, registration PIN set, not tied to corporate SSO
Backup:       Conference bridge on external provider; dial-in on paper card
Email:        Separate tenant ir.wattleridge-oob.example, hardware-key MFA only
Do not:       Discuss the incident in corporate email, Teams or tickets until cleared
Records:      Incident decisions copied to the IR log by the scribe (legal hold applies)
Last test:    2026-09-14 tabletop — all 11 members reached within 9 minutes
```

Reading it: the **trigger** says when to switch (not "when we see them reading our mail", but at a severity level, because you may never see it). There are **two groups**, so technical detail and executive decisions don't drown each other. Accounts are **independent** of the corporate identity system. The **backup** works even if phones or the messenger are down. The **"do not"** line covers the tickets and chat that responders use by habit. And **records** remind everyone that these messages may need to be kept.

**[Supplement]** Out-of-band messages can be **discoverable**. In a lawsuit, a regulator's investigation or (for government organisations) under records and freedom-of-information laws, the team's chat may have to be produced. Disappearing messages can conflict with record-keeping obligations. Agree the rules with your legal team in advance: what is kept, who keeps the official record, and what must never be discussed in a casual chat.

## Common analyst response mistakes { #analyst-mistakes }

Analysts make mistakes too — and the most common one is **over-zealously blocking an indicator found in an alert**. It is easy to do: many analysts have the power to apply controls, and they see huge numbers of indicators every day. Typical "oops" moments:

- blocked an important website;
- blocked email from a legitimate sender;
- took down a critical service;
- blew up the alert queue (a new detection rule that matches everything).

Prevention rules (blocks) can cause real denial of service, but even a careless detection rule causes SOC problems, such as an exploded alert queue that hides the real alerts.

How do you avoid it?

- **Don't assume an indicator should be blocked.** Sometimes blocking a domain, IP or hash is exactly right; but before you do anything that can take down a service, double-check.
- **Ask a co-worker to double-check your block** — a second pair of eyes catches the typo that blocks `*.wattleridge.example`.
- **SEARCH YOUR LOGS FIRST.** Before applying a block or changing a detection rule, run a **retroactive search** to see what the impact would be.

### Worked example: search before you block { #search-first }

An alert fires: *"Connection to known phishing domain: `fieldparts-supply.example`"*, from an external threat feed. The analyst's first instinct is to block the domain at the proxy. Instead, they search the last 7 days of proxy logs first:

```console
$ zcat /data/proxy/2026-11-{20..26}.log.gz \
    | grep -F 'fieldparts-supply.example' \
    | awk '{print $3}' | sort -u | wc -l
318

$ zcat /data/proxy/2026-11-{20..26}.log.gz \
    | grep -F 'fieldparts-supply.example' \
    | awk '{print $7}' | sort | uniq -c | sort -rn | head -5
   4120 /api/v2/orders
    905 /catalogue/search
    611 /login
     38 /invoice/download
      2 /promo/winter-sale.html
```

Line by line:

- `zcat /data/proxy/2026-11-{20..26}.log.gz` — the shell expands `{20..26}` into seven file names, one per day; `zcat` prints them all.
- `grep -F 'fieldparts-supply.example'` — keep lines mentioning the domain, as a fixed string.
- First command: `awk '{print $3}'` prints the third field (in this proxy's format, the client IP); `sort -u` removes duplicates; `wc -l` counts them. **318 different internal hosts** talked to this domain in a week.
- Second command: `awk '{print $7}'` prints the requested URL path; `uniq -c` counts each; `head -5` shows the top five. The traffic is **API calls, catalogue searches and logins** — exactly what an ordering system looks like.

A quick check with procurement confirms it: Field Parts Supply is Wattle Ridge's main spare-parts supplier, and the whole maintenance team orders through its portal. Blocking the domain would have stopped maintenance ordering across the company. So what was the alert about? The two hits on `/promo/winter-sale.html` lead to the real finding: that one page on the supplier's site had been hacked to serve a malicious redirect (exactly the "link to a hacked site" case from the [investigation section](../investigation/email-links-phishing.md)). The right response is a **narrow** block on that single URL path, a call to the supplier, and a check of the two hosts that loaded it — not a block of the whole domain.

The opposite result is just as useful: if a week (or more) of complete logs showed **no** host ever talking to the domain, you would know a block is very unlikely to break anything. The same logic applies to file hashes (is this "malicious" hash actually the IT team's remote support tool on 900 machines?), email sender domains, and any detection rule change: run it against past data first and count what it would have hit.

## What could go wrong? Preventing disaster { #what-could-go-wrong }

Even careful analysts will make a mistake at some point in their career. The question is how bad it will be. Before you block anything, think through the **worst plausible outcome**, and move carefully if the answer involves critical services, the whole company or VIP systems and workflows.

| Level | Example | How to prevent / recover |
| --- | --- | --- |
| **Critical or company-wide outage** | Blocking a cloud provider's IP range used by your email; quarantining a hash that turns out to be a core business application | Get **buy-in from the business owner and SOC manager** first; change control; a tested rollback |
| **Non-critical or partial outage** | Blocking one partner portal; isolating a department's print server | Retro-search first; second-person check; know how to undo it |
| **SOC issue** | A SIEM query that locks up the cluster; a new IDS feed that floods the queue; an OPSEC mistake | Test rules on past data; staged rollout; **recovery procedures available to everyone**, including off-hours |
| **Personal issue** | Infecting your own analysis VM; breaking your workstation | Revertible VMs; follow lab rules |

The top two rows are career-limiting; the bottom two are bad but usually recoverable. Most mistakes land in the bottom half, and very few have lasting consequences for the analyst. When you do make one: **don't panic, own it, report it quickly, and help fix it.** Don't make it worse with excuses. Everyone gets something wrong eventually, and expensive lessons are the ones you never repeat.

## Putting it together: the Wattle Ridge eviction { #eviction-plan }

On the previous page the Wattle Ridge intrusion pointed to **Engage**: strategic attacker, 27+ months of dwell, short-haul and long-haul backdoors, large knowledge gaps, high but not immediate risk. Here is how that plays out.

**Engage phase (about two weeks).** Extra logging and EDR on every server; packet capture at the operations-network boundary; long-window beacon hunting finds a third foothold (a VPN account with no owner); the cloud team finds an extra secret added to an engineering application in 2025. Memory from `WR-FS02` and `WR-HIS01` is captured and analysed privately. Communication moves to the OOB channel after the team confirms `svc-backup` can log on to SOC workstations. A trigger is agreed: any connection attempt from the historian towards the control network means immediate containment.

**Eviction day** — everything at once, in a planned window:

| Time | Action | Why at the same time |
| --- | --- | --- |
| T-0:00 | Block all known C2 domains and IPs (short-haul, long-haul, newly found) at the firewall and DNS | Cutting one channel alone would warn them |
| T-0:00 | Disable `svc-backup`, the orphan VPN account and the rogue cloud application secret | Removes identity backdoors that never beacon |
| T-0:05 | Isolate `WR-FS02`, `WR-HIS01`, `WR-JMP01` with EDR | Stops any running implant from acting |
| T-0:15 | Reset all privileged and service account passwords; reset `krbtgt` (the first of two resets) | Stolen hashes and forged Kerberos tickets stop working |
| T-0:30 | Revoke all sessions and refresh tokens for admin and engineering users; re-register MFA for those with exposure | Stolen cloud sessions survive a password reset |
| Day 1–3 | Rebuild the three hosts from known-good images; patch the jump server's entry point | Removes the root cause, not only the symptom |
| T+10 h or more | Second `krbtgt` reset (after the maximum ticket lifetime has passed) | Invalidates any ticket created before the first reset |
| Weeks after | Heightened monitoring for re-entry | Strategic attackers try again |

**[Supplement]** Why reset `krbtgt` twice? Every Kerberos ticket in an Active Directory domain is signed with the `krbtgt` account's key, and the domain keeps the current and the previous password. An attacker who stole that key can forge "golden" tickets. One reset leaves the previous key still valid; the second reset — after enough time has passed for legitimate tickets to expire (10 hours by default) — removes it. Microsoft provides guidance and a script for doing this safely.

**After eviction, what to watch.** The SOC adds alerts for signs that the attacker is trying the old doors:

- **Event 4625** (an account failed to log on) with status `0xC0000072` — "account currently disabled". Someone is still trying `svc-backup` or the orphan VPN account. Attackers care because it is often their first attempt to see what still works.
- **Event 4724** (an attempt was made to reset an account's password) on privileged accounts outside the planned window. An attacker who still has some admin access may try to take an account back.
- **Event 4769** (a Kerberos service ticket was requested) with unusual encryption types or from hosts that shouldn't request tickets for sensitive services — a sign of forged or roasted tickets being tried.
- Any DNS query or connection to the blocked C2 infrastructure, and any **new** rare, regular beacon — the sign of a backdoor you missed.

## Section summary: intrusion discovery { #summary }

- **Not every incident should be reacted to immediately.** The right speed depends on dwell time, intrusion type, motivation, business risk and what you know.
- **Targeted attacks require special handling.** The top goal is that the attacker **doesn't learn you have found them** until you are ready.
- **Watch and learn** their tools and TTPs, using strategic blocks and quiet manoeuvring to make them reveal every way in.
- **Plan a careful and complete response.** Then move **all at once** to evict the attacker and deny re-entry.
- **Business risk can override all of this.** Active harm to safety, data or operations means act now.

There is no single question that decides between immediate action and a crafted eviction plan. It is a complicated game with no definite answers and some uncertainty that never goes away. What defenders can do is use structured models like these to understand and reduce that uncertainty, so they are in a position to make a complete response.

## The 2026 view { #trends }

!!! success "[2026 Current] Still valid"
    The response spectrum, the split between opportunistic and targeted reactions, "search your logs before you block", and the warning against early, visible mitigation remain standard practice. The 2020 joint advisory's list of common mistakes is still widely quoted. Attackers monitoring the defenders is very much current: Microsoft disclosed in 2024 that a state-sponsored actor had read email accounts of senior leaders and cyber security staff, and CISA and partner agencies reported (updated in July 2025) that the group known as Scattered Spider searched victims' Slack, Teams and Exchange for discussion of their own intrusion and joined incident response calls. Out-of-band communication is now a routine item in mature IR plans and tabletop exercises.

!!! info "[Changed] What has changed"
    - **NIST SP 800-61 Rev. 3 (April 2025)** replaced Rev. 2 and frames incident response through the **CSF 2.0** functions (Govern, Identify, Protect, Detect, Respond, Recover) rather than the old four-phase lifecycle. The thinking on this page fits it well: decisions about containment and eradication sit under **Respond**, rebuilding under **Recover**, and the out-of-band plan and playbooks under preparation.
    - **US-CERT is now part of CISA**; cite CISA (and your national agency — for Australia, the ASD's ACSC) rather than US-CERT.
    - **Identity-first eviction.** Evictions now routinely include revoking sessions and refresh tokens, removing rogue OAuth applications and cloud credentials, re-registering MFA and checking mailbox rules, because many attackers persist in identity and SaaS rather than on hosts. Password reset alone is no longer an eviction.
    - **Speed has risen.** With initial access handed off to a second group in seconds (median 22 seconds in M-Trends 2026), and ransomware operators often acting within hours or days, the "engage" window for intrusions that look like ransomware precursors is short or zero. Engage is for espionage-style attackers where risk is controlled.
    - **Messaging security advice.** In December 2024 CISA advised highly targeted individuals to use end-to-end encrypted messaging apps such as Signal and phishing-resistant MFA, after telecommunications networks were compromised. A 2025 public incident in which a journalist was accidentally added to a government Signal group is a reminder that **membership control and records rules** matter as much as encryption.
    - **AI in response.** SOC copilots and SOAR playbooks can draft containment steps and run retroactive searches quickly — useful for "search before you block". But automated blocking driven by threat feeds or AI suggestions repeats the over-zealous-block mistake at machine speed unless there is an allow-list of critical partners and a human approval step for high-impact actions.

!!! warning "[Caution] Wrong or risky to do the old way"
    - **Don't treat a password reset as the end of an eviction.** Revoke sessions and tokens, remove added cloud credentials and OAuth apps, and check MFA methods and mail rules.
    - **Don't call an infostealer infection "done" after reimaging.** Stolen credentials and cookies outlive the laptop.
    - **Don't choose "engage" for a ransomware precursor** to learn more. Contain first.
    - **Don't run the response over corporate email, chat or tickets** once identity or admin compromise is suspected — and don't use the corporate SSO to sign in to the out-of-band channel.
    - **Don't block a domain, IP or hash from a feed without a retroactive search** — especially a supplier, a cloud provider range or a signed IT tool.
    - **Don't reset `krbtgt` twice in quick succession.** Wait out the ticket lifetime and replication between resets, or you can break authentication across the domain.

## Practice questions { #quiz }

### Question 1

Name the five response patterns from least to most drastic, and explain why the security skill they require is "U-shaped" rather than increasing steadily.

??? success "Answer and explanation"
    **Ignore → Disrupt → Engage → Clean all → Complete rebuild ("nuke from orbit").**

    Cost and effectiveness generally rise along the list, but skill doesn't. **Ignore** needs almost no skill, and **rebuild everything** is a huge project but needs little knowledge of the attacker — you don't have to understand their TTPs if nothing they touched survives. **Disrupt** (rebuild one host) is also simple. **Engage** sits in the middle and is the hardest: the team must keep watching a live adversary, find every foothold, protect the business without tipping them off, and plan a coordinated eviction. That is why engage is chosen deliberately, not by default, and why a team without the visibility for it may be better off with "clean all".

### Question 2

A threat feed alert says `fieldparts-supply.example` is a phishing domain. Your colleague wants to block it immediately at the proxy. What do you do first, what would the two possible results tell you, and what might the right response be?

??? success "Answer and explanation"
    **Search your logs first**: a retroactive search of proxy and DNS logs over at least a week (more if you have complete logs), counting how many internal hosts contacted the domain and which URL paths they requested.

    - If **many hosts** use it routinely (API calls, logins, catalogue pages), it is probably a real partner. Blocking the whole domain would cause an outage. Look for what made the feed flag it — perhaps one compromised page — and apply a **narrow** block (that URL), tell the partner, and check the hosts that loaded the bad page.
    - If **no host** has ever contacted it (and your logs are complete), a block is very unlikely to break anything and is reasonable.

    Either way, have a colleague double-check the block, and think about the worst case before applying it.

### Question 3

During a suspected targeted intrusion, the attacker has used a domain admin account. List four things you would do differently from a normal commodity-malware incident, and explain why communication is one of them.

??? success "Answer and explanation"
    Any four of: **scope carefully before acting** (all hosts, accounts, backdoors and cloud identities); **preserve volatile evidence** (memory and live connections) before isolation or reboot; **plan password resets and IOC blocks together** for eviction day, including `krbtgt` twice and token revocation; **increase data collection** (logging, EDR coverage, packet capture); **do not touch attacker infrastructure** from attributable systems; **do not submit samples publicly**; **quietly protect what they are after** without tipping them off.

    Communication matters because with domain admin rights the attacker can probably log on to the security team's own machines and read corporate email and chat. Assume they are listening and move to a pre-arranged **out-of-band** channel that uses separate accounts and strong MFA — otherwise they will read the eviction plan before you carry it out.

## Related { #related }

- [Reacting to an Intrusion — Dwell Time, Type, Backdoors, Motivation, Risk and Knowledge](dwell-type-motivation.md) — previous page
- [Reacting to Intrusions](index.md) — section overview
- [Researching Safely — common OPSEC failures](../analysis-opsec/passive-osint-failures.md) — submission, interaction and the premature block
- [Kill Chain, NIST CSF and the IR Cycle](../mental-models/kill-chain-did-nist-ir.md)
- [Email links and phishing](../investigation/email-links-phishing.md) — the hacked-partner-page case
- [Credential Dumping](../endpoint-attacks/credential-dumping-mimikatz.md) — why `krbtgt` and service accounts matter
- [Important Events](../important-events/index.md) — Windows event IDs
- [Adversary Techniques](../../../adversary/index.md)

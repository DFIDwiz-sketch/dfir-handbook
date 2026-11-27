---
title: "Targeted Attacks, Clicks, Captured Passwords and Business Email Compromise — Answering \"Who Fell for It?\""
tags:
  - training
  - blue-team
  - soc
  - analysis
  - investigation
  - email
  - phishing
  - bec
---

# Targeted Attacks, Clicks, Captured Passwords and Business Email Compromise — Answering "Who Fell for It?" { #targeted-clicks-bec }

!!! abstract "What this page covers"
    The previous page decided whether a message and its link were malicious. This page answers the questions that decide the **response**. First: **is this a targeted attack?** — the signs that someone spent extra effort on your organisation (a lookalike of your domain, your logo, a message to one named person, indicators nobody else has seen), why the answer changes how loudly and how quickly you respond, and why tipping off a targeted attacker can cost you the next intrusion. Second: **did anyone click?** — searching proxy, DNS and click-protection logs for both the short and the expanded URL, what the old public click counters could and could not prove, and why a click count is meaningful only for a targeted link. Third: **did anyone type a password?** — finding where a login form really posts, reading an unencrypted form submission in a reassembled TCP stream, and what to use instead when everything is HTTPS (decrypted proxy and Zeek POST records, then the identity logs that show the stolen password being used). Fourth: **business email compromise (BEC)** — how "CEO fraud" works with no file or link, why attackers hide their tracks with mailbox rules, and the detections that catch them: hidden-folder, auto-delete and external-forwarding rules, BEC keywords, new mailbox delegates, sign-ins from VPN and proxy services, and applications granted mailbox access — plus why MFA helps but does not end the problem. Invented Microsoft 365 audit records, an Entra sign-in record and two KQL queries are read line by line. The page, and the investigation section, close with the four investigation questions applied once more as a summary. The 2026 view and practice questions follow.

!!! note "Labels"
    **[Supplement]** = practical material you need to know, **[Correction]** = a commonly repeated claim that is wrong or outdated, **[Changed]**/**[Caution]** = what has changed recently and what is risky to do the old way. The company (Bluegum Freight, `bluegumfreight.example`), people, hostnames, domains, IPs, audit records and log lines are invented for illustration (`.example`, documentation and private IPs). Products, log tables, frameworks and public reports are real and described in my own words.

## The 8 key points { #key-points }

1. **Always ask "was this aimed at us?"** Customisation — your domain imitated, your logo, one named recipient, per-recipient tokens, indicators no one else has reported — means someone thought you were worth the effort.
2. **The answer drives the response.** Opportunistic, widely seen attacks can be handled briskly. Targeted ones need care: a clumsy, visible reaction can warn the attacker, who then changes tools and comes back where you are not looking.
3. **"Has anyone clicked?" is answered from your own logs.** Search for both the short and the expanded URL, and the destination domain, in proxy, DNS and click-protection logs.
4. **Public click counters were only ever a hint.** A click might be the attacker testing their own link, counts are meaningful only for a link sent to one target, and the big shorteners no longer show them publicly anyway.
5. **Follow the form, not the page.** A phishing page's form `action` tells you where a typed password goes; a POST to that address from one of your hosts is the evidence that someone submitted it.
6. **With HTTPS, the password itself is out of sight — so prove submission and use instead.** Decrypted proxy or Zeek records show the POST; identity logs show a new sign-in for that account from somewhere strange.
7. **BEC needs no malware.** It is a convincing story, urgency and a changed bank account, often sent from a real but compromised mailbox — and it is consistently one of the most costly kinds of cybercrime reported.
8. **Hunt the attacker's housekeeping.** Inbox rules that hide, delete or forward mail, new delegates, suspicious sign-ins and newly consented applications are how compromised mailboxes are found. MFA helps; it is not the end of the story.

## Why this matters in a SOC { #why }

Imagine finding a burglar's chalk mark on your front gate. If every gate on the street has the same mark, someone is walking the whole neighbourhood looking for easy pickings: lock up, tell the neighbours, done. If yours is the only one, and next to it is a photo of your back door, someone has studied *your* house. Ripping the mark off and putting up floodlights tells them you have noticed, and they come back another night through a window you did not think about. Then the questions are different: did they get in already, did anyone give them a key, and are they quietly reading your post?

Back to the technical reality. A phishing report is not finished when the link is judged malicious. The SOC must still decide whether the attack was aimed at the organisation, whether anyone clicked, whether anyone gave away a password, and whether a mailbox is already in the attacker's hands. Those four answers decide everything that follows: how many people to reset, whether to watch quietly or act at once, whether finance needs to stop a payment today. And BEC in particular can cost more than most malware incidents without a single malicious file ever touching an endpoint.

## Targeted vs opportunistic attacks { #targeted }

The first question to keep asking when you see evidence of malicious activity is: **does this look like an attack aimed specifically at me or my organisation?** The tell is anything showing the attacker took *extra time* to customise the attack for you or your people:

- **A lookalike of your own domain** (or of a supplier you really use).
- **Your logo, branding, templates or internal jargon** in the message.
- **Spear-phishing addressed to one employee by name**, perhaps mentioning their role, a real project or a real colleague.
- **Indicators nobody else seems to have seen** — the domain, hash or URL has no history in open-source or commercial intelligence.
- **[Supplement]** **Per-recipient tokens** in the link (an email address or ID in the URL), **role selection** (only finance, only executive assistants, only the IT help desk), and **timing** that matches your organisation (end of quarter, the week of a known supplier change).

Customisation can be cheap and still be telling. A financially motivated attacker who pastes a company's logo crudely onto a lure is still crafting messages organisation by organisation, which means whatever they are after is worth extra effort to them. And targeted attacks are not always obvious on the surface. A widely reported 2016 intrusion into a political campaign began with an ordinary-looking "your password was used, change it now" email. Its button was a shortened link to a password-stealing page on a domain built to look like the real sign-in site. Nothing in the message screamed "targeted"; what would have shown it was investigating the link — a destination domain unknown to any intelligence source, and a click history showing only a couple of visits instead of the thousands a mass campaign produces.

### Worked example: scoring the morning's emails { #targeted-example }

Bluegum's analyst scores the malicious messages from the [previous page](email-links-phishing.md#queue-result), plus a mass-spam message (E7) that arrived the same day:

| Sign | E2 rate card (IDN) | E3 mailbox full | E6 policy (short link) | E7 "parcel fee" spam |
| --- | --- | --- | --- | --- |
| Imitates our domain or brand | Yes — `xn--bluegum-fright-9vl` | Yes — our name as a subdomain | Yes — our HR language | No — a generic courier brand |
| Our logo/templates | Our real rate-card template | Copy of our webmail page | Our policy footer | No |
| Sent to | 3 sales staff, by name | 14 IT staff | 6 HR staff, by name | 4,100 mailboxes |
| Per-recipient tokens | No | Pre-filled address | Username in path | No |
| Seen elsewhere (intel, prevalence) | Never seen | Never seen | Never seen | Reported thousands of times |
| Domain age | 9 days | 4 days | 3 days | 2 months, on many blocklists |
| **Assessment** | **Targeted** | **Targeted** | **Targeted** | **Opportunistic** |

Three of the morning's emails were built for Bluegum, the same week, and E2, E3 and E6's domains were registered within six days of each other through the same registrar — likely one campaign (the Diamond Model's "same adversary" question from [the mental-models section](../mental-models/diamond-attack-trees.md)).

### Why the answer changes the response { #targeted-response }

If an attack is clearly generic and its indicators are already well known in public intelligence, the response can be relaxed: block, purge the message from mailboxes, reset anyone who clicked, close the ticket.

If it is targeted, think about the *angle* of the response before acting. You do not want to tip the attacker off that you have noticed them. If you do, they may switch infrastructure and tactics and come back with an attack you are not watching for. This is where the choice between **immediate response and watch-and-wait** comes in, and where careful operational security protects the investigation — for example, not scanning their per-recipient links publicly, not visiting their infrastructure from your own IP range, and not announcing to the whole company "we are under attack by X" when only a few people were targeted. The analysis OPSEC and intrusion-response sections that follow cover these choices in depth. **[Supplement]** "Careful" never means "slow" where harm is ongoing: if a password has been captured, the account is reset and its sessions revoked at once; the care is about *how visibly* you investigate the rest.

## Tracking clicks to shortened links { #tracking-clicks }

Sooner or later a targeted wave will use custom shortened links, and someone will ask **"has anyone clicked this?"** Once you know the final destination (previous page), the answer is in your own logs: search for **both** the shortened URL and the expanded one, and the destination's domain, because users may have reached it by either.

### Worked example: who clicked E6? { #clicks-example }

E6's link: `https://lnk.example/Pq7Rz` → `https://hr-docs-sign.example/policy/view?uid=l.ward`. The analyst searches yesterday's and today's proxy logs:

```
zgrep -hE 'lnk\.example/Pq7Rz|hr-docs-sign\.example' /logs/proxy/2026-11-2[67]*.log.gz | awk '{print $1, $2, $3, $5, $6, $8}'
```

- `zgrep` — `grep` that reads gzip-compressed files directly.
- `-h` — do not print the file name in front of each match.
- `-E` — extended regular expressions, so `|` means "or".
- `'lnk\.example/Pq7Rz|hr-docs-sign\.example'` — the short link **or** the destination domain. The `\.` matches a literal dot (a bare `.` would match any character).
- `/logs/proxy/2026-11-2[67]*.log.gz` — the log files for 26 and 27 November.
- `awk '{print $1, …}'` — print only the time, source IP, user, host, URL and action columns (positions in this proxy's format).

Output:

```
2026-11-27T07:58:03Z src=10.20.3.18 user=BLUEGUM\d.costa host=lnk.example url=/Pq7Rz action=allowed
2026-11-27T07:58:04Z src=10.20.3.18 user=BLUEGUM\d.costa host=hr-docs-sign.example url=/policy/view?uid=d.costa action=allowed
2026-11-27T08:01:47Z src=10.20.3.22 user=BLUEGUM\l.ward host=hr-docs-sign.example url=/policy/view?uid=l.ward action=allowed
```

- Line 1–2: **d.costa** clicked their own copy of the short link at 07:58 and was redirected a second later — the pair of lines is what a click through a shortener looks like.
- Line 3: **l.ward** (who reported it) reached the destination directly at 08:01 — no shortener line. Perhaps they copied the expanded URL from a preview, or their copy of the email had a different short code. Searching only for `lnk.example/Pq7Rz` would have missed them.

**[Supplement]** Click-time protection (for example Microsoft Defender for Office 365 Safe Links) records clicks even for users off the corporate network. In Microsoft Defender XDR advanced hunting, using KQL (Kusto Query Language — each line after the first starts with `|`, passing the results of the previous line to the next step):

```
UrlClickEvents
| where Timestamp > ago(2d)
| where Url has "hr-docs-sign.example" or Url has "lnk.example/Pq7Rz"
| project Timestamp, AccountUpn, Url, ActionType, IsClickedThrough, IPAddress
| order by Timestamp asc
```

- `UrlClickEvents` — the table of clicks on links that Safe Links protects.
- `where Timestamp > ago(2d)` — only the last two days.
- `where Url has "…" or Url has "…"` — `has` matches whole terms inside the URL; keep both the short and the expanded form.
- `project …` — keep only these columns: when, who, what URL, what Safe Links did (`ClickAllowed`, `ClickBlocked`, …), whether the user clicked through a warning page, and from which IP.
- `order by Timestamp asc` — oldest first, which makes a timeline.

A row with `ActionType = ClickAllowed` for `m.ito@bluegumfreight.example` from a home IP would add a third user the proxy never saw.

### What click counters could tell you — and why they mostly can't now { #click-counters }

Some shorteners used to publish statistics for any link: add the preview suffix and you saw the destination *and* how many times it had been clicked, and when. In the 2016 example above, those public stats showed the link had been clicked — a strong hint that the target had visited. Two cautions always applied:

- **A click is not necessarily the victim.** The attacker may have tested their own link, a security product may have pre-fetched it, or a researcher may have looked. It is one more data point, not proof.
- **It only works for a link aimed at one person or organisation.** For a link spammed worldwide, a large count tells you only that it was a mass campaign.

**[Changed]** Bitly no longer shows click data publicly — only the link's creator can see it when logged in. Treat any guide that says "add `+` to see the click count" as out of date. Your proxy, DNS and click-protection logs are the reliable source.

## Where does that password box go? { #password-box }

Clicking is bad; typing a password is worse. How can you tell whether anyone actually submitted credentials?

### Step 1: find where the form posts { #form-action }

Open the phishing page **in an isolated analysis browser** and use the browser's developer tools (right-click → *Inspect*) to view the HTML behind the form, or read the saved page source. E3's kit from the previous page:

```
<form method="POST" action="https://mailbox-quota.example/owa/post.php">
  <input type="email" name="u">
  <input type="password" name="p">
  <button type="submit">Sign in</button>
</form>
```

- `method="POST"` — the typed values travel in the body of an HTTP POST request.
- `action="https://mailbox-quota.example/owa/post.php"` — the address that receives them. **This URL is your search term**: a POST to it from one of your hosts means someone pressed *Sign in*.
- `name="u"`, `name="p"` — the field names in the submitted body (`u=…&p=…`).

**[Supplement]** Many kits post with JavaScript instead of a plain form (look for `fetch(` or `XMLHttpRequest` in the page's scripts), post to a different domain from the one hosting the page, or send the stolen values on to a chat-bot API. Follow the code to the real destination, and record every receiving host.

### Step 2a: if the traffic is not encrypted { #cleartext-post }

If the page uses plain HTTP and you have full packet capture, open the capture in Wireshark, filter for the POST, and use *Follow → TCP Stream* to see the whole conversation reassembled. A reconstructed submission (from a test run on the analysis machine, with fake credentials):

```
POST /owa/post.php HTTP/1.1
Host: mailbox-quota.example
Content-Type: application/x-www-form-urlencoded
Content-Length: 44

u=test.user%40analysis.example&p=NotARealPw1
HTTP/1.1 302 Found
Location: https://outlook.office.example/
```

- `POST /owa/post.php` — the request the form sends.
- `Content-Type: application/x-www-form-urlencoded` — values encoded as `name=value&name=value`.
- `u=test.user%40analysis.example` — the username, with `%40` standing for `@`.
- `p=NotARealPw1` — the password, in clear text, readable by anyone on the path.
- `302 Found` / `Location:` — after stealing the values, the kit redirects the victim to the **real** sign-in site so that nothing seems wrong. A very common touch.

In a real investigation the same stream from a user's machine would show *which* account was given away — which is exactly what you need to protect it.

### Step 2b: when everything is HTTPS (the usual case today) { #https-post }

Almost all phishing pages now use HTTPS, so without decryption the network shows only that a connection happened. You prove submission in other ways:

- **Decrypted proxy logs** show the method and URL. Search for `POST` to the form's `action`:

```
2026-11-27T08:12:40Z src=10.20.7.9 user=BLUEGUM\k.rahman method=POST host=mailbox-quota.example url=/owa/post.php status=302 bytes_out=1288 action=allowed
```

- `method=POST` to `/owa/post.php` — the *Sign in* button was pressed.
- `status=302` — the kit's redirect to the real site, as in the test above.
- `bytes_out=1288` — the size of the request including headers, consistent with a small form submission. The password itself should **not** be in your proxy logs; if your proxy records request bodies, handle those logs as sensitive.

- **Zeek** with TLS decryption upstream, or on plain HTTP, records the same fact in `http.log` as `method=POST`, the `uri`, and `request_body_len`.
- **The identity logs** then show whether the stolen password was *used*. Within minutes, the Entra ID sign-in log shows:

```
2026-11-27T08:19:02Z  userPrincipalName=k.rahman@bluegumfreight.example  appDisplayName=Office 365 Exchange Online  ipAddress=203.0.113.77  location=NL  clientAppUsed=Browser  userAgent=Mozilla/5.0 (X11; Linux x86_64) ...  status=Success  authenticationRequirement=singleFactorAuthentication  riskLevelDuringSignIn=high
```

- `ipAddress=203.0.113.77`, `location=NL` — a hosting-provider address in another country; k.rahman's laptop is in Brisbane.
- `userAgent=… Linux …` — Bluegum issues Windows laptops.
- `status=Success` with `singleFactorAuthentication` — the password alone was enough (this account was missing from the MFA policy — a finding in itself).
- `riskLevelDuringSignIn=high` — Entra ID Protection also thought it was odd.

The proxy POST at 08:12 plus the foreign sign-in at 08:19 is the story: credentials phished and used (T1598.003, then T1078.004 Valid Accounts: Cloud Accounts). Reset the password, **revoke all sessions and refresh tokens**, check for MFA methods the attacker may have added, and move straight to the mailbox checks in the next section — because the next thing an attacker does with a mailbox is often BEC. **[Supplement]** On-premises Windows logs would not show this: Security event **4624** (an account successfully logged on) records logons to Windows machines and domain controllers, not sign-ins to a cloud mail service. For cloud identities, the identity provider's sign-in log is the logon record.

## Business email compromise detection { #bec }

**Business email compromise (BEC)**, also called "CEO fraud", is a simple attack: the attacker asks for money, with a good story about why it must be paid in an unusual way, and puts the recipient under pressure — an urgent deadline, a secret deal, dire consequences if they don't act. An invented example:

```
From: "Dana Whitfield (CFO)" <d.whitfield@bluegumfreight.example>
To: p.lim@bluegumfreight.example
Subject: Immediate wire transfer
Importance: High

Priya, please process a transfer of AUD 248,000 today and code it to
"administrative expense". This is confidential until the acquisition is
announced, so please don't discuss it. Payment details to follow.
```

- `From` — the real CFO's real address. Nothing is spoofed; that is why SPF, DKIM and DMARC all pass. The account itself is compromised.
- `Importance: High`, "today", "confidential", "don't discuss" — urgency and secrecy, designed to stop the victim from checking with anyone.
- "Code it to administrative expense" — steering around normal approval.
- "Payment details to follow" — the bank account arrives in a second email, once the victim is committed.

BEC is hard to spot because there is not necessarily a file or link, and the sending account may be real. Related forms: **vendor email compromise** (a supplier's mailbox is taken over and sends "our bank details have changed"), payroll diversion (an "employee" asks HR to change their salary account), and gift-card scams. In ATT&CK terms: T1534 Internal Spearphishing when sent from a compromised internal account, and T1656 Impersonation.

### How attackers hide: mailbox rules { #bec-hiding }

To run the scam without the real CFO noticing, attackers add rules to the compromised mailbox: replies about the payment are moved to an obscure folder or deleted, often after being forwarded out, and marked as read. The account owner never sees the conversation. So the detections focus on the attacker's housekeeping.

**Inbox rules that** (ATT&CK T1564.008 Hide Artifacts: Email Hiding Rules, T1114.003 Email Collection: Email Forwarding Rule):

- auto-forward or move mail to **hidden or rarely used folders** (RSS Subscriptions, Conversation History, Archive, a folder named `.`),
- **auto-delete** messages,
- **redirect or forward** mail to an **external address**,
- trigger on **BEC-related keywords** — invoice, payment, wire, bank, transfer, remittance, the name of the person being impersonated.

**Other signs:**

- **New mailbox delegates** — someone given full access or send-as rights (T1098.002 Account Manipulation: Additional Email Delegate Permissions).
- **Sign-ins from proxy, VPN or hosting-provider IPs, or from an odd region.** Attackers use anonymisation services to hide where they are; employees seldom, if ever, sign in through them. Threat intelligence lists of such IP ranges help.
- **Too many failures before a success** — a threshold you will have to tune for your environment.
- **Applications granted mailbox access** — review consents regularly (below).

### Worked example: the CFO's new rule { #bec-rule-example }

After k.rahman's compromise, the analyst hunts for rule changes across the tenant in the Microsoft 365 audit data (here via Microsoft Sentinel's `OfficeActivity` table):

```
OfficeActivity
| where TimeGenerated > ago(7d)
| where Operation in ("New-InboxRule", "Set-InboxRule", "UpdateInboxRules", "Set-Mailbox")
| extend P = tostring(Parameters)
| where P has_any ("ForwardTo", "RedirectTo", "ForwardingSmtpAddress", "DeleteMessage", "MoveToFolder")
| project TimeGenerated, UserId, Operation, ClientIP, P
```

- `OfficeActivity` — the table holding Exchange Online, SharePoint and Teams audit events.
- `where TimeGenerated > ago(7d)` — the last seven days.
- `where Operation in (…)` — rule creation and changes from PowerShell or the web (`New-InboxRule`, `Set-InboxRule`), from Outlook clients (`UpdateInboxRules`), and mailbox-level forwarding (`Set-Mailbox`).
- `extend P = tostring(Parameters)` — turn the rule's parameters into one searchable text column.
- `where P has_any (…)` — keep only rules that forward, redirect, delete or move mail.
- `project …` — show when, who, what, from which IP, and the parameters.

One result, shown here as the underlying audit record (shortened):

```
{
  "CreationTime": "2026-11-27T08:31:15",
  "Operation": "New-InboxRule",
  "UserId": "d.whitfield@bluegumfreight.example",
  "ClientIP": "203.0.113.77",
  "Parameters": [
    { "Name": "Name", "Value": "." },
    { "Name": "SubjectOrBodyContainsWords", "Value": "payment;wire;transfer;bank;invoice" },
    { "Name": "MoveToFolder", "Value": "RSS Subscriptions" },
    { "Name": "MarkAsRead", "Value": "True" },
    { "Name": "StopProcessingRules", "Value": "True" }
  ]
}
```

- `Operation: New-InboxRule` — a new rule.
- `UserId: d.whitfield@…` — the **CFO's** mailbox, not k.rahman's. The attacker used k.rahman's access to phish onward, or reused the same infrastructure against the CFO.
- `ClientIP: 203.0.113.77` — the same hosting IP that signed in as k.rahman. One IP, two accounts: the link that ties them together.
- `Name: "."` — a name chosen to be almost invisible in the rules list.
- `SubjectOrBodyContainsWords: payment;wire;transfer;bank;invoice` — classic BEC keywords.
- `MoveToFolder: RSS Subscriptions` — a folder nobody opens.
- `MarkAsRead: True` — no unread-count to catch the eye.
- `StopProcessingRules: True` — no later rule will surface the message.

That rule is the hidden half of the wire-transfer email above. The SOC tells finance immediately to stop the payment and confirm by phone on a known number, removes the rule, resets and revokes the CFO's sessions, reviews delegates and consented apps on both accounts, and searches for other mailboxes touched from 203.0.113.77.

### MFA: turn it on — and know its gaps { #bec-mfa }

Making compromise require more than a password is the strongest single step: **turn on MFA**. But it is not perfect:

- **Illicit consent grants.** The attacker tricks a user into approving a malicious application ("Bluegum Document Viewer wants to read your mail"). The app gets an OAuth token and can read the mailbox via API **without** the user's password or MFA, and keeps access after a password reset until the consent is revoked (T1528 Steal Application Access Token, T1550.001 Use Alternate Authentication Material: Application Access Token). Review applications granted mailbox access, and restrict which apps users may consent to.
- **Adversary-in-the-middle phishing** captures the session cookie after MFA (previous page).
- **MFA fatigue and help-desk social engineering** get the second factor from the user or from IT.

This kind of attack has hit organisations with knowledgeable staff and good defences — they are hard to stop. So combine hardened accounts with rule, delegate and consent monitoring and anomalous-sign-in detection.

**And people.** Well-trained employees are part of the defence. If finance staff know this scam exists, know its signs (urgency, secrecy, changed bank details, payment by unusual route), and have a rule to verify any payment change by phone on a known number, they are far less likely to fall for it.

## Summary: the four investigation questions { #summary }

This section broke the big question "what happened here?" into smaller ones that can be answered in order:

1. **Question formulation** — what question are you trying to answer?
2. **Data identification** — what data do you need to answer it?
3. **Data collection** — how do you extract that data?
4. **Data interpretation** — what does that data tell you?

Applied one last time to this page:

| Question | Data needed | Where it came from | What it told us |
| --- | --- | --- | --- |
| Was E2/E3/E6 targeted? | Domains, recipients, intel history, registration dates | Email gateway, intel platform, WHOIS | Yes — one campaign built for Bluegum |
| Did anyone click E6? | Requests to the short and expanded URLs | Proxy (`zgrep`), Safe Links `UrlClickEvents` | d.costa and l.ward clicked |
| Did anyone submit credentials to E3? | POSTs to the form `action`; later sign-ins | Decrypted proxy; Entra sign-in log | k.rahman submitted; password used from 203.0.113.77 |
| Is a mailbox being used for BEC? | Rule, forwarding, delegate and consent changes | `OfficeActivity` audit data | CFO mailbox rule hiding payment mail — stop the transfer |

Decomposing like this makes the analysis repeatable and easy to hand over. Whenever you feel lost in an investigation, come back to these four questions and let them point the way.

## The 2026 view { #trends }

!!! success "[2026 Current] Still valid"
    Asking "targeted or opportunistic?" early, searching your own logs for both short and expanded URLs, following a phishing form to where it posts, and hunting hidden-folder, delete and forwarding rules, new delegates, odd sign-ins and consented apps are all current practice. BEC remains one of the costliest crimes reported: the FBI's Internet Crime Complaint Center report for 2025 (published April 2026) counted about 24,800 BEC complaints with roughly **US$3 billion** in reported losses — a small share of complaints but a large share of money lost. The four investigation questions are as useful as ever.

!!! info "[Changed] What has changed"
    - **Click counters are gone, click telemetry is better.** Bitly shows click data only to a link's owner. Click-time protection (Safe Links and similar products) and browser or EDR telemetry now give per-user click records, including off-network users.
    - **Credential phishing moved to session theft.** Adversary-in-the-middle kits, device-code phishing (the victim enters a code on the real sign-in page, handing the attacker tokens) and OAuth consent phishing bypass password-plus-MFA. Phishing-resistant MFA (FIDO2 security keys, passkeys, Windows Hello for Business) and conditional access on device compliance are the main answers. "Did anyone type a password?" is increasingly "did anyone authorise a session?".
    - **Consent defaults tightened.** In 2025 Microsoft moved Microsoft 365 tenants that had not configured it to a Microsoft-managed user-consent policy that stops users consenting by themselves to apps asking for access to their files and sites; admins should still review existing grants and tighten mail-related consent policies.
    - **AI in BEC.** Generative AI writes fluent, locally phrased lures in any language, and deepfake voice and video have been used to "confirm" fraudulent payment requests. Verification must use a channel the attacker does not control — a known phone number, an in-person check — never a number or meeting link in the message.
    - **Vendor and supply-chain email compromise** (a real supplier's mailbox asking you to change bank details) is now a major BEC form, and passes every authentication check.
    - **Defenders use AI too.** Defender XDR, Sentinel and other SIEM copilots summarise phishing clusters, explain mailbox-rule parameters and draft KQL like the queries above. Check the logic and the time range of every generated query before trusting "no results".
    - **ATT&CK IDs** on this page: T1566, T1598.003, T1078.004, T1534, T1656, T1564.008, T1114.003, T1098.002, T1528, T1550.001. Some tactic placements changed in ATT&CK v19 (April 2026); these IDs did not.

!!! warning "[Caution] Wrong or risky to do the old way"
    - **Don't rely on public click statistics** — they are mostly unavailable, and a click may not be the victim.
    - **Resetting a password is not enough.** Also revoke sessions and refresh tokens, remove attacker-added MFA methods, inbox rules, forwarding, delegates and app consents. Otherwise the attacker stays in.
    - **Don't verify a payment by replying to the email** or calling the number in it — the attacker controls both.
    - **Don't run a loud, company-wide reaction to a targeted attack** before you have scoped it; handle the people involved quietly and quickly, and protect captured accounts at once.
    - **Don't test a phishing form with real credentials** — use invented ones on an isolated analysis machine, and treat any log that captures request bodies as containing secrets.
    - **"No rules found" may mean "no logs".** Confirm mailbox auditing and the audit data you query are actually enabled and retained long enough before closing a BEC investigation.

## Practice questions { #quiz }

### Question 1

Two phishing emails arrive the same morning. One is a "your parcel is held — pay a small fee" message sent to 4,000 staff from a domain already on public blocklists. The other is sent to three named engineers, imitates your code-hosting portal with your logo, and links to a domain registered five days ago that no intelligence source has seen. Classify each, list the signs you used, and explain how your response to each should differ.

??? success "Answer and explanation"
    The parcel email is **opportunistic**: generic brand, huge recipient list, no customisation, and indicators already widely known. Respond briskly — block, purge it from mailboxes, check the proxy for clicks, reset anyone who entered details, close.

    The engineers' email is **targeted**: it imitates *your* portal with *your* logo, is addressed to a few named people in one role, and uses a fresh domain no one else has reported. Someone invested effort in you. Respond carefully: protect the three people at once (check clicks, submissions and sign-ins; reset and revoke if needed), but investigate quietly — avoid public scans of the link, avoid visiting the infrastructure from your own network, don't announce it company-wide — and decide deliberately between watching to learn more and acting immediately, so the attacker doesn't simply switch infrastructure and return unseen.

### Question 2

A credential-phishing page's form has `action="https://acct-review.example/s.php"`. The page is HTTPS and your proxy decrypts traffic. Describe how you would find out (a) who submitted the form and (b) whether their password was then used, and what records would convince you.

??? success "Answer and explanation"
    (a) Search the decrypted proxy logs (and Zeek `http.log` if it sees decrypted traffic) for **`POST` requests to `acct-review.example/s.php`** — the form's `action`, not just the page — over the time since delivery. Each hit gives a time, source host and user. A `POST` followed by a redirect (`302`) to the real sign-in site is the typical kit pattern. Also check the page code in case JavaScript posts somewhere else.

    (b) For each user, check the **identity provider's sign-in logs** (for example Entra ID) after the POST time: a successful sign-in from an unfamiliar IP (hosting/VPN provider, another country), unusual device or user agent, or a high risk score shortly after the submission shows the stolen credentials were used. Windows event 4624 on your domain controllers would not show a cloud mail sign-in. Then reset, revoke sessions, remove attacker-added MFA methods and check the mailbox for rules.

### Question 3

You find this mailbox rule on a finance manager's account, created from an IP belonging to a VPN service: name `..`, condition "subject or body contains *invoice; remittance; bank details*", action "forward to `ap.team.billing@freemail.example`, then delete". List what each part tells you, the ATT&CK techniques involved, and five follow-up checks.

??? success "Answer and explanation"
    - Name `..` — chosen to be nearly invisible in the rules list.
    - Keywords *invoice, remittance, bank details* — targets payment conversations: BEC.
    - **Forward to an external free-mail address** — the attacker receives every payment email (T1114.003 Email Forwarding Rule).
    - **Then delete** — the real owner never sees the replies (T1564.008 Email Hiding Rules).
    - Created from a **VPN-service IP** — employees seldom sign in that way; it points to an attacker hiding their location.

    Follow-ups: (1) review the account's sign-in logs for the VPN IP and others, and when access began; (2) check for **other rules, mailbox forwarding** (`Set-Mailbox` forwarding addresses) and **new delegates** (T1098.002); (3) review **applications granted access** to the mailbox and revoke unknown consents (T1528); (4) search for other mailboxes accessed from the same IP; (5) **contact finance and suppliers** by a known phone number to stop or verify any recent payment changes — then reset the password, revoke sessions and tokens, and remove attacker MFA methods.

## Related { #related }

- [Email Attacks and Assessing Links](email-links-phishing.md) — previous page: judging the message and its link
- [Investigation Questions](index.md) — section overview
- [Starting an Investigation](questions-and-data.md) — the four questions in full
- [The Diamond Model and Attack Trees](../mental-models/diamond-attack-trees.md) — the supplier-payment-fraud attack tree (T1114.003)
- [DMARC and the Email Wrap-up](../email/dmarc-summary.md) — what authentication does not stop
- [POST, Methods and Headers](../http/post-methods-headers.md) — cookies, session theft and AiTM
- [Logins](../important-events/logins.md) — Windows logon events and their limits
- [Phishing Delivery & Initial Execution](../../../adversary/phishing-delivery.md)
